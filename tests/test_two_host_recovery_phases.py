"""#520: the two-host harnesses' ``--phase refund`` / ``--phase abort`` recovery paths.

Both harnesses dispatched exactly five phases — intro, fund, claim, envelope, lock-claim — so each
role could reach funded-but-unrecoverable INSIDE the harness that drives the two-party adversarial
run: the taker funds and the maker stalls with nothing to drive an unwind; the maker's covenant is
locked and the taker never claims, with nothing to drive the CSV refund and a ``_NoFeeSource`` that
raises from inside the transaction builder if anything tries.

These tests cover the four recovery phases that close it. They touch NO chain and broadcast
NOTHING: the leg constructors are replaced with recording fakes and the REAL ``SwapCoordinator`` —
built by the harness's own ``_coordinator``, with the harness's own role tagging and margin policy —
runs over them, so the FSM, the P3 role guard and the maturity gates are the shipped ones.

The one thing these must never get wrong is WHICH refund each role drives.
``maybe_refund_asset_on_maker_stall`` refunds the asset only, and its CSV refund pays the MAKER in
both directions, so a taker driven to it gifts the asset back and destroys its own only recourse
while its counter leg stays locked — after which the maker, still holding p, takes both
(``tests/test_xchain_swap_regtest_e2e.py::TestMakerStallAssetOnlyRefundIsTakerLoss``). So there is a
structural test that no ``taker_phase_*`` function in either script can reach it, and a behavioural
one that the coordinator each harness builds for a taker refuses it outright.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as bt
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_COORDINATOR_SRC = Path(__file__).resolve().parent.parent / "src" / "pyrxd" / "gravity" / "swap_coordinator.py"


def _load(name: str):
    sys.path.insert(0, str(_SCRIPTS))  # the harnesses import their sibling _dust_swap_shared
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def eth_mod():
    return _load("eth_swap_two_host")


@pytest.fixture
def btc_mod():
    return _load("btc_swap_two_host")


# ---------------------------------------------------------------------------
# Recording fakes — nothing here reaches a node, and nothing signs
# ---------------------------------------------------------------------------


class _FakeChainIO:
    def __init__(self, confs: int) -> None:
        self.confs = confs

    async def confirmations(self, txid: str) -> int:
        return self.confs


class _FakeRadiantLeg:
    """A RadiantCovenantLeg stand-in. ``network='bcrt'`` keeps it non-value-bearing, so the
    coordinator's value-bearing setup gates behave exactly as they do on the real regtest leg."""

    network = "bcrt"

    def __init__(self, *, fee_source, confs: int = 10_000, funded: bool = True) -> None:
        self.fee_source = fee_source
        self.chain_io = _FakeChainIO(confs)
        self._confs = confs
        self._funded = funded
        self.refund_calls: list[object] = []

    async def find_covenant_utxo(self, spk, *, expected_value=None, pin_outpoint=None):
        if not self._funded:
            raise NetworkError("no UTXO found for the covenant scriptPubKey (not yet funded / wrong SPK)")
        return "cc" * 32 + ":0", int(expected_value or 0), 1

    async def refund_asset(self, record):
        # A REAL refund dispenses a fee input before it can build anything; keep that property so a
        # phase wired with _NoFeeSource still fails here rather than silently "refunding".
        self.fee_source.next_fee_input()
        self.refund_calls.append(record)
        return "rxdrefund" + "0" * 55


class _FakeFundingReader:
    def __init__(self, confs: int) -> None:
        self.confs = confs

    async def confirmations(self, txid: str) -> int:
        return self.confs


class _FakeCounterLeg:
    def __init__(self, *, confs: int = 10_000) -> None:
        self.funding_reader = _FakeFundingReader(confs)
        self.refund_calls: list[object] = []

    async def refund(self, locator, timeout=None) -> str:
        self.refund_calls.append(locator)
        return "0x" + "ef" * 32


class _FakeEthRpc:
    def __init__(self, now_ts: int) -> None:
        self._now = now_ts
        self.closed = False

    async def latest_block_timestamp_min(self) -> int:
        return self._now

    async def close(self) -> None:
        self.closed = True


class _FakeBtcSource:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _FeeSource:
    def next_fee_input(self):
        from pyrxd.gravity.htlc_spend import FeeInput

        return FeeInput(txid="ab" * 32, vout=0, value=100_000, scriptpubkey=b"\x76\xa9", wif=_FEE_WIF)


# A throwaway regtest WIF for the fee input — generated, never hand-written.
_FEE_WIF = PrivateKey(os.urandom(32)).wif()


# ---------------------------------------------------------------------------
# Scenario builders: a real envelope + a real locator on disk, as the harness writes them
# ---------------------------------------------------------------------------


def _eth_scenario(mod, tmp_path: Path, *, role: str, with_funding: bool, with_claim: bool = False, **over):
    io_dir = tmp_path / "swapdir"
    io_dir.mkdir()
    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    h = hashlib.sha256(os.urandom(32)).digest()
    eth_timeout = 1_800_000_000
    terms, cov = mod._terms_from_public(
        hashlock=h,
        rxd_photons=100_000,
        eth_amount_wei=10**14,
        t_rxd_blocks=120,
        margin_blocks=36,
        eth_timeout_unix_s=eth_timeout,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
    )
    (io_dir / "envelope.json").write_text(
        json.dumps(
            {
                "schema": "eth_rxd_two_host_envelope_v1",
                "terms": terms.to_dict(),
                "maker_pkh_hex": maker_pkh.hex(),
                "eth_maker_claim_addr": "0x" + "11" * 20,
                "eth_taker_refund_addr": "0x" + "22" * 20,
                "eth_chain_id": 31337,
                "rxd_network": "bcrt",
                "covenant_spk_hex": cov.funded_spk.hex(),
            }
        )
    )
    if with_funding:
        from pyrxd.eth_wallet.locator import EthHtlcLocator

        loc = EthHtlcLocator(
            chain_id=31337,
            contract_address="0x" + "33" * 20,
            deploy_tx_hash="0x" + "44" * 32,
            hashlock="0x" + h.hex(),
            claimant="0x" + "11" * 20,
            refundee="0x" + "22" * 20,
            timeout=eth_timeout,
            amount_wei=10**14,
        )
        (io_dir / "taker_funding.json").write_text(json.dumps({"eth_locator": loc.to_dict()}))
    if with_claim:
        (io_dir / "maker_claim.json").write_text(json.dumps({"eth_claim_tx_hash": "0x" + "55" * 32}))

    local = tmp_path / f".{role}_local.json"
    local.write_text(
        json.dumps(
            {
                "role": role,
                "taker_pkh_hex": taker_pkh.hex(),
                "maker_pkh_hex": maker_pkh.hex(),
                "eth_taker_refund_addr": "0x" + "22" * 20,
                "eth_maker_claim_addr": "0x" + "11" * 20,
            }
        )
    )
    args = argparse.Namespace(
        role=role,
        phase="refund",
        io=str(io_dir),
        local_out=str(local),
        yes=True,
        audit_cleared=False,
        eth_chain_id=31337,
        eth_network="anvil",
        eth_rpc_url="http://127.0.0.1:8545",
        eth_key_hex="",
        eth_artifact="",
        rxd_network="bcrt",
        rxd_electrumx_url="tcp://127.0.0.1:50001",
        rxd_electrumx_insecure=False,
        asset_locked_at_height=0,
        fee_txid="",
        fee_vout=0,
        fee_value=0,
        fee_spk_hex="",
        fee_wif="",
        margin_blocks=36,
        taker_min_rxd_confs=1,
        btc_block_interval_s=600.0,
        rxd_block_interval_s=300.0,
        rxd_block_interval_fast_s=36.0,
        eth_finalization_window_s=768,
        eth_finality_stall_tolerance_s=3600,
        rxd_claim_burial_s=1800,
        rxd_confirm_slack_s=600,
        rounding_slack_s=300,
        max_covenant_confirm_wait_s=600,
        poll_interval_s=0.0,
        resume_deadline_s=1.0,
    )
    for k, v in over.items():
        setattr(args, k, v)
    return args, terms, io_dir


def _btc_scenario(mod, tmp_path: Path, *, role: str, with_funding: bool, with_claim: bool = False, **over):
    io_dir = tmp_path / "btc_swapdir"
    io_dir.mkdir()
    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    taker_btc_refund = generate_keypair("bcrt")
    maker_btc_claim = coincurve.PrivateKey(os.urandom(32))
    refund_xonly = mod._xonly_of(taker_btc_refund._privkey.unsafe_raw_bytes())
    claim_xonly = mod._xonly_of(maker_btc_claim.secret)
    h = hashlib.sha256(os.urandom(32)).digest()
    # The self-check's proven honest layout: t_rxd 120 blk x 300 s dominates t_btc 20 blk x 600 s
    # plus the 36-block margin, so these terms are ones a real negotiation could produce.
    terms, cov = mod._terms_from_public(
        hashlock=h,
        btc_sats=100_000,
        t_rxd_blocks=120,
        t_btc_blocks=20,
        taker_pkh=taker_pkh,
        maker_pkh=maker_pkh,
        btc_claim_xonly=claim_xonly,
        btc_refund_xonly=refund_xonly,
    )
    (io_dir / "envelope.json").write_text(
        json.dumps(
            {
                "schema": "btc_rxd_two_host_envelope_v1",
                "terms": terms.to_dict(),
                "maker_pkh_hex": maker_pkh.hex(),
                "btc_maker_payout_spk_hex": "00" * 22,
                "rxd_network": "bcrt",
                "btc_network": "bcrt",
                "covenant_spk_hex": cov.funded_spk.hex(),
            }
        )
    )
    if with_funding:
        htlc = bt.build_htlc(
            hashlock=h,
            claim_pubkey_xonly=claim_xonly,
            refund_pubkey_xonly=refund_xonly,
            timeout=terms.t_btc,
            network="bcrt",
        )
        loc = htlc.with_funding(bt.BtcOutpoint("ab" * 32, 0), 100_000)
        (io_dir / "taker_funding.json").write_text(json.dumps({"btc_locator": loc.to_dict()}))
    if with_claim:
        (io_dir / "maker_claim.json").write_text(json.dumps({"btc_claim_tx_hex": "00" * 40}))

    local = tmp_path / f".{role}_local.json"
    local.write_text(
        json.dumps(
            {
                "role": role,
                "taker_pkh_hex": taker_pkh.hex(),
                "maker_pkh_hex": maker_pkh.hex(),
                "taker_btc_refund_wif": taker_btc_refund.unsafe_wif(),
                "maker_btc_claim_privkey_hex": maker_btc_claim.secret.hex(),
            }
        )
    )
    args = argparse.Namespace(
        role=role,
        phase="refund",
        io=str(io_dir),
        local_out=str(local),
        yes=True,
        rxd_network="bcrt",
        rxd_electrumx_url="tcp://127.0.0.1:50001",
        rxd_electrumx_insecure=False,
        rxd_block_interval_s=300.0,
        rxd_block_interval_fast_s=36.0,
        btc_network="bcrt",
        btc_rpc_url="http://127.0.0.1:18443",
        btc_rpc_user="u",
        btc_rpc_password="p",
        btc_block_interval_s=600.0,
        btc_fee_sats=2_000,
        btc_sats=100_000,
        t_rxd_blocks=120,
        margin_blocks=36,
        taker_min_rxd_confs=1,
        btc_funding_txid="",
        btc_funding_vout=0,
        btc_funding_value=0,
        btc_taker_payout_spk_hex="00" * 22,
        btc_maker_payout_spk_hex="00" * 22,
        fee_txid="",
        fee_vout=0,
        fee_value=0,
        fee_spk_hex="",
        fee_wif="",
        asset_locked_at_height=0,
        resume_deadline_s=1.0,
        poll_interval_s=0.0,
    )
    for k, v in over.items():
        setattr(args, k, v)
    return args, terms, io_dir


def _wire_eth(mod, monkeypatch, *, covenant_confs=10_000, covenant_funded=True, now_ts=1_900_000_000):
    """Replace ONLY the chain-leg constructors. The coordinator, the FSM, the role guard and the
    margin policy stay the shipped ones, built by the harness's own ``_coordinator``."""
    built: dict[str, object] = {}

    def _fake_radiant(args, *, taker_pkh, maker_pkh, fee_source):
        leg = _FakeRadiantLeg(fee_source=fee_source, confs=covenant_confs, funded=covenant_funded)
        built["rxd"] = leg
        return leg

    def _fake_eth(args, *, claim_to, refund_to, eth_timeout):
        rpc, leg = _FakeEthRpc(now_ts), _FakeCounterLeg()
        built["rpc"], built["counter"] = rpc, leg
        return rpc, leg

    monkeypatch.setattr(mod, "_radiant_leg", _fake_radiant)
    monkeypatch.setattr(mod, "_eth_leg", _fake_eth)
    return built


def _wire_btc(mod, monkeypatch, *, covenant_confs=10_000, covenant_funded=True, btc_confs=10_000):
    built: dict[str, object] = {}

    def _fake_radiant(args, *, taker_pkh, maker_pkh, fee_source):
        leg = _FakeRadiantLeg(fee_source=fee_source, confs=covenant_confs, funded=covenant_funded)
        built["rxd"] = leg
        return leg

    def _fake_source(args):
        src = _FakeBtcSource()
        built["source"] = src
        return src

    def _fake_btc_leg(args, source, **kw):
        leg = _FakeCounterLeg(confs=btc_confs)
        built["counter"] = leg
        built["counter_kw"] = kw
        return leg

    monkeypatch.setattr(mod, "_radiant_leg", _fake_radiant)
    monkeypatch.setattr(mod, "_btc_source", _fake_source)
    monkeypatch.setattr(mod, "_btc_leg", _fake_btc_leg)
    return built


def _wire_rxd_height(mod, monkeypatch, *, tip: int, locked_at: int):
    async def _height(args):
        return tip

    async def _anchor(rxd_leg, *, covenant_spk, expected_photons, explicit, now_rxd_height):
        return locked_at

    monkeypatch.setattr(mod, "_rxd_height", _height)
    monkeypatch.setattr(mod, "resolve_asset_locked_at_height", _anchor)


def _with_fee(args):
    args.fee_txid = "ab" * 32
    args.fee_vout = 0
    args.fee_value = 100_000
    args.fee_spk_hex = "76a914" + "11" * 20 + "88ac"
    args.fee_wif = _FEE_WIF
    return args


# ---------------------------------------------------------------------------
# 1. The phase set: dispatchable, reachable, and the same in both directions
# ---------------------------------------------------------------------------

_EXPECTED_PHASES = {
    ("taker", "intro"),
    ("taker", "fund"),
    ("taker", "claim"),
    ("taker", "abort"),
    ("taker", "refund"),
    ("maker", "envelope"),
    ("maker", "lock-claim"),
    ("maker", "abort"),
    ("maker", "refund"),
}


class TestEveryPhaseIsBothDispatchableAndReachable:
    """A phase in ``_DISPATCH`` that argparse rejects is unreachable; a phase argparse accepts that
    ``_DISPATCH`` lacks is an error message pretending to be a feature. Both directions, both files.
    """

    def test_eth_dispatch_table(self, eth_mod):
        assert set(eth_mod._DISPATCH) == _EXPECTED_PHASES

    def test_btc_dispatch_table(self, btc_mod):
        assert set(btc_mod._DISPATCH) == _EXPECTED_PHASES

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_the_cli_accepts_exactly_the_dispatchable_phases(self, name, monkeypatch):
        mod = _load(name)
        dispatchable = sorted({phase for _role, phase in mod._DISPATCH})
        assert mod._all_phases() == dispatchable
        # And argparse really uses that list — parse each phase through the shipped parser.
        for phase in dispatchable:
            if name == "btc_swap_two_host":
                parsed = mod._build_parser().parse_args(["--role", "taker", "--phase", phase])
            else:
                monkeypatch.setattr(sys, "argv", ["x", "--role", "taker", "--phase", phase])
                parsed = mod._args()
            assert parsed.phase == phase

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_both_roles_have_a_refund_and_an_abort(self, name):
        mod = _load(name)
        for role in ("taker", "maker"):
            for phase in ("refund", "abort"):
                assert (role, phase) in mod._DISPATCH, f"{role} cannot {phase}"


# ---------------------------------------------------------------------------
# 2. The taker must never reach the asset-only refund
# ---------------------------------------------------------------------------


def _functions_of(path: Path) -> dict[str, ast.AST]:
    tree = ast.parse(path.read_text())
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _names_used(node: ast.AST) -> set[str]:
    used = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            used.add(sub.attr)
        elif isinstance(sub, ast.Name):
            used.add(sub.id)
    return used


_TRAP = "maybe_refund_asset_on_maker_stall"


class TestNoTakerPhaseCanReachTheAssetOnlyRefund:
    """The asset CSV refund pays the MAKER in both directions. A taker that runs it gifts the asset
    back AND destroys its only recourse while its own counter leg is still locked, after which the
    maker — still holding p — takes both legs. This is derived over EVERY ``taker_phase_*`` function
    the file defines, not over a list someone has to remember to extend."""

    @pytest.mark.parametrize("script", ["eth_swap_two_host.py", "btc_swap_two_host.py"])
    def test_no_taker_phase_names_it(self, script):
        funcs = _functions_of(_SCRIPTS / script)
        taker_phases = {n: f for n, f in funcs.items() if n.startswith("taker_phase_")}
        # Non-vacuity: this must be scanning the phases that actually exist, including the new ones.
        assert {"taker_phase_abort", "taker_phase_refund"} <= set(taker_phases), taker_phases.keys()
        assert len(taker_phases) >= 5
        for name, fn in taker_phases.items():
            assert _TRAP not in _names_used(fn), f"{script}:{name} reaches the taker-stranding refund"

    @pytest.mark.parametrize("script", ["eth_swap_two_host.py", "btc_swap_two_host.py"])
    def test_exactly_one_maker_phase_names_it_and_it_is_the_refund(self, script):
        """The other direction: a guard entry with no item is a check that has stopped running. If
        the maker's refund stopped driving it, this scan would still pass vacuously above."""
        funcs = _functions_of(_SCRIPTS / script)
        namers = {n for n, f in funcs.items() if _TRAP in _names_used(f)}
        assert namers == {"maker_phase_refund"}, namers

    @pytest.mark.parametrize("script", ["eth_swap_two_host.py", "btc_swap_two_host.py"])
    def test_the_takers_own_counter_leg_refund_is_what_the_taker_phases_drive(self, script):
        funcs = _functions_of(_SCRIPTS / script)
        assert "taker_refund_btc" in _names_used(funcs["taker_phase_abort"])
        assert "mutual_refund" in _names_used(funcs["taker_phase_refund"])


class TestTheHarnessRoleTagMakesTheTrapUnreachableAtRuntime:
    """The structural scan proves no taker phase NAMES it. This proves the coordinator the harness
    builds for a taker REFUSES it — so a future mis-wiring fails closed instead of paying the maker.
    """

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_a_taker_role_coordinator_refuses_the_asset_only_refund(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            legs = {"eth_leg": _FakeCounterLeg()}
        else:
            args, terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            legs = {"btc_leg": _FakeCounterLeg()}
        rxd_leg = _FakeRadiantLeg(fee_source=_FeeSource())
        coord = mod._coordinator(args, terms=terms, rxd_leg=rxd_leg, keys_out=str(tmp_path / "k"), record=None, **legs)
        assert coord.config.role is SwapRole.TAKER
        with pytest.raises(ValidationError, match="MAKER-side primitive"):
            await coord.maybe_refund_asset_on_maker_stall(
                now_block_height=1_000, asset_locked_at_height=1, maker_has_claimed_btc=False
            )
        assert rxd_leg.refund_calls == []

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_a_maker_role_coordinator_is_tagged_maker(self, name, tmp_path):
        """The honest half: the role tag must not simply be TAKER everywhere, or the guard above
        would pass for the wrong reason and the maker's own recovery would be refused."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True)
            legs = {"eth_leg": _FakeCounterLeg()}
        else:
            args, terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True)
            legs = {"btc_leg": _FakeCounterLeg()}
        coord = mod._coordinator(
            args,
            terms=terms,
            rxd_leg=_FakeRadiantLeg(fee_source=_FeeSource()),
            keys_out=str(tmp_path / "k"),
            record=None,
            **legs,
        )
        assert coord.config.role is SwapRole.MAKER


class TestTheLibraryHasNoAssetRefundOutsideBothLocked:
    """The maker's ``--phase abort`` calls ``RadiantCovenantLeg.refund_asset`` directly and says in
    its docstring that no coordinator method drives an asset refund from NEGOTIATED. That is a
    CLAIM, and a claim inside a comment rots silently — so it is pinned here in both directions:
    the membership of the coordinator's asset-refunding methods, and their refusal from NEGOTIATED.
    Grow a third one, or relax either state guard, and this fails."""

    def test_exactly_two_coordinator_methods_refund_the_asset(self):
        tree = ast.parse(_COORDINATOR_SRC.read_text())
        callers: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "refund_asset"
                ):
                    callers.add(node.name)
        assert callers, "the scan found no asset-refund caller at all — it has stopped running"
        assert callers == {"maybe_refund_asset_on_maker_stall", "mutual_refund"}, callers

    async def test_both_of_them_refuse_from_negotiated(self, eth_mod, tmp_path):
        args, terms, _io = _eth_scenario(eth_mod, tmp_path, role="maker", with_funding=True)
        rxd_leg = _FakeRadiantLeg(fee_source=_FeeSource())
        coord = eth_mod._coordinator(
            args,
            terms=terms,
            eth_leg=_FakeCounterLeg(),
            rxd_leg=rxd_leg,
            keys_out=str(tmp_path / "k"),
            record=None,  # defaults to NEGOTIATED — the state a maker whose taker never funded is in
        )
        assert coord.record.state is SwapState.NEGOTIATED
        with pytest.raises(ValidationError, match="BOTH_LOCKED"):
            await coord.mutual_refund()
        with pytest.raises(ValidationError, match="BOTH_LOCKED"):
            await coord.maybe_refund_asset_on_maker_stall(
                now_block_height=1_000, asset_locked_at_height=1, maker_has_claimed_btc=False
            )
        assert rxd_leg.refund_calls == []


# ---------------------------------------------------------------------------
# 3. The taker's phases
# ---------------------------------------------------------------------------


class TestTakerAbortRecoversOnlyTheTakersOwnLeg:
    async def test_eth_abort_refunds_the_counter_leg_and_reaches_aborted(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch)
        await eth_mod.taker_phase_abort(args)
        assert len(built["counter"].refund_calls) == 1
        assert built["rxd"].refund_calls == [], "the taker's abort must not spend the maker's covenant"
        assert built["rpc"].closed

    async def test_btc_abort_refunds_the_counter_leg_and_reaches_aborted(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_btc(btc_mod, monkeypatch)
        await btc_mod.taker_phase_abort(args)
        assert len(built["counter"].refund_calls) == 1
        assert built["rxd"].refund_calls == []
        assert built["source"].closed

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_the_radiant_leg_cannot_dispense_a_fee_so_no_covenant_spend_is_buildable(
        self, name, tmp_path, monkeypatch
    ):
        """Not "we did not call it" — it CANNOT be called successfully. Every covenant spend
        dispenses a fee input first, so a leg holding _NoFeeSource is structurally incapable."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_eth(mod, monkeypatch)
            await mod.taker_phase_abort(_with_fee(args))  # even WITH --fee-*, the abort must not use it
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_btc(mod, monkeypatch)
            await mod.taker_phase_abort(_with_fee(args))
        assert isinstance(built["rxd"].fee_source, mod._NoFeeSource)
        with pytest.raises(SystemExit):
            built["rxd"].fee_source.next_fee_input()

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_an_unreadable_radiant_node_does_not_block_the_takers_own_recovery(
        self, name, tmp_path, monkeypatch, capsys
    ):
        """The covenant read here is a DISCLOSURE, not a gate. A recovery that needs the OTHER
        chain to be reachable is not a recovery — and a guard that refuses valid work is a bug."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_eth(mod, monkeypatch, covenant_funded=False)
            await mod.taker_phase_abort(args)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_btc(mod, monkeypatch, covenant_funded=False)
            await mod.taker_phase_abort(args)
        assert len(built["counter"].refund_calls) == 1
        assert "could not be read" in capsys.readouterr().out


class TestTakerRefundIsTheMutualUnwindAndNeverHalfBroadcasts:
    async def test_eth_refund_unwinds_both_legs(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch)
        await eth_mod.taker_phase_refund(_with_fee(args))
        assert len(built["counter"].refund_calls) == 1
        assert len(built["rxd"].refund_calls) == 1

    async def test_btc_refund_unwinds_both_legs(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_btc(btc_mod, monkeypatch)
        await btc_mod.taker_phase_refund(_with_fee(args))
        assert len(built["counter"].refund_calls) == 1
        assert len(built["rxd"].refund_calls) == 1

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_an_immature_covenant_refuses_BEFORE_the_counter_leg_is_broadcast(self, name, tmp_path, monkeypatch):
        """mutual_refund broadcasts the counter leg FIRST. Calling it while the covenant's CSV is
        immature refunds the counter leg, fails on the asset, and leaves the record stuck at
        BOTH_LOCKED — so the shortfall has to be caught before anything is broadcast at all."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_eth(mod, monkeypatch, covenant_confs=119)  # t_rxd is 120
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_btc(mod, monkeypatch, covenant_confs=119)
        with pytest.raises(SystemExit, match="NOT yet mature"):
            await mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == [], "nothing may broadcast before the shortfall check"
        assert built["rxd"].refund_calls == []

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_the_refusal_points_at_the_phase_that_still_works(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            _wire_eth(mod, monkeypatch, covenant_confs=1)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            _wire_btc(mod, monkeypatch, covenant_confs=1)
        with pytest.raises(SystemExit, match="--phase abort"):
            await mod.taker_phase_refund(_with_fee(args))

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_an_unverifiable_covenant_refuses_rather_than_guessing(self, name, tmp_path, monkeypatch):
        """ "Not funded" and "the node cannot answer" are the SAME exception from find_covenant_utxo.
        The phase must not report one as the other, and must not unwind on an unverified asset."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_eth(mod, monkeypatch, covenant_funded=False)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            built = _wire_btc(mod, monkeypatch, covenant_funded=False)
        with pytest.raises(SystemExit, match="cannot tell those apart"):
            await mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == []

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_without_a_fee_utxo_it_refuses_up_front_naming_the_flags(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="taker", with_funding=True)
            _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="taker", with_funding=True)
            _wire_btc(mod, monkeypatch)
        with pytest.raises(SystemExit, match="--fee-txid"):
            await mod.taker_phase_refund(args)


class TestTheEthTimeoutIsCheckedTooNotOnlyTheCovenant:
    async def test_a_live_eth_htlc_refuses_the_unwind(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch, now_ts=1_700_000_000)  # before the 1_800_000_000 timeout
        with pytest.raises(SystemExit, match="has NOT timed out"):
            await eth_mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == []

    async def test_an_immature_btc_csv_refuses_the_unwind(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_btc(btc_mod, monkeypatch, btc_confs=19)  # t_btc is 20
        with pytest.raises(SystemExit, match="NOT yet mature"):
            await btc_mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == []
        assert built["rxd"].refund_calls == []


# ---------------------------------------------------------------------------
# 4. The maker's phases
# ---------------------------------------------------------------------------


class TestMakerRefundIsTheMakersHalfOfTheUnwind:
    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_it_refunds_the_asset_when_the_taker_went_dark(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_btc(mod, monkeypatch)
        _wire_rxd_height(mod, monkeypatch, tip=1_120, locked_at=1_000)  # t_rxd 120 => matured exactly
        await mod.maker_phase_refund(_with_fee(args))
        assert len(built["rxd"].refund_calls) == 1
        assert built["counter"].refund_calls == [], "the counter leg is the taker's to refund"

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_a_maker_that_ALREADY_CLAIMED_does_not_also_take_the_asset(self, name, tmp_path, monkeypatch):
        """The maker publishes maker_claim.json when it claims the counter leg — it has been paid.
        Refunding the asset as well is the FSM's ONE_SIDED_LOSS_TAKER edge. The flag has to be READ
        from the exchange directory: hardcoding it False fires the refund and takes both legs."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True, with_claim=True)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True, with_claim=True)
            built = _wire_btc(mod, monkeypatch)
        _wire_rxd_height(mod, monkeypatch, tip=1_120, locked_at=1_000)
        with pytest.raises(SystemExit, match="declined to refund"):
            await mod.maker_phase_refund(_with_fee(args))
        assert built["rxd"].refund_calls == [], "the maker was already paid; this would be BOTH legs"

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_an_unopened_stall_window_broadcasts_nothing(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_btc(mod, monkeypatch)
        # N = 6, t_rxd = 120: the trigger opens at locked_at + 114. Sit well below it.
        _wire_rxd_height(mod, monkeypatch, tip=1_050, locked_at=1_000)
        with pytest.raises(SystemExit, match="declined to refund"):
            await mod.maker_phase_refund(_with_fee(args))
        assert built["rxd"].refund_calls == []

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_a_triggered_but_immature_csv_is_refused_by_the_coordinator_not_broadcast(
        self, name, tmp_path, monkeypatch
    ):
        """The trigger fires N blocks BEFORE maturity ("stop waiting"), and the coordinator's own
        maturity pre-check must still refuse the non-final broadcast."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_btc(mod, monkeypatch)
        _wire_rxd_height(mod, monkeypatch, tip=1_115, locked_at=1_000)  # triggered (>=1114), immature (<1120)
        with pytest.raises(NetworkError, match="not yet mature"):
            await mod.maker_phase_refund(_with_fee(args))
        assert built["rxd"].refund_calls == []

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_with_no_counter_leg_it_points_at_abort_rather_than_faking_both_locked(
        self, name, tmp_path, monkeypatch
    ):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=False)
            _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=False)
            _wire_btc(mod, monkeypatch)
        with pytest.raises(SystemExit, match="--phase abort"):
            await mod.maker_phase_refund(_with_fee(args))

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_without_a_fee_utxo_it_refuses_up_front_naming_the_flags(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True)
            _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True)
            _wire_btc(mod, monkeypatch)
        with pytest.raises(SystemExit, match="--fee-txid"):
            await mod.maker_phase_refund(args)


class TestMakerAbortUnlocksAnAssetTheTakerNeverMatched:
    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_it_refunds_the_covenant_when_the_taker_never_funded(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=False)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=False)
            built = _wire_btc(mod, monkeypatch)
        await mod.maker_phase_abort(_with_fee(args))
        assert len(built["rxd"].refund_calls) == 1
        assert built["rxd"].refund_calls[0].state is SwapState.NEGOTIATED, "no fabricated BOTH_LOCKED"

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_it_refuses_once_the_taker_HAS_funded_and_points_at_refund(self, name, tmp_path, monkeypatch):
        """A funded counter leg makes this the mutual unwind, which belongs in --phase refund where
        the coordinator's stall trigger, maturity pre-check and P3 role guard all apply."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=True)
            built = _wire_btc(mod, monkeypatch)
        with pytest.raises(SystemExit, match="--phase refund"):
            await mod.maker_phase_abort(_with_fee(args))
        # It refuses before a Radiant leg is even constructed — nothing exists that could spend.
        assert "rxd" not in built

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_without_a_fee_utxo_it_refuses_up_front_naming_the_flags(self, name, tmp_path, monkeypatch):
        """The gap #520 named: this path used to reach _NoFeeSource and raise from inside the
        transaction builder, which reads like a crash rather than a missing flag."""
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, _io = _eth_scenario(mod, tmp_path, role="maker", with_funding=False)
            _wire_eth(mod, monkeypatch)
        else:
            args, _terms, _io = _btc_scenario(mod, tmp_path, role="maker", with_funding=False)
            _wire_btc(mod, monkeypatch)
        with pytest.raises(SystemExit, match="--fee-txid"):
            await mod.maker_phase_abort(args)

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_a_covenant_the_envelope_does_not_describe_is_refused(self, name, tmp_path, monkeypatch):
        mod = _load(name)
        if name == "eth_swap_two_host":
            args, _terms, io_dir = _eth_scenario(mod, tmp_path, role="maker", with_funding=False)
            built = _wire_eth(mod, monkeypatch)
        else:
            args, _terms, io_dir = _btc_scenario(mod, tmp_path, role="maker", with_funding=False)
            built = _wire_btc(mod, monkeypatch)
        env = json.loads((io_dir / "envelope.json").read_text())
        env["covenant_spk_hex"] = "00" * 32
        (io_dir / "envelope.json").write_text(json.dumps(env))
        with pytest.raises(SystemExit, match="does not match"):
            await mod.maker_phase_abort(_with_fee(args))
        assert "rxd" not in built


# ---------------------------------------------------------------------------
# 5. The re-derivation both roles depend on
# ---------------------------------------------------------------------------


class TestBothRolesReDeriveTheSameCovenant:
    """The trust anchor: the recovery phases spend/inspect the covenant they re-derive from the
    terms they agreed to, never a hex string the envelope carries. That derivation is now one
    function rather than a shape copied at four sites, so it is worth one round-trip test."""

    def test_eth(self, eth_mod, tmp_path):
        args, terms, io_dir = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        env = json.loads((io_dir / "envelope.json").read_text())
        local = json.loads(Path(args.local_out).read_text())
        cov = eth_mod._rederive_covenant(
            args,
            terms=terms,
            taker_pkh=bytes.fromhex(local["taker_pkh_hex"]),
            maker_pkh=bytes.fromhex(env["maker_pkh_hex"]),
        )
        assert cov.funded_spk.hex() == env["covenant_spk_hex"]

    def test_btc(self, btc_mod, tmp_path):
        args, terms, io_dir = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        env = json.loads((io_dir / "envelope.json").read_text())
        local = json.loads(Path(args.local_out).read_text())
        cov = btc_mod._rederive_covenant(
            args,
            terms=terms,
            taker_pkh=bytes.fromhex(local["taker_pkh_hex"]),
            maker_pkh=bytes.fromhex(env["maker_pkh_hex"]),
        )
        assert cov.funded_spk.hex() == env["covenant_spk_hex"]

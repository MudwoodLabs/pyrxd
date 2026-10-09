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
import dataclasses
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
from pyrxd.eth_wallet.events import function_selector
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
        # Two properties of the REAL leg that the phases under test are built around, kept here so
        # the fixture is a situation that can actually occur rather than a permissive stand-in:
        #  1. it dispenses a fee input before it can build anything, so a phase wired with
        #     _NoFeeSource fails here rather than silently "refunding";
        #  2. its P3 maturity self-check refuses a non-final CSV refund (radiant_leg.refund_asset:
        #     "needs N confirmations, has M"). Without this the taker-refund pre-check could be
        #     deleted and the fake would happily "refund" an immature covenant.
        self.fee_source.next_fee_input()
        if self._confs < record.terms.t_rxd.value:
            raise NetworkError(
                f"covenant CSV refund is not yet mature: needs {record.terms.t_rxd.value} "
                f"confirmations, has {self._confs}"
            )
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

    # The reads the ETH taker's --phase refund pre-check makes (#850 PR R): an honest, unsettled
    # contract with no claim in its logs. Subclasses below model the other answers.
    async def is_settled(self, locator) -> bool:
        return False

    async def observed_claim_tx(self, locator):
        return None


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


def _eth_scenario(
    mod,
    tmp_path: Path,
    *,
    role: str,
    with_funding: bool,
    with_claim: bool = False,
    preimage: bytes | None = None,
    **over,
):
    io_dir = tmp_path / "swapdir"
    io_dir.mkdir()
    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    # `preimage` lets a test play the maker's reveal: the scenario's H is then sha256(preimage).
    h = hashlib.sha256(preimage if preimage is not None else os.urandom(32)).digest()
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


def _btc_scenario(
    mod,
    tmp_path: Path,
    *,
    role: str,
    with_funding: bool,
    with_claim: bool = False,
    preimage: bytes | None = None,
    **over,
):
    io_dir = tmp_path / "btc_swapdir"
    io_dir.mkdir()
    taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
    taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
    maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
    taker_btc_refund = generate_keypair("bcrt")
    maker_btc_claim = coincurve.PrivateKey(os.urandom(32))
    refund_xonly = mod._xonly_of(taker_btc_refund._privkey.unsafe_raw_bytes())
    claim_xonly = mod._xonly_of(maker_btc_claim.secret)
    h = hashlib.sha256(preimage if preimage is not None else os.urandom(32)).digest()
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


def _wire_eth(mod, monkeypatch, *, covenant_confs=10_000, covenant_funded=True, now_ts=1_900_000_000, counter_leg=None):
    """Replace ONLY the chain-leg constructors. The coordinator, the FSM, the role guard and the
    margin policy stay the shipped ones, built by the harness's own ``_coordinator``."""
    built: dict[str, object] = {}

    def _fake_radiant(args, *, taker_pkh, maker_pkh, fee_source):
        leg = _FakeRadiantLeg(fee_source=fee_source, confs=covenant_confs, funded=covenant_funded)
        built["rxd"] = leg
        return leg

    def _fake_eth(args, *, claim_to, refund_to, eth_timeout):
        rpc, leg = _FakeEthRpc(now_ts), (counter_leg if counter_leg is not None else _FakeCounterLeg())
        built["rpc"], built["counter"] = rpc, leg
        return rpc, leg

    monkeypatch.setattr(mod, "_radiant_leg", _fake_radiant)
    monkeypatch.setattr(mod, "_eth_leg", _fake_eth)
    return built


def _wire_btc(mod, monkeypatch, *, covenant_confs=10_000, covenant_funded=True, btc_confs=10_000, counter_leg=None):
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
        leg = counter_leg if counter_leg is not None else _FakeCounterLeg(confs=btc_confs)
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


class TestTakerRefundOnEthRefundsOnlyTheTakersLeg:
    """#850, ETH: the taker's ``--phase refund`` refunds the ETH HTLC and never the covenant. The
    covenant refund pays the MAKER; sent from the taker's side after the maker claimed the ETH with
    p, it takes away the taker's claim on the covenant. The record stays BOTH_LOCKED."""

    async def test_eth_refund_refunds_the_counter_leg_and_not_the_covenant(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch)
        await eth_mod.taker_phase_refund(args)  # no --fee-*: it is not needed any more
        assert len(built["counter"].refund_calls) == 1
        assert built["rxd"].refund_calls == [], "the taker's refund phase spent the maker's covenant"
        assert built["rpc"].closed

    async def test_eth_refund_cannot_spend_the_covenant_even_with_a_fee_utxo(self, eth_mod, tmp_path, monkeypatch):
        """Not "we did not call it" — the leg is structurally incapable, as in --phase abort."""
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch)
        await eth_mod.taker_phase_refund(_with_fee(args))
        assert isinstance(built["rxd"].fee_source, eth_mod._NoFeeSource)
        assert built["rxd"].refund_calls == []

    async def test_an_immature_covenant_no_longer_blocks_the_takers_own_eth_refund(
        self, eth_mod, tmp_path, monkeypatch
    ):
        """The honest path for the gate this replaced: the covenant's CSV maturity was checked only
        because the phase used to send the covenant refund too. Refusing the taker's own matured ETH
        refund on the covenant's clock would be a guard refusing valid work."""
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch, covenant_confs=1)  # t_rxd is 120
        await eth_mod.taker_phase_refund(args)
        assert len(built["counter"].refund_calls) == 1
        assert built["rxd"].refund_calls == []

    async def test_an_unverifiable_covenant_refuses_rather_than_guessing(self, eth_mod, tmp_path, monkeypatch):
        """ "Not funded" and "the node cannot answer" are the SAME exception from find_covenant_utxo.
        The phase pins the covenant outpoint in a BOTH_LOCKED record, so it must not guess."""
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_eth(eth_mod, monkeypatch, covenant_funded=False)
        with pytest.raises(SystemExit, match="cannot tell those apart"):
            await eth_mod.taker_phase_refund(args)
        assert built["counter"].refund_calls == []


class _ClaimedEthCounterLeg(_FakeCounterLeg):
    """The ETH HTLC after the maker claimed it, as the REAL leg reports it.

    ``EthHtlcContractLeg.refund`` preflights with ``eth_call``; against a claimed contract that
    reverts ``AlreadySettled()`` and ``EthRpc.preflight`` raises a ``ValidationError`` whose text is
    "tx would revert (preflight eth_call): " plus web3's rendering of the custom error — the 4-byte
    selector, not a name. The claim itself is readable from the contract's logs.
    """

    def __init__(
        self,
        preimage: bytes | None,
        *,
        claim_tx: str | None = "0x" + "55" * 32,
        settled: bool = True,
        lands_after_precheck: bool = False,
    ):
        super().__init__()
        self._p = preimage
        self._claim_tx = claim_tx
        self._settled = settled
        # The race the runner's pre-check cannot close: the contract is unsettled with no claim when
        # --phase refund reads it, and the maker's claim lands before the refund's own preflight. The
        # reads answer "unsettled, no claim" until the refund is attempted, then the configured values.
        self._lands_after_precheck = lands_after_precheck
        self.provenance_checked: list[str] = []

    def _not_yet(self) -> bool:
        return self._lands_after_precheck and not self.refund_calls

    async def refund(self, locator, timeout=None) -> str:
        self.refund_calls.append(locator)
        sel = "0x" + function_selector("AlreadySettled()").hex()
        raise ValidationError(f"tx would revert (preflight eth_call): ('{sel}', '{sel}')")

    async def observed_claim_tx(self, locator):
        return None if self._not_yet() else self._claim_tx

    async def is_settled(self, locator) -> bool:
        return False if self._not_yet() else self._settled

    async def fetch_claim_artifacts(self, tx_hash):
        return [b"\x00\x00\x00\x00" + self._p]

    def scrape_secret(self, artifacts, hashlock) -> bytes:
        from pyrxd.eth_wallet.secret import recover_secret

        return recover_secret(artifacts, hashlock)

    async def assert_claim_provenance(self, tx_hash, *, contract_address, preimage) -> None:
        self.provenance_checked.append(tx_hash)


def _wire_eth_claimed(mod, monkeypatch, leg, *, now_ts=1_900_000_000):
    built: dict[str, object] = {"counter": leg}

    def _fake_radiant(args, *, taker_pkh, maker_pkh, fee_source):
        rxd = _FakeRadiantLeg(fee_source=fee_source)
        built["rxd"] = rxd
        return rxd

    def _fake_eth(args, *, claim_to, refund_to, eth_timeout):
        rpc = _FakeEthRpc(now_ts)
        built["rpc"] = rpc
        return rpc, leg

    monkeypatch.setattr(mod, "_radiant_leg", _fake_radiant)
    monkeypatch.setattr(mod, "_eth_leg", _fake_eth)
    return built


class TestTakerEthRefundSaysWhatHappenedWhenItFails:
    """#850 review: the real leg's failure for "the maker claimed" is a bare preflight revert, the
    same text as "your refund already landed". The phase must tell the operator which.

    Since #850 PR R the phase refuses BEFORE the refund when the contract already reads settled or
    claimed (``TestTakerEthRefundPreCheck``). The coordinator's failure-time explanation still
    matters for the race that pre-check cannot close: the claim lands between the pre-check and the
    refund's preflight. These tests drive that race (``lands_after_precheck``)."""

    async def test_maker_already_claimed_names_the_claim_and_the_claim_phase(self, eth_mod, tmp_path, monkeypatch):
        p = os.urandom(32)
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True, preimage=p)
        leg = _ClaimedEthCounterLeg(p, lands_after_precheck=True)
        built = _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_refund(args)
        msg = str(raised.value)
        assert "MAKER CLAIMED" in msg and "0x" + "55" * 32 in msg, msg
        assert "--phase claim" in msg and "t_rxd" in msg, msg
        assert leg.provenance_checked == ["0x" + "55" * 32], "the claim was not verified before being reported"
        assert built["rxd"].refund_calls == []

    async def test_a_real_claim_hidden_by_the_logs_exits_non_zero_and_never_says_done(
        self, eth_mod, tmp_path, monkeypatch, capsys
    ):
        """The #851 re-review probe through the runner: the maker really claimed (settled), but the
        one endpoint withholds the claim log or forges a Refunded(). The phase used to print "done"
        and exit 0 right after confirming the covenant was unspent; the taker stopped and the maker
        kept both legs. It must exit non-zero with the check and the claim steps."""
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        # The leg's log scan finds no claim (withheld; a forged Refunded() reads the same through the
        # real scan — that half is tested through the shipped EthLeg in
        # test_taker_mutual_refund_leaves_covenant.py) while storage says settled.
        leg = _ClaimedEthCounterLeg(None, claim_tx=None, settled=True, lands_after_precheck=True)
        built = _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_refund(args)
        assert len(leg.refund_calls) == 1, "the race case: the pre-check passed and the refund was attempted"
        assert raised.value.code not in (None, 0), "the phase exited 0: the operator would stop here"
        msg = str(raised.value.code)
        assert "ALREADY SETTLED" in msg and "does not mean it was refunded" in msg, msg
        assert "maker_claim.json" in msg and "--phase claim" in msg and "t_rxd" in msg, msg
        assert "0x" + "33" * 20 in msg  # the contract to check
        assert "done" not in capsys.readouterr().out.lower()
        assert built["rxd"].refund_calls == []

    async def test_claim_phase_finds_the_claim_on_the_contract_without_maker_claim_json(
        self, eth_mod, tmp_path, monkeypatch
    ):
        p = os.urandom(32)
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True, preimage=p)
        assert not (Path(args.io) / "maker_claim.json").exists()

        class _Stop(Exception):
            pass

        class _Leg(_ClaimedEthCounterLeg):
            async def assert_claim_provenance(self, tx_hash, *, contract_address, preimage) -> None:
                self.provenance_checked.append(tx_hash)
                raise _Stop  # far enough: the discovered hash reached the verified reveal

        leg = _Leg(p, claim_tx="0x" + "66" * 32)
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(_Stop):
            await eth_mod.taker_phase_claim(_with_fee(args))
        assert leg.provenance_checked == ["0x" + "66" * 32]

    async def test_claim_phase_without_maker_claim_json_or_a_claim_refuses_clearly(
        self, eth_mod, tmp_path, monkeypatch
    ):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        _wire_eth_claimed(eth_mod, monkeypatch, _ClaimedEthCounterLeg(None, claim_tx=None, settled=False))
        with pytest.raises(SystemExit, match="no claim found in the logs") as raised:
            await eth_mod.taker_phase_claim(_with_fee(args))
        msg = str(raised.value.code)
        assert "NOT proof" in msg and "t_rxd = 120" in msg and "eth_claim_tx_hash" in msg, msg


class TestTakerRefundOnBtcIsStillTheMutualUnwind:
    """#850 interim, BTC: unchanged in this release, so these pin the OLD behaviour on purpose. On
    BTC the taker's run still sends the covenant refund — the same race is open there — until the
    watchtower can tell the taker's own BTC refund from a maker claim. When that lands, the first
    test here must fail and be rewritten to the ETH shape above."""

    async def test_btc_refund_still_unwinds_both_legs(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_btc(btc_mod, monkeypatch)
        await btc_mod.taker_phase_refund(_with_fee(args))
        assert len(built["counter"].refund_calls) == 1
        assert len(built["rxd"].refund_calls) == 1

    async def test_an_immature_covenant_refuses_BEFORE_the_counter_leg_is_broadcast(
        self, btc_mod, tmp_path, monkeypatch
    ):
        """mutual_refund broadcasts the counter leg FIRST. Calling it while the covenant's CSV is
        immature refunds the counter leg, fails on the asset, and leaves the record stuck at
        BOTH_LOCKED — so the shortfall has to be caught before anything is broadcast at all."""
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_btc(btc_mod, monkeypatch, covenant_confs=119)  # t_rxd is 120
        with pytest.raises(SystemExit, match="NOT yet mature"):
            await btc_mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == [], "nothing may broadcast before the shortfall check"
        assert built["rxd"].refund_calls == []

    async def test_the_refusal_points_at_the_phase_that_still_works(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        _wire_btc(btc_mod, monkeypatch, covenant_confs=1)
        with pytest.raises(SystemExit, match="--phase abort"):
            await btc_mod.taker_phase_refund(_with_fee(args))

    async def test_an_unverifiable_covenant_refuses_rather_than_guessing(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        built = _wire_btc(btc_mod, monkeypatch, covenant_funded=False)
        with pytest.raises(SystemExit, match="cannot tell those apart"):
            await btc_mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == []

    async def test_without_a_fee_utxo_it_refuses_up_front_naming_the_flags(self, btc_mod, tmp_path, monkeypatch):
        args, _terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        _wire_btc(btc_mod, monkeypatch)
        with pytest.raises(SystemExit, match="--fee-txid"):
            await btc_mod.taker_phase_refund(args)


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


# ---------------------------------------------------------------------------
# 6. The persisted record survives every phase, and a disagreement refuses (#850 PR R)
# ---------------------------------------------------------------------------
#
# Before PR R every recovery phase built a FRESH record from the exchange files, and the coordinator
# persisted it over `<local_out>.swaprec.json`, dropping whatever an earlier phase had saved (#850
# review B1). These drive the RUNNER ENTRY POINTS: each run loads a fresh copy of the script module,
# and the record is read back from disk through a new sink after every run.

#: What the fake Radiant leg reports for the covenant (`_FakeRadiantLeg.find_covenant_utxo`).
_FAKE_COVENANT_OUTPOINT = "cc" * 32 + ":0"

_OVERRIDE_STATEMENT = "single-operator depth accepted up to 5 RXD by user override (default 1 RXD)"


def _record_path(args) -> Path:
    return Path(str(Path(args.local_out).expanduser()) + ".swaprec.json")


def _read_back(args):
    """The record as a NEW process would see it: a new sink, reading the file."""
    from pyrxd.gravity.record_sink import JsonFileRecordSink

    return JsonFileRecordSink(_record_path(args)).load_record()


def _exchange_locator(io_dir: Path, *, eth: bool):
    doc = json.loads((io_dir / "taker_funding.json").read_text())
    if eth:
        from pyrxd.eth_wallet.locator import EthHtlcLocator

        return EthHtlcLocator.from_dict(doc["eth_locator"])
    return bt.BtcHtlcLocator.from_dict(doc["btc_locator"])


async def _seed(args, record) -> None:
    """Write a record the way the coordinator does: through the real sink."""
    from pyrxd.gravity.record_sink import JsonFileRecordSink

    await JsonFileRecordSink(_record_path(args))(record)


def _seeded_record(terms, io_dir: Path, *, eth: bool, state: SwapState, pending: bool = True):
    """The record an earlier phase of this host left behind, holding every field scenario 19 names.

    FIXTURE NOTE: on ETH this carries the funded locator AND the pending deploy/push handles of the
    same contract. Today's coordinator clears the pending handles when it attaches the locator
    (``SwapRecord.with_counter_lock``), and PR 3 of the #850 plan keeps the push handles beside the
    locator, so this exact combination is not one a 0.26.x run writes. It is the superset: the merge
    must carry whatever the record holds, and a field it drops fails here."""
    from pyrxd.gravity.swap_state import SwapRecord

    loc = _exchange_locator(io_dir, eth=eth)
    env = json.loads((io_dir / "envelope.json").read_text())
    rec = (
        SwapRecord(state=state, terms=terms)
        .with_counter_lock(loc)
        .with_radiant_lock(_FAKE_COVENANT_OUTPOINT, env["covenant_spk_hex"])
    )
    extra: dict[str, object] = {"single_operator_override": _OVERRIDE_STATEMENT}
    if eth and pending:
        extra.update(
            pending_counter_contract=loc.contract_address,
            pending_counter_deploy_tx=loc.deploy_tx_hash,
            pending_push_nonce=7,
            pending_push_tx_hash="0x" + "77" * 32,
        )
    return dataclasses.replace(rec, **extra)


def _kept_fields(rec) -> dict:
    """Every field but ``state``, in wire form: what must survive a phase."""
    d = rec.to_dict()
    d.pop("state")
    return d


#: (script, role, phase, the persisted state before run 1, the state the phase persists). Each
#: persists through the coordinator. Run 2 starts from what run 1 persisted, so the second run of
#: each is a same-state run or a retry: a claim from SECRET_REVEALED, a lock-claim from BTC_LOCKED,
#: an abort or refund re-run from the terminal state its broadcast wrote.
_PERSISTING_PHASES = [
    ("eth_swap_two_host", "taker", "claim", SwapState.BTC_LOCKED, SwapState.SECRET_REVEALED),
    ("eth_swap_two_host", "taker", "abort", SwapState.BTC_LOCKED, SwapState.ABORTED),
    ("eth_swap_two_host", "maker", "lock-claim", SwapState.BOTH_LOCKED, SwapState.BTC_LOCKED),
    ("eth_swap_two_host", "maker", "refund", SwapState.BOTH_LOCKED, SwapState.ASSET_REFUNDED_TAKER_ACTS),
    ("btc_swap_two_host", "taker", "claim", SwapState.BTC_LOCKED, SwapState.SECRET_REVEALED),
    ("btc_swap_two_host", "taker", "abort", SwapState.BTC_LOCKED, SwapState.ABORTED),
    ("btc_swap_two_host", "taker", "refund", SwapState.BOTH_LOCKED, SwapState.MUTUAL_REFUND),
    ("btc_swap_two_host", "maker", "lock-claim", SwapState.BOTH_LOCKED, SwapState.BTC_LOCKED),
    ("btc_swap_two_host", "maker", "refund", SwapState.BOTH_LOCKED, SwapState.ASSET_REFUNDED_TAKER_ACTS),
]


class _Stop(Exception):
    """Ends a long phase right after the coordinator step under test has persisted."""


class _RevealAndFundingLeg(_FakeCounterLeg):
    """A counter leg for the claim and lock-claim phases: the maker's reveal verifies (sha256(p) == H,
    provenance recorded), and the maker's verification of the taker's funding returns the funded
    locator. Unsettled, with no claim in the logs, for the refund pre-check."""

    def __init__(self, preimage: bytes, locator) -> None:
        super().__init__()
        self._p = preimage
        self._loc = locator
        self.provenance_checked: list[str] = []

    async def fetch_claim_artifacts(self, tx_hash):
        return [b"\x00\x00\x00\x00" + self._p]

    def scrape_secret(self, claim, hashlock) -> bytes:
        return self._p

    async def assert_claim_provenance(self, tx_hash, *, contract_address, preimage) -> None:
        self.provenance_checked.append(tx_hash)

    async def verify_counterparty_funded(self, ref, terms, **kw):
        return self._loc


def _btc_claim_tx(locator) -> bytes:
    """A minimal legacy transaction spending the HTLC funding outpoint: what the coordinator's
    provenance check parses (the inputs). The witness is not read: the fake leg returns p."""
    return (
        b"\x02\x00\x00\x00"
        + b"\x01"
        + locator.funding_outpoint.prevout_bytes()
        + b"\x00"
        + b"\xfd\xff\xff\xff"
        + b"\x01"
        + (1_000).to_bytes(8, "little")
        + b"\x00"
        + b"\x00\x00\x00\x00"
    )


def _phase_scenario(name: str, tmp_path: Path, *, role: str, phase: str):
    """The scenario a phase needs, plus the counter leg and the step that ends it (or None)."""
    eth = name == "eth_swap_two_host"
    p = os.urandom(32)
    scenario = _eth_scenario if eth else _btc_scenario
    args, terms, io_dir = scenario(_load(name), tmp_path, role=role, with_funding=True, preimage=p)
    leg, stop_at = None, None
    if phase in ("claim", "lock-claim"):
        leg = _RevealAndFundingLeg(p, _exchange_locator(io_dir, eth=eth))
    if phase == "claim":
        stop_at = "resolve_asset_locked_at_height"  # right after taker_observed_reveal persisted
        if eth:
            (io_dir / "maker_claim.json").write_text(json.dumps({"eth_claim_tx_hash": "0x" + "55" * 32}))
        else:
            claim = _btc_claim_tx(_exchange_locator(io_dir, eth=False)).hex()
            (io_dir / "maker_claim.json").write_text(json.dumps({"btc_claim_tx_hex": claim}))
    if phase == "lock-claim":
        stop_at = "wait_for_covenant_via_leg"  # right after maker_verify_counter_funding persisted
        local = json.loads(Path(args.local_out).read_text())
        local["preimage_p_hex"] = p.hex()
        Path(args.local_out).write_text(json.dumps(local))
    return args, terms, io_dir, leg, stop_at


async def _run_phase(name: str, args, monkeypatch, *, role: str, phase: str, counter_leg=None, stop_at=None):
    """Run one phase through the runner's own dispatch table, in a FRESH copy of the module."""
    mod = _load(name)
    wire = _wire_eth if name == "eth_swap_two_host" else _wire_btc
    built = wire(mod, monkeypatch, counter_leg=counter_leg)
    _wire_rxd_height(mod, monkeypatch, tip=1_120, locked_at=1_000)  # t_rxd 120 => matured exactly
    if stop_at is not None:

        async def _stop(*_a, **_k):
            raise _Stop

        monkeypatch.setattr(mod, stop_at, _stop)
    try:
        await mod._DISPATCH[(role, phase)](_with_fee(argparse.Namespace(**vars(args))))
    except _Stop:
        assert stop_at is not None
    return built


class TestEveryPhaseKeepsThePersistedRecord:
    """Scenario 19 (#850 PR R): each phase that persists, run twice, keeps every field the record holds."""

    @pytest.mark.parametrize(("name", "role", "phase", "start", "lands_in"), _PERSISTING_PHASES)
    async def test_run_twice_and_every_field_survives(self, name, role, phase, start, lands_in, tmp_path, monkeypatch):
        eth = name == "eth_swap_two_host"
        args, terms, io_dir, leg, stop_at = _phase_scenario(name, tmp_path, role=role, phase=phase)
        # The maker's lock-claim re-attaches the verified locator through `with_counter_lock`, which
        # clears pending handles by design; a maker record never holds them anyway.
        seeded = _seeded_record(terms, io_dir, eth=eth, state=start, pending=phase != "lock-claim")
        await _seed(args, seeded)
        before = _kept_fields(_read_back(args))
        assert before == _kept_fields(seeded), "the fixture did not round-trip through the sink"
        assert before["radiant_covenant_outpoint"] == _FAKE_COVENANT_OUTPOINT
        assert before["single_operator_override"] == _OVERRIDE_STATEMENT
        if eth and phase != "lock-claim":
            assert before["pending_push_nonce"] == 7 and before["pending_counter_contract"]

        for run in (1, 2):
            await _run_phase(name, args, monkeypatch, role=role, phase=phase, counter_leg=leg, stop_at=stop_at)
            after = _read_back(args)
            assert after.state is lands_in, f"run {run}: the phase did not persist ({after.state.value})"
            assert _kept_fields(after) == before, f"run {run}: the phase dropped persisted fields"

    async def test_the_outpoint_one_phase_persisted_is_the_one_the_next_phase_spends(self, tmp_path, monkeypatch):
        """The maker's lock-claim pins the covenant outpoint it verified; its later --phase refund must
        spend THAT outpoint. The refund leg receives the coordinator's record, so this reads what the
        next phase actually drove, not only what it wrote."""
        from pyrxd.gravity.swap_state import SwapRecord

        name = "eth_swap_two_host"
        args, terms, io_dir = _eth_scenario(_load(name), tmp_path, role="maker", with_funding=True)
        spk = json.loads((io_dir / "envelope.json").read_text())["covenant_spk_hex"]
        pinned = "dd" * 32 + ":1"
        lock_claim_left = (
            SwapRecord(state=SwapState.BOTH_LOCKED, terms=terms)
            .with_counter_lock(_exchange_locator(io_dir, eth=True))
            .with_radiant_lock(pinned, spk)
        )
        await _seed(args, lock_claim_left)
        built = await _run_phase(name, args, monkeypatch, role="maker", phase="refund")
        assert len(built["rxd"].refund_calls) == 1
        assert built["rxd"].refund_calls[0].radiant_covenant_outpoint == pinned
        assert _read_back(args).radiant_covenant_outpoint == pinned


class TestADisagreementRefusesAndSendsNothing:
    """A binding field (terms, hashlock, the counter-leg contract, the covenant) that differs between
    the persisted record and what a phase rebuilt REFUSES: nothing is broadcast and the file is left
    as it was. The survival tests above are the honest-path pair: same fields, equal values."""

    async def test_eth_taker_abort_refuses_a_different_counter_contract(self, eth_mod, tmp_path, monkeypatch):
        from pyrxd.gravity.swap_state import SwapRecord

        args, terms, io_dir = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        other = dataclasses.replace(_exchange_locator(io_dir, eth=True), contract_address="0x" + "99" * 20)
        await _seed(args, SwapRecord(state=SwapState.BTC_LOCKED, terms=terms).with_counter_lock(other))
        before = _record_path(args).read_bytes()
        built = _wire_eth(eth_mod, monkeypatch)
        with pytest.raises(SystemExit, match="disagree on counterchain_locator") as raised:
            await eth_mod.taker_phase_abort(args)
        assert "Nothing was sent" in str(raised.value.code)
        assert built["counter"].refund_calls == []
        assert _record_path(args).read_bytes() == before

    async def test_eth_taker_abort_refuses_a_pending_contract_that_is_not_the_funded_one(
        self, eth_mod, tmp_path, monkeypatch
    ):
        from pyrxd.gravity.swap_state import SwapRecord

        args, terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        await _seed(
            args,
            SwapRecord(
                state=SwapState.NEGOTIATED,
                terms=terms,
                pending_counter_contract="0x" + "98" * 20,
                pending_counter_deploy_tx="0x" + "97" * 32,
                fund_refusal="the taker gate refused",
            ),
        )
        built = _wire_eth(eth_mod, monkeypatch)
        with pytest.raises(SystemExit, match="counter-leg contract"):
            await eth_mod.taker_phase_abort(args)
        assert built["counter"].refund_calls == []

    async def test_btc_taker_refund_refuses_a_different_covenant_outpoint(self, btc_mod, tmp_path, monkeypatch):
        args, terms, io_dir = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        seeded = _seeded_record(terms, io_dir, eth=False, state=SwapState.BOTH_LOCKED)
        await _seed(args, dataclasses.replace(seeded, radiant_covenant_outpoint="ee" * 32 + ":3"))
        built = _wire_btc(btc_mod, monkeypatch)
        with pytest.raises(SystemExit, match="disagree on radiant_covenant_outpoint"):
            await btc_mod.taker_phase_refund(_with_fee(args))
        assert built["counter"].refund_calls == [] and built["rxd"].refund_calls == []

    async def test_eth_maker_lock_claim_refuses_different_terms_under_the_same_hashlock(
        self, eth_mod, tmp_path, monkeypatch
    ):
        p = os.urandom(32)
        args, terms, io_dir = _eth_scenario(eth_mod, tmp_path, role="maker", with_funding=True, preimage=p)
        local = json.loads(Path(args.local_out).read_text())
        local["preimage_p_hex"] = p.hex()  # lock-claim checks the maker's local p against H first
        Path(args.local_out).write_text(json.dumps(local))
        seeded = _seeded_record(terms, io_dir, eth=True, state=SwapState.BOTH_LOCKED)
        changed = dataclasses.replace(terms, radiant_amount=terms.radiant_amount + 1)
        await _seed(args, dataclasses.replace(seeded, terms=changed))
        built = _wire_eth(eth_mod, monkeypatch)
        with pytest.raises(SystemExit, match="disagree on terms"):
            await eth_mod.maker_phase_lock_claim(_with_fee(args))
        assert built["counter"].refund_calls == []

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_a_record_for_a_different_swap_refuses_the_maker_abort(self, name, tmp_path, monkeypatch):
        from pyrxd.gravity.swap_state import SwapRecord

        mod = _load(name)
        scenario = _eth_scenario if name == "eth_swap_two_host" else _btc_scenario
        args, terms, _io = scenario(mod, tmp_path, role="maker", with_funding=False)
        other = dataclasses.replace(terms, hashlock=hashlib.sha256(b"another swap").digest())
        await _seed(args, SwapRecord(state=SwapState.NEGOTIATED, terms=other))
        built = _wire_eth(mod, monkeypatch) if name == "eth_swap_two_host" else _wire_btc(mod, monkeypatch)
        with pytest.raises(SystemExit, match="different swaps"):
            await mod.maker_phase_abort(_with_fee(args))
        assert "counter" not in built and "rxd" not in built, "refused after a leg was built"


class TestTheMergeHelperOnItsOwn:
    """``merge_with_persisted_record`` as ``dust_swap_resume.py`` uses it (no two-host phase around it)."""

    def _merge(self, sink_path: Path, rebuilt):
        sys.path.insert(0, str(_SCRIPTS))
        from _dust_swap_shared import merge_with_persisted_record

        from pyrxd.gravity.record_sink import JsonFileRecordSink

        return merge_with_persisted_record(
            JsonFileRecordSink(sink_path), rebuilt, source="the test's rebuild", role="none", phase="resume"
        )

    async def test_no_record_returns_the_rebuild_unchanged(self, btc_mod, tmp_path):
        from pyrxd.gravity.swap_state import SwapRecord

        _args, terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        rebuilt = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms)
        assert self._merge(tmp_path / "none.swaprec.json", rebuilt) is rebuilt

    async def test_a_btc_locator_rebuilt_from_the_chain_equals_the_persisted_one(self, btc_mod, tmp_path):
        """The resume rebuilds the locator with ``build_htlc(...).with_funding(...)``; the forward run
        persisted the one its leg returned. Equal content must merge, or every resume would refuse."""
        from pyrxd.gravity.swap_state import SwapRecord

        args, terms, io_dir = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        persisted_loc = _exchange_locator(io_dir, eth=False)
        await _seed(args, SwapRecord(state=SwapState.BTC_LOCKED, terms=terms).with_counter_lock(persisted_loc))
        fresh = bt.build_htlc(
            hashlock=terms.hashlock,
            claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
            refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
            timeout=terms.t_btc,
            network="bcrt",
        ).with_funding(bt.BtcOutpoint("ab" * 32, 0), 100_000)
        rebuilt = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms).with_counter_lock(fresh)
        merged = self._merge(_record_path(args), rebuilt)
        assert merged.counterchain_locator.to_dict() == persisted_loc.to_dict()

    async def test_an_unreadable_record_refuses(self, btc_mod, tmp_path):
        from pyrxd.gravity.swap_state import SwapRecord

        _args, terms, _io = _btc_scenario(btc_mod, tmp_path, role="taker", with_funding=True)
        torn = tmp_path / "torn.swaprec.json"
        torn.write_text('{"state": "btc_lo')
        with pytest.raises(SystemExit, match="could not be read"):
            self._merge(torn, SwapRecord(state=SwapState.BTC_LOCKED, terms=terms))


# ---------------------------------------------------------------------------
# 7. The ETH taker's --phase refund pre-check (#850 PR R, Mythos M1)
# ---------------------------------------------------------------------------


class TestTakerEthRefundPreCheck:
    """Refuses when the HTLC is settled or a claim is found in its logs; never concludes "refunded"."""

    async def test_a_claim_in_the_logs_refuses_and_names_the_claim_phase(self, eth_mod, tmp_path, monkeypatch, capsys):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        leg = _ClaimedEthCounterLeg(os.urandom(32))
        built = _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_refund(args)
        msg = str(raised.value.code)
        assert msg.startswith("REFUSING to refund") and "0x" + "55" * 32 in msg, msg
        assert "not verified here" in msg and "--phase claim" in msg and "t_rxd = 120" in msg, msg
        assert "Nothing was sent" in msg, msg
        assert leg.refund_calls == [], "the refund was attempted against a claimed contract"
        assert built["rxd"].refund_calls == []
        assert "refunded" not in capsys.readouterr().out.lower()

    async def test_settled_with_no_claim_found_refuses_and_never_says_refunded(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        leg = _ClaimedEthCounterLeg(None, claim_tx=None, settled=True)
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_refund(args)
        msg = str(raised.value.code)
        assert "already SETTLED" in msg and "does not mean it was refunded" in msg, msg
        assert "maker_claim.json" in msg and "--phase claim" in msg and "0x" + "33" * 20 in msg, msg
        assert leg.refund_calls == []

    async def test_a_claim_on_an_unsettled_contract_still_refuses(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        leg = _ClaimedEthCounterLeg(os.urandom(32), settled=False)
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit, match="NOT settled"):
            await eth_mod.taker_phase_refund(args)
        assert leg.refund_calls == []

    async def test_it_runs_before_the_timeout_check(self, eth_mod, tmp_path, monkeypatch):
        """A claim before the ETH timeout is when the covenant claim is most urgent; the "has NOT
        timed out" refusal must not hide it."""
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        leg = _ClaimedEthCounterLeg(os.urandom(32))
        _wire_eth_claimed(eth_mod, monkeypatch, leg, now_ts=1_700_000_000)  # before the 1_800_000_000 timeout
        with pytest.raises(SystemExit, match="a claim of the ETH HTLC"):
            await eth_mod.taker_phase_refund(args)

    async def test_an_unreadable_settled_flag_refuses(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)

        class _Leg(_FakeCounterLeg):
            async def is_settled(self, locator) -> bool:
                raise NetworkError("eth_getStorageAt timed out")

        leg = _Leg()
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit, match="could not read whether"):
            await eth_mod.taker_phase_refund(args)
        assert leg.refund_calls == []

    async def test_unreadable_logs_on_an_unsettled_contract_do_not_block_the_refund(
        self, eth_mod, tmp_path, monkeypatch
    ):
        """The honest path: many endpoints cap or prune old logs, and an unsettled contract has no
        landed claim. A pre-check that refused here would block a valid refund."""
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)

        class _Leg(_FakeCounterLeg):
            async def observed_claim_tx(self, locator):
                raise NetworkError("eth_getLogs: block range too large")

        leg = _Leg()
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        await eth_mod.taker_phase_refund(args)
        assert len(leg.refund_calls) == 1


# ---------------------------------------------------------------------------
# 8. Every runner states its role (#850 D11)
# ---------------------------------------------------------------------------


def test_every_coordinator_config_a_script_builds_names_its_role():
    """Derived from the source: every ``CoordinatorConfig(...)`` call under scripts/ passes ``role=``.
    The two-host runners pass MAKER/TAKER; the single-process runners pass SINGLE_OPERATOR_ROLE."""
    calls: list[tuple[str, int, bool]] = []
    for path in sorted(_SCRIPTS.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name == "CoordinatorConfig":
                calls.append((path.name, node.lineno, any(k.arg == "role" for k in node.keywords)))
    found = {f for f, _line, _has in calls}
    # Non-vacuity: the six runners this rule was written for are all found.
    assert {
        "eth_swap_two_host.py",
        "btc_swap_two_host.py",
        "eth_swap_run.py",
        "eth_swap_grief_run.py",
        "dust_swap_run.py",
        "dust_swap_resume.py",
    } <= found, found
    missing = [f"{f}:{line}" for f, line, has_role in calls if not has_role]
    assert missing == [], f"CoordinatorConfig built without an explicit role= at {missing}"


# ---------------------------------------------------------------------------
# 9. The persisted state each phase may run on (#850 PR R, review F1)
# ---------------------------------------------------------------------------


def _shared():
    sys.path.insert(0, str(_SCRIPTS))
    import _dust_swap_shared

    return _dust_swap_shared


_P_PUBLIC = (SwapState.SECRET_REVEALED, SwapState.ASSET_VULNERABLE, SwapState.COMPLETED)


class TestThePhaseStateTable:
    def test_every_runner_phase_has_a_verdict_for_every_state(self, eth_mod, btc_mod):
        """Derived from ``SwapState`` and from the runners' own dispatch tables: a new state or a new
        phase without a verdict fails here instead of being allowed by default."""
        rules = _shared().PHASE_STATE_RULES
        assert set(rules) == set(eth_mod._DISPATCH) | set(btc_mod._DISPATCH) | {("none", "resume")}
        for key, row in rules.items():
            assert set(row) == set(SwapState), f"{key}: missing {set(SwapState) - set(row)}"
            assert {verdict for verdict, _why in row.values()} <= {"allow", "refuse", "n/a"}, key
            assert all(why for _verdict, why in row.values()), key

    def test_the_refusals_are_exactly_these(self):
        """Membership pinned: a change to WHICH combinations refuse must be made here on purpose.
        Terminal states are deliberately not refused yet (written at broadcast; PR 5b/9a)."""
        refused = {
            (role, phase, state)
            for (role, phase), row in _shared().PHASE_STATE_RULES.items()
            for state, (verdict, _why) in row.items()
            if verdict == "refuse"
        }
        expected = {("taker", phase, state) for phase in ("abort", "refund") for state in _P_PUBLIC}
        expected.add(("maker", "refund", SwapState.SECRET_REVEALED))
        assert refused == expected

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    def test_n_a_marks_exactly_the_phases_that_never_apply_the_rule(self, name):
        """Derived from each runner's source: a phase applies the rule iff its function calls
        ``_refuse_by_persisted_state`` with its own phase name. Those rows hold a real verdict for
        every state; the other rows are wholly ``n/a``. So a row cannot claim a check nobody runs,
        and a phase cannot apply a rule its row does not define."""
        mod = _load(name)
        fns = _functions_of(_SCRIPTS / f"{name}.py")
        rules = _shared().PHASE_STATE_RULES
        applied = set()
        for (role, phase), fn in mod._DISPATCH.items():
            for node in ast.walk(fns[fn.__name__]):
                if (
                    isinstance(node, ast.Call)
                    and getattr(node.func, "id", None) == "_refuse_by_persisted_state"
                    and any(k.arg == "phase" and getattr(k.value, "value", None) == phase for k in node.keywords)
                ):
                    applied.add((role, phase))
        assert applied, "the derivation found no phase applying the rule"
        for key in mod._DISPATCH:
            verdicts = {verdict for verdict, _why in rules[key].values()}
            if key in applied:
                assert "n/a" not in verdicts, key
            else:
                assert verdicts == {"n/a"}, key
        assert set(mod._DISPATCH) - applied == {("taker", "intro"), ("taker", "fund"), ("maker", "envelope")}

    def test_applying_an_n_a_row_raises(self):
        # The row raises before it reads the record's terms, so a state-only stand-in suffices.
        rec = argparse.Namespace(state=SwapState.BOTH_LOCKED, terms=None)
        with pytest.raises(ValueError, match="does not apply"):
            _shared().persisted_state_refusal("taker", "fund", rec)


class TestThePersistedStateGuardThroughTheRunners:
    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    @pytest.mark.parametrize("phase", ["abort", "refund"])
    @pytest.mark.parametrize("state", _P_PUBLIC)
    async def test_taker_recovery_refuses_once_p_is_public(self, name, phase, state, tmp_path, monkeypatch):
        """The probe that motivated it: a BTC taker --phase refund on SECRET_REVEALED or COMPLETED
        sent BOTH refunds, the maker-paying covenant refund included."""
        args, terms, io_dir, _leg, _stop = _phase_scenario(name, tmp_path, role="taker", phase=phase)
        await _seed(args, _seeded_record(terms, io_dir, eth=name == "eth_swap_two_host", state=state, pending=False))
        before = _record_path(args).read_bytes()
        mod = _load(name)
        wire = _wire_eth if name == "eth_swap_two_host" else _wire_btc
        built = wire(mod, monkeypatch)
        with pytest.raises(SystemExit) as raised:
            await mod._DISPATCH[("taker", phase)](_with_fee(args))
        msg = str(raised.value.code)
        assert f"says {state.value}" in msg and "--phase claim" in msg and "t_rxd = 120" in msg, msg
        assert "Nothing was sent" in msg, msg
        assert "counter" not in built and "rxd" not in built, "refused after a leg was built"
        assert _record_path(args).read_bytes() == before

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    @pytest.mark.parametrize("phase", ["abort", "refund"])
    async def test_before_maturity_the_claim_instruction_is_not_hidden(self, name, phase, tmp_path, monkeypatch):
        """Re-review MEDIUM: the guard used to run at the merge, AFTER the maturity and timeout checks,
        so a SECRET_REVEALED record with the covenant 5 of 120 deep got "not yet mature, retry at
        maturity" (BTC) or "Nothing is recoverable on the ETH leg yet" (ETH): the claim-before-t_rxd
        instruction only appeared once t_rxd had passed. It must come first, before any chain read."""
        eth = name == "eth_swap_two_host"
        args, terms, io_dir, _leg, _stop = _phase_scenario(name, tmp_path, role="taker", phase=phase)
        await _seed(args, _seeded_record(terms, io_dir, eth=eth, state=SwapState.SECRET_REVEALED, pending=False))
        mod = _load(name)
        if eth:
            built = _wire_eth(mod, monkeypatch, covenant_confs=5, now_ts=1_700_000_000)  # before the timeout
        else:
            built = _wire_btc(mod, monkeypatch, covenant_confs=5, btc_confs=5)  # neither CSV is mature
        with pytest.raises(SystemExit) as raised:
            await mod._DISPATCH[("taker", phase)](_with_fee(args))
        msg = str(raised.value.code)
        assert "--phase claim" in msg and "t_rxd = 120" in msg, msg
        assert "mature" not in msg and "Nothing is recoverable" not in msg, msg
        assert "counter" not in built and "rxd" not in built, "a leg was built before the refusal"

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    async def test_maker_refund_refuses_after_the_maker_revealed_p(self, name, tmp_path, monkeypatch):
        args, terms, io_dir, _leg, _stop = _phase_scenario(name, tmp_path, role="maker", phase="refund")
        seeded = _seeded_record(
            terms, io_dir, eth=name == "eth_swap_two_host", state=SwapState.SECRET_REVEALED, pending=False
        )
        await _seed(args, seeded)
        mod = _load(name)
        built = (_wire_eth if name == "eth_swap_two_host" else _wire_btc)(mod, monkeypatch)
        _wire_rxd_height(mod, monkeypatch, tip=1_120, locked_at=1_000)  # the stall window is open
        with pytest.raises(SystemExit, match="take both legs") as raised:
            await mod.maker_phase_refund(_with_fee(args))
        assert "--phase lock-claim" in str(raised.value.code)
        assert "counter" not in built and "rxd" not in built, "refused after a leg was built"

    @pytest.mark.parametrize("name", ["eth_swap_two_host", "btc_swap_two_host"])
    @pytest.mark.parametrize(
        ("role", "phase", "persisted", "lands_in"),
        [
            # A claim retry must rewind the reveal it already recorded.
            ("taker", "claim", SwapState.SECRET_REVEALED, SwapState.SECRET_REVEALED),
            ("taker", "claim", SwapState.ASSET_VULNERABLE, SwapState.SECRET_REVEALED),
            # A lock-claim retry after the maker's claim was sent (and may have been dropped).
            ("maker", "lock-claim", SwapState.SECRET_REVEALED, SwapState.BTC_LOCKED),
            # The maker's refund after a covenant mismatch.
            ("maker", "refund", SwapState.PARAMS_MISMATCH, SwapState.ASSET_REFUNDED_TAKER_ACTS),
            # Re-sending a refund whose broadcast already wrote the terminal state.
            ("taker", "abort", SwapState.ABORTED, SwapState.ABORTED),
            ("maker", "refund", SwapState.ASSET_REFUNDED_TAKER_ACTS, SwapState.ASSET_REFUNDED_TAKER_ACTS),
        ],
    )
    async def test_the_legitimate_retries_still_run(
        self, name, role, phase, persisted, lands_in, tmp_path, monkeypatch
    ):
        """The honest-path pair of the refusals above."""
        eth = name == "eth_swap_two_host"
        args, terms, io_dir, leg, stop_at = _phase_scenario(name, tmp_path, role=role, phase=phase)
        await _seed(args, _seeded_record(terms, io_dir, eth=eth, state=persisted, pending=False))
        await _run_phase(name, args, monkeypatch, role=role, phase=phase, counter_leg=leg, stop_at=stop_at)
        assert _read_back(args).state is lands_in

    async def test_btc_taker_refund_from_mutual_refund_re_sends(self, btc_mod, tmp_path, monkeypatch):
        """BTC's terminal MUTUAL_REFUND is written at broadcast: a dropped refund must be re-sendable."""
        args, terms, io_dir, _leg, _stop = _phase_scenario("btc_swap_two_host", tmp_path, role="taker", phase="refund")
        await _seed(args, _seeded_record(terms, io_dir, eth=False, state=SwapState.MUTUAL_REFUND, pending=False))
        built = await _run_phase("btc_swap_two_host", args, monkeypatch, role="taker", phase="refund")
        assert len(built["counter"].refund_calls) == 1
        assert _read_back(args).state is SwapState.MUTUAL_REFUND


# ---------------------------------------------------------------------------
# 10. The second door: ETH taker --phase abort sends the same refund (#850 PR R, review F2)
# ---------------------------------------------------------------------------


class TestTakerEthAbortHasTheSameChecks:
    async def test_a_claimed_htlc_refuses_before_the_refund(self, eth_mod, tmp_path, monkeypatch):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        leg = _ClaimedEthCounterLeg(os.urandom(32))
        built = _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_abort(args)
        msg = str(raised.value.code)
        assert msg.startswith("REFUSING to refund") and "--phase claim" in msg and "t_rxd = 120" in msg, msg
        assert leg.refund_calls == [] and built["rxd"].refund_calls == []

    async def test_a_claim_landing_after_the_pre_check_is_explained(self, eth_mod, tmp_path, monkeypatch):
        """Before this, the abort sent the refund and surfaced a bare preflight ValidationError."""
        p = os.urandom(32)
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True, preimage=p)
        leg = _ClaimedEthCounterLeg(p, lands_after_precheck=True)
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_abort(args)
        msg = str(raised.value.code)
        assert "MAKER CLAIMED" in msg and "0x" + "55" * 32 in msg and "--phase claim" in msg, msg
        assert len(leg.refund_calls) == 1
        assert leg.provenance_checked == ["0x" + "55" * 32], "the claim was not verified before being reported"

    async def test_settled_with_no_verified_claim_after_the_pre_check_never_says_refunded(
        self, eth_mod, tmp_path, monkeypatch
    ):
        args, _terms, _io = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
        leg = _ClaimedEthCounterLeg(None, claim_tx=None, settled=True, lands_after_precheck=True)
        _wire_eth_claimed(eth_mod, monkeypatch, leg)
        with pytest.raises(SystemExit) as raised:
            await eth_mod.taker_phase_abort(args)
        msg = str(raised.value.code)
        assert "ALREADY SETTLED" in msg and "does not mean it was refunded" in msg and "--phase claim" in msg, msg


# ---------------------------------------------------------------------------
# 11. A locator filled into a pending record clears what it supersedes (#850 PR R, review F4)
# ---------------------------------------------------------------------------


async def test_a_filled_locator_clears_the_pending_handles_and_the_fund_refusal(eth_mod, tmp_path, monkeypatch):
    from pyrxd.gravity.swap_state import SwapRecord

    args, terms, io_dir = _eth_scenario(eth_mod, tmp_path, role="taker", with_funding=True)
    loc = _exchange_locator(io_dir, eth=True)
    await _seed(
        args,
        SwapRecord(
            state=SwapState.NEGOTIATED,
            terms=terms,
            pending_counter_contract=loc.contract_address,
            pending_counter_deploy_tx=loc.deploy_tx_hash,
            pending_push_nonce=4,
            fund_refusal="the taker gate refused",
            single_operator_override=_OVERRIDE_STATEMENT,
        ),
    )
    built = _wire_eth(eth_mod, monkeypatch)
    await eth_mod.taker_phase_abort(args)
    assert len(built["counter"].refund_calls) == 1
    after = _read_back(args)
    assert after.state is SwapState.ABORTED
    assert after.counterchain_locator.to_dict() == loc.to_dict()
    assert after.pending_counter_contract is None and after.pending_counter_deploy_tx is None
    assert after.pending_push_nonce is None and after.fund_refusal is None
    assert after.single_operator_override == _OVERRIDE_STATEMENT, "only what the locator supersedes is cleared"


# ---------------------------------------------------------------------------
# 12. dust_swap_resume.py merges THROUGH the script (#850 PR R, review F3)
# ---------------------------------------------------------------------------


def _resume_argv(keys: Path) -> list[str]:
    return [
        "--keys-out",
        str(keys),
        "--btc-htlc-funding-txid",
        "ab" * 32,
        "--rxd-ssh-host",
        "unused-host",
        "--rxd-container",
        "unused-container",
    ]


class TestDustSwapResumeMergesThroughTheScript:
    """``resume()`` runs for real up to the coordinator it builds; the transports, the legs and the
    coordinator are stand-ins. The coordinator stand-in records the record it was handed and stops."""

    def _keys(self, tmp_path: Path) -> tuple[Path, int]:
        from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd

        p = os.urandom(32)
        h = hashlib.sha256(p).digest()
        maker_btc = coincurve.PrivateKey(os.urandom(32))
        taker_btc = generate_keypair("bcrt")
        taker_rxd, maker_rxd = PrivateKey(os.urandom(32)), PrivateKey(os.urandom(32))
        taker_pkh = bytes(Hex20(taker_rxd.public_key().hash160()))
        maker_pkh = bytes(Hex20(maker_rxd.public_key().hash160()))
        claim_xo = coincurve.PublicKeyXOnly.from_secret(maker_btc.secret).format()
        refund_xo = coincurve.PublicKeyXOnly.from_secret(bytes(taker_btc._privkey.unsafe_raw_bytes())).format()
        t_btc = bt.Timelock(20, bt.TimeUnit.BLOCKS)
        cov = build_htlc_covenant_rxd(amount=1000, taker_pkh=taker_pkh, maker_pkh=maker_pkh, hashlock=h, refund_csv=120)
        htlc = bt.build_htlc(
            hashlock=h, claim_pubkey_xonly=claim_xo, refund_pubkey_xonly=refund_xo, timeout=t_btc, network="bcrt"
        )
        keys = tmp_path / "run_keys.json"
        keys.write_text(
            json.dumps(
                {
                    "btc_network": "bcrt",
                    "rxd_network": "bcrt",
                    "hashlock_H": h.hex(),
                    "preimage_p_hex": p.hex(),
                    "maker_btc_wif_raw_hex": maker_btc.secret.hex(),
                    "taker_btc_wif": taker_btc.unsafe_wif(),
                    "taker_rxd_wif": taker_rxd.wif(),
                    "maker_rxd_wif": maker_rxd.wif(),
                    "t_btc_blocks": 20,
                    "t_rxd_blocks": 120,
                    "btc_htlc_address": htlc.address,
                    "rxd_covenant_spk": cov.funded_spk.hex(),
                    "btc_claim_payout_spk": "00" * 22,
                    "btc_refund_payout_spk": "00" * 22,
                }
            )
        )
        return keys, htlc

    def _wire(self, mod, monkeypatch, htlc, seen: list):
        class _Reader:
            def __init__(self, *a, **k):
                self._http = self

            async def read_output_amount_sats(self, txid, vout, *, min_confirmations=1):
                return 1260

            async def tx_json(self, txid):
                return {"vout": [{"scriptpubkey": htlc.scriptpubkey.hex()}]}

            async def close(self):
                return None

        class _Client:
            def __init__(self, *a, **k):
                pass

            def register_spk(self, spk):
                return None

        async def _margin(args):
            return object(), {}

        def _coordinator(**kw):
            seen.append(kw["record"])
            raise _Stop

        monkeypatch.setattr(mod, "measured_margin_from_mainnet", _margin)
        for name in ("MempoolSpaceFundingReader", "MempoolSpaceBroadcaster", "MempoolSpaceSource"):
            monkeypatch.setattr(mod, name, _Reader)
        monkeypatch.setattr(mod, "SshTrRadiantClient", _Client)
        for name in ("BitcoinTaprootLeg", "RadiantCovenantLeg", "RadiantChainIO", "DurableSeenStore"):
            monkeypatch.setattr(mod, name, lambda *a, **k: object())
        monkeypatch.setattr(mod, "CoordinatorConfig", lambda **kw: kw)
        monkeypatch.setattr(mod, "SwapCoordinator", _coordinator)

    async def _resume(self, keys: Path, htlc, monkeypatch) -> object:
        mod = _load("dust_swap_resume")
        seen: list = []
        self._wire(mod, monkeypatch, htlc, seen)
        args = mod._parse_args(_resume_argv(keys))
        with pytest.raises(_Stop):
            await mod.resume(args)
        assert len(seen) == 1
        return seen[0]

    async def test_the_persisted_fields_reach_the_coordinator(self, tmp_path, monkeypatch):
        from pyrxd.gravity.record_sink import JsonFileRecordSink

        keys, htlc = self._keys(tmp_path)
        rebuilt = await self._resume(keys, htlc, monkeypatch)  # no record yet: the rebuild as before
        assert rebuilt.radiant_covenant_outpoint is None and rebuilt.state is SwapState.BTC_LOCKED
        persisted = dataclasses.replace(
            rebuilt,
            radiant_covenant_outpoint="cc" * 32 + ":0",
            radiant_covenant_spk_hex="51",
            single_operator_override=_OVERRIDE_STATEMENT,
        )
        await JsonFileRecordSink(str(keys) + ".swaprec.json")(persisted)
        merged = await self._resume(keys, htlc, monkeypatch)
        assert merged.radiant_covenant_outpoint == "cc" * 32 + ":0"
        assert merged.single_operator_override == _OVERRIDE_STATEMENT
        assert merged.counterchain_locator.to_dict() == rebuilt.counterchain_locator.to_dict()

    async def test_different_terms_refuse_before_the_coordinator(self, tmp_path, monkeypatch):
        from pyrxd.gravity.record_sink import JsonFileRecordSink

        keys, htlc = self._keys(tmp_path)
        rebuilt = await self._resume(keys, htlc, monkeypatch)
        other = dataclasses.replace(rebuilt.terms, radiant_amount=rebuilt.terms.radiant_amount + 1)
        await JsonFileRecordSink(str(keys) + ".swaprec.json")(dataclasses.replace(rebuilt, terms=other))
        mod = _load("dust_swap_resume")
        seen: list = []
        self._wire(mod, monkeypatch, htlc, seen)
        args = mod._parse_args(_resume_argv(keys))
        with pytest.raises(SystemExit, match="disagree on terms"):
            await mod.resume(args)
        assert seen == [], "the coordinator was built on a record that disagrees with the rebuild"

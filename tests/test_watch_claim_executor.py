"""Tests for the autonomous asset-claim executor (``gravity.watch.claim_executor``).

No real chain: the Radiant leg + claim sources are fakes. For the byte-dependent paths (txid match,
provenance, scrape) a REAL BTC maker-claim tx is built via the BTC HTLC leg (the same way the swap
flow produces it) so the executor's local txid re-derivation / provenance / scrape run against real bytes.
Dormant-by-construction: nothing here moves value; every BROADCAST is a fake leg recording the call.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.btc_wallet.taproot import Timelock, TimeUnit, btc_txid_from_raw
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import (
    BtcClaimStatus,
    ClaimExecutor,
    CompositeExecutor,
    CovenantClaimContext,
    Decision,
    ExecOutcome,
    Intent,
    NullExecutor,
    load_claim_context,
)
from pyrxd.gravity.watch.claim_executor import sidecar_leg_resolver
from pyrxd.security.errors import NetworkError, ValidationError

# --------------------------------------------------------------------------- real BTC claim tx


def _xonly(kp) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(kp._privkey.unsafe_raw_bytes()).format()


def _terms(*, maker_kp, taker_kp, hashlock, variant="rxd", radiant_amount=1_000):
    return NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=100_000,
        radiant_amount=radiant_amount,
        t_btc=t.Timelock(72, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(144, t.TimeUnit.BLOCKS),
        asset_variant=variant,
        genesis_ref=b"" if variant == "rxd" else (b"\xab" * 32 + b"\x00\x00\x00\x00"),
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(maker_kp),
        btc_refund_pubkey_xonly=_xonly(taker_kp),
    )


class _RecordingBroadcaster:
    def __init__(self):
        self.raw_seen: list[bytes] = []

    async def broadcast(self, raw_tx: bytes) -> str:
        self.raw_seen.append(bytes(raw_tx))
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


async def _build_real_claim(*, variant="rxd", radiant_amount=1_000):
    """Return (terms, p, raw_claim_bytes, claim_txid, locator, btc_leg) for a real maker claim tx."""
    taker, maker = generate_keypair("bcrt"), generate_keypair("bcrt")
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    terms = _terms(maker_kp=maker, taker_kp=taker, hashlock=h, variant=variant, radiant_amount=radiant_amount)
    bc = _RecordingBroadcaster()
    leg = BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly(maker),
        broadcaster=bc,
        funding_reader=_FakeFundingReader(),
        refund_to_scriptpubkey=b"\x00\x14" + b"\x33" * 20,
        claim_to_scriptpubkey=b"\x00\x14" + b"\x44" * 20,
        fee_sats=500,
        min_confirmations=1,
        maker_claim_privkey=maker._privkey.unsafe_raw_bytes(),
    )
    htlc = leg._htlc(terms)
    locator = htlc.with_funding(t.BtcOutpoint("cd" * 32, 0), terms.btc_sats)
    await leg.claim(locator, p)
    raw_claim = bc.raw_seen[0]
    return terms, p, raw_claim, btc_txid_from_raw(raw_claim), locator, leg


class _FakeFundingReader:
    async def read_output_amount_sats(self, txid, vout, *, min_confirmations):
        return 100_000

    async def confirmations(self, txid):
        return 100

    async def txid_of(self, raw_tx):
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


# --------------------------------------------------------------------------- Radiant-side fakes


class _FakeChainIO:
    def __init__(
        self, *, value=1_000, funded_h=100, confs=1, missing=False, error: Exception | None = None, mempool_unspent=None
    ):
        self.outpoint = "rr" * 32 + ":0"
        self._value, self._funded_h, self._confs = value, funded_h, confs
        self._missing, self._error = missing, error
        self._mempool_unspent = mempool_unspent  # None → mempool re-check abstains (fall back to SeenStore)
        self.pin_seen: str | None = "<never called>"

    async def find_covenant_utxo(self, spk, *, expected_value=None, pin_outpoint=None):
        # Record what the executor asked for. The pin is the difference between reading the funded
        # outpoint and re-DISCOVERING it by SPK scan — and a scan can be made ambiguous by anyone
        # paying the covenant address, which is the brick this exists to stop.
        self.pin_seen = pin_outpoint
        if self._error is not None:
            raise self._error
        if self._missing:
            raise NetworkError("no UTXO found for the covenant scriptPubKey (not yet funded / wrong SPK)")
        return self.outpoint, self._value, self._funded_h

    async def confirmations(self, txid):
        return self._confs

    async def covenant_unspent_incl_mempool(self, outpoint):
        return self._mempool_unspent  # True=unspent, False=spent incl. mempool, None=can't answer


class _FakeRadiantLeg:
    #: Production ``RadiantCovenantLeg`` sets ``.network`` (radiant_leg.py:426), and the
    #: executor's network-consistency guard reads it via ``getattr(leg, "network", None)``.
    #: This double used to omit the attribute entirely, so ``leg_net`` was ``None`` in all
    #: 38 leg resolutions across the suite and the comparison was structurally unreachable
    #: — the guard could be deleted with every test still green. Every construction now
    #: carries a network matching its executor, so the comparison actually runs, and
    #: ``test_leg_on_a_different_network_is_declined`` drives it apart.
    def __init__(self, chain_io, *, claim_txid="dd" * 32, network="bcrt"):
        self.chain_io = chain_io
        self.network = network
        self._claim_txid = claim_txid
        self.claimed_with: bytes | None = None
        self.claim_calls = 0  # spy: number of times claim_asset actually broadcast

    async def expected_covenant_scriptpubkey(self, terms):
        return b"\x76\xa9" + b"\x00" * 20 + b"\x88\xac"

    async def claim_asset(self, record, preimage):
        self.claim_calls += 1
        self.claimed_with = bytes(preimage)
        return self._claim_txid


class _FakeDepthCorroborator:
    """Quorum RXD depth read (MultiSourceRxdChainSource shape): ``async covenant_confirmations``.
    ``depth=None`` → below quorum (fail-closed); ``raises=exc`` → unresolvable (fail-closed)."""

    def __init__(self, *, depth: int | None = None, raises: Exception | None = None):
        self._depth, self._raises = depth, raises

    async def covenant_confirmations(self, outpoint: str) -> int | None:
        if self._raises is not None:
            raise self._raises
        return self._depth


class _FakeStatusSource:
    def __init__(self, *, claim_txid, claimed=True, confs=10):
        self._claim_txid, self._claimed, self._confs = claim_txid, claimed, confs

    async def claim_status(self, funding_txid, funding_vout):
        return BtcClaimStatus(claimed=self._claimed, claim_txid=self._claim_txid if self._claimed else None)

    async def confirmations(self, claim_txid):
        return self._confs


class _FakeBytesSource:
    def __init__(self, mapping):
        self._m = mapping

    async def claim_tx_bytes(self, claim_txid):
        return self._m.get(claim_txid)


def _resolver(leg):
    """Wrap a (fake) leg as the executor's async per-swap ``resolve_leg(swap_id, record)``."""

    async def _r(swap_id, record):
        return leg

    return _r


def _claim_decision(*, low_corroboration=False) -> Decision:
    return Decision(
        Intent.PAGE_CLAIM,
        reason="SAFE claim race",
        recommended_action="taker_scrape_and_claim_asset",
        deadline_rxd_height=172,
        low_corroboration=low_corroboration,
        autonomous_asset_claim=True,
    )


def _value_scaled_policy(*, cost_per_block: int = 100) -> MarginPolicy:
    """A policy with value-scaling ON — `rxd_reorg_cost_per_block` set.

    `MarginPolicy.estimated()` leaves it None, which switches `_value_scaled_burial_blocks` off
    entirely and makes `value_at_risk_photons` unread. A test about the value-at-risk plumbing run
    on that policy cannot express the defect it names, however the plumbing behaves.

    At cost 100 photons/block and the default `burial_safety_factor` of 1.0, a 1_234-photon swap
    requires `ceil(1234/100) = 13` blocks of burial, above the flat 6 — so the value genuinely
    changes the answer here rather than being carried and ignored.
    """
    return MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_reorg_cost_per_block=cost_per_block,
    )


async def _armed_executor(
    *,
    network="bcrt",
    confs=1,
    missing=False,
    btc_confs=10,
    status_claimed=True,
    mempool_unspent=None,
    policy=None,
    **kw,
):
    terms, p, raw, claim_txid, locator, _btc_leg = await _build_real_claim(
        variant=kw.pop("variant", "rxd"), radiant_amount=kw.pop("radiant_amount", 1_000)
    )
    chain_io = _FakeChainIO(value=terms.radiant_amount, confs=confs, missing=missing, mempool_unspent=mempool_unspent)
    # The leg's network matches the executor's unless a test deliberately drives them apart.
    leg = _FakeRadiantLeg(chain_io, network=kw.pop("leg_network", network))
    # "armed" fixture: arm mainnet custody by default so the value-bearing tests exercise the claim path.
    # (No effect on audit-cleared networks like bcrt, where _value_bearing is False.) Override via kw.
    kw.setdefault("enable_autonomous_mainnet_custody", True)
    ex = ClaimExecutor(
        resolve_leg=_resolver(leg),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid, claimed=status_claimed, confs=btc_confs),
        claim_bytes_source=_FakeBytesSource({claim_txid: raw}),
        policy=policy or MarginPolicy.estimated(),
        network=network,
        **kw,
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    return ex, leg, rec, p


# --------------------------------------------------------------------------- tests: early gates


async def test_non_claim_decision_is_silent_noop():
    ex, leg, rec, _ = await _armed_executor()
    refund = Decision(Intent.PAGE_REFUND, reason="x", recommended_action="mutual_refund")
    assert await ex.execute("s1", rec, refund) is None  # not a claim → None (no-op)
    assert leg.claimed_with is None


async def test_dormant_when_leg_or_sources_missing():
    terms, _p, _raw, _claim_txid, locator, _btc_leg = await _build_real_claim()
    ex = ClaimExecutor(
        resolve_leg=None,  # dormant
        claim_status_source=None,
        claim_bytes_source=None,
        policy=MarginPolicy.estimated(),
        network="bc",
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED


async def test_leg_on_a_different_network_is_declined():
    """FALS-06: the network-consistency guard, made reachable.

    The arming latch and the value cap key on the EXECUTOR's network; the leg broadcasts
    on ITS own (set independently by the sidecar resolver). A divergence means both
    guards were evaluated against a network the transaction will not be sent to, so the
    executor must fail closed rather than claim.

    The guard shipped correct but untestable: ``_FakeRadiantLeg`` had no ``network``
    attribute, so ``getattr(leg, "network", None)`` returned ``None`` in every one of the
    suite's 38 leg resolutions and the comparison was never evaluated. Mutating the
    condition left the whole suite green. The double now carries a network, so the
    comparison runs everywhere and this test drives the two apart.
    """
    ex, leg, rec, _ = await _armed_executor(network="bcrt", leg_network="bc")
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claim_calls == 0
    assert leg.claimed_with is None


async def test_resolver_returning_none_is_dormant_for_that_swap():
    # No covenant sidecar for this swap → resolve_leg returns None → DECLINED (no broadcast).
    terms, _p, _raw, claim_txid, locator, _btc_leg = await _build_real_claim()
    ex = ClaimExecutor(
        resolve_leg=_resolver(None),  # armed sources, but no per-swap leg
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid),
        claim_bytes_source=_FakeBytesSource({}),
        policy=MarginPolicy.estimated(),
        network="bcrt",
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED


async def test_resolver_raising_fails_closed():
    terms, _p, _raw, claim_txid, locator, _btc_leg = await _build_real_claim()

    async def _boom(swap_id, record):
        raise RuntimeError("sidecar load blew up")

    ex = ClaimExecutor(
        resolve_leg=_boom,
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid),
        claim_bytes_source=_FakeBytesSource({}),
        policy=MarginPolicy.estimated(),
        network="bcrt",
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.FAILED


async def test_low_corroboration_declines_without_optin():
    ex, leg, rec, _ = await _armed_executor()
    assert await ex.execute("s1", rec, _claim_decision(low_corroboration=True)) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_low_corroboration_allowed_with_optin():
    ex, leg, rec, p = await _armed_executor(accept_single_source=True)
    assert await ex.execute("s1", rec, _claim_decision(low_corroboration=True)) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


# --------------------------------------------------------------------------- tests: value-vs-reorg cap (HIGH-1)


async def test_value_bearing_declines_without_mainnet_custody_arming():
    # As-is posture: a wired executor on a value-bearing network broadcasts NOTHING until the operator
    # explicitly arms it — even when value/finality would otherwise permit the claim.
    ex, leg, rec, _ = await _armed_executor(
        network="bc", reorg_cost_per_block=1_000, radiant_amount=1_000, enable_autonomous_mainnet_custody=False
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_value_bearing_default_is_unarmed_declines():
    # Pin the load-bearing __init__ DEFAULT (security panel #244): an executor built WITHOUT the kwarg
    # declines on a value-bearing network. Built directly to bypass the fixture's setdefault(..., True),
    # so flipping the production default to True would fail this test.
    terms, _p, raw, claim_txid, locator, _ = await _build_real_claim()
    leg = _FakeRadiantLeg(_FakeChainIO(value=terms.radiant_amount), network="bc")
    ex = ClaimExecutor(
        resolve_leg=_resolver(leg),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid, claimed=True, confs=10),
        claim_bytes_source=_FakeBytesSource({claim_txid: raw}),
        policy=MarginPolicy.estimated(),
        network="bc",
        reorg_cost_per_block=1_000,
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_arming_flag_rejects_non_bool():
    # The arming latch must reject truthy non-bools (bool("false") is True) so a config/env string
    # can never silently arm unattended mainnet custody (security panel #244).
    with pytest.raises(ValidationError):
        ClaimExecutor(
            resolve_leg=_resolver(_FakeRadiantLeg(_FakeChainIO(value=1_000), network="bc")),
            claim_status_source=None,
            claim_bytes_source=None,
            policy=MarginPolicy.estimated(),
            network="bc",
            enable_autonomous_mainnet_custody="true",
        )


async def test_unbounded_flag_does_not_waive_relative_ceiling_above_dust():
    # accept_unbounded_reorg_risk is a DUST opt-in only: for RXD value ABOVE the 10k default it must NOT
    # skip the relative reorg-cost ceiling, even with the absolute ceiling raised (security panel #244
    # footgun). value 50_000 > 10k dust; raised ceiling 100_000 passes the absolute check; relative ceiling
    # floor(6 * 100 / 2.0) = 300 << 50_000 → DECLINE despite accept_unbounded=True.
    ex, leg, rec, _ = await _armed_executor(
        network="bc",
        accept_unbounded_reorg_risk=True,
        radiant_amount=50_000,
        claim_dust_ceiling=100_000,
        reorg_cost_per_block=100,
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_unbounded_flag_still_waives_for_genuine_dust():
    # The dust opt-in still works for RXD value <= the 10k default (the relative ceiling is not reached).
    ex, leg, rec, p = await _armed_executor(
        network="bc", accept_unbounded_reorg_risk=True, radiant_amount=5_000, reorg_cost_per_block=100
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


async def test_value_bearing_above_default_ceiling_broadcasts_when_operator_raises_it():
    # The ceiling is a *default the operator raises with explicit per-value consent*, not a hard block.
    # value 50_000 is ABOVE the 10k default ceiling but below the explicitly-raised claim_dust_ceiling
    # (100_000) AND below the relative reorg ceiling floor(6 * 20_000 / 2.0) = 60_000 → broadcasts.
    ex, leg, rec, p = await _armed_executor(
        network="bc", reorg_cost_per_block=20_000, radiant_amount=50_000, claim_dust_ceiling=100_000
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


async def test_value_bearing_rxd_over_ceiling_declines():
    # mainnet ("bc") value-bearing; ceiling = floor(6 burial * 100 cost / 2.0) = 300; value 1000 > 300.
    ex, leg, rec, _ = await _armed_executor(network="bc", reorg_cost_per_block=100, radiant_amount=1_000)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_value_bearing_rxd_within_ceiling_broadcasts():
    # ceiling = floor(6 * 1000 / 2.0) = 3000; value 1000 <= 3000.
    ex, leg, rec, p = await _armed_executor(network="bc", reorg_cost_per_block=1_000, radiant_amount=1_000)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


async def test_value_bearing_without_reorg_cost_declines():
    ex, _leg, rec, _ = await _armed_executor(network="bc")  # no reorg_cost_per_block
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED


async def test_value_bearing_ft_nft_declines_without_unbounded_optin():
    # ft/nft radiant_amount is carrier dust, not market value → no in-record bound → decline.
    ex, _leg, rec, _ = await _armed_executor(network="bc", variant="nft", radiant_amount=1, reorg_cost_per_block=1_000)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED


async def test_value_bearing_unbounded_optin_skips_cap():
    ex, leg, rec, p = await _armed_executor(network="bc", accept_unbounded_reorg_risk=True)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


# --------------------------------------------------------------------------- tests: byte-dependent paths


async def test_happy_path_broadcasts_and_passes_real_preimage():
    ex, leg, rec, p = await _armed_executor()
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p  # the REAL scraped preimage was handed to the leg


async def test_stale_verdict_no_fresh_claim_declines():
    ex, _leg, rec, _ = await _armed_executor(status_claimed=False)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED  # nothing claimed on a fresh read


async def test_unfetchable_claim_bytes_fails():
    terms, _p, _raw, claim_txid, locator, _btc_leg = await _build_real_claim()
    ex = ClaimExecutor(
        resolve_leg=_resolver(_FakeRadiantLeg(_FakeChainIO())),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid),
        claim_bytes_source=_FakeBytesSource({}),  # no bytes for the txid
        policy=MarginPolicy.estimated(),
        network="bcrt",
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.FAILED


async def test_bytes_txid_mismatch_fails():
    terms, _p, raw, _claim_txid, locator, _btc_leg = await _build_real_claim()
    wrong = "ee" * 32  # status reports a txid the bytes don't hash to
    ex = ClaimExecutor(
        resolve_leg=_resolver(_FakeRadiantLeg(_FakeChainIO())),
        claim_status_source=_FakeStatusSource(claim_txid=wrong),
        claim_bytes_source=_FakeBytesSource({wrong: raw}),
        policy=MarginPolicy.estimated(),
        network="bcrt",
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.FAILED


async def test_covenant_already_spent_is_idempotent_declined():
    ex, leg, rec, _ = await _armed_executor(missing=True)  # find_covenant_utxo raises "no UTXO found"
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_fresh_reassess_squeezed_declines():
    # t_rxd window already closed at fresh read: funded_h far below now so blocks_left < burial.
    terms, _p, raw, claim_txid, locator, _btc_leg = await _build_real_claim()
    # now_rxd = funded_h + confs - 1 = 100 + 172 - 1 = 271 > refund_opens (100 + 144 = 244) → SQUEEZED.
    # The numbers moved with t_rxd, which #482 raised from 72 to 144; at the old confs=100 the
    # window is still wide open and this test asserts a SQUEEZE that does not happen.
    chain_io = _FakeChainIO(value=terms.radiant_amount, funded_h=100, confs=172)
    leg = _FakeRadiantLeg(chain_io)
    ex = ClaimExecutor(
        resolve_leg=_resolver(leg),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid, confs=10),
        claim_bytes_source=_FakeBytesSource({claim_txid: raw}),
        policy=MarginPolicy.estimated(),
        network="bcrt",
    )
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_shallow_btc_claim_waits_or_declines():
    # btc_claim depth below the reorg requirement → NOT_YET_FINAL_LIVE → not SAFE → decline.
    ex, leg, rec, _ = await _armed_executor(btc_confs=1)  # required depth is 6 (estimated policy)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


def _assess_spy(monkeypatch) -> dict:
    """Record the kwargs `claim_executor` hands `assess_claim_finality`, and still run the real gate."""
    import pyrxd.gravity.watch.claim_executor as ce

    captured: dict = {}
    real = ce.assess_claim_finality

    def _spy(**kw):
        captured.update(kw)
        return real(**kw)

    monkeypatch.setattr(ce, "assess_claim_finality", _spy)
    return captured


async def test_fresh_reassess_passes_per_record_value_at_risk(monkeypatch):
    """CLAIM-1 regression: the fresh pre-broadcast re-assess must pass the SAME per-record
    value-at-risk `decide()` uses (`radiant_amount` for an rxd swap) rather than let it default to
    None — under which `assess_claim_finality` returns SQUEEZED for EVERY swap and the autonomous
    claim silently never fires, degrading to alert-only.

    THIS TEST RAN ON `MarginPolicy.estimated()`, WHERE THAT DEFECT CANNOT HAPPEN. That policy
    leaves `rxd_reorg_cost_per_block` at None, so `_value_scaled_burial_blocks` returns 0 and the
    gate never reads the value at all: BROADCAST was the outcome whether the kwarg arrived or not,
    and only the spy line was load-bearing. A test whose fixture cannot express the defect it
    describes is passing for a reason unrelated to the code being correct.

    So it runs under the value-scaled policy the docstring names. 1_234 photons at 100
    photons/block needs 13 blocks of burial against the flat 6 — the value is now what decides the
    verdict, and dropping the kwarg turns this BROADCAST into a DECLINED.

    Measured, with `value_at_risk_photons=None` planted at the call site (claim_executor.py:527
    — the CLAIM-1 regression itself): on `MarginPolicy.estimated()` the executor still returns
    BROADCAST, so only the spy line below noticed; on the value-scaled policy it returns
    DECLINED, so the outcome assertion carries the test.
    """
    captured = _assess_spy(monkeypatch)
    ex, _leg, rec, _p = await _armed_executor(radiant_amount=1_234, policy=_value_scaled_policy())
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert captured.get("value_at_risk_photons") == 1_234  # the rxd per-record value reached the gate, not None


async def test_fresh_reassess_value_at_risk_is_none_for_ft_nft(monkeypatch):
    """The FT/NFT peer: their on-chain `radiant_amount` is carrier dust, not market value, so
    `_value_at_risk_photons` returns None and the gate must FAIL CLOSED under a value-scaled policy
    rather than certify a claim on value it cannot see.

    Also on the value-scaled policy now, for the same reason as its rxd peer — and here the
    consequence is the point: this is a DECLINE, not a broadcast. On `MarginPolicy.estimated()` the
    identical None produced a cheerful BROADCAST, so the fail-closed behaviour the comment claimed
    was never exercised.
    """
    captured = _assess_spy(monkeypatch)
    # unbounded dust opt-in so an nft swap reaches the fresh re-assess on bcrt (past the value cap).
    ex, leg, rec, _ = await _armed_executor(
        variant="nft", radiant_amount=1, accept_unbounded_reorg_risk=True, policy=_value_scaled_policy()
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None  # fail-closed: no autonomous claim on unreadable value
    assert "value_at_risk_photons" in captured
    assert captured["value_at_risk_photons"] is None  # ft/nft carrier dust is NOT treated as economic value


async def test_a_value_scaled_policy_still_broadcasts_a_swap_its_burial_covers(monkeypatch):
    """The honest path under value-scaling, which must not be refused.

    The peer above is a refusal, and a refusal test alone cannot tell "fails closed correctly"
    apart from "refuses everything once value-scaling is on". Here the same policy, given a swap
    small enough for the flat burial to cover (100 photons needs `ceil(100/100) = 1` block, under
    the flat 6), broadcasts — so the DECLINE above is attributable to the unreadable NFT value and
    not to the policy.
    """
    captured = _assess_spy(monkeypatch)
    ex, leg, rec, _p = await _armed_executor(radiant_amount=100, policy=_value_scaled_policy())
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with is not None
    assert captured["value_at_risk_photons"] == 100


# --------------------------------------------------------------------------- FIX 1: fire-once guard


async def test_fire_once_guard_blocks_per_tick_recarve():
    # The covenant reads "unspent" between broadcast and confirmation, so a 2nd tick reaches step 8 again.
    # With a SeenStore the first execute broadcasts; the second is an idempotent no-op (no 2nd claim_asset).
    from pyrxd.gravity.radiant_leg import SeenStore

    ex, leg, rec, p = await _armed_executor(seen_store=SeenStore())
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claim_calls == 1
    assert leg.claimed_with == p
    # Same swap, same still-"unspent" covenant outpoint on the next tick → DECLINED, NO second broadcast.
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claim_calls == 1  # the fire-once guard prevented the per-tick re-carve


async def test_mempool_aware_check_blocks_recarve_for_pending_claim():
    # The STRONGER guard: a claim already PENDING in the mempool still reads "unspent" via the
    # mempool-blind scan, but the mempool-aware re-check (covenant_unspent_incl_mempool → False)
    # treats it as claimed → DECLINE before the broadcast (no re-carve), WITHOUT needing a SeenStore.
    ex, leg, rec, _p = await _armed_executor(mempool_unspent=False)  # covenant spent in the mempool
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claim_calls == 0  # fired before the broadcast — no fee re-carve


async def test_mempool_aware_unspent_refires_where_seenstore_would_not():
    # A covenant that reads truly UNSPENT including mempool (e.g. a reorg-evicted claim) → the
    # executor RE-FIRES. This is the mempool-aware guard's advantage over the SeenStore, which would
    # have falsely declined an evicted-claim re-broadcast.
    ex, leg, rec, p = await _armed_executor(mempool_unspent=True)
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claim_calls == 1
    assert leg.claimed_with == p


async def test_fire_once_marks_only_after_successful_broadcast():
    # A transient broadcast failure must NOT mark the outpoint seen (so a retry can still fire). Model it by
    # raising from claim_asset on the first call, then succeeding — the guard must let the retry through.
    from pyrxd.gravity.radiant_leg import SeenStore
    from pyrxd.security.errors import NetworkError as _NetErr

    ex, leg, rec, p = await _armed_executor(seen_store=SeenStore())

    calls = {"n": 0}
    orig = leg.claim_asset

    async def _flaky(record, preimage):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _NetErr("transient broadcast hiccup")
        return await orig(record, preimage)

    leg.claim_asset = _flaky
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.FAILED  # broadcast failed
    # Not marked seen → the retry tick fires (mark-after-success, not mark-before).
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


# --------------------------------------------------------------------------- FIX 2: MAX-depth RXD quorum


async def test_corroborated_deeper_depth_flips_safe_to_squeezed():
    # Single node says confs=1 → now_rxd=100 → SAFE. A corroborator reporting a DEEPER depth (172)
    # makes now_rxd=271 > refund_opens(244) → SQUEEZED → DECLINED. The deeper (MAX) read can't
    # false-SAFE. The corroborated depth scales with t_rxd (72 → 144 at #482); at the old 100 the
    # deeper read is still SAFE and this test proves nothing about the flip it is named for.
    ex, leg, rec, _ = await _armed_executor(confs=1, rxd_depth_corroborator=_FakeDepthCorroborator(depth=172))
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_corroborator_none_fails_closed():
    # Below-quorum (None) → fail closed, never trust the single node's would-be-SAFE read.
    ex, leg, rec, _ = await _armed_executor(confs=1, rxd_depth_corroborator=_FakeDepthCorroborator(depth=None))
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_corroborator_raising_fails_closed():
    ex, leg, rec, _ = await _armed_executor(
        confs=1, rxd_depth_corroborator=_FakeDepthCorroborator(raises=NetworkError("uncorroborated"))
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_corroborator_agreeing_depth_still_broadcasts():
    # A corroborator confirming the shallow depth (max(1,1)=1) leaves the SAFE verdict intact → broadcast.
    ex, leg, rec, p = await _armed_executor(confs=1, rxd_depth_corroborator=_FakeDepthCorroborator(depth=1))
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


# --------------------------------------------------------------------------- FIX 3: absolute dust floor


async def test_absolute_dust_floor_not_waived_by_unbounded():
    # accept_unbounded_reorg_risk waives the RELATIVE reorg-cost ceiling but NOT the absolute dust floor:
    # an rxd claim above the ceiling is DECLINED even with the unbounded flag set.
    ex, leg, rec, _ = await _armed_executor(
        network="bc", accept_unbounded_reorg_risk=True, radiant_amount=20_000, claim_dust_ceiling=10_000
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claimed_with is None


async def test_absolute_dust_floor_at_ceiling_passes():
    # At/below the absolute ceiling, the unbounded flag still lets it through (the relative cap is waived).
    ex, leg, rec, p = await _armed_executor(
        network="bc", accept_unbounded_reorg_risk=True, radiant_amount=10_000, claim_dust_ceiling=10_000
    )
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p


# --------------------------------------------------------------------------- discriminator + composite


# --------------------------------------------------------------------------- covenant claim sidecar


def test_claim_context_roundtrip_and_validation():
    ctx = CovenantClaimContext(swap_id="s1", taker_pkh=b"\x11" * 20, maker_pkh=b"\x22" * 20)
    assert CovenantClaimContext.from_dict(ctx.to_dict()) == ctx
    for bad in (b"\x11" * 19, b"\x11" * 21, "nothex"):
        with pytest.raises(ValidationError):
            CovenantClaimContext(swap_id="s1", taker_pkh=bad, maker_pkh=b"\x22" * 20)
    with pytest.raises(ValidationError):
        CovenantClaimContext(swap_id="", taker_pkh=b"\x11" * 20, maker_pkh=b"\x22" * 20)


def test_executor_rejects_non_finite_reorg_safety_factor():
    # security review LOW: a NaN/inf reorg_safety_factor must fail-closed at CONSTRUCTION
    # (NaN < 1.0 is False, so without the isfinite guard it would pass here and only crash a
    # later tick inside max_protected_value instead of a clean decline).
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError, match="finite"):
            ClaimExecutor(
                resolve_leg=None,
                claim_status_source=None,
                claim_bytes_source=None,
                policy=MarginPolicy.estimated(),
                network="bcrt",
                reorg_safety_factor=bad,
            )


def test_load_claim_context_absent_misfiled_and_present(tmp_path):
    assert load_claim_context(tmp_path, "s1") is None  # absent → None (executor declines)
    ctx = CovenantClaimContext(swap_id="s1", taker_pkh=b"\xaa" * 20, maker_pkh=b"\xbb" * 20)
    (tmp_path / "s1.claim.json").write_text(json.dumps(ctx.to_dict()))
    assert load_claim_context(tmp_path, "s1") == ctx
    # misfiled: a context whose swap_id != the filename is rejected fail-closed.
    (tmp_path / "s2.claim.json").write_text(json.dumps(ctx.to_dict()))  # content is s1, filename s2
    with pytest.raises(ValidationError, match="misfiled"):
        load_claim_context(tmp_path, "s2")


async def test_sidecar_resolver_none_without_sidecar(tmp_path):
    resolve = sidecar_leg_resolver(tmp_path, chain_io=None, fee_source=None, network="bcrt")
    assert await resolve("s1", None) is None  # no sidecar for this swap → None (dormant)


async def test_sidecar_resolver_loads_and_builds_leg_on_mainnet(tmp_path):
    # 0.9.0: the audit gate is non-blocking. The resolver loads the sidecar and
    # builds a live per-swap leg on a value-bearing network ("bc") without an
    # explicit opt-in — proving the build is attempted and now succeeds.
    from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg

    class _Client:
        async def broadcast(self, raw):
            return "dd" * 32

        async def get_transaction_verbose(self, txid):
            return {"confirmations": 1}

        async def get_utxos(self, script_hash):
            return []

    class _FeeSource:
        def next_fee_input(self):  # pragma: no cover - not exercised here
            raise NotImplementedError

    ctx = CovenantClaimContext(swap_id="s1", taker_pkh=b"\x11" * 20, maker_pkh=b"\x22" * 20)
    (tmp_path / "s1.claim.json").write_text(json.dumps(ctx.to_dict()))
    resolve = sidecar_leg_resolver(
        tmp_path, chain_io=RadiantChainIO(_Client()), fee_source=_FeeSource(), network="bc", audit_cleared=False
    )
    leg = await resolve("s1", None)
    assert isinstance(leg, RadiantCovenantLeg)
    assert leg.network == "bc"


def test_decision_rejects_claim_flag_on_non_page_claim():
    with pytest.raises(ValidationError, match="autonomous_asset_claim is only valid on a PAGE_CLAIM"):
        Decision(Intent.PAGE_SQUEEZED, reason="x", autonomous_asset_claim=True)


def test_decision_rejects_both_autonomy_flags():
    with pytest.raises(ValidationError, match="cannot set both"):
        Decision(Intent.PAGE_CLAIM, reason="x", autonomous_btc_refund=True, autonomous_asset_claim=True)


async def test_composite_dispatches_to_the_matching_executor():
    ex, leg, rec, p = await _armed_executor()
    composite = CompositeExecutor(NullExecutor(), ex)  # Null no-ops, Claim acts
    assert await composite.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claimed_with == p
    # A non-claim decision: both no-op → None.
    refund = Decision(Intent.PAGE_REFUND, reason="x", recommended_action="mutual_refund")
    assert await composite.execute("s1", rec, refund) is None


# --------------------------------------------------------------------------- A1: fee affordability


async def test_fee_shortfall_declines_and_pages_but_does_NOT_disarm_the_claim():
    """REGRESSION TEST: a fee shortfall must not permanently disarm an armed claim.

    The first cut of this handler called ``mark_seen`` on InsufficientFundsError, on the
    reasoning that "the same fee source will keep handing out the same too-small UTXOs".
    That is FALSE for the source actually wired here: ``CappedFeeWalletSource`` is
    dispense-once ("the returned UTXO is never returned again") and dispenses its pool
    in order, so the NEXT tick hands out a DIFFERENT input. A pool ordered small-first
    would therefore have had its claim disarmed by the first small dispense while
    perfectly good covering inputs were still sitting in the pool — and once seen, the
    claim never fires again and the maker's CSV refund takes the asset.

    So: DECLINED (which pages) on every shortfall, but the claim stays armed and the
    next tick tries again. Retry cost is bounded — the pool is capped and dispense-once,
    so its cursor advances at most one input per tick and cannot run past its own cap.
    """
    from pyrxd.gravity.radiant_leg import SeenStore
    from pyrxd.security.errors import InsufficientFundsError

    ex, leg, rec, _p = await _armed_executor(seen_store=SeenStore())

    async def _too_poor(record, preimage):
        leg.claim_calls += 1
        raise InsufficientFundsError(
            "HTLC covenant claim (pre-broadcast gate): fee of 546 photons is below the required 2660000",
            available=546,
            required=2_660_000,
        )

    leg.claim_asset = _too_poor
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claim_calls == 1
    # NOT marked seen → the next tick retries rather than being an idempotent no-op.
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert leg.claim_calls == 2


async def test_a_later_tick_with_a_bigger_input_still_claims_after_a_shortfall():
    """The point of not marking seen: the claim is still there to fire when funds arrive.

    Tick 1 draws a too-small input and declines. Tick 2 draws a covering one — the claim
    must broadcast. Under the old mark-seen behaviour tick 2 was an idempotent no-op and
    the asset was lost while the pool could still have paid for it.
    """
    from pyrxd.gravity.radiant_leg import SeenStore
    from pyrxd.security.errors import InsufficientFundsError

    ex, leg, rec, _p = await _armed_executor(seen_store=SeenStore())

    async def _poor_then_rich(record, preimage):
        leg.claim_calls += 1
        if leg.claim_calls == 1:
            raise InsufficientFundsError(
                "HTLC covenant claim (pre-broadcast gate): fee of 546 photons is below the required 2660000",
                available=546,
                required=2_660_000,
            )
        return "ab" * 32

    leg.claim_asset = _poor_then_rich
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST
    assert leg.claim_calls == 2


async def test_fee_shortfall_is_not_reported_as_a_transient_failure(caplog):
    # It must not read as FAILED ("retry next tick"), and the log must be actionable.
    from pyrxd.security.errors import InsufficientFundsError

    ex, leg, rec, _p = await _armed_executor()

    async def _too_poor(record, preimage):
        raise InsufficientFundsError(
            "fee of 546 photons is below the required 2660000", available=546, required=2_660_000
        )

    leg.claim_asset = _too_poor
    with caplog.at_level("ERROR"):
        assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED
    assert any("CANNOT COVER" in r.getMessage() and r.levelname == "ERROR" for r in caplog.records)


async def test_the_executor_PINS_the_recorded_covenant_outpoint():
    """The autonomous claim path is a SECOND reader of the covenant UTXO set, and it was missed when
    the pin was added to the coordinator's spend path.

    Without the pin it re-discovers by scriptPubKey scan — and that scan is made ambiguous by anyone
    paying the covenant address, which is a public function of the negotiated terms. The refusal is
    then classified by `_is_missing_utxo` as a transient read fault, so this retries every tick,
    reporting healthy until `t_rxd` expires and the maker CSV-refunds. Reading the outpoint the record
    already holds removes the discovery step the attack depends on.
    """
    ex, leg, rec, _p = await _armed_executor()
    rec = rec.with_radiant_lock("ab" * 32 + ":1", "00" * 25)
    await ex.execute("s1", rec, _claim_decision())
    assert leg.chain_io.pin_seen == "ab" * 32 + ":1", (
        f"the executor passed pin_outpoint={leg.chain_io.pin_seen!r} — it is re-discovering by scan, "
        "so a second payment to the covenant address still bricks the autonomous claim"
    )


# --------------------------------------------------------- tests: the decision BOUNDARY


class TestTheBroadcastBoundaryIsPinned:
    """Every other broadcast test in this file runs at MAXIMUM slack, and that is a
    problem the suite cannot see from the inside.

    `_armed_executor` defaults `confs=1`, so `now_rxd == funded_h` and `blocks_left`
    is the full `t_rxd` — while the BTC claim is 10 confirmations deep. Radiant does
    not reach that state: 10 Bitcoin confirmations is roughly 100 minutes, which is
    20-plus Radiant blocks at the measured 222 s median, not zero.

    Measured through the production entry point, sweeping `confs` 1..199: the verdict
    flips BROADCAST -> DECLINED between **137 and 138**. The suite's fixtures use 1
    and 172 and nothing else, so no case sat within 136 blocks of the flip on one
    side or 34 on the other. An off-by-one in the executor's depth-to-height
    derivation (`now_rxd = funded_h + max(cov_confs, 1) - 1`) was therefore invisible.

    Both directions of that off-by-one are real defects: one block LATE is a spurious
    squeeze after `p` is public, which is a forfeiture path; one block EARLY certifies
    a claim that cannot bury in time.
    """

    async def test_the_last_confs_that_still_broadcasts(self) -> None:
        ex, _leg, rec, _ = await _armed_executor(confs=137)
        assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST

    async def test_one_block_further_declines(self) -> None:
        ex, _leg, rec, _ = await _armed_executor(confs=138)
        assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.DECLINED

    async def test_a_REACHABLE_state_still_broadcasts(self) -> None:
        """The honest path at a co-occurring depth rather than at maximum slack.

        With the BTC claim 10 confirmations deep, roughly 20-plus Radiant blocks have
        also passed. Pinning that here means the happy path is exercised at a state
        the chain can actually be in — the default `confs=1` never is.
        """
        ex, _leg, rec, _ = await _armed_executor(confs=24, btc_confs=10)
        assert await ex.execute("s1", rec, _claim_decision()) is ExecOutcome.BROADCAST


class TestTheValueCapReadsTheRadiantInterval:
    """`_check_value_cap` converts a RADIANT burial, so it must use RADIANT's interval.

    #579 fixed seven sites; this one had NO test that failed when reverted. Measured
    rather than argued: switching it back to `policy.block_interval_s` passed all
    10,993 tests, `test_watch_claim_executor.py`, and the scanner written for exactly
    this defect class — which is line-based and cannot see a call split over two
    lines, the shape here.

    It survives because it is INERT while every fixture tags the burial in BLOCKS:
    `normalize_to` is then the identity and the interval argument is never read. No
    test in this file supplied a SECONDS-tagged burial, so the wrong argument and the
    right one produced identical output. **A test whose fixture cannot express the
    defect passes for a reason unrelated to the code being correct.**

    So the fixture below deliberately makes the two intervals DIFFER (600 vs 300) and
    picks an amount BETWEEN the two ceilings. Equal values hide conflations; this is
    the smallest fixture in which the two readings disagree.
    """

    #: 1800 s is 6 Radiant blocks (ceiling 3000) or 3 Bitcoin blocks (ceiling 1500).
    BURIAL_S, RXD_INTERVAL, BTC_INTERVAL = 1800, 300.0, 600.0
    COST, FACTOR = 1000, 2.0
    CEILING_RADIANT, CEILING_BITCOIN = 3_000, 1_500
    #: Between the two. Legitimate at the real ceiling, refused at the wrong one.
    AMOUNT = 2_000

    def _policy(self) -> MarginPolicy:
        return dataclasses.replace(
            MarginPolicy.estimated(),
            block_interval_s=self.BTC_INTERVAL,
            rxd_block_interval_s=self.RXD_INTERVAL,
            rxd_claim_burial=Timelock(self.BURIAL_S, TimeUnit.SECONDS),
        )

    async def _gate(self, amount: int):
        terms, _p, raw, txid, locator, _b = await _build_real_claim(radiant_amount=amount)
        ex = ClaimExecutor(
            resolve_leg=_resolver(_FakeRadiantLeg(_FakeChainIO())),
            claim_status_source=_FakeStatusSource(claim_txid=txid),
            claim_bytes_source=_FakeBytesSource({txid: raw}),
            policy=self._policy(),
            network="mainnet",
            reorg_cost_per_block=self.COST,
            reorg_safety_factor=self.FACTOR,
            claim_dust_ceiling=10_000,
            enable_autonomous_mainnet_custody=True,
        )
        rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=locator)
        return ex._check_value_cap(rec)

    def test_the_two_intervals_really_do_disagree_here(self) -> None:
        """Guards the fixture itself. If these ever coincide the test below proves
        nothing while still passing — the failure mode it exists to catch."""
        policy = self._policy()
        radiant = policy.rxd_claim_burial.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.rxd_block_interval_s)
        bitcoin = policy.rxd_claim_burial.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s)
        assert radiant.value == 6 and bitcoin.value == 3
        assert self.CEILING_BITCOIN < self.AMOUNT < self.CEILING_RADIANT

    async def test_an_honest_claim_inside_the_RADIANT_ceiling_is_allowed(self) -> None:
        """The assertion that fails when #579 is reverted here. With Bitcoin's
        interval the burial reads 3 blocks, the ceiling halves to 1500, and this
        legitimate 2000-photon claim is refused — a guard refusing valid work, and
        for an autonomous claim a refusal can mean the swap is not claimed at all."""
        assert await self._gate(self.AMOUNT) is None

    async def test_a_claim_above_the_RADIANT_ceiling_is_still_refused(self) -> None:
        """The other half. A gate that allows everything would also pass the test
        above, so pin that it still says no — and that it names the real ceiling."""
        reason = await self._gate(self.CEILING_RADIANT + 1)
        assert reason is not None and str(self.CEILING_RADIANT) in reason

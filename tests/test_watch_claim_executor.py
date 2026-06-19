"""Tests for the autonomous asset-claim executor (``gravity.watch.claim_executor``).

No real chain: the Radiant leg + claim sources are fakes. For the byte-dependent paths (txid match,
provenance, scrape) a REAL BTC maker-claim tx is built via the BTC HTLC leg (the same way the swap
flow produces it) so the executor's local txid re-derivation / provenance / scrape run against real bytes.
Dormant-by-construction: nothing here moves value; every BROADCAST is a fake leg recording the call.
"""

from __future__ import annotations

import hashlib
import json
import os

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.btc_wallet.taproot import btc_txid_from_raw
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
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
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

    async def find_covenant_utxo(self, spk, *, expected_value=None):
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
    def __init__(self, chain_io, *, claim_txid="dd" * 32):
        self.chain_io = chain_io
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


async def _armed_executor(
    *, network="bcrt", confs=1, missing=False, btc_confs=10, status_claimed=True, mempool_unspent=None, **kw
):
    terms, p, raw, claim_txid, locator, _btc_leg = await _build_real_claim(
        variant=kw.pop("variant", "rxd"), radiant_amount=kw.pop("radiant_amount", 1_000)
    )
    chain_io = _FakeChainIO(value=terms.radiant_amount, confs=confs, missing=missing, mempool_unspent=mempool_unspent)
    leg = _FakeRadiantLeg(chain_io)
    ex = ClaimExecutor(
        resolve_leg=_resolver(leg),
        claim_status_source=_FakeStatusSource(claim_txid=claim_txid, claimed=status_claimed, confs=btc_confs),
        claim_bytes_source=_FakeBytesSource({claim_txid: raw}),
        policy=MarginPolicy.estimated(),
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
    # now_rxd = funded_h + confs - 1 = 100 + 100 - 1 = 199 > refund_opens (100 + 72 = 172) → SQUEEZED.
    chain_io = _FakeChainIO(value=terms.radiant_amount, funded_h=100, confs=100)
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
    # Single node says confs=1 → now_rxd=100 → SAFE. A corroborator reporting a DEEPER depth (100) makes
    # now_rxd=199 > refund_opens(172) → SQUEEZED → DECLINED. The deeper (MAX) read can't false-SAFE.
    ex, leg, rec, _ = await _armed_executor(confs=1, rxd_depth_corroborator=_FakeDepthCorroborator(depth=100))
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

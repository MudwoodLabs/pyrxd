"""Coordinator tests + a SIMULATED end-to-end swap with MOCK chains.

No real RPC, no live chain. The BTC + Radiant legs are duck-typed fakes that
record what the coordinator asked them to do and hand back the locator/secret the
real legs would. This exercises:

* the happy path NEGOTIATED -> ... -> COMPLETED (maker reveals p, taker scrapes &
  claims), asserting the taker ends up with the asset and the maker with the BTC;
* MUTUAL_REFUND (maker never claims) — both parties whole;
* PARAMS_MISMATCH (maker locks the wrong covenant) -> taker refunds BTC -> ABORTED;
* MAKER_STALLS (maker stalls past t_RXD - N) -> taker refunds the asset proactively
  -> ASSET_REFUNDED_TAKER_ACTS;
* the margin check (ordering / cross-unit fail-closed / real-value-needs-measured);
* H freshness via a persistent seen-store fake (reused H rejected);
* the secret is SecretBytes (unpicklable) and never lands in the persisted record.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import math
import os
import pickle

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.ref_authenticity import ResolvedRef
from pyrxd.gravity.swap_coordinator import (
    ESTIMATED_DEFAULT_MARGIN_BLOCKS,
    MAKER_SECRET_TAKER_LOCKS_BTC_FIRST,
    ClaimFinality,
    CoordinatorConfig,
    MarginPolicy,
    SwapCoordinator,
    assert_timelock_margin,
    assess_claim_finality,
    generate_secret,
    measure_margin_from_btc_block_times,
    should_taker_refund_proactively,
)
from pyrxd.gravity.swap_state import (
    NegotiatedTerms,
    SwapRecord,
    SwapState,
)
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import SecretBytes


def _verdict(confs: int, policy: MarginPolicy) -> CounterClaimFinality:
    """The PoW counter-claim verdict the coordinator builds inline from a depth read."""
    depth = policy.btc_claim_reorg_depth.normalize_to(t.TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
    return CounterClaimFinality.from_btc_depth(confs, depth)


# ---------------------------------------------------------------------------
# Mock chain legs + indexer + seen-store (duck-typed fakes; no Protocol)
# ---------------------------------------------------------------------------


def _xonly(sk=None) -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(sk or os.urandom(32)).format()


class FakeBtcLeg:
    """A duck-typed stand-in for ``BitcoinTaprootLeg``.

    Derives a REAL BtcHtlcLocator (so persistence round-trips genuinely) but the
    claim/refund just record calls instead of broadcasting. The maker's claim
    builds a real witness embedding p, so ``scrape_secret`` works for real.
    """

    def __init__(
        self, *, tamper_promised_spk: bool = False, fund_amount_delta: int = 0, claim_confs: int = 100
    ) -> None:
        self.tamper_promised_spk = tamper_promised_spk
        # Simulate a buggy/malicious leg (or a mutated `terms`) that funds the HTLC
        # with a value != the negotiated btc_sats. Positive = overfund, negative = under.
        self.fund_amount_delta = fund_amount_delta
        # Reorg gate: confirmation depth confirmations_of_claim reports. Default deep.
        self.claim_confs = claim_confs
        self.calls: list[str] = []
        self.last_locator: t.BtcHtlcLocator | None = None
        self.claimed_with: bytes | None = None
        self.refunded = False

    def _htlc(self, terms: NegotiatedTerms):
        return t.build_htlc(
            hashlock=terms.hashlock,
            claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
            refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
            timeout=terms.t_btc,
        )

    # Sync: pure SPK derivation, no chain access.
    def derive_funding_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        return self._htlc(terms).scriptpubkey

    def promised_funding_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        spk = self._htlc(terms).scriptpubkey
        if self.tamper_promised_spk:
            return spk[:-1] + bytes([spk[-1] ^ 0x01])
        return spk

    # Async: the real leg broadcasts/reads chain here.
    async def fund(self, terms: NegotiatedTerms) -> t.BtcHtlcLocator:
        self.calls.append("fund")
        amount = terms.btc_sats + self.fund_amount_delta
        loc = self._htlc(terms).with_funding(t.BtcOutpoint("ab" * 32, 0), amount)
        self.last_locator = loc
        return loc

    async def claim(self, locator: t.BtcHtlcLocator, preimage: bytes) -> None:
        # Real claim tx so scrape_secret has something to scrape.
        self.calls.append("claim")
        self.claimed_with = bytes(preimage)

    async def refund(self, locator: t.BtcHtlcLocator, timeout: t.Timelock) -> None:
        self.calls.append("refund")
        self.refunded = True

    def locked_amount(self, locator) -> int:
        return locator.amount_sats

    # Sync: pure byte-parse of the claim tx witness (no chain access).
    def scrape_secret(self, claim_tx_bytes: bytes, hashlock: bytes) -> bytes:
        return t.scrape_secret(claim_tx_bytes, hashlock)

    async def confirmations_of_claim(self, claim_tx_bytes: bytes) -> int:
        # Reorg gate input: default to a deep, reorg-safe claim. Tests that exercise
        # WAIT/SQUEEZED set `claim_confs` to a shallow value.
        return self.claim_confs


class FakeRadiantLeg:
    """A duck-typed stand-in for the Radiant covenant leg.

    The expected covenant SPK is a deterministic function of the negotiated terms
    + H (mirrors the real covenant's constructor binding). ``tamper`` flips the
    on-chain-vs-expected match to drive PARAMS_MISMATCH.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.claimed_with: bytes | None = None
        self.refunded = False

    async def expected_covenant_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        # Deterministic stand-in for the fused covenant SPK.
        body = (
            terms.hashlock
            + terms.genesis_ref
            + terms.taker_dest_hash
            + terms.maker_dest_hash
            + terms.radiant_amount.to_bytes(8, "little")
            + terms.t_rxd.to_nsequence().to_bytes(4, "little")
        )
        return b"\x76\xa9" + hashlib.sha256(body).digest()

    async def covenant_outpoint(self, terms: NegotiatedTerms) -> str:
        return "ef" * 32 + ":0"

    async def claim_asset(self, record: SwapRecord, preimage: bytes) -> None:
        self.calls.append("claim_asset")
        self.claimed_with = bytes(preimage)

    async def refund_asset(self, record: SwapRecord) -> None:
        self.calls.append("refund_asset")
        self.refunded = True


class FakeIndexer:
    """Async ``RefAuthenticityIndexer`` fake — resolves a ref to a ResolvedRef.

    ``authentic=True`` returns a ResolvedRef whose genesis_outpoint == the queried
    ref, with a gly marker and deep confirmations (passes every binding). The knobs
    drive each fail-closed path: ``raise_unavailable`` (indexer error),
    ``returns_none`` (unknown token), ``wrong_genesis`` (binding a/d),
    ``no_marker`` (binding b), ``confirmations`` (binding e).
    """

    def __init__(
        self,
        *,
        authentic: bool = True,
        raise_unavailable: bool = False,
        returns_none: bool = False,
        wrong_genesis: bool = False,
        no_marker: bool = False,
        confirmations: int = 100,
        payload_hash: bytes = b"\x99" * 32,
    ) -> None:
        self.authentic = authentic
        self.raise_unavailable = raise_unavailable
        self.returns_none = returns_none
        self.wrong_genesis = wrong_genesis
        self.no_marker = no_marker
        self.confirmations = confirmations
        self.payload_hash = payload_hash

    async def resolve_ref(self, genesis_ref: bytes) -> ResolvedRef | None:
        if self.raise_unavailable:
            raise RuntimeError("indexer unreachable")
        if self.returns_none or not self.authentic:
            return None
        return ResolvedRef(
            genesis_outpoint=(b"\xcc" * 36) if self.wrong_genesis else bytes(genesis_ref),
            has_gly_marker=not self.no_marker,
            payload_hash=self.payload_hash,
            confirmations=self.confirmations,
        )


class FakeSeenStore:
    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def reserve(self, hashlock: bytes) -> bool:
        h = bytes(hashlock)
        if h in self._seen:
            return False
        self._seen.add(h)
        return True

    def has_seen(self, hashlock: bytes) -> bool:
        return bytes(hashlock) in self._seen

    def mark_seen(self, hashlock: bytes) -> None:
        self._seen.add(bytes(hashlock))


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _terms(*, variant: str = "ft", t_btc_blocks: int = 144, t_rxd_blocks: int = 72, hashlock: bytes | None = None):
    if hashlock is None:
        hashlock = hashlib.sha256(os.urandom(32)).digest()
    return NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(t_btc_blocks, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
        asset_variant=variant,
        genesis_ref=b"\xaa" * 36 if variant in ("ft", "nft") else b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _coordinator(*, terms, btc_leg=None, radiant_leg=None, indexer=None, seen_store=None, policy=None, window=6):
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    return SwapCoordinator(
        record=rec,
        btc_leg=btc_leg or FakeBtcLeg(),
        radiant_leg=radiant_leg or FakeRadiantLeg(),
        indexer=indexer or FakeIndexer(),
        seen_store=seen_store or FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=policy or MarginPolicy.estimated(),
            maker_stall_safety_window_blocks=window,
        ),
    )


def _real_maker_claim_tx(locator: t.BtcHtlcLocator, preimage: bytes) -> bytes:
    """Build a real BTC claim tx (with p in the witness) for scrape tests."""
    import coincurve

    maker_sk = coincurve.PrivateKey(os.urandom(32))
    return t.build_claim_tx(
        locator=locator,
        preimage=preimage,
        claim_privkey=maker_sk.secret,
        to_scriptpubkey=b"\x00\x14" + b"\x00" * 20,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )


# ---------------------------------------------------------------------------
# Role invariant constant
# ---------------------------------------------------------------------------


def test_role_invariant_constant_spelled_out():
    inv = MAKER_SECRET_TAKER_LOCKS_BTC_FIRST
    assert inv.startswith("MAKER_SECRET_TAKER_LOCKS_BTC_FIRST")
    for phrase in ("generates the secret", "locks BTC FIRST", "locks the asset SECOND", "claims the BTC FIRST"):
        assert phrase in inv
    assert "t_BTC > t_RXD" in inv


# ---------------------------------------------------------------------------
# Margin check (C2/C3)
# ---------------------------------------------------------------------------


async def test_taker_funds_btc_rejects_amount_mismatch():
    """Regression (2026-05-24 panel): taker_funds_btc must bind the funded amount
    to the negotiated btc_sats. A P2TR scriptPubKey commits to the taptree, not the
    output value, so the pre-lock SPK check cannot catch a wrong amount — this Python
    assert is the only layer that can. Overfunding is a one-sided taker loss (the
    maker claims the whole output via the preimage); we reject both directions.
    """
    terms = _terms()

    # Overfund: leg locks more than negotiated -> reject, do not advance.
    over_leg = FakeBtcLeg(fund_amount_delta=50_000)
    seen = FakeSeenStore()
    coord = _coordinator(terms=terms, btc_leg=over_leg, seen_store=seen)
    with pytest.raises(ValidationError, match="funded counter-leg amount"):
        await coord.taker_funds_btc(terms)
    assert coord.record.state is SwapState.NEGOTIATED  # never advanced
    # H IS consumed here, NOT a regression: reserve() commits PRE-broadcast, and the
    # amount check runs AFTER fund() has already broadcast (a P2TR SPK cannot pin the
    # value, so the over-fund is only catchable post-lock). The BTC is locked on-chain
    # at this point, so the option is genuinely spent — burning the per-swap H is the
    # correct fail-closed posture (a fresh H is minted for any new swap).
    assert seen.has_seen(terms.hashlock)

    # Underfund: also rejected (self-correcting in practice, but fail-closed here).
    under_leg = FakeBtcLeg(fund_amount_delta=-1)
    coord2 = _coordinator(terms=terms, btc_leg=under_leg)
    with pytest.raises(ValidationError, match="funded counter-leg amount"):
        await coord2.taker_funds_btc(terms)

    # Exact match still funds and advances.
    ok_coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg())
    rec = await ok_coord.taker_funds_btc(terms)
    assert rec.state is SwapState.BTC_LOCKED


def test_margin_rejects_btc_not_greater_than_rxd():
    # Construct via direct Timelocks (NegotiatedTerms would also reject same-unit).
    policy = MarginPolicy.estimated()
    with pytest.raises(ValidationError):
        assert_timelock_margin(t.Timelock(72, t.TimeUnit.BLOCKS), t.Timelock(72, t.TimeUnit.BLOCKS), policy)


def test_margin_rejects_insufficient_gap():
    policy = MarginPolicy.estimated()  # 36-block ESTIMATED margin
    # gap = 10 blocks < 36 required
    with pytest.raises(ValidationError):
        assert_timelock_margin(t.Timelock(82, t.TimeUnit.BLOCKS), t.Timelock(72, t.TimeUnit.BLOCKS), policy)


def test_margin_accepts_safe_gap():
    policy = MarginPolicy.estimated()
    # gap = 100 blocks >= 36
    assert_timelock_margin(t.Timelock(172, t.TimeUnit.BLOCKS), t.Timelock(72, t.TimeUnit.BLOCKS), policy)


def test_margin_cross_unit_normalises():
    # t_btc in seconds, t_rxd in blocks; 600s/block. 144*600=86400s vs 72 blk=43200s,
    # gap = 72 blocks-equiv = enough for the 36-block margin.
    policy = MarginPolicy.estimated(block_interval_s=600.0)
    assert_timelock_margin(t.Timelock(86_400, t.TimeUnit.SECONDS), t.Timelock(72, t.TimeUnit.BLOCKS), policy)


def test_margin_fail_closed_on_non_timelock():
    policy = MarginPolicy.estimated()
    with pytest.raises(ValidationError):
        assert_timelock_margin(144, t.Timelock(72, t.TimeUnit.BLOCKS), policy)  # type: ignore[arg-type]


def test_margin_real_value_mode_requires_measured():
    # The ESTIMATED constructor in real-value mode is refused at construction.
    with pytest.raises(ValidationError):
        MarginPolicy.estimated(require_measured=True)
    # A measured policy in real-value mode is accepted.
    measured = MarginPolicy.measured(margin=t.Timelock(50, t.TimeUnit.BLOCKS), block_interval_s=600.0)
    assert measured.is_measured and measured.require_measured
    assert_timelock_margin(t.Timelock(200, t.TimeUnit.BLOCKS), t.Timelock(72, t.TimeUnit.BLOCKS), measured)


def test_estimated_margin_is_labelled():
    # Honesty: the default is an estimate, not a measurement.
    policy = MarginPolicy.estimated()
    assert policy.is_measured is False
    assert policy.margin.value == ESTIMATED_DEFAULT_MARGIN_BLOCKS


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------


def test_generate_secret_returns_secretbytes_and_matching_H():
    p, h = generate_secret()
    assert isinstance(p, SecretBytes)
    assert h == hashlib.sha256(p.unsafe_raw_bytes()).digest()


def test_secret_is_unpicklable():
    p, _h = generate_secret()
    with pytest.raises(TypeError):
        pickle.dumps(p)


# ---------------------------------------------------------------------------
# H freshness gate
# ---------------------------------------------------------------------------


async def test_reused_hashlock_rejected():
    store = FakeSeenStore()
    h = hashlib.sha256(os.urandom(32)).digest()
    store.mark_seen(h)  # already used in a prior swap
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms, seen_store=store)
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "reused" in gate.reason


async def test_seen_store_reserves_before_fund():
    """H is reserved when the swap COMMITS to broadcasting, not after fund success.

    (Renamed from test_seen_store_marks_only_after_successful_fund: under the
    TOCTOU-1 fix the consume is an atomic reserve() PRE-broadcast, so the old
    "only after success" promise no longer holds. Happy path still leaves H seen.)
    """
    store = FakeSeenStore()
    terms = _terms()
    coord = _coordinator(terms=terms, seen_store=store)
    assert not store.has_seen(terms.hashlock)
    await coord.taker_funds_btc(terms)
    assert store.has_seen(terms.hashlock)


def test_reserve_is_atomic_idempotent():
    """The contract that makes TOCTOU-1 closeable: reserve is a one-shot test-and-set."""
    store = FakeSeenStore()
    h = hashlib.sha256(os.urandom(32)).digest()
    assert store.reserve(h) is True  # first wins
    assert store.reserve(h) is False  # second is refused
    assert store.has_seen(h) is True


async def test_taker_funds_btc_reserves_before_broadcast_fail_closed():
    """A seen-store whose reserve() raises must fail CLOSED: refuse, never broadcast.

    Also pins the ORDER (reserve precedes fund): the leg's fund() must never be
    called when the reservation cannot be taken.
    """

    class RaisingReserveStore:
        def reserve(self, hashlock):
            raise RuntimeError("store backend down")

        def has_seen(self, hashlock):  # advisory probe used by the gate
            return False

    terms = _terms()
    leg = FakeBtcLeg()
    coord = _coordinator(terms=terms, btc_leg=leg, seen_store=RaisingReserveStore())
    with pytest.raises(ValidationError, match="seen-store unavailable; fail-closed"):
        await coord.taker_funds_btc(terms)
    assert "fund" not in leg.calls  # never broadcast
    assert coord.record.state is SwapState.NEGOTIATED  # never advanced


async def test_concurrent_funders_same_H_exactly_one_wins():
    """TOCTOU-1 regression: two coordinators sharing one seen-store + one H race to
    fund. The atomic pre-broadcast reserve() must let EXACTLY ONE broadcast; the other
    is refused (with nothing funded). Pre-fix, both passed the has_seen gate and both
    funded — a double-lock of the same H.

    To exercise the actual TOCTOU window we force a yield BETWEEN the gate's advisory
    has_seen probe and the reserve, via a slow persist hook (the intent-persist sits
    exactly there). Both tasks therefore clear the gate before EITHER reserves, so the
    loser must be caught by reserve() itself — proving the reserve, not the advisory
    gate, is the load-bearing guard. (Without the yield the gate would catch the loser
    first and the test would not touch the reserve path at all.)
    """

    async def slow_persist(_rec):
        await asyncio.sleep(0.02)

    terms = _terms()
    shared = FakeSeenStore()
    leg_a, leg_b = FakeBtcLeg(), FakeBtcLeg()

    def _coord(leg):
        return SwapCoordinator(
            record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
            btc_leg=leg,
            radiant_leg=FakeRadiantLeg(),
            indexer=FakeIndexer(),
            seen_store=shared,
            config=CoordinatorConfig(margin_policy=MarginPolicy.estimated()),
            persist=slow_persist,
        )

    coord_a, coord_b = _coord(leg_a), _coord(leg_b)
    results = await asyncio.gather(
        coord_a.taker_funds_btc(terms),
        coord_b.taker_funds_btc(terms),
        return_exceptions=True,
    )
    funded = [r for r in results if isinstance(r, SwapRecord)]
    refused = [r for r in results if isinstance(r, ValidationError)]
    assert len(funded) == 1, f"exactly one should fund, got {results!r}"
    # The loser is caught by the RESERVE (post-gate), not the advisory has_seen gate.
    assert len(refused) == 1 and "already reserved" in str(refused[0]), str(refused)
    # Exactly one leg broadcast; the refused coordinator never advanced.
    assert ("fund" in leg_a.calls) ^ ("fund" in leg_b.calls)
    states = {coord_a.record.state, coord_b.record.state}
    assert states == {SwapState.BTC_LOCKED, SwapState.NEGOTIATED}


def test_coordinator_refuses_nondurable_seen_on_value_bearing_network():
    """SEEN-1 guard: a value-bearing network + non-durable store + no opt-in => refuse.

    Mirrors RadiantCovenantLeg's require_audit_cleared gate so a long-lived /
    multi-process value-moving deployment cannot silently inherit the in-memory set.
    """
    terms = _terms()
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    value_leg = FakeBtcLeg()
    value_leg.network = "bc"  # mainnet => value-bearing
    cfg = CoordinatorConfig(margin_policy=MarginPolicy.estimated())

    with pytest.raises(ValidationError, match="NON-durable"):
        SwapCoordinator(
            record=rec,
            btc_leg=value_leg,
            radiant_leg=FakeRadiantLeg(),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),  # durable defaults False
            config=cfg,
        )

    # Explicit opt-in constructs fine (the conscious single-process dust posture).
    ok = SwapCoordinator(
        record=rec,
        btc_leg=value_leg,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated(), accept_nondurable_seen=True),
    )
    assert ok.seen_store is not None

    # A store declaring durability constructs fine even without the opt-in.
    class DurableStub:
        durable = True

        def reserve(self, h):
            return True

        def has_seen(self, h):
            return False

    durable_ok = SwapCoordinator(
        record=rec,
        btc_leg=value_leg,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=DurableStub(),
        config=cfg,
    )
    assert durable_ok.seen_store.durable is True


# ---------------------------------------------------------------------------
# Pre-BTC-lock gate: indexer fail-closed
# ---------------------------------------------------------------------------


async def test_pre_lock_indexer_unavailable_fail_closed():
    terms = _terms(variant="ft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(raise_unavailable=True))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "fail-closed" in gate.reason


async def test_pre_lock_indexer_says_inauthentic():
    terms = _terms(variant="nft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(authentic=False))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "REF authenticity failed" in gate.reason


async def test_pre_lock_ref_wrong_genesis_fail_closed():
    """Binding (a)/(d): a genuine glyph whose genesis outpoint != the advertised
    ref is the wrong asset — reject (the ref IS the asset identity)."""
    terms = _terms(variant="nft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(wrong_genesis=True))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "REF authenticity failed" in gate.reason


async def test_pre_lock_ref_no_gly_marker_fail_closed():
    """Binding (b): a bare singleton with no `gly` envelope (the exact R1 forgery)
    is rejected even if the outpoint matches."""
    terms = _terms(variant="ft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(no_marker=True))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "REF authenticity failed" in gate.reason


async def test_pre_lock_ref_shallow_genesis_fail_closed():
    """Binding (e): a genesis shallower than min_ref_confirmations can be reorged
    out after payment — reject."""
    terms = _terms(variant="nft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(confirmations=2))  # < default 6
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "REF authenticity failed" in gate.reason


async def test_pre_lock_maker_promised_params_mismatch():
    terms = _terms()
    coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg(tamper_promised_spk=True))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "promised" in gate.reason


async def test_taker_refuses_to_fund_on_failed_gate():
    terms = _terms()
    coord = _coordinator(terms=terms, indexer=FakeIndexer(authentic=False))
    with pytest.raises(ValidationError):
        await coord.taker_funds_btc(terms)


# ---------------------------------------------------------------------------
# MAKER_STALLS trigger (C1)
# ---------------------------------------------------------------------------


def test_should_refund_proactively_only_near_maturity():
    t_rxd = t.Timelock(72, t.TimeUnit.BLOCKS)
    # locked at 1000; maturity = 1072; window = 6 -> act at >= 1066.
    assert not should_taker_refund_proactively(
        now_block_height=1050,
        asset_locked_at_height=1000,
        t_rxd=t_rxd,
        safety_window_blocks=6,
        maker_has_claimed_btc=False,
    )
    assert should_taker_refund_proactively(
        now_block_height=1066,
        asset_locked_at_height=1000,
        t_rxd=t_rxd,
        safety_window_blocks=6,
        maker_has_claimed_btc=False,
    )


def test_should_not_refund_if_maker_already_claimed():
    # Once p is public the taker should scrape+claim, not refund.
    assert not should_taker_refund_proactively(
        now_block_height=2000,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        safety_window_blocks=6,
        maker_has_claimed_btc=True,
    )


# ---------------------------------------------------------------------------
# SIMULATED END-TO-END: happy path -> COMPLETED
# ---------------------------------------------------------------------------


async def test_e2e_happy_path_completed():
    # Maker generates p; only H goes into the terms.
    p_secret, h = generate_secret()
    terms = _terms(hashlock=h)

    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)

    # 1. Taker locks BTC first (gate passes, locator persisted).
    rec = await coord.taker_funds_btc(terms)
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.btc_locator is not None

    # 2. Maker locks the asset; on-chain SPK matches expected => BOTH_LOCKED.
    expected_spk = await rxd.expected_covenant_scriptpubkey(terms)
    rec = await coord.post_asset_lock_revalidate(expected_spk)
    assert rec.state is SwapState.BOTH_LOCKED

    # 3. Maker claims BTC, revealing p; p is zeroized after.
    rec = await coord.maker_claims_btc(p_secret)
    assert rec.state is SwapState.SECRET_REVEALED
    assert btc.claimed_with is not None and hashlib.sha256(btc.claimed_with).digest() == h
    with pytest.raises(Exception):
        p_secret.unsafe_raw_bytes()  # zeroized

    # 4. Taker scrapes p from the maker's real claim tx and claims the asset. The
    # maker's BTC claim is deep (FakeBtcLeg.claim_confs default) and the t_rxd window
    # has room, so the reorg gate returns SAFE.
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    rec = await coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED

    # Right party ends whole: maker got the BTC (claim called), taker got the asset.
    assert "claim" in btc.calls
    assert rxd.claimed_with is not None
    assert hashlib.sha256(rxd.claimed_with).digest() == h
    # No refunds happened on the happy path.
    assert not btc.refunded and not rxd.refunded


# ---------------------------------------------------------------------------
# SIMULATED: MUTUAL_REFUND (maker never claims)
# ---------------------------------------------------------------------------


async def test_e2e_mutual_refund_both_whole():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)

    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    assert coord.record.state is SwapState.BOTH_LOCKED

    # Maker never claims; both timeouts elapse; both refund.
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND
    # Both parties recovered their own assets — no one-sided loss.
    assert btc.refunded and rxd.refunded


# ---------------------------------------------------------------------------
# SIMULATED: PARAMS_MISMATCH (maker locks wrong covenant) -> taker refunds BTC
# ---------------------------------------------------------------------------


async def test_e2e_params_mismatch_taker_refunds_btc():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)

    await coord.taker_funds_btc(terms)

    # Maker locks the asset, but the on-chain covenant SPK is WRONG (tampered).
    wrong_spk = b"\xde\xad" + b"\x00" * 32
    rec = await coord.post_asset_lock_revalidate(wrong_spk)
    assert rec.state is SwapState.PARAMS_MISMATCH

    # Taker refunds the BTC via the timelock leg -> ABORTED.
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED
    assert btc.refunded
    # Taker is whole (got BTC back); maker never received BTC.
    assert "claim" not in btc.calls


# ---------------------------------------------------------------------------
# SIMULATED: MAKER_STALLS -> taker refunds asset proactively
# ---------------------------------------------------------------------------


async def test_e2e_maker_stalls_taker_refunds_asset():
    _p, h = generate_secret()
    terms = _terms(hashlock=h, t_rxd_blocks=72)
    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd, window=6)

    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    assert coord.record.state is SwapState.BOTH_LOCKED

    # Maker stalls: hasn't claimed and we are within N of t_RXD maturity.
    # locked at 1000; maturity = 1072; act at >= 1066.
    rec = await coord.maybe_refund_asset_on_maker_stall(
        now_block_height=1066, asset_locked_at_height=1000, maker_has_claimed_btc=False
    )
    assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS
    assert rxd.refunded  # the covenant CSV refund was broadcast — it pays the MAKER, not the taker.
    # NOTE: this exercises the helper's mechanics only. The CSV refund pays the maker (maker owns the
    # covenant), so this is NOT a taker recovery — the watchtower routes a taker to mutual_refund
    # instead (FSM finding #2, 2026-06-09). See test_xchain_swap_regtest_e2e for the taker-loss proof.


async def test_maker_stall_noop_before_window():
    _p, h = generate_secret()
    terms = _terms(hashlock=h, t_rxd_blocks=72)
    coord = _coordinator(terms=terms)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await coord.radiant_leg.expected_covenant_scriptpubkey(terms))
    # Far from maturity -> no-op, stays BOTH_LOCKED.
    rec = await coord.maybe_refund_asset_on_maker_stall(
        now_block_height=1000, asset_locked_at_height=1000, maker_has_claimed_btc=False
    )
    assert rec.state is SwapState.BOTH_LOCKED


# ---------------------------------------------------------------------------
# Crash recovery: the persisted record carries the full locator
# ---------------------------------------------------------------------------


async def test_crash_recovery_refund_from_persisted_record():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms)
    await coord.taker_funds_btc(terms)

    # Simulate a crash: serialise the record, lose all in-memory state, reload.
    blob = json.dumps(coord.record.to_dict())
    # Secret p is NOT in the blob.
    assert "preimage" not in blob.lower()
    reloaded = SwapRecord.from_dict(json.loads(blob))
    assert reloaded.btc_locator is not None

    # A fresh coordinator can refund the BTC purely from the reloaded record.
    btc2 = FakeBtcLeg()
    coord2 = SwapCoordinator(
        record=reloaded,
        btc_leg=btc2,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated()),
    )
    rec = await coord2.taker_refund_btc()
    assert rec.state is SwapState.ABORTED
    assert btc2.refunded


async def test_maker_claims_rejects_wrong_preimage():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await coord.radiant_leg.expected_covenant_scriptpubkey(terms))
    # A different secret that does not hash to H must be refused before broadcast.
    wrong = SecretBytes(os.urandom(32))
    with pytest.raises(ValidationError):
        await coord.maker_claims_btc(wrong)


# ---------------------------------------------------------------------------
# T7 D2: a SYNC gate over the async indexer fails OPEN — must be impossible
# ---------------------------------------------------------------------------


async def test_async_indexer_resolve_ref_is_actually_awaited():
    """Regression for the fail-OPEN catastrophe (T7 plan D2): if the gate were sync
    and merely *called* ``resolve_ref`` without awaiting, it would hold a truthy
    coroutine object and pass. Here we drive the real (async) gate and prove a
    counterfeit ref (resolve_ref returns None) is REJECTED — i.e. the gate awaits
    the coroutine and inspects its result, never a bare coroutine object.
    """
    terms = _terms(variant="nft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(returns_none=True))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "REF authenticity failed" in gate.reason
    # And funding is refused on that failed gate.
    with pytest.raises(ValidationError):
        await coord.taker_funds_btc(terms)


# ---------------------------------------------------------------------------
# T7 D1: persist-before-broadcast + asyncio.shield atomicity
# ---------------------------------------------------------------------------


class RecordingPersist:
    """An async persist hook that records the (state, has_locator) of every write."""

    def __init__(self) -> None:
        self.writes: list[tuple[SwapState, bool]] = []

    async def __call__(self, record: SwapRecord) -> None:
        self.writes.append((record.state, record.btc_locator is not None))


async def test_persist_intent_before_broadcast_then_shielded_after():
    """The intent record is persisted BEFORE the awaited fund/broadcast (so a crash
    leaves a recoverable record), and the funded record is persisted AFTER. Order:
    first write is still NEGOTIATED (pre-broadcast intent), the next is BTC_LOCKED
    with the locator (post-broadcast, shielded)."""
    terms = _terms()
    persist = RecordingPersist()
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        btc_leg=FakeBtcLeg(),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated()),
        persist=persist,
    )
    await coord.taker_funds_btc(terms)
    assert persist.writes[0] == (SwapState.NEGOTIATED, False)  # intent, pre-broadcast
    assert persist.writes[-1] == (SwapState.BTC_LOCKED, True)  # funded, post-broadcast


async def test_post_broadcast_persist_survives_cancellation():
    """The shielded post-broadcast persist must complete even if the awaiting task is
    cancelled right after the broadcast — otherwise the BTC is locked on-chain but
    the record never advanced (double-fund on retry, kieran-python HIGH)."""
    terms = _terms()
    completed: list[SwapState] = []

    async def slow_persist(record: SwapRecord) -> None:
        # Intent (pre-broadcast) write is fast; the post-broadcast BTC_LOCKED write is
        # slow + shielded, so the cancellation below lands squarely inside it.
        if record.state is SwapState.BTC_LOCKED:
            await asyncio.sleep(0.03)
        completed.append(record.state)

    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        btc_leg=FakeBtcLeg(),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated()),
        persist=slow_persist,
    )
    task = asyncio.ensure_future(coord.taker_funds_btc(terms))
    await asyncio.sleep(0.01)  # let it broadcast + enter the shielded persist
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # asyncio.shield detaches the inner persist; the outer await is cancelled but the
    # shielded write keeps running. Give it time to finish, then assert it completed.
    await asyncio.sleep(0.05)
    # The shielded BTC_LOCKED persist still completed despite the cancellation.
    assert SwapState.BTC_LOCKED in completed


# ---------------------------------------------------------------------------
# CoordinatorConfig: min_ref_confirmations validation
# ---------------------------------------------------------------------------


def test_config_rejects_bad_min_ref_confirmations():
    with pytest.raises(ValidationError):
        CoordinatorConfig(margin_policy=MarginPolicy.estimated(), min_ref_confirmations=-1)
    with pytest.raises(ValidationError):
        CoordinatorConfig(margin_policy=MarginPolicy.estimated(), min_ref_confirmations=True)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Reorg-finality gate (plan 2026-05-26, security-HIGH)
# ---------------------------------------------------------------------------


def test_margin_policy_rejects_reorg_depth_below_floor():
    """A 0 OR 1 block reorg depth defeats the gate — rejected at construction (floor >= 2).
    A 1-block depth is materially unsafe on a real chain (single-block reorgs happen);
    dust bounds the loss, not the reorg probability."""
    for bad in (0, 1):
        with pytest.raises(ValidationError, match="btc_claim_reorg_depth"):
            MarginPolicy(
                margin=t.Timelock(36, t.TimeUnit.BLOCKS),
                block_interval_s=600.0,
                is_measured=False,
                btc_claim_reorg_depth=t.Timelock(bad, t.TimeUnit.BLOCKS),
            )
        with pytest.raises(ValidationError, match="rxd_claim_burial"):
            MarginPolicy(
                margin=t.Timelock(36, t.TimeUnit.BLOCKS),
                block_interval_s=600.0,
                is_measured=False,
                rxd_claim_burial=t.Timelock(bad, t.TimeUnit.BLOCKS),
            )
    # The floor (2) itself is accepted — a defensible chosen dust value.
    ok = MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
    )
    assert ok.btc_claim_reorg_depth.value == 2

    # A seconds-tagged depth is floored in BLOCK terms too: 1 BTC block ~600s, so 60s
    # normalises to < 1 block -> below the 2-block floor -> rejected.
    with pytest.raises(ValidationError, match="btc_claim_reorg_depth"):
        MarginPolicy(
            margin=t.Timelock(36, t.TimeUnit.BLOCKS),
            block_interval_s=600.0,
            is_measured=False,
            btc_claim_reorg_depth=t.Timelock(60, t.TimeUnit.SECONDS),
        )


def _policy(*, btc_depth=6, rxd_burial=6):
    return MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(btc_depth, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(rxd_burial, t.TimeUnit.BLOCKS),
    )


def test_assess_claim_finality_safe():
    # Deep BTC claim (10 >= 6) + roomy window: locked@1000, t_rxd=72 -> opens@1072,
    # now=1000 -> 72 blocks left >= rxd_burial 6 -> SAFE.
    out = assess_claim_finality(
        counter_claim_finality=_verdict(10, _policy()),
        now_rxd_height=1000,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        policy=_policy(),
    )
    assert out is ClaimFinality.SAFE


def test_assess_claim_finality_wait():
    # Shallow BTC claim (1 < 6) but ample window: after waiting the remaining BTC
    # depth there is still room to bury -> WAIT.
    out = assess_claim_finality(
        counter_claim_finality=_verdict(1, _policy()),
        now_rxd_height=1000,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        policy=_policy(),
    )
    assert out is ClaimFinality.WAIT


def test_assess_claim_finality_squeezed_shallow_closing_window():
    # Shallow claim AND window closing: locked@1000, t_rxd=10 -> opens@1010, now=1006
    # -> 4 blocks left; after waiting btc depth there's no room to bury -> SQUEEZED.
    out = assess_claim_finality(
        counter_claim_finality=_verdict(1, _policy()),
        now_rxd_height=1006,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(10, t.TimeUnit.BLOCKS),
        policy=_policy(),
    )
    assert out is ClaimFinality.SQUEEZED


def test_assess_claim_finality_squeezed_deep_but_no_room():
    # Deep BTC claim but the window can't even fit our own burial -> SQUEEZED (don't
    # claim into a window that closes before we bury).
    out = assess_claim_finality(
        counter_claim_finality=_verdict(10, _policy()),
        now_rxd_height=1008,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(10, t.TimeUnit.BLOCKS),
        policy=_policy(),
    )
    assert out is ClaimFinality.SQUEEZED


def test_assess_claim_finality_fail_closed_on_bad_inputs():
    policy = _policy()
    # Negative confirmations now fail-closed at the verdict adapter, not the gate.
    with pytest.raises(ValidationError):
        CounterClaimFinality.from_btc_depth(-1, 6)
    # Bad Radiant heights still fail-closed at the gate.
    for bad in (dict(now_rxd_height=-1), dict(asset_locked_at_height=-1)):
        kw = dict(
            counter_claim_finality=_verdict(10, policy),
            now_rxd_height=1000,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            policy=policy,
        )
        kw.update(bad)
        with pytest.raises(ValidationError):
            assess_claim_finality(**kw)
    # Wrong t_rxd type.
    with pytest.raises(ValidationError):
        assess_claim_finality(
            counter_claim_finality=_verdict(10, policy),
            now_rxd_height=1000,
            asset_locked_at_height=1000,
            t_rxd=72,
            policy=policy,
        )  # type: ignore[arg-type]
    # A non-verdict input is rejected (no silent fail-open).
    with pytest.raises(ValidationError):
        assess_claim_finality(
            counter_claim_finality=10,
            now_rxd_height=1000,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            policy=policy,
        )  # type: ignore[arg-type]


def test_assess_claim_finality_rejects_now_below_lock_f013():
    # F-013: now_rxd_height < asset_locked_at_height is impossible on an honest chain
    # (a lagging/lying node). Fail-closed rather than computing an optimistic SAFE off
    # an inflated refund_opens_at.
    with pytest.raises(ValidationError, match="impossible on an honest chain"):
        assess_claim_finality(
            counter_claim_finality=_verdict(10, _policy()),
            now_rxd_height=999,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            policy=_policy(),
        )


def test_assess_claim_finality_f007_rxd_interval_scaling():
    # F-007: the BTC reorg depth must be converted from BTC blocks to RXD blocks before
    # subtracting from the RXD window. With btc=600s / rxd=300s (ratio 2), a 6-BTC-block
    # depth consumes 12 RXD blocks, not 6. A 14-RXD-block window looks safe-to-WAIT under
    # the old 1:1 conflation but is actually SQUEEZED.
    base = dict(
        now_rxd_height=1006,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(20, t.TimeUnit.BLOCKS),  # opens@1020 -> 14 blocks left
    )

    def _p(rxd_interval):
        return MarginPolicy(
            margin=t.Timelock(36, t.TimeUnit.BLOCKS),
            block_interval_s=600.0,
            is_measured=False,
            rxd_block_interval_s=rxd_interval,
            btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
            rxd_claim_burial=t.Timelock(6, t.TimeUnit.BLOCKS),
        )

    # shallow counter-claim (1 < depth 6).
    # ratio 2: 14 - ceil(6 * 600/300)=12 -> 2 < burial 6 -> SQUEEZED (correct)
    p2 = _p(300.0)
    assert assess_claim_finality(counter_claim_finality=_verdict(1, p2), **base, policy=p2) is ClaimFinality.SQUEEZED
    # ratio 1 (same interval) reproduces the old 1:1 behaviour: 14 - 6 = 8 >= 6 -> WAIT
    p1 = _p(600.0)
    assert assess_claim_finality(counter_claim_finality=_verdict(1, p1), **base, policy=p1) is ClaimFinality.WAIT


def test_assess_claim_finality_parity_sweep_byte_equivalent():
    """Auditor-grade regression: the verdict refactor reproduces the OLD int-based
    SAFE/WAIT/SQUEEZED decision byte-for-byte. Sweeps confs in 0..2*depth across several
    (now, t_rxd, policy) configs and asserts old-formula == new-verdict for every cell.
    """

    def _old(confs, now, locked, t_rxd, policy):
        bi, rbi = policy.block_interval_s, policy.rxd_block_interval_s
        rxd_blocks = t_rxd.normalize_to(t.TimeUnit.BLOCKS, block_interval_s=bi).value
        rxd_burial = policy.rxd_claim_burial.normalize_to(t.TimeUnit.BLOCKS, block_interval_s=bi).value
        depth = policy.btc_claim_reorg_depth.normalize_to(t.TimeUnit.BLOCKS, block_interval_s=bi).value
        blocks_left = (locked + rxd_blocks) - now
        if confs >= depth:
            return ClaimFinality.SAFE if blocks_left >= rxd_burial else ClaimFinality.SQUEEZED
        depth_in_rxd = math.ceil(depth * bi / rbi)
        remaining = depth - confs
        if blocks_left - depth_in_rxd >= rxd_burial and remaining > 0:
            return ClaimFinality.WAIT
        return ClaimFinality.SQUEEZED

    policies = [
        _policy(),
        MarginPolicy(
            margin=t.Timelock(36, t.TimeUnit.BLOCKS),
            block_interval_s=600.0,
            is_measured=False,
            rxd_block_interval_s=300.0,  # ratio 2 exercises the F-007 scaling
            btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
            rxd_claim_burial=t.Timelock(6, t.TimeUnit.BLOCKS),
        ),
    ]
    locked = 1000
    for policy in policies:
        depth = policy.btc_claim_reorg_depth.normalize_to(
            t.TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s
        ).value
        for t_rxd_blocks in (10, 20, 36, 72):
            t_rxd = t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS)
            for now in range(locked, locked + t_rxd_blocks + 1):
                for confs in range(0, 2 * depth + 1):
                    expected = _old(confs, now, locked, t_rxd, policy)
                    got = assess_claim_finality(
                        counter_claim_finality=CounterClaimFinality.from_btc_depth(confs, depth),
                        now_rxd_height=now,
                        asset_locked_at_height=locked,
                        t_rxd=t_rxd,
                        policy=policy,
                    )
                    assert got is expected, (confs, now, t_rxd_blocks, policy.rxd_block_interval_s, got, expected)


def test_assess_claim_finality_eth_stall_squeezes():
    # RF-06: a COUNTER_CHAIN_NOT_FINALIZING verdict (ETH non-finality stall) SQUEEZES even
    # in a roomy window where a FINAL verdict would be SAFE.
    policy = _policy()
    roomy = dict(
        now_rxd_height=1000,
        asset_locked_at_height=1000,
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        policy=policy,
    )
    assert assess_claim_finality(counter_claim_finality=_verdict(10, policy), **roomy) is ClaimFinality.SAFE
    stalled = CounterClaimFinality(state=CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING)
    assert assess_claim_finality(counter_claim_finality=stalled, **roomy) is ClaimFinality.SQUEEZED


async def test_gate_safe_claims_asset():
    p_secret, h = generate_secret()
    terms = _terms(variant="rxd", t_rxd_blocks=72, hashlock=h)
    btc = FakeBtcLeg(claim_confs=10)
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    rec = await coord.maker_claims_btc(p_secret)
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    rec = await coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with is not None  # asset actually claimed


async def test_gate_wait_does_not_claim_and_stays_secret_revealed():
    p_secret, h = generate_secret()
    terms = _terms(variant="rxd", t_rxd_blocks=72, hashlock=h)
    btc = FakeBtcLeg(claim_confs=1)  # shallow
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    rec = await coord.maker_claims_btc(p_secret)
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    rec = await coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000)
    # FAIL-OPEN REGRESSION: a shallow BTC claim must NOT settle the asset.
    assert rec.state is SwapState.SECRET_REVEALED
    assert rxd.claimed_with is None  # asset NOT claimed


async def test_serialized_step_concurrent_duplicate_step_acts_once():
    """@_serialized_step (#2b): two concurrent invocations of the SAME step on ONE
    coordinator do not interleave — exactly one acts, the other gets a clean FSM-state
    rejection, NOT a double broadcast. A slow Radiant claim forces the interleave
    attempt; without the per-instance lock both would pass the SECRET_REVEALED check
    and both claim the asset.
    """

    class SlowClaimRxd(FakeRadiantLeg):
        async def claim_asset(self, record, preimage):
            await asyncio.sleep(0.02)
            return await super().claim_asset(record, preimage)

    p_secret, h = generate_secret()
    terms = _terms(variant="rxd", t_rxd_blocks=72, hashlock=h)
    btc = FakeBtcLeg(claim_confs=10)
    rxd = SlowClaimRxd()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    rec = await coord.maker_claims_btc(p_secret)
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)

    results = await asyncio.gather(
        coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000),
        coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000),
        return_exceptions=True,
    )
    completed = [r for r in results if isinstance(r, SwapRecord)]
    rejected = [r for r in results if isinstance(r, ValidationError)]
    assert len(completed) == 1 and completed[0].state is SwapState.COMPLETED
    assert len(rejected) == 1 and "only valid from SECRET_REVEALED" in str(rejected[0])
    assert rxd.calls.count("claim_asset") == 1  # serialized: asset claimed exactly once


async def test_scrape_rejects_claim_tx_for_foreign_funding_outpoint():
    """Provenance gate (#3): a claim tx that reveals the right p but spends a DIFFERENT
    funding outpoint (a wrong / cross-swap claim tx) is refused before any asset claim.
    """
    p_secret, h = generate_secret()
    terms = _terms(variant="rxd", t_rxd_blocks=72, hashlock=h)
    btc = FakeBtcLeg(claim_confs=10)
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    rec = await coord.maker_claims_btc(p_secret)

    # A claim tx revealing the SAME p but spending a different outpoint than our HTLC.
    foreign = dataclasses.replace(rec.btc_locator, funding_outpoint=t.BtcOutpoint("cd" * 32, 1))
    foreign_claim = _real_maker_claim_tx(foreign, btc.claimed_with)
    with pytest.raises(ValidationError, match="does not spend this swap"):
        await coord.taker_scrape_and_claim_asset(foreign_claim, now_rxd_height=1000, asset_locked_at_height=1000)
    assert rxd.claimed_with is None  # asset NOT claimed off a foreign claim tx
    assert coord.record.state is SwapState.SECRET_REVEALED  # no advance on a refused scrape

    # Sanity: the LEGIT claim tx (spending our outpoint) still settles.
    legit = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    rec2 = await coord.taker_scrape_and_claim_asset(legit, now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec2.state is SwapState.COMPLETED


async def test_gate_squeezed_goes_vulnerable_then_explicit_claim():
    p_secret, h = generate_secret()
    terms = _terms(variant="rxd", t_rxd_blocks=10, hashlock=h)
    btc = FakeBtcLeg(claim_confs=1)  # shallow
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    rec = await coord.maker_claims_btc(p_secret)
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    # Window closing (now near t_rxd maturity) + shallow -> SQUEEZED -> ASSET_VULNERABLE.
    rec = await coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1006, asset_locked_at_height=1000)
    assert rec.state is SwapState.ASSET_VULNERABLE
    assert rxd.claimed_with is None  # not auto-claimed
    # The deliberate winner-take-all claim is a separate, explicit decision.
    rec = await coord.taker_claim_asset_from_vulnerable(claim_tx)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with is not None


async def test_gate_fail_closed_on_confs_read_error():
    class ErrLeg(FakeBtcLeg):
        async def confirmations_of_claim(self, claim_tx_bytes: bytes) -> int:
            raise RuntimeError("node unreachable")

    p_secret, h = generate_secret()
    terms = _terms(variant="rxd", t_rxd_blocks=72, hashlock=h)
    btc = ErrLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    rec = await coord.maker_claims_btc(p_secret)
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    with pytest.raises(RuntimeError):  # propagates fail-closed; no claim
        await coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000)
    assert rxd.claimed_with is None


async def test_claim_from_vulnerable_rejects_wrong_state():
    _p, h = generate_secret()
    terms = _terms(variant="rxd", hashlock=h)
    coord = _coordinator(terms=terms)  # state NEGOTIATED, not ASSET_VULNERABLE
    with pytest.raises(ValidationError, match="only valid from ASSET_VULNERABLE"):
        await coord.taker_claim_asset_from_vulnerable(b"\x00")


# ---------------------------------------------------------------------------
# Measured MarginPolicy from BTC block times (P-SAFE-1b)
# ---------------------------------------------------------------------------


def test_measure_margin_from_btc_block_times_basic():
    # 11 timestamps -> 10 gaps, all multiples of 600 so percentile picks are exact.
    # gaps sorted: [600]*8, 1200, 1800. Median (index 5) = 600 -> interval 600.
    base = 1_700_000_000
    ts = [base]
    for gap in (600, 600, 600, 600, 1200, 600, 1800, 600, 600, 600):
        ts.append(ts[-1] + gap)
    policy, prov = measure_margin_from_btc_block_times(
        btc_block_timestamps=ts,
        btc_tail_percentile=99.9,  # nearest-rank over 10 gaps -> the max
        btc_claim_reorg_depth_blocks=3,
        rxd_claim_burial_blocks=3,
        rxd_block_interval_s=300.0,
    )
    assert policy.is_measured and policy.require_measured
    assert policy.btc_claim_reorg_depth.value == 3
    assert prov["measured"]["btc_block_interval_s_median"] == 600
    # 99.9th-pct tail = max gap 1800s -> ceil(1800/600) = 3-block margin.
    assert prov["measured"]["btc_tail_gap_s"] == 1800
    assert policy.margin.value == 3
    assert prov["chosen"]["min_reorg_depth_floor_blocks"] == 2
    assert "MEASURED" in prov["note"] and "CHOSEN" in prov["note"]


def test_measure_margin_handles_unordered_and_equal_timestamps():
    base = 1_700_000_000
    ts = [base + 1200, base, base + 600, base + 600, base + 1800]  # unordered + a duplicate
    policy, prov = measure_margin_from_btc_block_times(
        btc_block_timestamps=ts,
        btc_tail_percentile=75.0,
        btc_claim_reorg_depth_blocks=2,
        rxd_claim_burial_blocks=2,
        rxd_block_interval_s=300.0,
    )
    assert policy.margin.value >= 1  # never below a block
    assert prov["measured"]["btc_samples"] == 5


def test_measure_margin_rejects_thin_or_bad_inputs():
    with pytest.raises(ValidationError, match=">= 3 BTC block timestamps"):
        measure_margin_from_btc_block_times(
            btc_block_timestamps=[1, 2],
            btc_tail_percentile=90.0,
            btc_claim_reorg_depth_blocks=3,
            rxd_claim_burial_blocks=3,
            rxd_block_interval_s=300.0,
        )
    with pytest.raises(ValidationError, match="btc_tail_percentile"):
        measure_margin_from_btc_block_times(
            btc_block_timestamps=[1, 2, 3, 4],
            btc_tail_percentile=10.0,
            btc_claim_reorg_depth_blocks=3,
            rxd_claim_burial_blocks=3,
            rxd_block_interval_s=300.0,
        )
    with pytest.raises(ValidationError, match="must all be ints"):
        measure_margin_from_btc_block_times(
            btc_block_timestamps=[1, 2.5, 3],
            btc_tail_percentile=90.0,  # type: ignore[list-item]
            btc_claim_reorg_depth_blocks=3,
            rxd_claim_burial_blocks=3,
            rxd_block_interval_s=300.0,
        )


def test_measure_margin_inherits_reorg_depth_floor():
    # A chosen depth below the floor must be rejected by MarginPolicy even via the helper.
    ts = [1_700_000_000 + i * 600 for i in range(6)]
    with pytest.raises(ValidationError, match="btc_claim_reorg_depth"):
        measure_margin_from_btc_block_times(
            btc_block_timestamps=ts,
            btc_tail_percentile=90.0,
            btc_claim_reorg_depth_blocks=1,
            rxd_claim_burial_blocks=3,
            rxd_block_interval_s=300.0,
        )


# --------------------------------------------------------------------------- C2a: §9 ETH reserve


def _eth_finality_policy(*, window_s=768, is_measured=False, rxd_block_interval_s=300.0):
    return MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=is_measured,
        rxd_block_interval_s=rxd_block_interval_s,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(6, t.TimeUnit.BLOCKS),
        eth_finalization_window_s=window_s,
    )


def _eth_not_final():
    # ETH verdict: no depth -> remaining_positive True, reserve from eth_finalization_window_s
    return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)


def test_eth_not_yet_final_uses_finalization_window():
    policy = _eth_finality_policy(window_s=768)  # 768s / 300 = ceil 3 RXD blocks
    # roomy: opens@1072, now=1000 -> 72 left; 72 - 3 >= 6 -> WAIT
    assert (
        assess_claim_finality(
            counter_claim_finality=_eth_not_final(),
            now_rxd_height=1000,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            policy=policy,
        )
        is ClaimFinality.WAIT
    )
    # closing: opens@1010, now=1006 -> 4 left; 4 - 3 = 1 < 6 -> SQUEEZED
    assert (
        assess_claim_finality(
            counter_claim_finality=_eth_not_final(),
            now_rxd_height=1006,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(10, t.TimeUnit.BLOCKS),
            policy=policy,
        )
        is ClaimFinality.SQUEEZED
    )


def test_eth_verdict_without_finalization_window_fail_closed():
    policy = MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(6, t.TimeUnit.BLOCKS),
    )  # eth_finalization_window_s defaults None
    with pytest.raises(ValidationError, match="eth_finalization_window_s"):
        assess_claim_finality(
            counter_claim_finality=_eth_not_final(),
            now_rxd_height=1000,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            policy=policy,
        )


def test_dual_source_reorg_depth_divergence_fail_closed():
    # §9 #2: a PoW verdict whose required_depth disagrees with the policy depth is refused.
    policy = _policy()
    diverging = CounterClaimFinality.from_btc_depth(1, 100)  # required_depth 100 != policy depth
    with pytest.raises(ValidationError, match="divergent reserve"):
        assess_claim_finality(
            counter_claim_finality=diverging,
            now_rxd_height=1000,
            asset_locked_at_height=1000,
            t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
            policy=policy,
        )


# --------------------------------------------------------------------------- C2b + R6: ETH claim flow
#
# The coordinator's BTC↔RXD claim path is exercised end-to-end above via the FSM. The ETH
# variant shares the RXD leg + FSM + reorg gate; only the COUNTER-leg differs (tx-hash claim
# ref, calldata/log scrape, finalized-checkpoint verdict, contract-address provenance). These
# tests drive a record straight to SECRET_REVEALED with an EthHtlcLocator (the ETH funding
# path is a separate concern, proven on Anvil in Phase 4) and assert the dispatch + gate order.


class FakeEthLeg:
    """Duck-typed stand-in for EthLeg, from SECRET_REVEALED onward.

    Returns the known preimage from scrape (the coordinator re-verifies sha256==H), a
    configurable finality verdict, and a provenance gate that records its args and can be
    flipped to fail-closed. No ``network`` attr → the value-bearing/durable gate stays off.
    """

    def __init__(
        self,
        *,
        preimage,
        verdict: CounterClaimFinality,
        provenance_ok: bool = True,
        fund_amount_delta: int = 0,
        verify_raises: bool = False,
    ) -> None:
        self._p = preimage.unsafe_raw_bytes() if isinstance(preimage, SecretBytes) else bytes(preimage)
        self._verdict = verdict
        self.provenance_ok = provenance_ok
        self.fund_amount_delta = fund_amount_delta  # simulate a mis-funded (over/under) contract
        self.verify_raises = verify_raises  # simulate verify_funded failing AFTER deploy (atomicity inversion)
        self.calls: list[str] = []
        self.provenance_args: dict | None = None
        self.last_locator: EthHtlcLocator | None = None
        self.claimed_with: bytes | None = None
        self.refunded = False
        self.counterparty_verify_raises = False  # simulate a hostile-taker contract (claimant!=maker)

    # -- fund-path (full lifecycle) ----------------------------------------------------
    def _commitment(self, terms) -> bytes:
        return hashlib.sha256(
            b"fake-eth-commit" + terms.hashlock + int(terms.value_amount).to_bytes(32, "big")
        ).digest()

    def derive_funding_scriptpubkey(self, terms) -> bytes:
        return self._commitment(terms)

    def promised_funding_scriptpubkey(self, terms) -> bytes:
        return self._commitment(terms)

    def locked_amount(self, locator) -> int:
        return locator.amount_wei

    async def fund(self, terms) -> EthHtlcLocator:
        # Deploy+fund THEN verify (the ETH ordering the audit flagged): if verify_raises, the
        # contract is already deployed on-chain when we raise — the atomicity inversion.
        self.calls.append("fund")
        loc = EthHtlcLocator(
            chain_id=11155111,
            contract_address="0x" + "ab" * 20,
            deploy_tx_hash="0x" + "cd" * 32,
            hashlock="0x" + terms.hashlock.hex(),
            claimant="0x" + "11" * 20,
            refundee="0x" + "22" * 20,
            timeout=terms.eth_timeout_unix_s,
            amount_wei=int(terms.value_amount) + self.fund_amount_delta,
        )
        self.last_locator = loc
        if self.verify_raises:
            raise ValidationError("verify_funded failed AFTER deploy (contract is live on-chain)")
        return loc

    async def claim(self, locator, preimage) -> str:
        self.calls.append("claim")
        self.claimed_with = bytes(preimage)
        return "0xethclaim"

    async def refund(self, locator, timeout=None) -> str:
        self.calls.append("refund")
        self.refunded = True
        return "0xethrefund"

    async def fetch_claim_artifacts(self, tx_hash) -> list[bytes]:
        self.calls.append("fetch")
        return [b"\x00\x00\x00\x00" + self._p]  # p after a 4-byte selector

    def scrape_secret(self, artifacts, hashlock) -> bytes:
        self.calls.append("scrape")
        return self._p

    async def assert_claim_provenance(self, tx_hash, *, contract_address, preimage) -> None:
        self.calls.append("provenance")
        self.provenance_args = {"tx_hash": tx_hash, "contract_address": contract_address, "preimage": preimage}
        if not self.provenance_ok:
            raise ValidationError("claim tx 'to' is not this swap's HTLC contract address")

    async def claim_finality_verdict(self, tx_hash) -> CounterClaimFinality:
        self.calls.append("verdict")
        return self._verdict

    async def verify_counterparty_funded(self, contract_address, terms, *, block_identifier=None):
        """MAKER-side gate stand-in: records the call, raises if configured hostile, else returns a
        locator bound to the contract address (the real EthLeg builds it from the maker's config).
        ``block_identifier`` ('finalized' on the real-value re-verify) is recorded for assertions."""
        self.calls.append("verify_counterparty")
        self.last_verify_block_identifier = block_identifier
        self.last_locator = EthHtlcLocator(
            chain_id=11155111,
            contract_address=contract_address,
            deploy_tx_hash="0x" + "00" * 32,
            hashlock="0x" + bytes(terms.hashlock).hex(),
            claimant="0x" + "11" * 20,
            refundee="0x" + "22" * 20,
            timeout=terms.eth_timeout_unix_s,
            amount_wei=int(terms.value_amount),
        )
        if self.counterparty_verify_raises:
            raise ValidationError("on-chain claimant != negotiated maker (hostile taker contract)")
        return self.last_locator


def _eth_terms(*, hashlock: bytes, t_rxd_blocks: int = 72, eth_timeout_unix_s: int = 1779710245):
    return NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x00" * 32,  # eth: x-only fields are the _ZERO32 placeholder
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=10**15,
        eth_timeout_unix_s=eth_timeout_unix_s,
    )


def _eth_locator(hashlock: bytes) -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address="0x" + "ab" * 20,
        deploy_tx_hash="0x" + "cd" * 32,
        hashlock="0x" + hashlock.hex(),
        claimant="0x" + "11" * 20,
        refundee="0x" + "22" * 20,
        timeout=1779710245,
        amount_wei=10**15,
    )


def _eth_coord_at_secret_revealed(*, eth_leg, terms, radiant_leg=None, policy=None):
    rec = SwapRecord(state=SwapState.SECRET_REVEALED, terms=terms, counterchain_locator=_eth_locator(terms.hashlock))
    return SwapCoordinator(
        record=rec,
        counter_leg=eth_leg,
        radiant_leg=radiant_leg or FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=policy or _eth_finality_policy(window_s=768),
            maker_stall_safety_window_blocks=6,
        ),
    )


def _final():
    return CounterClaimFinality(state=CounterClaimState.FINAL)


def _eth_not_final_verdict():
    return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)


def _eth_coord_at_btc_locked(*, eth_leg, terms, policy=None, n=6):
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms)
    return SwapCoordinator(
        record=rec,
        counter_leg=eth_leg,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=policy or _eth_finality_policy(window_s=768),
            maker_stall_safety_window_blocks=n,
        ),
    )


# -- red-team CRITICAL: maker-side counter-funding verification gate -------------------


async def test_maker_verify_counter_funding_refuses_hostile_taker_contract():
    """The honest maker's coordinator gate fails closed when the taker-deployed ETH HTLC does not
    bind to terms (claimant!=maker) — so the maker never locks the asset (red-team CRITICAL)."""
    p, h = generate_secret()
    leg = FakeEthLeg(preimage=p, verdict=_final())
    leg.counterparty_verify_raises = True  # hostile taker contract
    coord = _eth_coord_at_btc_locked(eth_leg=leg, terms=_eth_terms(hashlock=h))
    with pytest.raises(ValidationError, match="claimant"):
        await coord.maker_verify_counter_funding("0x" + "99" * 20)
    assert "verify_counterparty" in leg.calls
    # The maker never advanced past BTC_LOCKED (asset untouched).
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_maker_verify_counter_funding_records_locator_on_success():
    """On a well-funded taker contract the gate returns, recording the verified locator so the
    maker's subsequent claim has the contract address."""
    p, h = generate_secret()
    leg = FakeEthLeg(preimage=p, verdict=_final())
    coord = _eth_coord_at_btc_locked(eth_leg=leg, terms=_eth_terms(hashlock=h))
    rec = await coord.maker_verify_counter_funding("0x" + "99" * 20)
    assert rec.counterchain_locator is not None
    assert rec.counterchain_locator.contract_address.lower() == ("0x" + "99" * 20).lower()


async def test_maker_verify_counter_funding_rejects_btc_leg():
    """The gate is ETH-specific (BTC funding target is pre-derivable + bound by derive==promised)."""
    _p, h = generate_secret()
    btc_terms = _terms(hashlock=h)  # counter_chain defaults to btc
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.BTC_LOCKED, terms=btc_terms),
        counter_leg=FakeBtcLeg(),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=_policy()),
    )
    with pytest.raises(ValidationError, match="ETH counter leg"):
        await coord.maker_verify_counter_funding("0x" + "99" * 20)


# -- red-team HIGH: proactive-refund N coupled to the ETH finality reserve -------------


def test_eth_config_rejects_small_N_below_finality_reserve_when_measured():
    """A REAL-VALUE (is_measured) ETH config with N below the finality+burial reserve floor is
    refused at construction — a maker could otherwise time its reveal into a SQUEEZE window."""
    p, h = generate_secret()
    measured = _eth_finality_policy(window_s=768, is_measured=True, rxd_block_interval_s=300.0)
    # floor = ceil(768/300)=3 + burial 6 - 1 = 8; N=6 < 8 -> reject
    with pytest.raises(ValidationError, match="finality\\+burial reserve floor"):
        SwapCoordinator(
            record=SwapRecord(state=SwapState.NEGOTIATED, terms=_eth_terms(hashlock=h)),
            counter_leg=FakeEthLeg(preimage=p, verdict=_final()),
            radiant_leg=FakeRadiantLeg(),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(margin_policy=measured, maker_stall_safety_window_blocks=6),
        )
    # N=8 satisfies the floor -> constructs fine
    SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=_eth_terms(hashlock=h)),
        counter_leg=FakeEthLeg(preimage=p, verdict=_final()),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=measured, maker_stall_safety_window_blocks=8),
    )


async def test_eth_claim_safe_settles_and_runs_provenance():
    p, h = generate_secret()
    terms = _eth_terms(hashlock=h)
    leg = FakeEthLeg(preimage=p, verdict=_final())
    rxd = FakeRadiantLeg()
    coord = _eth_coord_at_secret_revealed(eth_leg=leg, terms=terms, radiant_leg=rxd)
    rec = await coord.taker_scrape_and_claim_asset("0xclaim", now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with == p.unsafe_raw_bytes()  # asset claimed with the scraped p
    # Gate order: scrape, then provenance, then verdict — provenance BEFORE the verdict/claim.
    assert leg.calls == ["fetch", "scrape", "provenance", "verdict"]
    assert leg.provenance_args["contract_address"] == "0x" + "ab" * 20
    assert leg.provenance_args["preimage"] == p.unsafe_raw_bytes()  # binds the SECRET p, not H


async def test_eth_claim_rejects_failed_provenance_no_claim():
    p, h = generate_secret()
    terms = _eth_terms(hashlock=h)
    leg = FakeEthLeg(preimage=p, verdict=_final(), provenance_ok=False)
    rxd = FakeRadiantLeg()
    coord = _eth_coord_at_secret_revealed(eth_leg=leg, terms=terms, radiant_leg=rxd)
    with pytest.raises(ValidationError, match="not this swap's HTLC contract"):
        await coord.taker_scrape_and_claim_asset("0xforeign", now_rxd_height=1000, asset_locked_at_height=1000)
    assert rxd.claimed_with is None  # never claimed off a foreign claim tx
    assert coord.record.state is SwapState.SECRET_REVEALED  # no advance
    assert "verdict" not in leg.calls  # fail-closed BEFORE the finality read/claim


async def test_eth_claim_wait_stays_secret_revealed():
    p, h = generate_secret()
    terms = _eth_terms(hashlock=h, t_rxd_blocks=72)  # roomy
    leg = FakeEthLeg(preimage=p, verdict=_eth_not_final_verdict())
    rxd = FakeRadiantLeg()
    coord = _eth_coord_at_secret_revealed(eth_leg=leg, terms=terms, radiant_leg=rxd)
    rec = await coord.taker_scrape_and_claim_asset("0xclaim", now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.SECRET_REVEALED  # not-yet-final + room → WAIT, no claim
    assert rxd.claimed_with is None


async def test_eth_claim_squeezed_then_explicit_vulnerable_claim():
    p, h = generate_secret()
    terms = _eth_terms(hashlock=h, t_rxd_blocks=10)  # window closing
    leg = FakeEthLeg(preimage=p, verdict=_eth_not_final_verdict())
    rxd = FakeRadiantLeg()
    coord = _eth_coord_at_secret_revealed(eth_leg=leg, terms=terms, radiant_leg=rxd)
    # not-yet-final + closing window → SQUEEZED → ASSET_VULNERABLE, no auto-claim
    rec = await coord.taker_scrape_and_claim_asset("0xclaim", now_rxd_height=1006, asset_locked_at_height=1000)
    assert rec.state is SwapState.ASSET_VULNERABLE
    assert rxd.claimed_with is None
    # The deliberate winner-take-all claim (ETH path) runs scrape + provenance and settles.
    rec = await coord.taker_claim_asset_from_vulnerable("0xclaim")
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with == p.unsafe_raw_bytes()


async def test_eth_late_reveal_races_csv_taker_squeezed_then_cannot_claim_spent_covenant():
    """HIGH #2 (red-team) — the reveal-on-the-LONG-leg FREE-OPTION, late-reveal-races-CSV variant.

    The inherent reactor-unsafe ordering: the maker (secret holder) reveals p on the LONG (ETH) leg
    while the honest taker must react on the SHORT (RXD) leg. A malicious maker waits until the t_rxd
    window has all but closed before revealing (claiming ETH — so the reveal is genuinely FINAL, not
    a stall), then races its own covenant CSV refund (which pays the maker, needs no preimage). This
    closes the test gap the red-team verifier flagged: S1 is a full stall, S2 is the premature-claim
    race, S4 is a bare not-yet-final squeeze — none drive a FINAL-but-too-late reveal against an
    ALREADY-CSV-REFUNDED covenant. The safety assertion is that the honest taker is NEVER silently
    driven to COMPLETED: the reorg gate SQUEEZES the late FINAL reveal to ASSET_VULNERABLE, and the
    deliberate winner-take-all claim then FAILS against the spent covenant, leaving the documented
    ONE_SIDED_LOSS residual (FSM ASSET_VULNERABLE -> ONE_SIDED_LOSS_TAKER) — an accepted, pre-audit
    inherent HTLC property, surfaced loudly, not a false success. (See eth_rxd_timelock.py: this is
    why the cross-clock margin couples N to the finality+burial reserve, and why it is audit-gated.)"""
    p, h = generate_secret()
    terms = _eth_terms(hashlock=h, t_rxd_blocks=72)
    leg = FakeEthLeg(preimage=p, verdict=_final())  # the ETH claim IS final — maker revealed at t_eth-epsilon

    # Maker already CSV-refunded the covenant to itself: the taker's Radiant claim must fail closed
    # (the UTXO is gone). This is the on-chain reality the winner-take-all race loses.
    class _SpentCovenantRadiantLeg(FakeRadiantLeg):
        async def claim_asset(self, record, preimage):
            self.calls.append("claim_asset")
            raise NetworkError("covenant UTXO already spent (maker CSV-refunded the asset)")

    rxd = _SpentCovenantRadiantLeg()
    coord = _eth_coord_at_secret_revealed(eth_leg=leg, terms=terms, radiant_leg=rxd)
    # refund opens @ 1000+72=1072; the maker revealed only as it closed: now=1070 -> 2 blocks left <
    # rxd_burial(6). FINAL verdict + a window that no longer fits our own burial -> SQUEEZED, NOT an
    # automatic claim (the gate refuses to claim off a window it cannot safely bury in).
    rec = await coord.taker_scrape_and_claim_asset("0xlateclaim", now_rxd_height=1070, asset_locked_at_height=1000)
    assert rec.state is SwapState.ASSET_VULNERABLE, (
        f"a FINAL but too-late reveal must SQUEEZE to ASSET_VULNERABLE, got {rec.state.value}"
    )
    assert rxd.claimed_with is None  # no automatic claim happened
    # The deliberate winner-take-all race against the already-spent covenant fails closed; the honest
    # taker stays in the documented ONE_SIDED_LOSS residual — it is NEVER advanced to COMPLETED.
    with pytest.raises(NetworkError, match="already spent"):
        await coord.taker_claim_asset_from_vulnerable("0xlateclaim")
    assert coord.record.state is SwapState.ASSET_VULNERABLE  # not COMPLETED
    assert "claim_asset" in rxd.calls  # it really attempted (and lost) the race


# --------------------------------------------------------------------------- Wave B (audit fixes)


def test_eth_finalization_window_floor_enforced():
    # Below the ~2-epoch (768s) floor -> rejected at MarginPolicy construction.
    with pytest.raises(ValidationError, match="safety floor"):
        MarginPolicy(
            margin=t.Timelock(36, t.TimeUnit.BLOCKS),
            block_interval_s=600.0,
            is_measured=False,
            eth_finalization_window_s=300,
        )
    ok = MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        eth_finalization_window_s=768,
    )
    assert ok.eth_finalization_window_s == 768


def test_eth_coordinator_requires_finalization_window_at_setup():
    p, h = generate_secret()
    terms = _eth_terms(hashlock=h)
    bad_policy = MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
    )  # no eth_finalization_window_s
    with pytest.raises(ValidationError, match="eth_finalization_window_s"):
        SwapCoordinator(
            record=SwapRecord(
                state=SwapState.SECRET_REVEALED,
                terms=terms,
                counterchain_locator=_eth_locator(terms.hashlock),
            ),
            counter_leg=FakeEthLeg(preimage=p, verdict=_final()),
            radiant_leg=FakeRadiantLeg(),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(margin_policy=bad_policy, maker_stall_safety_window_blocks=6),
        )


def test_reserve_to_blocks_rounds_up_for_seconds():
    from pyrxd.gravity.swap_coordinator import _reserve_to_blocks

    assert _reserve_to_blocks(t.Timelock(6, t.TimeUnit.BLOCKS), 600.0) == 6  # identity for BLOCKS
    # ceil(1300/600)=3, NOT floor 2 — a reserve must round UP (the safe direction).
    assert _reserve_to_blocks(t.Timelock(1300, t.TimeUnit.SECONDS), 600.0) == 3


# --------------------------------------------------------------------------- Wave C: HIGH-1 ordering

from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin

_NOW = 1_700_000_000


def _xmargin():
    # total = 768 + 1800 + 600 + 300 = 3468s
    return CrossClockMargin(
        eth_reorg_finality_s=768, rxd_claim_burial_s=1800, rxd_confirm_slack_s=600, rounding_slack_s=300
    )


def _eth_fund_policy(**kw):
    return MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
        cross_clock_margin=kw.get("cross_clock_margin", _xmargin()),
        max_covenant_confirm_wait_s=kw.get("max_covenant_confirm_wait_s", 3600),
    )


def _eth_coord_negotiated(*, terms, policy=None):
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    p_dummy = b"\x01" * 32
    return SwapCoordinator(
        record=rec,
        counter_leg=FakeEthLeg(preimage=p_dummy, verdict=_final()),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=policy or _eth_fund_policy(), maker_stall_safety_window_blocks=6),
    )


# projected_rxd_open = now + max_confirm_wait(3600) + t_rxd(72)*rxd_interval(300)=21600 = now+25200
# deadline = eth_timeout - margin.total(3468). Need now+25200 < eth_timeout-3468 -> eth_timeout > now+28668.


def test_eth_timelock_ordering_accepts_safe_deadline():
    _, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    coord = _eth_coord_negotiated(terms=terms)
    coord._assert_eth_timelock_ordering(terms, now_unix_s=_NOW)  # no raise (40000 > 28668)


def test_eth_timelock_ordering_rejects_deadline_too_close():
    # HIGH-1 core: an eth_timeout that does NOT clear the RXD window + margin is refused —
    # a maker cannot set a deadline that lets it refund both legs.
    _, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 10000)  # 10000 < 28668
    coord = _eth_coord_negotiated(terms=terms)
    with pytest.raises(ValidationError, match="confirm too late"):
        coord._assert_eth_timelock_ordering(terms, now_unix_s=_NOW)


def test_eth_timelock_ordering_rejects_expired_deadline():
    # The now-vs-timeout grief (completeness finding): an already-expired ETH HTLC is refused.
    _, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW - 100)
    coord = _eth_coord_negotiated(terms=terms)
    with pytest.raises(ValidationError, match="confirm too late"):
        coord._assert_eth_timelock_ordering(terms, now_unix_s=_NOW)


def test_eth_timelock_ordering_requires_now_and_margin():
    _, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    coord = _eth_coord_negotiated(terms=terms)
    with pytest.raises(ValidationError, match="now_unix_s"):
        coord._assert_eth_timelock_ordering(terms, now_unix_s=None)
    bare = MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
    )  # no cross_clock_margin / max_covenant_confirm_wait_s
    coord2 = _eth_coord_negotiated(terms=terms, policy=bare)
    with pytest.raises(ValidationError, match="cross_clock_margin"):
        coord2._assert_eth_timelock_ordering(terms, now_unix_s=_NOW)


async def test_pre_lock_dispatches_eth_ordering_gate():
    # Integration: pre_btc_lock_check step 3 routes an ETH swap to the cross-clock gate.
    _, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 10000)  # too close
    coord = _eth_coord_negotiated(terms=terms)
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert not gate.ok and "margin check failed" in gate.reason
    # A safe deadline PASSES the ordering step (step 3). The minimal FakeEthLeg has no
    # fund-path SPK methods, so the gate may still stop at step 4 — but never at the margin
    # check, which is what this asserts (step-3 isolation).
    terms_ok = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    coord_ok = _eth_coord_negotiated(terms=terms_ok)
    gate_ok = await coord_ok.pre_btc_lock_check(terms_ok, now_unix_s=_NOW)
    assert "margin check failed" not in (gate_ok.reason or "")


# --------------------------------------------------------------------------- ETH full lifecycle


def _eth_coord_full(*, terms, eth_leg, radiant_leg=None, seen_store=None, policy=None):
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    return SwapCoordinator(
        record=rec,
        counter_leg=eth_leg,
        radiant_leg=radiant_leg or FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=seen_store or FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=policy or _eth_fund_policy(), maker_stall_safety_window_blocks=6),
    )


async def test_eth_full_lifecycle_negotiated_to_completed():
    # Drives a whole ETH↔RXD swap through the REAL coordinator (closes the structural coverage
    # hole: the Wave-C fund path — now_unix_s, ordering gate, wei amount bind — never ran e2e).
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    leg = FakeEthLeg(preimage=secret, verdict=_final())
    rxd = FakeRadiantLeg()
    coord = _eth_coord_full(terms=terms, eth_leg=leg, radiant_leg=rxd)

    rec = await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert rec.state is SwapState.BTC_LOCKED and "fund" in leg.calls
    assert isinstance(rec.counterchain_locator, EthHtlcLocator)  # wei locator recorded
    # ETH revalidation now requires now_unix_s (the post-confirm cross-clock recheck); an
    # on-time lock at _NOW passes.
    rec = await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert rec.state is SwapState.BOTH_LOCKED
    p_bytes = secret.unsafe_raw_bytes()  # capture BEFORE maker_claims_btc zeroizes the secret
    rec = await coord.maker_claims_btc(secret)
    # the maker reveals p (not h) to the ETH contract via the counter leg
    assert rec.state is SwapState.SECRET_REVEALED and leg.claimed_with == p_bytes and "claim" in leg.calls
    rec = await coord.taker_scrape_and_claim_asset("0xethclaim", now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with == p_bytes  # RXD asset claimed with the scraped p


async def test_eth_fund_rejects_wrong_wei_amount():
    # The funded-amount bind runs in the ETH wei unit (mirrors the BTC sats bind).
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    leg = FakeEthLeg(preimage=secret, verdict=_final(), fund_amount_delta=10**9)  # overfund
    coord = _eth_coord_full(terms=terms, eth_leg=leg)
    with pytest.raises(ValidationError, match="funded counter-leg amount"):
        await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert coord.record.state is SwapState.NEGOTIATED  # never advanced


async def test_eth_deploy_then_verify_inversion_strands_recoverably():
    # Audit completeness finding (deploy-then-verify atomicity inversion): an ETH verify failure
    # raises AFTER the contract is on-chain. Documents the actual behavior: H burned, record
    # stays NEGOTIATED, and the deployed locator is retained on the leg (recoverable for refund),
    # NOT silently lost.
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    leg = FakeEthLeg(preimage=secret, verdict=_final(), verify_raises=True)
    seen = FakeSeenStore()
    coord = _eth_coord_full(terms=terms, eth_leg=leg, seen_store=seen)
    with pytest.raises(ValidationError, match="verify_funded failed"):
        await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert coord.record.state is SwapState.NEGOTIATED  # no advance
    assert seen.has_seen(h)  # H consumed (on-chain value committed at the pre-broadcast reserve)
    assert leg.last_locator is not None  # the deployed contract address is retained → refundable


# ----------------------------------------------------- re-verify HIGH: maker-delay second run


async def _eth_to_btc_locked(*, leg, terms, rxd, now_unix_s):
    coord = _eth_coord_full(terms=terms, eth_leg=leg, radiant_leg=rxd)
    await coord.taker_funds_btc(terms, now_unix_s=now_unix_s)
    assert coord.record.state is SwapState.BTC_LOCKED
    return coord


async def test_eth_post_confirm_recheck_accepts_on_time_lock():
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    # Maker locks promptly (now ~ _NOW): projected rxd_open _NOW+21600 < deadline _NOW+36532 -> OK.
    rec = await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert rec.state is SwapState.BOTH_LOCKED


async def test_eth_post_confirm_recheck_refuses_stalled_maker_lock():
    # THE re-verify HIGH: a maker who STALLS the covenant broadcast (locks late) collapses the
    # cross-clock margin the pre-fund gate projected. The second run catches it and refuses to
    # enter BOTH_LOCKED — the taker must refund the counter leg, not proceed.
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    # Maker delays the lock to _NOW+30000: actual rxd_open _NOW+30000+21600 > deadline _NOW+36532.
    with pytest.raises(ValidationError, match="confirm too late"):
        await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW + 30000)
    assert coord.record.state is SwapState.BTC_LOCKED  # did NOT advance to BOTH_LOCKED
    assert rxd.claimed_with is None


async def test_eth_post_confirm_recheck_requires_now_unix_s():
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    coord = await _eth_to_btc_locked(
        leg=FakeEthLeg(preimage=secret, verdict=_final()), terms=terms, rxd=rxd, now_unix_s=_NOW
    )
    with pytest.raises(ValidationError, match="now_unix_s"):
        await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))  # ETH: now required
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_eth_post_confirm_refuses_unverified_counter_funding():
    """Re-verify HIGH #1 (red-team): the maker-side counter-funding gate is FSM-ENFORCED, not
    optional. An ETH leg with NO verified EthHtlcLocator on the record (maker never ran
    maker_verify_counter_funding) must FAIL CLOSED at post_asset_lock_revalidate — advancing to the
    reveal-enabling BOTH_LOCKED without the verification is impossible. Models the two-party maker
    path (the maker's coordinator never runs taker_funds_btc, so the locator is only set by the
    verify gate)."""
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    leg = FakeEthLeg(preimage=secret, verdict=_final())
    # BTC_LOCKED with terms but NO counterchain_locator (verify never ran).
    coord = _eth_coord_at_btc_locked(eth_leg=leg, terms=terms)
    with pytest.raises(ValidationError, match="never verified"):
        await coord.post_asset_lock_revalidate(
            await coord.radiant_leg.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW
        )
    assert coord.record.state is SwapState.BTC_LOCKED  # did NOT advance to BOTH_LOCKED


async def test_eth_post_confirm_reverifies_counter_funding_at_lock_time():
    """Re-verify HIGH #1+#2 (red-team): on the success path post_asset_lock_revalidate RE-RUNS the
    counter-funding verification (a fresh re-bind that closes the verify->lock TOCTOU), and for a
    test/estimated (is_measured=False) config it pins to 'latest' (None)."""
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    leg = FakeEthLeg(preimage=secret, verdict=_final())
    coord = await _eth_to_btc_locked(leg=leg, terms=terms, rxd=rxd, now_unix_s=_NOW)
    leg.calls.clear()
    rec = await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert rec.state is SwapState.BOTH_LOCKED
    assert leg.calls.count("verify_counterparty") == 1  # re-verified at lock time
    assert leg.last_verify_block_identifier is None  # is_measured=False -> 'latest'


async def test_eth_post_confirm_reverify_failure_refuses_both_locked():
    """Re-verify HIGH #2 (red-team): if the lock-time re-verification fails (e.g. a reorg replaced the
    taker's deploy), post_asset_lock_revalidate refuses BOTH_LOCKED — the maker never reveals p."""
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    leg = FakeEthLeg(preimage=secret, verdict=_final())
    coord = await _eth_to_btc_locked(leg=leg, terms=terms, rxd=rxd, now_unix_s=_NOW)
    leg.counterparty_verify_raises = True  # the re-verify now fails (deploy replaced / mismatch)
    with pytest.raises(ValidationError, match="claimant"):
        await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert coord.record.state is SwapState.BTC_LOCKED  # did NOT advance
    assert rxd.claimed_with is None


# ---------------------------------------------------------------------------
# MEDIUM-1 (whole-stack audit): value-bearing ETH leg must not silently run on
# an estimated policy (which disables the verify->lock 'finalized' reorg pin +
# the proactive-refund N-floor). Refuse at construction unless explicitly accepted.
# ---------------------------------------------------------------------------


def _value_bearing_radiant() -> FakeRadiantLeg:
    rl = FakeRadiantLeg()
    rl.network = "mainnet"  # not in AUDIT_CLEARED_NETWORKS => value-bearing
    return rl


def _construct_eth_coord(*, policy, accept_estimated=False, radiant_leg=None, window=8):
    h = hashlib.sha256(os.urandom(32)).digest()
    return SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=_eth_terms(hashlock=h)),
        counter_leg=FakeEthLeg(preimage=SecretBytes(os.urandom(32)), verdict=_final()),
        radiant_leg=radiant_leg if radiant_leg is not None else _value_bearing_radiant(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=policy,
            accept_nondurable_seen=True,
            accept_estimated_eth_margins=accept_estimated,
            maker_stall_safety_window_blocks=window,
        ),
    )


def test_value_bearing_eth_estimated_policy_refused():
    # is_measured=False on a value-bearing ETH swap, no explicit opt-in -> refused.
    with pytest.raises(ValidationError, match="value-bearing ETH"):
        _construct_eth_coord(policy=_eth_finality_policy(is_measured=False))


def test_value_bearing_eth_estimated_allowed_with_explicit_optin():
    # Conscious dust-run acceptance (accept_estimated_eth_margins=True) -> constructs.
    coord = _construct_eth_coord(policy=_eth_finality_policy(is_measured=False), accept_estimated=True)
    assert coord is not None


def test_value_bearing_eth_allowed_when_measured():
    # A measured policy is the proper fix path; window>=N-floor (8) -> constructs.
    coord = _construct_eth_coord(policy=_eth_finality_policy(is_measured=True), window=8)
    assert coord is not None


def test_non_value_bearing_eth_estimated_unaffected():
    # No mainnet leg tag -> not value-bearing -> the MEDIUM-1 guard does not fire.
    coord = _construct_eth_coord(policy=_eth_finality_policy(is_measured=False), radiant_leg=FakeRadiantLeg())
    assert coord is not None


def test_value_bearing_btc_estimated_unaffected():
    # The guard is ETH-specific; a value-bearing BTC swap on an estimated policy still constructs.
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()),
        btc_leg=FakeBtcLeg(),
        radiant_leg=_value_bearing_radiant(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated(), accept_nondurable_seen=True),
    )
    assert coord is not None

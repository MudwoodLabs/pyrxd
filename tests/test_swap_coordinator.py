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

import hashlib
import json
import os
import pickle

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import (
    ESTIMATED_DEFAULT_MARGIN_BLOCKS,
    MAKER_SECRET_TAKER_LOCKS_BTC_FIRST,
    CoordinatorConfig,
    MarginPolicy,
    SwapCoordinator,
    assert_timelock_margin,
    generate_secret,
    should_taker_refund_proactively,
)
from pyrxd.gravity.swap_state import (
    NegotiatedTerms,
    SwapRecord,
    SwapState,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import SecretBytes

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

    def __init__(self, *, tamper_promised_spk: bool = False, fund_amount_delta: int = 0) -> None:
        self.tamper_promised_spk = tamper_promised_spk
        # Simulate a buggy/malicious leg (or a mutated `terms`) that funds the HTLC
        # with a value != the negotiated btc_sats. Positive = overfund, negative = under.
        self.fund_amount_delta = fund_amount_delta
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

    def derive_funding_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        return self._htlc(terms).scriptpubkey

    def promised_funding_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
        spk = self._htlc(terms).scriptpubkey
        if self.tamper_promised_spk:
            return spk[:-1] + bytes([spk[-1] ^ 0x01])
        return spk

    def fund(self, terms: NegotiatedTerms) -> t.BtcHtlcLocator:
        self.calls.append("fund")
        amount = terms.btc_sats + self.fund_amount_delta
        loc = self._htlc(terms).with_funding(t.BtcOutpoint("ab" * 32, 0), amount)
        self.last_locator = loc
        return loc

    def claim(self, locator: t.BtcHtlcLocator, preimage: bytes) -> None:
        # Real claim tx so scrape_secret has something to scrape.
        self.calls.append("claim")
        self.claimed_with = bytes(preimage)

    def refund(self, locator: t.BtcHtlcLocator, timeout: t.Timelock) -> None:
        self.calls.append("refund")
        self.refunded = True

    def scrape_secret(self, claim_tx_bytes: bytes, hashlock: bytes) -> bytes:
        return t.scrape_secret(claim_tx_bytes, hashlock)


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

    def expected_covenant_scriptpubkey(self, terms: NegotiatedTerms) -> bytes:
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

    def covenant_outpoint(self, terms: NegotiatedTerms) -> str:
        return "ef" * 32 + ":0"

    def claim_asset(self, record: SwapRecord, preimage: bytes) -> None:
        self.calls.append("claim_asset")
        self.claimed_with = bytes(preimage)

    def refund_asset(self, record: SwapRecord) -> None:
        self.calls.append("refund_asset")
        self.refunded = True


class FakeIndexer:
    def __init__(self, *, authentic: bool = True, raise_unavailable: bool = False) -> None:
        self.authentic = authentic
        self.raise_unavailable = raise_unavailable

    def verify_ref(self, genesis_ref: bytes) -> bool:
        if self.raise_unavailable:
            raise RuntimeError("indexer unreachable")
        return self.authentic


class FakeSeenStore:
    def __init__(self) -> None:
        self._seen: set[bytes] = set()

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


def test_taker_funds_btc_rejects_amount_mismatch():
    """Regression (2026-05-24 panel): taker_funds_btc must bind the funded amount
    to the negotiated btc_sats. A P2TR scriptPubKey commits to the taptree, not the
    output value, so the pre-lock SPK check cannot catch a wrong amount — this Python
    assert is the only layer that can. Overfunding is a one-sided taker loss (the
    maker claims the whole output via the preimage); we reject both directions.
    """
    terms = _terms()

    # Overfund: leg locks more than negotiated -> reject, do not advance, do not mark seen.
    over_leg = FakeBtcLeg(fund_amount_delta=50_000)
    seen = FakeSeenStore()
    coord = _coordinator(terms=terms, btc_leg=over_leg, seen_store=seen)
    with pytest.raises(ValidationError, match="funded BTC amount"):
        coord.taker_funds_btc(terms)
    assert coord.record.state is SwapState.NEGOTIATED  # never advanced
    assert not seen.has_seen(terms.hashlock)  # H not consumed on a refused fund

    # Underfund: also rejected (self-correcting in practice, but fail-closed here).
    under_leg = FakeBtcLeg(fund_amount_delta=-1)
    coord2 = _coordinator(terms=terms, btc_leg=under_leg)
    with pytest.raises(ValidationError, match="funded BTC amount"):
        coord2.taker_funds_btc(terms)

    # Exact match still funds and advances.
    ok_coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg())
    rec = ok_coord.taker_funds_btc(terms)
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


def test_reused_hashlock_rejected():
    store = FakeSeenStore()
    h = hashlib.sha256(os.urandom(32)).digest()
    store.mark_seen(h)  # already used in a prior swap
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms, seen_store=store)
    gate = coord.pre_btc_lock_check(terms)
    assert not gate.ok and "reused" in gate.reason


def test_seen_store_marks_only_after_successful_fund():
    store = FakeSeenStore()
    terms = _terms()
    coord = _coordinator(terms=terms, seen_store=store)
    assert not store.has_seen(terms.hashlock)
    coord.taker_funds_btc(terms)
    assert store.has_seen(terms.hashlock)


# ---------------------------------------------------------------------------
# Pre-BTC-lock gate: indexer fail-closed
# ---------------------------------------------------------------------------


def test_pre_lock_indexer_unavailable_fail_closed():
    terms = _terms(variant="ft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(raise_unavailable=True))
    gate = coord.pre_btc_lock_check(terms)
    assert not gate.ok and "fail-closed" in gate.reason


def test_pre_lock_indexer_says_inauthentic():
    terms = _terms(variant="nft")
    coord = _coordinator(terms=terms, indexer=FakeIndexer(authentic=False))
    gate = coord.pre_btc_lock_check(terms)
    assert not gate.ok and "authenticity" in gate.reason


def test_pre_lock_maker_promised_params_mismatch():
    terms = _terms()
    coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg(tamper_promised_spk=True))
    gate = coord.pre_btc_lock_check(terms)
    assert not gate.ok and "promised" in gate.reason


def test_taker_refuses_to_fund_on_failed_gate():
    terms = _terms()
    coord = _coordinator(terms=terms, indexer=FakeIndexer(authentic=False))
    with pytest.raises(ValidationError):
        coord.taker_funds_btc(terms)


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


def test_e2e_happy_path_completed():
    # Maker generates p; only H goes into the terms.
    p_secret, h = generate_secret()
    terms = _terms(hashlock=h)

    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)

    # 1. Taker locks BTC first (gate passes, locator persisted).
    rec = coord.taker_funds_btc(terms)
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.btc_locator is not None

    # 2. Maker locks the asset; on-chain SPK matches expected => BOTH_LOCKED.
    expected_spk = rxd.expected_covenant_scriptpubkey(terms)
    rec = coord.post_asset_lock_revalidate(expected_spk)
    assert rec.state is SwapState.BOTH_LOCKED

    # 3. Maker claims BTC, revealing p; p is zeroized after.
    rec = coord.maker_claims_btc(p_secret)
    assert rec.state is SwapState.SECRET_REVEALED
    assert btc.claimed_with is not None and hashlib.sha256(btc.claimed_with).digest() == h
    with pytest.raises(Exception):
        p_secret.unsafe_raw_bytes()  # zeroized

    # 4. Taker scrapes p from the maker's real claim tx and claims the asset.
    claim_tx = _real_maker_claim_tx(rec.btc_locator, btc.claimed_with)
    rec = coord.taker_scrape_and_claim_asset(claim_tx)
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


def test_e2e_mutual_refund_both_whole():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)

    coord.taker_funds_btc(terms)
    coord.post_asset_lock_revalidate(rxd.expected_covenant_scriptpubkey(terms))
    assert coord.record.state is SwapState.BOTH_LOCKED

    # Maker never claims; both timeouts elapse; both refund.
    rec = coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND
    # Both parties recovered their own assets — no one-sided loss.
    assert btc.refunded and rxd.refunded


# ---------------------------------------------------------------------------
# SIMULATED: PARAMS_MISMATCH (maker locks wrong covenant) -> taker refunds BTC
# ---------------------------------------------------------------------------


def test_e2e_params_mismatch_taker_refunds_btc():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd)

    coord.taker_funds_btc(terms)

    # Maker locks the asset, but the on-chain covenant SPK is WRONG (tampered).
    wrong_spk = b"\xde\xad" + b"\x00" * 32
    rec = coord.post_asset_lock_revalidate(wrong_spk)
    assert rec.state is SwapState.PARAMS_MISMATCH

    # Taker refunds the BTC via the timelock leg -> ABORTED.
    rec = coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED
    assert btc.refunded
    # Taker is whole (got BTC back); maker never received BTC.
    assert "claim" not in btc.calls


# ---------------------------------------------------------------------------
# SIMULATED: MAKER_STALLS -> taker refunds asset proactively
# ---------------------------------------------------------------------------


def test_e2e_maker_stalls_taker_refunds_asset():
    _p, h = generate_secret()
    terms = _terms(hashlock=h, t_rxd_blocks=72)
    btc = FakeBtcLeg()
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=rxd, window=6)

    coord.taker_funds_btc(terms)
    coord.post_asset_lock_revalidate(rxd.expected_covenant_scriptpubkey(terms))
    assert coord.record.state is SwapState.BOTH_LOCKED

    # Maker stalls: hasn't claimed and we are within N of t_RXD maturity.
    # locked at 1000; maturity = 1072; act at >= 1066.
    rec = coord.maybe_refund_asset_on_maker_stall(
        now_block_height=1066, asset_locked_at_height=1000, maker_has_claimed_btc=False
    )
    assert rec.state is SwapState.ASSET_REFUNDED_TAKER_ACTS
    assert rxd.refunded  # taker recovered the asset rather than wait
    # Taker is whole on the asset side; never lost both.


def test_maker_stall_noop_before_window():
    _p, h = generate_secret()
    terms = _terms(hashlock=h, t_rxd_blocks=72)
    coord = _coordinator(terms=terms)
    coord.taker_funds_btc(terms)
    coord.post_asset_lock_revalidate(coord.radiant_leg.expected_covenant_scriptpubkey(terms))
    # Far from maturity -> no-op, stays BOTH_LOCKED.
    rec = coord.maybe_refund_asset_on_maker_stall(
        now_block_height=1000, asset_locked_at_height=1000, maker_has_claimed_btc=False
    )
    assert rec.state is SwapState.BOTH_LOCKED


# ---------------------------------------------------------------------------
# Crash recovery: the persisted record carries the full locator
# ---------------------------------------------------------------------------


def test_crash_recovery_refund_from_persisted_record():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms)
    coord.taker_funds_btc(terms)

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
    rec = coord2.taker_refund_btc()
    assert rec.state is SwapState.ABORTED
    assert btc2.refunded


def test_maker_claims_rejects_wrong_preimage():
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    coord = _coordinator(terms=terms)
    coord.taker_funds_btc(terms)
    coord.post_asset_lock_revalidate(coord.radiant_leg.expected_covenant_scriptpubkey(terms))
    # A different secret that does not hash to H must be refused before broadcast.
    wrong = SecretBytes(os.urandom(32))
    with pytest.raises(ValidationError):
        coord.maker_claims_btc(wrong)

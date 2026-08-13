"""Mutation-hardening for the HTLC atomic-swap fund-safety gates.

Every test here was written because a **planted defect survived the whole swap suite**: the
guard it names could be deleted from ``src/pyrxd/gravity/`` and 1,606 tests stayed green. The
survey that produced them is a hand-mutation sweep over the swap surface (the counterpart of
``tests/test_mutation_hardening.py`` for the consensus primitives), so each test states the
exact mutant it kills — delete the named line in ``src/`` and this file must go red.

The recurring shape, and why it matters here: several coordinator steps **broadcast before they
advance the FSM**. On those paths the state machine is not a backstop — ``advance()`` raises
only *after* the on-chain effect. The method's own ``state is ...`` precondition is therefore
the ONLY thing standing between a wrong-state call and an irreversible broadcast, and until now
nothing pinned it. ``maker_claims_btc`` is the worst case: its broadcast publishes ``p``.

Nothing here weakens an assertion, and every group carries an honest-path control so a guard
that refuses VALID work would fail too.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator, generate_secret
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapRole, SwapState
from pyrxd.security.errors import NetworkError, ValidationError
from tests.test_swap_coordinator import (
    FakeBtcLeg,
    FakeEthLeg,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _eth_terms,
    _final,
    _real_maker_claim_tx,
    _terms,
    _xmargin,
    _xonly,
)

# ``asyncio_mode = "auto"`` (pyproject) collects the async tests here; no module-level
# ``pytest.mark.asyncio`` — it would warn on the sync terms-construction tests at the bottom.

_NOW = 1_759_000_000


def _coord(
    *,
    terms,
    btc_leg=None,
    radiant_leg=None,
    seen_store=None,
    state=SwapState.NEGOTIATED,
    locator=None,
    persist=None,
    role=None,
    policy=None,
    window=6,
):
    """A BTC-swap coordinator pinned at an arbitrary state (the crash-resume shape)."""
    return SwapCoordinator(
        record=SwapRecord(state=state, terms=terms, counterchain_locator=locator),
        btc_leg=btc_leg or FakeBtcLeg(),
        radiant_leg=radiant_leg or FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=seen_store or FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=policy or MarginPolicy.estimated(),
            maker_stall_safety_window_blocks=window,
            role=role,
        ),
        persist=persist,
    )


async def _to_both_locked(*, terms, btc_leg, radiant_leg, role=None):
    coord = _coord(terms=terms, btc_leg=btc_leg, radiant_leg=radiant_leg, role=role)
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await radiant_leg.expected_covenant_scriptpubkey(terms))
    assert coord.record.state is SwapState.BOTH_LOCKED
    return coord


# ---------------------------------------------------------------------------
# The reveal precondition: p must not become public before BOTH_LOCKED
# ---------------------------------------------------------------------------


async def test_maker_cannot_reveal_p_before_both_locked():
    """MUTANT: delete ``if self.record.state is not SwapState.BOTH_LOCKED`` in ``maker_claims_btc``.

    This is the single highest-consequence guard in the coordinator and it was unpinned. The FSM
    is NOT a backstop here: ``counter_leg.claim(...)`` is awaited FIRST and ``_advance`` only
    afterwards, so with the precondition gone the claim — which publishes ``p`` in the Bitcoin
    witness — is broadcast, and the ``ValidationError`` that follows arrives with the secret
    already on chain and irrevocable.

    The state guard is what forces the maker through ``post_asset_lock_revalidate``, i.e. through
    ``_assert_btc_counter_funding_verified`` + ``_assert_credential_binding_verified``. Revealing
    at BTC_LOCKED means the maker sweeps the taker's HTLC while its OWN asset is not locked: a
    one-sided taker loss of the full ``btc_sats``.

    So the assertion that matters is not "it raised" — it is that NOTHING was broadcast.
    """
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc = FakeBtcLeg()
    coord = _coord(terms=terms, btc_leg=btc)
    await coord.taker_funds_btc(terms)
    assert coord.record.state is SwapState.BTC_LOCKED  # the maker has NOT locked the asset yet

    with pytest.raises(ValidationError, match="only valid from BOTH_LOCKED"):
        await coord.maker_claims_btc(secret)

    assert "claim" not in btc.calls, "p must not be broadcast from a pre-BOTH_LOCKED state"
    assert btc.claimed_with is None
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_maker_claims_btc_still_works_from_both_locked():
    """Honest-path control for the guard above: a guard that refuses VALID work is its own bug."""
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd)
    p_bytes = secret.unsafe_raw_bytes()

    rec = await coord.maker_claims_btc(secret)

    assert rec.state is SwapState.SECRET_REVEALED
    assert btc.claimed_with == p_bytes


# ---------------------------------------------------------------------------
# The maker-stall asset refund: broadcast-before-advance, same shape
# ---------------------------------------------------------------------------


async def test_maker_stall_refund_cannot_fire_from_a_post_reveal_state():
    """MUTANT: delete the ``state is not SwapState.BOTH_LOCKED`` check in
    ``maybe_refund_asset_on_maker_stall``.

    ``radiant_leg.refund_asset`` is awaited BEFORE the two ``_advance`` calls (deliberately — the
    red-team LOW fix that stops a failed broadcast wedging the FSM at MAKER_STALLS), so the FSM
    cannot catch a wrong-state call in time. From SECRET_REVEALED ``p`` is already public and the
    taker is mid-claim; a stall refund fired there races the taker's asset claim with the maker's
    CSV refund — the ONE_SIDED_LOSS_TAKER edge, with the maker having already taken the BTC.

    ``maker_has_claimed_btc`` is a CALLER-supplied flag, so a buggy or hostile driver reaching this
    method from the wrong state is exactly the case the precondition exists for.
    """
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.maker_claims_btc(secret)
    assert coord.record.state is SwapState.SECRET_REVEALED

    with pytest.raises(ValidationError, match="only valid from BOTH_LOCKED"):
        await coord.maybe_refund_asset_on_maker_stall(
            now_block_height=10_000,  # far past maturity: the trigger + the P3 maturity check both pass
            asset_locked_at_height=1_000,
            maker_has_claimed_btc=False,
        )

    assert rxd.refunded is False, "no covenant CSV refund may be broadcast from a post-reveal state"
    assert "refund_asset" not in rxd.calls


# ---------------------------------------------------------------------------
# taker_funds_btc: the double-fund guard
# ---------------------------------------------------------------------------


async def test_taker_cannot_refund_the_counter_leg_twice_after_a_restart():
    """MUTANT: delete the ``state is not SwapState.NEGOTIATED`` check in ``taker_funds_btc``.

    The H reserve looks like a backstop, but it is only as durable as the seen-store — and the
    WIRED store is explicitly non-durable (``SeenStore.durable = False``; SEEN-1). Model the exact
    situation the code documents: a process restart resumes a persisted record that is already
    BOTH_LOCKED, with a FRESH in-memory seen store. With the state precondition gone, the gate
    passes, ``reserve(H)`` succeeds against the empty store, and ``counter_leg.fund`` locks a
    SECOND HTLC for the same swap — value the taker can only recover at ``t_btc``, if at all.
    """
    _secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    first = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd)

    resumed = _coord(
        terms=terms,
        btc_leg=btc,
        radiant_leg=rxd,
        seen_store=FakeSeenStore(),  # the restart: H-freshness did not survive
        state=SwapState.BOTH_LOCKED,
        locator=first.record.counterchain_locator,
    )
    btc.calls.clear()

    with pytest.raises(ValidationError, match="only valid from NEGOTIATED"):
        await resumed.taker_funds_btc(terms)

    assert "fund" not in btc.calls, "a resumed record must never re-fund the counter leg"


# ---------------------------------------------------------------------------
# The verify->lock TOCTOU on the taker's asset gate (HZ-1)
# ---------------------------------------------------------------------------


class _CovenantVanishesDuringPersist:
    """A persist hook that models the maker double-spending its covenant funding away.

    The intent persist is a real ``await`` between ``pre_btc_lock_check`` and the BTC broadcast —
    a durable write can take arbitrarily long, and that is precisely the window the re-verify
    exists to close.
    """

    def __init__(self, radiant_leg) -> None:
        self.radiant_leg = radiant_leg
        self.calls = 0

    async def __call__(self, record) -> None:
        self.calls += 1
        if self.calls == 1:
            self.radiant_leg.asset_funded = False


async def test_asset_funding_is_reverified_after_the_gate_not_only_inside_it():
    """MUTANT: delete the second ``await self.taker_verify_asset_funding(terms)`` in
    ``taker_funds_btc`` (the one AFTER the intent persist).

    ``test_the_verify_to_lock_toctou_is_closed`` looks like it covers this, but it does not:
    ``taker_funds_btc`` calls ``pre_btc_lock_check`` itself, so that test's refusal comes from the
    gate, not from the re-run — deleting the re-run leaves it green. The re-run's own window is
    everything AFTER the gate returns, which on this path is the awaited durable write. Vanish the
    covenant there and only the re-run can see it.
    """
    _secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    hook = _CovenantVanishesDuringPersist(rxd)
    coord = _coord(terms=terms, btc_leg=btc, radiant_leg=rxd, persist=hook)

    assert (await coord.pre_btc_lock_check(terms)).ok is True  # verified while it was still funded

    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)

    assert hook.calls == 1, "the intent persist must have run (this is the window under test)"
    assert "fund" not in btc.calls, "no BTC may be locked against a covenant that vanished mid-step"
    assert coord.record.state is SwapState.NEGOTIATED


# ---------------------------------------------------------------------------
# Nothing counterparty-supplied may survive into the maker's claim
# ---------------------------------------------------------------------------


async def test_lock_time_reverify_replaces_the_recorded_counter_locator():
    """MUTANT: delete ``self.record = self.record.with_counter_lock(reverified)`` in
    ``_assert_btc_counter_funding_verified``.

    The docstring's promise — *"the record's locator is then REPLACED with the leg's own
    re-derivation, so nothing counterparty-supplied survives into maker_claims_btc"* — had no
    test. A record carrying a counterparty-influenced locator (here: an inflated
    ``amount_sats``) would otherwise be what ``maker_claims_btc`` builds its spend from.
    """
    _secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()

    lying = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
    ).with_funding(t.BtcOutpoint("ab" * 32, 0), terms.value_amount + 50_000)

    coord = _coord(terms=terms, btc_leg=btc, radiant_leg=rxd, state=SwapState.BTC_LOCKED, locator=lying)
    rec = await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))

    assert rec.state is SwapState.BOTH_LOCKED
    assert rec.counterchain_locator.amount_sats == terms.value_amount, (
        "the record must carry the leg's own on-chain re-derivation, not the counterparty's claim"
    )


async def test_post_asset_lock_revalidate_leaves_the_record_untouched_from_a_wrong_state():
    """MUTANT: delete the ``state is not SwapState.BTC_LOCKED`` check in
    ``post_asset_lock_revalidate``.

    The method writes the caller-supplied ``observed_covenant_spk`` into the record
    (``with_radiant_lock``) BEFORE any FSM transition is attempted, so a wrong-state call
    overwrites the durable covenant fields even though ``advance`` later refuses. The refusal must
    happen first, leaving the record byte-identical.
    """
    _secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd)
    before = coord.record

    with pytest.raises(ValidationError, match="only valid from BTC_LOCKED"):
        await coord.post_asset_lock_revalidate(b"\x6a" + b"\xff" * 31)

    assert coord.record is before
    assert coord.record.radiant_covenant_spk_hex == before.radiant_covenant_spk_hex


# ---------------------------------------------------------------------------
# Refund paths: no broadcast from a state that does not own them
# ---------------------------------------------------------------------------


async def test_mutual_refund_broadcasts_nothing_from_a_post_reveal_state():
    """MUTANT: delete the ``state is not SwapState.BOTH_LOCKED`` check in ``mutual_refund``.

    Both refunds are awaited before ``_advance``, so the FSM again catches a wrong-state call only
    after the broadcasts. From SECRET_REVEALED the maker has already taken the BTC with ``p``; the
    correct move is to CLAIM the asset, and firing the refund pair there both wastes fees and races
    the taker's own claim.
    """
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd)
    await coord.maker_claims_btc(secret)

    with pytest.raises(ValidationError, match="only valid from BOTH_LOCKED"):
        await coord.mutual_refund()

    assert btc.refunded is False and rxd.refunded is False


async def test_taker_refund_btc_broadcasts_nothing_from_both_locked():
    """MUTANT: delete the ``state not in (BTC_LOCKED, PARAMS_MISMATCH)`` check in
    ``taker_refund_btc``.

    ``counter_leg.refund`` is awaited before ``_advance``. From BOTH_LOCKED the asset IS locked and
    the swap is still live; the taker's recovery there is ``mutual_refund`` (both legs unwind), not
    a unilateral counter-leg refund that leaves the covenant to the maker's CSV.
    """
    _secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd)

    with pytest.raises(ValidationError, match="not valid from"):
        await coord.taker_refund_btc()

    assert btc.refunded is False and "refund" not in btc.calls


# ---------------------------------------------------------------------------
# Reveal observation: same-H cross-swap provenance + the sha256 re-check
# ---------------------------------------------------------------------------


def _foreign_same_h_claim_tx(terms: NegotiatedTerms, preimage: bytes) -> bytes:
    """A REAL claim tx revealing the SAME ``p`` — from a DIFFERENT funding outpoint.

    The seen-store rejects a reused H at ADMISSION; the provenance gate is the witness-side half
    of that defence, for a reveal that arrives through any path the store does not cover. Because
    ``p`` here genuinely opens ``H``, the scrape and the ``sha256(p) == H`` re-check both PASS —
    only the outpoint bind can tell this tx apart from ours.
    """
    foreign = t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
    ).with_funding(t.BtcOutpoint("cd" * 32, 1), terms.btc_sats)
    return _real_maker_claim_tx(foreign, preimage)


async def test_observed_reveal_refuses_a_same_H_claim_tx_from_another_swap():
    """MUTANT: delete ``self._assert_claim_tx_spends_our_htlc(maker_claim_ref)`` in
    ``taker_observed_reveal``.

    The existing ``test_taker_observed_reveal_rejects_foreign_reveal`` uses a foreign tx with a
    DIFFERENT H, so the scrape fails long before the provenance gate — the gate itself was
    unpinned at this call site. SECRET_REVEALED has no edge back to MUTUAL_REFUND, so a spurious
    advance strands the taker's whole refund route in the machine that is supposed to protect it.
    """
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd, role=SwapRole.TAKER)
    foreign = _foreign_same_h_claim_tx(terms, secret.unsafe_raw_bytes())

    with pytest.raises(ValidationError, match="does not spend this swap"):
        await coord.taker_observed_reveal(foreign)

    assert coord.record.state is SwapState.BOTH_LOCKED


async def test_claim_from_vulnerable_refuses_a_same_H_claim_tx_from_another_swap():
    """MUTANT: delete ``self._assert_claim_tx_spends_our_htlc(maker_claim_tx_bytes)`` in
    ``taker_claim_asset_from_vulnerable``.

    The winner-take-all path is the one taken under deadline pressure, which is exactly when a
    counterparty-supplied "here is the reveal" blob is least scrutinised. It is also the only
    claim path with no finality gate, so the provenance bind is its sole remaining check on the
    tx it acts upon.
    """
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = FakeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd, role=SwapRole.TAKER)
    ours = _real_maker_claim_tx(coord.record.btc_locator, secret.unsafe_raw_bytes())
    await coord.taker_observed_reveal(ours)
    # Squeeze the window so the gate routes to ASSET_VULNERABLE (t_rxd=72, burial 6).
    btc.claim_confs = 0
    await coord.taker_scrape_and_claim_asset(ours, now_rxd_height=1_070, asset_locked_at_height=1_000)
    assert coord.record.state is SwapState.ASSET_VULNERABLE

    foreign = _foreign_same_h_claim_tx(terms, secret.unsafe_raw_bytes())
    with pytest.raises(ValidationError, match="does not spend this swap"):
        await coord.taker_claim_asset_from_vulnerable(foreign)

    assert rxd.claimed_with is None
    assert coord.record.state is SwapState.ASSET_VULNERABLE


class _LyingScrapeBtcLeg(FakeBtcLeg):
    """A counter leg whose ``scrape_secret`` returns something that does NOT open H.

    ``scrape_secret`` is documented to select by ``sha256(candidate) == H``, but it is leg code:
    the coordinator re-derives the hash itself precisely so a buggy or hostile leg cannot decide
    what the swap's preimage is.
    """

    def scrape_secret(self, claim_tx_bytes: bytes, hashlock: bytes) -> bytes:
        return b"\x00" * 32


async def test_observed_reveal_recomputes_sha256_p_over_the_legs_answer():
    """MUTANT: delete the ``sha256(p) != hashlock`` re-check in ``taker_observed_reveal``.

    Without it the FSM advances to SECRET_REVEALED on a leg-supplied value nobody verified, and
    SECRET_REVEALED is a one-way door away from ``mutual_refund``.
    """
    secret, h = generate_secret()
    terms = _terms(hashlock=h)
    btc, rxd = _LyingScrapeBtcLeg(), FakeRadiantLeg()
    coord = await _to_both_locked(terms=terms, btc_leg=btc, radiant_leg=rxd, role=SwapRole.TAKER)
    ours = _real_maker_claim_tx(coord.record.btc_locator, secret.unsafe_raw_bytes())

    with pytest.raises(ValidationError, match="does not reveal a p that opens H"):
        await coord.taker_observed_reveal(ours)

    assert coord.record.state is SwapState.BOTH_LOCKED
    assert hashlib.sha256(secret.unsafe_raw_bytes()).digest() == h  # the honest p really does open H


# ---------------------------------------------------------------------------
# The ETH 'finalized' reorg pin (whole-stack audit MEDIUM-1)
# ---------------------------------------------------------------------------


def _measured_eth_policy():
    """A real-value ETH policy. ``min_n = ceil(768/300) + 6 - 1 = 8``, so N must be >= 8."""
    return MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=True,
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
        cross_clock_margin=_xmargin(),
        max_covenant_confirm_wait_s=3600,
    )


async def test_measured_eth_policy_pins_the_lock_time_reverify_to_finalized():
    """MUTANT: replace ``block_id = "finalized" if ...is_measured else None`` with ``None``.

    Only the ``is_measured=False -> None`` half was pinned
    (``test_eth_post_confirm_reverifies_counter_funding_at_lock_time``); the half that actually
    defends a real-value swap was not. This IS the MEDIUM-1 defence: a ``latest`` re-verify cannot
    catch a reorg that re-deploys a DIFFERENT contract at the same CREATE address between the
    maker's verify and its RXD lock, and the maker then reveals ``p`` against a contract that no
    longer pays it.
    """
    secret, h = generate_secret()
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40_000)
    leg = FakeEthLeg(preimage=secret, verdict=_final())
    rxd = FakeRadiantLeg()
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=leg,
        radiant_leg=rxd,
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=_measured_eth_policy(), maker_stall_safety_window_blocks=8),
    )
    await coord.taker_funds_btc(terms, now_unix_s=_NOW)

    rec = await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)

    assert rec.state is SwapState.BOTH_LOCKED
    assert leg.last_verify_block_identifier == "finalized", (
        "a real-value ETH swap must re-bind the counter leg at the finalized checkpoint"
    )


# ---------------------------------------------------------------------------
# Terms-construction guards
# ---------------------------------------------------------------------------


def _btc_terms_kwargs() -> dict:
    return dict(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


@pytest.mark.parametrize("value_amount", [99_999, 150_000])
def test_btc_terms_reject_a_value_amount_that_diverges_from_btc_sats(value_amount):
    """MUTANT: replace ``elif self.value_amount != self.btc_sats`` with a false branch — or with
    a one-sided ``>`` / ``<``, which is why BOTH directions are exercised.

    For a BTC swap the counter-leg amount IS ``btc_sats``. The two are read by different layers —
    the HTLC funding derives from ``btc_sats`` while the coordinator's funded-amount bind and the
    maker's ``verify_counterparty_funded`` compare against ``value_amount`` — so a divergence
    silently prices the two sides of one swap differently, in whichever direction it leans.
    """
    with pytest.raises(ValidationError, match="must equal btc_sats"):
        NegotiatedTerms(**_btc_terms_kwargs(), value_amount=value_amount)

    # Control: the sentinel (0) and an explicit exact match both construct.
    assert NegotiatedTerms(**_btc_terms_kwargs(), value_amount=0).value_amount == 100_000
    assert NegotiatedTerms(**_btc_terms_kwargs(), value_amount=100_000).value_amount == 100_000


def test_credential_ref_must_be_empty_or_a_full_singleton_ref():
    """MUTANT: replace ``if len(self.credential_ref) not in (0, 36)`` with a false branch.

    A truncated ref is not a weaker credential — it is a DIFFERENT one. The gate resolves whatever
    it is handed, so a length that cannot be a singleton ref must never reach the resolver.
    """
    for bad_len in (35, 37):
        with pytest.raises(ValidationError, match="empty or 36 bytes"):
            NegotiatedTerms(**_btc_terms_kwargs(), credential_ref=b"\x07" * bad_len)
    # Control: both legal lengths still construct.
    assert NegotiatedTerms(**_btc_terms_kwargs(), credential_ref=b"").credential_ref == b""
    assert len(NegotiatedTerms(**_btc_terms_kwargs(), credential_ref=b"\x07" * 36).credential_ref) == 36

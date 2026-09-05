"""Truth-table tests for the pure watchtower decision core (``gravity.watch.decide``).

Pure, no chain/network. Covers every Intent branch, the chain-truth-dominates rule
(claim race assessed from BOTH_LOCKED, not just SECRET_REVEALED), fail-closed paths
(missing depth, lying ``now < lock``), and low-corroboration propagation. The
finality-gate math is exercised indirectly — decide() consumes the real
``assess_claim_finality`` / ``taker_refund_window_open``, never a re-derivation.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import Intent, Observations, decide
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


# t_rxd KEEPS its 72 and t_btc drops to 36 (#482). Inverting the usual 72/144 pair the other
# way would have moved REFUND_OPENS from 172 to 244 and invalidated every height constant in
# this file — dozens of `now=` literals chosen relative to it. Shrinking t_btc satisfies the
# inverted ordering while leaving the heights, which are what these tests are about, alone.
def _btc_terms(*, t_btc_blocks: int = 36, t_rxd_blocks: int = 72) -> NegotiatedTerms:
    p = os.urandom(32)
    return NegotiatedTerms(
        hashlock=hashlib.sha256(p).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(t_btc_blocks, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _eth_terms() -> NegotiatedTerms:
    p = os.urandom(32)
    return NegotiatedTerms(
        hashlock=hashlib.sha256(p).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        # Same reasoning as `_btc_terms` above: t_rxd stays 72 so REFUND_OPENS stays 172, and
        # t_btc drops to 36 to satisfy the inverted ordering (#482).
        t_btc=t.Timelock(36, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=10**15,
        eth_timeout_unix_s=4_000_000_000,
    )


def _policy() -> MarginPolicy:
    # Explicit reorg depths so the gate math is deterministic in tests:
    #   required BTC depth = 6 blocks; RXD claim burial = 2 blocks.
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
    )


def _eth_policy() -> MarginPolicy:
    # ETH finality is a CHECKPOINT, not a depth: the gate reserves a TIME window converted to RXD
    # blocks (ceil(eth_finalization_window_s / rxd_block_interval_s)) in the WAIT branch, NOT a BTC
    # depth. 768 s (~2 post-Merge epochs) is the floor; ceil(768 / 300) = 3 RXD blocks reserved.
    # (RXD claim burial stays 2 blocks, as in _policy.)
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
    )


def _record(state: SwapState, *, terms: NegotiatedTerms | None = None) -> SwapRecord:
    return SwapRecord(state=state, terms=terms or _btc_terms())


SAFETY = 6
LOCK = 100  # asset_locked_at_height
# t_rxd = 72 → maker CSV refund opens at LOCK + 72 = 172.
REFUND_OPENS = LOCK + 72


def _decide(record, obs, *, policy: MarginPolicy | None = None):
    return decide(record=record, observations=obs, policy=policy or _policy(), safety_window_blocks=SAFETY)


def _eth(state: SwapState) -> SwapRecord:
    return SwapRecord(state=state, terms=_eth_terms())


def _decide_e(record, obs, *, policy: MarginPolicy | None = None):
    """decide() with the ETH policy (carries eth_finalization_window_s) unless overridden."""
    return decide(record=record, observations=obs, policy=policy or _eth_policy(), safety_window_blocks=SAFETY)


# ---------------------------------------------------------------------------
# Terminal / out-of-scope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    [
        SwapState.COMPLETED,
        SwapState.MUTUAL_REFUND,
        SwapState.ABORTED,
        SwapState.ASSET_REFUNDED_TAKER_ACTS,
        SwapState.ONE_SIDED_LOSS_TAKER,
    ],
)
def test_terminal_states_retire(state):
    d = _decide(_record(state), Observations(maker_has_claimed_btc=False, now_rxd_height=150))
    assert d.intent is Intent.RETIRE


# ---------------------------------------------------------------------------
# Maker-stall recovery is SYMMETRIC across counter-chains (FSM finding #2, 2026-06-09 — FIXED)
# ---------------------------------------------------------------------------
# Both the BTC and ETH stall paths recommend the SAME safe recovery for the SAME situation
# (BOTH_LOCKED, maker has not claimed, t_rxd maturity approaching): mutual_refund (unwinds BOTH
# legs). Before the fix the BTC path named the asset-only maybe_refund_asset_on_maker_stall whose
# CSV pays the MAKER — a one-sided taker loss (reproduced in test_xchain_swap_regtest_e2e.py::
# TestMakerStallAssetOnlyRefundIsTakerLoss, which stays as the durable characterization of why that
# helper is maker-only). These tests pin the symmetry so a regression re-surfaces here.


def test_btc_and_eth_maker_stall_both_recommend_mutual_refund():
    """The decision core is SYMMETRIC: identical maker-stall situation → mutual_refund on both."""
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=170, asset_locked_at_height=LOCK)
    btc = _decide(_record(SwapState.BOTH_LOCKED), obs)
    eth = _decide_e(_eth(SwapState.BOTH_LOCKED), obs)
    assert btc.intent is Intent.PAGE_REFUND and eth.intent is Intent.PAGE_REFUND
    # Neither counter-chain routes the taker to the asset-only refund (pays the maker — the loss path).
    assert btc.recommended_action == eth.recommended_action == "mutual_refund"


def test_btc_maker_stalls_state_pages_squeezed_no_clean_step():
    """MAKER_STALLS is unreachable on the coordinator path post-fix (its only producer,
    maybe_refund_asset_on_maker_stall, is no longer a taker watchtower action). If a record is
    observed there anyway, decide() fails closed to PAGE_SQUEEZED rather than naming a loss path —
    mirroring the ETH branch."""
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.MAKER_STALLS), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.recommended_action is not None and "mutual_refund" in d.recommended_action


def test_asset_refunded_terminal_retires_while_btc_still_locked():
    """Secondary strand (now unreachable on the taker path, but the invariant still holds): a record
    at the terminal ASSET_REFUNDED_TAKER_ACTS makes the watchtower RETIRE — it stops tracking even
    though a taker's BTC counter-leg would still be locked until t_btc. Removing the asset-only refund
    from the taker path is what makes this terminal unreachable for a taker; this pins the underlying
    terminal→RETIRE behavior so a future re-introduction of that path is caught."""
    # BTC funding shallow + maker has NOT claimed: the BTC leg is unambiguously still locked.
    obs = Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=180,  # past t_rxd maturity (172); t_btc is 36 blk and its own maturity is
        # judged on btc_funding_confirmations (1 here), not on this RXD height. The comment said
        # "t_btc (LOCK+144=244)" — a leftover from when t_btc was the longer leg (#482).
        asset_locked_at_height=LOCK,
        btc_funding_confirmations=1,
    )
    d = _decide(_record(SwapState.ASSET_REFUNDED_TAKER_ACTS), obs)
    assert d.intent is Intent.RETIRE  # no page to recover the still-locked BTC


# ---------------------------------------------------------------------------
# ETH counter-leg (v3) — finalized-checkpoint finality, mutual_refund on stall
# ---------------------------------------------------------------------------
# With _eth_policy(): rxd_burial = 2, rxd_claim_inclusion = 2 (#511), counter_reserve_rxd =
# ceil(768/300) = 3, t_rxd = 72, LOCK = 100 → REFUND_OPENS = 172, blocks_left = 172 - now. So:
#   FINAL              → SAFE iff blocks_left >= 4 (burial 2 + inclusion 2), else SQUEEZED.
#   NOT_YET_FINAL_LIVE → WAIT iff blocks_left >= 7 (burial 2 + reserve 3 + inclusion 2), else SQUEEZED.
# Both floors said 2 and 5 here until this line was corrected: #511 added the inclusion term and
# nothing updated the arithmetic these tests are read against. Measured through `decide()`, not
# derived: FINAL flips PAGE_CLAIM→PAGE_SQUEEZED between blocks_left 4 and 3, NOT_YET_FINAL_LIVE
# flips WATCH→PAGE_SQUEEZED between 7 and 6.


def _eth_obs(*, detected, finality, now, lock=LOCK, low_corroboration=False):
    return Observations(
        maker_has_claimed_btc=False,  # BTC field unused on the ETH path
        now_rxd_height=now,
        asset_locked_at_height=lock,
        eth_claim_detected=detected,
        eth_claim_finality=finality,
        low_corroboration=low_corroboration,
    )


def test_eth_claim_finalized_pages_claim():
    # FINAL + ample window → SAFE → PAGE_CLAIM with the ETH claim step + deadline.
    obs = _eth_obs(detected=True, finality=CounterClaimState.FINAL, now=150)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_scrape_and_claim_asset"
    assert d.deadline_rxd_height == REFUND_OPENS


def test_eth_claim_not_yet_finalized_waits():
    # NOT_YET_FINAL_LIVE but window has room (blocks_left 22 >= the floor of 7) → WAIT → WATCH (no page).
    obs = _eth_obs(detected=True, finality=CounterClaimState.NOT_YET_FINAL_LIVE, now=150)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.WATCH


def test_eth_claim_finalized_but_window_closing_squeezes():
    # FINAL but only 1 block left (< the floor of 4 = burial 2 + inclusion 2) → SQUEEZED → PAGE_SQUEEZED.
    obs = _eth_obs(detected=True, finality=CounterClaimState.FINAL, now=REFUND_OPENS - 1)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "vulnerable" in d.recommended_action.lower() or "winner" in d.recommended_action.lower()


def test_eth_claim_not_yet_final_window_closing_squeezes():
    # NOT_YET_FINAL_LIVE and blocks_left 4 < the floor of 7 → no room to wait for finality → SQUEEZED.
    obs = _eth_obs(detected=True, finality=CounterClaimState.NOT_YET_FINAL_LIVE, now=168)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_claim_dominates_lagging_record():
    # Chain shows the ETH claim (FINAL) but the record still says BOTH_LOCKED (operator offline) →
    # the claim race is assessed from chain truth anyway → PAGE_CLAIM.
    obs = _eth_obs(detected=True, finality=CounterClaimState.FINAL, now=150)
    d = _decide_e(_eth(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_CLAIM


def test_eth_secret_revealed_record_with_no_finality_fails_closed():
    # SECRET_REVEALED record arms the gate even if detection is suppressed; with no finalized verdict
    # it fails CLOSED to a decision-required page (never a silent all-clear).
    obs = _eth_obs(detected=False, finality=None, now=150)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "un-assessable" in d.reason


def test_eth_claim_missing_lock_height_fails_closed():
    obs = _eth_obs(detected=True, finality=CounterClaimState.FINAL, now=150, lock=None)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_claim_now_below_lock_fails_closed():
    # now < asset_locked ⇒ lagging/lying node ⇒ gate raises ⇒ fail-closed page.
    obs = _eth_obs(detected=True, finality=CounterClaimState.FINAL, now=50)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_not_yet_final_without_finalization_window_fails_closed():
    # The finalization-reserve (WAIT-vs-SQUEEZED) branch needs eth_finalization_window_s. A NOT_YET_FINAL
    # claim under a policy that lacks it makes assess_claim_finality raise → decide() fails CLOSED to a
    # decision-required page, never an optimistic WAIT/SAFE. (A FINAL claim needs no such reserve, so the
    # window is only load-bearing here.)
    obs = _eth_obs(detected=True, finality=CounterClaimState.NOT_YET_FINAL_LIVE, now=150)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs, policy=_policy())  # _policy() has no eth window
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_maker_stall_refund_due_pages_mutual_refund():
    # now >= maturity - safety (166) and maker hasn't revealed → PAGE_REFUND naming mutual_refund
    # (NOT maybe_refund_asset_on_maker_stall, which is forbidden on the ETH stall path).
    obs = _eth_obs(detected=False, finality=None, now=167)
    d = _decide_e(_eth(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "mutual_refund"
    assert d.deadline_rxd_height == REFUND_OPENS


def test_eth_maker_stall_refund_not_due_watches():
    obs = _eth_obs(detected=False, finality=None, now=150)
    d = _decide_e(_eth(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.WATCH


def test_eth_maker_stalls_state_fails_closed_to_squeezed():
    # MAKER_STALLS is unreachable on the coordinator-driven ETH path and no clean coordinator refund
    # applies from it (mutual_refund is BOTH_LOCKED-only) → fail closed to a decision-required page,
    # NOT a step the coordinator would reject.
    obs = _eth_obs(detected=False, finality=None, now=150)
    d = _decide_e(_eth(SwapState.MAKER_STALLS), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.recommended_action != "mutual_refund"


def test_eth_params_mismatch_pages_counter_leg_refund():
    # mutual_refund is BOTH_LOCKED-only and would touch the maker's covenant; the state-valid step
    # from PARAMS_MISMATCH is taker_refund_btc, which refunds the ETH counter-leg HTLC (mirrors BTC).
    obs = _eth_obs(detected=False, finality=None, now=150)
    d = _decide_e(_eth(SwapState.PARAMS_MISMATCH), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "taker_refund_btc"


def test_eth_asset_vulnerable_pages_decision():
    obs = _eth_obs(detected=False, finality=None, now=170)
    d = _decide_e(_eth(SwapState.ASSET_VULNERABLE), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_low_corroboration_propagates():
    obs = _eth_obs(detected=False, finality=None, now=167, low_corroboration=True)
    d = _decide_e(_eth(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.low_corroboration is True


def test_eth_terminal_retires():
    obs = _eth_obs(detected=False, finality=None, now=150)
    d = _decide_e(_eth(SwapState.COMPLETED), obs)
    assert d.intent is Intent.RETIRE


def test_eth_observations_validation():
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=10, eth_claim_detected="yes")
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=10, eth_claim_finality="final")


def test_eth_counter_chain_not_finalizing_squeezes_even_with_room():
    # RF-06: a non-finalizing counter chain must SQUEEZE, never WAIT — even with an ample t_rxd window.
    # (The point-in-time leg verdict never emits this today; the field carries it for when the
    # FinalityStallTracker is wired, and decide() must pass it straight to the gate, which SQUEEZES.)
    obs = _eth_obs(detected=True, finality=CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING, now=150)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_detected_without_finality_fails_closed_regardless_of_state():
    # The claim-race guard is armed by detection alone; a detected claim with NO finalized verdict
    # fails CLOSED to a decision-required page even when record.state has not advanced (BOTH_LOCKED).
    obs = _eth_obs(detected=True, finality=None, now=150)
    d = _decide_e(_eth(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "un-assessable" in d.reason


def test_eth_not_yet_final_reserve_boundary():
    # Locks the 3-block finalization reserve (ceil(768/300)) against an off-by-one regression.
    # The floor is burial 2 + reserve 3 + inclusion 2 (#511) = 7, so blocks_left 7 (now=165) WAITs
    # and blocks_left 6 (now=166) SQUEEZES. It was 5/4 while the claim was assumed to bury from the
    # current height; #511 reserves the blocks it needs to be MINED first.
    wait = _decide_e(
        _eth(SwapState.SECRET_REVEALED), _eth_obs(detected=True, finality=CounterClaimState.NOT_YET_FINAL_LIVE, now=165)
    )
    squeeze = _decide_e(
        _eth(SwapState.SECRET_REVEALED), _eth_obs(detected=True, finality=CounterClaimState.NOT_YET_FINAL_LIVE, now=166)
    )
    assert wait.intent is Intent.WATCH
    assert squeeze.intent is Intent.PAGE_SQUEEZED


def test_btc_and_eth_finality_dispatch_parity():
    # The two branches must map the gate verdict to the same Intents (guards against a one-sided edit):
    #   FINAL + ample window      → PAGE_CLAIM
    #   not-yet-final + room       → WATCH (never PAGE_CLAIM)
    #   FINAL + closing window     → PAGE_SQUEEZED
    def _btc(confs, now):
        return _decide(
            _record(SwapState.SECRET_REVEALED),
            Observations(
                maker_has_claimed_btc=True,
                now_rxd_height=now,
                asset_locked_at_height=LOCK,
                btc_claim_confirmations=confs,
            ),
        ).intent

    def _eth_(final, now):
        return _decide_e(_eth(SwapState.SECRET_REVEALED), _eth_obs(detected=True, finality=final, now=now)).intent

    assert _btc(6, 150) is Intent.PAGE_CLAIM and _eth_(CounterClaimState.FINAL, 150) is Intent.PAGE_CLAIM
    assert _btc(3, 150) is Intent.WATCH and _eth_(CounterClaimState.NOT_YET_FINAL_LIVE, 150) is Intent.WATCH
    assert (
        _btc(6, REFUND_OPENS - 1) is Intent.PAGE_SQUEEZED
        and _eth_(CounterClaimState.FINAL, REFUND_OPENS - 1) is Intent.PAGE_SQUEEZED
    )


# ---------------------------------------------------------------------------
# Claim race (maker revealed p) — gate verdict drives the page
# ---------------------------------------------------------------------------


def test_claim_safe_pages_claim():
    # FINAL (6 conf) and room to bury (now well before refund opens) → SAFE → PAGE_CLAIM.
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_scrape_and_claim_asset"
    assert d.deadline_rxd_height == REFUND_OPENS


def test_secret_revealed_record_arms_gate_even_if_detection_suppressed():
    # red-team #7: a record at SECRET_REVEALED is INDEPENDENT evidence p is public. Even if the
    # single-source chain DETECTION is suppressed (maker_has_claimed_btc=False), the swap must NOT
    # fall to the silent WATCH catch-all — the record alone arms the claim-finality assessment, which
    # with no claim depth available fails CLOSED to a decision-required page (never a silent all-clear).
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "un-assessable" in d.reason


def test_claim_wait_keeps_watching():
    # NOT_YET_FINAL (3 conf) but window has room → WAIT → WATCH (no page).
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=3
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.WATCH


def test_claim_squeezed_pages_decision():
    # FINAL but window closing (1 block left < the floor of 4 = burial 2 + inclusion 2) → SQUEEZED.
    obs = Observations(
        maker_has_claimed_btc=True,
        now_rxd_height=REFUND_OPENS - 1,
        asset_locked_at_height=LOCK,
        btc_claim_confirmations=6,
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert "vulnerable" in d.recommended_action.lower() or "winner" in d.recommended_action.lower()


def test_claim_race_dominates_lagging_record():
    # Chain shows the maker claimed, but the record still says BOTH_LOCKED (operator
    # offline). The claim race must be assessed anyway (Gap 2/7).
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_CLAIM


def test_claim_missing_depth_fails_closed():
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=LOCK, btc_claim_confirmations=None
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_claim_missing_lock_height_fails_closed():
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=None, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_claim_now_below_lock_fails_closed():
    # now_rxd_height < asset_locked_at_height ⇒ lying/lagging node ⇒ gate raises ⇒ fail-closed page.
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=50, asset_locked_at_height=LOCK, btc_claim_confirmations=6
    )
    d = _decide(_record(SwapState.SECRET_REVEALED), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


class TestTheBtcClaimRaceVerdictBoundaries:
    """Every BTC claim-race test above sits tens of blocks from the flip it is about.

    They use `now=150` (blocks_left 22) or `REFUND_OPENS - 1` (blocks_left 1) and nothing
    else. Measured through `decide()` with `_policy()` — swept over every height from LOCK
    to REFUND_OPENS rather than derived — the two verdicts actually flip at:

      * FINAL (6 conf):              PAGE_CLAIM at blocks_left 4, PAGE_SQUEEZED at 3
      * NOT_YET_FINAL_LIVE (3 conf): WATCH at blocks_left 16, PAGE_SQUEEZED at 15

    4 is the #511 floor (burial 2 + inclusion 2); 16 adds the F-007 counter reserve
    `ceil(6 * 600 / 300) = 12`.

    What these close is the BTC DISPATCH, not the gate. A change inside
    `assess_claim_finality` itself is already caught elsewhere — planting the pre-#511 floor
    (`burial + counter_reserve`, inclusion dropped) fails the coordinator's parity sweep, the
    ETH reserve boundary and the executor's broadcast boundary as well as these. What nothing
    covered was `decide()`'s own BTC branch: planting `now_rxd_height + 1` on it alone fails
    EXACTLY these four tests and nothing else in the tree (measured over the full suite —
    11,417 passed, 2 failed, twice, once per direction).

    Both directions are real defects, which is why each flip is pinned from BOTH sides: one
    block early certifies a claim that cannot bury before the maker's refund opens; one block
    late refuses an honest claim after `p` is already public, which is the forfeiture path.

    The ETH branch already had `test_eth_not_yet_final_reserve_boundary`; the BTC branch,
    which is the one the shipped BTC↔RXD swaps take, had no boundary case at all.
    """

    @staticmethod
    def _at(confs: int, now: int) -> Intent:
        obs = Observations(
            maker_has_claimed_btc=True,
            now_rxd_height=now,
            asset_locked_at_height=LOCK,
            btc_claim_confirmations=confs,
        )
        return _decide(_record(SwapState.SECRET_REVEALED), obs).intent

    def test_final_pages_claim_with_exactly_the_floor_left(self) -> None:
        """blocks_left == 4 is the LAST height a claim can still be mined and buried in time."""
        assert self._at(6, REFUND_OPENS - 4) is Intent.PAGE_CLAIM

    def test_final_squeezes_one_block_past_the_floor(self) -> None:
        assert self._at(6, REFUND_OPENS - 3) is Intent.PAGE_SQUEEZED

    def test_not_yet_final_waits_with_exactly_the_reserve_left(self) -> None:
        """blocks_left == 16 still leaves room to wait out the remaining BTC depth and then bury."""
        assert self._at(3, REFUND_OPENS - 16) is Intent.WATCH

    def test_not_yet_final_squeezes_one_block_past_the_reserve(self) -> None:
        assert self._at(3, REFUND_OPENS - 15) is Intent.PAGE_SQUEEZED


# ---------------------------------------------------------------------------
# Refund / stall / danger states (maker has NOT revealed p)
# ---------------------------------------------------------------------------


def test_asset_vulnerable_pages_decision():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=170, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.ASSET_VULNERABLE), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_params_mismatch_pages_btc_refund():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150)
    d = _decide(_record(SwapState.PARAMS_MISMATCH), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "taker_refund_btc"


def test_both_locked_refund_not_due_watches():
    # now well before (maturity - safety) = 172 - 6 = 166.
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.WATCH


def test_both_locked_refund_due_pages_refund():
    # now >= maturity - safety (166) → refund window near; the taker prepares mutual_refund (the
    # safe both-legs unwind), NOT the asset-only refund that pays the maker (FSM finding #2).
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=167, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "mutual_refund"


def test_maker_stalls_pages_squeezed():
    # Post-fix MAKER_STALLS is unreachable on the coordinator path; if seen, fail closed (no clean step).
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    d = _decide(_record(SwapState.MAKER_STALLS), obs)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_both_locked_unknown_lock_height_watches():
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=None)
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.WATCH


@pytest.mark.parametrize("state", [SwapState.NEGOTIATED, SwapState.BTC_LOCKED])
def test_pre_lock_states_watch(state):
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150)
    d = _decide(_record(state), obs)
    assert d.intent is Intent.WATCH


# ---------------------------------------------------------------------------
# Low-corroboration propagation + input validation
# ---------------------------------------------------------------------------


def test_low_corroboration_propagates():
    obs = Observations(
        maker_has_claimed_btc=False, now_rxd_height=167, asset_locked_at_height=LOCK, low_corroboration=True
    )
    d = _decide(_record(SwapState.BOTH_LOCKED), obs)
    assert d.intent is Intent.PAGE_REFUND
    assert d.low_corroboration is True


def test_decide_rejects_bad_inputs():
    rec = _record(SwapState.BOTH_LOCKED)
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=LOCK)
    with pytest.raises(ValidationError):
        decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=-1)
    with pytest.raises(ValidationError):
        decide(record="not a record", observations=obs, policy=_policy(), safety_window_blocks=SAFETY)


def test_observations_validation():
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=-1)
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=10, btc_claim_confirmations=-3)


def test_value_at_risk_photons_rxd_only():
    """Audit follow-up: the watchtower's per-record value is radiant_amount ONLY for an RXD swap;
    FT/NFT (token amount / NFT carrier dust — not the off-chain economic value) return None."""
    from pyrxd.gravity.watch.decide import _value_at_risk_photons

    class _T:
        def __init__(self, variant, amt):
            self.asset_variant = variant
            self.radiant_amount = amt

    assert _value_at_risk_photons(_T("rxd", 7000)) == 7000
    assert _value_at_risk_photons(_T("ft", 7000)) is None
    assert _value_at_risk_photons(_T("nft", 1)) is None


def test_watchtower_ft_swap_with_value_scaling_fails_closed():
    """The seam fix: with value-scaling CONFIGURED on the tower policy but the swap FT/NFT (the tower
    can't read the off-chain value), the gate fails closed → PAGE_SQUEEZED, never an optimistic
    PAGE_CLAIM. Contrast test_eth_claim_finalized_pages_claim (same obs, no value-scaling → PAGE_CLAIM)."""
    import dataclasses

    vs_policy = dataclasses.replace(_eth_policy(), rxd_reorg_cost_per_block=100_000)
    obs = _eth_obs(detected=True, finality=CounterClaimState.FINAL, now=150)
    d = _decide_e(_eth(SwapState.SECRET_REVEALED), obs, policy=vs_policy)
    assert d.intent is Intent.PAGE_SQUEEZED


# ---------------------------------------------------------------------------
# ETH arm: maker never locks the asset (the branch the BTC arm always had)
# ---------------------------------------------------------------------------
#
# `taker_funds_btc` is the funding step for BOTH counter-chains and advances to BTC_LOCKED, so an
# ETH swap sits at BTC_LOCKED with the taker's ETH HTLC funded and the maker's covenant absent.
# `decide`'s BTC arm pages PAGE_REFUND there once maturity is provable; `_decide_eth` had no
# BTC_LOCKED branch at all and fell through to the silent WATCH catch-all — every tick, forever.


def _eth_btc_locked_obs(*, now_unix_s=None, lock=None):
    return Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=150,
        asset_locked_at_height=lock,
        eth_claim_detected=False,
        eth_claim_finality=None,
        now_unix_s=now_unix_s,
    )


def test_eth_maker_never_locks_pages_refund_once_the_timeout_passes():
    """MUTANT: delete the ``state is SwapState.BTC_LOCKED`` branch in ``_decide_eth``.

    The taker's ETH HTLC is funded, the maker locked nothing, and ``eth_timeout_unix_s``
    (4_000_000_000 in ``_eth_terms``) has passed — the counter-leg refund is DUE and the operator
    must be told. Without the branch this is an ``Intent.WATCH``, which the reconciler does not
    route to any handler: no page, no webhook, no heartbeat count.
    """
    d = _decide_e(_eth(SwapState.BTC_LOCKED), _eth_btc_locked_obs(now_unix_s=4_000_000_001))
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "taker_refund_btc"
    # The autonomous discriminator arms the BTC keyless pre-signed refund; it has no ETH counterpart.
    assert d.autonomous_btc_refund is False


def test_eth_maker_never_locks_watches_before_the_timeout():
    """The honest-path control: a maker that has simply not locked YET must not be paged. A guard
    that fires on every healthy pre-lock tick is its own failure for an alert-only tower."""
    d = _decide_e(_eth(SwapState.BTC_LOCKED), _eth_btc_locked_obs(now_unix_s=3_999_999_999))
    assert d.intent is Intent.WATCH


def test_eth_maker_never_locks_watches_when_the_clock_is_unread():
    """Fail-closed in the SAME direction as the BTC arm, which watches on an unread funding depth:
    an absent ``now_unix_s`` (every pre-existing caller) can never manufacture a page."""
    d = _decide_e(_eth(SwapState.BTC_LOCKED), _eth_btc_locked_obs(now_unix_s=None))
    assert d.intent is Intent.WATCH


def test_eth_stale_btc_locked_record_with_an_observed_asset_lock_does_not_page_refund():
    """Mirrors the BTC arm's fail-closed: an asset lock seen on-chain means the maker DID lock, so a
    stale BTC_LOCKED record must not be turned into a refund recommendation."""
    d = _decide_e(
        _eth(SwapState.BTC_LOCKED),
        _eth_btc_locked_obs(now_unix_s=4_000_000_001, lock=LOCK),
    )
    assert d.intent is Intent.WATCH
    assert "maker locked" in d.reason


def test_observations_rejects_a_negative_clock():
    with pytest.raises(ValidationError):
        Observations(maker_has_claimed_btc=False, now_rxd_height=10, now_unix_s=-1)


class TestTheDepthVerdictAndTheGateUseONEConversion:
    """`_required_btc_depth_blocks` and `assess_claim_finality` must not round apart.

    The docstring said they were "identical to the coordinator's construction … so the
    verdict and the gate's internal reserve cannot diverge (assess_claim_finality fails
    closed on a mismatch)". They were two different roundings of one quantity:
    `normalize_to` FLOORS, `_reserve_to_blocks` CEILS. At
    `btc_claim_reorg_depth = Timelock(3700, SECONDS)` with `block_interval_s = 600` they
    gave 6 and 7.

    And the mismatch guard did not save it, because it only covers the WAIT path:

    * at 5 confirmations the guard raises and an honest WATCH degrades to
      PAGE_SQUEEZED "un-assessable" — a guard refusing valid work;
    * at 6 the FINAL branch returns BEFORE the guard, so the tower pages PAGE_CLAIM and
      arms `autonomous_asset_claim` one block shallower than the policy's own reserve.

    Fixed by calling the gate's conversion rather than a second one, so they agree by
    construction. CEIL is the safe direction for a reserve — flooring under-counts, and
    under-counting is what armed the claim early.
    """

    INTERVAL = 600.0

    def _policy(self, value: int, unit):
        import dataclasses

        from pyrxd.btc_wallet.taproot import Timelock
        from pyrxd.gravity.swap_coordinator import MarginPolicy

        return dataclasses.replace(
            MarginPolicy.estimated(),
            block_interval_s=self.INTERVAL,
            btc_claim_reorg_depth=Timelock(value, unit),
        )

    @pytest.mark.parametrize("seconds", [3599, 3600, 3700, 4200, 7777])
    def test_they_agree_on_a_SECONDS_tagged_reserve(self, seconds: int) -> None:
        from pyrxd.btc_wallet.taproot import TimeUnit
        from pyrxd.gravity.swap_coordinator import _reserve_to_blocks
        from pyrxd.gravity.watch.decide import _required_btc_depth_blocks

        policy = self._policy(seconds, TimeUnit.SECONDS)
        assert int(_required_btc_depth_blocks(policy)) == int(
            _reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s)
        )

    @pytest.mark.parametrize("blocks", [2, 3, 6, 12, 20])
    def test_nothing_the_repo_actually_builds_changes(self, blocks: int) -> None:
        """Every constructor here produces BLOCKS, where both conversions are the
        identity. The fix must be a no-op across the shipped configuration space, or it
        is a behaviour change smuggled in as a correctness fix."""
        from pyrxd.btc_wallet.taproot import TimeUnit
        from pyrxd.gravity.watch.decide import _required_btc_depth_blocks

        assert int(_required_btc_depth_blocks(self._policy(blocks, TimeUnit.BLOCKS))) == blocks

    def test_the_divergent_case_really_did_diverge(self) -> None:
        """Guards the fixture. If floor and ceil ever coincided at these parameters the
        tests above would pass while proving nothing."""
        from pyrxd.btc_wallet.taproot import TimeUnit

        policy = self._policy(3700, TimeUnit.SECONDS)
        floored = policy.btc_claim_reorg_depth.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s
        ).value
        assert floored == 6, "the old FLOOR path"
        from pyrxd.gravity.swap_coordinator import _reserve_to_blocks

        assert _reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s) == 7

    def test_the_verdict_never_requires_LESS_depth_than_the_reserve(self) -> None:
        """The property that matters, swept. Requiring less is what arms an autonomous
        claim shallower than policy; the reverse only costs a wait."""
        from pyrxd.btc_wallet.taproot import TimeUnit
        from pyrxd.gravity.swap_coordinator import _reserve_to_blocks
        from pyrxd.gravity.watch.decide import _required_btc_depth_blocks

        for seconds in range(3000, 5000, 37):
            policy = self._policy(seconds, TimeUnit.SECONDS)
            assert int(_required_btc_depth_blocks(policy)) >= int(
                _reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s)
            ), seconds

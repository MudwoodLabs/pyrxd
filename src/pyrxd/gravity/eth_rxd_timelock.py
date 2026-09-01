"""Cross-clock (ETH absolute-seconds ↔ RXD relative-blocks) timelock bridge.

The BTC↔RXD swap keeps both legs in the same relative-CSV/BLOCKS clock, so the mature
``assert_timelock_margin`` can normalize them through one block interval. The ETH leg
breaks that symmetry: an ETH HTLC refund is an ABSOLUTE unix-second ``block.timestamp``
deadline, while the Radiant covenant refund is a RELATIVE CSV/BIP68 count in BLOCKS that
only starts counting once the covenant is MINED. This module bridges the two:

* :func:`eth_absolute_to_rxd_relative_blocks` converts the absolute ETH deadline into the
  relative RXD-block window the maker should lock the covenant for, with conservative
  (floor) rounding + a fail-closed safety floor, so the canonical HTLC ordering invariant
  holds across the unit + anchor boundary: the asset/RXD leg (claimed SECOND, by the taker)
  opens its refund strictly BEFORE the counter/ETH leg's deadline by at least the margin —
  i.e. the counter/ETH leg, claimed FIRST by the maker, holds the SHORTER deadline (the
  cross-clock analog of the BTC ``t_BTC > t_RXD`` invariant). The inherent risk this ordering
  creates (a maker withholding its claim until past the RXD refund, then claiming AND
  refunding) is mitigated by the proactive asset-refund + the cross-clock margin coupling, not
  by the timelock alone — see
  :func:`pyrxd.gravity.swap_coordinator.taker_refund_window_open`.

  RESIDUAL FREE-OPTION (red-team HIGH, NOT fully closed pre-audit). The reveal-on-the-long-leg
  free-option is INHERENT to this swap shape and is only BOUNDED here, not eliminated. Honest
  caveats: (1) the proactive asset-refund returns the covenant to the MAKER (it owns the asset;
  p is not yet public), so it does NOT recover value for the ETH TAKER — the taker's value sits
  in the ETH HTLC, refundable only after ``eth_timeout`` via ``mutual_refund``. (2) A maker that
  reveals at ``eth_timeout - epsilon`` (genuinely FINAL, not a stall) after the ``t_rxd`` window
  has closed can race its own CSV refund; the coordinator's reorg gate then SQUEEZES the taker to
  ``ASSET_VULNERABLE`` and a winner-take-all claim can lose to the already-landed CSV refund —
  the FSM-modeled ``ASSET_VULNERABLE -> ONE_SIDED_LOSS_TAKER`` residual. The defenses that BOUND
  it: the cross-clock margin (this module) sizes ``t_rxd`` to open strictly before the ETH
  deadline minus the full finality-stall-tolerant margin, and the coordinator couples the
  proactive-refund window ``N`` to the finality+burial reserve so a reveal cannot be timed into a
  squeeze the taker could otherwise have acted in. This residual is an ACCEPTED, documented,
  pre-external-audit property (same as the BTC<->RXD direction), surfaced loudly (never a silent
  COMPLETED) and gated behind the external audit + the test
  ``test_eth_late_reveal_races_csv_taker_squeezed_then_cannot_claim_spent_covenant``.

* :func:`assert_covenant_confirms_before_eth_deadline` is the funding-confirmation gate
  that closes the NEW mixed-clock race (re-audit SC-3/TLK-1): because the RXD CSV clock
  does not start until the covenant confirms, a delay between agreeing terms and the
  covenant being mined pushes the real RXD refund later in wall-clock against the FIXED ETH
  deadline. The gate refuses to lock RXD unless the covenant can plausibly confirm with
  enough margin still left.

Pure (no chain I/O) and fail-closed (``ValidationError``, never ``assert``). On mainnet
``rxd_block_interval_s`` MUST be a MEASURED value — estimates are test-only — the same
provenance discipline as ``MarginPolicy`` / ``Timelock.normalize_to``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.constants import SEQUENCE_LOCKTIME_MASK
from pyrxd.security.errors import ValidationError

__all__ = [
    "CrossClockMargin",
    "assert_covenant_confirms_before_eth_deadline",
    "assert_eth_deadline_is_claimable",
    "assert_t_rxd_fits_the_eth_deadline",
    "eth_absolute_to_rxd_relative_blocks",
]

# BIP68 relative-block fields are 16 bits; mirrors Timelock's own guard so the converter
# fails with a domain-specific message instead of a generic encoding error. Taken from
# the shared consensus constant rather than re-typed as 0xFFFF — a fourth spelling of
# SEQUENCE_LOCKTIME_MASK is a fourth place for it to be wrong.
_MAX_RXD_CSV_BLOCKS = SEQUENCE_LOCKTIME_MASK


@dataclass(frozen=True)
class CrossClockMargin:
    """The safety budget (seconds) carved out of the ETH→RXD deadline gap.

    Each component is a deliberate, documented seconds budget; the converter subtracts
    their sum from the ETH deadline before sizing the RXD window, so the RXD refund opens
    strictly BEFORE the ETH deadline by at least this much wall-clock (the RXD/asset leg,
    LOCKED by the maker, holds the LONGER deadline; the ETH/counter leg the shorter).

    ``eth_reorg_finality_s`` is the post-Merge ETH finalized-checkpoint lag in the STEADY
    STATE (~2 epochs ≈ 768 s ≈ 12.8 min — formally specified, ethereum.org/eth2book).

    ``eth_finality_stall_tolerance_s`` is the ADDITIONAL budget for an ETH FINALITY STALL —
    the checkpoint freezing while blocks keep being produced (observed on Sepolia 2026-06-01,
    ~20 min; the May-2023 MAINNET incident reached ~9 epochs ≈ 1 hr; an inactivity-leak worst
    case is unbounded — Jump Crypto). This is the single most important safety addition: the
    taker waits for ETH FINALITY before claiming RXD (the trust-minimised choice per the
    ethresear.ch "rational finality stalls" analysis — do NOT downgrade to a block count during
    a stall), so the RXD refund must NOT open until the taker has had a stall-tolerant window.
    Sizing this against happy-path finality (~13 min) is the exact bug a stall triggers. Set it
    to AT LEAST a May-2023-class hour for a mainnet ETH leg; larger is safer (the cost is only
    the maker's asset being locked longer, a liveness cost, never a safety one).

    ``rounding_slack_s`` MUST be at least one ``rxd_block_interval_s`` to absorb the converter's
    floor rounding plus a cross-chain clock-skew budget.
    """

    eth_reorg_finality_s: int  # ETH finalized-checkpoint STEADY-STATE lag (~2 epochs, specified)
    rxd_claim_burial_s: int  # time for the taker's RXD claim to bury reorg-deep
    rxd_confirm_slack_s: int  # slack for the RXD claim tx to propagate + confirm
    rounding_slack_s: int  # block-rounding (>= one block) + cross-chain clock-skew budget
    eth_finality_stall_tolerance_s: int = 0  # ADDITIONAL budget for an ETH finality STALL (see docstring)

    def __post_init__(self) -> None:
        for name in (
            "eth_reorg_finality_s",
            "rxd_claim_burial_s",
            "rxd_confirm_slack_s",
            "rounding_slack_s",
            "eth_finality_stall_tolerance_s",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValidationError(f"CrossClockMargin.{name} must be int seconds")
            if value < 0:
                raise ValidationError(f"CrossClockMargin.{name} must be >= 0")

    def total_s(self) -> int:
        return (
            self.eth_reorg_finality_s
            + self.rxd_claim_burial_s
            + self.rxd_confirm_slack_s
            + self.rounding_slack_s
            + self.eth_finality_stall_tolerance_s
        )


#: How far the sizer may step down to reach a value the gate accepts. The analytic value is
#: never more than one block out; the extra room is so a genuine divergence raises rather
#: than silently shrinking the taker's claim window block by block.
_SIZER_GATE_STEPS = 3


def eth_absolute_to_rxd_relative_blocks(
    *,
    eth_timeout_unix_s: int,
    expected_rxd_lock_time_unix_s: int,
    margin: CrossClockMargin,
    rxd_block_interval_s: float,
    floor_blocks: int = 12,
) -> Timelock:
    """Size the RXD covenant's RELATIVE CSV window (in BLOCKS) from the ETH ABSOLUTE deadline.

    The RXD refund — relative, anchored at covenant mining ≈ ``expected_rxd_lock_time_unix_s``
    — must open strictly AFTER the ETH deadline plus the full margin (the RXD/asset leg is the
    one the MAKER LOCKED, so it holds the LONGER deadline; the ETH/counter leg the shorter).
    INVERTED 2026-08-31, #482: this subtracted the margin, putting the RXD refund BEFORE the ETH
    deadline and handing the maker a window in which to refund the covenant while ``p`` was still
    secret and then claim the counter leg. See :func:`assert_timelock_margin` for the rule and the
    Herlihy citation.

    The margin's components were always the right budget for THIS direction — every one is time
    the TAKER needs after the reveal (ETH finality, stall tolerance, claim burial, confirm slack,
    rounding), and the maker may reveal as late as ``eth_timeout``. Only the sign was wrong::

        budget_s = eth_timeout_unix_s + margin.total_s() - expected_rxd_lock_time_unix_s

    converted to blocks by FLOOR. Flooring can only SHORTEN the RXD window, which lets the
    maker reclaim the asset no later than computed (never longer); the sub-block remainder
    is covered by ``margin.rounding_slack_s``. Fail-closed ``ValidationError`` if the budget
    is non-positive, below the safety floor, or beyond the BIP68 16-bit cap.

    ``rxd_block_interval_s`` MUST be a conservative FAST-TAIL percentile of the RXD inter-block
    distribution (e.g. p10), NOT the mean. Rationale (the attacker-benefits-when-RXD-runs-fast
    rule): ``t_rxd = ceil(budget_s / interval) - 1`` picks the block count whose EXPECTED wall-clock
    is ``budget_s``; if RXD then mines FASTER than ``interval`` assumed, those ``t_rxd`` blocks
    elapse SOONER than ``budget_s`` and the refund opens EARLY — shrinking (in the worst case
    eliminating) the taker's claim window. A smaller (fast-tail) ``interval`` yields MORE blocks
    for the same budget, so the refund opens later in the fast case — the safe direction. Using
    the mean UNDERESTIMATES how fast the window can open. Measured RXD mainnet 2026-06-02 (150
    blocks): min 9 s, p10 43 s, median 229 s, mean 330 s — the p10/min, not the mean, is the
    load-bearing number. A slow RXD only lengthens the maker's lock (a liveness, not safety, cost).

    RE-MEASURED 2026-08-26 (720 blocks): p10 36 s, median 221 s, mean 296 s, p90 671 s, max
    2325 s. The p10 drifted DOWN from 43 s, which is the direction that under-counts a reserve —
    sizing with the June figure against the August reality gives 16% fewer blocks than the window
    holds. Measure per run; do not inherit either number.
    """
    _require_int(eth_timeout_unix_s, "eth_timeout_unix_s")
    _require_int(expected_rxd_lock_time_unix_s, "expected_rxd_lock_time_unix_s")
    if not isinstance(floor_blocks, int) or isinstance(floor_blocks, bool) or floor_blocks < 1:
        raise ValidationError("floor_blocks must be a positive int")
    if rxd_block_interval_s <= 0:
        raise ValidationError(
            "rxd_block_interval_s must be > 0 (use a MEASURED conservative FAST-TAIL percentile "
            "on mainnet, e.g. p10 — NOT the mean; see docstring)"
        )

    budget_s = eth_timeout_unix_s + margin.total_s() - expected_rxd_lock_time_unix_s
    if budget_s <= 0:
        raise ValidationError(
            f"no RXD timelock budget: eth_timeout - margin - rxd_lock_time = {budget_s}s "
            "(ETH deadline too close / margin too large to safely lock RXD)"
        )
    # `ceil(x) - 1`, NOT `floor(x)`. The two differ only when the budget divides EXACTLY by the
    # interval, and on exactly those inputs `floor` emits a value this module's own punctuality
    # gate then REFUSES: `assert_covenant_confirms_before_eth_deadline` compares with a strict `<`,
    # so a projection landing precisely ON the deadline is late. Swept 1480 parameter combinations
    # (eth_timeout 12-48h x 8 fast tails x 5 confirm waits): 111 divided exactly, and the gate
    # refused the sizer's own output on all 111 and on no others.
    #
    # It stayed invisible because nothing in production calls this function — the runner takes a
    # hand-typed `--t-rxd-blocks` — and because the test asserting sizer and gate agree sizes with
    # a zero confirm wait, which never lands on the boundary. The real run's parameters do:
    # (86400 - 7068 - 600) / 36 = 2187.0 exactly, so the canonical derivation produced 2187 and the
    # gate accepted only 2186. Deriving one block SHORT is the safe direction anyway: it opens the
    # maker's refund marginally LATER, costing the maker a block of lock time rather than letting
    # the refund open before the deadline it is sized to outlast (#482 inverted this: the gate is
    # now a LOWER bound on t_rxd, so `ceil` with no -1 is the smallest accepted value, where it was
    # `ceil - 1` for the largest accepted one).
    t_rxd_blocks = math.ceil(budget_s / rxd_block_interval_s)
    # ...and then ASK THE GATE, rather than trusting that arithmetic to match it.
    #
    # `ceil(x) - 1` is algebraically the largest `t` with `t * I < budget`, and it is exact for an
    # integer interval. It is NOT exact once `I` has a fractional part, because both sides round
    # differently in binary floating point: brute-forced against the real gate over 365 parameter
    # rows per interval, 0% of sized values were refused at 9/20/36/43/60/120/300 s and 0.27-2.74%
    # were refused at 36.2/36.4/36.5/36.7/43.3/60.5/331.7 s. `--rxd-block-interval-fast-s` is a
    # float and a MEASURED p10 almost never lands on an integer, so the failing set is the normal
    # case and the passing set is the rounded one.
    #
    # Patching the formula would fix the intervals someone thought to test. Deferring to the gate
    # makes the two agree by construction for every interval, which is the property actually
    # wanted: this function's contract is "the largest window the gate will accept".
    # RANGE FIRST, then the gate. Asking the gate about an absurd value gets an absurd answer:
    # a far-future deadline sizes to ~10^9 blocks, the gate refuses it for its own reasons, and the
    # step-down loop exhausted and reported "the sizer and the gate disagree" — burying the real
    # and much clearer BIP68 refusal under a message about rounding. Establish the value is even in
    # range before asking anything else about it.
    if t_rxd_blocks < floor_blocks:
        raise ValidationError(
            f"RXD timelock {t_rxd_blocks} blocks below safety floor {floor_blocks} "
            f"(budget {budget_s}s at {rxd_block_interval_s}s/block)"
        )
    if t_rxd_blocks > _MAX_RXD_CSV_BLOCKS:
        raise ValidationError(
            f"RXD timelock {t_rxd_blocks} blocks exceeds the BIP68 16-bit cap "
            f"{_MAX_RXD_CSV_BLOCKS} (ETH deadline too far in the future to map to a "
            "relative CSV window)"
        )
    # START ONE BELOW THE ANALYTIC VALUE, then step up. `ceil` is the exact minimum only in exact
    # arithmetic; at fractional intervals the float division can round the quotient UP across an
    # integer boundary, and starting AT it would then return a window one block longer than the
    # gate actually requires, with no step able to find the shorter one (the search only goes up).
    # This is the mirror of the pre-#482 note about `ceil(x) - 1` legitimately being one block low.
    # The gate remains the authority: whatever this returns has been accepted by it.
    t_rxd_blocks = max(floor_blocks, t_rxd_blocks - 1)
    for _ in range(_SIZER_GATE_STEPS):
        try:
            assert_covenant_confirms_before_eth_deadline(
                now_unix_s=expected_rxd_lock_time_unix_s,
                eth_timeout_unix_s=eth_timeout_unix_s,
                margin=margin,
                t_rxd=Timelock(t_rxd_blocks, TimeUnit.BLOCKS),
                rxd_block_interval_s=rxd_block_interval_s,
                # The gate anchors on `now + wait`; anchoring it on the expected lock time with a
                # zero wait is the same instant, and keeps this function's own signature intact.
                max_covenant_confirm_wait_s=0,
            )
            break
        except ValidationError:
            # UP, not down (#482). The gate bounds t_rxd from BELOW now, so a refusal means the
            # window is too SHORT. Stepping down was the old direction and moves away from
            # acceptance — the loop then always exhausts and reports the sizer and gate as
            # disagreeing, which is how this was found.
            t_rxd_blocks += 1
    else:  # pragma: no cover — the analytic value is never more than one block out
        raise ValidationError(
            f"could not size a t_rxd the punctuality gate accepts within {_SIZER_GATE_STEPS} "
            f"blocks of {math.ceil(budget_s / rxd_block_interval_s)} (budget {budget_s}s at "
            f"{rxd_block_interval_s}s/block). The sizer and the gate disagree by more than a "
            "rounding step, which means one of them has changed meaning."
        )
    # The step-UP can cross the BIP68 cap by one, so re-check THAT. Not the floor: stepping up only
    # ever increases, and a value already at or above the floor stays there. This pairing flipped
    # with the search direction (#482) — re-checking the floor after an upward search is a check
    # that can no longer fail, and would have left the cap unguarded.
    if t_rxd_blocks > _MAX_RXD_CSV_BLOCKS:
        raise ValidationError(
            f"RXD timelock {t_rxd_blocks} blocks exceeds the BIP68 16-bit cap {_MAX_RXD_CSV_BLOCKS} "
            f"after the punctuality gate required one block more than the {budget_s}s budget allows "
            f"at {rxd_block_interval_s}s/block"
        )
    return Timelock(t_rxd_blocks, TimeUnit.BLOCKS)


def assert_covenant_confirms_before_eth_deadline(
    *,
    now_unix_s: int,
    eth_timeout_unix_s: int,
    margin: CrossClockMargin,
    t_rxd: Timelock,
    rxd_block_interval_s: float,
    max_covenant_confirm_wait_s: int,
    elapsed_blocks: int = 0,
) -> None:
    """Covenant-punctuality gate (re-audit SC-3/TLK-1).

    WHAT THIS ACTUALLY VERIFIES — read before changing it. The arithmetic below looks like a
    wall-clock projection of the RXD refund, and its previous docstring described it as one. It is
    not, because ``rxd_block_interval_s`` **cancels**: ``eth_absolute_to_rxd_relative_blocks``
    computes ``t_rxd = floor(budget_s / interval)`` and this function then computes
    ``ceil(t_rxd * interval)``, which are inverse operations and return ``budget_s`` again. Measured
    over 20 scenarios at six intervals spanning 9s to 1200s — a 133x range straddling the whole
    observed RXD distribution — the verdict did not change once. The interval is a no-op input.

    Substituting the reduction, the check that actually happens is::

        now_unix_s + max_covenant_confirm_wait_s  <  expected_rxd_lock_time_unix_s

    i.e. **does the covenant confirm by the time the sizing assumed it would**. That is a real and
    useful property — the CSV clock starts at covenant MINING, so a covenant that confirms late
    shifts the whole RXD window right — but it is punctuality, not a slow-chain defence.

    DO NOT "FIX" THIS BY PASSING A SLOWER PERCENTILE. That was attempted and it refuses every
    configuration at every budget, because sizing deliberately maximises the block count using a
    FAST-tail interval while a projection multiplied by a slow-tail one inflates it by the ratio
    between the two (~5.3x at p10 vs median). It would also be defending the wrong direction:
    :func:`eth_absolute_to_rxd_relative_blocks` establishes that a slow RXD only lengthens the
    MAKER'S LOCK — a liveness cost, never a safety one — because it gives the taker *more* time to
    claim, not less. The safety-critical direction is RXD running FAST, and that is handled where
    it belongs, in the sizing.

    The projected open is rounded UP (``ceil``) so the gate errs toward refusing; that rounding is
    the only residual effect the interval has, worth about one block at the boundary. Run this TWICE: (1)
    pre-lock with the worst-case ``max_covenant_confirm_wait_s`` (a projection before
    broadcasting the covenant), and (2) post-confirm with ``now_unix_s = actual mining time``
    and ``max_covenant_confirm_wait_s = 0``; if (2) fails the maker must refund the covenant
    proactively rather than proceed. Raises ``ValidationError`` when the covenant would
    confirm too late to lock RXD safely.
    """
    if not isinstance(t_rxd, Timelock) or t_rxd.unit is not TimeUnit.BLOCKS:
        raise ValidationError("t_rxd must be a BLOCKS Timelock")
    _require_int(now_unix_s, "now_unix_s")
    _require_int(eth_timeout_unix_s, "eth_timeout_unix_s")
    if rxd_block_interval_s <= 0:
        raise ValidationError("rxd_block_interval_s must be > 0")
    if not isinstance(max_covenant_confirm_wait_s, int) or isinstance(max_covenant_confirm_wait_s, bool):
        raise ValidationError("max_covenant_confirm_wait_s must be int")
    if max_covenant_confirm_wait_s < 0:
        raise ValidationError("max_covenant_confirm_wait_s must be >= 0")

    # ASSERT THE INVARIANT ITSELF, not a proxy for it (#482 §5). This checked "does the covenant
    # confirm by the time the sizing assumed" — the right question under the OLD relation, where
    # the RXD refund had to open BEFORE the ETH deadline and a LATE confirm pushed it past.
    #
    # The relation is inverted now: the refund must open AFTER the deadline plus the margin, so a
    # late confirm only adds margin (a liveness cost to the maker) and an EARLY one is what eats
    # it. The floor is therefore taken at the EARLIEST plausible confirm — `now_unix_s`, with no
    # allowance added — and the check is the property itself:
    #
    #     earliest_confirm + t_rxd  >=  eth_timeout + margin
    #
    # `max_covenant_confirm_wait_s` is still validated above and still meaningful to the caller as
    # an operational bound, but it no longer belongs in THIS arithmetic: adding it here would
    # assume a late confirm, which is the optimistic direction now.
    # ELAPSED DEPTH IS SUBTRACTED (#482, the #531 class applied to this gate). `t_rxd` is a
    # RELATIVE CSV counted from the covenant's MINING, so once the covenant has confirmations the
    # refund opens that much sooner. Anchoring at `now` with the undecremented `t_rxd` overstates
    # the window by exactly `elapsed_blocks * interval` — and the MAKER chooses that number, by
    # locking its covenant early and presenting the swap late. Under the old relation an overstated
    # window was the safe direction, which is why this went unnoticed; inverted, it is precisely
    # the direction that lets a maker refund RXD while still holding `p` to claim the ETH leg.
    _require_int(elapsed_blocks, "elapsed_blocks")
    if elapsed_blocks < 0:
        raise ValidationError("elapsed_blocks cannot be negative")
    remaining_blocks = t_rxd.value - elapsed_blocks
    required_open_s = eth_timeout_unix_s + margin.total_s()
    earliest_rxd_open_s = now_unix_s + math.ceil(remaining_blocks * rxd_block_interval_s)
    if earliest_rxd_open_s < required_open_s:
        raise ValidationError(
            f"the RXD refund could open too EARLY: the CSV clock starts at covenant MINING, so a "
            f"confirmation at {now_unix_s} puts the refund at {earliest_rxd_open_s} ({remaining_blocks} blk left of {t_rxd.value}), before the "
            f"{required_open_s} this swap requires (eth_timeout {eth_timeout_unix_s} + margin "
            f"{margin.total_s()}s). The maker LOCKS the Radiant leg, so it must outlast the leg "
            "the maker CLAIMS — refusing to lock RXD (#482). A LATE confirmation is safe here and "
            "costs the maker only lock time; an early one is what eats the taker's window."
        )


def assert_eth_deadline_is_claimable(
    *,
    now_unix_s: int,
    eth_timeout_unix_s: int,
    margin: CrossClockMargin,
) -> None:
    """Refuse an ETH deadline that has already passed, or is too near for the swap to complete.

    THIS EXISTS BECAUSE #482's INVERSION SILENTLY DROPPED IT. Under the old (wrong) relation the
    gate demanded the projected RXD refund land BEFORE ``eth_timeout``, so an expired or near-expiry
    deadline failed automatically — the refusal was a side effect of the arithmetic, and the two
    tests covering it were the only thing recording that the requirement existed. Inverting the
    relation turned a close deadline into the EASY case (the RXD refund clears it trivially), so
    both tests went green-by-vacuity and the protection disappeared with nothing to show for it.
    A requirement that only ever held as a side effect is one refactor away from gone.

    THE REQUIREMENT ITSELF IS INDEPENDENT of the ordering invariant, which is why it needs its own
    check. Ordering asks "if both parties act, can either be robbed?". This asks "can the party who
    must act still act at all?". The maker claims the ETH leg, and will not do so until the taker's
    funding is final — so the deadline must leave room for that finality plus a stall, or the taker
    is funding a leg the maker provably cannot claim. Both parties then refund, which loses no
    principal but burns fees, locks the taker's capital for the full ``t_rxd``, and hands the maker
    a free option: it can watch the price and simply decline to reveal.

    Fail-closed on a deadline in the past — that case is not a tight window, it is a dead swap.
    """
    _require_int(now_unix_s, "now_unix_s")
    _require_int(eth_timeout_unix_s, "eth_timeout_unix_s")

    # The maker acts only on FINAL funding, so that is the floor: finality, plus the stall budget
    # the policy already carries for it, plus the rounding/skew allowance.
    claim_reachable_s = margin.eth_reorg_finality_s + margin.eth_finality_stall_tolerance_s + margin.rounding_slack_s
    remaining_s = eth_timeout_unix_s - now_unix_s
    if remaining_s < claim_reachable_s:
        expired = " (ALREADY EXPIRED)" if remaining_s < 0 else ""
        raise ValidationError(
            f"the ETH deadline leaves too little time to claim{expired}: eth_timeout is {remaining_s}s away "
            f"but the maker cannot act until the counter leg is final, which needs {claim_reachable_s}s "
            f"(finality {margin.eth_reorg_finality_s}s + stall {margin.eth_finality_stall_tolerance_s}s + "
            f"rounding {margin.rounding_slack_s}s). Funding this would confirm too late to be claimed — "
            "both legs would refund, and until then the maker holds a free option (#482)."
        )


def assert_t_rxd_fits_the_eth_deadline(
    *,
    t_rxd: Timelock,
    eth_timeout_unix_s: int,
    expected_rxd_lock_time_unix_s: int,
    margin: CrossClockMargin,
    rxd_block_interval_s: float,
    floor_blocks: int = 12,
) -> None:
    """Check a SUPPLIED ``t_rxd`` against the counter-chain deadline. Fail-closed.

    :func:`eth_absolute_to_rxd_relative_blocks` DERIVES the largest safe window; this checks that an
    independently-chosen one fits inside it. Both are needed because operators supply ``t_rxd`` as a
    raw integer and the runners had no way to tell them it was wrong: the script-level check they
    ran compared ``t_btc - t_rxd >= margin`` against a ``t_btc`` constructed as
    ``t_rxd + margin + 4``, so it passed for every possible input while being labelled the safety
    gate.

    A ``t_rxd`` LARGER than the derived maximum pushes the Radiant refund past the counter-chain
    deadline, which inverts the leg ordering the whole protocol rests on. Smaller is safe here and
    deliberately permitted — a shorter window is the maker's own liveness cost, and #507 is the gate
    that stops it being made TOO short.
    """
    if not isinstance(t_rxd, Timelock) or t_rxd.unit is not TimeUnit.BLOCKS:
        raise ValidationError("t_rxd must be a BLOCKS Timelock")
    largest = eth_absolute_to_rxd_relative_blocks(
        eth_timeout_unix_s=eth_timeout_unix_s,
        expected_rxd_lock_time_unix_s=expected_rxd_lock_time_unix_s,
        margin=margin,
        rxd_block_interval_s=rxd_block_interval_s,
        floor_blocks=floor_blocks,
    )
    if int(t_rxd.value) > int(largest.value):
        raise ValidationError(
            f"t_rxd of {t_rxd.value} blocks exceeds the largest window the counter-chain deadline "
            f"allows ({largest.value} blocks): the Radiant refund would open at or after the ETH "
            "deadline minus margin, inverting the leg ordering. Shorten t_rxd or extend the ETH "
            "timeout."
        )


def _require_int(value: object, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{name} must be int seconds")

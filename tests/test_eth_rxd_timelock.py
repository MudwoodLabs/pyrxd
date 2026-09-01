"""Tests for the ETH↔RXD cross-clock timelock bridge (Tier-1 D1/D2).

Pure / offline. Property + fuzz coverage of the absolute-seconds→relative-blocks converter
and the funding-confirmation gate; both are fail-closed.
"""

from __future__ import annotations

import math

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.eth_rxd_timelock import (
    CrossClockMargin,
    assert_covenant_confirms_before_eth_deadline,
    assert_t_rxd_fits_the_eth_deadline,
    eth_absolute_to_rxd_relative_blocks,
)
from pyrxd.security.errors import ValidationError

_CAP = 0xFFFF


def _margin(a=300, b=600, c=300, d=600):
    return CrossClockMargin(eth_reorg_finality_s=a, rxd_claim_burial_s=b, rxd_confirm_slack_s=c, rounding_slack_s=d)


# ─────────────────────────────────────────────────────── CrossClockMargin ──


def test_margin_total_and_validation():
    assert _margin(1, 2, 3, 4).total_s() == 10
    with pytest.raises(ValidationError):
        CrossClockMargin(eth_reorg_finality_s=-1, rxd_claim_burial_s=0, rxd_confirm_slack_s=0, rounding_slack_s=0)
    with pytest.raises(ValidationError):
        CrossClockMargin(eth_reorg_finality_s=0, rxd_claim_burial_s=0, rxd_confirm_slack_s=0, rounding_slack_s=True)


def test_stall_tolerance_defaults_zero_and_is_additive():
    # Back-compat: omitting the new field leaves total_s unchanged (defaults to 0).
    assert _margin(1, 2, 3, 4).total_s() == 10
    # Set it and it adds to the total (a May-2023-class ~1hr stall budget).
    m = CrossClockMargin(
        eth_reorg_finality_s=768,  # ~2 epochs steady-state finality
        rxd_claim_burial_s=600,
        rxd_confirm_slack_s=300,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=3600,  # +1hr for a finality stall
    )
    assert m.total_s() == 768 + 600 + 300 + 300 + 3600
    # And it is validated like the others.
    with pytest.raises(ValidationError):
        CrossClockMargin(
            eth_reorg_finality_s=0,
            rxd_claim_burial_s=0,
            rxd_confirm_slack_s=0,
            rounding_slack_s=0,
            eth_finality_stall_tolerance_s=-1,
        )


def test_stall_tolerance_GROWS_the_rxd_window():
    # INVERTED WITH THE RELATION (#482). The margin used to be subtracted from the window: the RXD
    # refund had to open before the ETH deadline, so every second of stall budget bought fewer
    # blocks. It is added now — the refund must open AFTER the deadline PLUS the margin — so a
    # stall tolerance makes the maker lock its asset LONGER, which is who should pay for it.
    base = CrossClockMargin(
        eth_reorg_finality_s=768, rxd_claim_burial_s=600, rxd_confirm_slack_s=300, rounding_slack_s=300
    )
    with_stall = CrossClockMargin(
        eth_reorg_finality_s=768,
        rxd_claim_burial_s=600,
        rxd_confirm_slack_s=300,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=3600,
    )
    kw = dict(eth_timeout_unix_s=100_000, expected_rxd_lock_time_unix_s=0, rxd_block_interval_s=36.0)
    t_base = eth_absolute_to_rxd_relative_blocks(margin=base, **kw)
    t_stall = eth_absolute_to_rxd_relative_blocks(margin=with_stall, **kw)
    assert t_stall.value > t_base.value  # stall budget strictly LENGTHENS the maker's lock


def test_stall_tolerance_can_force_failclosed():
    # Still fail-closed, at the OPPOSITE end (#482). A huge stall tolerance used to leave NO budget;
    # it now demands a window past the BIP68 16-bit cap, which is equally unlockable. The refusal
    # survived the inversion; the reason for it did not, so the match string has to move with it.
    huge_stall = CrossClockMargin(
        eth_reorg_finality_s=768,
        rxd_claim_burial_s=600,
        rxd_confirm_slack_s=300,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=100_000_000,
    )
    with pytest.raises(ValidationError, match="BIP68"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=10_000,
            expected_rxd_lock_time_unix_s=0,
            margin=huge_stall,
            rxd_block_interval_s=36.0,
        )


def test_fast_interval_yields_more_blocks_than_mean():
    # The fast-tail (p10=36s, measured 2026-08-26) interval yields MORE blocks than the mean (330s) for the same
    # budget — the refund opens LATER in the fast case, which is the safe direction.
    kw = dict(eth_timeout_unix_s=100_000, expected_rxd_lock_time_unix_s=0, margin=_margin())
    t_fast = eth_absolute_to_rxd_relative_blocks(rxd_block_interval_s=36.0, **kw)
    t_mean = eth_absolute_to_rxd_relative_blocks(rxd_block_interval_s=330.0, **kw)
    assert t_fast.value > t_mean.value


# ─────────────────────────────────────────────────────── converter (D1) ──


def test_converter_concrete_floor_and_unit():
    # budget = 100000 + 1800(margin) - 0 = 101800s ; /600 = 169.67 -> ceil 170 blocks. The margin
    # is ADDED and the rounding is UP (#482): the window must COVER the budget, where it used to
    # have to fit inside it.
    m = _margin()  # total 1800
    t = eth_absolute_to_rxd_relative_blocks(
        eth_timeout_unix_s=100_000,
        expected_rxd_lock_time_unix_s=0,
        margin=m,
        rxd_block_interval_s=600.0,
        floor_blocks=12,
    )
    assert t == Timelock(170, TimeUnit.BLOCKS)
    assert t.value * 600.0 >= (100_000 + 1800)  # the window never UNDERshoots the budget


def test_converter_failclosed_no_budget():
    # "No budget" now means the lock time is so far PAST the deadline+margin that the required
    # window is non-positive — the swap is already over. Equal timestamps no longer produce it:
    # with the margin added, lock-at-deadline still needs `margin` seconds of window (#482).
    with pytest.raises(ValidationError, match="no RXD timelock budget|below safety floor"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=1000,
            expected_rxd_lock_time_unix_s=100_000,
            margin=_margin(),
            rxd_block_interval_s=600.0,
        )


def test_converter_failclosed_below_floor():
    # budget tiny -> blocks below floor
    with pytest.raises(ValidationError, match="below safety floor"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=1801 + 600,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=600.0,
            floor_blocks=12,
        )


def test_converter_failclosed_above_bip68_cap():
    # huge far-future deadline -> > 0xFFFF blocks
    with pytest.raises(ValidationError, match="BIP68 16-bit cap"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=10**9,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=1.0,
        )


def test_converter_rejects_bad_interval_and_floor():
    with pytest.raises(ValidationError):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=100_000,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=0.0,
        )
    with pytest.raises(ValidationError):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=100_000,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=600.0,
            floor_blocks=0,
        )


def _analytic_start(budget: float, interval: float) -> int:
    """The sizer's analytic STARTING point — not a model of its answer.

    This helper used to be named `_expected_blocks` and the property test asserted
    `t.value == _expected_blocks(...)`, restating the sizer's arithmetic (`ceil(x) - 1`; before
    that, `floor(x)`). That model was stale twice over: the sizer's real contract is now "the
    largest value `assert_covenant_confirms_before_eth_deadline` accepts", reached by stepping
    DOWN from this analytic value, and at fractional intervals it legitimately returns one block
    less than `ceil(x) - 1` (both sides of `ceil(t*I) < budget` round differently in binary
    floating point). At `eth_timeout=44, interval=1.5` the analytic value 29 projects to exactly
    44s against a 44s deadline, the gate correctly refuses it, and the sizer returns 28 — so the
    equality assertion failed on CORRECT output, and because hypothesis persists shrunk
    counterexamples into the committed `tests/.hypothesis-corpus/`, the first CI run to find one
    would have turned the suite permanently red.

    What remains true of this value: the sizer starts here and may step UP at most
    `_SIZER_GATE_STEPS` (3) times (#482 inverted the search), so it bounds the answer from below
    and (plus 2 — the third refusal raises instead of returning) from above.
    """
    return max(0, math.ceil(budget / interval) - 1) if budget > 0 else 0


def _gate_accepts_at_lock_time(t_blocks: int, *, eth_timeout: int, rxd_lock: int, margin, interval: float) -> bool:
    """Would the punctuality gate accept `t_blocks`, asked exactly as the sizer asks it?

    Mirrors the sizer's internal query (`now = expected lock time`, zero confirm wait) so the
    property test can state the sizer's contract — "the largest value the gate accepts" — using
    the REAL gate as the oracle instead of restating either function's arithmetic.
    """
    try:
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=rxd_lock,
            eth_timeout_unix_s=eth_timeout,
            margin=margin,
            t_rxd=Timelock(t_blocks, TimeUnit.BLOCKS),
            rxd_block_interval_s=interval,
            max_covenant_confirm_wait_s=0,
        )
        return True
    except ValidationError:
        return False


@given(
    eth_timeout=st.integers(min_value=1, max_value=4_000_000_000),
    rxd_lock=st.integers(min_value=0, max_value=4_000_000_000),
    m1=st.integers(0, 1_000_000),
    m2=st.integers(0, 1_000_000),
    m3=st.integers(0, 1_000_000),
    m4=st.integers(0, 1_000_000),
    interval=st.floats(min_value=1.0, max_value=3600.0, allow_nan=False, allow_infinity=False),
    floor_blocks=st.integers(min_value=1, max_value=1000),
)
# The deterministic boundary case that made the old `t.value == ceil(x)-1` model fail on CORRECT
# output: budget 44 at 1.5s/block → analytic 29 projects to exactly 44s against a 44s deadline,
# the gate refuses it, and the sizer rightly returns 28. Pinned as an @example so this exact
# fractional-interval step-down is exercised on EVERY run, not only when hypothesis rediscovers it.
@example(eth_timeout=44, rxd_lock=0, m1=0, m2=0, m3=0, m4=0, interval=1.5, floor_blocks=1)
# A second instance found while reproducing the flake (seed 7): budget 85190 at 1.5s/block,
# analytic 56793 refused, 56792 returned. Same class, different magnitude.
@example(eth_timeout=173_171, rxd_lock=0, m1=0, m2=0, m3=0, m4=87_981, interval=1.5, floor_blocks=1)
def test_converter_invariants_or_failclosed(eth_timeout, rxd_lock, m1, m2, m3, m4, interval, floor_blocks):
    margin = CrossClockMargin(
        eth_reorg_finality_s=m1, rxd_claim_burial_s=m2, rxd_confirm_slack_s=m3, rounding_slack_s=m4
    )
    budget = eth_timeout + margin.total_s() - rxd_lock
    start = _analytic_start(budget, interval)

    def accepts(t_blocks: int) -> bool:
        return _gate_accepts_at_lock_time(
            t_blocks, eth_timeout=eth_timeout, rxd_lock=rxd_lock, margin=margin, interval=interval
        )

    try:
        t = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=eth_timeout,
            expected_rxd_lock_time_unix_s=rxd_lock,
            margin=margin,
            rxd_block_interval_s=interval,
            floor_blocks=floor_blocks,
        )
    except ValidationError:
        # Fail-closed is legitimate exactly when: no budget at all, the analytic value is out of
        # the representable range, or even the SMALLEST permitted window (`floor_blocks`) is
        # already too late for the gate (the step-down crossed the safety floor). The last
        # disjunct uses the gate as the oracle: acceptance is downward-closed in t (the
        # projection `ceil(t*I)` is non-decreasing), so "the gate refuses floor_blocks" is
        # equivalent to "every value the floor allows is refused". If NONE of these hold, the
        # refusal turned away honest work — the sizer/gate contract has genuinely diverged.
        assert budget <= 0 or start < floor_blocks or start > _CAP or not accepts(_CAP)
        return
    # success → invariants hold
    assert t.unit is TimeUnit.BLOCKS
    assert floor_blocks <= t.value <= _CAP
    # The sizer's REAL contract — deferring to its own punctuality gate — stated with the gate as
    # the oracle rather than restated arithmetic. The old model here (`floor`, later `ceil-1`)
    # went stale both times the sizer changed; asking the gate cannot.
    #   (a) what it emitted, the gate accepts (honest path);
    assert accepts(t.value), f"the sizer emitted t_rxd={t.value} and its own gate refuses it"
    #   (b) one FEWER block is refused — the emitted value is the SMALLEST the gate accepts, so no
    #       fix for (a) may quietly lengthen the maker's lock instead (#482 flipped which side of
    #       the boundary is the give-away);
    #       ...but ONLY where the GATE is the binding constraint. When the safety floor is what
    #       stops the search, the emitted value is the floor and the gate legitimately accepts less
    #       — asserting otherwise demands the sizer return a value below its own floor. Found by
    #       hypothesis at floor_blocks=2, emitted 2, gate accepting 1.
    if t.value > floor_blocks:
        assert not accepts(t.value - 1), (
            f"the gate also accepts t_rxd={t.value - 1}: the maker's lock is a block too long"
        )
    #   (c) the step-UP never drifts: the answer stays within the sizer's documented reach of
    #       the analytic value (start, or up to 2 above it — the third refusal raises instead).
    assert start <= t.value <= start + 2, f"t.value={t.value} outside [{start}, {start + 2}]"
    # "the sized value is conservative — never overshoots the budget", to within floating-point
    # noise. `ceil(x) - 1` is at most `floor(x)`, so it is conservative wherever floor was.
    #
    # The tolerance is not papering over a production bug; it is here because BOTH sides of
    # this comparison are IEEE 754 doubles and neither can represent the exact quantity:
    #
    #   1. The production function starts from `ceil(budget / rxd_block_interval_s) - 1` (then
    #      only ever steps DOWN, so the bound below holds a fortiori), and
    #      that division is itself rounded. It can round the true quotient UP across an
    #      integer boundary — at eth_timeout=54294, m4=4904, interval=1.1 the budget is 49390
    #      and the exact quotient is 44899.999999999996, but the float quotient is exactly
    #      44900.0, so floor returns 44900 rather than the exact floor 44899.
    #   2. This test then recomputes `t.value * interval` in floating point, which rounds again.
    #
    # The combined overshoot is bounded by ~2 ULP of the budget (one rounding from each
    # step); measured worst case across a structured sweep of "nice" intervals is 1 ULP —
    # for the case above, 7.3e-12 seconds against a 49,390-second budget. `floor` remains
    # the right, conservative choice: any REAL overshoot would be at least one whole block,
    # i.e. >= `interval` >= 1.0 second, which is many orders of magnitude above this bound,
    # so the invariant still fails loudly if the direction of the rounding ever flips.
    # Sub-block remainder is covered by `margin.rounding_slack_s` by design (see the
    # `eth_absolute_to_rxd_relative_blocks` docstring).
    # UNDERSHOOT is the direction to bound now (#482): the window must COVER the budget, where it
    # used to have to fit inside it.
    #
    # AND THE CEIL IS LOAD-BEARING ON THIS SIDE. The gate compares `ceil(t * interval)`, not the
    # raw product. Under the old inequality the un-rounded product was a conservative proxy — it is
    # never larger — so dropping the ceil here was safe and this line did not have one. Reversed,
    # the same omission understates the window by up to a second and the assertion fails on
    # CORRECT output: at eth_timeout=44, interval=1.5 the sizer returns 29, whose 43.5s projects to
    # ceil = 44 and exactly meets a 44s budget. That is the pinned @example above, and it is why
    # the model has to mirror the gate's arithmetic rather than approximate it.
    assert math.ceil(t.value * interval) >= budget - 8 * math.ulp(float(budget))


# ─────────────────────────────────────────────────── funding-confirm gate (D2) ──


def test_gate_passes_with_margin_left():
    m = _margin(60, 60, 60, 60)  # total 240
    t = Timelock(10, TimeUnit.BLOCKS)
    # earliest open = 1000 + ceil(10*600) = 7000 ; required = 6700 + 240 = 6940 <= 7000 → OK
    assert_covenant_confirms_before_eth_deadline(
        now_unix_s=1000,
        eth_timeout_unix_s=6700,
        margin=m,
        t_rxd=t,
        rxd_block_interval_s=600.0,
        max_covenant_confirm_wait_s=0,
    )


def test_gate_fails_when_the_refund_would_open_before_the_deadline():
    m = _margin(60, 60, 60, 60)  # total 240
    t = Timelock(10, TimeUnit.BLOCKS)
    # earliest open = 7000 ; required = 6761 + 240 = 7001 > 7000 → raise, by exactly one second
    with pytest.raises(ValidationError, match="open too EARLY"):
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=1000,
            eth_timeout_unix_s=6761,
            margin=m,
            t_rxd=t,
            rxd_block_interval_s=600.0,
            max_covenant_confirm_wait_s=0,
        )


def test_the_confirm_wait_no_longer_moves_the_verdict():
    """THIS TEST CHANGED PURPOSE, deliberately, and says so rather than being deleted (#482).

    It asserted that a `max_covenant_confirm_wait_s` budget pushed the projected open past the
    deadline and forced a refusal. That term is gone from the arithmetic: the floor is now taken at
    the EARLIEST plausible confirm, and adding a wait would assume a LATE one, which is the
    optimistic direction under this relation.

    The parameter is still validated and still meaningful to callers as an operational bound, so
    the thing worth pinning is that it is INERT here — otherwise a future change could quietly
    reintroduce it into the arithmetic and reopen exactly the window it used to close.
    """
    m = _margin(60, 60, 60, 60)
    t = Timelock(10, TimeUnit.BLOCKS)
    kw = dict(now_unix_s=1000, eth_timeout_unix_s=6700, margin=m, t_rxd=t, rxd_block_interval_s=600.0)
    assert_covenant_confirms_before_eth_deadline(max_covenant_confirm_wait_s=0, **kw)
    assert_covenant_confirms_before_eth_deadline(max_covenant_confirm_wait_s=600, **kw)
    assert_covenant_confirms_before_eth_deadline(max_covenant_confirm_wait_s=100_000, **kw)


def test_gate_requires_blocks_timelock():
    with pytest.raises(ValidationError, match="BLOCKS"):
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=1000,
            eth_timeout_unix_s=10_000,
            margin=_margin(),
            t_rxd=Timelock(600, TimeUnit.SECONDS),
            rxd_block_interval_s=600.0,
            max_covenant_confirm_wait_s=0,
        )


class TestASuppliedTRxdIsCheckedAgainstTheCounterChainDeadline:
    """Operators supply `t_rxd` as a raw integer, and the script-level check that was supposed to
    catch a bad one could not fail: it compared `t_btc - t_rxd >= margin` against a `t_btc` built
    as `t_rxd + margin + 4`, so the difference it inspected was constant by construction. It was
    labelled the safety gate and validated nothing.

    The real question needs `eth_timeout_unix_s` — the quantity the old check never looked at.
    """

    @staticmethod
    def _margin() -> CrossClockMargin:
        return CrossClockMargin(
            eth_reorg_finality_s=780,
            rxd_claim_burial_s=1_800,
            rxd_confirm_slack_s=600,
            rounding_slack_s=300,
            eth_finality_stall_tolerance_s=3_600,
        )

    def _check(self, blocks: int, *, budget_s: int = 200_000, interval: float = 229.0):
        now = 1_700_000_000
        assert_t_rxd_fits_the_eth_deadline(
            t_rxd=Timelock(blocks, TimeUnit.BLOCKS),
            eth_timeout_unix_s=now + budget_s,
            expected_rxd_lock_time_unix_s=now,
            margin=self._margin(),
            rxd_block_interval_s=interval,
        )

    def test_a_t_rxd_that_overruns_the_eth_deadline_is_REFUSED(self) -> None:
        """The case the tautology could never catch: a Radiant refund opening at or after the ETH
        deadline minus margin inverts the leg ordering the protocol rests on."""
        largest = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=1_700_000_000 + 200_000,
            expected_rxd_lock_time_unix_s=1_700_000_000,
            margin=self._margin(),
            rxd_block_interval_s=229.0,
        )
        with pytest.raises(ValidationError, match="exceeds the largest window"):
            self._check(int(largest.value) + 1)

    def test_the_LARGEST_fitting_window_is_accepted(self) -> None:
        """The boundary. Refusing here would reject the correctly-maximised window the sizer itself
        computes — a guard that refuses valid work, on the parameter an honest maker must choose."""
        largest = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=1_700_000_000 + 200_000,
            expected_rxd_lock_time_unix_s=1_700_000_000,
            margin=self._margin(),
            rxd_block_interval_s=229.0,
        )
        self._check(int(largest.value))

    def test_a_SHORTER_window_is_permitted(self) -> None:
        """Deliberately allowed: a shorter window is the maker's own liveness cost, and #507 is the
        gate that stops it being made too short to contain the value-scaled burial. This check is
        only about the upper bound."""
        self._check(12)


class TestTheCovenantGateIsPunctualityNotASlowChainDefence:
    """The gate LOOKS like a wall-clock projection of the RXD refund and was documented as one.
    It is not: `rxd_block_interval_s` cancels, because sizing computes `ceil(budget/interval)`
    and the gate computes `ceil(t_rxd * interval)` — inverse operations. (Sizing was
    `floor(budget/interval)` before #482 inverted the bound; the cancellation survives, which is
    why every test in this class except the direction of the refusal still holds.)

    These tests exist to stop the obvious "fix". Splitting the interval into fast and slow tails
    and passing the slow one here was attempted; it refuses every configuration at every budget,
    and it defends the wrong direction anyway — `eth_absolute_to_rxd_relative_blocks` establishes
    that a slow RXD only lengthens the MAKER's lock, a liveness cost, because it gives the taker
    MORE time to claim. The safety-critical direction is RXD running FAST, handled in the sizing.
    """

    @staticmethod
    def _margin() -> CrossClockMargin:
        return CrossClockMargin(
            eth_reorg_finality_s=780,
            rxd_claim_burial_s=1_800,
            rxd_confirm_slack_s=600,
            rounding_slack_s=300,
            eth_finality_stall_tolerance_s=3_600,
        )

    def _verdict(self, interval: float, *, lock_delay: int, wait: int) -> bool:
        now = 1_700_000_000
        lock = now + lock_delay
        eth_timeout = lock + 200_000
        t_rxd = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=eth_timeout,
            expected_rxd_lock_time_unix_s=lock,
            margin=self._margin(),
            rxd_block_interval_s=interval,
            floor_blocks=1,
        )
        try:
            assert_covenant_confirms_before_eth_deadline(
                now_unix_s=now,
                eth_timeout_unix_s=eth_timeout,
                margin=self._margin(),
                t_rxd=t_rxd,
                rxd_block_interval_s=interval,
                max_covenant_confirm_wait_s=wait,
            )
            return True
        except ValidationError:
            return False

    @pytest.mark.parametrize(("lock_delay", "wait"), [(600, 0), (3_600, 300), (7_200, 1_800), (20_000, 19_000)])
    def test_the_verdict_does_not_depend_on_the_block_interval_at_all(self, lock_delay: int, wait: int) -> None:
        """9s to 1200s is a 133x range straddling the entire observed RXD distribution (measured
        mainnet: min 9s, p10 43s, median 229s, mean 330s). If a change ever makes one of these
        disagree, the gate has started measuring something new — check it is the thing you meant,
        and that it does not simply refuse everything."""
        verdicts = {
            iv: self._verdict(iv, lock_delay=lock_delay, wait=wait) for iv in (9.0, 36.0, 229.0, 330.0, 600.0, 1_200.0)
        }
        assert len(set(verdicts.values())) == 1, (
            f"the interval changed the verdict: {verdicts}. The gate is documented as punctuality-"
            "only precisely because it cannot see the block rate."
        )

    def test_it_refuses_an_EARLY_covenant_confirmation(self) -> None:
        """WHICH DIRECTION IS DANGEROUS FLIPPED WITH THE RELATION (#482), and this pair is the
        clearest statement of it in the suite.

        The gate used to refuse a confirmation LATER than sizing assumed, because a late mine
        pushed the RXD refund past the ETH deadline it had to precede. The refund must now OUTLAST
        that deadline, so lateness only costs the maker lock time. What robs the taker is an EARLY
        confirmation: `t_rxd` counts from mining, so mining sooner opens the refund sooner, and the
        maker can refund its Radiant leg while still holding `p` for the ETH leg.

        `_verdict` checks the gate at `now` against a `t_rxd` sized for a lock at
        `now + lock_delay`, so a positive `lock_delay` IS the early-confirmation case.
        """
        assert not self._verdict(229.0, lock_delay=3_600, wait=0)

    def test_it_accepts_a_PUNCTUAL_covenant_confirmation(self) -> None:
        """Paired honest path — the gate must not refuse a covenant that confirms on time."""
        assert self._verdict(229.0, lock_delay=0, wait=0)

    def test_it_accepts_a_LATE_covenant_confirmation_which_is_now_the_SAFE_direction(self) -> None:
        """The refusal this class used to assert, now required to PASS.

        A guard that refuses valid work is a bug, and this one would refuse the maker for being
        slow — on the swap's most common non-adversarial deviation, where the cost falls on the
        maker alone and the taker is strictly better off.
        """
        assert self._verdict(229.0, lock_delay=-3_600, wait=0)

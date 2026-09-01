"""Boundary assertions that surviving mutants proved were missing.

`task mutate ethtimelock` was run for the first time after the ETH leg was added to cosmic-ray's
scope (it had none: 43 modules covered, 0 under `eth_wallet/`, and this file uncovered too, having
shipped two off-by-ones in one week). Result: **340 mutants, 279 killed, 61 survived**.

Most survivors are the documented equivalent classes — 12 sit inside an error-message f-string in a
`# pragma: no cover` branch, and 4 more are on the sizer's arithmetic line, where the step-down
loop repairs any initial value, so the arithmetic is genuinely not load-bearing on its own.

These are the ones that were real: each test below kills a specific mutant that the whole 10,000-
test suite did not notice. Every one is a BOUNDARY — the same class that produced the exact-division
off-by-one this module already shipped.
"""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.constants import SEQUENCE_LOCKTIME_MASK
from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin, eth_absolute_to_rxd_relative_blocks
from pyrxd.security.errors import ValidationError

_NOW = 1_700_000_000


def _margin(**kw) -> CrossClockMargin:
    base = dict(
        eth_reorg_finality_s=768,
        rxd_claim_burial_s=1800,
        rxd_confirm_slack_s=600,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=3600,
    )
    base.update(kw)
    return CrossClockMargin(**base)


def _size_for_budget(budget_s: int, interval: float, *, lock_delay: int = 600, **kw):
    """Size against an EXACT budget, which is what every boundary below is really about.

    #482 flipped the budget from `eth_timeout - margin - lock` to `eth_timeout + margin - lock`, so
    the old `eth_timeout_s = 7068 + N` idiom now means a budget 14136s larger than intended. Naming
    the budget directly makes these constants say what they pin instead of encoding one particular
    arrangement of the formula, and it survives the next change to the formula's shape.
    """
    return _size(
        eth_timeout_s=budget_s - _margin().total_s() + lock_delay, interval=interval, lock_delay=lock_delay, **kw
    )


def _size(*, eth_timeout_s: int, interval: float, lock_delay: int = 0, **kw):
    return eth_absolute_to_rxd_relative_blocks(
        eth_timeout_unix_s=_NOW + eth_timeout_s,
        expected_rxd_lock_time_unix_s=_NOW + lock_delay,
        margin=_margin(),
        rxd_block_interval_s=interval,
        **kw,
    )


class TestTheSafetyFloorDefault:
    """Killed mutants: `floor_blocks: int = 12` -> 11, -> 13.

    The default was pinned by nothing, so every caller that omits it — which is the normal case —
    was relying on an untested number. A floor that is one too low admits a window the design says
    is unsafe; one too high refuses a window that is fine.
    """

    def test_the_default_floor_is_exactly_twelve(self) -> None:
        # MEASURED against the real sizer, not derived by hand — deriving them by hand is what put
        # an off-by-one in this test on the first attempt, which is the same error class the whole
        # file exists to pin. Re-measured after #482: the sizer now emits the SMALLEST t with
        # `ceil(t*interval) >= budget`, so a 661s budget at 60s/block is the first that reaches 12.
        assert _size_for_budget(661, 60.0).value == 12
        assert _size_for_budget(720, 60.0).value == 12  # ...and 720 is the last
        assert _size_for_budget(721, 60.0).value == 13  # one second more buys the next block

    def test_one_block_below_the_default_floor_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="below safety floor 12"):
            _size_for_budget(660, 60.0)


class TestTheBip68CapBoundary:
    """Killed mutant: `if t_rxd_blocks > _MAX_RXD_CSV_BLOCKS` -> `>=`.

    A relative CSV window is a 16-bit field; the mask IS a representable value. Refusing it would
    reject a legitimate maximum-length timelock — a guard refusing valid work — and the boundary
    was untested in both directions.
    """

    def test_exactly_the_cap_is_ACCEPTED(self) -> None:
        cap = SEQUENCE_LOCKTIME_MASK
        # At 1s/block the budget IS the block count, so the cap is reached by a budget of exactly
        # `cap` seconds. (It was `cap + 1` while the sizer subtracted one from the ceiling.)
        sized = _size_for_budget(cap, 1.0, lock_delay=0)
        assert sized.value == cap, f"expected the cap {cap} to be representable, got {sized.value}"

    def test_one_block_ABOVE_the_cap_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="BIP68 16-bit cap"):
            _size_for_budget(SEQUENCE_LOCKTIME_MASK + 1, 1.0, lock_delay=0)


class TestTheIntervalAndBudgetBoundaries:
    """Killed mutants: `rxd_block_interval_s <= 0` -> `== 0`; `budget_s <= 0` -> `<= 1` / `< 0`.

    Only zero was ever exercised. A NEGATIVE interval is nonsense that `== 0` would let through,
    and it divides the budget — so it would silently produce a negative or inverted block count
    rather than failing closed.
    """

    @pytest.mark.parametrize("interval", [-1.0, -0.5, -36.0])
    def test_a_NEGATIVE_interval_is_refused_not_just_zero(self, interval: float) -> None:
        with pytest.raises(ValidationError, match="rxd_block_interval_s"):
            _size(eth_timeout_s=86_400, interval=interval)

    def test_a_zero_interval_is_still_refused(self) -> None:
        with pytest.raises(ValidationError, match="rxd_block_interval_s"):
            _size(eth_timeout_s=86_400, interval=0.0)

    def test_a_budget_of_exactly_zero_is_refused(self) -> None:
        """`<= 0` vs `< 0`: a zero budget buys no blocks at all and must fail closed."""
        with pytest.raises(ValidationError):
            _size_for_budget(0, 1.0, lock_delay=0)

    def test_a_budget_of_exactly_one_second_is_refused_by_the_FLOOR_not_by_the_sign(self) -> None:
        """`<= 0` vs `<= 1`: one second is a positive budget, so it must pass the sign check and be
        refused by the safety floor instead — a different error, which is what distinguishes them."""
        with pytest.raises(ValidationError, match="below safety floor"):
            _size_for_budget(1, 1.0, lock_delay=0)


class TestTheFloorBlocksTypeGuard:
    """Killed mutant: `not isinstance(x, int) or isinstance(x, bool)` -> `... and ...`.

    `True` is an `int` in Python, so a bool reaches the arithmetic unless it is rejected
    explicitly. Under the mutation a bool sails through, and `floor_blocks=True` silently means a
    safety floor of 1.
    """

    @pytest.mark.parametrize("bad", [True, False])
    def test_a_bool_floor_is_refused(self, bad: bool) -> None:
        with pytest.raises(ValidationError, match="floor_blocks"):
            _size(eth_timeout_s=86_400, interval=36.0, floor_blocks=bad)

    def test_an_honest_int_floor_is_accepted(self) -> None:
        """The paired honest path — the guard must reject bools without rejecting ints."""
        assert _size(eth_timeout_s=86_400, interval=36.0, floor_blocks=12).value > 12


class TestTheAnalyticValueNeedsAtMostOneStep:
    """Four mutants on the sizer's arithmetic line survive, and I first called them equivalent.

    `t_rxd_blocks = ceil(budget/interval)` mutates to `+ 1`, `// 1`, `* 1`, `** 1` — and the loop
    then walks the value until the gate accepts it, so the final answer is the same. "Equivalent",
    I said. (#482 inverted the search: it starts one BELOW the analytic value and steps UP, where
    it used to start at `ceil - 1` and step down. The invariant this class pins — that the loop
    corrects a rounding edge rather than repairing arithmetic nobody checks — is unchanged.)

    That is only true because `_SIZER_GATE_STEPS` is 3, giving the loop room to absorb a wrong
    starting point. The code's own comment claims the analytic value is "never more than one block
    out", and that claim IS testable — it is the difference between a loop that corrects a rounding
    edge and a loop quietly repairing arithmetic nobody checks.

    Pinning it kills all four, and it pins a real invariant rather than an implementation detail:
    if the analytic value ever needs two steps, the arithmetic has drifted from the gate and the
    loop is hiding it.
    """

    @staticmethod
    def _steps_needed(*, eth_timeout_s: int, interval: float, lock_delay: int = 600) -> int:
        """How far the loop must walk from its starting value to reach one the gate accepts.

        UPWARD now (#482), so the subtraction is `emitted - analytic`. Left as `analytic - emitted`
        this returns a negative number, `0 <= steps` fails, and the message blames the arithmetic
        for drifting when the only thing that moved was the direction of the walk.
        """
        import math

        margin = _margin()
        budget = eth_timeout_s + margin.total_s() - lock_delay
        analytic = math.ceil(budget / interval) - 1  # the sizer's own starting point
        emitted = _size(eth_timeout_s=eth_timeout_s, interval=interval, lock_delay=lock_delay).value
        return emitted - analytic

    @pytest.mark.parametrize("interval", [36.0, 36.2, 36.4, 43.3, 41.618, 60.0, 22.7])
    @pytest.mark.parametrize("eth_timeout_s", [43_200, 61_200, 86_400, 111_600])
    def test_the_loop_never_walks_more_than_one_block(self, interval: float, eth_timeout_s: int) -> None:
        steps = self._steps_needed(eth_timeout_s=eth_timeout_s, interval=interval)
        assert 0 <= steps <= 1, (
            f"the analytic value needed {steps} steps at interval={interval}, "
            f"eth_timeout_s={eth_timeout_s}. The code documents at most one; more means the "
            f"arithmetic has drifted from the gate and the step-down loop is concealing it."
        )


def test_the_cross_clock_margin_is_immutable() -> None:
    """Killed mutant: `@dataclass(frozen=True)` -> `frozen=False`.

    Nothing tested it. The margin is read repeatedly across a swap's lifetime — sizing, the
    punctuality gate, the runner's bounds — and a caller that mutated it midway would re-time a
    contract that cannot be re-timed.
    """
    m = _margin()
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.eth_reorg_finality_s = 1  # type: ignore[misc]

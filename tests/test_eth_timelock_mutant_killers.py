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
        """`<= 0` vs `< 0`: a zero budget buys no blocks at all and must fail closed.

        THE `match=` IS THE WHOLE TEST, and it was missing — so this class's named mutant was ALIVE.
        Mutating `budget_s <= 0` to `< 0` lets a zero budget through the sign check; it then falls
        to the safety floor and raises a DIFFERENT ValidationError, which a bare `pytest.raises`
        accepts. Measured: with that mutant planted, 262 tests across all four timelock files passed
        while this class's docstring claimed to kill it.

        A refusal test without `match=` asserts only "something went wrong", which on a fail-closed
        path is nearly always true and is why it caught nothing.
        """
        with pytest.raises(ValidationError, match="no RXD timelock budget"):
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

    @pytest.mark.parametrize(
        ("interval", "eth_timeout_s"), [(0.3, 4_800), (0.3, 10_000), (0.7, 4_800), (0.81335, 10_000)]
    )
    def test_the_search_starts_exactly_one_below_the_analytic_value(self, interval: float, eth_timeout_s: int) -> None:
        """Killed mutant: `max(floor_blocks, t_rxd_blocks - 1)` -> `- 2`.

        Listed as equivalent in the first pass, and it is not. At intervals of 1 s or more the gate
        refuses `ceil - 2`, so the step-up loop lands on the same value from either start. Below 1 s
        the gate's whole-second `ceil` makes several block counts project to the same second, and
        on the rows here `ceil - 2` is ALSO accepted (measured), so the `- 2` start returns a
        different window and `steps` comes out at -1.

        What this pins is the documented start point ("START ONE BELOW THE ANALYTIC VALUE"), not a
        claim that the result is the smallest accepted window: at sub-second intervals it is not,
        and the error is in the safe direction (longer). A sub-second interval is not a realistic
        Radiant block time, but `rxd_block_interval_s` only requires `> 0`, so it is a real input.
        If the sizer is ever changed to search for the true minimum, this test should change with it.
        """
        steps = self._steps_needed(eth_timeout_s=eth_timeout_s, interval=interval)
        assert steps == 0, f"expected the sizer's own start point to be accepted as-is, got {steps} steps"


def test_the_cross_clock_margin_is_immutable() -> None:
    """Killed mutant: `@dataclass(frozen=True)` -> `frozen=False`.

    Nothing tested it. The margin is read repeatedly across a swap's lifetime — sizing, the
    punctuality gate, the runner's bounds — and a caller that mutated it midway would re-time a
    contract that cannot be re-timed.
    """
    m = _margin()
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.eth_reorg_finality_s = 1  # type: ignore[misc]


# ─────────────────────────────────────────────── second pass, 2026-09-29 ──
#
# The weekly run of 2026-09-22 measured 386 mutants, 316 killed, 70 survived (81%) against an 86%
# floor; reproduced locally on `fa47d7f6` with the identical 386/316/70. The largest single cluster
# was `assert_eth_deadline_is_claimable`: 32 survivors, because none of the four files in this
# group's test list called it at all. Its production caller is `SwapCoordinator` (the ETH-leg
# pre-funding checks), so the gate ran in production with nothing in this group able to see a
# change to it. The rest are fail-closed input guards that were only ever exercised on their
# happy path, and the `elapsed_blocks` term, which no test in the group ever set to a nonzero value.


def _claimable(remaining_s: int, **margin_kw) -> None:
    from pyrxd.gravity.eth_rxd_timelock import assert_eth_deadline_is_claimable

    assert_eth_deadline_is_claimable(
        now_unix_s=_NOW, eth_timeout_unix_s=_NOW + remaining_s, margin=_margin(**margin_kw)
    )


class TestTheEthDeadlineMustLeaveTimeToClaim:
    """Killed mutants: every operator on `claim_reachable_s = finality + stall + rounding`, on
    `claim_floor_s = reachable + CLAIM_INCLUSION_BUDGET_S`, on `remaining_s = eth_timeout - now`,
    the budget literal itself, and `<=` -> `<` / `==` / `is` on both comparisons.

    THE AUTHORITY IS THE CONTRACT. `EthHtlc.claim` reverts with `Expired()` once
    `block.timestamp >= timeout` (`EthHtlc.sol`, in the `pyrxd-eth-htlc` repo; the ABI is vendored
    as `tests/fixtures/EthHtlc.json`), so a claim must be MINED strictly before `timeout`. The maker
    acts only once the taker's funding is FINAL (finality + stall + rounding), and its own claim guard
    (`eth_wallet/htlc_leg.py`) then refuses to broadcast unless `now + CLAIM_INCLUSION_BUDGET_S <
    timeout`. So the deadline must be MORE than finality + stall + rounding + 96 s away.

    `_margin()` gives 768 + 3600 + 300 = 4668 s to finality, and 4764 s with the inclusion budget.
    4764 s left is REFUSED (the maker's claim guard would see exactly 96 s of head-room and refuse
    it); 4765 s is the first accepted value.

    THIS CLASS PINNED THE OPPOSITE until review: it accepted exactly 4668 s and called that "a swap
    the maker can still claim". With 4668 s left the maker reaches finality at `timeout` itself, and
    a claim landing there reverts. The source had both defects — a strict `<` and no inclusion
    budget — and this test was pinning them in.
    """

    REACHABLE = 768 + 3600 + 300  # finality + stall + rounding, from `_margin()`
    FLOOR = REACHABLE + 96  # ...+ CLAIM_INCLUSION_BUDGET_S, typed as a literal so a mutant of it is seen

    def test_the_first_accepted_deadline_is_one_second_past_the_floor(self) -> None:
        """The honest boundary: one second of claim head-room beyond the inclusion budget."""
        _claimable(self.FLOOR + 1)

    def test_a_deadline_exactly_AT_the_floor_is_refused(self) -> None:
        """The maker would reach its claim with exactly 96 s left, which its own guard refuses
        (`now + budget >= timeout`), so funding it hands the maker a leg it will not claim."""
        with pytest.raises(ValidationError, match="leaves too little time to claim"):
            _claimable(self.FLOOR)

    def test_the_inclusion_budget_is_part_of_the_floor(self) -> None:
        """The second defect: finality alone was the floor. Every deadline in the 96 s above it was
        accepted for funding and then unclaimable — including exactly the old floor."""
        for remaining in (self.REACHABLE, self.REACHABLE + 1, self.REACHABLE + 50, self.FLOOR - 1):
            with pytest.raises(ValidationError, match=r"claim inclusion 96s"):
                _claimable(remaining)

    def test_the_budget_is_the_one_the_claim_guard_uses(self) -> None:
        """One number, not two copies that can drift: the ETH leg re-exports this module's value.

        Asserted on the SOURCE of `htlc_leg`, not on the value. An identity check (`is`) cannot
        see the leg going back to its own `= 96` literal, because CPython caches small ints: a
        local 96 and the imported 96 are the same object, so the drift this guards against would
        pass. What must not exist is a module-level assignment of the NAME to anything but the
        imported definition.
        """
        import ast
        import inspect

        from pyrxd.eth_wallet import htlc_leg
        from pyrxd.gravity import eth_rxd_timelock

        name = "CLAIM_INCLUSION_BUDGET_S"
        tree = ast.parse(inspect.getsource(htlc_leg))
        imported_as = {
            alias.asname or alias.name
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "pyrxd.gravity.eth_rxd_timelock"
            for alias in node.names
            if alias.name == name
        }
        assert imported_as, f"htlc_leg no longer imports {name} from eth_rxd_timelock"

        assigned: list[tuple[int, str]] = []
        for node in tree.body:
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if any(isinstance(t, ast.Name) and t.id == name for t in targets):
                assigned.append((node.lineno, ast.unparse(value)))
        # Non-vacuity: the re-export itself IS an assignment, so an empty list means the scan
        # stopped seeing assignments, not that the module is clean.
        assert assigned, f"expected htlc_leg's re-export of {name}; the scan found no assignment"
        bad = [(line, src) for line, src in assigned if src not in imported_as]
        assert not bad, (
            f"htlc_leg defines its own {name} ({bad}) instead of re-exporting "
            "eth_rxd_timelock's: the claim guard and the pre-funding check can drift apart again"
        )
        assert htlc_leg.CLAIM_INCLUSION_BUDGET_S == eth_rxd_timelock.CLAIM_INCLUSION_BUDGET_S == 96

    def test_a_deadline_far_short_of_the_floor_is_refused(self) -> None:
        """Not only the boundary: `==` would refuse exactly one value and wave the rest through."""
        with pytest.raises(ValidationError, match="leaves too little time to claim"):
            _claimable(60)

    def test_the_claim_burial_and_confirm_slack_are_NOT_part_of_the_floor(self) -> None:
        """The floor is the time before the MAKER's claim must be mined. Burial and confirm slack are
        time the TAKER needs after the reveal; they belong to `total_s()` and the RXD window, not
        here. Growing them must not move this boundary, in either direction."""
        _claimable(self.FLOOR + 1, rxd_claim_burial_s=50_000, rxd_confirm_slack_s=50_000)
        with pytest.raises(ValidationError, match="leaves too little time to claim"):
            _claimable(self.FLOOR, rxd_claim_burial_s=0, rxd_confirm_slack_s=0)

    @pytest.mark.parametrize("field", ["eth_reorg_finality_s", "eth_finality_stall_tolerance_s", "rounding_slack_s"])
    def test_each_component_counts_in_full(self, field: str) -> None:
        """One more second in any of the three components moves the floor by exactly one second."""
        bumped = {
            field: dict(eth_reorg_finality_s=768, eth_finality_stall_tolerance_s=3600, rounding_slack_s=300)[field] + 1
        }
        _claimable(self.FLOOR + 2, **bumped)
        with pytest.raises(ValidationError, match="leaves too little time to claim"):
            _claimable(self.FLOOR + 1, **bumped)

    def test_an_already_expired_deadline_is_refused_and_says_so(self) -> None:
        """`eth_timeout % now` equals `eth_timeout - now` whenever `now <= eth_timeout < 2 * now`,
        which is every realistic future deadline, so only a PAST deadline separates them — and a
        past deadline is the case that must never fund."""
        with pytest.raises(ValidationError, match=r"ALREADY EXPIRED"):
            _claimable(-1)
        with pytest.raises(ValidationError, match=r"ALREADY EXPIRED"):
            _claimable(-86_400)

    def test_zero_seconds_left_is_EXPIRED(self) -> None:
        """`block.timestamp >= timeout` reverts, so a deadline equal to `now` is already dead, and
        the label is the operator's only way to tell "dead swap" from "tight window"."""
        with pytest.raises(ValidationError, match=r"ALREADY EXPIRED"):
            _claimable(0)

    def test_zero_seconds_left_is_refused_even_with_an_ALL_ZERO_margin(self) -> None:
        """The first defect in its sharpest form. With every component zero the old check was
        `0 < 0`, false, so a deadline equal to `now` was ACCEPTED — a leg the contract had already
        expired. Real-value mode forbids this margin (stall >= 3600 s); dust and test runs do not."""
        zero = dict(eth_reorg_finality_s=0, eth_finality_stall_tolerance_s=0, rounding_slack_s=0)
        with pytest.raises(ValidationError, match=r"ALREADY EXPIRED"):
            _claimable(0, **zero)

    def test_one_second_left_is_refused_below_the_budget_but_not_called_expired(self) -> None:
        """`remaining == 1` is live on the contract (a claim mined in the next second succeeds), but
        it is below the inclusion budget even with an all-zero margin, so it is refused as TIGHT."""
        zero = dict(eth_reorg_finality_s=0, eth_finality_stall_tolerance_s=0, rounding_slack_s=0)
        with pytest.raises(ValidationError) as exc:
            _claimable(1, **zero)
        assert "leaves too little time to claim" in str(exc.value)
        assert "ALREADY EXPIRED" not in str(exc.value)

    def test_with_an_all_zero_margin_the_floor_is_the_inclusion_budget_alone(self) -> None:
        zero = dict(eth_reorg_finality_s=0, eth_finality_stall_tolerance_s=0, rounding_slack_s=0)
        with pytest.raises(ValidationError, match="leaves too little time to claim"):
            _claimable(96, **zero)
        _claimable(97, **zero)

    def test_a_close_but_FUTURE_deadline_is_not_called_expired(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _claimable(1)
        assert "ALREADY EXPIRED" not in str(exc.value)

    @pytest.mark.parametrize("remaining_s", [86_400, 12 * 3600, 4 * 3600])
    def test_the_honest_path_at_real_value_margins_still_passes(self, remaining_s: int) -> None:
        """Real-value mode requires `eth_finality_stall_tolerance_s >= 3600`
        (`MAINNET_ETH_FINALITY_STALL_FLOOR_S`); the runner's real run used an 86,400 s deadline.
        The fix must not refuse these — a guard refusing valid work is a bug too."""
        from pyrxd.gravity.swap_coordinator import MAINNET_ETH_FINALITY_STALL_FLOOR_S

        _claimable(remaining_s, eth_finality_stall_tolerance_s=MAINNET_ETH_FINALITY_STALL_FLOOR_S)
        _claimable(remaining_s, eth_finality_stall_tolerance_s=2 * MAINNET_ETH_FINALITY_STALL_FLOOR_S)


class TestTheCoordinatorRefusesTheBoundaryBeforeAnyLock:
    """The same boundary, through the PRODUCTION entry point: `SwapCoordinator.taker_funds_btc`.

    The class above calls `assert_eth_deadline_is_claimable` directly, so it proves the function
    and nothing about whether the taker's funding path still reaches it with the policy's margin.
    Before this class existed, removing the inclusion budget from the floor was caught ONLY by the
    direct tests; every coordinator test used a deadline 40,000 s out, far from any boundary.

    Margin: the same 768 + 3600 + 300 s to finality as `_margin()`, carried by the coordinator's
    `MarginPolicy.cross_clock_margin`, so the floor is 4764 s. `t_rxd` is 80 blocks at the
    fixtures' 300 s dividing interval (24,000 s), which clears `eth_timeout + total_s()` (at most
    4765 + 7068 s) with room to spare, so the ordering gate cannot be what refuses; only the
    deadline differs between the two cases.
    """

    FLOOR = 768 + 3600 + 300 + 96  # finality + stall + rounding + CLAIM_INCLUSION_BUDGET_S

    @staticmethod
    def _coordinator(remaining_s: int):
        from tests.test_swap_coordinator import _NOW as COORD_NOW
        from tests.test_swap_coordinator import (
            FakeEthLeg,
            FakeRadiantLeg,
            FakeSeenStore,
            _eth_coord_full,
            _eth_fund_policy,
            _eth_terms,
            _final,
            generate_secret,
        )

        secret, h = generate_secret()
        terms = _eth_terms(hashlock=h, eth_timeout_unix_s=COORD_NOW + remaining_s, t_rxd_blocks=80)
        leg = FakeEthLeg(preimage=secret, verdict=_final())
        seen = FakeSeenStore()
        coord = _eth_coord_full(
            terms=terms,
            eth_leg=leg,
            radiant_leg=FakeRadiantLeg(),
            seen_store=seen,
            policy=_eth_fund_policy(cross_clock_margin=_margin()),
        )
        return coord, terms, leg, seen, h, COORD_NOW

    async def test_a_deadline_AT_the_floor_is_refused_before_any_counter_leg_lock(self) -> None:
        from pyrxd.gravity.swap_state import SwapState

        coord, terms, leg, seen, h, now = self._coordinator(self.FLOOR)
        gate = await coord.pre_btc_lock_check(terms, now_unix_s=now)
        assert not gate.ok
        assert "leaves too little time to claim" in gate.reason and "claim inclusion 96s" in gate.reason

        with pytest.raises(ValidationError, match=r"pre-BTC-lock gate refused funding: .*claim inclusion 96s"):
            await coord.taker_funds_btc(terms, now_unix_s=now)
        assert "fund" not in leg.calls, "the counter leg was funded against a deadline the maker cannot claim"
        assert coord.record.state is SwapState.NEGOTIATED
        assert not seen.has_seen(h), "a refused gate must not burn H"

    async def test_one_second_past_the_floor_funds(self) -> None:
        """The paired honest path: the same wiring one second later must fund, or the refusal
        above could be any other gate failing."""
        from pyrxd.gravity.swap_state import SwapState

        coord, terms, leg, _seen, _h, now = self._coordinator(self.FLOOR + 1)
        gate = await coord.pre_btc_lock_check(terms, now_unix_s=now)
        assert gate.ok, gate.reason
        rec = await coord.taker_funds_btc(terms, now_unix_s=now)
        assert rec.state is SwapState.BTC_LOCKED
        assert "fund" in leg.calls


class TestTheGateSubtractsElapsedDepthExactly:
    """Killed mutants: `remaining_blocks = t_rxd.value - elapsed_blocks` -> `+`, `|`, `^`, `<<`,
    `>>`; `if elapsed_blocks < 0` -> `> 0`, `!= 0`, `< -1`.

    No test in this group ever passed a nonzero `elapsed_blocks`, so the term the #482 fix added —
    a maker locking its covenant early and presenting the swap late — was invisible to all of them.
    `t_rxd` is RELATIVE from covenant mining; each block already mined opens the refund one
    interval sooner.

    Fixture: interval 600 s, `t_rxd` 32. With two blocks already mined, 30 remain and the refund
    opens at exactly 18,000 s after `now`; the deadline is set so 18,000 is precisely what is
    required. A third mined block (17,400 s) must be refused. Every mutant differs from `-` on at
    least one of the two: at elapsed 3, `+` `|` `^` all give 35 and `<<` gives 256, each ACCEPTED
    where 29 is refused; at elapsed 2, `>>` gives 8, REFUSED where 30 is accepted.

    THE DEADLINE IS IN THE FUTURE. It was `now + 6000 - 7068`, i.e. already 1,068 s past, which
    the coordinator can never present to this gate: `assert_eth_deadline_is_claimable` runs first
    and refuses it. At `now + 10,932` (and `now + 12,132` for the zero-depth case) it clears that
    check, so these are states the production path can actually reach.
    """

    T_RXD = 32
    INTERVAL = 600.0

    def _gate(self, *, elapsed: int, required_open_s: int = 18_000) -> None:
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
        from pyrxd.gravity.eth_rxd_timelock import assert_covenant_confirms_before_eth_deadline

        margin = _margin()
        eth_timeout = _NOW + required_open_s - margin.total_s()
        _claimable(eth_timeout - _NOW)  # reachable: the coordinator's first check accepts it
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=_NOW,
            eth_timeout_unix_s=eth_timeout,
            margin=margin,
            t_rxd=Timelock(self.T_RXD, TimeUnit.BLOCKS),
            rxd_block_interval_s=self.INTERVAL,
            max_covenant_confirm_wait_s=0,
            elapsed_blocks=elapsed,
        )

    def test_the_remaining_window_exactly_at_the_requirement_is_ACCEPTED(self) -> None:
        """Honest path: a covenant with some depth that still clears the deadline plus margin."""
        self._gate(elapsed=2)

    def test_one_more_mined_block_is_REFUSED(self) -> None:
        """The #482 direction: the maker's early lock has eaten into the taker's window."""
        with pytest.raises(ValidationError, match="open too EARLY"):
            self._gate(elapsed=3)

    def test_the_refusal_names_the_blocks_actually_left(self) -> None:
        with pytest.raises(ValidationError, match=r"\(29 blk left of 32\)"):
            self._gate(elapsed=3)

    def test_zero_depth_is_the_full_window(self) -> None:
        self._gate(elapsed=0, required_open_s=19_200)
        with pytest.raises(ValidationError, match="open too EARLY"):
            self._gate(elapsed=0, required_open_s=19_201)

    @pytest.mark.parametrize("bad", [-1, -2, -12])
    def test_negative_depth_is_refused(self, bad: int) -> None:
        """A negative depth would LENGTHEN the projected window — the optimistic direction."""
        with pytest.raises(ValidationError, match="elapsed_blocks cannot be negative"):
            self._gate(elapsed=bad)


class TestTheGateRefusesNonsenseInputsWithTheRightReason:
    """Killed mutants: the gate's `rxd_block_interval_s <= 0` -> `== 0` / `< 0` / `<= -1`;
    `max_covenant_confirm_wait_s` bool guard `or` -> `and`; `max_covenant_confirm_wait_s < 0` ->
    `< -1`.

    Only the SIZER's copy of the interval guard was tested. The gate is called on its own by the
    coordinator with a negotiated `t_rxd`, so its guard is the only one on that path. A zero or
    negative interval projects the refund at or before `now`; under every mutant that is refused
    anyway, but as "open too EARLY", which tells the operator the window is short when the real
    fault is the interval they passed. The `match=` is what separates the two.
    """

    def _gate(self, **overrides) -> None:
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
        from pyrxd.gravity.eth_rxd_timelock import assert_covenant_confirms_before_eth_deadline

        kw = dict(
            now_unix_s=_NOW,
            # A deadline a day out, which `assert_eth_deadline_is_claimable` accepts. It was `_NOW`,
            # a deadline the contract has already expired and the coordinator never gets this far with.
            eth_timeout_unix_s=_NOW + 86_400,
            margin=_margin(),
            t_rxd=Timelock(10_000, TimeUnit.BLOCKS),
            rxd_block_interval_s=36.0,
            max_covenant_confirm_wait_s=0,
        )
        kw.update(overrides)
        assert_covenant_confirms_before_eth_deadline(**kw)

    def test_the_fixture_is_accepted(self) -> None:
        """Honest path for every refusal below: only the named input differs."""
        self._gate()
        self._gate(max_covenant_confirm_wait_s=600)

    @pytest.mark.parametrize("interval", [0.0, -0.5, -1.0, -36.0])
    def test_a_non_positive_interval_is_refused_as_an_interval_error(self, interval: float) -> None:
        with pytest.raises(ValidationError, match=r"rxd_block_interval_s must be > 0"):
            self._gate(rxd_block_interval_s=interval)

    @pytest.mark.parametrize("bad", [True, False, 1.5, "600"])
    def test_a_non_int_confirm_wait_is_refused(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="max_covenant_confirm_wait_s must be int"):
            self._gate(max_covenant_confirm_wait_s=bad)

    @pytest.mark.parametrize("bad", [-1, -600])
    def test_a_negative_confirm_wait_is_refused(self, bad: int) -> None:
        with pytest.raises(ValidationError, match="max_covenant_confirm_wait_s must be >= 0"):
            self._gate(max_covenant_confirm_wait_s=bad)


class TestIntegerSecondsAreRequiredOnEveryEntryPoint:
    """Killed mutant: `_require_int`'s `not isinstance(v, int) or isinstance(v, bool)` -> `and`.

    Under the mutant a bool or a float passes. `True` is then the unix time 1 — a deadline in
    1970 — and a float timestamp silently enters the ceil arithmetic. Either may still be refused
    downstream for a DIFFERENT reason (no budget, too early), which is why each test matches the
    type error specifically.
    """

    @pytest.mark.parametrize("bad", [True, 1_700_086_400.0])
    def test_the_sizer_refuses_a_non_int_deadline(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="eth_timeout_unix_s must be int seconds"):
            eth_absolute_to_rxd_relative_blocks(
                eth_timeout_unix_s=bad, expected_rxd_lock_time_unix_s=_NOW, margin=_margin(), rxd_block_interval_s=36.0
            )

    @pytest.mark.parametrize("bad", [False, float(_NOW)])
    def test_the_sizer_refuses_a_non_int_lock_time(self, bad: object) -> None:
        with pytest.raises(ValidationError, match="expected_rxd_lock_time_unix_s must be int seconds"):
            eth_absolute_to_rxd_relative_blocks(
                eth_timeout_unix_s=_NOW + 86_400,
                expected_rxd_lock_time_unix_s=bad,
                margin=_margin(),
                rxd_block_interval_s=36.0,
            )

    @pytest.mark.parametrize("field", ["now_unix_s", "eth_timeout_unix_s", "elapsed_blocks"])
    @pytest.mark.parametrize("bad", [True, 2.0])
    def test_the_gate_refuses_non_int_times(self, field: str, bad: object) -> None:
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
        from pyrxd.gravity.eth_rxd_timelock import assert_covenant_confirms_before_eth_deadline

        kw = dict(now_unix_s=_NOW, eth_timeout_unix_s=_NOW + 86_400, elapsed_blocks=0)
        kw[field] = bad
        with pytest.raises(ValidationError, match=f"{field} must be int seconds"):
            assert_covenant_confirms_before_eth_deadline(
                margin=_margin(),
                t_rxd=Timelock(10_000, TimeUnit.BLOCKS),
                rxd_block_interval_s=36.0,
                max_covenant_confirm_wait_s=0,
                **kw,
            )

    @pytest.mark.parametrize("field", ["now_unix_s", "eth_timeout_unix_s"])
    @pytest.mark.parametrize("bad", [True, 2.0])
    def test_the_claimable_check_refuses_non_int_times(self, field: str, bad: object) -> None:
        from pyrxd.gravity.eth_rxd_timelock import assert_eth_deadline_is_claimable

        kw = dict(now_unix_s=_NOW, eth_timeout_unix_s=_NOW + 86_400)
        kw[field] = bad
        with pytest.raises(ValidationError, match=f"{field} must be int seconds"):
            assert_eth_deadline_is_claimable(margin=_margin(), **kw)


class TestANegativeBudgetIsRefusedAsNoBudget:
    """Killed mutant: `if budget_s <= 0` -> `== 0`.

    The existing test covers a budget of exactly zero. A NEGATIVE one — the RXD lock is already
    past the ETH deadline plus the margin — slips past `== 0`, sizes to a negative block count and
    is then refused by the safety floor, whose message tells the operator to lengthen a window that
    cannot exist at all.
    """

    @pytest.mark.parametrize("budget", [-1, -86_400])
    def test_a_negative_budget_is_refused_as_no_budget(self, budget: int) -> None:
        with pytest.raises(ValidationError, match="no RXD timelock budget"):
            _size_for_budget(budget, 36.0, lock_delay=0)


class TestTheSuppliedTRxdCheck:
    """Killed mutants: `assert_t_rxd_fits_the_eth_deadline`'s own `floor_blocks: int = 12` -> 11 /
    13, and its unit guard `or` -> `and`.

    The sizer's default floor is pinned above, but this function carries a SEPARATE default and
    passes it through; `eth_swap_two_host.py` calls it without one. At 11 the check would accept an
    11-block window the design calls unsafe; at 13 it would refuse the 12 the sizer emits.

    The unit guard: under `and`, a SECONDS Timelock skips the check and its raw `.value` is then
    compared as if it were blocks — 20,480 seconds read as 20,480 blocks.
    """

    @staticmethod
    def _fits(t_rxd, budget_s: int, interval: float = 60.0, lock_delay: int = 600) -> None:
        from pyrxd.gravity.eth_rxd_timelock import assert_t_rxd_fits_the_eth_deadline

        assert_t_rxd_fits_the_eth_deadline(
            t_rxd=t_rxd,
            eth_timeout_unix_s=_NOW + budget_s - _margin().total_s() + lock_delay,
            expected_rxd_lock_time_unix_s=_NOW + lock_delay,
            margin=_margin(),
            rxd_block_interval_s=interval,
        )

    def test_the_default_floor_admits_exactly_twelve(self) -> None:
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit

        # 661 s at 60 s/block is the first budget the sizer turns into 12 (measured above).
        self._fits(Timelock(12, TimeUnit.BLOCKS), 661)

    def test_the_default_floor_refuses_a_budget_worth_eleven(self) -> None:
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit

        with pytest.raises(ValidationError, match="below safety floor 12"):
            self._fits(Timelock(11, TimeUnit.BLOCKS), 660)

    def test_a_SECONDS_timelock_is_refused_not_read_as_blocks(self) -> None:
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit

        with pytest.raises(ValidationError, match="t_rxd must be a BLOCKS Timelock"):
            self._fits(Timelock(20_480, TimeUnit.SECONDS), 661)

    def test_a_non_Timelock_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="t_rxd must be a BLOCKS Timelock"):
            self._fits(20_480, 661)

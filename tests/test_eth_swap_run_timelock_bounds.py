"""The runner's parse-time t_rxd bounds, which decide a real swap's safety before it spends a fee.

Every defect pinned here was found by an adversarial review of the PREVIOUS round's fixes, and all
of them share a shape: a bound that checks the wrong quantity still looks like a bound. It refuses
things, its message is specific, and it is measuring something that is not the swap being run.
"""

from __future__ import annotations

import argparse
import importlib.util
import math
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


@pytest.fixture(scope="module")
def runner():
    sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location("eth_swap_run_bounds", _SCRIPTS / "eth_swap_run.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(_SCRIPTS))


def _ns(**kw) -> argparse.Namespace:
    """The arguments the bounds read. A real-value token leg, since that is what they gate."""
    base = dict(
        eth_timeout_s=86_400,
        t_rxd_blocks=0,
        rxd_block_interval_s=300.0,
        rxd_block_interval_fast_s=36.0,
        max_covenant_confirm_wait_s=600,
        eth_finalization_window_s=768,
        rxd_claim_burial_s=1800,
        rxd_confirm_slack_s=600,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=3600,
        maker_stall_safety_window_blocks=30,
        margin_blocks=240,
        btc_block_interval_s=600.0,
    )
    base.update(kw)
    # A p10 cannot be SLOWER than the nominal interval; MarginPolicy refuses the pair outright as
    # "the two are swapped". Keeping the nominal above the fast tail keeps every fixture here a
    # situation the chain can actually be in — caught the moment these tests started driving the
    # real `_policy` instead of a hand-copied imitation of it, on the 331.7s row.
    if "rxd_block_interval_s" not in kw:
        base["rxd_block_interval_s"] = max(base["rxd_block_interval_s"], float(base["rxd_block_interval_fast_s"]))
    return argparse.Namespace(**base)


#: (fast_interval_s, eth_timeout_s, confirm_wait_s) triples on which the PRE-FIX arithmetic
#: `ceil(budget/interval) - 1` emits a t_rxd the punctuality gate refuses. Found by brute force,
#: one representative row per interval out of 163.
#:
#: These are here because the first version of this test fixed eth_timeout at 86_400 and swept only
#: the interval — and 86_400 appears in NONE of the 163. The test asserted exactly the right
#: property, on inputs where the defect it describes cannot occur, and passed with the fix removed.
#: An assertion is only load-bearing on inputs that can break it.
_GATE_DISAGREEMENT_ROWS = [
    (36.2, 48600, 300),
    (36.4, 47400, 0),
    (36.5, 45000, 300),
    (36.7, 49200, 0),
    (43.3, 57600, 0),
    (60.5, 73800, 0),
    (331.7, 109200, 300),
    (41.618, 44400, 0),
]


def _sized_and_gate(fast: float, eth_timeout_s: int, wait: int):
    """Size at these parameters and return (sized_value, accepts) against the real gate."""
    import pyrxd.btc_wallet.taproot as bt
    from pyrxd.gravity.eth_rxd_timelock import (
        CrossClockMargin,
        assert_covenant_confirms_before_eth_deadline,
        eth_absolute_to_rxd_relative_blocks,
    )

    now = 1_700_000_000
    margin = CrossClockMargin(
        eth_reorg_finality_s=768,
        rxd_claim_burial_s=1800,
        rxd_confirm_slack_s=600,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=3600,
    )
    sized = eth_absolute_to_rxd_relative_blocks(
        eth_timeout_unix_s=now + eth_timeout_s,
        expected_rxd_lock_time_unix_s=now + wait,
        margin=margin,
        rxd_block_interval_s=fast,
    ).value

    def accepts(t: int) -> bool:
        try:
            assert_covenant_confirms_before_eth_deadline(
                # Anchored at the LOCK time with a zero wait, matching the sizer above. The gate
                # used to ADD the wait to `now`, making the two the same instant; #482 removed
                # that term (it assumes a LATE confirm, the optimistic direction), so the anchors
                # have to be written alike to stay alike.
                now_unix_s=now + wait,
                eth_timeout_unix_s=now + eth_timeout_s,
                margin=margin,
                t_rxd=bt.Timelock(t, bt.TimeUnit.BLOCKS),
                rxd_block_interval_s=fast,
                max_covenant_confirm_wait_s=0,
            )
            return True
        except Exception:
            return False

    return sized, accepts


class TestNonIntegerIntervalsAreSizedCorrectly:
    """L-11. `ceil(x) - 1` is algebraically right and NOT right in floating point once the interval
    has a fractional part: both sides round differently, and the sizer emitted values its own gate
    refused on 0.27-2.74% of parameter rows at 36.2/36.4/36.5/36.7/43.3/60.5/331.7 s while being
    perfect at 9/20/36/43/60/120/300 s.

    `--rxd-block-interval-fast-s` is a float and a MEASURED p10 almost never lands on an integer,
    so the broken set is the normal case. The live run used 36 only because the measurement was
    rounded before it was typed.

    The fix is not better arithmetic — it is that the sizer now ASKS the gate, so the two agree by
    construction at any interval.
    """

    @pytest.mark.parametrize("fast,eth_timeout_s,wait", _GATE_DISAGREEMENT_ROWS)
    def test_the_rows_where_the_OLD_arithmetic_was_refused(self, fast: float, eth_timeout_s: int, wait: int) -> None:
        sized, accepts = _sized_and_gate(fast, eth_timeout_s, wait)
        # The margin is ADDED and there is no `- 1` since #482 — this reproduces the OLD
        # arithmetic's mistake against the NEW budget, which is what makes the row a defect
        # demonstration rather than an arbitrary number.
        naive = math.ceil((eth_timeout_s + 7068 - wait) / fast) - 1
        assert not accepts(naive), (
            f"this row no longer reproduces the defect: the naive value {naive} is accepted at "
            f"fast={fast}, so it cannot demonstrate anything"
        )
        assert accepts(sized), f"gate refused the sizer's own output {sized} at {fast}s"
        assert sized == naive + 1, f"expected the sizer to step UP from {naive}, got {sized}"

    @pytest.mark.parametrize(
        "fast", [9.0, 20.0, 36.0, 43.0, 60.0, 120.0, 300.0, 36.2, 36.4, 36.5, 36.7, 43.3, 60.5, 331.7, 41.618]
    )
    @pytest.mark.parametrize("eth_timeout_s", [45_000, 48_600, 57_600, 86_400, 109_200])
    def test_the_gate_accepts_the_sized_value_across_the_grid(self, fast: float, eth_timeout_s: int) -> None:
        """Breadth alongside the pinned rows: a fix tailored to eight known triples would satisfy
        the class above and fail here."""
        for wait in (0, 300, 600, 900, 1200):
            sized, accepts = _sized_and_gate(fast, eth_timeout_s, wait)
            assert accepts(sized), f"gate refused sized={sized} at fast={fast}, eth={eth_timeout_s}, wait={wait}"
            assert not accepts(sized - 1), (
                f"t_rxd={sized - 1} also accepted at fast={fast}, eth={eth_timeout_s}, wait={wait} "
                "— the maker's asset locked a block longer than the deadline requires (#482 moved "
                "the give-away from the taker's window to the maker's lock)"
            )


class TestAResumeIsBoundedByWhatIsLEFT:
    """L-12. `--eth-timeout-s` is a DURATION from now. On a resume the deadline is an immutable of
    the deployed HTLC, fixed hours ago, and the only budget is what remains of it. The bounds
    divided the original duration, so they accepted a t_rxd the coordinator then refused mid-run —
    after funding, which is exactly when a refusal costs something.
    """

    def test_the_bound_shrinks_as_the_deadline_approaches(self, runner) -> None:
        full = runner._derive_t_rxd_blocks(_ns())
        half = runner._derive_t_rxd_blocks(_ns(), remaining_s=43_200)
        assert half < full, (
            f"with half the deadline left the derived window is still {half} (was {full}) — the "
            "bound is dividing the original duration, not what remains"
        )

    def test_a_value_valid_at_the_start_is_refused_once_too_little_remains(self, runner) -> None:
        at_start = runner._derive_t_rxd_blocks(_ns())
        with pytest.raises(SystemExit):
            runner._assert_t_rxd_outlasts_the_eth_deadline(_ns(t_rxd_blocks=at_start), remaining_s=43_200)

    def test_the_honest_resume_still_passes(self, runner) -> None:
        """Paired, because a bound that refuses every resume strands funds it was meant to save."""
        remaining = 43_200
        derived = runner._derive_t_rxd_blocks(_ns(), remaining_s=remaining)
        runner._assert_t_rxd_outlasts_the_eth_deadline(_ns(t_rxd_blocks=derived), remaining_s=remaining)
        runner._assert_t_rxd_bounds_the_vulnerable_window(_ns(t_rxd_blocks=derived), remaining_s=remaining)


class TestAnImpossibleDeadlineNamesTheRightArgument:
    """L-13, WITH ITS DIRECTION INVERTED BY #482 — which is the whole finding here.

    The original: a 3 h deadline refused t_rxd=86 as "too SHORT" while advising the operator to
    omit the flag and let it derive, which derives 86. Self-contradictory, and it pointed at the
    one argument that could not help. The rule was "the deadline must hold roughly two margins plus
    the reserve", because bound B capped t_rxd from above and the floors pushed from below.

    Under the corrected relation bound B is a FLOOR: `t_rxd >= ceil((budget + margin) / fast)`,
    which RISES with the deadline, and the only ceiling left is the BIP68 field width. So:

      - a SHORT deadline is always satisfiable. 3 h yields a feasible (497, 65535) — the exact
        case this class was written about is no longer a failure at all.
      - what cannot be satisfied is a deadline too FAR: past roughly 23 days no 16-bit relative
        CSV reaches it.

    The remedy inverts with it. Asking for more time was the fix; it is now the cause, and a search
    that walked upward would have advised an operator to lengthen a deadline already too long.
    """

    #: Past the BIP68 reach at the default 36s fast tail. Measured, not estimated: 2_000_000 still
    #: yields (55752, 65535) and 2_400_000 yields None.
    _TOO_FAR_S = 2_400_000

    def test_a_too_FAR_deadline_refuses_before_any_t_rxd_advice(self, runner) -> None:
        with pytest.raises(SystemExit, match="cannot hold the timelock at all"):
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=self._TOO_FAR_S))

    def test_the_deadline_that_USED_to_be_impossible_is_now_fine(self, runner) -> None:
        """The paired honest path, and the strongest single statement of what #482 changed.

        3 h is the deadline from the live incident this class records. It was infeasible, the
        refusal contradicted itself, and two funded covenants were burned on it. It now has a
        feasible set and the whole parse-time pipeline accepts the derived value.
        """
        args = _ns(eth_timeout_s=10_800)
        runner._assert_the_eth_deadline_can_hold_the_margins(args)
        args.t_rxd_blocks = runner._recommended_t_rxd_blocks(args)
        _run_the_whole_parse_time_pipeline(runner, args)

    def test_it_names_eth_timeout_and_not_t_rxd(self, runner) -> None:
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=self._TOO_FAR_S))
        msg = str(exc.value)
        assert "--eth-timeout-s" in msg
        assert "--t-rxd-blocks" not in msg.split("no --t-rxd-blocks satisfies all three bounds")[-1], (
            "the remedy must not point at --t-rxd-blocks; no value of it can help"
        )

    def test_the_maximum_it_advertises_actually_WORKS(self, runner) -> None:
        """The advice has to be true. A refusal naming a bound that is itself refused is how the
        live run burned two funded covenants."""
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=self._TOO_FAR_S))
        msg = str(exc.value)
        # NOT a skip. The search starts from the analytic BIP68 boundary rather than walking down
        # from the requested value, so a workable maximum always exists at fast > 0 — and a skip
        # here would hide the search failing to find one, which is the defect this test is for.
        assert "maximum: --eth-timeout-s " in msg, f"the refusal named no workable maximum:\n{msg}"
        maximum = int(msg.split("maximum: --eth-timeout-s ")[1].split()[0])
        runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=maximum))
        derived = runner._derive_t_rxd_blocks(_ns(eth_timeout_s=maximum))
        args = _ns(eth_timeout_s=maximum, t_rxd_blocks=derived)
        runner._assert_t_rxd_covers_the_takers_wait(args)
        runner._assert_t_rxd_outlasts_the_eth_deadline(args)
        runner._assert_t_rxd_bounds_the_vulnerable_window(args)

    def test_one_second_ABOVE_the_maximum_is_still_refused(self, runner) -> None:
        """Pins the boundary rather than the direction, so a maximum that drifts down to be safely
        wrong fails here."""
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=self._TOO_FAR_S))
        msg = str(exc.value)
        # NOT a skip. The search starts from the analytic BIP68 boundary rather than walking down
        # from the requested value, so a workable maximum always exists at fast > 0 — and a skip
        # here would hide the search failing to find one, which is the defect this test is for.
        assert "maximum: --eth-timeout-s " in msg, f"the refusal named no workable maximum:\n{msg}"
        maximum = int(msg.split("maximum: --eth-timeout-s ")[1].split()[0])
        with pytest.raises(SystemExit, match="cannot hold"):
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=maximum + 1))

    def test_a_normal_24h_deadline_is_untouched(self, runner) -> None:
        runner._assert_the_eth_deadline_can_hold_the_margins(_ns())


class TestResumeCannotSilentlyLookLikeAFreshRun:
    """L-14. `resolve_eth_timeout` branches on `restore is None` where the original branched on
    `args.resume`. Those agree only while `_load_restore` cannot return None for a resume — so pin
    that, rather than trusting two conditions to stay equivalent. Getting it wrong re-times the
    swap against a deadline the deployed contract does not agree with.
    """

    def test_a_resume_whose_file_is_unreadable_RAISES_rather_than_returning_None(self, runner, tmp_path) -> None:
        args = _ns(resume=True, keys_out=str(tmp_path / "absent.json"))
        with pytest.raises(SystemExit, match="cannot open"):
            runner._load_restore(args)

    def test_a_fresh_run_takes_the_clock_and_a_resume_takes_the_RECORD(self, runner) -> None:
        now = 1_700_000_000
        assert runner.resolve_eth_timeout(None, now_unix_s=now, eth_timeout_s=86_400) == now + 86_400
        recorded = now - 7_000 + 86_400
        assert (
            runner.resolve_eth_timeout({"eth_timeout_unix_s": recorded}, now_unix_s=now, eth_timeout_s=86_400)
            == recorded
        ), "a resume recomputed its deadline from the clock, re-timing a contract that cannot be re-timed"


def test_the_derivation_matches_what_the_bounds_demand(runner) -> None:
    """The whole point of deriving: the value handed back must satisfy every bound that checks it.
    `eth_absolute_to_rxd_relative_blocks` shipped correct and UNCALLED for the life of this
    corridor while the runner took a hand-typed default of 60."""
    for eth_timeout_s in (43_200, 86_400, 129_600, 172_800):
        args = _ns(eth_timeout_s=eth_timeout_s)
        runner._assert_the_eth_deadline_can_hold_the_margins(args)
        args.t_rxd_blocks = runner._derive_t_rxd_blocks(args)
        runner._assert_t_rxd_covers_the_takers_wait(args)
        runner._assert_t_rxd_outlasts_the_eth_deadline(args)
        runner._assert_t_rxd_bounds_the_vulnerable_window(args)
        assert args.t_rxd_blocks < math.ceil(eth_timeout_s / 36.0)


#: (fast_interval_s, eth_timeout_s, stall_s, confirm_wait_s) rows on which the PRE-FIX deadline
#: guard — the loose sum ``2 * margin + wait + ceil(fast)`` — PASSED while the integer feasible set
#: was EMPTY, so the operator was refused a value and then advised to use that same value.
#:
#: Every row has a FRACTIONAL fast tail, and that is the point. Bound B caps t_rxd at
#: ``ceil((budget - margin - wait)/fast) - 1`` and bound C floors it at the algebraically IDENTICAL
#: integer; in binary floating point the two expressions round at different places and land one
#: apart. Measured over 4000 random rows each: 0 empty sets at 9/20/36/43/60/120/300 s, 3 at
#: 36.2/36.4/36.5/36.7/43.3/55.9/60.5/22.7/331.7/41.618 s. An integer-only sweep CANNOT see this
#: defect, which is exactly why the loose sum shipped — so these rows are pinned by value and each
#: test re-asserts that its row still reproduces, rather than trusting that it does.
_EMPTY_FEASIBLE_SET_ROWS = [
    (36.4, 92_298, 3600, 600),
    (55.9, 83_692, 3600, 600),
    (43.3, 43_310, 7200, 600),
]


def _pre_fix_loose_sum_passes(runner, args) -> bool:
    """The closed form the guard used BEFORE the fix.

    Kept so each row can assert it is a row where that sum was WRONG. If a margin default changes
    and the sum starts refusing these rows, the assertion fails loudly instead of passing vacuously
    on inputs that no longer bite.
    """
    margin_s = runner._cross_clock_margin(args).total_s()
    need_s = 2 * margin_s + int(args.max_covenant_confirm_wait_s) + math.ceil(float(args.rxd_block_interval_fast_s))
    return int(args.eth_timeout_s) >= need_s


def _run_the_whole_parse_time_pipeline(runner, args) -> None:
    """Drive the REAL production entry point, ``_policy``, not a hand-copied imitation of it.

    An earlier version of this helper restated ``_policy``'s sequence inline. It then went on
    passing after ``_policy`` changed which sizing function it calls — testing the mechanism while
    the shipped path did something else. A copy of a call sequence is not the call sequence.
    """
    args.counter_asset = "usdc"
    args.eth_chain_id = 1  # a value-bearing EVM: the branch where every bound is enforced
    runner._policy(args)


class TestTheFeasibilityCheckIsTheSetAndNotASum:
    """L-15. The guard added to stop self-contradictory refusals reintroduced one.

    It modelled the feasible set as ``2 * margin + wait + ceil(fast)`` — a loose SUM that does not
    represent the ~one-block gap between bound B\'s cap and bound C\'s floor. At a fractional fast
    tail (a MEASURED p10 — the normal case) the two round one apart, the integer set is EMPTY, and
    the sum says the deadline is roomy. The operator then gets, verbatim,
    ``--t-rxd-blocks 2324 leaves a 1.97 h ASSET_VULNERABLE window`` with
    ``OMIT --t-rxd-blocks entirely and it is derived: 2324`` as the remedy: refusing 2324 while
    recommending 2324, the exact contradiction the guard exists to eliminate, and the one the
    commit says burned two funded covenants.
    """

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _EMPTY_FEASIBLE_SET_ROWS)
    def test_every_historically_EMPTY_row_now_has_a_feasible_set(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """THE DEFECT CLASS IS GONE BY CONSTRUCTION, NOT BY A BETTER GUARD (#482).

        These rows are the brute-forced parameter sets on which the feasible set was EMPTY: bound
        B capped t_rxd from above, bound C floored it from below, the two were algebraically the
        same integer and rounded one apart at a fractional fast tail, and the operator was refused
        a value while being advised it. Two funded covenants were burned on that.

        Inverting the relation moved bound B to the FLOOR side. Every bound is a floor now and the
        only ceiling is the BIP68 field width, so `[max(floors), 65535]` cannot be emptied by two
        bounds disagreeing about a rounding — there is nothing left to disagree. Each of these rows
        now yields a healthy range.

        Asserting this on the ORIGINAL rows is the point: it is evidence the specific inputs that
        broke are fixed, which a fresh property test over new parameters would not give. If a
        future change reintroduces a ceiling below the cap, these go red first.
        """
        args = _ns(
            rxd_block_interval_fast_s=fast,
            eth_timeout_s=eth_timeout_s,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        rng = runner._t_rxd_feasible_range(args)
        assert rng is not None, f"row fast={fast} eth={eth_timeout_s} still has an empty feasible set"
        lo, hi = rng
        assert lo <= hi
        assert hi == runner._T_RXD_BIP68_MAX_BLOCKS, (
            f"the feasible set is capped at {hi}, below the BIP68 maximum. A ceiling other than the "
            "field width has come back, and with it the empty-set class this row records."
        )

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _EMPTY_FEASIBLE_SET_ROWS)
    def test_the_pipeline_accepts_the_derived_value_on_every_such_row(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """The honest path these rows could not previously have: derive, then run the whole
        parse-time pipeline over the derived value and require it to PASS.

        This is the assertion the old suite could not make. When the set was empty the best it
        could check was that the refusal did not contradict itself — a property about the wording
        of a failure. There is a correct answer on these parameters now, so the test asks for it.
        """
        args = _ns(
            rxd_block_interval_fast_s=fast,
            eth_timeout_s=eth_timeout_s,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        args.t_rxd_blocks = runner._recommended_t_rxd_blocks(args)
        _run_the_whole_parse_time_pipeline(runner, args)  # must not raise
        lo, hi = runner._t_rxd_feasible_range(args)
        assert lo <= args.t_rxd_blocks <= hi

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _EMPTY_FEASIBLE_SET_ROWS)
    def test_the_minimum_it_names_is_reached_by_the_whole_pipeline(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """Honest path. A refusal that leaves the operator with no correct action IS the defect;
        the remedy has to survive the derivation AND all three bounds."""
        base = dict(
            rxd_block_interval_fast_s=fast,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=eth_timeout_s, **base))
        minimum = int(str(exc.value).split("minimum: --eth-timeout-s ")[1].split()[0])
        _run_the_whole_parse_time_pipeline(runner, _ns(eth_timeout_s=minimum, **base))

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _EMPTY_FEASIBLE_SET_ROWS)
    def test_the_minimum_is_actually_minimAL(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        base = dict(
            rxd_block_interval_fast_s=fast,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=eth_timeout_s, **base))
        minimum = int(str(exc.value).split("minimum: --eth-timeout-s ")[1].split()[0])
        with pytest.raises(SystemExit, match="cannot hold"):
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=minimum - 1, **base))

    @pytest.mark.parametrize("fast", [36.2, 36.4, 36.5, 36.7, 43.3, 55.9, 60.5, 22.7, 331.7, 41.618, 9.7, 128.3])
    def test_a_FRACTIONAL_sweep_never_clears_a_deadline_the_bounds_then_refuse(self, runner, fast: float) -> None:
        """Breadth, on fractional intervals ONLY. The equivalent sweep at INTEGER intervals passes
        with the fix reverted — that is precisely how this shipped — so the sweep that matters is
        this one. If the guard clears a deadline, the derivation and all three bounds must succeed.
        """
        for eth_timeout_s in range(40_000, 172_800, 1_237):
            for wait in (0, 600, 1200):
                args = _ns(
                    rxd_block_interval_fast_s=fast, eth_timeout_s=eth_timeout_s, max_covenant_confirm_wait_s=wait
                )
                try:
                    runner._assert_the_eth_deadline_can_hold_the_margins(args)
                except SystemExit:
                    continue
                _run_the_whole_parse_time_pipeline(runner, args)

    def test_an_INTEGER_interval_deadline_is_still_accepted(self, runner) -> None:
        """Paired honest path: the fix must not start refusing the parameterisation that always
        worked. A feasibility check that refuses everything satisfies every refusal test above."""
        for fast in (9.0, 20.0, 36.0, 43.0, 60.0, 120.0, 300.0):
            _run_the_whole_parse_time_pipeline(runner, _ns(rxd_block_interval_fast_s=fast, eth_timeout_s=86_400))

    def test_the_feasible_range_is_exactly_the_values_the_bounds_accept(self, runner) -> None:
        """The range is not a MODEL of the bounds; it must BE them. Brute-forced against the real
        bound functions across the neighbourhood of the range."""
        for fast in (36.0, 36.4, 43.3, 55.9):
            args = _ns(rxd_block_interval_fast_s=fast, eth_timeout_s=86_400)
            window = runner._t_rxd_feasible_range(args)
            assert window is not None
            lo, hi = window
            for t in range(max(1, lo - 3), hi + 4):
                probe = _ns(rxd_block_interval_fast_s=fast, eth_timeout_s=86_400, t_rxd_blocks=t)
                accepted = True
                try:
                    runner._assert_t_rxd_covers_the_takers_wait(probe)
                    runner._assert_t_rxd_outlasts_the_eth_deadline(probe)
                    runner._assert_t_rxd_bounds_the_vulnerable_window(probe)
                except SystemExit:
                    accepted = False
                assert accepted == (lo <= t <= hi), (
                    f"fast={fast} t={t}: bounds say accepted={accepted}, range says {lo}..{hi}"
                )


class TestTheTwoBoundsWhoseREFUSALHadNeverRun:
    """L-16. ``_assert_t_rxd_bounds_the_vulnerable_window`` and
    ``_assert_t_rxd_covers_the_takers_wait`` were reachable only from tests that handed them an
    ALREADY-DERIVED (hence compliant) value. Replacing either body with a bare ``return`` left all
    94 tests green: the refusal branch — the entire reason each exists — had never executed.

    These drive each refusal directly, from the wrong side of its own bound, and pair it with the
    honest value so a bound that refuses everything cannot pass either.
    """

    def test_a_t_rxd_below_the_takers_wait_is_REFUSED(self, runner) -> None:
        floor_blocks = math.ceil(7068 / 36.0)
        with pytest.raises(SystemExit, match="too SHORT for a real-value run"):
            runner._assert_t_rxd_covers_the_takers_wait(_ns(t_rxd_blocks=floor_blocks - 1))

    def test_the_takers_wait_bound_ACCEPTS_the_value_one_higher(self, runner) -> None:
        """Paired honest path, and it pins the exact boundary: a floor that drifts up by one to be
        \'safely wrong\' fails here rather than quietly costing the maker liveness."""
        runner._assert_t_rxd_covers_the_takers_wait(_ns(t_rxd_blocks=math.ceil(7068 / 36.0)))

    def test_the_takers_wait_refusal_names_the_margin_it_could_not_cover(self, runner) -> None:
        """A refusal that does not say WHICH quantity was short sends the operator guessing during
        a run. Pins the message\'s load-bearing content, not merely that it raised."""
        with pytest.raises(SystemExit) as exc:
            runner._assert_t_rxd_covers_the_takers_wait(_ns(t_rxd_blocks=12))
        msg = str(exc.value)
        assert "cross-clock margin" in msg
        assert "7068s" in msg, "the refusal must name the margin the window failed to cover"

    def test_a_t_rxd_that_leaves_a_wide_vulnerable_window_is_REFUSED(self, runner) -> None:
        """The live run used 240 against a 24 h deadline and carried a 21.6 h ASSET_VULNERABLE
        window where the design intends roughly the cross-clock margin. 240 passes the OTHER two
        bounds, so only this one can catch it — and its refusal had never run."""
        with pytest.raises(SystemExit, match="ASSET_VULNERABLE"):
            runner._assert_t_rxd_bounds_the_vulnerable_window(_ns(t_rxd_blocks=240))

    def test_the_vulnerable_window_refusal_reports_the_span_it_measured(self, runner) -> None:
        with pytest.raises(SystemExit) as exc:
            runner._assert_t_rxd_bounds_the_vulnerable_window(_ns(t_rxd_blocks=240))
        hours = float(str(exc.value).split("leaves a ")[1].split(" h ")[0])
        expected = (86_400 - 600 - 240 * 36.0) / 3600
        assert abs(hours - expected) < 0.01, f"reported {hours} h, measured {expected} h"

    def test_the_vulnerable_window_bound_ACCEPTS_the_derived_value(self, runner) -> None:
        """Paired honest path. This bound refused the library\'s own derivation once already — a
        guard rejecting honest work — so the pairing is not ceremonial."""
        args = _ns()
        args.t_rxd_blocks = runner._derive_t_rxd_blocks(args)
        runner._assert_t_rxd_bounds_the_vulnerable_window(args)

    def test_the_vulnerable_window_bound_is_a_FLOOR_and_refuses_one_block_under_it(self, runner) -> None:
        """Pins the DIRECTION. A bound that only refuses very small values would satisfy the 240
        test above while still accepting everything near the boundary."""
        derived = runner._derive_t_rxd_blocks(_ns())
        runner._assert_t_rxd_bounds_the_vulnerable_window(_ns(t_rxd_blocks=derived))
        with pytest.raises(SystemExit, match="ASSET_VULNERABLE"):
            runner._assert_t_rxd_bounds_the_vulnerable_window(_ns(t_rxd_blocks=derived - 1))


#: (fast_interval_s, eth_timeout_s, stall_s, confirm_wait_s) rows where the feasible set is
#: NON-empty but ``eth_absolute_to_rxd_relative_blocks`` lands one block BELOW it.
#:
#: The sizer asks the punctuality gate, so it always satisfies bound B — and nothing makes it
#: satisfy the two FLOORS. Where float rounding puts it under them, the runner derived a value its
#: own bounds refused, and every refusal message advised exactly that value. Found by brute force
#: over 60,000 fractional rows; all fractional, all one block low.
_DERIVATION_MISSES_THE_RANGE_ROWS = [
    (36.2, 141_609, 5400, 900),
    (7.13, 156_554, 5400, 900),
    (9.7, 153_034, 7200, 600),
    (55.9, 113_118, 7200, 600),
    (41.618, 130_794, 5400, 900),
]


class TestTheADVICEIsSourcedFromTheFeasibleSet:
    """L-17. Found by re-attacking the L-15 fix, which had traded one defect for another.

    That fix folded "the derivation lands inside the feasible set" into the DEADLINE guard. It
    stopped the empty-set contradiction and started a new one: on 254 of 950 measured fractional
    rows the set was non-empty and the guard refused anyway, announcing "no --t-rxd-blocks
    satisfies all three bounds" about parameters where one plainly did — and refusing an explicit,
    in-range ``--t-rxd-blocks`` an operator could have passed. A guard that refuses honest work is
    a defect, not a safe default.

    The condition belonged to the ADVICE. Sourcing the recommendation from the feasible SET makes
    the contradiction unrepresentable: a value that is advised is a value that passes.
    """

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _DERIVATION_MISSES_THE_RANGE_ROWS)
    def test_the_row_still_reproduces_the_derivation_gap(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """Guards the guard: without an actual gap these rows prove nothing."""
        args = _ns(
            rxd_block_interval_fast_s=fast,
            eth_timeout_s=eth_timeout_s,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        window = runner._t_rxd_feasible_range(args)
        assert window is not None, "this row's feasible set is empty; it belongs in the other class"
        derived = runner._derive_t_rxd_blocks(args)
        assert not (window[0] <= derived <= window[1]), (
            f"the raw derivation {derived} now lands inside {window} at fast={fast} — this row no "
            "longer demonstrates the gap; find a replacement rather than deleting it"
        )

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _DERIVATION_MISSES_THE_RANGE_ROWS)
    def test_the_deadline_guard_does_NOT_refuse_a_workable_deadline(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """The regression the re-attack found. A feasible set exists, so the deadline is fine."""
        runner._assert_the_eth_deadline_can_hold_the_margins(
            _ns(
                rxd_block_interval_fast_s=fast,
                eth_timeout_s=eth_timeout_s,
                eth_finality_stall_tolerance_s=stall,
                max_covenant_confirm_wait_s=wait,
            )
        )

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _DERIVATION_MISSES_THE_RANGE_ROWS)
    def test_an_explicit_IN_RANGE_value_is_accepted(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """The honest work the earlier fix refused: an operator who reads the range and types a
        value from it must be allowed to run."""
        base = dict(
            rxd_block_interval_fast_s=fast,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
            eth_timeout_s=eth_timeout_s,
        )
        lo, hi = runner._t_rxd_feasible_range(_ns(**base))
        for t in {lo, hi}:
            _run_the_whole_parse_time_pipeline(runner, _ns(t_rxd_blocks=t, **base))

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _DERIVATION_MISSES_THE_RANGE_ROWS)
    def test_the_recommendation_lands_INSIDE_the_range(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        args = _ns(
            rxd_block_interval_fast_s=fast,
            eth_timeout_s=eth_timeout_s,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        lo, hi = runner._t_rxd_feasible_range(args)
        assert lo <= runner._recommended_t_rxd_blocks(args) <= hi

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _DERIVATION_MISSES_THE_RANGE_ROWS)
    def test_the_fix_up_LENGTHENS_the_window_never_shortens_it(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """The direction is the safety argument. A longer t_rxd costs the maker liveness; a shorter
        one costs the taker safety, and only one of those is recoverable."""
        args = _ns(
            rxd_block_interval_fast_s=fast,
            eth_timeout_s=eth_timeout_s,
            eth_finality_stall_tolerance_s=stall,
            max_covenant_confirm_wait_s=wait,
        )
        assert runner._recommended_t_rxd_blocks(args) >= runner._derive_t_rxd_blocks(args)

    @pytest.mark.parametrize("fast,eth_timeout_s,stall,wait", _DERIVATION_MISSES_THE_RANGE_ROWS)
    def test_the_whole_pipeline_completes_with_the_flag_omitted(
        self, runner, fast: float, eth_timeout_s: int, stall: int, wait: int
    ) -> None:
        """The operational point: omitting the flag — the documented, recommended thing to do —
        must produce a run, not a refusal."""
        _run_the_whole_parse_time_pipeline(
            runner,
            _ns(
                rxd_block_interval_fast_s=fast,
                eth_timeout_s=eth_timeout_s,
                eth_finality_stall_tolerance_s=stall,
                max_covenant_confirm_wait_s=wait,
            ),
        )

    def test_no_bound_message_can_advise_a_value_it_would_refuse(self, runner) -> None:
        """The contradiction, closed by construction rather than by inspection: every "and it is
        derived: X" in every refusal must be an X the three bounds accept."""
        checked = 0
        for fast, eth_timeout_s, stall, wait in _DERIVATION_MISSES_THE_RANGE_ROWS:
            base = dict(
                rxd_block_interval_fast_s=fast,
                eth_finality_stall_tolerance_s=stall,
                max_covenant_confirm_wait_s=wait,
                eth_timeout_s=eth_timeout_s,
            )
            lo, hi = runner._t_rxd_feasible_range(_ns(**base))
            for bad in (lo - 1, hi + 1, 12):
                if lo <= bad <= hi or bad < 1:
                    continue
                try:
                    _run_the_whole_parse_time_pipeline(runner, _ns(t_rxd_blocks=bad, **base))
                except SystemExit as exc:
                    msg = str(exc)
                    if "and it is derived: " not in msg:
                        continue
                    advised = int(msg.split("and it is derived: ")[1].split()[0])
                    checked += 1
                    assert lo <= advised <= hi, (
                        f"a refusal of --t-rxd-blocks {bad} advised {advised}, outside the feasible "
                        f"range {lo}..{hi} — advice the next parse would refuse"
                    )
        assert checked, "no refusal carried an 'it is derived' line; this test asserted nothing"

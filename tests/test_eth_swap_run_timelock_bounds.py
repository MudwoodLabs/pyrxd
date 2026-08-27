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
                now_unix_s=now,
                eth_timeout_unix_s=now + eth_timeout_s,
                margin=margin,
                t_rxd=bt.Timelock(t, bt.TimeUnit.BLOCKS),
                rxd_block_interval_s=fast,
                max_covenant_confirm_wait_s=wait,
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
        naive = math.ceil((eth_timeout_s - 7068 - wait) / fast) - 1
        assert not accepts(naive), (
            f"this row no longer reproduces the defect: the naive value {naive} is accepted at "
            f"fast={fast}, so it cannot demonstrate anything"
        )
        assert accepts(sized), f"gate refused the sizer's own output {sized} at {fast}s"
        assert sized == naive - 1, f"expected the sizer to step down from {naive}, got {sized}"

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
            assert not accepts(sized + 1), (
                f"t_rxd={sized + 1} also accepted at fast={fast}, eth={eth_timeout_s}, wait={wait} "
                "— a block of the taker's claim window given away"
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
            runner._assert_t_rxd_opens_before_the_eth_deadline(_ns(t_rxd_blocks=at_start), remaining_s=43_200)

    def test_the_honest_resume_still_passes(self, runner) -> None:
        """Paired, because a bound that refuses every resume strands funds it was meant to save."""
        remaining = 43_200
        derived = runner._derive_t_rxd_blocks(_ns(), remaining_s=remaining)
        runner._assert_t_rxd_opens_before_the_eth_deadline(_ns(t_rxd_blocks=derived), remaining_s=remaining)
        runner._assert_t_rxd_bounds_the_vulnerable_window(_ns(t_rxd_blocks=derived), remaining_s=remaining)


class TestAnImpossibleDeadlineNamesTheRightArgument:
    """L-13. A 3 h deadline refused t_rxd=86 as "too SHORT" while advising the operator to omit the
    flag and let it derive — which derives 86. Self-contradictory, and it pointed at the one
    argument that cannot help. The deadline has to hold roughly two margins plus the reserve; below
    that no t_rxd exists and the honest message says so.
    """

    def test_a_too_short_deadline_refuses_before_any_t_rxd_advice(self, runner) -> None:
        with pytest.raises(SystemExit, match="cannot hold the timelock at all"):
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=10_800))

    def test_it_names_eth_timeout_and_not_t_rxd(self, runner) -> None:
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=10_800))
        msg = str(exc.value)
        assert "--eth-timeout-s" in msg
        assert "--t-rxd-blocks" not in msg.split("no --t-rxd-blocks satisfies both bounds")[-1], (
            "the remedy must not point at --t-rxd-blocks; no value of it can help"
        )

    def test_the_minimum_it_advertises_actually_WORKS(self, runner) -> None:
        """The advice has to be true. A refusal naming a minimum that is itself refused is how the
        live run burned two funded covenants."""
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=10_800))
        minimum = int(str(exc.value).split("minimum: --eth-timeout-s ")[1].split()[0])
        runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=minimum))
        derived = runner._derive_t_rxd_blocks(_ns(eth_timeout_s=minimum))
        args = _ns(eth_timeout_s=minimum, t_rxd_blocks=derived)
        runner._assert_t_rxd_covers_the_takers_wait(args)
        runner._assert_t_rxd_opens_before_the_eth_deadline(args)
        runner._assert_t_rxd_bounds_the_vulnerable_window(args)

    def test_one_second_below_the_minimum_is_still_refused(self, runner) -> None:
        """Pins the boundary rather than the direction, so a minimum that drifts up to be safely
        wrong fails here."""
        with pytest.raises(SystemExit) as exc:
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=10_800))
        minimum = int(str(exc.value).split("minimum: --eth-timeout-s ")[1].split()[0])
        with pytest.raises(SystemExit, match="cannot hold"):
            runner._assert_the_eth_deadline_can_hold_the_margins(_ns(eth_timeout_s=minimum - 1))

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
        runner._assert_t_rxd_opens_before_the_eth_deadline(args)
        runner._assert_t_rxd_bounds_the_vulnerable_window(args)
        assert args.t_rxd_blocks < math.ceil(eth_timeout_s / 36.0)

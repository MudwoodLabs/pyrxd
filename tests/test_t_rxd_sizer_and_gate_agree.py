"""The sizer and the punctuality gate must use the SAME interval, or neither bound means anything.

`eth_absolute_to_rxd_relative_blocks` DIVIDES a budget by an interval to size `t_rxd`.
`assert_covenant_confirms_before_eth_deadline` MULTIPLIES `t_rxd` by an interval to project the
refund forward. Its docstring says the interval "cancels" and is "a no-op input" — which is true
only while both use the same one.

They did not. The coordinator passed the NOMINAL interval while the sizer divides by the FAST tail,
an ~8x mismatch, so the gate refused precisely the value the sizer produces. A runner-side cap was
then added to satisfy the gate, and that cap shortened `t_rxd` ~8x — widening the ASSET_VULNERABLE
window (maker has the asset refunded AND can still claim the counter leg with `p`) from ~2h to ~21h
at the fast tail. Two guards agreeing with each other and disagreeing with the thing they guard.

These tests pin the relationship rather than either number, so re-introducing the mismatch fails
here regardless of what the measured intervals happen to be.
"""

from __future__ import annotations

import math

import pytest

import pyrxd.btc_wallet.taproot as bt
from pyrxd.gravity.eth_rxd_timelock import (
    CrossClockMargin,
    assert_covenant_confirms_before_eth_deadline,
    eth_absolute_to_rxd_relative_blocks,
)
from pyrxd.gravity.swap_coordinator import MarginPolicy, _dividing_interval_s

_NOW = 1_000_000_000
_ETH_TIMEOUT_S = 86_400


def _margin() -> CrossClockMargin:
    return CrossClockMargin(
        eth_reorg_finality_s=768,
        rxd_claim_burial_s=1800,
        rxd_confirm_slack_s=600,
        rounding_slack_s=300,
        eth_finality_stall_tolerance_s=3600,
    )


def _policy(fast: float = 36.0, nominal: float = 300.0) -> MarginPolicy:
    return MarginPolicy(
        margin=bt.Timelock(240, bt.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=True,
        require_measured=True,
        rxd_block_interval_s=nominal,
        rxd_block_interval_fast_s=fast,
        eth_finalization_window_s=768,
        cross_clock_margin=_margin(),
        max_covenant_confirm_wait_s=600,
        accept_flat_burial=True,
    )


def _gate_accepts(t_rxd: int, interval: float, wait: int = 0) -> bool:
    try:
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=_NOW,
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            margin=_margin(),
            t_rxd=bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS),
            rxd_block_interval_s=interval,
            max_covenant_confirm_wait_s=wait,
        )
        return True
    except Exception:
        return False


class TestTheIntervalActuallyCancels:
    def test_the_gate_ACCEPTS_what_the_sizer_produces(self) -> None:
        """The cancellation property, stated as a test. This is what was broken."""
        fast = _dividing_interval_s(_policy())
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert _gate_accepts(sized, fast), (
            f"the gate refused t_rxd={sized}, which is exactly what the sizer produced at the same "
            "interval — the interval does not cancel, so neither bound means what it says"
        )

    def test_the_MISMATCH_is_what_breaks_it(self) -> None:
        """The defect, as a test. Sizing at the fast tail and checking at the nominal refuses the
        sizer's own output — which is how a runner-side cap came to shorten the window ~8x."""
        fast, nominal = 36.0, 300.0
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert not _gate_accepts(sized, nominal), (
            "expected the mismatched pairing to refuse — if this passes, the two intervals have "
            "converged and this test no longer describes anything"
        )

    def test_the_coordinator_passes_the_DIVIDING_interval(self) -> None:
        """Pins the call-site fix. `_dividing_interval_s` is the one function that decides this, and
        the coordinator must route through it rather than reading the nominal field.

        Checked against the AST. The previous version scanned text and hand-rolled paren matching,
        which made it both brittle (a reformat that wrapped the call across lines broke it) and
        DEFEATABLE: `_dividing_interval_s(policy) * 8.3` contains the substring it looked for and
        reintroduces exactly the 8.3x mismatch this module exists to prevent. An AST check sees the
        multiplication, because the argument is then a BinOp and not the call itself.
        """
        import ast
        import pathlib

        pol = _policy(fast=36.0, nominal=300.0)
        assert _dividing_interval_s(pol) == 36.0

        tree = ast.parse(pathlib.Path("src/pyrxd/gravity/swap_coordinator.py").read_text())
        calls = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id == "assert_covenant_confirms_before_eth_deadline"
        ]
        assert len(calls) >= 2, f"expected at least two call sites, found {len(calls)}"
        for call in calls:
            arg = next(
                (k.value for k in call.keywords if k.arg == "rxd_block_interval_s"),
                None,
            )
            assert arg is not None, "a call site does not name rxd_block_interval_s at all"
            assert isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name), (
                f"line {call.lineno}: the interval is {ast.dump(arg)[:80]}, not a bare "
                "`_dividing_interval_s(...)` call — anything wrapping it (a factor, a fallback, a "
                "different field) is the mismatch this module exists to prevent"
            )
            assert arg.func.id == "_dividing_interval_s", (
                f"line {call.lineno}: passes {arg.func.id}(...), not _dividing_interval_s(...)"
            )


class TestTheWindowThisProtects:
    @pytest.mark.parametrize("fast", [20.0, 36.0, 60.0, 120.0])
    def test_the_sized_value_bounds_the_vulnerable_window_by_the_margin(self, fast: float) -> None:
        """WHY the cancellation matters, at several tails so it is not a coincidence of one number.

        ASSET_VULNERABLE = eth_timeout - t_rxd*interval: the span in which the maker holds the
        refunded asset AND can still claim the counter leg with p. Sizing at the fast tail bounds it
        by the cross-clock margin; the nominal-derived cap did not.
        """
        m = _margin()
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW,
            margin=m,
            rxd_block_interval_s=fast,
        ).value
        window_s = _ETH_TIMEOUT_S - sized * fast
        assert window_s <= m.total_s() + fast, (
            f"at fast={fast}s the sized t_rxd={sized} leaves a {window_s / 3600:.2f}h vulnerable "
            f"window, above the {m.total_s() / 3600:.2f}h margin it is supposed to be bounded by"
        )

    def test_a_nominal_derived_cap_would_blow_that_bound(self) -> None:
        """The regression, quantified. Keeps the cost visible if anyone re-introduces the cap."""
        m = _margin()
        capped = math.floor((_ETH_TIMEOUT_S - m.total_s() - 600) / 300.0)
        window_s = _ETH_TIMEOUT_S - capped * 36.0
        assert window_s > 5 * m.total_s(), (
            "the nominal-derived cap is supposed to be much worse at the fast tail; if it is not, "
            "the intervals have converged and this test is obsolete"
        )


class TestTheExactDivisionBoundary:
    """The one input class where sizer and gate disagreed — and the one the real run landed on.

    `TestTheIntervalActuallyCancels` sizes with a ZERO confirm wait, so its budget never divides
    evenly by the interval and it never reaches this boundary. On an exact quotient the old
    `floor(budget/interval)` returned the quotient itself, and the gate compares with a strict `<`,
    so a projection landing precisely ON the deadline is late: the sizer emitted a value its own
    gate refused.

    Invisible in production for a different reason — `eth_absolute_to_rxd_relative_blocks` had no
    production caller at all. The runner took a hand-typed `--t-rxd-blocks`. The first run to
    derive the value would have met it immediately: (86400 - 7068 - 600) / 36 = 2187.0 exactly.
    """

    def test_the_gate_ACCEPTS_the_sizer_output_when_the_budget_divides_EXACTLY(self) -> None:
        wait = 600
        fast = _dividing_interval_s(_policy())
        budget = _ETH_TIMEOUT_S - _margin().total_s() - wait
        assert budget % fast == 0, (
            f"this test is only meaningful on an exact quotient; budget/interval = {budget / fast}"
        )
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW + wait,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert _gate_accepts(sized, fast, wait=wait), (
            f"the gate refused t_rxd={sized}, the sizer's own output at the same interval — the "
            f"exact-division boundary is back"
        )

    def test_the_sized_value_is_still_the_LARGEST_the_gate_accepts(self) -> None:
        """The paired honest-path check. Fixing a refusal by shrinking the answer would also pass
        the test above while quietly handing the taker a shorter claim window every run."""
        wait = 600
        fast = _dividing_interval_s(_policy())
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW + wait,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert not _gate_accepts(sized + 1, fast, wait=wait), (
            f"t_rxd={sized + 1} is also accepted, so the sizer gave away a block of the taker's "
            f"claim window for nothing"
        )

    @pytest.mark.parametrize("wait", [0, 300, 600, 900, 1200])
    @pytest.mark.parametrize("fast", [20.0, 24.0, 30.0, 36.0, 45.0, 60.0])
    def test_across_the_parameter_grid_the_sizer_is_exactly_the_gate_boundary(self, fast: float, wait: int) -> None:
        """Both properties at once, over the grid the sweep that found this defect used. Two
        one-off cases can be satisfied by a fudge that happens to fit them; a grid cannot."""
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW + wait,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert _gate_accepts(sized, fast, wait=wait), f"gate refused sized t_rxd={sized}"
        assert not _gate_accepts(sized + 1, fast, wait=wait), f"t_rxd={sized + 1} also accepted"

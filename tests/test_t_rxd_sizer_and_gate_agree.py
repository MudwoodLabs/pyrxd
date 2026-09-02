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
from hypothesis import given, settings
from hypothesis import strategies as st

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


def _analytic_smallest(budget: int, interval: float) -> int:
    """The largest t the gate can accept, derived from its DOCUMENTED semantics — not by asking it.

    The gate refuses when `now + wait + ceil(t * interval) >= eth_timeout - margin`, i.e. accepts
    exactly when `ceil(t * interval) < budget`. With an integer budget that is `t*interval <=
    budget - 1`, so the largest acceptable t is `floor((budget-1) / interval)` — computed here over
    `Fraction`, exactly, with no floats and no call into either production function.

    WHY THIS EXISTS: the sizer now defers to the gate (it steps down until the gate accepts), so
    "the gate accepts what the sizer emitted" and even "one more block is refused" are true BY
    CONSTRUCTION — they pin sizer↔gate agreement but would stay green if BOTH drifted together
    (e.g. a gate arithmetic change silently shrinking every window; measured: a 30s drift in the
    gate's deadline passes every agreement test in this file). This independent restatement of the
    boundary is what catches joint drift.

    Exactness caveat, and why it is safe HERE: the production gate computes `ceil(t*interval)` in
    binary floating point, and at awkward fractional intervals float and rational can disagree by
    one block (the reason the SIZER defers to the gate instead of trusting `ceil(x)-1`). This
    file's grids use intervals whose products with block counts are exactly representable
    (integer-valued floats, t < 2^53), where float and Fraction provably coincide — so an
    inequality against this model is a real defect, not float noise. Do not lift this helper into
    a fuzz over arbitrary floats; there, the gate itself is the only exact oracle.
    """
    from fractions import Fraction

    # SMALLEST, not largest (#482). The gate bounds t_rxd from BELOW — the refund must open at or
    # after `eth_timeout + margin` — so the boundary value is `ceil(budget / interval)`, the least
    # t with `t * interval >= budget`. It was `floor((budget - 1) / interval)`, the greatest t
    # with `t * interval < budget`, which is the boundary of the opposite inequality.
    return math.ceil(Fraction(budget) / Fraction(interval))


def _gate_accepts(t_rxd: int, interval: float, wait: int = 0) -> bool:
    try:
        # ANCHOR AT THE LOCK TIME, with a zero wait. The gate used to ADD
        # `max_covenant_confirm_wait_s` to `now`, so passing it here was the same instant as the
        # sizer's `expected_rxd_lock_time_unix_s = _NOW + wait`. #482 removed that term from the
        # arithmetic — adding it now would assume a LATE confirm, which is the optimistic
        # direction — so the two anchors have to be written the same way to stay the same instant.
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=_NOW + wait,
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            margin=_margin(),
            t_rxd=bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS),
            rxd_block_interval_s=interval,
            max_covenant_confirm_wait_s=0,
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
        # THE DANGEROUS PAIRING SWAPPED ENDS WITH THE RELATION (#482). Sizing at the FAST tail and
        # checking at the NOMINAL used to refuse, because a bigger interval overshot an upper
        # bound. The gate bounds t_rxd from below now, so that pairing OVER-satisfies and passes.
        # What refuses today is the reverse: size at the nominal, check at the fast tail, and the
        # window is far too short. Same defect, opposite arrangement — a test left as it was would
        # have gone quietly green while the mismatch it exists for was still reachable.
        fast, nominal = 36.0, 300.0
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW,
            margin=_margin(),
            rxd_block_interval_s=nominal,
        ).value
        assert not _gate_accepts(sized, fast), (
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

        What could still satisfy this structural check while the property fails — each hole named,
        and where it is closed:
          1. `_dividing_interval_s(<helper>(policy))`, a wrapper that hands the helper a DOCTORED
             policy (e.g. one with the fast tail blanked so the `or` falls back to nominal). The
             outer node is still a bare `_dividing_interval_s(...)` call. CLOSED BELOW: the
             argument must itself be a plain Name, not a call or any other expression.
          2. Rebinding the name — a second `def _dividing_interval_s` or an assignment shadowing
             the import target inside swap_coordinator.py. CLOSED BELOW: exactly one binding of
             that name may exist in the module.
          3. Rebinding the POLICY variable before the call (`policy = _nominalized(policy)`), or
             calling the gate under an import alias so the call-site scan never sees it. Beyond a
             per-site structural check's reach — CLOSED by
             `TestTheIntervalThatReachesTheGate`, which drives the real coordinator methods and
             asserts on the value that actually ARRIVES at the gate.
        """
        import ast
        import pathlib

        import pyrxd.gravity.swap_coordinator as sc

        pol = _policy(fast=36.0, nominal=300.0)
        assert _dividing_interval_s(pol) == 36.0

        # The imported module's own file — not a cwd-relative guess at where its source lives.
        tree = ast.parse(pathlib.Path(sc.__file__).read_text())

        # Hole 2: the name must be bound exactly once (the one real helper). A shadowing def or
        # assignment would let every call site "route through _dividing_interval_s" while calling
        # something else.
        bindings = [
            n
            for n in ast.walk(tree)
            if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_dividing_interval_s")
            or (
                isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "_dividing_interval_s" for t in n.targets)
            )
        ]
        assert len(bindings) == 1, f"_dividing_interval_s is bound {len(bindings)} times; a shadow can swap the tail"

        # Hole 3 (alias half): the gate must be imported under its own name, so the call-site scan
        # below cannot be dodged by `import ... as _gate`.
        gate_imports = [
            alias
            for n in ast.walk(tree)
            if isinstance(n, ast.ImportFrom)
            for alias in n.names
            if alias.name == "assert_covenant_confirms_before_eth_deadline"
        ]
        assert gate_imports and all(a.asname is None for a in gate_imports), (
            "the gate is imported under an alias, so a call-site scan by name proves nothing"
        )

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
            # Hole 1: the helper must be handed the policy ITSELF. A call or expression here can
            # doctor the policy on the way in (`_dividing_interval_s(_nominal_view(policy))`
            # reintroduces the 8.3x mismatch while keeping the outer call's shape intact).
            assert len(arg.args) == 1 and not arg.keywords and isinstance(arg.args[0], ast.Name), (
                f"line {call.lineno}: _dividing_interval_s is not passed a bare policy variable "
                f"({ast.dump(arg)[:120]}) — whatever transforms it there can swap the tail"
            )


class TestTheIntervalThatReachesTheGate:
    """The behavioral half of the call-site pin: drive the REAL coordinator methods and observe
    the interval that actually arrives at the gate. This is what closes the holes a structural
    scan cannot reach (a policy variable reassigned before the call, a dodging alias, a wrapper
    the AST test did not anticipate): no matter how the source is arranged, the value handed to
    `assert_covenant_confirms_before_eth_deadline` either is the policy's fast tail or is not."""

    @staticmethod
    def _drive(monkeypatch) -> list[float]:
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        try:
            from test_swap_coordinator import (
                FakeEthLeg,
                FakeIndexer,
                FakeRadiantLeg,
                FakeSeenStore,
                _eth_terms,
                _final,
                generate_secret,
            )
        finally:
            sys.path.pop(0)

        import pyrxd.gravity.swap_coordinator as sc
        from pyrxd.gravity.swap_coordinator import CoordinatorConfig, SwapCoordinator
        from pyrxd.gravity.swap_state import SwapRecord, SwapState

        captured: list[float] = []

        def _spy(**kw):  # signature-compatible: the coordinator calls it with keywords only
            captured.append(kw["rxd_block_interval_s"])

        monkeypatch.setattr(sc, "assert_covenant_confirms_before_eth_deadline", _spy)

        _, h = generate_secret()
        terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40_000)
        # Built like test_swap_coordinator's `_eth_coord_negotiated`, but with a stall window that
        # clears the finality+burial reserve floor the FAST tail implies (ceil(768/36)+6-1 = 27;
        # that helper hardcodes 6, sized for its nominal-only policies).
        coord = SwapCoordinator(
            record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
            counter_leg=FakeEthLeg(preimage=b"\x01" * 32, verdict=_final()),
            radiant_leg=FakeRadiantLeg(),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(
                margin_policy=_policy(fast=36.0, nominal=300.0), maker_stall_safety_window_blocks=27
            ),
        )
        coord._assert_eth_timelock_ordering(terms, now_unix_s=_NOW)  # pre-fund ordering gate
        coord._assert_eth_lock_timing_still_safe(now_unix_s=_NOW)  # post-confirm recheck
        return captured

    def test_both_coordinator_gate_calls_receive_the_fast_tail(self, monkeypatch) -> None:
        captured = self._drive(monkeypatch)
        assert captured == [36.0, 36.0], (
            f"the interval that reached the gate was {captured}, not the policy's fast tail "
            "(36.0) both times — whatever the call sites look like, the value arriving is wrong, "
            "which is the 8.3x mismatch this file exists to prevent"
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
        # 624, not 600: the budget gained `+ margin` instead of `- margin` when the relation was
        # inverted (#482), which moved the exact quotient. The precondition assert below is what
        # caught it — a test that needs an exact division has to re-derive the constant, not keep
        # the one that used to produce one.
        wait = 624
        fast = _dividing_interval_s(_policy())
        budget = _ETH_TIMEOUT_S + _margin().total_s() - wait
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
        # The agreement check above is true BY CONSTRUCTION now that the sizer defers to the gate;
        # this is the independent half: on an exact quotient q, the largest acceptable value is
        # exactly q - 1, derived from the gate's documented semantics without calling either
        # function. A joint sizer+gate drift keeps the line above green and fails this one.
        # On an exact quotient q the SMALLEST acceptable value is exactly q (not q - 1): q blocks
        # reach the deadline precisely, and equality satisfies a `>=` bound.
        assert sized == budget // int(fast) == _analytic_smallest(budget, fast)

    def test_the_sized_value_is_still_the_SMALLEST_the_gate_accepts(self) -> None:
        """The paired honest-path check, inverted with the relation (#482). The give-away is now
        upward: satisfying the gate by GROWING t_rxd would also pass the test above, while locking
        the maker's asset longer than the swap needs on every run."""
        # 624, matching its sibling. The exact quotient moved when #482 flipped the budget's
        # sign; at 600 this sits at budget/interval = 2579.67 — off the boundary the whole
        # class exists for, so the refuse-below half proves nothing.
        wait = 624
        fast = _dividing_interval_s(_policy())
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW + wait,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert not _gate_accepts(sized - 1, fast, wait=wait), (
            f"t_rxd={sized - 1} is also accepted, so the sizer locked the maker's asset a block "
            f"longer than the deadline requires"
        )

    @pytest.mark.parametrize("wait", [0, 300, 600, 900, 1200])
    @pytest.mark.parametrize("fast", [20.0, 24.0, 30.0, 36.0, 45.0, 60.0])
    def test_across_the_parameter_grid_the_sizer_is_exactly_the_gate_boundary(self, fast: float, wait: int) -> None:
        """The boundary property from BOTH sides, over the grid the sweep that found this defect
        used — plus the value itself from a third, implementation-independent derivation.

        The accept/refuse pair pins sizer↔gate AGREEMENT, but the sizer reaches its answer by
        asking the gate, so agreement alone survives any change that moves both together — it is
        sharp at whatever boundary the gate currently has, right or wrong. `_analytic_smallest`
        restates where that boundary is SUPPOSED to be (exact rational arithmetic, no production
        code), so the three assertions jointly refuse: a sizer that undershoots (gate refuses it),
        a sizer that overshoots (sized-1 also accepted), and a sizer and gate that drifted in
        lockstep (analytic value disagrees)."""
        budget = _ETH_TIMEOUT_S + _margin().total_s() - wait
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW + wait,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert _gate_accepts(sized, fast, wait=wait), f"gate refused sized t_rxd={sized}"
        assert not _gate_accepts(sized - 1, fast, wait=wait), f"t_rxd={sized - 1} also accepted"
        assert sized == _analytic_smallest(budget, fast), (
            f"sized {sized} != analytic smallest-acceptable {_analytic_smallest(budget, fast)} for "
            f"budget {budget}s at {fast}s/block — the sizer and the gate agree with each other "
            "but not with the documented boundary, i.e. they drifted together"
        )

    @settings(max_examples=300, deadline=None)
    @given(
        whole=st.integers(min_value=15, max_value=400),
        hundredths=st.integers(min_value=1, max_value=99),
        wait=st.integers(min_value=0, max_value=3600),
    )
    def test_the_boundary_is_sharp_at_FRACTIONAL_intervals_too(self, whole: int, hundredths: int, wait: int) -> None:
        """The grid above is all whole-second intervals. Real ones are not.

        Every measured Radiant figure in this repo is fractional — a 222 s median, a 293 s mean,
        a p10 that moved 43 s -> 36 s between two samples — and the sizer DIVIDES by that number.
        Fractional divisors are where `ceil(t * interval)` in binary floating point stops agreeing
        with exact rational arithmetic, which is the whole reason the sizer defers to the gate
        rather than computing `ceil(x) - 1` itself.

        NOTE what this does NOT assert. `_analytic_smallest` is documented as valid only for
        integer-valued intervals, "where float and Fraction provably coincide", and says in as many
        words: *do not lift this helper into a fuzz over arbitrary floats; there, the gate itself
        is the only exact oracle.* So the third, drift-catching assertion of the grid test has no
        meaning here and is deliberately omitted — asserting it would manufacture float-noise
        failures and teach the next reader to loosen a real check.

        What survives at arbitrary intervals is the two-sided boundary property, and it is the one
        D7/D8 regressed: the gate must ACCEPT what the sizer emits (no undershoot, which strands
        the maker) and REFUSE one block less (no overshoot, which locks the maker's asset longer
        than the swap needs, every run).

        MEASURED, and the reason this earns its runtime: planting a one-block overshoot in the
        sizer (`math.ceil(...) + 1`) fails THIS test and nothing else in the file — the
        whole-second grid above stays green on all 41 of its cases. Fractional divisors are not a
        cosmetic widening of the grid; they are the only rows that catch it.
        """
        fast = whole + hundredths / 100.0
        assert fast % 1 != 0, "the draw must be fractional — that is the point"
        sized = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=_NOW + _ETH_TIMEOUT_S,
            expected_rxd_lock_time_unix_s=_NOW + wait,
            margin=_margin(),
            rxd_block_interval_s=fast,
        ).value
        assert _gate_accepts(sized, fast, wait=wait), (
            f"gate refused the sized t_rxd={sized} at {fast}s/block, wait={wait}s — the sizer "
            f"undershot and the maker's covenant would be refused at its own gate"
        )
        assert not _gate_accepts(sized - 1, fast, wait=wait), (
            f"t_rxd={sized - 1} is also accepted at {fast}s/block, wait={wait}s — the sizer "
            f"overshot, locking the maker's asset a block longer than the deadline requires"
        )

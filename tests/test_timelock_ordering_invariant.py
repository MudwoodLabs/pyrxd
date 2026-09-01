"""The cross-chain timelock invariant, stated once (#482).

Herlihy, *Atomic Cross-Chain Swaps* (arXiv:1801.09515) §1, verbatim: Alice creates the secret and
publishes a contract with timelock **6∆**; Bob publishes at **5∆**; Carol at **4∆**; then "Alice
sends s to Carol's contract". So the secret generator LOCKS the longest-dated leg and CLAIMS the
shortest-dated one, and Lemma 4.13 fixes the gap:

    the timeout on each arc (u, v) is later by at least ∆ than the timeout on each arc (v, w).

Our maker generates ``p``, LOCKS the Radiant covenant and CLAIMS the counter leg. Therefore
``t_rxd`` is the LONGER leg. The code enforced the reverse until this change, which handed the
maker a window — at least ``margin`` wide by construction — in which to refund the covenant while
``p`` was still secret and then claim the counter leg.

This file is deliberately small and states the rule ONCE. Every other suite exercises swaps built
from that rule; this one is where the rule itself lives.
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin
from pyrxd.security.errors import ValidationError

MARGIN = 36


def _policy(margin: int = MARGIN) -> MarginPolicy:
    return MarginPolicy(margin=t.Timelock(margin, t.TimeUnit.BLOCKS), block_interval_s=600.0, is_measured=False)


def _blk(n: int) -> t.Timelock:
    return t.Timelock(n, t.TimeUnit.BLOCKS)


class TestTheRule:
    def test_the_leg_the_maker_LOCKED_must_outlast_the_leg_it_CLAIMS(self) -> None:
        assert_timelock_margin(_blk(72), _blk(72 + MARGIN), _policy())

    def test_the_OLD_direction_is_now_refused(self) -> None:
        """The regression that matters. Under `t_btc > t_rxd` the maker refunds the covenant while
        `p` is still secret and then claims the counter leg — both legs, deterministically, with
        the taker unable to claim (no `p`) or refund (its deadline is later)."""
        with pytest.raises(ValidationError, match="ordering violated"):
            assert_timelock_margin(_blk(144), _blk(72), _policy())

    def test_equality_is_not_enough(self) -> None:
        with pytest.raises(ValidationError, match="ordering violated"):
            assert_timelock_margin(_blk(100), _blk(100), _policy())

    def test_a_gap_smaller_than_the_margin_is_refused(self) -> None:
        """Δ exists because the taker needs time AFTER the reveal — the maker may reveal as late as
        its own deadline."""
        with pytest.raises(ValidationError, match="insufficient margin"):
            assert_timelock_margin(_blk(72), _blk(72 + MARGIN - 1), _policy())

    def test_exactly_the_margin_passes(self) -> None:
        """Boundary, inclusive. A guard that refuses valid work is a bug, and this one sits on a
        parameter an honest maker must choose."""
        assert_timelock_margin(_blk(72), _blk(72 + MARGIN), _policy())


class TestTheHerlihyExample:
    """The paper's own numbers, mapped onto two parties.

    Alice locks 6∆ and claims a 4∆ leg. Collapsing the three-party cycle to two, the secret
    holder's locked leg keeps the larger timeout and the claimed leg the smaller.
    """

    @pytest.mark.parametrize("delta", [1, 6, 144])
    def test_locked_6delta_claimed_4delta_holds_at_any_scale(self, delta: int) -> None:
        pol = _policy(margin=2 * delta)
        assert_timelock_margin(_blk(4 * delta), _blk(6 * delta), pol)

    @pytest.mark.parametrize("delta", [1, 6, 144])
    def test_the_mirror_image_is_refused_at_any_scale(self, delta: int) -> None:
        pol = _policy(margin=2 * delta)
        with pytest.raises(ValidationError):
            assert_timelock_margin(_blk(6 * delta), _blk(4 * delta), pol)


def test_the_theft_window_no_longer_exists() -> None:
    """The adversarial scenario as a test, not a comment.

    Under the old relation `[rxd_refund_opens, counter_deadline]` was non-empty and at least
    `margin` wide, and the maker could act inside it. Under the corrected relation the counter
    deadline comes FIRST, so the window is empty by construction: by the time the maker's own
    refund opens, the taker has already been able to refund the counter leg.
    """
    t_btc, t_rxd = 72, 72 + MARGIN
    assert_timelock_margin(_blk(t_btc), _blk(t_rxd), _policy())
    assert t_btc < t_rxd, "the counter leg must expire FIRST"
    assert t_rxd - t_btc >= MARGIN, "and by at least Δ, so the taker has time after the reveal"


class TestTheSizingAnchor:
    """The anchor inverted with the relation, and the two runners disagreed about it (#482).

    `t_rxd` is committed in the covenant script BEFORE broadcast, and the refund opens at
    `actual_confirm + t_rxd`. The invariant is `actual_confirm + t_rxd >= counter_deadline +
    margin`, so:

        confirm LATER than assumed   -> refund opens later  -> MORE margin -> safe
        confirm EARLIER than assumed -> refund opens sooner -> invariant BREAKS

    The conservative anchor is therefore the EARLIEST plausible confirm — `now`. Reserving a
    confirm allowance was correct under the OLD relation, where a LATE confirm pushed the refund
    past the deadline, and is exactly wrong under this one.
    """

    def test_both_runners_anchor_on_now(self) -> None:
        """They disagreed: `eth_swap_run` reserved `max_covenant_confirm_wait_s` while
        `eth_swap_two_host` used `now`. Under the inversion that made one of them unsafe, and
        nothing reconciled them — so the agreement is pinned rather than left to convention."""
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parent.parent / "scripts"
        for name in ("eth_swap_run.py", "eth_swap_two_host.py"):
            src = (root / name).read_text()
            anchors = re.findall(r"expected_rxd_lock_time_unix_s=([^,\n]+)", src)
            assert anchors, f"{name} no longer sizes a t_rxd — check this test still has a subject"
            for anchor in anchors:
                assert "max_covenant_confirm_wait" not in anchor, (
                    f"{name} anchors the sizing on a LATE confirm ({anchor.strip()}). Under the "
                    "inverted relation an early confirm is what breaks the invariant, so the "
                    "anchor must be the earliest plausible confirm."
                )
                assert "time.time()" in anchor, f"{name} anchors on {anchor.strip()!r}, expected now"

    def test_an_earlier_confirm_than_assumed_is_the_unsafe_direction(self) -> None:
        """The property behind the rule, arithmetic only — no chain, no sizing call.

        Anchoring on `now` makes every actual confirm at-or-after the anchor, so the refund can
        only open LATER than planned. Anchoring on a late confirm admits actual < assumed, which
        moves it earlier and eats the margin.
        """
        counter_deadline, margin, interval = 10_000, 1_000, 10
        now = 0

        # Anchored on `now`: t_rxd sized so the refund opens exactly at deadline + margin.
        t_rxd_now = (counter_deadline + margin - now) // interval
        for actual_confirm in (0, 50, 500):  # never earlier than the anchor
            assert actual_confirm + t_rxd_now * interval >= counter_deadline + margin

        # Anchored on a LATE confirm: a fast chain confirms sooner and the invariant fails.
        assumed_late = 500
        t_rxd_late = (counter_deadline + margin - assumed_late) // interval
        assert 0 + t_rxd_late * interval < counter_deadline + margin, (
            "a confirm earlier than the assumed one must break the invariant — if it does not, "
            "this test is not exercising the direction it claims"
        )

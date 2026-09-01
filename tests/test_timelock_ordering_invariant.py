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

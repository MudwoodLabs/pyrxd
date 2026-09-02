"""#482 follow-ups found by the post-merge security panel, both fund-safety.

TWO DEFECTS, both created by the inversion and both of the same shape: a fix applied where the
defect was DEMONSTRATED and not where the defect LIVES.

1. THE ELAPSED-DEPTH CORRECTION WAS ETH-ONLY. `t_rxd` is a relative CSV counted from the covenant's
   MINING, so a covenant with confirmations opens its refund that much sooner and the real gap is
   `(t_rxd - elapsed) - t_btc`. #482 taught the ETH cross-clock gate to subtract elapsed depth and
   #531 taught the burial floor; `assert_timelock_margin` — the gate the BTC path relies on — was
   the third instance and the only one left. The maker picks `elapsed` by locking its covenant and
   presenting the swap later, so this is maker-controlled, not incidental.

2. `t_btc` BECAME A SUBTRACTION AND COULD UNDERFLOW. The runners derive `t_btc = t_rxd - margin - 4`.
   The old `+ margin + 4` form could not go below zero; this one can. `Timelock(0)` constructs and
   `refund_leaf_script` emits `OP_0 OP_CSV OP_DROP` — a counter leg refundable in its own funding
   block, which the taker can refund immediately while the maker's asset is still locked.
"""

from __future__ import annotations

import pytest

import pyrxd.btc_wallet.taproot as t
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin
from pyrxd.security.errors import ValidationError

_MARGIN = 36


def _policy() -> MarginPolicy:
    return MarginPolicy(margin=t.Timelock(_MARGIN, t.TimeUnit.BLOCKS), block_interval_s=600.0, is_measured=False)


def _blk(n: int) -> t.Timelock:
    return t.Timelock(n, t.TimeUnit.BLOCKS)


class TestTheMarginIsJudgedOnTheWindowThatREMAINS:
    """`assert_timelock_margin` subtracts the covenant's elapsed depth from t_rxd."""

    def test_an_aged_covenant_that_erodes_the_margin_is_REFUSED(self) -> None:
        """The exploit, at the numbers it was demonstrated on.

        t_rxd 120 / t_btc 20 clears the margin in WALL CLOCK on the negotiated terms: 10.0 h of
        Radiant against 3.33 h of Bitcoin plus a 6.0 h margin, so 112 Radiant blocks must remain.
        A covenant 9 blocks deep leaves 111 and the swap is already unsafe; at 44 deep it leaves 76.

        The numbers moved with #567 — they were t_rxd 80 / t_btc 40, which reads as a comfortable
        40-block gap and is 6.67 h against 12.67 h required. The fixture was itself an inverted
        configuration in wall-clock, so it could not have distinguished an elapsed-depth failure
        from a units failure.
        """
        for elapsed, remaining in ((9, 111), (20, 100), (44, 76)):
            with pytest.raises(ValidationError) as exc:
                assert_timelock_margin(_blk(20), _blk(120), _policy(), elapsed_blocks=elapsed)
            assert str(remaining) in str(exc.value) or "WALL CLOCK" in str(exc.value), str(exc.value)

    def test_a_FRESH_covenant_with_the_same_terms_still_passes(self) -> None:
        """The paired honest path, and the reason this is about DEPTH and not about the terms.
        Identical t_rxd/t_btc; only the covenant's age differs. Without this, the refusal above
        would be indistinguishable from a margin that was simply too tight."""
        assert_timelock_margin(_blk(20), _blk(120), _policy(), elapsed_blocks=1)  # 119 blk left
        assert_timelock_margin(_blk(20), _blk(120), _policy(), elapsed_blocks=8)  # 112 left = the floor exactly

    def test_the_boundary_is_exact(self) -> None:
        assert_timelock_margin(_blk(20), _blk(120), _policy(), elapsed_blocks=8)
        with pytest.raises(ValidationError):
            assert_timelock_margin(_blk(20), _blk(120), _policy(), elapsed_blocks=9)

    def test_the_default_is_the_NEGOTIATED_check_and_is_unchanged(self) -> None:
        """Callers that have not read the chain pass nothing and get the old behaviour, which is
        still correct for what it is — a check on the terms, not on the live window."""
        assert_timelock_margin(_blk(20), _blk(120), _policy())

    @pytest.mark.parametrize("bad", [-1, True, 2.0, "2", None])
    def test_a_bad_elapsed_value_fails_CLOSED(self, bad: object) -> None:
        with pytest.raises(ValidationError):
            assert_timelock_margin(_blk(20), _blk(120), _policy(), elapsed_blocks=bad)  # type: ignore[arg-type]


class TestACounterLegCannotMatureInItsOwnFundingBlock:
    """`t_btc` derives by SUBTRACTION now, so it can underflow where it previously could not."""

    def test_a_zero_block_t_btc_is_REFUSED_at_construction(self) -> None:
        from pyrxd.gravity.swap_coordinator import generate_secret
        from tests.test_swap_coordinator import _terms

        _secret, h = generate_secret()
        with pytest.raises(ValidationError, match="own funding block"):
            _terms(hashlock=h, t_rxd_blocks=80, t_btc_blocks=0)

    def test_one_block_is_permitted(self) -> None:
        """The paired honest path. A 1-block counter leg is short but it is a real timelock, and
        refusing it would be a guard refusing valid work on a parameter dust runs legitimately
        choose."""
        from pyrxd.gravity.swap_coordinator import generate_secret
        from tests.test_swap_coordinator import _terms

        _secret, h = generate_secret()
        terms = _terms(hashlock=h, t_rxd_blocks=80, t_btc_blocks=1)
        assert terms.t_btc.value == 1

    def test_the_zero_script_this_prevents_really_is_immediately_spendable(self) -> None:
        """Why the refusal exists, stated in the bytes rather than asserted in prose.

        `OP_0 OP_CSV OP_DROP` is a relative timelock of zero — satisfied in the funding block
        itself. This is what the guard above stops being constructible.
        """
        import coincurve

        from pyrxd.btc_wallet.taproot import refund_leaf_script

        xonly = coincurve.PublicKeyXOnly.from_secret(bytes(range(1, 33))).format()
        assert refund_leaf_script(xonly, _blk(0)).hex().startswith("00b275")
        assert not refund_leaf_script(xonly, _blk(1)).hex().startswith("00b275")


class TestTheCoordinatorACTUALLYPassesElapsedDepthOnTheBtcPath:
    """Reachability, and the reason this class exists separately from the ones above.

    Those tests call `assert_timelock_margin(..., elapsed_blocks=N)` by hand. They prove the
    MECHANISM and say nothing about whether the coordinator ever passes `cov_confs` on a BTC swap —
    which is the entire defect. Verified by planting: replacing step 7's BTC branch with `pass`
    leaves every test above green. A test that builds the input by hand cannot catch a missing
    caller; at least one has to reach the code through the production entry point.
    """

    @pytest.mark.asyncio
    async def test_a_deep_covenant_is_REFUSED_through_pre_btc_lock_check(self) -> None:
        from pyrxd.gravity.swap_coordinator import generate_secret
        from tests.test_swap_coordinator import FakeRadiantLeg, _coordinator, _policy, _terms

        _secret, h = generate_secret()
        # t_rxd 120 / t_btc 20 clears the margin in WALL CLOCK on the NEGOTIATED terms (10.0 h
        # of Radiant vs 3.33 h + a 6.0 h margin), so 112 Radiant blocks must remain.
        terms = _terms(hashlock=h, t_rxd_blocks=120, t_btc_blocks=20)
        for confs, remaining in ((9, 111), (20, 100), (44, 76)):
            coord = _coordinator(terms=terms, radiant_leg=FakeRadiantLeg(report_confs=confs), policy=_policy())
            gate = await coord.pre_btc_lock_check(terms)
            assert not gate.ok, f"covenant {confs} deep leaves {remaining} blk; the gate must refuse"
            assert "REMAINING window" in gate.reason, gate.reason

    @pytest.mark.asyncio
    async def test_a_FRESH_covenant_with_the_same_terms_still_funds(self) -> None:
        """The paired honest path, through the same entry point. Without it, wiring the gate to
        refuse everything would satisfy the test above."""
        from pyrxd.gravity.swap_coordinator import generate_secret
        from tests.test_swap_coordinator import FakeRadiantLeg, _coordinator, _policy, _terms

        _secret, h = generate_secret()
        terms = _terms(hashlock=h, t_rxd_blocks=120, t_btc_blocks=20)
        coord = _coordinator(terms=terms, radiant_leg=FakeRadiantLeg(report_confs=1), policy=_policy())
        gate = await coord.pre_btc_lock_check(terms)
        assert gate.ok, gate.reason

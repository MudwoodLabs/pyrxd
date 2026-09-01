"""#511: the taker's claim must be MINED before it can start burying, and nothing reserved for it.

`assess_claim_finality` compared `blocks_left >= burial` — the condition for a claim that is
already confirmed. A claim being decided on has not been broadcast yet, so it cannot be mined at
the current height, and its burial can only start at the next one.

WHAT #511's BODY CLAIMS IS NOT WHAT IS WRONG HERE, and the distinction decided the fix. It
describes the maker winning a mempool race: broadcast a minimum-fee refund the instant CSV matures,
and every node that saw it first rejects the taker's claim as `txn-mempool-conflict`, with no RBF to
outbid. That attack does not work. Radiant Core `validation.cpp:718-728` accepts a BIP68-locked
transaction into the mempool ONLY if it "can be mined in the next block", so the maker cannot
pre-broadcast, and a claim already sitting in the mempool is the one that wins. The issue's own
TITLE says as much — "eviction/reorg, not a lost mempool race" — and its body was never updated.

What survives verification is narrower and is still real: an UNCONFIRMED claim sitting through
maturity is exposed, because Radiant has no RBF and no CPFP, so a claim evicted from the mempool
(~8h expiry) cannot be bumped back in, and at maturity the maker's refund becomes valid. The
defence is to stop certifying SAFE at heights where the claim cannot CONFIRM and bury in time.
"""

from __future__ import annotations

import pytest

import pyrxd.btc_wallet.taproot as t
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.gravity.swap_coordinator import (
    ClaimFinality,
    MarginPolicy,
    assess_claim_finality,
)

_LOCK = 1_000
_T_RXD = 72
_BURIAL = 6


def _policy(*, inclusion: int | None = None) -> MarginPolicy:
    kw = {}
    if inclusion is not None:
        kw["rxd_claim_inclusion"] = t.Timelock(inclusion, t.TimeUnit.BLOCKS)
    return MarginPolicy(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        rxd_claim_burial=t.Timelock(_BURIAL, t.TimeUnit.BLOCKS),
        accept_flat_burial=True,
        **kw,
    )


def _verdict(blocks_left: int, *, policy: MarginPolicy | None = None) -> ClaimFinality:
    return assess_claim_finality(
        t_rxd=t.Timelock(_T_RXD, t.TimeUnit.BLOCKS),
        policy=policy or _policy(),
        counter_claim_finality=CounterClaimFinality.from_btc_depth(confirmations=10, required_depth=6),
        now_rxd_height=_LOCK + _T_RXD - blocks_left,
        asset_locked_at_height=_LOCK,
    )


class TestTheClaimNeedsBlocksToBeMinedBeforeItCanBury:
    """The floor is `burial + counter_reserve + inclusion`, not `burial + counter_reserve`."""

    def test_the_boundary_is_where_the_claim_can_still_bury_in_time(self) -> None:
        """Stated as the ARITHMETIC, not as a number, so a changed default moves the test with it.

        A claim decided on at height `H` is mined no earlier than `H + 1` and, allowing the
        reserve, by `H + inclusion`. It reaches depth `burial` at `H + inclusion + burial - 1`,
        which must land STRICTLY BEFORE the refund opens.
        """
        inclusion = 2
        floor = _BURIAL + inclusion  # counter_reserve is 0 on a BTC counter leg
        assert _verdict(floor) is ClaimFinality.SAFE
        assert _verdict(floor - 1) is ClaimFinality.SQUEEZED

        # ...and the floor is the honest one: at exactly `floor` the claim buries one block before
        # the refund; one less and it buries exactly AT it, where the refund is also valid.
        now = _LOCK + _T_RXD - floor
        assert (now + inclusion) + _BURIAL - 1 < _LOCK + _T_RXD
        now_short = _LOCK + _T_RXD - (floor - 1)
        assert (now_short + inclusion) + _BURIAL - 1 >= _LOCK + _T_RXD

    def test_the_OLD_floor_certified_a_claim_that_could_not_bury_in_time(self) -> None:
        """The defect, stated on the value that used to pass.

        `blocks_left == burial` was SAFE. Even mined in the very NEXT block — the most optimistic
        assumption available — such a claim reaches depth `burial` exactly AT the refund height,
        where the maker's refund is simultaneously valid. It must not be SAFE.
        """
        assert _verdict(_BURIAL) is ClaimFinality.SQUEEZED
        assert (_LOCK + _T_RXD - _BURIAL + 1) + _BURIAL - 1 == _LOCK + _T_RXD  # buries exactly at it

    def test_a_ROOMY_window_is_still_SAFE(self) -> None:
        """The paired honest path. A reserve that squeezes ordinary swaps forfeits assets on a
        chain where a missed claim cannot be bumped — the refusal has to stay narrow."""
        assert _verdict(_T_RXD) is ClaimFinality.SAFE
        assert _verdict(_BURIAL + 8) is ClaimFinality.SAFE

    @pytest.mark.parametrize("inclusion", [1, 2, 3, 6])
    def test_the_reserve_is_a_POLICY_knob_and_moves_the_boundary(self, inclusion: int) -> None:
        """Pins that the floor tracks the configured reserve rather than a baked-in constant — an
        operator who measures their own inclusion behaviour must be able to use the measurement."""
        pol = _policy(inclusion=inclusion)
        floor = _BURIAL + inclusion
        assert _verdict(floor, policy=pol) is ClaimFinality.SAFE
        assert _verdict(floor - 1, policy=pol) is ClaimFinality.SQUEEZED


class TestTheFundGateAndTheClaimGateAgree:
    """They disagreed by exactly one block before #511, on the permissive side: the fund gate
    required `burial + reserve + 1` and the assessor required `burial + reserve`. A swap could be
    funded against the stricter floor and then certified SAFE by the looser one."""

    def test_both_gates_read_the_same_floor_function(self) -> None:
        from pyrxd.gravity import swap_coordinator as sc

        pol = _policy()
        floor = sc._claim_floor_blocks(pol, burial=_BURIAL, counter_reserve=0)
        assert floor == _BURIAL + 2
        # the claim-time gate's boundary IS that number
        assert _verdict(floor) is ClaimFinality.SAFE
        assert _verdict(floor - 1) is ClaimFinality.SQUEEZED

    def test_the_counter_leg_reserve_widens_it_the_same_way_for_both(self) -> None:
        from pyrxd.gravity import swap_coordinator as sc

        pol = _policy()
        bare = sc._claim_floor_blocks(pol, burial=_BURIAL, counter_reserve=0)
        with_reserve = sc._claim_floor_blocks(pol, burial=_BURIAL, counter_reserve=5)
        assert with_reserve - bare == 5, "the counter-leg reserve must enter the floor additively"


def test_the_reserve_is_settable_through_the_constructor_a_REAL_VALUE_OPERATOR_USES():
    """Reachability, applied to a config knob.

    `ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS` tells an operator to measure this for a real-value run,
    and `MarginPolicy.measured()` is the constructor such an operator is told to use. A knob
    settable only by building the raw dataclass is not reachable from the documented path — the
    same gap #556 found at subsystem scale, one field wide.
    """
    from pyrxd.gravity.swap_coordinator import ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS

    measured = MarginPolicy.measured(
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        rxd_claim_inclusion=t.Timelock(4, t.TimeUnit.BLOCKS),
    )
    assert measured.rxd_claim_inclusion.value == 4
    # ...and omitting it keeps the documented default rather than silently dropping to zero.
    assert (
        MarginPolicy.measured(
            margin=t.Timelock(36, t.TimeUnit.BLOCKS), block_interval_s=600.0
        ).rxd_claim_inclusion.value
        == ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS
    )

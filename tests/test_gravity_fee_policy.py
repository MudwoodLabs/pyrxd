"""Unit tests for the deadline-aware fee policy (gap-closure A1).

The policy is pure: size + rate in, photons out. No network reads, so every number
below is derivable by hand. Rates are injected, so a node-policy change is a caller
concern, not a code change.

Reference numbers, from the live mainnet node's ``getmempoolinfo`` (read 2026-08-09):
``minrelaytxfee`` 0.01 RXD/kB, ``effective_minrelaytxfee`` 0.10 RXD/kB, and
1 RXD = 100,000,000 photons — so the effective rate is 10,000,000 photons/kB.
"""

from __future__ import annotations

import math

import pytest

from pyrxd.gravity.fee_policy import (
    BITCOIN_MIN_RELAY_SATS_PER_KB,
    DEFAULT_BITCOIN_DEADLINE_FEE_POLICY,
    DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
    MEMPOOL_EXPIRY_HOURS,
    PHOTONS_PER_RXD,
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    RADIANT_MIN_RELAY_PHOTONS_PER_KB,
    DeadlineFeePolicy,
    assert_fee_covers,
    photons_per_kb_from_rxd_per_kb,
)
from pyrxd.security.errors import InsufficientFundsError, ValidationError

# ---------------------------------------------------------------- the reference rates


def test_reference_rates_match_the_node_reading():
    # 0.10 RXD/kB and 0.01 RXD/kB expressed in photons — the two values
    # `getmempoolinfo` reports. Pinned so a hand-edit of either constant is loud.
    assert RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB == 10_000_000
    assert RADIANT_MIN_RELAY_PHOTONS_PER_KB == 1_000_000
    assert int(0.10 * PHOTONS_PER_RXD) == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
    # The EFFECTIVE rate is what binds and it is 10x the nominal one — the default
    # must be the higher of the two, never the friendlier-looking `minrelaytxfee`.
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.relay_fee_per_kb == RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
    assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.relay_fee_per_kb == BITCOIN_MIN_RELAY_SATS_PER_KB
    assert MEMPOOL_EXPIRY_HOURS == 8  # Radiant-Core DEFAULT_MEMPOOL_EXPIRY


@pytest.mark.parametrize(
    ("rxd_per_kb", "expected"),
    [
        (0.10, 10_000_000),  # effective_minrelaytxfee on the reference node
        (0.01, 1_000_000),  # minrelaytxfee on the reference node
        (1.0, 100_000_000),
        (0, 0),
        (0.000_000_01, 1),  # one photon/kB — the smallest representable rate
    ],
)
def test_photons_per_kb_from_rxd_per_kb(rxd_per_kb, expected):
    assert photons_per_kb_from_rxd_per_kb(rxd_per_kb) == expected


def test_photons_per_kb_rounds_up_never_understates_a_floor():
    # A sub-photon rate must not round to zero: a relay floor may only ever err high.
    assert photons_per_kb_from_rxd_per_kb(0.000_000_001) == 1


@pytest.mark.parametrize("bad", [-0.1, float("nan"), float("inf")])
def test_photons_per_kb_rejects_nonsense(bad):
    with pytest.raises(ValidationError):
        photons_per_kb_from_rxd_per_kb(bad)


def test_photons_per_kb_rejects_non_numbers():
    with pytest.raises(ValidationError):
        photons_per_kb_from_rxd_per_kb("0.1")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        photons_per_kb_from_rxd_per_kb(True)  # type: ignore[arg-type]


# ---------------------------------------------------------------- min_relay_fee


@pytest.mark.parametrize(
    ("size", "rate", "expected"),
    [
        (1000, 10_000_000, 10_000_000),  # exactly 1 kB at the effective rate
        (2000, 10_000_000, 20_000_000),
        (266, 10_000_000, 2_660_000),  # a MEASURED RXD HTLC claim (see test_htlc_spend_fee_floor)
        (233, 10_000_000, 2_330_000),  # a MEASURED RXD HTLC refund
        (317, 10_000_000, 3_170_000),  # a MEASURED FT HTLC claim
        (11_000, 10_000_000, 110_000_000),  # an 11 kB tx == 1.1 RXD, for scale
        (1, 10_000_000, 10_000),
        (1, 1, 1),  # ceil(0.001) == 1: never round a floor down to zero
        (1001, 999, 1_000),  # ceil(1000.0) -> 1000 (999.999 rounds up, not down)
        (250, 1_000, 250),
    ],
)
def test_min_relay_fee_is_size_times_rate_rounded_up(size, rate, expected):
    # allow_below_protocol_floor: the last three cases use rates far under Radiant's
    # 1,000,000 photons/kB floor DELIBERATELY, to exercise the rounding arithmetic at
    # sizes where ceil() is observable at all (at 10M/kB every case rounds exactly).
    # The construction guard would otherwise refuse them, correctly — so opt out
    # explicitly rather than weaken the guard. See the guard tests below.
    assert DeadlineFeePolicy(relay_fee_per_kb=rate, allow_below_protocol_floor=True).min_relay_fee(size) == expected


def test_min_relay_fee_matches_ceil_for_a_wide_size_sweep():
    policy = DeadlineFeePolicy(relay_fee_per_kb=10_000_000)
    for size in range(1, 4000, 7):
        assert policy.min_relay_fee(size) == math.ceil(size * 10_000_000 / 1000)


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, "266", None])
def test_min_relay_fee_rejects_a_non_positive_or_non_int_size(bad):
    with pytest.raises(ValidationError, match="size_bytes"):
        DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(bad)


# ---------------------------------------------------------------- urgency multiplier


def test_urgency_multiplier_is_one_without_a_deadline():
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.urgency_multiplier(None) == 1.0


@pytest.mark.parametrize(
    ("blocks_left", "expected"),
    [
        (100, 1.0),  # far outside the horizon
        (6, 1.0),  # exactly at the horizon — no premium yet
        (5, 1.0 + 2.0 * 1 / 6),
        (3, 2.0),  # halfway in => halfway up the ramp
        (1, 1.0 + 2.0 * 5 / 6),
        (0, 3.0),  # at the deadline => the maximum premium
        (-5, 3.0),  # already past it => still the maximum, never more
    ],
)
def test_urgency_multiplier_ramps_linearly_to_the_max(blocks_left, expected):
    # Defaults: horizon 6 blocks, max 3.0 => 1 + 2*(6-b)/6 inside the horizon.
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.urgency_multiplier(blocks_left) == pytest.approx(expected)


def test_urgency_multiplier_is_monotone_non_increasing_in_blocks_left():
    # A closer deadline must never fee LESS than a farther one — the whole point.
    policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    values = [policy.urgency_multiplier(b) for b in range(-3, 20)]
    assert values == sorted(values, reverse=True)


def test_urgency_multiplier_rejects_a_non_int_deadline():
    with pytest.raises(ValidationError, match="blocks_to_deadline"):
        DEFAULT_RADIANT_DEADLINE_FEE_POLICY.urgency_multiplier(2.5)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="blocks_to_deadline"):
        DEFAULT_RADIANT_DEADLINE_FEE_POLICY.urgency_multiplier(True)  # type: ignore[arg-type]


def test_a_flat_policy_never_applies_a_premium():
    flat = DeadlineFeePolicy(max_urgency_multiplier=1.0)
    assert [flat.urgency_multiplier(b) for b in (-1, 0, 3, 99)] == [1.0, 1.0, 1.0, 1.0]
    assert flat.required_fee(266, blocks_to_deadline=0) == flat.min_relay_fee(266)


# ---------------------------------------------------------------- required_fee


def test_required_fee_is_the_floor_without_a_deadline():
    policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    assert policy.required_fee(266) == policy.min_relay_fee(266) == 2_660_000


def test_required_fee_scales_with_the_deadline():
    policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    assert policy.required_fee(266, blocks_to_deadline=6) == 2_660_000  # at the horizon
    assert policy.required_fee(266, blocks_to_deadline=3) == 5_320_000  # x2.0
    assert policy.required_fee(266, blocks_to_deadline=0) == 7_980_000  # x3.0


def test_required_fee_uses_exact_rational_arithmetic_not_floats():
    # 1/3-shaped multipliers are where a float path drifts. 1 + 2*(6-4)/6 = 5/3.
    # A 3-photon/kB rate is a deliberate arithmetic fixture (it makes the base fee
    # exactly 3, so a one-unit float drift is visible), not a realistic node reading —
    # hence the explicit opt-out from the protocol-floor guard.
    policy = DeadlineFeePolicy(
        relay_fee_per_kb=3, urgency_horizon_blocks=6, max_urgency_multiplier=3.0, allow_below_protocol_floor=True
    )
    base = policy.min_relay_fee(1000)  # exactly 3
    assert base == 3
    assert policy.required_fee(1000, blocks_to_deadline=4) == 5  # ceil(3 * 5/3) == 5, exactly


def test_required_fee_rounds_up():
    # 1,000/kB over 101 bytes gives a base of 101 — a size where ceil() is observable.
    # Under Radiant's floor, so opt out explicitly; this is arithmetic, not a node rate.
    policy = DeadlineFeePolicy(
        relay_fee_per_kb=1_000, urgency_horizon_blocks=6, max_urgency_multiplier=2.0, allow_below_protocol_floor=True
    )
    base = policy.min_relay_fee(101)  # ceil(101 * 1000/1000) == 101
    assert base == 101
    # b=5 -> 1 + 1*(1/6) = 7/6; ceil(101 * 7/6) == ceil(117.83) == 118
    assert policy.required_fee(101, blocks_to_deadline=5) == 118


# ---------------------------------------------------------------- construction guards


@pytest.mark.parametrize("bad", [0, -1, 1.5, True, None])
def test_policy_rejects_a_non_positive_rate(bad):
    with pytest.raises(ValidationError, match="relay_fee_per_kb"):
        DeadlineFeePolicy(relay_fee_per_kb=bad)


@pytest.mark.parametrize("bad", [0, -1, 2.5, True, None])
def test_policy_rejects_a_bad_horizon(bad):
    with pytest.raises(ValidationError, match="urgency_horizon_blocks"):
        DeadlineFeePolicy(urgency_horizon_blocks=bad)


@pytest.mark.parametrize("bad", [0.99, -1.0, float("nan"), float("inf"), True, "3.0"])
def test_policy_rejects_a_bad_multiplier(bad):
    # NaN in particular: `NaN < 1.0` is False, so without the isfinite guard a NaN
    # would sail through construction and poison every fee it ever computed.
    with pytest.raises(ValidationError, match="max_urgency_multiplier"):
        DeadlineFeePolicy(max_urgency_multiplier=bad)


def test_policy_is_frozen():
    with pytest.raises(Exception):
        DEFAULT_RADIANT_DEADLINE_FEE_POLICY.relay_fee_per_kb = 1  # type: ignore[misc]


# ---------------------------------------------------------------- the protocol-floor bound
#
# The rate is normally read from a NODE (`getmempoolinfo` -> photons_per_kb_from_rxd_per_kb),
# so it crosses a trust boundary. A lying or misconfigured endpoint could otherwise set an
# arbitrarily low "floor", and with no RBF and no CPFP the resulting spend is unfixable.


@pytest.mark.parametrize("hostile", [1, 999_999, 10])
def test_policy_refuses_a_rate_below_the_chains_own_relay_floor(hostile):
    # 0.00000001 RXD/kB from a hostile node would make the "floor" ~1 photon/kB —
    # thousands of times under the real requirement. Refuse at construction.
    with pytest.raises(ValidationError, match="below the chain's relay floor"):
        DeadlineFeePolicy(relay_fee_per_kb=hostile)


def test_the_sub_floor_opt_out_is_explicit_and_works():
    # regtest / a chain you control legitimately runs lower — but saying so must be a
    # deliberate, greppable act, never a silently-accepted low rate.
    policy = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)
    assert policy.min_relay_fee(266) == 1  # ceil(266 * 1/1000)


def test_the_bound_is_per_chain_not_a_hardcoded_photon_number():
    # Bitcoin's floor is 1,000 SATS/kB; Radiant's is 1,000,000 PHOTONS/kB. A BTC-side
    # policy sized in sats must pass its own chain's floor, not opt out of the guard.
    btc = DeadlineFeePolicy(
        relay_fee_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB, protocol_floor_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB
    )
    assert btc.relay_fee_per_kb == 1_000
    assert btc.allow_below_protocol_floor is False
    # The same rate against Radiant's floor is (correctly) refused.
    with pytest.raises(ValidationError, match="below the chain's relay floor"):
        DeadlineFeePolicy(relay_fee_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB)


def test_the_shipped_bitcoin_default_still_constructs():
    # Module import would blow up if the shipped BTC default were bounded by Radiant's
    # photon floor — a units bug that would break every watchtower refund path at import.
    assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.relay_fee_per_kb == BITCOIN_MIN_RELAY_SATS_PER_KB
    assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.protocol_floor_per_kb == BITCOIN_MIN_RELAY_SATS_PER_KB
    assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.allow_below_protocol_floor is False
    assert DEFAULT_BITCOIN_DEADLINE_FEE_POLICY.min_relay_fee(250) == 250  # 250 vB at 1 sat/vB


def test_the_radiant_default_sits_at_the_effective_rate_ten_x_above_its_own_bound():
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.protocol_floor_per_kb == RADIANT_MIN_RELAY_PHOTONS_PER_KB
    assert DEFAULT_RADIANT_DEADLINE_FEE_POLICY.allow_below_protocol_floor is False
    # The bound is the LEGACY floor, so the effective rate is comfortably inside it: the
    # guard catches hostile lowballs without rejecting a node that reports the old rate.
    assert DeadlineFeePolicy(relay_fee_per_kb=RADIANT_MIN_RELAY_PHOTONS_PER_KB).relay_fee_per_kb == 1_000_000


def test_a_node_reading_that_is_hostile_is_caught_end_to_end():
    # The realistic attack shape: the endpoint reports a rate 1e7x too low in RXD/kB.
    hostile_rate = photons_per_kb_from_rxd_per_kb(0.000_000_01)
    assert hostile_rate == 1
    with pytest.raises(ValidationError, match="below the chain's relay floor"):
        DeadlineFeePolicy(relay_fee_per_kb=hostile_rate)


# ---------------------------------------------------------------- assert_fee_covers


def test_assert_fee_covers_returns_the_requirement_when_covered():
    got = assert_fee_covers(
        fee_value=10_000_000,
        size_bytes=266,
        policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
        blocks_to_deadline=None,
        what="test",
    )
    assert got == 2_660_000


@pytest.mark.parametrize("blocks_left", [0, 1, 2, 3])  # 4+ puts the target under the 5M fixture
def test_assert_fee_covers_does_not_raise_between_the_floor_and_the_urgency_target(blocks_left):
    """REGRESSION TEST: the urgency premium is a TARGET, never a broadcast gate.

    The first cut raised here, which was a fund-loss bug. 5,000,000 photons on a
    266-byte claim is nearly 2x the node's real 2,660,000 floor — the node accepts it
    and mines it — but the premium demands up to 3x, so the old gate refused. Refusing
    does not reduce the fee paid (the whole input is the fee on a single-output
    covenant), it just means the claim never goes out, the counterparty's CSV refund
    opens, and the asset is lost. And because the premium RISES as the deadline closes,
    it refused hardest exactly when claiming mattered most.
    """
    policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    fee = 5_000_000
    assert policy.min_relay_fee(266) == 2_660_000 < fee, "fixture must clear the node floor"
    target = policy.required_fee(266, blocks_to_deadline=blocks_left)
    assert target > fee, "fixture must sit UNDER the urgency target, or it proves nothing"
    got = assert_fee_covers(
        fee_value=fee,
        size_bytes=266,
        policy=policy,
        blocks_to_deadline=blocks_left,
        what="HTLC covenant claim",
    )
    # It returns the premium-inclusive target so the caller can WARN and size its pool.
    assert got == target


def test_assert_fee_covers_still_raises_below_the_node_floor_at_every_urgency():
    # The guard was re-aimed, not weakened: under min_relay_fee the node itself rejects,
    # and with no RBF/CPFP the spend is unfixable — refusing costs nothing there.
    policy = DEFAULT_RADIANT_DEADLINE_FEE_POLICY
    for blocks_left in (None, 0, 1, 3, 6, 100):
        with pytest.raises(InsufficientFundsError) as ei:
            assert_fee_covers(
                fee_value=2_659_999,  # one photon under the 2,660,000 floor
                size_bytes=266,
                policy=policy,
                blocks_to_deadline=blocks_left,
                what="HTLC covenant claim",
            )
        # The shortfall is reported against the HARD floor, not the (larger) target —
        # that is the number an operator must clear to get the spend relayed at all.
        assert ei.value.required == 2_660_000, blocks_left
        assert ei.value.shortfall == 1, blocks_left


def test_assert_fee_covers_accepts_exactly_the_requirement():
    # The boundary is inclusive: paying exactly the floor is sufficient.
    assert_fee_covers(
        fee_value=2_660_000,
        size_bytes=266,
        policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
        what="test",
    )
    with pytest.raises(InsufficientFundsError):
        assert_fee_covers(
            fee_value=2_659_999,
            size_bytes=266,
            policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
            what="test",
        )


def test_assert_fee_covers_names_required_supplied_and_shortfall():
    with pytest.raises(InsufficientFundsError) as ei:
        assert_fee_covers(
            fee_value=546,
            size_bytes=266,
            policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
            what="HTLC covenant claim",
        )
    exc = ei.value
    assert exc.available == 546
    assert exc.required == 2_660_000
    assert exc.shortfall == 2_659_454
    msg = str(exc)
    assert "546" in msg and "2660000" in msg and "2659454" in msg
    assert "266-byte" in msg
    # The message must carry WHY this is fatal rather than merely slow.
    assert "no RBF" in msg and "no CPFP" in msg and "8h" in msg


def test_assert_fee_covers_is_a_validation_error_subclass():
    # Existing `except ValidationError` handlers around the swap stack must keep
    # catching this; InsufficientFundsError only ADDS the machine-readable triple.
    with pytest.raises(ValidationError):
        assert_fee_covers(
            fee_value=1,
            size_bytes=266,
            policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
            what="test",
        )


def test_assert_fee_covers_reports_the_deadline_in_the_message():
    with pytest.raises(InsufficientFundsError, match="3 block\\(s\\) to deadline"):
        assert_fee_covers(
            fee_value=1,
            size_bytes=266,
            policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
            blocks_to_deadline=3,
            what="test",
        )
    with pytest.raises(InsufficientFundsError, match="no deadline"):
        assert_fee_covers(
            fee_value=1,
            size_bytes=266,
            policy=DEFAULT_RADIANT_DEADLINE_FEE_POLICY,
            what="test",
        )


def test_assert_fee_covers_units_are_caller_supplied():
    with pytest.raises(InsufficientFundsError, match="sats"):
        assert_fee_covers(
            fee_value=1,
            size_bytes=250,
            policy=DEFAULT_BITCOIN_DEADLINE_FEE_POLICY,
            what="pre-signed BTC refund",
            unit="sats",
        )

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
    assert DeadlineFeePolicy(relay_fee_per_kb=rate).min_relay_fee(size) == expected


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
    policy = DeadlineFeePolicy(relay_fee_per_kb=3, urgency_horizon_blocks=6, max_urgency_multiplier=3.0)
    base = policy.min_relay_fee(1000)  # exactly 3
    assert base == 3
    assert policy.required_fee(1000, blocks_to_deadline=4) == 5  # ceil(3 * 5/3) == 5, exactly


def test_required_fee_rounds_up():
    policy = DeadlineFeePolicy(relay_fee_per_kb=1_000, urgency_horizon_blocks=6, max_urgency_multiplier=2.0)
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

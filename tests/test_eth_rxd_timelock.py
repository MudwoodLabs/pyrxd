"""Tests for the ETH↔RXD cross-clock timelock bridge (Tier-1 D1/D2).

Pure / offline. Property + fuzz coverage of the absolute-seconds→relative-blocks converter
and the funding-confirmation gate; both are fail-closed.
"""

from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.eth_rxd_timelock import (
    CrossClockMargin,
    assert_covenant_confirms_before_eth_deadline,
    eth_absolute_to_rxd_relative_blocks,
)
from pyrxd.security.errors import ValidationError

_CAP = 0xFFFF


def _margin(a=300, b=600, c=300, d=600):
    return CrossClockMargin(eth_reorg_finality_s=a, rxd_claim_burial_s=b, rxd_confirm_slack_s=c, rounding_slack_s=d)


# ─────────────────────────────────────────────────────── CrossClockMargin ──


def test_margin_total_and_validation():
    assert _margin(1, 2, 3, 4).total_s() == 10
    with pytest.raises(ValidationError):
        CrossClockMargin(eth_reorg_finality_s=-1, rxd_claim_burial_s=0, rxd_confirm_slack_s=0, rounding_slack_s=0)
    with pytest.raises(ValidationError):
        CrossClockMargin(eth_reorg_finality_s=0, rxd_claim_burial_s=0, rxd_confirm_slack_s=0, rounding_slack_s=True)


# ─────────────────────────────────────────────────────── converter (D1) ──


def test_converter_concrete_floor_and_unit():
    # budget = 100000 - 1800(margin) - 0 = 98200s ; /600 = 163.66 -> floor 163 blocks
    m = _margin()  # total 1800
    t = eth_absolute_to_rxd_relative_blocks(
        eth_timeout_unix_s=100_000,
        expected_rxd_lock_time_unix_s=0,
        margin=m,
        rxd_block_interval_s=600.0,
        floor_blocks=12,
    )
    assert t == Timelock(163, TimeUnit.BLOCKS)
    assert t.value * 600.0 <= (100_000 - 1800)  # floor never overshoots the budget


def test_converter_failclosed_no_budget():
    with pytest.raises(ValidationError, match="no RXD timelock budget"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=1000,
            expected_rxd_lock_time_unix_s=1000,
            margin=_margin(),
            rxd_block_interval_s=600.0,
        )


def test_converter_failclosed_below_floor():
    # budget tiny -> blocks below floor
    with pytest.raises(ValidationError, match="below safety floor"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=1801 + 600,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=600.0,
            floor_blocks=12,
        )


def test_converter_failclosed_above_bip68_cap():
    # huge far-future deadline -> > 0xFFFF blocks
    with pytest.raises(ValidationError, match="BIP68 16-bit cap"):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=10**9,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=1.0,
        )


def test_converter_rejects_bad_interval_and_floor():
    with pytest.raises(ValidationError):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=100_000,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=0.0,
        )
    with pytest.raises(ValidationError):
        eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=100_000,
            expected_rxd_lock_time_unix_s=0,
            margin=_margin(),
            rxd_block_interval_s=600.0,
            floor_blocks=0,
        )


@given(
    eth_timeout=st.integers(min_value=1, max_value=4_000_000_000),
    rxd_lock=st.integers(min_value=0, max_value=4_000_000_000),
    m1=st.integers(0, 1_000_000),
    m2=st.integers(0, 1_000_000),
    m3=st.integers(0, 1_000_000),
    m4=st.integers(0, 1_000_000),
    interval=st.floats(min_value=1.0, max_value=3600.0, allow_nan=False, allow_infinity=False),
    floor_blocks=st.integers(min_value=1, max_value=1000),
)
def test_converter_invariants_or_failclosed(eth_timeout, rxd_lock, m1, m2, m3, m4, interval, floor_blocks):
    margin = CrossClockMargin(
        eth_reorg_finality_s=m1, rxd_claim_burial_s=m2, rxd_confirm_slack_s=m3, rounding_slack_s=m4
    )
    budget = eth_timeout - margin.total_s() - rxd_lock
    try:
        t = eth_absolute_to_rxd_relative_blocks(
            eth_timeout_unix_s=eth_timeout,
            expected_rxd_lock_time_unix_s=rxd_lock,
            margin=margin,
            rxd_block_interval_s=interval,
            floor_blocks=floor_blocks,
        )
    except ValidationError:
        blocks = math.floor(budget / interval) if budget > 0 else 0
        assert budget <= 0 or blocks < floor_blocks or blocks > _CAP
        return
    # success → invariants hold
    assert t.unit is TimeUnit.BLOCKS
    assert t.value == math.floor(budget / interval)
    assert floor_blocks <= t.value <= _CAP
    assert t.value * interval <= budget  # floor is conservative — never overshoots the budget


# ─────────────────────────────────────────────────── funding-confirm gate (D2) ──


def test_gate_passes_with_margin_left():
    m = _margin(60, 60, 60, 60)  # total 240
    t = Timelock(10, TimeUnit.BLOCKS)
    # projected = 1000 + 0 + ceil(10*600) = 7000 ; deadline = 7241 - 240 = 7001 > 7000 → OK
    assert_covenant_confirms_before_eth_deadline(
        now_unix_s=1000,
        eth_timeout_unix_s=7241,
        margin=m,
        t_rxd=t,
        rxd_block_interval_s=600.0,
        max_covenant_confirm_wait_s=0,
    )


def test_gate_fails_when_covenant_confirms_too_late():
    m = _margin(60, 60, 60, 60)  # total 240
    t = Timelock(10, TimeUnit.BLOCKS)
    # projected 7000 ; deadline = 7240 - 240 = 7000 ; 7000 >= 7000 → raise
    with pytest.raises(ValidationError, match="confirm too late"):
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=1000,
            eth_timeout_unix_s=7240,
            margin=m,
            t_rxd=t,
            rxd_block_interval_s=600.0,
            max_covenant_confirm_wait_s=0,
        )


def test_gate_failclosed_on_confirm_wait_squeeze():
    m = _margin(60, 60, 60, 60)
    t = Timelock(10, TimeUnit.BLOCKS)
    # pre-lock projection with a confirm-wait budget pushes the open past the deadline
    with pytest.raises(ValidationError, match="confirm too late"):
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=1000,
            eth_timeout_unix_s=7241,
            margin=m,
            t_rxd=t,
            rxd_block_interval_s=600.0,
            max_covenant_confirm_wait_s=600,
        )


def test_gate_requires_blocks_timelock():
    with pytest.raises(ValidationError, match="BLOCKS"):
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=1000,
            eth_timeout_unix_s=10_000,
            margin=_margin(),
            t_rxd=Timelock(600, TimeUnit.SECONDS),
            rxd_block_interval_s=600.0,
            max_covenant_confirm_wait_s=0,
        )

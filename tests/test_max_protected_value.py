"""Direct unit tests for ``swap_coordinator.max_protected_value`` — the pure
value-vs-reorg ceiling helper used by the autonomous claim executor's
defense-in-depth gate (the exact inverse of the coordinator's value-scaled
burial). Ported with the executor from the watchtower line.
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.swap_coordinator import max_protected_value
from pyrxd.security.errors import ValidationError


def test_max_protected_value_arithmetic():
    # value * safety_factor <= burial * cost  =>  ceiling = floor(burial*cost/factor).
    # burial 6, cost 1000/blk, factor 2.0 => floor(6000/2) = 3000.
    assert max_protected_value(rxd_claim_burial_blocks=6, reorg_cost_per_block=1000, safety_factor=2.0) == 3000
    # factor 1.0 (indifference bound) => the full burial*cost budget.
    assert max_protected_value(rxd_claim_burial_blocks=6, reorg_cost_per_block=1000, safety_factor=1.0) == 6000
    # default factor is conservative (>1), so the default ceiling is below the raw budget.
    assert max_protected_value(rxd_claim_burial_blocks=6, reorg_cost_per_block=1000) < 6000


def test_max_protected_value_rejects_bad_inputs():
    for kwargs in (
        {"rxd_claim_burial_blocks": 0, "reorg_cost_per_block": 1000},
        {"rxd_claim_burial_blocks": 6, "reorg_cost_per_block": 0},
        {"rxd_claim_burial_blocks": 6, "reorg_cost_per_block": 1000, "safety_factor": 0.5},
        {"rxd_claim_burial_blocks": True, "reorg_cost_per_block": 1000},  # bool is not an int here
        {"rxd_claim_burial_blocks": 6, "reorg_cost_per_block": 1000, "safety_factor": float("nan")},  # NaN bypass guard
        {"rxd_claim_burial_blocks": 6, "reorg_cost_per_block": 1000, "safety_factor": float("inf")},  # inf rejected
    ):
        with pytest.raises(ValidationError):
            max_protected_value(**kwargs)


def test_max_protected_value_integer_exact_above_2_53():
    # Review INFO: above 2^53 a float division can drift UPWARD; the integer-exact floor must
    # never exceed the true bound. cost = full-supply-scale photons, factor 2.0.
    cost = 1_589_000_000_000_000_000  # ~RXD full supply in photons, > 2^53
    cap = max_protected_value(rxd_claim_burial_blocks=6, reorg_cost_per_block=cost, safety_factor=2.0)
    assert cap == (6 * cost) // 2  # exact, no float drift
    # A non-power-of-two factor still floors exactly (never rounds up).
    cap3 = max_protected_value(rxd_claim_burial_blocks=6, reorg_cost_per_block=cost, safety_factor=3.0)
    assert cap3 * 3 <= 6 * cost  # the defining inequality holds exactly

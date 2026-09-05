"""Every float knob on ``MarginPolicy`` must be FINITE, and its own bounds do not say so.

``__post_init__`` guards ``burial_safety_factor`` with ``< 1.0`` and the three intervals with
``<= 0``. IEEE-754 makes every comparison with NaN False, so ``nan < 1.0`` and ``nan <= 0`` are
both False and NaN passes the bound written to exclude it — **vacuously**, which in the output is
indistinguishable from passing because the value is sound. ``inf`` passes for the honest reason
that it genuinely is above every bound.

Reachable from the shipped CLI: ``argparse(type=float)`` accepts ``nan``/``inf``, and #580 wired
``--burial-safety-factor`` straight to the dataclass. MEASURED before the fix on
``pyrxd-watchtower --measured ... --burial-safety-factor nan``: the policy constructed, the startup
report printed ``burial_safety_factor=nan``, and then every rxd claim race hit
``Fraction(nan)`` inside ``_value_scaled_burial_blocks`` (ValueError; ``inf`` gives OverflowError),
which the gate rewraps as "could not normalise reorg depths to blocks" and ``decide`` turns into
PAGE_SQUEEZED "verify finality manually" — on every tick, for every rxd swap.

That is FAIL-CLOSED: the tower never emits a false SAFE, and this file proves the direction rather
than asserting it. It is still a bug, because **a guard that refuses valid work is a bug**: a
healthy swap gets paged as a squeeze and its operator is pushed to verify finality by hand, under
time pressure, off a typo. ``ClaimExecutor.__init__`` and ``max_protected_value`` already carry
``math.isfinite`` and document this exact hole; ``MarginPolicy`` was the one factor site without it.
"""

from __future__ import annotations

import dataclasses
import math

import pytest

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.gravity.swap_coordinator import (
    ClaimFinality,
    MarginPolicy,
    _float_field_names,
    _value_scaled_burial_blocks,
    assess_claim_finality,
)
from pyrxd.security.errors import ValidationError

_MEASURED = {
    "margin": Timelock(36, TimeUnit.BLOCKS),
    "block_interval_s": 600.0,
    "rxd_block_interval_fast_s": 36.0,
}


# ---------------------------------------------------------------------------
# The derivation, both directions — the check is structural, so its SET must not be hand-typed
# ---------------------------------------------------------------------------


def test_the_float_field_derivation_finds_every_float_and_only_floats():
    """A validator that iterates a hand-kept list of its own field names is how
    ``rxd_claim_inclusion`` shipped with no floor. This one reads the dataclass — so pin that the
    reading works, in both directions, rather than trusting a green run over an empty set."""
    derived = set(_float_field_names(MarginPolicy))
    assert derived, "no float fields found on MarginPolicy — the derivation has broken and the check is vacuous"
    by_hand = {f.name for f in dataclasses.fields(MarginPolicy) if "float" in str(f.type)}
    assert derived == by_hand
    assert "burial_safety_factor" in derived, "the field this defect was found on must be covered"


@pytest.mark.parametrize("field", sorted(_float_field_names(MarginPolicy)))
@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_no_float_knob_accepts_a_non_finite_value(field, bad):
    """Derived over the fields, so a float knob added later is covered without anyone extending
    a list — including one whose own bound would let NaN through the same way."""
    with pytest.raises(ValidationError, match="not finite"):
        MarginPolicy(**{**_MEASURED, "is_measured": True, "require_measured": True, field: bad})


def test_the_shipped_watchtower_flag_is_refused_at_the_cli_edge():
    """Through the PRODUCTION entry point, not the dataclass: ``argparse(type=float)`` parses
    'nan' happily, so the refusal has to survive the whole path an operator actually takes."""
    from pyrxd.gravity.watch.run import _parse_args, _policy_from_args

    argv = ["--records-dir", "/tmp/x", "--measured", "--rxd-block-interval-fast-s", "36", "--accept-flat-burial"]
    with pytest.raises(ValidationError, match="not finite"):
        _policy_from_args(_parse_args([*argv, "--burial-safety-factor", "nan"]))


# ---------------------------------------------------------------------------
# The honest path, paired with every refusal above
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("factor", [1.0, 1.5, 2.0, 10.0, 1e12])
def test_every_finite_factor_at_or_above_break_even_still_constructs(factor):
    """A bound that refuses honest input is a real defect. Nothing finite is newly rejected —
    including the large factors a cautious real-value operator would reach for."""
    assert MarginPolicy.measured(burial_safety_factor=factor, **_MEASURED).burial_safety_factor == factor


def test_a_finite_factor_still_scales_the_burial():
    """The knob must keep WORKING, not merely construct: 3x the factor is 3x the required depth."""
    kw = {**_MEASURED, "rxd_reorg_cost_per_block": 1_000}
    at_one = _value_scaled_burial_blocks(MarginPolicy.measured(burial_safety_factor=1.0, **kw), 10_000)
    at_three = _value_scaled_burial_blocks(MarginPolicy.measured(burial_safety_factor=3.0, **kw), 10_000)
    assert (at_one, at_three) == (10, 30)


def test_a_below_break_even_factor_is_still_refused_for_its_own_reason():
    """The pre-existing bound is untouched — this adds a check, it does not replace one."""
    with pytest.raises(ValidationError, match="below"):
        MarginPolicy.measured(burial_safety_factor=0.5, **_MEASURED)


# ---------------------------------------------------------------------------
# What it prevented: the direction of the failure, measured rather than asserted
# ---------------------------------------------------------------------------


def test_the_non_finite_factor_used_to_squeeze_a_healthy_swap():
    """FAIL-CLOSED, PROVEN. Reconstruct the policy the CLI used to build (bypassing the new
    refusal with ``object.__setattr__``, which is the only way to get one now) and show the gate
    that would have said SAFE saying SQUEEZED instead — a healthy swap paged for manual
    verification. This is the cost the refusal removes; the absence of a false SAFE is why the
    finding is not worse than that.
    """
    healthy = MarginPolicy.measured(rxd_reorg_cost_per_block=1_000, burial_safety_factor=1.0, **_MEASURED)
    verdict = {
        "counter_claim_finality": CounterClaimFinality.from_btc_depth(6, 6),
        "now_rxd_height": 120,
        "asset_locked_at_height": 100,
        "t_rxd": Timelock(72, TimeUnit.BLOCKS),
        "value_at_risk_photons": 1_000,
    }
    assert assess_claim_finality(policy=healthy, **verdict) is ClaimFinality.SAFE

    broken = MarginPolicy.measured(rxd_reorg_cost_per_block=1_000, burial_safety_factor=1.0, **_MEASURED)
    object.__setattr__(broken, "burial_safety_factor", float("nan"))
    assert not math.isfinite(broken.burial_safety_factor)
    with pytest.raises(ValidationError, match="could not normalise reorg depths to blocks"):
        assess_claim_finality(policy=broken, **verdict)

"""Measure Radiant's per-block reorg cost, with provenance, instead of carrying a constant.

``MarginPolicy.rxd_reorg_cost_per_block`` sizes the value-scaled claim burial::

    required_blocks = ceil(value_at_risk_photons * burial_safety_factor / cost_per_block)

It **divides**, so a figure carried over from a period of HIGHER hashrate yields FEWER required
blocks than the chain now warrants — under-burial, silently, in the unsafe direction. A too-LOW
figure only over-buries, which costs time and not funds.

That is not hypothetical drift. Measured off the mainnet node 2026-08-30, difficulty 25,892,399
at the 300 s target is ~371 TH/s, roughly **5x below** a figure recorded a few months earlier,
and the decline is real. Anyone reusing the older number would have under-buried by about that
factor with nothing to signal it. See issue #533.

WHAT THIS MODULE DOES AND DOES NOT AUTOMATE
-------------------------------------------
The quantity bundles four things of very different character:

===================  ==========================  ===============================
component            source                      moves
===================  ==========================  ===============================
hashrate             CHAIN (difficulty)          fast — this is what went stale
block subsidy        CHAIN (reward schedule)     scheduled
cost per unit hash   external, capex amortised   slow
RXD price            external                    fast, no trustworthy on-chain oracle
===================  ==========================  ===============================

The half that went stale is the measurable half. This module does that arithmetic and stamps the
result with its inputs and a timestamp, so a stale measurement can FAIL CLOSED rather than quietly
under-burying. It deliberately does **not** fetch difficulty itself — there is no Radiant
difficulty reader in this package yet, and inventing a transport here would put a network
dependency inside a sizing decision. The operator reads one number off their own node
(``radiant-cli getblockchaininfo`` -> ``difficulty``) and passes it in. Automating that read is
the obvious follow-on and does not change anything below.

It deliberately does not derive the RXD **price** either. A price feed inside fund-safety sizing
is a new attack surface: whoever can move the reported price can shrink the burial.

CONSERVATIVE DIRECTION
----------------------
``cost_per_block`` scales with hashrate and ``required_blocks`` divides by it, so a HIGH hashrate
reading produces FEWER burial blocks. Safety therefore wants the **low** end of the observed
range, not the mean — assume the chain is weaker than average. :func:`measure_rxd_reorg_cost`
accepts a sequence of difficulties and takes a low percentile for exactly this reason. It is the
same discipline ``MarginPolicy.rxd_block_interval_fast_s`` already applies (a p10 fast tail,
chosen because reserves divide by it).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction

from pyrxd.security.errors import ValidationError

__all__ = [
    "DEFAULT_HASHRATE_PERCENTILE",
    "PHOTONS_PER_RXD",
    "ReorgCostMeasurement",
    "hashrate_hs_from_difficulty",
    "low_percentile",
    "measure_rxd_reorg_cost",
]

#: Hashes represented by one unit of difficulty (Bitcoin-family: difficulty-1 target).
_HASHES_PER_DIFFICULTY = 2**32

#: 1 RXD = 100,000,000 photons. Same as ``pyrxd.gravity.fee_policy``'s constant; imported there
#: rather than redefined would be circular, so it is asserted equal by a test instead.
PHOTONS_PER_RXD = 100_000_000

#: Which end of the observed difficulty range to size from. p10 = assume the chain is weaker than
#: it usually is, because a high reading under-buries. NOT the mean.
DEFAULT_HASHRATE_PERCENTILE = 10.0


def hashrate_hs_from_difficulty(difficulty: float, block_interval_s: float) -> float:
    """Network hashrate in hashes/second implied by ``difficulty`` at ``block_interval_s``.

    ``hashrate = difficulty * 2**32 / block_interval_s``. Radiant targets 300 s, so passing
    Bitcoin's 600 s here would report half the true rate — which is the SAFE direction (a lower
    cost means deeper burial), but wrong, so it is validated rather than left to chance.
    """
    if not isinstance(difficulty, (int, float)) or isinstance(difficulty, bool):
        raise ValidationError("difficulty must be a number")
    if not math.isfinite(difficulty) or difficulty <= 0:
        raise ValidationError(f"difficulty must be finite and > 0, got {difficulty!r}")
    if not isinstance(block_interval_s, (int, float)) or isinstance(block_interval_s, bool):
        raise ValidationError("block_interval_s must be a number")
    if not math.isfinite(block_interval_s) or block_interval_s <= 0:
        raise ValidationError(f"block_interval_s must be finite and > 0, got {block_interval_s!r}")
    return float(difficulty) * _HASHES_PER_DIFFICULTY / float(block_interval_s)


def low_percentile(values: Sequence[float], percentile: float) -> float:
    """The ``percentile``-th value of ``values``, nearest-rank, LOW end.

    Nearest-rank rather than interpolated so the result is always an OBSERVED value: an
    interpolated figure between two samples is a number the chain never actually showed.
    """
    if not values:
        raise ValidationError("low_percentile needs at least one value")
    if not isinstance(percentile, (int, float)) or isinstance(percentile, bool):
        raise ValidationError("percentile must be a number")
    if not math.isfinite(percentile) or not (0.0 < percentile <= 100.0):
        raise ValidationError(f"percentile must be in (0, 100], got {percentile!r}")
    ordered = sorted(float(v) for v in values)
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[rank - 1]


@dataclass(frozen=True)
class ReorgCostMeasurement:
    """A per-block reorg cost together with everything needed to tell whether it still holds.

    The whole point is the provenance. A bare ``int`` cannot express "this assumed 1.88 PH/s in
    May", so nothing could notice when the chain moved. Carrying the assumed hashrate and the
    measurement time lets a stale figure fail closed instead of silently under-burying.

    ``max_age_s`` is the operator's judgement about how fast their inputs move — hashrate and RXD
    price both drift, and neither is observable from inside this dataclass. There is deliberately
    no default: picking one here would be an estimate masquerading as a measurement, which is the
    exact failure this module exists to prevent.
    """

    photons_per_block: int
    hashrate_hs: float
    difficulty: float
    block_interval_s: float
    usd_per_hash: float
    rxd_price_usd: float
    measured_at_unix_s: int
    max_age_s: int
    samples: int = 1
    percentile: float = DEFAULT_HASHRATE_PERCENTILE

    def __post_init__(self) -> None:
        if not isinstance(self.photons_per_block, int) or isinstance(self.photons_per_block, bool):
            raise ValidationError("photons_per_block must be an int")
        if self.photons_per_block <= 0:
            raise ValidationError(
                f"photons_per_block must be > 0, got {self.photons_per_block} — a zero or negative "
                "cost would make the value-scaled burial divide by zero or go negative"
            )
        for name in ("hashrate_hs", "difficulty", "block_interval_s", "usd_per_hash", "rxd_price_usd"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ValidationError(f"ReorgCostMeasurement.{name} must be a number")
            if not math.isfinite(value) or value <= 0:
                raise ValidationError(f"ReorgCostMeasurement.{name} must be finite and > 0, got {value!r}")
        for name in ("measured_at_unix_s", "max_age_s", "samples"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValidationError(f"ReorgCostMeasurement.{name} must be an int")
            if value <= 0:
                raise ValidationError(f"ReorgCostMeasurement.{name} must be > 0, got {value}")

    def age_s(self, now_unix_s: int) -> int:
        """Seconds since the measurement. Negative ages raise: a measurement stamped in the future
        is a clock or provenance error, and treating it as very fresh is the unsafe reading."""
        if not isinstance(now_unix_s, int) or isinstance(now_unix_s, bool):
            raise ValidationError("now_unix_s must be an int")
        age = now_unix_s - self.measured_at_unix_s
        if age < 0:
            raise ValidationError(
                f"reorg-cost measurement is stamped {-age}s in the FUTURE (measured_at "
                f"{self.measured_at_unix_s}, now {now_unix_s}) — refusing rather than treating a "
                "clock error as a fresh measurement"
            )
        return age

    def assert_fresh(self, now_unix_s: int) -> None:
        """Raise unless the measurement is still within ``max_age_s``.

        Fails CLOSED on purpose. The alternative — carrying on with a figure whose inputs have
        moved — is the under-burial this exists to prevent, and it is invisible when it happens.
        """
        age = self.age_s(now_unix_s)
        if age > self.max_age_s:
            raise ValidationError(
                f"reorg-cost measurement is {age}s old, past its {self.max_age_s}s bound. It assumed "
                f"{self.hashrate_hs / 1e12:.1f} TH/s (difficulty {self.difficulty:,.0f}) and RXD at "
                f"${self.rxd_price_usd}. Re-measure: the burial depth DIVIDES by this, so a figure "
                "from a period of higher hashrate under-buries in the unsafe direction."
            )


def measure_rxd_reorg_cost(
    *,
    difficulty: float | Sequence[float],
    block_interval_s: float,
    usd_per_hash: float,
    rxd_price_usd: float,
    measured_at_unix_s: int,
    max_age_s: int,
    percentile: float = DEFAULT_HASHRATE_PERCENTILE,
) -> ReorgCostMeasurement:
    """Compute the per-block reorg cost in photons, stamped with its inputs.

    ``difficulty`` may be one reading or a sequence over a lookback window; a sequence is reduced
    by :func:`low_percentile`, because a high reading under-buries (see the module docstring).

    The cost model is the marginal work an attacker must out-spend for one block::

        hashrate      = difficulty * 2**32 / block_interval_s
        usd_per_block = hashrate * block_interval_s * usd_per_hash
        photons       = usd_per_block / rxd_price_usd * PHOTONS_PER_RXD

    ``usd_per_hash`` is the operator's amortised cost of one hash on SHA512/256 hardware. It is
    genuinely a judgement — Radiant's algorithm has no rental market, which is exactly why its
    modest hashrate is not as exposed as a SHA-256 chain of similar size — so it is an input here
    rather than something this function pretends to know.

    Rounded UP: over-stating the attacker's cost would UNDER-bury, so the rounding goes the safe
    way. Computed over ``Fraction`` because float division silently loses integer precision at
    large photon counts, the same reason ``_value_scaled_burial_blocks`` uses exact arithmetic.
    """
    if isinstance(difficulty, (int, float)) and not isinstance(difficulty, bool):
        samples = 1
        chosen = float(difficulty)
    else:
        values = list(difficulty)  # type: ignore[arg-type]
        if not values:
            raise ValidationError("measure_rxd_reorg_cost needs at least one difficulty reading")
        samples = len(values)
        chosen = low_percentile(values, percentile)

    hashrate = hashrate_hs_from_difficulty(chosen, block_interval_s)
    for name, value in (("usd_per_hash", usd_per_hash), ("rxd_price_usd", rxd_price_usd)):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValidationError(f"{name} must be a number")
        if not math.isfinite(value) or value <= 0:
            raise ValidationError(f"{name} must be finite and > 0, got {value!r}")

    usd_per_block = Fraction(hashrate) * Fraction(block_interval_s) * Fraction(usd_per_hash)
    photons = usd_per_block / Fraction(rxd_price_usd) * PHOTONS_PER_RXD
    photons_per_block = -((-photons.numerator) // photons.denominator)  # ceil, exact
    if photons_per_block <= 0:
        raise ValidationError(
            f"the inputs imply a per-block reorg cost of {photons_per_block} photons, which cannot "
            "size a burial. Check usd_per_hash and rxd_price_usd."
        )
    return ReorgCostMeasurement(
        photons_per_block=photons_per_block,
        hashrate_hs=hashrate,
        difficulty=chosen,
        block_interval_s=float(block_interval_s),
        usd_per_hash=float(usd_per_hash),
        rxd_price_usd=float(rxd_price_usd),
        measured_at_unix_s=measured_at_unix_s,
        max_age_s=max_age_s,
        samples=samples,
        percentile=float(percentile),
    )

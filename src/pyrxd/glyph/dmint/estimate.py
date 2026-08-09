"""Hash-rate benchmark + time-to-mint estimator for dMint SHA256d PoW.

Answers "how long will this contract take me to mint?" with three
strictly separated classes of number — the separation is part of the
API, not just the presentation:

**MEASURED**
    :func:`benchmark_sha256d` runs the *same* SHA256d chain the miner
    runs and reports the single-core rate it actually observed on this
    machine. :func:`live_stats` likewise reports the aggregate rate
    observed during a real grind.

**EXACT**
    :func:`estimate_attempts` — ``p``, ``E[attempts]``, and the attempt
    quantiles are closed-form consequences of the verifier predicate.
    No measurement, no assumption, no fitting.

**PROJECTED**
    :func:`project_mint_eta` — every wall-clock ETA, and the aggregate
    rate it divides by. Aggregate rate is ``single-core × workers``:
    **cross-core scaling is not measured**, and real machines fall short
    of linear (shared L3, SMT, thermal/power limits).

Where the probability comes from
--------------------------------

``verify_sha256d_solution`` accepts a digest iff::

    full[0:4] == b"\\x00\\x00\\x00\\x00"
    and int.from_bytes(full[4:12], "big") < min(target, MAX_SHA256D_TARGET)

Since ``MAX_SHA256D_TARGET = 2**63 - 1 < 2**64``, the effective target
never reaches the width of the second field, so those two clauses are
*exactly* the single condition "the top 96 bits of the digest, read
big-endian, are < target": if the low 64 bits are already below a bound
under ``2**64``, the high 32 bits must be zero, and conversely. SHA-256
output is uniform over those 96 bits, and exactly ``target`` of the
``2**96`` values satisfy it, so::

    p            = target / 2**96
    E[attempts]  = 2**96 / target

Cross-check against a number the codebase already asserts elsewhere: at
difficulty 1 (``target = 2**63 - 1``) this gives ``p ≈ 2**-33`` and
``P(at least one hit in a 2**32 V1 nonce sweep) = 1 - (1-p)**(2**32)
≈ 0.3935`` — the "~39% chance" documented on the V1 reroll loop in
``pyrxd.cli.glyph_cmds._mine_claim_with_rerolls``. See
``tests/test_dmint_estimate.py`` for that cross-check as an executable
test.

.. warning::
   ``MAX_SHA256D_TARGET / target`` is the **difficulty multiplier**
   (:func:`~pyrxd.glyph.dmint.target_to_difficulty`), *not* an attempt
   count — it is low by a factor of ``2**96 / MAX_SHA256D_TARGET ≈
   2**33``. At difficulty 1 it claims one expected attempt where the
   true mean is ``2**33 ≈ 8.6 billion``.

Mining is a Bernoulli process, so attempts-to-first-hit is geometric and
therefore **memoryless**: hashes already burned change nothing about the
remaining distribution. That is why this module reports a mean plus
quantiles and never a countdown. It is also why the V1 OP_RETURN reroll
loop does not perturb the estimate: partitioning an i.i.d. hash stream
into 2**32-nonce chunks leaves the total-attempts distribution unchanged,
so one estimate covers V1 (4-byte nonce + rerolls) and V2 (8-byte nonce)
alike.

Layering: this module sits at the end of the subpackage's one-way graph
(``types ← builders ← chain ← miner ← estimate``).

Symbols (12):
    SHA256D_HIT_SPACE, DEFAULT_QUANTILES, DEFAULT_BENCHMARK_SECONDS,
    BENCHMARK_PREIMAGE,
    Sha256dBenchmark, AttemptEstimate, MintEtaProjection, LiveMiningStats,
    benchmark_sha256d, estimate_attempts, attempts_for_quantile,
    project_mint_eta, live_stats
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

from .miner import target_to_difficulty
from .types import MAX_SHA256D_TARGET

# The verifier constrains the digest's top 96 bits (4 zero bytes + an 8-byte
# big-endian value under the target). Uniform SHA-256 output means exactly
# `target` of these 2**96 values are hits — see the module docstring.
SHA256D_HIT_SPACE = 2**96

#: Quantiles reported by default. Geometric ⇒ memoryless, so these describe
#: the *remaining* work at any point in a grind, not a countdown.
DEFAULT_QUANTILES: tuple[float, ...] = (0.5, 0.9, 0.99)

#: Default benchmark duration. Long enough to average over scheduler noise,
#: short enough that a CLI invocation still feels instant.
DEFAULT_BENCHMARK_SECONDS = 0.5

#: Fixed 64-byte benchmark preimage. Real preimages are hashes, so their
#: bytes are irrelevant to throughput; pinning one makes the benchmark's
#: first digest a reproducible value a test can byte-match.
BENCHMARK_PREIMAGE = bytes(range(64))

# Hashes between clock reads inside the benchmark loop. Large enough that
# perf_counter() is a rounding error against the SHA256d work.
_BENCHMARK_BATCH = 4096


@dataclass(frozen=True)
class Sha256dBenchmark:
    """**MEASURED** single-core SHA256d throughput on this machine.

    Every field here was observed, not assumed. Nothing in it accounts
    for multiple cores — see :class:`MintEtaProjection` for that.

    :param hashes:            SHA256d evaluations actually performed.
    :param elapsed_s:         Wall-clock seconds they took.
    :param hashes_per_second: ``hashes / elapsed_s`` — MEASURED, single core.
    :param first_digest:      The digest of nonce 0, produced by the
                              benchmark's own inner loop. Pinning it in a
                              test is what stops a refactor from silently
                              benchmarking a different hash chain.
    """

    hashes: int
    elapsed_s: float
    hashes_per_second: float
    first_digest: bytes


@dataclass(frozen=True)
class AttemptEstimate:
    """**EXACT** attempt statistics for a target — closed form, no measurement.

    :param target:                  The target as supplied.
    :param effective_target:        ``min(target, MAX_SHA256D_TARGET)`` — the
                                    verifier clamps, so the estimate must too.
    :param clamped:                 True iff the supplied target exceeded the
                                    ceiling and was clamped.
    :param difficulty:              ``target_to_difficulty(effective_target)``.
    :param probability_per_attempt: ``p = effective_target / 2**96``.
    :param expected_attempts:       ``1 / p = 2**96 / effective_target``.
    :param quantile_attempts:       ``(quantile, attempts)`` pairs; ``attempts``
                                    is the smallest n with ``P(hit within n) >=
                                    quantile``.
    """

    target: int
    effective_target: int
    clamped: bool
    difficulty: int
    probability_per_attempt: float
    expected_attempts: float
    quantile_attempts: tuple[tuple[float, int], ...]


@dataclass(frozen=True)
class MintEtaProjection:
    """**PROJECTED** wall-clock times. Every field is a projection.

    ``aggregate_hashes_per_second`` assumes *linear* scaling across
    ``workers``, which this library does not measure. Treat it as an
    upper bound: shared L3, SMT siblings, and power/thermal limits all
    pull real aggregate throughput below ``single-core × workers``.

    :param workers:                     Worker count the projection assumes.
    :param single_core_hashes_per_second: The per-core rate fed in (MEASURED
                                        if it came from :func:`benchmark_sha256d`,
                                        otherwise whatever the caller supplied).
    :param aggregate_hashes_per_second: ``single-core × workers`` — PROJECTED.
    :param mean_s:                      ``E[attempts] / aggregate`` — PROJECTED.
    :param quantile_s:                  ``(quantile, seconds)`` pairs — PROJECTED.
    """

    workers: int
    single_core_hashes_per_second: float
    aggregate_hashes_per_second: float
    mean_s: float
    quantile_s: tuple[tuple[float, float], ...]


@dataclass(frozen=True)
class LiveMiningStats:
    """Progress snapshot during a real grind: MEASURED rate, PROJECTED remainder.

    ``observed_hashes_per_second`` is measured — it is the aggregate rate
    the running miner actually achieved, so it needs no scaling assumption.
    The remaining-time fields are projections built on it.

    Because the process is memoryless, the remaining-work distribution is
    identical to the distribution at attempt zero: ``attempts`` already
    burned do **not** reduce ``remaining_mean_s``. This is a distribution,
    not a countdown.

    :param attempts:                   Attempts completed so far.
    :param elapsed_s:                  Seconds elapsed so far.
    :param observed_hashes_per_second: MEASURED aggregate rate.
    :param remaining_mean_s:           PROJECTED mean seconds still to go
                                       (``None`` if no rate is observable yet).
    :param remaining_quantile_s:       PROJECTED ``(quantile, seconds)`` pairs.
    """

    attempts: int
    elapsed_s: float
    observed_hashes_per_second: float
    remaining_mean_s: float | None
    remaining_quantile_s: tuple[tuple[float, float], ...]


def benchmark_sha256d(
    *,
    duration_s: float = DEFAULT_BENCHMARK_SECONDS,
    preimage: bytes = BENCHMARK_PREIMAGE,
    nonce_width: int = 8,
) -> Sha256dBenchmark:
    """Measure this machine's single-core SHA256d rate. **MEASURED.**

    Runs the identical hash chain the miner runs —
    ``sha256(sha256(preimage + nonce).digest()).digest()`` over a
    little-endian nonce — inlined exactly as in
    ``pyrxd.contrib.miner.parallel._worker``. Benchmarking anything else
    (a bare ``sha256``, a stand-in payload) would report a rate the miner
    never achieves.

    The first batch is deliberately one hash wide so ``first_digest``
    falls out of the benchmark's own loop rather than a parallel
    expression that could drift away from it.

    Single core only. Multiply by a worker count at your own risk — see
    :func:`project_mint_eta`.

    :param duration_s:  Target wall-clock duration. The loop overshoots by
                        at most one batch.
    :param preimage:    64-byte preimage to hash against.
    :param nonce_width: 4 (V1) or 8 (V2). Throughput is width-independent
                        in practice; the parameter exists so the benchmark
                        can mirror a specific contract exactly.
    :raises ValidationError: ``duration_s`` is not positive, ``preimage`` is
                             not 64 bytes, ``nonce_width`` is not 4 or 8, or
                             the clock did not advance.
    """
    if duration_s <= 0:
        raise ValidationError(f"duration_s must be positive, got {duration_s}")
    if len(preimage) != 64:
        raise ValidationError(f"preimage must be 64 bytes, got {len(preimage)}")
    if nonce_width not in (4, 8):
        raise ValidationError(f"nonce_width must be 4 or 8, got {nonce_width}")

    sha256 = hashlib.sha256
    hashes = 0
    batch = 1  # first batch is 1 hash wide so `digest` below IS nonce 0's digest
    first_digest: bytes | None = None
    digest = b""
    started = time.perf_counter()
    deadline = started + duration_s
    while True:
        for _ in range(batch):
            nonce = hashes.to_bytes(nonce_width, "little")
            digest = sha256(sha256(preimage + nonce).digest()).digest()
            hashes += 1
        if first_digest is None:
            first_digest = digest
            batch = _BENCHMARK_BATCH
        if time.perf_counter() >= deadline:
            break
    elapsed = time.perf_counter() - started

    if elapsed <= 0:  # pragma: no cover — needs a broken monotonic clock
        raise ValidationError("benchmark clock did not advance; cannot report a rate")
    return Sha256dBenchmark(
        hashes=hashes,
        elapsed_s=elapsed,
        hashes_per_second=hashes / elapsed,
        first_digest=first_digest or b"",
    )


def attempts_for_quantile(target: int, quantile: float) -> int:
    """Attempts needed to hit with probability ``quantile``. **EXACT.**

    The smallest ``n`` with ``1 - (1-p)**n >= quantile``, i.e.
    ``ceil(ln(1-quantile) / ln(1-p))``. Both logs go through
    :func:`math.log1p`, which keeps full precision at the ``p ~ 1e-10``
    scale where ``log(1 - p)`` would round to ``log(1.0) == 0`` and the
    division would blow up.

    :param target:   PoW target (clamped to ``MAX_SHA256D_TARGET``).
    :param quantile: Strictly between 0 and 1.
    :raises ValidationError: ``target < 1`` or ``quantile`` out of range.
    """
    if not 0.0 < quantile < 1.0:
        raise ValidationError(f"quantile must be in (0, 1), got {quantile}")
    p = _hit_probability(target)
    return math.ceil(math.log1p(-quantile) / math.log1p(-p))


def estimate_attempts(
    target: int,
    *,
    quantiles: tuple[float, ...] = DEFAULT_QUANTILES,
) -> AttemptEstimate:
    """Closed-form attempt statistics for a dMint target. **EXACT.**

    ``p = target / 2**96`` and ``E[attempts] = 2**96 / target`` — derived
    from the verifier predicate, not estimated. See the module docstring
    for the derivation and for why the difficulty multiplier
    (``MAX_SHA256D_TARGET / target``) is *not* an attempt count.

    Valid for V1 and V2 alike: rerolling a V1 preimage after a
    2**32-nonce sweep re-partitions the same i.i.d. hash stream, which
    leaves the total-attempts distribution untouched.

    :param target:    The contract's ``target`` state field.
    :param quantiles: Quantiles to report, each in (0, 1).
    :raises ValidationError: ``target < 1`` or a quantile is out of range.

    >>> from pyrxd.glyph.dmint import difficulty_to_target, estimate_attempts
    >>> est = estimate_attempts(difficulty_to_target(1))
    >>> round(est.expected_attempts)
    8589934592
    """
    p = _hit_probability(target)
    effective_target = min(target, MAX_SHA256D_TARGET)
    return AttemptEstimate(
        target=target,
        effective_target=effective_target,
        clamped=target > MAX_SHA256D_TARGET,
        difficulty=target_to_difficulty(effective_target),
        probability_per_attempt=p,
        expected_attempts=SHA256D_HIT_SPACE / effective_target,
        quantile_attempts=tuple((q, attempts_for_quantile(target, q)) for q in quantiles),
    )


def project_mint_eta(
    estimate: AttemptEstimate,
    *,
    single_core_hashes_per_second: float,
    workers: int = 1,
) -> MintEtaProjection:
    """Turn EXACT attempt counts into **PROJECTED** wall-clock times.

    Two separate reasons this is a projection and not a measurement:

    1. ``aggregate = single_core × workers`` assumes linear cross-core
       scaling. pyrxd does not measure that, and real machines do not
       achieve it.
    2. Even given a perfect rate, the completion time is a random
       variable. ``mean_s`` is its mean; the quantiles bracket it. There
       is no single "time remaining".

    :param estimate:                     From :func:`estimate_attempts`.
    :param single_core_hashes_per_second: Per-core rate (from
                                         :func:`benchmark_sha256d`, or supplied).
    :param workers:                      Worker count to project across.
    :raises ValidationError: non-positive rate or ``workers < 1``.
    """
    if single_core_hashes_per_second <= 0:
        raise ValidationError(f"single_core_hashes_per_second must be positive, got {single_core_hashes_per_second}")
    if workers < 1:
        raise ValidationError(f"workers must be >= 1, got {workers}")
    aggregate = single_core_hashes_per_second * workers
    return MintEtaProjection(
        workers=workers,
        single_core_hashes_per_second=single_core_hashes_per_second,
        aggregate_hashes_per_second=aggregate,
        mean_s=estimate.expected_attempts / aggregate,
        quantile_s=tuple((q, n / aggregate) for q, n in estimate.quantile_attempts),
    )


def live_stats(attempts: int, elapsed_s: float, estimate: AttemptEstimate) -> LiveMiningStats:
    """Snapshot a running grind: MEASURED rate + PROJECTED remaining time.

    Unlike :func:`project_mint_eta`, the aggregate rate here is measured —
    it is what the miner actually achieved over ``elapsed_s`` — so no
    scaling assumption is involved. The remaining-time fields are still
    projections, and they do **not** shrink as ``attempts`` grows: the
    geometric distribution is memoryless, so the work remaining after a
    billion misses is distributed exactly as it was at attempt zero.

    :param attempts:  Attempts completed so far (0 is allowed).
    :param elapsed_s: Seconds elapsed so far (0 is allowed; then no rate
                      is observable and the remaining fields are empty).
    :param estimate:  From :func:`estimate_attempts`.
    :raises ValidationError: negative ``attempts`` or ``elapsed_s``.
    """
    if attempts < 0:
        raise ValidationError(f"attempts must be >= 0, got {attempts}")
    if elapsed_s < 0:
        raise ValidationError(f"elapsed_s must be >= 0, got {elapsed_s}")
    observed = attempts / elapsed_s if elapsed_s > 0 else 0.0
    if observed <= 0:
        return LiveMiningStats(
            attempts=attempts,
            elapsed_s=elapsed_s,
            observed_hashes_per_second=0.0,
            remaining_mean_s=None,
            remaining_quantile_s=(),
        )
    return LiveMiningStats(
        attempts=attempts,
        elapsed_s=elapsed_s,
        observed_hashes_per_second=observed,
        remaining_mean_s=estimate.expected_attempts / observed,
        remaining_quantile_s=tuple((q, n / observed) for q, n in estimate.quantile_attempts),
    )


def _hit_probability(target: int) -> float:
    """``p`` for one SHA256d attempt against ``target``. **EXACT.**

    Clamps to ``MAX_SHA256D_TARGET`` exactly as ``verify_sha256d_solution``
    does — an unclamped target above the ceiling would overstate ``p``.
    """
    if target < 1:
        raise ValidationError(f"target must be >= 1, got {target}")
    return min(target, MAX_SHA256D_TARGET) / SHA256D_HIT_SPACE

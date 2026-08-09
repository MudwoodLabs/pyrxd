"""Tests for the dMint hash-rate benchmark + time-to-mint estimator.

The load-bearing tests here are the two that pin the *derivation* rather
than the implementation:

* :class:`TestProbabilityDerivation` proves the closed form against the
  real verifier predicate and against the "~39% chance at difficulty 1"
  figure the CLI's V1 reroll loop already documents.
* :class:`TestBenchmarkHashesTheRealChain` byte-matches the benchmark's
  first digest against an independently computed SHA256d, so a refactor
  cannot quietly benchmark a different hash chain and report a rate the
  miner never achieves.
"""

from __future__ import annotations

import hashlib
import math
import os

import pytest

from pyrxd.glyph.dmint import (
    MAX_SHA256D_TARGET,
    SHA256D_HIT_SPACE,
    attempts_for_quantile,
    benchmark_sha256d,
    difficulty_to_target,
    estimate_attempts,
    live_stats,
    mine_solution,
    project_mint_eta,
    target_to_difficulty,
)
from pyrxd.glyph.dmint.estimate import BENCHMARK_PREIMAGE
from pyrxd.security.errors import MaxAttemptsError, ValidationError


class TestProbabilityDerivation:
    """The estimator's probability must follow from the verifier, not from a guess."""

    def test_hit_space_is_the_top_96_bits(self):
        assert SHA256D_HIT_SPACE == 2**96

    @pytest.mark.parametrize("difficulty", [1, 2, 17, 4096, 2**20])
    def test_expected_attempts_is_two_to_the_96_over_target(self, difficulty: int):
        target = difficulty_to_target(difficulty)
        est = estimate_attempts(target)
        assert est.probability_per_attempt == target / 2**96
        assert est.expected_attempts == pytest.approx(2**96 / target, rel=1e-12)
        # ...and 1/p, i.e. the mean of a Geometric(p).
        assert est.expected_attempts == pytest.approx(1 / est.probability_per_attempt, rel=1e-12)

    def test_predicate_equivalence_top96_bits_vs_verifier_clauses(self):
        """``digest[:4]==0 and int(digest[4:12]) < T`` == ``int(digest[:12]) < T``.

        That equivalence is the whole reason ``p = target / 2**96``. It holds
        because the effective target is < 2**64, so a low-64 value below it
        forces the high 32 bits to zero. Checked against random digests plus
        hand-built boundary cases (all-zero prefix, prefix off by the least
        significant bit, low word at exactly the target).
        """
        targets = [1, 2, 1000, MAX_SHA256D_TARGET, MAX_SHA256D_TARGET // 7]
        samples = [os.urandom(32) for _ in range(2000)]
        for t in targets:
            samples.append(b"\x00" * 4 + t.to_bytes(8, "big") + os.urandom(20))  # == target
            samples.append(b"\x00" * 4 + (t - 1).to_bytes(8, "big") + os.urandom(20))  # == target - 1
            samples.append(b"\x00\x00\x00\x01" + (t - 1).to_bytes(8, "big") + os.urandom(20))  # nonzero prefix
        for digest in samples:
            top96 = int.from_bytes(digest[:12], "big")
            for t in targets:
                verifier_clauses = digest[:4] == b"\x00\x00\x00\x00" and int.from_bytes(digest[4:12], "big") < t
                assert verifier_clauses == (top96 < t), (digest[:12].hex(), t)

    def test_counting_argument_on_a_scaled_down_analogue(self):
        """Exactly ``target`` of the value space are hits — checked exhaustively.

        The real space is 2**96 values, so the argument is verified on a
        miniature with the same shape: a 4-bit "zero prefix" plus an 8-bit
        low word, target < 2**8.
        """
        for t in range(1, 2**8):
            hits = sum(
                1
                for prefix in range(2**4)
                for low in range(2**8)
                if prefix == 0 and low < t  # the verifier's two clauses
            )
            assert hits == t

    def test_difficulty_one_matches_the_39_percent_figure_in_the_cli(self):
        """Cross-check against `_mine_claim_with_rerolls`'s "~39% at difficulty 1".

        That comment is an independent statement of the same physics, written
        before this module existed. With the correct ``p`` the V1 nonce space
        (2**32 attempts) yields ``1 - (1-p)**(2**32) ≈ 0.3935``. With the
        difficulty multiplier misused as an attempt count it would be ~100%,
        which is why that formula is not what this module implements.
        """
        p = estimate_attempts(difficulty_to_target(1)).probability_per_attempt
        chance = -math.expm1(2**32 * math.log1p(-p))
        assert chance == pytest.approx(0.3935, abs=0.0005)
        assert 0.38 < chance < 0.40, "the ~39% figure documented on the V1 reroll loop no longer holds"

    def test_difficulty_multiplier_is_not_an_attempt_count(self):
        """Guard against re-introducing ``MAX_SHA256D_TARGET / target``.

        It is off by ``2**96 / MAX_SHA256D_TARGET ≈ 2**33`` — at difficulty 1
        it claims *one* expected attempt where the true mean is ~8.6 billion.
        """
        target = difficulty_to_target(1)
        wrong = MAX_SHA256D_TARGET / target
        assert wrong == 1.0
        est = estimate_attempts(target)
        assert est.expected_attempts / wrong == pytest.approx(2**33, rel=1e-9)
        assert est.expected_attempts > 8e9

    def test_expected_attempts_scales_with_difficulty(self):
        low = estimate_attempts(difficulty_to_target(1)).expected_attempts
        high = estimate_attempts(difficulty_to_target(1024)).expected_attempts
        assert high == pytest.approx(low * 1024, rel=1e-9)

    def test_target_above_the_ceiling_is_clamped_like_the_verifier(self):
        est = estimate_attempts(MAX_SHA256D_TARGET * 4)
        assert est.clamped is True
        assert est.effective_target == MAX_SHA256D_TARGET
        assert est.probability_per_attempt == MAX_SHA256D_TARGET / 2**96
        assert est.difficulty == target_to_difficulty(MAX_SHA256D_TARGET)

    def test_rejects_non_positive_target(self):
        with pytest.raises(ValidationError, match="target must be >= 1"):
            estimate_attempts(0)


class TestQuantiles:
    def test_median_is_ln2_times_the_mean(self):
        est = estimate_attempts(difficulty_to_target(1))
        median = dict(est.quantile_attempts)[0.5]
        assert median == pytest.approx(math.log(2) * est.expected_attempts, rel=1e-6)

    def test_quantiles_are_increasing(self):
        est = estimate_attempts(difficulty_to_target(64))
        values = [n for _, n in est.quantile_attempts]
        assert values == sorted(values)
        assert len(set(values)) == len(values)

    def test_quantile_attempts_realise_the_stated_probability(self):
        """``1 - (1-p)**n >= q`` at n, and ``< q`` one attempt earlier."""
        target = difficulty_to_target(8)
        p = estimate_attempts(target).probability_per_attempt
        for q in (0.5, 0.9, 0.99):
            n = attempts_for_quantile(target, q)
            assert -math.expm1(n * math.log1p(-p)) >= q
            assert -math.expm1((n - 1) * math.log1p(-p)) < q

    def test_log1p_keeps_precision_where_the_naive_form_collapses(self):
        """At a real high-difficulty ``p``, ``log(1 - p)`` is exactly 0.0.

        ``1 - p`` rounds to ``1.0`` once ``p`` drops below the double's
        epsilon, so the naive denominator becomes zero and the quantile
        divides by it. ``log1p(-p)`` stays accurate, which is why the
        implementation uses it and why the quantiles below are finite.
        """
        target = difficulty_to_target(2**40)
        p = estimate_attempts(target).probability_per_attempt
        assert 1 - p == 1.0
        assert math.log(1 - p) == 0.0  # naive form: division by zero downstream
        assert math.log1p(-p) == pytest.approx(-p, rel=1e-12)
        assert math.isfinite(attempts_for_quantile(target, 0.9))

    def test_naive_form_would_divide_by_zero_at_high_difficulty(self):
        """State the failure the implementation avoids, not just the fix."""
        p = estimate_attempts(difficulty_to_target(2**40)).probability_per_attempt
        with pytest.raises(ZeroDivisionError):
            math.ceil(math.log1p(-0.9) / math.log(1 - p))

    @pytest.mark.parametrize("bad", [0.0, 1.0, -0.5, 1.5])
    def test_rejects_out_of_range_quantiles(self, bad: float):
        with pytest.raises(ValidationError, match="quantile must be in"):
            attempts_for_quantile(difficulty_to_target(1), bad)


class TestBenchmarkHashesTheRealChain:
    """The benchmark must measure exactly what the miner runs."""

    def test_first_digest_byte_matches_an_independent_sha256d(self):
        """Pin the hash chain: ``sha256(sha256(preimage + nonce))`` at nonce 0.

        Computed here from scratch, not by calling anything in the module
        under test. If a refactor swaps in a single SHA-256, a different
        preimage, or a different nonce encoding, this fails — and the
        reported rate would otherwise silently stop describing the miner.
        """
        expected = hashlib.sha256(hashlib.sha256(BENCHMARK_PREIMAGE + (0).to_bytes(8, "little")).digest()).digest()
        bench = benchmark_sha256d(duration_s=0.01)
        assert bench.first_digest == expected

    def test_first_digest_matches_the_verifier_path_for_v1_width(self):
        expected = hashlib.sha256(hashlib.sha256(BENCHMARK_PREIMAGE + (0).to_bytes(4, "little")).digest()).digest()
        bench = benchmark_sha256d(duration_s=0.01, nonce_width=4)
        assert bench.first_digest == expected

    def test_reports_a_positive_measured_rate(self):
        bench = benchmark_sha256d(duration_s=0.02)
        assert bench.hashes > 0
        assert bench.elapsed_s > 0
        assert bench.hashes_per_second == pytest.approx(bench.hashes / bench.elapsed_s)

    def test_longer_run_hashes_more(self):
        short = benchmark_sha256d(duration_s=0.01)
        longer = benchmark_sha256d(duration_s=0.15)
        assert longer.hashes > short.hashes

    def test_accepts_a_custom_preimage(self):
        preimage = bytes(range(63, -1, -1))
        expected = hashlib.sha256(hashlib.sha256(preimage + (0).to_bytes(8, "little")).digest()).digest()
        assert benchmark_sha256d(duration_s=0.01, preimage=preimage).first_digest == expected

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"duration_s": 0}, "duration_s must be positive"),
            ({"preimage": b"\x00" * 32}, "preimage must be 64 bytes"),
            ({"nonce_width": 7}, "nonce_width must be 4 or 8"),
        ],
    )
    def test_validation(self, kwargs: dict, match: str):
        kwargs.setdefault("duration_s", 0.01)
        with pytest.raises(ValidationError, match=match):
            benchmark_sha256d(**kwargs)


class TestEtaProjection:
    def test_aggregate_is_single_core_times_workers(self):
        est = estimate_attempts(difficulty_to_target(1))
        proj = project_mint_eta(est, single_core_hashes_per_second=1_000_000, workers=8)
        assert proj.aggregate_hashes_per_second == 8_000_000
        assert proj.mean_s == pytest.approx(est.expected_attempts / 8_000_000)

    def test_eta_quantiles_track_attempt_quantiles(self):
        est = estimate_attempts(difficulty_to_target(4))
        proj = project_mint_eta(est, single_core_hashes_per_second=2_000_000, workers=2)
        for (q_a, attempts), (q_s, seconds) in zip(est.quantile_attempts, proj.quantile_s):
            assert q_a == q_s
            assert seconds == pytest.approx(attempts / 4_000_000)

    def test_more_workers_shortens_the_projection_proportionally(self):
        est = estimate_attempts(difficulty_to_target(1))
        one = project_mint_eta(est, single_core_hashes_per_second=1e6, workers=1)
        four = project_mint_eta(est, single_core_hashes_per_second=1e6, workers=4)
        assert one.mean_s == pytest.approx(four.mean_s * 4)

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"single_core_hashes_per_second": 0}, "must be positive"),
            ({"single_core_hashes_per_second": 1e6, "workers": 0}, "workers must be >= 1"),
        ],
    )
    def test_validation(self, kwargs: dict, match: str):
        kwargs.setdefault("single_core_hashes_per_second", 1e6)
        with pytest.raises(ValidationError, match=match):
            project_mint_eta(estimate_attempts(difficulty_to_target(1)), **kwargs)


class TestLiveStatsAreMemoryless:
    def test_observed_rate_is_measured_from_the_grind(self):
        est = estimate_attempts(difficulty_to_target(1))
        stats = live_stats(30_000_000, 3.0, est)
        assert stats.observed_hashes_per_second == pytest.approx(10_000_000)

    def test_remaining_time_does_not_shrink_as_attempts_accumulate(self):
        """The headline honesty property: this is a distribution, not a countdown.

        Same observed rate, 100x the attempts already burned — the projected
        remaining time is identical, because a geometric process forgets.
        """
        est = estimate_attempts(difficulty_to_target(1))
        early = live_stats(10_000_000, 1.0, est)
        late = live_stats(1_000_000_000, 100.0, est)
        assert early.observed_hashes_per_second == late.observed_hashes_per_second
        assert early.remaining_mean_s == late.remaining_mean_s
        assert early.remaining_quantile_s == late.remaining_quantile_s

    def test_no_rate_yet_reports_nothing_rather_than_guessing(self):
        stats = live_stats(0, 0.0, estimate_attempts(difficulty_to_target(1)))
        assert stats.observed_hashes_per_second == 0.0
        assert stats.remaining_mean_s is None
        assert stats.remaining_quantile_s == ()

    @pytest.mark.parametrize(
        ("attempts", "elapsed", "match"),
        [(-1, 1.0, "attempts must be >= 0"), (1, -1.0, "elapsed_s must be >= 0")],
    )
    def test_validation(self, attempts: int, elapsed: float, match: str):
        with pytest.raises(ValidationError, match=match):
            live_stats(attempts, elapsed, estimate_attempts(difficulty_to_target(1)))


class TestMineSolutionProgress:
    """`mine_solution` grows a progress hook without changing what it mines."""

    def test_callback_receives_attempts_and_elapsed(self):
        seen: list[tuple[int, float]] = []
        # An impossible target so the sweep runs to max_attempts; the interval
        # is tiny so a callback certainly fires within the 65536-attempt
        # checkpoint cadence.
        with pytest.raises(MaxAttemptsError):
            mine_solution(
                b"\xab" * 64,
                1,
                nonce_width=4,
                max_attempts=300_000,
                progress=lambda a, e: seen.append((a, e)),
                progress_interval_s=1e-9,
            )
        assert seen, "progress callback never fired"
        attempts = [a for a, _ in seen]
        assert attempts == sorted(attempts)
        assert all(e >= 0 for _, e in seen)

    def test_callback_exception_propagates_so_it_can_impose_a_deadline(self):
        class Stop(Exception):
            pass

        def stop(_attempts: int, _elapsed: float) -> None:
            raise Stop

        with pytest.raises(Stop):
            mine_solution(
                b"\xab" * 64,
                1,
                nonce_width=4,
                max_attempts=10_000_000,
                progress=stop,
                progress_interval_s=1e-9,
            )

    def test_no_callback_still_mines_the_same_nonce(self):
        """The progress plumbing must not perturb the search itself.

        Real PoW cannot be brute-forced in a unit test — the 4-zero-byte
        prefix alone floors the mean at 2**33 attempts — so this follows the
        established pattern in ``tests/test_dmint_v1_mint.py`` and patches
        hashlib so nonce 0 wins.
        """
        from unittest.mock import patch

        winning = b"\x00\x00\x00\x00" + (0).to_bytes(8, "big") + b"\xff" * 20
        results = []
        for progress in (None, lambda a, e: None):
            with patch("pyrxd.glyph.dmint.miner.hashlib") as mock_hashlib:
                mock_hashlib.sha256.return_value.digest.return_value = winning
                results.append(mine_solution(b"\x11" * 64, target=1, nonce_width=4, progress=progress))
        assert results[0].nonce == results[1].nonce == b"\x00\x00\x00\x00"
        assert results[0].attempts == results[1].attempts == 1

    def test_first_checkpoint_lands_on_the_65536_attempt_cadence(self):
        """The callback rides the same 65536-attempt checkpoint as the workers."""
        seen: list[int] = []
        with pytest.raises(MaxAttemptsError):
            mine_solution(
                b"\xcd" * 64,
                1,
                nonce_width=4,
                max_attempts=200_000,
                progress=lambda a, e: seen.append(a),
                progress_interval_s=1e-9,
            )
        # attempts is n+1 at the checkpoint, and n is a multiple of 65536.
        assert seen
        assert all((a - 1) % 65536 == 0 for a in seen), seen

    def test_rejects_non_positive_progress_interval(self):
        with pytest.raises(ValidationError, match="progress_interval_s must be positive"):
            mine_solution(b"\xab" * 64, 1, nonce_width=4, max_attempts=1, progress_interval_s=0)

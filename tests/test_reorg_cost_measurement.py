"""The per-block reorg cost must carry its provenance, and a stale one must fail closed.

Radiant's hashrate fell roughly 5x between two measurements and nothing noticed, because the
figure that depends on it is a bare int. The burial formula DIVIDES by it, so a value from a
period of higher hashrate yields FEWER blocks than the chain warrants — under-burial, silently,
in the unsafe direction (#533).
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.reorg_cost import (
    PHOTONS_PER_RXD,
    ReorgCostMeasurement,
    hashrate_hs_from_difficulty,
    low_percentile,
    measure_rxd_reorg_cost,
)
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.security.errors import ValidationError

# Measured off the Radiant mainnet node 2026-08-30 (getblockchaininfo, block 459,806).
MAINNET_DIFFICULTY = 25_892_399.457
RXD_TARGET_BLOCK_S = 300.0
NOW = 1_788_000_000


def _measure(**kw):
    args = dict(
        difficulty=MAINNET_DIFFICULTY,
        block_interval_s=RXD_TARGET_BLOCK_S,
        usd_per_hash=1e-15,
        rxd_price_usd=0.0002,
        measured_at_unix_s=NOW,
        max_age_s=86_400,
    )
    args.update(kw)
    return measure_rxd_reorg_cost(**args)


class TestHashrateArithmetic:
    def test_reproduces_the_measured_mainnet_hashrate(self) -> None:
        """The figure this was all derived from: ~371 TH/s. Pinned so a change to the constant or
        the block time is visible rather than silently re-sizing every burial."""
        hr = hashrate_hs_from_difficulty(MAINNET_DIFFICULTY, RXD_TARGET_BLOCK_S)
        assert 370.0e12 < hr < 371.5e12, hr

    def test_the_photon_constant_agrees_with_the_fee_policy(self) -> None:
        """Defined twice (importing would be circular), so it is pinned equal instead."""
        from pyrxd.gravity import fee_policy

        assert PHOTONS_PER_RXD == fee_policy.PHOTONS_PER_RXD

    @pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf")])
    def test_non_positive_or_non_finite_difficulty_is_refused(self, bad) -> None:
        with pytest.raises(ValidationError):
            hashrate_hs_from_difficulty(bad, RXD_TARGET_BLOCK_S)

    def test_a_slower_assumed_block_time_reports_LESS_hashrate(self) -> None:
        """Direction check. Less hashrate => lower cost => DEEPER burial, the safe direction. A
        test that only asserted 'it changes' would pass with the division inverted."""
        assert hashrate_hs_from_difficulty(MAINNET_DIFFICULTY, 600.0) < hashrate_hs_from_difficulty(
            MAINNET_DIFFICULTY, 300.0
        )


class TestLowPercentile:
    def test_takes_the_low_end_not_the_mean(self) -> None:
        """A HIGH hashrate reading produces FEWER burial blocks, so safety wants the low end."""
        values = [10.0, 20.0, 30.0, 40.0, 100.0]
        assert low_percentile(values, 10.0) == 10.0
        assert low_percentile(values, 100.0) == 100.0
        assert low_percentile(values, 10.0) < sum(values) / len(values)

    def test_returns_an_OBSERVED_value_never_an_interpolation(self) -> None:
        """Nearest-rank on purpose: an interpolated figure is a number the chain never showed."""
        values = [1.0, 2.0]
        assert low_percentile(values, 50.0) in values

    def test_a_sequence_sizes_from_the_low_percentile(self) -> None:
        spread = _measure(difficulty=[MAINNET_DIFFICULTY, MAINNET_DIFFICULTY * 5], percentile=10.0)
        single = _measure(difficulty=MAINNET_DIFFICULTY)
        assert spread.difficulty == MAINNET_DIFFICULTY
        assert spread.photons_per_block == single.photons_per_block
        assert spread.samples == 2


class TestStaleness:
    def test_a_fresh_measurement_is_accepted(self) -> None:
        """The honest path. A guard that refuses valid work is a bug, so freshness inside the
        bound — including exactly AT it — must pass."""
        m = _measure()
        m.assert_fresh(NOW)
        m.assert_fresh(NOW + 86_400)  # exactly at the bound

    def test_a_stale_measurement_is_REFUSED(self) -> None:
        m = _measure()
        with pytest.raises(ValidationError, match="past its"):
            m.assert_fresh(NOW + 86_401)

    def test_the_refusal_names_the_hashrate_it_assumed(self) -> None:
        """Without this the operator cannot tell whether re-measuring will change anything."""
        m = _measure()
        with pytest.raises(ValidationError, match="TH/s"):
            m.assert_fresh(NOW + 999_999)

    def test_a_measurement_stamped_in_the_FUTURE_is_refused(self) -> None:
        """A clock error must not read as 'very fresh' — that is the unsafe interpretation."""
        m = _measure()
        with pytest.raises(ValidationError, match="FUTURE"):
            m.assert_fresh(NOW - 1)


class TestPolicyIntegration:
    def _policy(self, **kw):
        return MarginPolicy(margin=t.Timelock(36, t.TimeUnit.BLOCKS), block_interval_s=600.0, is_measured=False, **kw)

    def test_a_measurement_populates_the_plain_field(self) -> None:
        """So `_value_scaled_burial_blocks` and the setup gate read it unchanged."""
        m = _measure()
        assert self._policy(reorg_cost=m).rxd_reorg_cost_per_block == m.photons_per_block

    def test_the_bare_int_path_still_works(self) -> None:
        """Back-compat: the watchtower CLI passes an int today. A guard that refuses valid work
        is a bug, and this is the only production caller."""
        assert self._policy(rxd_reorg_cost_per_block=999).rxd_reorg_cost_per_block == 999

    def test_supplying_BOTH_is_refused(self) -> None:
        """Same quantity from two sources. Silently preferring one makes the other look effective
        while doing nothing — which is how a stale figure survives."""
        with pytest.raises(ValidationError, match="BOTH"):
            self._policy(reorg_cost=_measure(), rxd_reorg_cost_per_block=5)


class TestConstructionGuards:
    @pytest.mark.parametrize(
        "field", ["hashrate_hs", "difficulty", "block_interval_s", "usd_per_hash", "rxd_price_usd"]
    )
    def test_non_positive_numeric_fields_are_refused(self, field: str) -> None:
        kw = dict(
            photons_per_block=1,
            hashrate_hs=1.0,
            difficulty=1.0,
            block_interval_s=1.0,
            usd_per_hash=1.0,
            rxd_price_usd=1.0,
            measured_at_unix_s=NOW,
            max_age_s=1,
        )
        kw[field] = 0.0
        with pytest.raises(ValidationError):
            ReorgCostMeasurement(**kw)  # type: ignore[arg-type]

    def test_a_zero_cost_cannot_be_constructed(self) -> None:
        """It would divide by zero in the burial formula."""
        with pytest.raises(ValidationError, match="photons_per_block"):
            ReorgCostMeasurement(
                photons_per_block=0,
                hashrate_hs=1.0,
                difficulty=1.0,
                block_interval_s=1.0,
                usd_per_hash=1.0,
                rxd_price_usd=1.0,
                measured_at_unix_s=NOW,
                max_age_s=1,
            )

    def test_rounding_goes_the_SAFE_way(self) -> None:
        """Over-stating the attacker's cost UNDER-buries, so the cost rounds UP."""
        m = _measure(usd_per_hash=1e-30, rxd_price_usd=1e6)
        assert m.photons_per_block >= 1


class TestTheWatchtowerActuallyUsesIt:
    """Reachability: a measurement type nothing constructs in production is not finished.

    These drive `_reorg_cost_from_args`, the real code path behind `--rxd-difficulty`, rather than
    building a ReorgCostMeasurement by hand — a test that constructs the input itself proves the
    mechanism and not the wiring.
    """

    def _args(self, **kw):
        import argparse

        base = dict(
            rxd_difficulty=None,
            rxd_usd_per_hash=None,
            rxd_price_usd=None,
            rxd_block_interval_s=RXD_TARGET_BLOCK_S,
            reorg_cost_max_age_s=86_400,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_no_difficulty_flag_means_no_measurement(self) -> None:
        """The honest path for every existing invocation: the flags are opt-in, so a watchtower
        that does not use them must behave exactly as before."""
        from pyrxd.gravity.watch.run import _reorg_cost_from_args

        assert _reorg_cost_from_args(self._args()) is None

    def test_the_flags_build_a_real_measurement(self) -> None:
        from pyrxd.gravity.watch.run import _reorg_cost_from_args

        m = _reorg_cost_from_args(
            self._args(rxd_difficulty=MAINNET_DIFFICULTY, rxd_usd_per_hash=1e-15, rxd_price_usd=0.0002)
        )
        assert m is not None
        assert m.photons_per_block > 0
        assert 370.0e12 < m.hashrate_hs < 371.5e12
        assert m.max_age_s == 86_400

    @pytest.mark.parametrize(
        "kw,missing",
        [
            ({"rxd_price_usd": 0.0002}, "--rxd-usd-per-hash"),
            ({"rxd_usd_per_hash": 1e-15}, "--rxd-price-usd"),
        ],
    )
    def test_difficulty_without_the_economics_is_refused(self, kw, missing) -> None:
        """Half the model would size the burial off an incomplete picture. Fail closed, and name
        the flag that is missing rather than the whole set."""
        from pyrxd.gravity.watch.run import _reorg_cost_from_args

        with pytest.raises(ValidationError, match=missing):
            _reorg_cost_from_args(self._args(rxd_difficulty=MAINNET_DIFFICULTY, **kw))

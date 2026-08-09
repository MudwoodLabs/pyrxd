"""Tests for ``pyrxd glyph dmint-estimate`` and the live-progress reporter.

The most important test in this file is
:meth:`TestJsonKeepsMeasuredAndProjectedApart.test_no_eta_or_aggregate_leaks_into_the_measured_block`.
The command's whole reason to exist is that it does not let a projection
be read as a measurement, and the JSON shape is the machine-readable
promise of that. If an ETA ever migrates into the ``measured`` block,
that test fails the build.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli.glyph_estimate import (
    MiningDeadline,
    _format_count,
    _format_duration,
    _format_rate,
    _MiningReporter,
)
from pyrxd.cli.main import cli
from pyrxd.glyph.dmint import difficulty_to_target, estimate_attempts


def _extract_json(output: str) -> dict:
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        raise AssertionError(f"no JSON object found in output:\n{output!r}")
    return json.loads(output[start : end + 1])


# Every ETA/aggregate field name. Named once so the separation test and the
# leak test cannot drift apart.
_PROJECTION_FIELDS = frozenset(
    {"eta_mean_s", "eta_quantile_s", "aggregate_hashes_per_second", "scaling_assumption", "workers"}
)


class TestOfflineEstimate:
    def test_difficulty_renders_the_three_labelled_sections(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "1", "--benchmark-seconds", "0.01"])
        assert result.exit_code == 0, result.output
        assert "MEASURED (this machine" in result.output
        assert "EXACT (closed form" in result.output
        assert "PROJECTED" in result.output
        assert "NOT measured" in result.output
        assert "memoryless" in result.output

    def test_human_output_states_the_exact_formula(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "1", "--benchmark-seconds", "0.01"])
        assert "p = target / 2^96" in result.output
        assert "= 2^96 / target" in result.output

    def test_raw_target_accepts_hex_and_decimal(self, runner: CliRunner) -> None:
        for arg in ("0x7fffffffffffffff", "9223372036854775807"):
            result = runner.invoke(
                cli,
                ["--json", "glyph", "dmint-estimate", "--target", arg, "--hash-rate", "1000000"],
            )
            assert result.exit_code == 0, result.output
            assert _extract_json(result.output)["exact"]["target"] == 9223372036854775807

    def test_quiet_mode_prints_only_the_mean_eta(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            ["--quiet", "glyph", "dmint-estimate", "--difficulty", "1", "--hash-rate", "1000000", "--workers", "1"],
        )
        assert result.exit_code == 0, result.output
        assert float(result.output.strip()) == pytest.approx(8589934592.0 / 1e6)

    def test_clamped_target_is_flagged(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli,
            ["glyph", "dmint-estimate", "--target", "0xffffffffffffffff", "--hash-rate", "1e6"],
        )
        assert result.exit_code == 0, result.output
        assert "clamped" in result.output


class TestJsonKeepsMeasuredAndProjectedApart:
    def _payload(self, runner: CliRunner, *extra: str) -> dict:
        result = runner.invoke(
            cli,
            ["--json", "glyph", "dmint-estimate", "--difficulty", "1", "--workers", "4", *extra],
        )
        assert result.exit_code == 0, result.output
        return _extract_json(result.output)

    def test_top_level_keys_are_the_provenance_split(self, runner: CliRunner) -> None:
        payload = self._payload(runner, "--benchmark-seconds", "0.01")
        assert set(payload) == {"contract", "measured", "assumed", "exact", "projected"}

    def test_no_eta_or_aggregate_leaks_into_the_measured_block(self, runner: CliRunner) -> None:
        """A projection must never be reachable under a "measured" key."""
        payload = self._payload(runner, "--benchmark-seconds", "0.01")
        measured = payload["measured"]
        assert measured is not None
        assert not (_PROJECTION_FIELDS & set(measured)), measured
        assert not any("eta" in k for k in measured)
        # ...and every projection field really is in the projected block.
        assert set(payload["projected"]) >= _PROJECTION_FIELDS

    def test_exact_block_carries_no_wall_clock_at_all(self, runner: CliRunner) -> None:
        payload = self._payload(runner, "--benchmark-seconds", "0.01")
        exact = payload["exact"]
        assert not any(k.endswith("_s") or "eta" in k or "second" in k for k in exact), exact
        assert set(exact) == {
            "target",
            "effective_target",
            "clamped",
            "difficulty",
            "probability_per_attempt",
            "expected_attempts",
            "quantile_attempts",
        }

    def test_projected_block_names_its_own_assumption(self, runner: CliRunner) -> None:
        payload = self._payload(runner, "--benchmark-seconds", "0.01")
        assert "NOT measured" in payload["projected"]["scaling_assumption"]

    def test_benchmarked_run_has_measured_and_no_assumed(self, runner: CliRunner) -> None:
        payload = self._payload(runner, "--benchmark-seconds", "0.01")
        assert payload["assumed"] is None
        assert payload["measured"]["source"] == "benchmark"
        assert payload["measured"]["benchmark_hashes"] > 0

    def test_supplied_rate_has_assumed_and_no_measured(self, runner: CliRunner) -> None:
        payload = self._payload(runner, "--hash-rate", "2000000")
        assert payload["measured"] is None, "nothing was benchmarked; 'measured' must stay empty"
        assert payload["assumed"]["single_core_hashes_per_second"] == 2_000_000
        assert payload["assumed"]["source"] == "--hash-rate"

    def test_measured_and_assumed_are_never_both_populated(self, runner: CliRunner) -> None:
        for extra in (("--benchmark-seconds", "0.01"), ("--hash-rate", "1e6")):
            payload = self._payload(runner, *extra)
            assert (payload["measured"] is None) != (payload["assumed"] is None)

    def test_exact_values_match_the_sdk(self, runner: CliRunner) -> None:
        payload = self._payload(runner, "--hash-rate", "1e6")
        est = estimate_attempts(difficulty_to_target(1))
        assert payload["exact"]["expected_attempts"] == est.expected_attempts
        assert payload["exact"]["probability_per_attempt"] == est.probability_per_attempt
        assert [e["value"] for e in payload["exact"]["quantile_attempts"]] == [n for _, n in est.quantile_attempts]

    def test_offline_run_reports_no_contract(self, runner: CliRunner) -> None:
        assert self._payload(runner, "--hash-rate", "1e6")["contract"] is None


class TestLocatorValidation:
    def test_requires_a_locator(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate"])
        assert result.exit_code != 0
        assert "exactly one" in result.output

    def test_rejects_two_locators(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "1", "--target", "1000"])
        assert result.exit_code != 0
        assert "exactly one" in result.output

    def test_rejects_unparseable_target(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--target", "not-a-number"])
        assert result.exit_code != 0
        assert "could not parse --target" in result.output

    def test_rejects_zero_target(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--target", "0"])
        assert result.exit_code != 0
        assert "--target must be >= 1" in result.output

    def test_rejects_zero_difficulty(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "0"])
        assert result.exit_code != 0
        assert "invalid --difficulty" in result.output

    def test_rejects_zero_workers(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "1", "--workers", "0"])
        assert result.exit_code != 0
        assert "--workers must be >= 1" in result.output

    def test_rejects_non_positive_hash_rate(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "1", "--hash-rate", "0"])
        assert result.exit_code != 0
        assert "--hash-rate must be positive" in result.output


class TestFormatters:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [(0, "0"), (999, "999"), (1000, "1.00 k"), (8_589_934_592, "8.59 G"), (1.5e18, "1.50 E")],
    )
    def test_format_count(self, value: float, expected: str) -> None:
        assert _format_count(value) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(872.0, "872 h/s"), (2_020_000, "2.02 Mh/s"), (28_000_000, "28.00 Mh/s")],
    )
    def test_format_rate(self, value: float, expected: str) -> None:
        assert _format_rate(value) == expected

    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (0.25, "250ms"),
            (12.34, "12.3s"),
            (91, "1m 31s"),
            (3700, "1h 01m"),
            (200_000, "2.3 days"),
            (86400 * 400, "1.1 years"),
            (float("inf"), "unknown"),
            (float("nan"), "unknown"),
        ],
    )
    def test_format_duration(self, seconds: float, expected: str) -> None:
        assert _format_duration(seconds) == expected


class _FakeClock:
    """Monotonic clock the test drives by hand."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class TestMiningReporter:
    def _reporter(self, clock, **kwargs) -> _MiningReporter:
        defaults = {"enabled": True, "deadline_s": None, "print_interval_s": 1.0, "clock": clock}
        defaults.update(kwargs)
        return _MiningReporter(estimate_attempts(difficulty_to_target(1)), **defaults)

    def test_raises_the_deadline_once_the_clock_passes_it(self) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock, deadline_s=10.0)
        clock.now = 9.0
        reporter(1_000_000, 9.0)  # under the deadline: fine
        clock.now = 10.0
        with pytest.raises(MiningDeadline, match="deadline reached"):
            reporter(2_000_000, 10.0)

    def test_no_deadline_never_raises(self) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock, deadline_s=None)
        clock.now = 1e9
        reporter(1, 1e9)

    def test_disabled_reporter_still_enforces_the_deadline(self) -> None:
        """--no-progress must not disable --timeout."""
        clock = _FakeClock()
        reporter = self._reporter(clock, enabled=False, deadline_s=5.0)
        clock.now = 6.0
        with pytest.raises(MiningDeadline):
            reporter(1, 6.0)

    def test_writes_progress_to_stderr_not_stdout(self, capsys) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock)
        clock.now = 2.0
        reporter(20_000_000, 2.0)
        captured = capsys.readouterr()
        assert captured.out == "", "progress must not pollute stdout (--json reads it)"
        assert "mining" in captured.err
        assert "10.00 Mh/s observed" in captured.err

    def test_header_states_the_exact_distribution_once(self, capsys) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock)
        clock.now = 2.0
        reporter(10_000_000, 2.0)
        clock.now = 4.0
        reporter(20_000_000, 4.0)
        err = capsys.readouterr().err
        assert err.count("EXACT: mean 8.59 G attempts") == 1
        assert "not a countdown" in err

    def test_rate_limits_rendered_lines(self, capsys) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock, print_interval_s=5.0)
        clock.now = 5.0
        reporter(1_000_000, 5.0)
        clock.now = 6.0
        reporter(2_000_000, 6.0)  # inside the interval: suppressed
        err = capsys.readouterr().err
        assert err.count("attempts  elapsed") == 1

    def test_disabled_reporter_prints_nothing(self, capsys) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock, enabled=False)
        clock.now = 100.0
        reporter(1_000_000, 100.0)
        reporter.finish()
        assert capsys.readouterr().err == ""

    def test_reports_remaining_as_a_distribution_not_a_countdown(self, capsys) -> None:
        """Same observed rate, 10x the attempts — identical remaining figures."""
        lines = []
        for attempts, elapsed in ((10_000_000, 1.0), (100_000_000, 10.0)):
            clock = _FakeClock()
            reporter = self._reporter(clock)
            clock.now = elapsed
            reporter(attempts, elapsed)
            lines.append(capsys.readouterr().err.rsplit("remaining:", 1)[1].strip())
        assert lines[0] == lines[1]

    def test_measuring_placeholder_before_any_elapsed_time(self, capsys) -> None:
        clock = _FakeClock()
        reporter = self._reporter(clock)
        clock.now = 1.0
        reporter(0, 0.0)
        assert "measuring" in capsys.readouterr().err


class TestEstimateHelpText:
    def test_appears_in_the_glyph_group_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "--help"])
        assert result.exit_code == 0
        assert "dmint-estimate" in result.output

    def test_help_warns_it_is_not_a_countdown(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--help"])
        assert result.exit_code == 0
        assert "memoryless" in result.output


class TestNetworkLocator:
    """The --contract path resolves a live target through the shared helper."""

    def test_contract_target_drives_the_estimate(
        self, runner: CliRunner, tmp_wallet_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pyrxd.cli import glyph_estimate
        from pyrxd.glyph.dmint import DmintContractUtxo, DmintState, build_dmint_v1_contract_script
        from pyrxd.glyph.dmint.types import DmintAlgo
        from pyrxd.glyph.types import GlyphRef

        script = build_dmint_v1_contract_script(
            height=3,
            contract_ref=GlyphRef(txid="ab" * 32, vout=1),
            token_ref=GlyphRef(txid="cd" * 32, vout=0),
            max_height=100,
            reward=1000,
            target=difficulty_to_target(64),
            algo=DmintAlgo.SHA256D,
        )
        utxo = DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=script, state=DmintState.from_script(script))
        monkeypatch.setattr(glyph_estimate, "_fetch_contract", lambda *a, **k: utxo)

        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "--json",
                "glyph",
                "dmint-estimate",
                "--contract",
                f"{'ab' * 32}:0",
                "--hash-rate",
                "1e6",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["contract"]["height"] == 3
        assert payload["contract"]["version"] == "V1"
        assert payload["contract"]["nonce_width"] == 4
        assert payload["exact"]["difficulty"] == 64
        assert payload["exact"]["expected_attempts"] == pytest.approx(
            estimate_attempts(difficulty_to_target(64)).expected_attempts
        )


class TestTerminalRendering:
    """On a tty the progress line is rewritten in place; on a pipe it scrolls."""

    def test_tty_rewrites_one_line_and_pads_over_the_previous(self, capsys, monkeypatch) -> None:
        monkeypatch.setattr("pyrxd.cli.glyph_estimate.sys.stderr.isatty", lambda: True, raising=False)
        clock = _FakeClock()
        reporter = _MiningReporter(
            estimate_attempts(difficulty_to_target(1)),
            enabled=True,
            deadline_s=None,
            print_interval_s=1.0,
            clock=clock,
        )
        clock.now = 2.0
        reporter(20_000_000, 2.0)
        clock.now = 4.0
        reporter(1, 4.0)  # a much shorter line: the pad must clear the old one
        reporter.finish()
        err = capsys.readouterr().err
        assert "\r" in err
        assert err.endswith("\n"), "finish() must close the in-place line"

    def test_finish_is_a_noop_when_nothing_was_rendered(self, capsys) -> None:
        reporter = _MiningReporter(
            estimate_attempts(difficulty_to_target(1)), enabled=True, deadline_s=None, clock=_FakeClock()
        )
        reporter.finish()
        assert capsys.readouterr().err == ""


class TestBenchmarkFailureSurfaces:
    def test_benchmark_error_becomes_a_user_error(self, runner: CliRunner, monkeypatch) -> None:
        from pyrxd.security.errors import ValidationError

        def boom(**_kwargs):
            raise ValidationError("clock did not advance")

        monkeypatch.setattr("pyrxd.cli.glyph_estimate.benchmark_sha256d", boom)
        result = runner.invoke(cli, ["glyph", "dmint-estimate", "--difficulty", "1"])
        assert result.exit_code != 0
        assert "could not benchmark this machine" in result.output


class TestContractLookup:
    """`_fetch_contract` — the only part of the command that touches the network."""

    @staticmethod
    def _utxo(height: int = 3, difficulty: int = 64, *, exhausted: bool = False):
        import dataclasses

        from pyrxd.glyph.dmint import DmintContractUtxo, DmintState, build_dmint_v1_contract_script
        from pyrxd.glyph.dmint.types import DmintAlgo
        from pyrxd.glyph.types import GlyphRef

        script = build_dmint_v1_contract_script(
            height=height,
            contract_ref=GlyphRef(txid="ab" * 32, vout=1),
            token_ref=GlyphRef(txid="cd" * 32, vout=0),
            max_height=100,
            reward=1000,
            target=difficulty_to_target(difficulty),
            algo=DmintAlgo.SHA256D,
        )
        state = DmintState.from_script(script)
        if exhausted:
            # The builder refuses to emit a born-exhausted contract (height >=
            # max_height locks the pool), so age the parsed state instead.
            state = dataclasses.replace(state, height=state.max_height)
        return DmintContractUtxo(txid="ab" * 32, vout=0, value=1, script=script, state=state)

    def _ctx(self, fake_client_factory):
        from pyrxd.cli.config import Config
        from pyrxd.cli.context import CliContext

        return CliContext(
            config=Config(network="mainnet", electrumx="wss://example/", fee_rate=10_000, wallet_path=Path("x")),
            electrumx_url="wss://example/",
            client_factory=fake_client_factory,
        )

    def test_contract_arg_goes_through_the_shared_fetch_helper(self, monkeypatch, fake_client_factory) -> None:
        from pyrxd.cli import glyph_estimate

        async def fake_fetch(_client, txid, vout):
            assert vout == 0
            return self._utxo()

        monkeypatch.setattr(glyph_estimate, "_fetch_dmint_contract", fake_fetch)
        utxo = glyph_estimate._fetch_contract(self._ctx(fake_client_factory), f"{'ab' * 32}:0", None)
        assert utxo.state.height == 3

    def test_token_ref_picks_the_first_live_contract(self, monkeypatch, fake_client_factory) -> None:
        from pyrxd.cli import glyph_estimate
        from pyrxd.glyph import dmint as dmint_pkg

        exhausted = self._utxo(exhausted=True)
        live = self._utxo(height=7)

        async def fake_find(_client, *, token_ref):
            return [exhausted, live]

        monkeypatch.setattr(dmint_pkg, "find_dmint_contract_utxos", fake_find, raising=False)
        utxo = glyph_estimate._fetch_contract(self._ctx(fake_client_factory), None, f"{'cd' * 32}:0")
        assert utxo.state.height == 7

    def test_no_live_contract_is_a_user_error(self, monkeypatch, fake_client_factory) -> None:
        from pyrxd.cli import glyph_estimate
        from pyrxd.cli.errors import UserError
        from pyrxd.glyph import dmint as dmint_pkg

        async def fake_find(_client, *, token_ref):
            return [self._utxo(exhausted=True)]

        monkeypatch.setattr(dmint_pkg, "find_dmint_contract_utxos", fake_find, raising=False)
        with pytest.raises(UserError, match="no live"):
            glyph_estimate._fetch_contract(self._ctx(fake_client_factory), None, f"{'cd' * 32}:0")

    def test_network_failure_points_at_the_offline_path(self, monkeypatch, fake_client_factory) -> None:
        from pyrxd.cli import glyph_estimate
        from pyrxd.cli.errors import NetworkBoundaryError
        from pyrxd.security.errors import NetworkError

        async def fake_fetch(_client, _txid, _vout):
            raise NetworkError("connection refused")

        monkeypatch.setattr(glyph_estimate, "_fetch_dmint_contract", fake_fetch)
        with pytest.raises(NetworkBoundaryError) as exc:
            glyph_estimate._fetch_contract(self._ctx(fake_client_factory), f"{'ab' * 32}:0", None)
        assert "--difficulty" in (exc.value.fix or "")

    def test_human_output_shows_the_contract_block(self, runner: CliRunner, monkeypatch) -> None:
        from pyrxd.cli import glyph_estimate

        monkeypatch.setattr(glyph_estimate, "_fetch_contract", lambda *a, **k: self._utxo())
        result = runner.invoke(
            cli,
            ["glyph", "dmint-estimate", "--contract", f"{'ab' * 32}:0", "--hash-rate", "1e6"],
        )
        assert result.exit_code == 0, result.output
        assert "CONTRACT (from the network)" in result.output
        assert "3 / 100" in result.output
        assert "1,000 photons per mint" in result.output

"""Tests for `pyrxd setup` — Cut 3 onboarding flow."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from pyrxd.cli.main import cli


def _extract_json(output: str) -> dict:
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        raise AssertionError(f"no JSON object found in output:\n{output!r}")
    return json.loads(output[start : end + 1])


def _patches(*, node_ok: bool, electrumx_ok: bool):
    """Return context managers that patch the two probe functions.

    The ElectrumX probe is async; replace it with an async no-op that
    returns the desired truthy/falsy bool. Patching with a plain
    function would return a coroutine that isn't awaited correctly.
    """

    async def _fake_probe(url: str) -> bool:
        return electrumx_ok

    return (
        patch("pyrxd.cli.setup_cmd._probe_local_node", return_value=node_ok),
        patch("pyrxd.cli.setup_cmd._probe_electrumx", new=_fake_probe),
    )


class TestSetupNoInteractive:
    """--no-interactive should never prompt and should produce a JSON-able result."""

    def test_json_output(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "--json", "setup", "--no-interactive"],
            )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["wallet_path"] == str(tmp_wallet_path)
        assert payload["wallet_exists"] is False
        assert payload["node_reachable"] is False
        assert payload["electrumx_reachable"] is False

    def test_quiet_says_todo_when_unready(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "--quiet", "setup", "--no-interactive"],
            )
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "todo"

    def test_quiet_says_ok_when_ready(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        # Pre-create a wallet so the readiness gate flips.
        runner.invoke(cli, ["--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"])
        n, e = _patches(node_ok=True, electrumx_ok=True)
        with n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "--quiet", "setup", "--no-interactive"],
            )
        assert result.exit_code == 0, result.output
        assert result.output.strip() == "ok"


class TestSetupHumanOutput:
    def test_lists_status_lines(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "setup", "--no-interactive"],
            )
        assert result.exit_code == 0, result.output
        for label in ("config:", "node:", "electrumx:", "wallet:"):
            assert label in result.output, f"missing {label!r} in status block"

    def test_shows_next_steps_when_unready(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "setup", "--no-interactive"],
            )
        assert result.exit_code == 0, result.output
        assert "Next steps:" in result.output
        assert "wallet new" in result.output


class TestSetupCoinType:
    """`setup --coin-type` records the SLIP-0044 coin type for `wallet new`."""

    def _run_setup(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path, *coin_args: str):
        """Run `setup` with DEFAULT_CONFIG_PATH redirected into tmp_path."""
        cfg_path = tmp_path / "config.toml"
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with (
            patch("pyrxd.cli.setup_cmd._config.DEFAULT_CONFIG_PATH", cfg_path),
            n,
            e,
        ):
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "--json", "setup", "--no-interactive", *coin_args],
            )
        return result, cfg_path

    def test_default_coin_type_is_512(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        result, _cfg_path = self._run_setup(runner, tmp_path, tmp_wallet_path)
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["coin_type"] == 512
        assert payload["derivation_path"] == "m/44'/512'/0'"

    def test_coin_type_zero_in_payload_and_config(
        self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path
    ) -> None:
        result, cfg_path = self._run_setup(runner, tmp_path, tmp_wallet_path, "--coin-type", "0")
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["coin_type"] == 0
        assert payload["derivation_path"] == "m/44'/0'/0'"
        # Persisted so a subsequent `wallet new` derives at m/44'/0'/0'.
        from pyrxd.cli import config as _config

        assert _config.load(cfg_path).coin_type == 0

    def test_coin_type_512_in_config(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        result, cfg_path = self._run_setup(runner, tmp_path, tmp_wallet_path, "--coin-type", "512")
        assert result.exit_code == 0, result.output
        from pyrxd.cli import config as _config

        assert _config.load(cfg_path).coin_type == 512

    def test_invalid_coin_type_rejected(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        result, _cfg_path = self._run_setup(runner, tmp_path, tmp_wallet_path, "--coin-type", "999")
        assert result.exit_code != 0

    def test_existing_config_updated_in_place(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text('network = "testnet"\nfee_rate = 5000\n')
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with patch("pyrxd.cli.setup_cmd._config.DEFAULT_CONFIG_PATH", cfg_path), n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "--json", "setup", "--coin-type", "0"],
            )
        assert result.exit_code == 0, result.output
        from pyrxd.cli import config as _config

        cfg = _config.load(cfg_path)
        assert cfg.coin_type == 0
        assert cfg.fee_rate == 5000  # untouched

    def test_bare_rerun_does_not_clobber_existing_coin_type(
        self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path
    ) -> None:
        # A prior `setup --coin-type 0` recorded 0; a later bare `setup` (no
        # --coin-type) must report it and leave it intact, not reset it to 512.
        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text('network = "mainnet"\ncoin_type = 0\n')
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with patch("pyrxd.cli.setup_cmd._config.DEFAULT_CONFIG_PATH", cfg_path), n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "--json", "setup", "--no-interactive"],
            )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["coin_type"] == 0  # reported, not reset
        from pyrxd.cli import config as _config

        assert _config.load(cfg_path).coin_type == 0  # still 0 on disk

    def test_human_summary_shows_coin_type(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        cfg_path = tmp_path / "config.toml"
        n, e = _patches(node_ok=False, electrumx_ok=False)
        with patch("pyrxd.cli.setup_cmd._config.DEFAULT_CONFIG_PATH", cfg_path), n, e:
            result = runner.invoke(
                cli,
                ["--wallet", str(tmp_wallet_path), "setup", "--no-interactive", "--coin-type", "0"],
            )
        assert result.exit_code == 0, result.output
        assert "coin type: 0" in result.output
        assert "m/44'/0'/0'" in result.output

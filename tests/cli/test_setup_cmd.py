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

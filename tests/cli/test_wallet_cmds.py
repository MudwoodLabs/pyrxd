"""Tests for `pyrxd wallet new`, `wallet load`, `wallet info`."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pyrxd.cli.main import cli


def _extract_json(output: str) -> dict:
    """Extract trailing JSON object from CLI output (skipping any prompts)."""
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        raise AssertionError(f"no JSON object found in output:\n{output!r}")
    return json.loads(output[start : end + 1])


def _new_wallet_args(tmp_wallet_path: Path, *, json_mode: bool = True) -> list[str]:
    args = ["--wallet", str(tmp_wallet_path)]
    if json_mode:
        args += ["--json", "--yes"]
    args += ["wallet", "new"]
    return args


class TestWalletNew:
    def test_creates_wallet_file(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        assert result.exit_code == 0, result.output
        assert tmp_wallet_path.exists()

    def test_json_emits_mnemonic_and_address(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        payload = _extract_json(result.output)
        assert "mnemonic" in payload
        assert payload["address"].startswith("1")
        assert payload["wallet_path"] == str(tmp_wallet_path)

    def test_mnemonic_word_count(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new", "--mnemonic-words", "24"],
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert len(payload["mnemonic"].split()) == 24

    def test_default_is_12_words(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        payload = _extract_json(result.output)
        assert len(payload["mnemonic"].split()) == 12

    def test_refuses_to_overwrite(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        # Create once.
        result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        assert result.exit_code == 0
        # Try again — must error out, not clobber.
        result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_json_without_yes_errors(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "wallet", "new"],
        )
        assert result.exit_code != 0
        assert "--yes" in result.output


class TestWalletLoad:
    def test_load_missing_file_errors(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "load"],
            input="some-mnemonic\n",
        )
        assert result.exit_code != 0
        assert "no wallet" in result.output

    def test_load_with_correct_mnemonic_succeeds(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        # Create wallet, capture mnemonic.
        new_result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        mnemonic = _extract_json(new_result.output)["mnemonic"]

        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "wallet", "load"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["wallet_path"] == str(tmp_wallet_path)
        assert payload["account"] == 0

    def test_load_with_wrong_mnemonic_exits_3(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        # Create one wallet.
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        # Try to load with a different (valid-shape) mnemonic.
        wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "load"],
            input=f"{wrong}\n",
        )
        assert result.exit_code == 3
        assert "decrypt" in result.output.lower()

    def test_load_with_empty_mnemonic_errors(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "load"],
            input="\n",
        )
        assert result.exit_code != 0
        assert "mnemonic" in result.output

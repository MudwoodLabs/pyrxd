"""Tests for `pyrxd address` and `pyrxd balance`."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pyrxd.cli.main import cli


def _extract_json(output: str) -> dict:
    """Extract the trailing JSON object from CLI output.

    Hidden prompts (``Mnemonic (input hidden): ``) appear in
    ``result.output`` ahead of the JSON body. Slice from the first
    ``{`` to the last ``}``.
    """
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        raise AssertionError(f"no JSON object found in output:\n{output!r}")
    return json.loads(output[start : end + 1])


def _create_wallet(runner: CliRunner, tmp_wallet_path: Path) -> str:
    result = runner.invoke(
        cli,
        ["--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"],
    )
    assert result.exit_code == 0, result.output
    return _extract_json(result.output)["mnemonic"]


class TestAddressCmd:
    def test_index_zero_matches_wallet_new_address(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "address", "--index", "0"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["address"].startswith("1")
        assert payload["path"] == "m/44'/512'/0'/0/0"

    def test_index_specific(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "address", "--index", "5"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["path"] == "m/44'/512'/0'/0/5"

    def test_change_chain(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "address", "--index", "0", "--change"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["path"] == "m/44'/512'/0'/1/0"

    def test_negative_index_errors(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "address", "--index", "-1"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code != 0
        assert "index" in result.output.lower()

    def test_quiet_prints_just_address(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--quiet", "address", "--index", "0"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        # Output is just the address (plus a trailing newline).
        line = result.output.strip().split("\n")[-1]
        assert line.startswith("1")
        # No path or other annotation.
        assert "m/44" not in line


class TestUtxosCmd:
    """Cut 3 — read-only diagnostic. Covered with mocked ElectrumX."""

    def test_no_used_addresses_returns_empty_table(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        # Fresh wallet has no used addresses → empty result.
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "utxos"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        # JSON output should be an empty array.
        body = result.output[result.output.find("[") :].strip()
        assert body == "[]"

    def test_min_photons_flag_accepted(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        mnemonic = _create_wallet(runner, tmp_wallet_path)
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "utxos", "--min-photons", "1000000"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output

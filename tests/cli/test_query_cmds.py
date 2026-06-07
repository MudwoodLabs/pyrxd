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


class TestAddressCoinType:
    """Display strings must reflect the wallet's ACTUAL coin type, not a
    hardcoded 512. A wallet created at coin_type 0 (Photonic / Electron-
    Radiant legacy) must report m/44'/0'/... in its path output.
    """

    def _config_with_coin_type(self, tmp_path: Path, coin_type: int) -> Path:
        cfg = tmp_path / "config.toml"
        cfg.write_text(f'network = "mainnet"\ncoin_type = {coin_type}\n')
        return cfg

    def _create_wallet_with_config(self, runner: CliRunner, tmp_wallet_path: Path, cfg: Path) -> str:
        result = runner.invoke(
            cli,
            ["--config", str(cfg), "--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"],
        )
        assert result.exit_code == 0, result.output
        return _extract_json(result.output)["mnemonic"]

    def test_address_path_reflects_coin_type_zero(
        self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path
    ) -> None:
        cfg = self._config_with_coin_type(tmp_path, 0)
        mnemonic = self._create_wallet_with_config(runner, tmp_wallet_path, cfg)
        result = runner.invoke(
            cli,
            ["--config", str(cfg), "--wallet", str(tmp_wallet_path), "--json", "address", "--index", "0"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        # The coin_type persisted in the wallet file is restored on load, so
        # the path string must show 0 — not the legacy hardcoded 512.
        assert payload["path"] == "m/44'/0'/0'/0/0"
        assert "512" not in payload["path"]

    def test_wallet_new_json_reports_coin_type_and_path(
        self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path
    ) -> None:
        cfg = self._config_with_coin_type(tmp_path, 0)
        result = runner.invoke(
            cli,
            ["--config", str(cfg), "--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"],
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["coin_type"] == 0
        assert payload["path"] == "m/44'/0'/0'"

    def test_default_config_yields_512_path(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        cfg = self._config_with_coin_type(tmp_path, 512)
        mnemonic = self._create_wallet_with_config(runner, tmp_wallet_path, cfg)
        result = runner.invoke(
            cli,
            ["--config", str(cfg), "--wallet", str(tmp_wallet_path), "--json", "address", "--index", "3"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        assert _extract_json(result.output)["path"] == "m/44'/512'/0'/0/3"


class TestExportXpubCoinType:
    """`wallet export-xpub` path output must track the wallet coin type."""

    def test_xpub_path_reflects_coin_type_zero(self, runner: CliRunner, tmp_path: Path, tmp_wallet_path: Path) -> None:
        cfg = tmp_path / "config.toml"
        cfg.write_text('network = "mainnet"\ncoin_type = 0\n')
        new = runner.invoke(
            cli,
            ["--config", str(cfg), "--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"],
        )
        assert new.exit_code == 0, new.output
        mnemonic = _extract_json(new.output)["mnemonic"]
        result = runner.invoke(
            cli,
            ["--config", str(cfg), "--wallet", str(tmp_wallet_path), "--json", "wallet", "export-xpub"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["path"] == "m/44'/0'/0'"


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

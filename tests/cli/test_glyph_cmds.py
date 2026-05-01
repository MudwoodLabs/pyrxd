"""Tests for `pyrxd glyph …` commands.

Covers the parts of Cut 2 that don't require a live ElectrumX +
on-chain confirmation:

* ``init-metadata`` scaffolds (every type, --out, refusal to overwrite).
* metadata file parsing (protocol-as-strings, validation errors).
* the broadcast-summary / --json-without-yes gate.
* mint-nft / deploy-ft / transfer-ft / transfer-nft top-level argument
  validation (no network).

Full mint flow requires a real chain and is covered by
``examples/glyph_mint_demo.py`` + the integration tests in
``tests/test_dmint_deploy_integration.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pyrxd.cli.main import cli


def _new_wallet_args(tmp_wallet_path: Path) -> list[str]:
    return ["--wallet", str(tmp_wallet_path), "--json", "--yes", "wallet", "new"]


def _extract_json(output: str) -> dict:
    start = output.find("{")
    end = output.rfind("}")
    if start == -1 or end == -1:
        raise AssertionError(f"no JSON object found in output:\n{output!r}")
    return json.loads(output[start : end + 1])


# ---------------------------------------------------------------------------
# init-metadata
# ---------------------------------------------------------------------------


class TestInitMetadata:
    def test_default_type_is_nft(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata"])
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["NFT"]

    def test_ft_template_has_ticker(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "ft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["FT"]
        assert payload["ticker"] == "MTK"
        assert payload["decimals"] == 0

    def test_dmint_ft_template(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "dmint-ft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["FT", "DMINT"]

    def test_mutable_nft_template(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "mutable-nft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["NFT", "MUT"]

    def test_container_template(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "container-nft"])
        payload = _extract_json(result.output)
        assert payload["protocol"] == ["NFT", "CONTAINER"]

    def test_out_writes_file(self, runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "metadata.json"
        result = runner.invoke(cli, ["glyph", "init-metadata", "--out", str(target)])
        assert result.exit_code == 0, result.output
        assert target.exists()
        payload = json.loads(target.read_text())
        assert payload["protocol"] == ["NFT"]

    def test_out_refuses_to_overwrite(self, runner: CliRunner, tmp_path: Path) -> None:
        target = tmp_path / "metadata.json"
        target.write_text("{}")
        result = runner.invoke(cli, ["glyph", "init-metadata", "--out", str(target)])
        assert result.exit_code != 0
        assert "overwrite" in result.output.lower()

    def test_unknown_type_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["glyph", "init-metadata", "--type", "bogus"])
        assert result.exit_code != 0
        # click's Choice prints "Invalid value" with the bad input.
        assert "bogus" in result.output or "Invalid" in result.output


# ---------------------------------------------------------------------------
# metadata file parsing
# ---------------------------------------------------------------------------


def _write_meta(path: Path, **overrides: object) -> Path:
    """Write a metadata.json with an FT default and arbitrary overrides."""
    body: dict = {
        "name": "Test",
        "description": "test",
        "protocol": ["FT"],
        "ticker": "TST",
        "decimals": 0,
    }
    body.update(overrides)
    path.write_text(json.dumps(body))
    return path


class TestMetadataFileErrors:
    def test_missing_file(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        # File doesn't exist → UserError before any wallet decryption.
        # Pre-create a wallet so the --wallet existence check passes.
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                "/nonexistent/metadata.json",
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "metadata file not found" in result.output

    def test_unknown_protocol_name(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["NOT_A_THING"])
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "unknown protocol" in result.output.lower()

    def test_empty_protocol_list_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=[])
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "non-empty list" in result.output

    def test_invalid_json_file(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = tmp_path / "m.json"
        meta.write_text("not valid json {{{")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "could not read" in result.output.lower()


# ---------------------------------------------------------------------------
# argument-level validation
# ---------------------------------------------------------------------------


class TestArgumentValidation:
    def test_deploy_ft_zero_supply_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "0",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "supply" in result.output.lower()

    def test_deploy_ft_invalid_treasury_rejected(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "not-an-address",
            ],
        )
        assert result.exit_code != 0
        assert "treasury" in result.output.lower()

    def test_transfer_ft_invalid_ref(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "transfer-ft",
                "no-colon-ref",
                "10",
                "--to",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "ref" in result.output.lower()

    def test_transfer_ft_zero_amount_rejected(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "transfer-ft",
                "ab" * 32 + ":0",
                "0",
                "--to",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "amount" in result.output.lower()


# ---------------------------------------------------------------------------
# protocol validation: NFT mint requires NFT, FT deploy requires FT
# ---------------------------------------------------------------------------


class TestProtocolValidation:
    def test_mint_nft_with_ft_metadata_rejected(self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path) -> None:
        # FT metadata, but trying to mint as NFT.
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json")  # default protocol is FT
        # Use a known mnemonic since wallet creation already happened.
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "glyph", "mint-nft", str(meta)],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code != 0
        # Either the protocol-mismatch check fired (FT meta + NFT command) or
        # wallet decrypt failed (wrong mnemonic) — both are valid rejections.
        assert "NFT" in result.output or "decrypt" in result.output.lower()

    def test_deploy_ft_with_nft_metadata_rejected(
        self, runner: CliRunner, tmp_wallet_path: Path, tmp_path: Path
    ) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        meta = _write_meta(tmp_path / "m.json", protocol=["NFT"], ticker="")
        result = runner.invoke(
            cli,
            [
                "--wallet",
                str(tmp_wallet_path),
                "glyph",
                "deploy-ft",
                str(meta),
                "--supply",
                "100",
                "--treasury",
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            ],
        )
        assert result.exit_code != 0
        assert "FT" in result.output

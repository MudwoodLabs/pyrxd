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

    def test_debug_emits_traceback_on_decrypt_failure(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """--debug must show the chained exception traceback so a user
        can diagnose decrypt failures, but the traceback must NOT
        contain mnemonic values (only variable names from source lines)."""
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = runner.invoke(
            cli,
            ["--debug", "--wallet", str(tmp_wallet_path), "wallet", "load"],
            input=f"{wrong}\n",
        )
        assert result.exit_code == 3
        # The user-facing block is still the static decrypt message.
        assert "Could not decrypt wallet file" in result.output
        # Traceback shows up.
        assert "Traceback" in result.output
        # The mnemonic VALUE must not appear anywhere — only the
        # variable name `mnemonic` in source lines is acceptable.
        # The wrong mnemonic happens to be all "abandon" + "about"
        # which would also appear in random words sometimes; check the
        # specific 12-word phrase.
        assert wrong not in result.output

    def test_no_debug_hides_traceback(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """Without --debug, decrypt failure shows ONLY the static error block."""
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "load"],
            input=f"{wrong}\n",
        )
        assert result.exit_code == 3
        assert "Traceback" not in result.output


class TestMnemonicEdgeCases:
    """Real-world inputs that previously could surface raw exceptions."""

    def test_mnemonic_with_extra_whitespace_normalized(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """`abc  def` (double space) and tabs must not crash — they
        normalize to a single space before validation."""
        new_result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        mnemonic = _extract_json(new_result.output)["mnemonic"]
        # Insert tabs, double-spaces, leading/trailing whitespace.
        mangled = "  " + mnemonic.replace(" ", "  \t ") + "\n  "

        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "wallet", "load"],
            input=f"{mangled}\n",
        )
        assert result.exit_code == 0, result.output

    def test_mnemonic_with_unknown_word_exits_3(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """A word not in the BIP39 list raises ValueError — must surface
        as exit code 3 with the static decrypt-failed message, never as
        a raw traceback."""
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        bad = "notaword " * 11 + "alsobogus"
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "load"],
            input=f"{bad}\n",
        )
        assert result.exit_code == 3
        assert "decrypt" in result.output.lower()
        assert "Traceback" not in result.output
        # The user's input must NEVER appear in the output.
        assert "notaword" not in result.output

    def test_mnemonic_empty_after_normalize_errors(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """All-whitespace input collapses to '' and is rejected up front."""
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "load"],
            input="   \t \n",
        )
        assert result.exit_code != 0
        assert "mnemonic" in result.output.lower()


class TestWalletExportXpub:
    """Cut 3: account-level xpub export for watch-only use."""

    def test_export_with_correct_mnemonic(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        new_result = runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        mnemonic = _extract_json(new_result.output)["mnemonic"]
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "--json", "wallet", "export-xpub"],
            input=f"{mnemonic}\n",
        )
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["xpub"].startswith("xpub")
        assert payload["account"] == 0
        assert payload["path"] == "m/44'/236'/0'"

    def test_export_with_wrong_mnemonic_exits_3(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        runner.invoke(cli, _new_wallet_args(tmp_wallet_path))
        wrong = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "export-xpub"],
            input=f"{wrong}\n",
        )
        assert result.exit_code == 3
        assert "decrypt" in result.output.lower()

    def test_export_no_wallet_errors(self, runner: CliRunner, tmp_wallet_path: Path) -> None:
        """If the wallet file doesn't exist, fail fast — no mnemonic prompt."""
        result = runner.invoke(
            cli,
            ["--wallet", str(tmp_wallet_path), "wallet", "export-xpub"],
            input="anything\n",
        )
        assert result.exit_code != 0
        assert "no wallet" in result.output

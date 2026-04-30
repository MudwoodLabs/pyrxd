"""Top-level CLI tests: --help, --version, global flag plumbing."""

from __future__ import annotations

from click.testing import CliRunner

from pyrxd.cli.main import cli


def test_help_lists_commands(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "wallet" in result.output
    assert "address" in result.output
    assert "balance" in result.output


def test_version(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "pyrxd" in result.output


def test_unknown_subcommand_errors(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["nonexistent"])
    assert result.exit_code != 0
    assert "No such command" in result.output or "Usage:" in result.output


def test_json_and_quiet_mutually_exclusive(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--json", "--quiet", "address", "--index", "0"])
    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_unknown_network_rejected(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--network", "marsnet", "address"])
    assert result.exit_code != 0
    # Click's choice validator emits its own error.
    assert "marsnet" in result.output or "Invalid value" in result.output

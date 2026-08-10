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


def test_wallet_path_with_null_byte_is_a_clean_usage_error(runner: CliRunner) -> None:
    # A path with an embedded null byte raises ValueError deep inside click's
    # Path conversion (os.stat); without _SafePath it escapes as an unhandled
    # traceback with an undocumented exit code. It must be a clean usage error.
    result = runner.invoke(cli, ["--wallet", "\x00", "balance"])
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "invalid path" in result.output.lower()


def test_config_path_with_null_byte_is_a_clean_usage_error(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--config", "\x00", "address"])
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "invalid path" in result.output.lower()


def test_network_flag_cannot_reach_the_mainnet_endpoint(runner: CliRunner, tmp_path, monkeypatch) -> None:
    """END-TO-END regression: `--network regtest` on a stock mainnet config must not
    connect anywhere. It used to silently use the MAINNET ElectrumX server while
    reporting itself as regtest.

    `glyph inspect --fetch` is the cheapest network-touching command that needs no
    wallet, so it exercises the real CliContext.make_client() path.
    """
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
        monkeypatch.delenv(var, raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('network = "mainnet"\nelectrumx = "wss://electrumx.radiant4people.com:50022/"\n')

    result = runner.invoke(
        cli,
        ["--config", str(cfg), "--network", "regtest", "glyph", "inspect", "ab" * 32, "--fetch"],
    )

    assert result.exit_code == 1, result.output
    assert "no ElectrumX endpoint is configured for network 'regtest'" in result.output
    assert "[networks.regtest]" in result.output
    # And it never fell back to mainnet's server.
    assert "radiant4people" not in result.output


def test_electrumx_flag_makes_a_non_default_network_usable(runner: CliRunner, tmp_path, monkeypatch) -> None:
    """The fail-closed path must stay escapable in one flag: naming the endpoint
    alongside --network is an explicit statement about which server serves it."""
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
        monkeypatch.delenv(var, raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('network = "mainnet"\n')

    result = runner.invoke(
        cli,
        [
            "--config",
            str(cfg),
            "--network",
            "regtest",
            "--electrumx",
            "wss://127.0.0.1:50022/",
            "glyph",
            "inspect",
            "ab" * 32,
            "--fetch",
        ],
    )

    # It gets as far as the network (and fails there, offline) rather than being
    # refused at config time.
    assert "no ElectrumX endpoint is configured" not in result.output

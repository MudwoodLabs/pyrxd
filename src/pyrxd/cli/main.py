"""pyrxd CLI entry point.

Command shape (Cut 1 — see docs/wallet-cli-plan.md):

    pyrxd [GLOBAL OPTS] <command> [ARGS]

Global options apply to every subcommand:

    --network          mainnet | testnet | regtest (default: mainnet)
    --electrumx URL    override the configured server
    --wallet PATH      override the configured wallet file
    --json             machine-readable output
    --quiet            suppress progress; print only the bare result
    --no-color         disable ANSI color
    --config PATH      use an alternate config file
    --yes / -y         skip confirmation prompts (required with --json
                       for destructive ops)
    --debug            show full tracebacks on error (default: hide)

Cut 1 commands: wallet (group), address, balance.
Cut 2 commands: glyph (group).
Cut 3 commands: setup, utxos, wallet export-xpub.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .. import __version__ as _pyrxd_version
from . import config as _config
from . import errors as _errors
from .context import CliContext
from .errors import CliError


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(_pyrxd_version, "--version", "-V", prog_name="pyrxd")
@click.option(
    "--network",
    type=click.Choice(["mainnet", "testnet", "regtest"], case_sensitive=False),
    default=None,
    help="Network to use. Overrides the config file.",
)
@click.option(
    "--electrumx",
    "electrumx_url",
    default=None,
    metavar="URL",
    help="ElectrumX WebSocket URL (wss://...).",
)
@click.option(
    "--wallet",
    "wallet_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to encrypted wallet file (default ~/.pyrxd/wallet.dat).",
)
@click.option("--json", "json_output", is_flag=True, help="Machine-readable output.")
@click.option("--quiet", "-q", is_flag=True, help="Print only the bare result.")
@click.option("--no-color", is_flag=True, help="Disable ANSI color.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Alternate config file (default ~/.pyrxd/config.toml).",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompts. Required with --json for destructive ops.",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Show full tracebacks on error (default: hide).",
)
@click.pass_context
def cli(
    click_ctx: click.Context,
    network: str | None,
    electrumx_url: str | None,
    wallet_path: Path | None,
    json_output: bool,
    quiet: bool,
    no_color: bool,
    config_path: Path | None,
    yes: bool,
    debug: bool,
) -> None:
    """pyrxd — wallet, Glyph token, and Gravity-swap CLI for Radiant.

    Use `pyrxd <command> --help` for command-specific options. See the
    repository docs (docs/how-to/cli.md) for the full reference.
    """
    if json_output and quiet:
        click.echo("error: --json and --quiet are mutually exclusive", err=True)
        sys.exit(1)

    # --debug flips the module-global flag that CliError.show() reads.
    # We set it as early as possible so any error during config load
    # also benefits from the traceback.
    _errors.set_debug(debug)

    cfg = _config.load(config_path)

    # Resolve final network: flag > env (already in cfg) > built-in default.
    final_network = network or cfg.network
    cfg = cfg.for_network(final_network)

    ctx = CliContext(
        config=cfg,
        network=final_network,
        electrumx_url=electrumx_url or cfg.electrumx,
        fee_rate=cfg.fee_rate,
        wallet_path=(wallet_path.expanduser() if wallet_path else cfg.wallet_path),
        output_mode=("json" if json_output else "quiet" if quiet else "human"),
        no_color=no_color,
        yes=yes,
        debug=debug,
    )
    click_ctx.obj = ctx


# ---- error boundary ---------------------------------------------------------
#
# CliError is a click.ClickException subclass — click handles its
# formatting + exit code natively. We only wrap unexpected exceptions
# (bug path, exit code 4) here.


def run() -> None:
    """Top-level entry point used by ``[project.scripts]`` and ``__main__``.

    Click handles ``CliError`` (typed user/network/decrypt errors) via
    its native machinery. This wrapper only catches truly unexpected
    exceptions and surfaces them with exit code 4.
    """
    try:
        cli()
    except CliError:
        # Click already handled it (printed + exit). The bare except is
        # defensive — should not be reachable.
        raise
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover — bug path
        click.echo(f"error: unexpected failure ({type(exc).__name__})", err=True)
        click.echo(f"  cause: {exc}", err=True)
        click.echo("  fix: re-run with --debug to see the full traceback", err=True)
        sys.exit(4)


# Subcommand registration. The wallet/address/balance commands attach
# themselves to the `cli` group via @cli.command / @cli.group decorators.
# Subcommand modules are imported here and explicitly registered via
# cli.add_command() below. They do NOT import `cli` from this module —
# that would create an import cycle that CodeQL flags (py/cyclic-import)
# and that breaks static analysis even though Python's import system
# tolerates it at runtime.

from . import glyph_cmds, query_cmds, setup_cmd, wallet_cmds  # noqa: E402

cli.add_command(glyph_cmds.glyph_group)
cli.add_command(query_cmds.address_cmd)
cli.add_command(query_cmds.balance_cmd)
cli.add_command(query_cmds.utxos_cmd)
cli.add_command(setup_cmd.setup_cmd)
cli.add_command(wallet_cmds.wallet_group)


if __name__ == "__main__":
    run()

"""``pyrxd agent`` — the local signing agent CLI surface (issue #8, Path A').

Three subcommands:

* ``unlock`` — prompt for the mnemonic once, then hold the unlocked wallet and
  serve signing requests in the FOREGROUND (this terminal). Per-spend
  confirmation prompts appear here, on the daemon's own terminal — the channel a
  hostile same-uid requester cannot drive. Ctrl-C locks (zeroizes) and exits.
* ``status`` — is an agent live on this wallet's socket? (and its account xpub).
* ``lock`` — tell a running agent to zeroize and shut down.

The socket lives next to the wallet (``<wallet dir>/agent.sock``) so ``--wallet``
co-locates it. Foreground is deliberate: a detached daemon has no terminal to
confirm on, so non-trivial spends would fail closed. Background it with ``&`` in
the same terminal if you want your shell back — ``/dev/tty`` still reaches you.
"""

from __future__ import annotations

from pathlib import Path

import click

from ..agent import AgentClient, AgentDaemon, TtyConfirmer
from ..agent.daemon import DEFAULT_IDLE_TIMEOUT_S
from ..hd.wallet import HdWallet
from ..security.errors import ValidationError
from .context import CliContext
from .errors import UserError, WalletDecryptError
from .format import emit
from .prompts import prompt_mnemonic_input, prompt_passphrase_input


def _socket_path(ctx: CliContext) -> Path:
    """The agent socket sits next to the wallet file (``--wallet`` co-locates it)."""
    return ctx.wallet_path.parent / "agent.sock"


@click.group(name="agent")
def agent_group() -> None:
    """Local signing agent: unlock once, sign on the CLI's behalf (key never leaves it)."""


@agent_group.command(name="status")
@click.pass_obj
def agent_status(ctx: CliContext) -> None:
    """Report whether a signing agent is live on this wallet's socket."""
    sock = _socket_path(ctx)
    client = AgentClient(sock)
    live = client.is_live()
    payload: dict[str, object] = {"live": live, "socket": str(sock)}
    if live:
        payload["xpub"] = client.account_xpub()

    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="live"))
    else:
        click.echo(f"agent: {'LIVE' if live else 'not running'}  ({sock})")
        if live:
            click.echo(f"  account xpub: {payload['xpub']}")


@agent_group.command(name="lock")
@click.pass_obj
def agent_lock(ctx: CliContext) -> None:
    """Tell a running agent to lock (zeroize the seed) and shut down."""
    client = AgentClient(_socket_path(ctx))
    if not client.is_live():
        click.echo("no agent running (nothing to lock)")
        return
    client.lock()
    click.echo("agent locked (seed zeroized)")


@agent_group.command(name="unlock")
@click.option(
    "--idle-timeout",
    type=float,
    default=DEFAULT_IDLE_TIMEOUT_S,
    show_default=True,
    metavar="SECONDS",
    help="Auto-lock (zeroize) after this many seconds with no activity.",
)
@click.option(
    "--auto-confirm-under",
    type=int,
    default=0,
    show_default=True,
    metavar="PHOTONS",
    help="Skip the confirmation prompt for spends whose total to external payees is at/below this. "
    "0 = always confirm. Spends above the threshold ALWAYS require a keypress.",
)
@click.option("--passphrase/--no-passphrase", default=False, help="Prompt for a BIP39 passphrase.")
@click.pass_obj
def agent_unlock(ctx: CliContext, idle_timeout: float, auto_confirm_under: int, passphrase: bool) -> None:
    """Unlock the wallet and hold it in a foreground signing agent.

    Prompts for the mnemonic once, then serves signing requests on
    ``<wallet dir>/agent.sock`` until you press Ctrl-C (or the idle timeout
    fires). Confirmation prompts for each non-trivial spend appear in THIS
    terminal — keep it where you can see it.
    """
    if not ctx.wallet_path.exists():
        raise UserError(
            f"no wallet at {ctx.wallet_path}",
            cause="the file does not exist",
            fix="run `pyrxd wallet new` to create one, or pass --wallet PATH",
        )
    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError("mnemonic is required", cause="no input received", fix="enter the wallet's BIP39 mnemonic")
    passphrase_str = ""  # nosec B105 — empty string is the BIP39 spec default (no passphrase)
    if passphrase:
        passphrase_str = prompt_passphrase_input(optional=False)
    try:
        wallet = HdWallet.load(ctx.wallet_path, mnemonic, passphrase_str)
    except (ValidationError, ValueError) as exc:
        raise WalletDecryptError() from exc

    sock = _socket_path(ctx)
    daemon = AgentDaemon(
        wallet,
        socket_path=sock,
        confirm=TtyConfirmer(auto_confirm_under=auto_confirm_under),
        idle_timeout_s=idle_timeout,
    )
    click.echo(f"pyrxd agent: unlocked. Serving on {sock}.")
    click.echo("  Per-spend confirmations appear in THIS terminal. Ctrl-C to lock and exit.")
    try:
        daemon.serve_forever()
    except KeyboardInterrupt:
        daemon.lock()
        click.echo("\nagent locked (seed zeroized).")
    else:
        # serve_forever returns when locked (idle auto-lock or a `lock` request).
        click.echo("agent locked (seed zeroized).")

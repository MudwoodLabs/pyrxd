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

import atexit
import signal

import click

from ..agent import AgentClient, AgentDaemon, TtyConfirmer, agent_socket_path
from ..agent.daemon import DEFAULT_IDLE_TIMEOUT_S
from ..agent.hygiene import harden_process
from ..hd.wallet import HdWallet
from ..security.errors import ValidationError
from .context import CliContext
from .errors import UserError, WalletDecryptError
from .format import emit
from .prompts import prompt_mnemonic_input, prompt_passphrase_input


def _socket_path(ctx: CliContext):
    """The agent socket sits next to the wallet file (``--wallet`` co-locates it)."""
    return agent_socket_path(ctx.wallet_path)


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
    # Harden BEFORE the mnemonic exists in this process, not after.
    #
    # ``harden_process()`` used to run only inside ``AgentDaemon.serve_forever``,
    # which is the LAST thing this command does — so the mnemonic was typed, the
    # passphrase prompted and the seed derived while the process was still
    # swappable, dumpable and ptrace-able. Measured on this path: 23.9 ms with an
    # automated prompt, however long the user takes to type with a real one, and
    # unbounded under ``--passphrase``, which waits on a human twice.
    #
    # What this actually buys, stated honestly:
    #   * ``mlockall`` — the real gain. Before it runs, the pages holding the
    #     plaintext mnemonic and the derived seed are ordinary swappable memory,
    #     and swap survives a reboot in a way a sub-second memory window does not.
    #   * ``RLIMIT_CORE = 0`` — a crash during the prompt or the scrypt decrypt
    #     can no longer write a core file containing the mnemonic. (Many distros
    #     already ship a 0 soft limit; the hard limit is unlimited, so this is a
    #     conditional gain, not a universal one.)
    #   * ``PR_SET_DUMPABLE 0`` — closes the attacker who arrives AFTER unlock.
    #     It does NOT close a watcher already holding an open ``/proc/<pid>/mem``
    #     fd, because the prctl does not revoke open descriptors. Moving the call
    #     earlier does not change that, and it should not be claimed to.
    #
    # ``harden_process`` is documented never to raise, and that contract is now
    # load-bearing: an exception here would deny the user their own wallet on a
    # host that merely lacks ``CAP_IPC_LOCK``. Every measure inside it is
    # best-effort and failures are reported, never fatal.
    harden_process()

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

    # Scrub on any exit path, not just Ctrl-C (security-panel H2): SIGTERM/SIGHUP
    # (kill, logout) and a normal process exit must also zeroize. lock() is
    # idempotent, so the overlapping handlers + atexit + serve_forever's own
    # finally are all safe.
    def _scrub_and_exit(signum, _frame):
        daemon.lock()
        raise SystemExit(128 + signum)

    for _sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(_sig, _scrub_and_exit)
    atexit.register(daemon.lock)

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

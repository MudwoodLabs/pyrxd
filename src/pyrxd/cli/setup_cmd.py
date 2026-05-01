"""``pyrxd setup`` — Cut 3 onboarding flow.

Walks a fresh install through the steps it needs to actually use
pyrxd. Designed to take a fresh ``pip install pyrxd`` to "ready to
mint a Glyph" in under five minutes without bundling a node.

Each step is non-destructive by default (prints what it found) and
emits a ``--json`` payload describing what it would do. Wallet
creation is the only destructive action; gated by ``--yes`` exactly
like ``wallet new``.
"""

from __future__ import annotations

import asyncio
import socket

import click

from . import config as _config
from .context import CliContext
from .format import emit
from .main import cli

# Default Radiant Core mainnet RPC port — matches `radiantd` on
# 127.0.0.1:7332. Used as a heuristic only; we never authenticate.
_NODE_PROBE_HOST = "127.0.0.1"
_NODE_PROBE_PORT = 7332
_NODE_PROBE_TIMEOUT_S = 1.0


def _probe_local_node() -> bool:
    """Return True if a TCP connection to the default Radiant RPC port
    succeeds. Does NOT authenticate or verify the service is actually
    radiantd — we only use this as an "is something listening" hint.
    """
    try:
        with socket.create_connection((_NODE_PROBE_HOST, _NODE_PROBE_PORT), timeout=_NODE_PROBE_TIMEOUT_S):
            return True
    except (TimeoutError, OSError):
        return False


async def _probe_electrumx(url: str) -> bool:
    """Try to open + close an ElectrumXClient at *url*. Returns True
    on success. Suppresses all exceptions — this is a "can we reach
    it" check, not a strict validation.
    """
    from ..network.electrumx import ElectrumXClient

    try:
        client = ElectrumXClient([url])
        async with client:
            await client.get_tip_height()
        return True
    except Exception:
        return False


@cli.command(name="setup")
@click.option(
    "--no-interactive",
    is_flag=True,
    help="Don't prompt for any input. Just write the default config and exit.",
)
@click.pass_obj
def setup_cmd(ctx: CliContext, no_interactive: bool) -> None:
    """Onboarding walkthrough — detects node, ElectrumX, wallet.

    Prints what it finds and how to fix any gaps. Writes
    ``~/.pyrxd/config.toml`` with built-in defaults if the file is
    missing. Does NOT create a wallet — run ``pyrxd wallet new``
    afterwards.
    """
    # 1. Config file presence.
    config_path = _config.DEFAULT_CONFIG_PATH
    config_existed = config_path.exists()
    if not config_existed:
        if no_interactive:
            written = _config.write_default()
            click.echo(f"wrote default config to {written}") if ctx.output_mode == "human" else None
        else:
            click.echo(f"\nNo config at {config_path}.")
            if click.confirm("Create one with built-in defaults?", default=True):
                written = _config.write_default()
                click.echo(f"  wrote {written}")

    # 2. Node probe.
    has_node = _probe_local_node()

    # 3. ElectrumX probe.
    has_electrumx = asyncio.run(_probe_electrumx(ctx.electrumx_url))

    # 4. Wallet presence.
    wallet_path = ctx.wallet_path
    has_wallet = wallet_path.exists()

    payload = {
        "config_path": str(config_path),
        "config_existed": config_existed,
        "node_probed": f"{_NODE_PROBE_HOST}:{_NODE_PROBE_PORT}",
        "node_reachable": has_node,
        "electrumx_url": ctx.electrumx_url,
        "electrumx_reachable": has_electrumx,
        "wallet_path": str(wallet_path),
        "wallet_exists": has_wallet,
    }

    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
        return
    if ctx.output_mode == "quiet":
        # In quiet mode, print "ok" if everything looks ready, "todo"
        # otherwise. Used for scripted readiness checks.
        ready = has_electrumx and has_wallet
        click.echo("ok" if ready else "todo")
        return

    # Human-readable summary with concrete next steps.
    click.echo("\npyrxd setup status:")
    click.echo(f"  config:    {config_path} {'(exists)' if config_existed else '(written with defaults)'}")
    click.echo(f"  node:      {_NODE_PROBE_HOST}:{_NODE_PROBE_PORT} {'reachable' if has_node else 'NOT reachable'}")
    click.echo(f"  electrumx: {ctx.electrumx_url} {'reachable' if has_electrumx else 'NOT reachable'}")
    click.echo(f"  wallet:    {wallet_path} {'(exists)' if has_wallet else '(missing)'}")

    next_steps: list[str] = []
    if not has_electrumx and not has_node:
        next_steps.append(
            "ElectrumX not reachable. Either:\n"
            "      - run a local Radiant Core node on 127.0.0.1:7332, or\n"
            f"      - point pyrxd at a public ElectrumX server via PYRXD_ELECTRUMX env\n"
            f"        (current: {ctx.electrumx_url})"
        )
    if not has_wallet:
        next_steps.append("create a wallet:  pyrxd wallet new")

    if next_steps:
        click.echo("\nNext steps:")
        for i, step in enumerate(next_steps, 1):
            click.echo(f"  {i}. {step}")
    else:
        click.echo("\nReady to mint! Try: pyrxd glyph init-metadata --out my-nft.json")


__all__ = ["setup_cmd"]

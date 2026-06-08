"""``pyrxd regtest`` — one-command local Radiant regtest node for development.

A thin CLI over :class:`pyrxd.devnet.RegtestNode`. The goal is for a fresh
developer to get a funded, spendable regtest identity in a single command::

    pyrxd regtest up

which stands up an isolated regtest chain in docker, mines a mature coinbase,
generates a pre-funded key, and prints the connection details. ``mine``,
``fund``, ``info`` operate on the running node; ``down`` tears it down.

These commands are intentionally self-contained (they do not touch the wallet
or network config) — regtest is a throwaway sandbox reached via ``docker exec``.
"""

from __future__ import annotations

import click

from ..devnet import DevnetError, RegtestNode
from .format import emit


def _fail(exc: DevnetError) -> None:
    raise click.ClickException(str(exc))


@click.group(name="regtest")
def regtest_group() -> None:
    """Manage a local Radiant regtest node for development (docker)."""


@regtest_group.command(name="up")
@click.option("--fresh", is_flag=True, help="Tear down any existing node for a clean chain.")
@click.option(
    "--fund",
    "fund_rxd",
    type=float,
    default=100.0,
    metavar="RXD",
    help="RXD to pre-fund the generated dev key with (default 100).",
)
@click.option("--json", "json_output", is_flag=True, help="Machine-readable output.")
def regtest_up(fresh: bool, fund_rxd: float, json_output: bool) -> None:
    """Start the regtest node and print a pre-funded dev key."""
    node = RegtestNode()
    try:
        already = node.is_running() and not fresh
        node.start(fresh=fresh)
        info = node.info()
        key = node.new_funded_key(fund_rxd)
    except DevnetError as exc:
        _fail(exc)
    result = {**info, "dev_address": key.address, "dev_wif": key.wif, "dev_funded_rxd": key.funded_rxd}
    if json_output:
        click.echo(emit(result, mode="json"))
        return
    if already:
        click.echo("regtest node already running (use --fresh for a clean chain)")
    else:
        click.echo("regtest node up")
    click.echo(f"  container: {info['container']}  (image {info['image']})")
    click.echo(f"  height:    {info['height']}")
    click.echo(f"  rpc:       user={info['rpc_user']} password={info['rpc_password']} wallet={info['wallet']}")
    click.echo("")
    click.echo("pre-funded dev key (import with PrivateKey(wif)):")
    click.echo(f"  address: {key.address}")
    click.echo(f"  wif:     {key.wif}")
    click.echo(f"  funded:  {key.funded_rxd:g} RXD")
    click.echo("")
    click.echo("next:")
    click.echo("  pyrxd regtest mine 1            # advance the chain")
    click.echo("  pyrxd regtest fund <address> 50 # faucet 50 RXD to any address")
    click.echo("  pyrxd regtest down              # tear it all down")


@regtest_group.command(name="down")
def regtest_down() -> None:
    """Stop and remove the regtest node (wipes the chain)."""
    node = RegtestNode()
    try:
        node.stop()
    except DevnetError as exc:
        _fail(exc)
    click.echo("regtest node down")


@regtest_group.command(name="mine")
@click.argument("count", type=int, default=1)
@click.option(
    "--to", "address", default=None, metavar="ADDRESS", help="Mine to this address (default: a fresh wallet address)."
)
@click.option("--json", "json_output", is_flag=True, help="Machine-readable output.")
def regtest_mine(count: int, address: str | None, json_output: bool) -> None:
    """Mine COUNT blocks (default 1)."""
    node = RegtestNode()
    try:
        height = node.mine(count, address)
    except DevnetError as exc:
        _fail(exc)
    if json_output:
        click.echo(emit({"mined": count, "height": height}, mode="json"))
    else:
        click.echo(f"mined {count} block(s) — height {height}")


@regtest_group.command(name="fund")
@click.argument("address")
@click.argument("amount", type=float, default=10.0)
@click.option("--json", "json_output", is_flag=True, help="Machine-readable output.")
def regtest_fund(address: str, amount: float, json_output: bool) -> None:
    """Faucet AMOUNT RXD (default 10) to ADDRESS, confirmed in a block."""
    node = RegtestNode()
    try:
        txid = node.fund(address, amount)
    except DevnetError as exc:
        _fail(exc)
    if json_output:
        click.echo(emit({"txid": txid, "address": address, "amount_rxd": amount}, mode="json"))
    else:
        click.echo(f"funded {address} with {amount:g} RXD")
        click.echo(f"  txid: {txid}")


@regtest_group.command(name="info")
@click.option("--json", "json_output", is_flag=True, help="Machine-readable output.")
def regtest_info(json_output: bool) -> None:
    """Show the running node's connection + chain summary."""
    node = RegtestNode()
    try:
        info = node.info()
    except DevnetError as exc:
        _fail(exc)
    if json_output:
        click.echo(emit(info, mode="json"))
        return
    click.echo(f"container: {info['container']}  (image {info['image']})")
    click.echo(f"height:    {info['height']}")
    click.echo(f"rpc:       user={info['rpc_user']} password={info['rpc_password']} wallet={info['wallet']}")
    click.echo(f"exec:      {info['exec_prefix']} ...")

"""Bare query subcommands: ``address``, ``balance``.

These are intentionally minimal — they cover the no-node onboarding
case ("I just installed pyrxd, what's my address and balance?")
without trying to compete with ``radiant-cli`` for general wallet ops.
See docs/wallet-cli-plan.md "Address & balance" for the rationale.
"""

from __future__ import annotations

import asyncio

import click

from ..hd.wallet import HdWallet
from ..security.errors import NetworkError, ValidationError
from .context import CliContext
from .errors import NetworkBoundaryError, UserError, WalletDecryptError
from .format import emit, format_photons
from .main import cli
from .prompts import prompt_mnemonic_input, prompt_passphrase_input


def _load_wallet(ctx: CliContext, *, prompt_passphrase: bool = False) -> HdWallet:
    """Open the wallet referenced by *ctx*. Used by every query command."""
    if not ctx.wallet_path.exists():
        raise UserError(
            f"no wallet at {ctx.wallet_path}",
            cause="the file does not exist",
            fix="run `pyrxd wallet new` to create one, or pass --wallet PATH",
        )
    mnemonic = prompt_mnemonic_input()
    if not mnemonic:
        raise UserError(
            "mnemonic is required",
            cause="no input received",
            fix="enter the BIP39 mnemonic the wallet was created with",
        )
    passphrase = ""  # nosec B105 — empty string is the BIP39 spec default (no passphrase), not a hardcoded secret
    if prompt_passphrase:
        passphrase = prompt_passphrase_input(optional=False)
    try:
        return HdWallet.load(ctx.wallet_path, mnemonic, passphrase)
    except (ValidationError, ValueError) as exc:
        # ValidationError: library's "Could not decrypt" surface.
        # ValueError:      bip39.validate_mnemonic on a non-wordlist word.
        # Both collapse to a single decrypt-failed exit code — we never
        # echo the user's input back, so distinguishing them would only
        # leak information about which guess was closer.
        raise WalletDecryptError() from exc


@cli.command(name="address")
@click.option("--next", "next_unused", is_flag=True, default=True, help="Next unused external address (default).")
@click.option("--index", type=int, default=None, help="Specific index lookup.")
@click.option("--change", is_flag=True, help="Internal chain instead of external.")
@click.option("--passphrase/--no-passphrase", default=False, help="Prompt for the BIP39 passphrase.")
@click.pass_obj
def address_cmd(
    ctx: CliContext,
    next_unused: bool,
    index: int | None,
    change: bool,
    passphrase: bool,
) -> None:
    """Print a wallet address.

    Default behavior is the next unused external receive address.
    `--index N --change` lets you look up a specific change-chain index
    deterministically.
    """
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)
    chain = 1 if change else 0

    if index is not None:
        if index < 0:
            raise UserError(
                "index must be >= 0",
                cause=f"received index={index}",
                fix="pass a non-negative integer to --index",
            )
        addr = wallet._derive_address(chain, index)
        path = f"m/44'/512'/{wallet.account}'/{chain}/{index}"
    else:
        # `--next` — walks the wallet's known addresses.
        addr = wallet.next_receive_address() if not change else _next_internal_address(wallet)
        # next_receive_address creates the record at the chosen index;
        # find it back from the known dict to report the path.
        path = _path_for_address(wallet, addr)

    payload = {"address": addr, "path": path, "network": ctx.network}
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="address"))
    else:
        click.echo(emit(payload, mode="human", human_lines=[f"{addr}  ({path})"]))


def _next_internal_address(wallet: HdWallet) -> str:
    """Mirror of next_receive_address but for the internal chain."""
    from ..hd.wallet import _GAP_LIMIT, AddressRecord

    for idx in range(wallet.internal_tip + _GAP_LIMIT):
        pkey = wallet._path_key(1, idx)
        rec = wallet.addresses.get(pkey)
        if rec is None or not rec.used:
            if rec is None:
                addr = wallet._derive_address(1, idx)
                wallet.addresses[pkey] = AddressRecord(address=addr, change=1, index=idx, used=False)
            else:
                addr = rec.address
            return addr
    idx = wallet.internal_tip + _GAP_LIMIT
    addr = wallet._derive_address(1, idx)
    wallet.addresses[wallet._path_key(1, idx)] = AddressRecord(address=addr, change=1, index=idx, used=False)
    return addr


def _path_for_address(wallet: HdWallet, address: str) -> str:
    for rec in wallet.addresses.values():
        if rec.address == address:
            return f"m/44'/512'/{wallet.account}'/{rec.change}/{rec.index}"
    return "?"


@cli.command(name="balance")
@click.option("--refresh", is_flag=True, help="Run a gap-limit scan first to discover used addresses.")
@click.option("--passphrase/--no-passphrase", default=False, help="Prompt for the BIP39 passphrase.")
@click.pass_obj
def balance_cmd(ctx: CliContext, refresh: bool, passphrase: bool) -> None:
    """Print confirmed/unconfirmed photon balance across the wallet."""
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _query() -> tuple[int, int]:
        client = ctx.make_client()
        async with client:
            if refresh:
                await wallet.refresh(client)
            confirmed_total = 0
            unconfirmed_total = 0
            from ..network.electrumx import script_hash_for_address

            used = [r for r in wallet.addresses.values() if r.used]
            for rec in used:
                c, u = await client.get_balance(script_hash_for_address(rec.address))
                confirmed_total += int(c)
                unconfirmed_total += int(u)
            return confirmed_total, unconfirmed_total

    try:
        confirmed, unconfirmed = asyncio.run(_query())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable, or use --electrumx URL",
        ) from exc

    payload = {
        "network": ctx.network,
        "confirmed_photons": confirmed,
        "unconfirmed_photons": unconfirmed,
    }
    if ctx.output_mode == "json":
        click.echo(emit(payload, mode="json"))
    elif ctx.output_mode == "quiet":
        click.echo(emit(payload, mode="quiet", quiet_field="confirmed_photons"))
    else:
        lines = [
            f"Network    {ctx.network}",
            f"Confirmed  {format_photons(confirmed)}",
            f"Pending    {format_photons(unconfirmed)}",
        ]
        click.echo(emit(payload, mode="human", human_lines=lines))


@cli.command(name="utxos")
@click.option("--min-photons", type=int, default=0, help="Minimum value filter.")
@click.option("--addr", default=None, help="Restrict to a single wallet address.")
@click.option("--passphrase/--no-passphrase", default=False)
@click.pass_obj
def utxos_cmd(ctx: CliContext, min_photons: int, addr: str | None, passphrase: bool) -> None:
    """List wallet UTXOs (read-only diagnostic).

    Output spans every used address by default; use ``--addr`` to
    drill into a single one. Filter by ``--min-photons`` to suppress
    dust.
    """
    from .format import emit_table

    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _query() -> list[dict]:
        client = ctx.make_client()
        async with client:
            triples = await wallet.collect_spendable(client)
            rows: list[dict] = []
            for utxo, address, _pk in triples:
                if min_photons and utxo.value < min_photons:
                    continue
                if addr and address != addr:
                    continue
                rows.append(
                    {
                        "txid": utxo.tx_hash,
                        "vout": utxo.tx_pos,
                        "value": utxo.value,
                        "height": utxo.height,
                        "address": address,
                    }
                )
            return rows

    try:
        rows = asyncio.run(_query())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {ctx.electrumx_url} is reachable, or use --electrumx URL",
        ) from exc

    columns = ["txid", "vout", "value", "height", "address"]
    click.echo(emit_table(rows, columns, mode=ctx.output_mode, quiet_field="txid"))


__all__ = ["address_cmd", "balance_cmd", "utxos_cmd"]

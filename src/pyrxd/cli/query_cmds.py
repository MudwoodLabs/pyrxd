"""Bare query subcommands: ``address``, ``balance``, ``utxos``.

These are intentionally minimal — they cover the no-node onboarding
case ("I just installed pyrxd, what's my address and balance?")
without trying to compete with ``radiant-cli`` for general wallet ops.
See docs/wallet-cli-plan.md "Address & balance" for the rationale.

``balance`` and ``utxos`` here, and ``glyph list``, read what the chain holds for
the wallet. Each runs the gap-limit scan first (:func:`scan_then_read`, or
``collect_spendable``, which runs the same scan), and each reports an address it
could not read as INCOMPLETE rather than as empty (:func:`refuse_if_incomplete`).
``address`` runs the same scan before it picks the next unused address, and refuses
when the scan cannot finish (#781).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

import click

from ..hd.wallet import HdWallet
from ..network.electrumx import script_hash_for_address
from ..network.redaction import redacted_url
from ..security.errors import NetworkError
from .context import CliContext
from .errors import NetworkBoundaryError, UserError
from .format import emit, format_photons
from .prompts import _load_wallet


@dataclass(frozen=True)
class AddressReads:
    """What a read-only command got from the wallet's used addresses, after the scan.

    ``answered`` pairs each address whose read succeeded with what the read returned;
    ``unread`` names the addresses whose read failed; ``used`` counts them all.
    """

    answered: list[tuple[str, Any]]
    unread: tuple[str, ...]
    used: int


async def scan_then_read(
    wallet: HdWallet,
    client: Any,
    read: Callable[[str], Awaitable[object]],
    *,
    what: str,
) -> AddressReads:
    """Run the gap-limit scan, then *read* every address it found used.

    The scan is :meth:`HdWallet.refresh`, the one ``collect_spendable`` runs before
    every spend (#759). An address is marked used only by that scan, and a wallet
    file made by ``pyrxd wallet new`` records none, so a read that skipped the scan
    showed a funded new wallet as holding nothing. The scan's result is not saved:
    ``balance --refresh`` never saved it either, and the wallet file format is
    unchanged. A scan that cannot read an address raises :class:`NetworkError`.

    The per-address reads go through the wallet's own per-address reader, which
    logs a failed read instead of dropping it; the addresses that failed come back
    in :attr:`AddressReads.unread` for :func:`refuse_if_incomplete`.
    """
    await wallet.refresh(client)
    used = [rec for rec in wallet.addresses.values() if rec.used]
    results = await wallet._read_per_address(used, read, what=what, strict=False)
    pairs = list(zip(used, results, strict=True))
    return AddressReads(
        answered=[(rec.address, result) for rec, result in pairs if result is not None],
        unread=tuple(rec.address for rec, result in pairs if result is None),
        used=len(used),
    )


def refuse_if_incomplete(ctx: CliContext, unread: Sequence[str], used: int, *, what: str, view: str) -> None:
    """Return only when every used address was read. Otherwise exit 2, never showing a short view as whole.

    An address whose read failed is not an empty one, so a balance or a listing
    without it is not the wallet's. This is ``collect_spendable``'s strict default
    (#768) applied to a view: a spend may go ahead on a partial read that is
    enough, but a view has no "enough", so a partial one never exits 0.

    *view* is the human rendering of what the other addresses returned. The human
    output prints it with an INCOMPLETE line naming the unread addresses, on
    stdout, so it is seen even when stderr is not. JSON and quiet output print
    nothing: neither shape has a place to say "incomplete", and a script reading
    a lower bound as a balance is the mistake this refuses. When no address could
    be read there is no view, in any mode.
    """
    if not unread:
        return
    endpoint_fix = f"retry, or check that {redacted_url(ctx.electrumx_url)} is reachable, or use --electrumx URL"
    if len(unread) >= used:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=f"{len(unread)} of {used} used address reads failed, and an address that could not be read "
            "is not an empty one",
            fix=endpoint_fix,
        )
    if ctx.output_mode == "human":
        if view:
            click.echo(view)
        click.echo(
            f"INCOMPLETE: {len(unread)} of {used} used addresses could not be read, "
            f"so {what} leaves out whatever they hold: {', '.join(unread)}"
        )
    raise NetworkBoundaryError(
        f"{what} is incomplete: {len(unread)} of this wallet's {used} used addresses could not be read",
        cause="an address whose read failed is not an empty one",
        fix=endpoint_fix,
    )


@click.command(name="address")
@click.option(
    "--next",
    "next_unused",
    is_flag=True,
    default=True,
    help="First address with no plain-RXD history, after a gap-limit scan (default).",
)
@click.option("--index", type=int, default=None, help="Specific index lookup. Reads nothing from the network.")
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

    Default behavior is the next unused external receive address: the gap-limit
    scan runs first, on both chains, and the answer is the first address on the
    chain whose P2PKH script hash has no history. That is plain-RXD history: an
    address paid RXD, including one paid and then spent from, is not handed out
    again. An address that has only received a Glyph token is not seen as used,
    because the server lists a token output under its zeroed-ref script hash,
    which the scan does not read (#787). If the scan cannot read an address the
    command exits 2 and prints no address. Nothing is saved to the wallet file.
    `--index N` (with `--change` for the internal chain) derives that index
    directly and reads nothing from the network.
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
        path = f"m/44'/{wallet.coin_type}'/{wallet.account}'/{chain}/{index}"
    else:
        # `--next`: the first address with no chain history. Both pickers below choose from what
        # the wallet records as used, only the gap-limit scan records that, and nothing saves a
        # scan, so without this scan a `wallet new` file handed out index 0 forever, funded or
        # not (#781). This is the scan `scan_then_read` and `collect_spendable` run
        # (HdWallet.refresh): an address is used when ElectrumX reports history at its P2PKH
        # script hash, so an address paid and then spent from is used too. A token output is
        # listed under a zeroed-ref hash the scan does not read, so a token-only address is
        # not seen as used (#787). It reads every address it needs or
        # raises, so there is no partial result to show; a failed read is refused before
        # anything is printed. The scan is not saved, as in #768 and #779.
        _scan_or_refuse(ctx, wallet)
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


def _scan_or_refuse(ctx: CliContext, wallet: HdWallet) -> None:
    """Run the gap-limit scan on *wallet*, or exit 2: an address not proven unused is not handed out."""

    async def _scan() -> None:
        client = ctx.make_client()
        async with client:
            await wallet.refresh(client)

    try:
        asyncio.run(_scan())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=f"{exc}; an address this command cannot show has no history is not handed out",
            fix=f"retry, or check that {redacted_url(ctx.electrumx_url)} is reachable, or use --electrumx URL; "
            "--index N prints a specific address without reading the network",
        ) from exc


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
            return f"m/44'/{wallet.coin_type}'/{wallet.account}'/{rec.change}/{rec.index}"
    return "?"


@click.command(name="balance")
@click.option(
    "--refresh",
    is_flag=True,
    help="Accepted so existing scripts keep working, and changes nothing: the gap-limit scan is now the default.",
)
@click.option("--passphrase/--no-passphrase", default=False, help="Prompt for the BIP39 passphrase.")
@click.pass_obj
def balance_cmd(ctx: CliContext, refresh: bool, passphrase: bool) -> None:
    """Print confirmed/unconfirmed photon balance across the wallet.

    Runs the gap-limit scan first, on both chains (the one every spend command
    runs), so it counts funds at any address inside the gap window, including on a
    wallet `pyrxd wallet new` just made. Nothing is saved to the wallet file.

    An address that cannot be read is never counted as empty: the command exits 2,
    and only the human output shows what the other addresses hold, marked
    INCOMPLETE.
    """
    del refresh  # the scan always runs; the flag only has to keep parsing
    wallet = _load_wallet(ctx, prompt_passphrase=passphrase)

    async def _query() -> AddressReads:
        client = ctx.make_client()
        async with client:
            return await scan_then_read(
                wallet,
                client,
                lambda address: client.get_balance(script_hash_for_address(address)),
                what="get_balance",
            )

    try:
        reads = asyncio.run(_query())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {redacted_url(ctx.electrumx_url)} is reachable, or use --electrumx URL",
        ) from exc

    confirmed = sum(int(c) for _address, (c, _u) in reads.answered)
    unconfirmed = sum(int(u) for _address, (_c, u) in reads.answered)
    lines = [
        f"Network    {ctx.network}",
        f"Confirmed  {format_photons(confirmed)}",
        f"Pending    {format_photons(unconfirmed)}",
    ]
    refuse_if_incomplete(ctx, reads.unread, reads.used, what="the balance", view="\n".join(lines))

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
        click.echo(emit(payload, mode="human", human_lines=lines))


@click.command(name="utxos")
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

    async def _query() -> tuple[list[dict], tuple[str, ...], int]:
        client = ctx.make_client()
        async with client:
            # Not a spend: a read-only listing. It collects the partial view so it can say which
            # addresses failed, then follows `balance`'s rule (refuse_if_incomplete): a listing
            # with an unread address is never shown as the whole wallet's.
            triples = await wallet.collect_spendable(client, strict=False)
            used = sum(1 for rec in wallet.addresses.values() if rec.used)
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
            return rows, triples.unread, used

    try:
        rows, unread, used = asyncio.run(_query())
    except NetworkError as exc:
        raise NetworkBoundaryError(
            "could not reach ElectrumX",
            cause=str(exc),
            fix=f"check that {redacted_url(ctx.electrumx_url)} is reachable, or use --electrumx URL",
        ) from exc

    if addr:
        # Asked about one address: only that address's read decides whether the answer is whole.
        unread, used = tuple(a for a in unread if a == addr), 1
    columns = ["txid", "vout", "value", "height", "address"]
    refuse_if_incomplete(
        ctx, unread, used, what="this list", view=emit_table(rows, columns, mode="human") if rows else ""
    )
    click.echo(emit_table(rows, columns, mode=ctx.output_mode, quiet_field="txid"))


__all__ = ["AddressReads", "address_cmd", "balance_cmd", "refuse_if_incomplete", "scan_then_read", "utxos_cmd"]

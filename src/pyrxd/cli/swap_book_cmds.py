"""``pyrxd swap orders/post/take/cancel`` — the on-chain RSWP orderbook commands.

Thin CLI over the proven :mod:`pyrxd.swap.rswp` library (design:
docs/plans/2026-07-05-rswp-orderbook-design.md). Same safety posture as the
glyph commands:

* **Read side** (``orders``) never signs and never broadcasts. It talks to a
  Radiant node running ``-swapindex=1`` and re-verifies every row against
  chain data — *fillable* means the maker signature and every advertised
  claim checked out, not that the index said so.
* **Write side** (``post`` / ``take`` / ``cancel``) shows a full value summary
  and asks for confirmation before ANY broadcast (``--json`` requires
  ``--yes``, same gate as the glyph commands). Funding comes from the local
  HD wallet; the offered/give UTXO must be owned by a wallet key.

Wire/format authority: the maker's offer is signed
``SIGHASH_SINGLE|ANYONECANPAY|FORKID`` — posting publishes a price that stays
fillable until the offered UTXO is spent. ``cancel`` (a self-spend) is the
ONLY hard revocation; the confirmation text says so.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import click

from ..glyph.types import GlyphRef
from ..keys import PrivateKey
from ..security.errors import RxdSdkError, ValidationError
from ..security.types import Txid
from ..swap import Asset, FundingInput
from ..swap.partial import _asset_of, _owner_pkh_of
from ..swap.resolve import fetch_transaction
from ..swap.rswp import (
    NodeRpcSource,
    OrderbookClient,
    RswpOrder,
    build_advert_tx,
    build_cancel_tx,
    create_rswp_order,
    decode_rswp_order,
    take_rswp_order,
)
from ..transaction.transaction import Transaction
from .context import CliContext
from .errors import UserError
from .format import emit, sanitize_terminal
from .glyph_helpers import _BroadcastSummary, _confirm_or_abort
from .prompts import _load_wallet

# Broadcast-tx size guesses for the single-pass fee estimate (photons = rate × size/1000,
# floored at 1000). Deliberately generous — a slight overpay beats a stuck tx; use
# --fee for exact control.
_TX_BASE_BYTES = 220
_TX_PER_INPUT_BYTES = 150
_TX_PER_OUTPUT_BYTES = 40
_MIN_FEE_PHOTONS = 1_000
_MAX_FUNDING_INPUTS = 8


# --------------------------------------------------------------------------- arg parsing


def _parse_outpoint(value: str) -> tuple[str, int]:
    """``TXID:VOUT`` → (txid, vout)."""
    txid, sep, vout = value.partition(":")
    if not sep or len(txid) != 64:
        raise UserError(
            f"invalid outpoint {sanitize_terminal(value, max_len=80)!r}",
            cause="expected TXID:VOUT (64-hex txid, decimal vout)",
            fix="e.g. --give 3f2a…9c:0",
        )
    try:
        return str(Txid(txid)), int(vout)
    except (ValueError, RxdSdkError) as exc:
        raise UserError(f"invalid outpoint: {exc}") from exc


def _parse_token(value: str) -> GlyphRef | None:
    """``rxd`` | 72-hex contract ref | ``TXID:VOUT`` → GlyphRef (None = native RXD)."""
    if value.lower() == "rxd":
        return None
    try:
        if ":" in value:
            txid, vout = _parse_outpoint(value)
            return GlyphRef(txid=Txid(txid), vout=vout)
        if len(value) == 72:
            return GlyphRef.from_contract_hex(value)
    except (RxdSdkError, UserError, ValueError):
        pass
    raise UserError(
        f"invalid token {sanitize_terminal(value, max_len=80)!r}",
        cause="expected 'rxd', a 72-hex contract ref, or TXID:VOUT",
        fix="copy the token's contract id from an explorer, or pass its genesis outpoint",
    )


def _parse_asset_spec(value: str) -> Asset:
    """``rxd:AMOUNT`` | ``TOKEN:AMOUNT`` (FT) | ``nft:TOKEN:CARRIER_PHOTONS`` → Asset.

    A bare token ref means FT (the common case); an NFT must be explicit via
    the ``nft:`` prefix because the ref alone cannot distinguish the two.
    """
    kind = "ft"
    if value.lower().startswith("nft:"):
        kind = "nft"
        value = value[4:]
    token_part, sep, amount_part = value.rpartition(":")
    if not sep:
        raise UserError(
            f"invalid asset spec {sanitize_terminal(value, max_len=80)!r}",
            cause="expected ASSET:AMOUNT",
            fix="e.g. --receive rxd:900000, --receive <72-hex-ref>:50, or --receive nft:<72-hex-ref>:600",
        )
    try:
        amount = int(amount_part)
    except ValueError as exc:
        raise UserError(f"invalid amount {sanitize_terminal(amount_part, max_len=40)!r}") from exc
    ref = _parse_token(token_part)
    if ref is None and kind == "nft":
        raise UserError("nft: prefix requires a token ref, not 'rxd'")
    try:
        return Asset(kind="rxd", amount=amount) if ref is None else Asset(kind=kind, amount=amount, ref=ref)
    except RxdSdkError as exc:
        raise UserError(f"invalid asset spec: {exc}") from exc


def _describe_asset(asset: Asset) -> str:
    if asset.kind == "rxd":
        return f"{asset.amount} photons (RXD)"
    if asset.kind == "nft":
        return f"the NFT {asset.ref.txid}:{asset.ref.vout} (carrier {asset.amount} photons)"
    return f"{asset.amount} units of FT {asset.ref.txid}:{asset.ref.vout}"


def _estimate_fee(ctx: CliContext, n_inputs: int, n_outputs: int, override: int | None) -> int:
    if override is not None:
        if override < 0:
            raise UserError("--fee must be non-negative")
        return override
    size = _TX_BASE_BYTES + n_inputs * _TX_PER_INPUT_BYTES + n_outputs * _TX_PER_OUTPUT_BYTES
    return max(_MIN_FEE_PHOTONS, (ctx.fee_rate * size + 999) // 1000)


def _cancel_needs_fee_funding(give_kind: str, give_value: int, fee: int) -> bool:
    """Whether a cancel self-spend needs separate plain-RXD fee funding.

    Token cancels ALWAYS do: an FT cancel conserves the full token amount and
    an NFT cancel returns the full carrier (a singleton has no change path), so
    neither leaves photons for the fee. (Red-team MEDIUM on the NFT slice: the
    original FT-only condition made `swap cancel` — the advertised hard
    revocation — abort for every non-dust NFT.) An RXD cancel funds the fee
    from its own value unless that value cannot cover it.
    """
    return give_kind in ("ft", "nft") or give_value <= fee


# --------------------------------------------------------------------------- wallet plumbing


@dataclass
class _WalletFunds:
    """Wallet UTXOs resolved for a build: funding inputs plus key lookup by owner pkh."""

    triples: list  # (UtxoRecord, address, PrivateKey)

    def key_for_pkh(self, pkh: bytes) -> PrivateKey:
        for _utxo, _addr, key in self.triples:
            if key.public_key().hash160() == pkh:
                return key
        raise UserError(
            "the UTXO's owner key is not in this wallet",
            cause="no wallet address matches the output's owner pubkey-hash",
            fix="run `pyrxd balance --refresh` to discover used addresses, or check the outpoint",
        )

    def change_pkh(self) -> bytes:
        if not self.triples:
            raise UserError("wallet has no spendable UTXOs", fix="fund the wallet first")
        return self.triples[0][2].public_key().hash160()


async def _collect_funds(ctx: CliContext, client) -> _WalletFunds:
    wallet = _load_wallet(ctx)
    return _WalletFunds(triples=await wallet.collect_spendable(client))


async def _rxd_funding(
    client, funds: _WalletFunds, target_photons: int, *, exclude: tuple[str, int] | None = None
) -> list[FundingInput]:
    """Greedy plain-RXD funding selection totalling >= target (fetches each source tx)."""
    picked: list[FundingInput] = []
    total = 0
    for utxo, _addr, key in sorted(funds.triples, key=lambda t: t[0].value, reverse=True):
        if len(picked) >= _MAX_FUNDING_INPUTS:
            break
        if exclude is not None and (str(utxo.tx_hash), utxo.tx_pos) == exclude:
            continue
        source = await fetch_transaction(client, utxo.tx_hash)
        out = source.outputs[utxo.tx_pos]
        if _asset_of(out.satoshis, out.locking_script.serialize()).kind != "rxd":
            continue  # never burn token UTXOs as plain funding
        picked.append(FundingInput(source_tx=source, vout=utxo.tx_pos, key=key))
        total += out.satoshis
        if total >= target_photons:
            return picked
    raise UserError(
        f"wallet cannot fund {target_photons} photons (found {total} across {len(picked)} plain UTXOs)",
        fix="fund the wallet, consolidate UTXOs, or lower the amount/fee",
    )


# --------------------------------------------------------------------------- commands


@click.command(name="orders")
@click.argument("token")
@click.option("--want", is_flag=True, default=False, help="Browse orders WANTING the token instead of offering it.")
@click.option("--node-rpc", required=True, help="Radiant node JSON-RPC URL (node must run -swapindex=1 -txindex=1).")
@click.option("--rpc-user", default=None, envvar="RADIANT_RPC_USER", help="Node RPC username (or $RADIANT_RPC_USER).")
@click.option(
    "--rpc-password", default=None, envvar="RADIANT_RPC_PASSWORD", help="Node RPC password (or $RADIANT_RPC_PASSWORD)."
)
@click.option("--limit", default=50, show_default=True, help="Maximum orders to fetch.")
@click.pass_obj
def swap_orders_cmd(ctx: CliContext, token: str, want: bool, node_rpc: str, rpc_user, rpc_password, limit: int) -> None:
    """Browse + verify the on-chain book for TOKEN ('rxd', 72-hex ref, or TXID:VOUT).

    READ-ONLY. Every row is re-verified against chain data (maker signature,
    advertised token ids vs the real UTXO); rows that fail show the reason.
    """
    ref = _parse_token(token)
    if want and ref is None:
        raise UserError(
            "the want-side book cannot be queried for native RXD",
            cause="RXD-want orders omit want_tokenid on the wire, so the index has no key for them",
            fix="browse the OFFER side of the token you would pay with instead",
        )

    async def _run() -> list[dict]:
        async with NodeRpcSource(node_rpc, rpc_user=rpc_user, rpc_password=rpc_password) as source:
            book = OrderbookClient(source)
            entries = await (book.orders_wanting(ref, limit=limit) if want else book.orders_offering(ref, limit=limit))
        rows = []
        for e in entries:
            demanded = e.order.demanded_outputs
            rows.append(
                {
                    "offered_utxo": f"{e.order.offered_txid}:{e.order.offered_utxo_index}",
                    "gives": _describe_asset(e.offer.terms.give) if e.offer else "(unverified)",
                    "wants": _describe_asset(e.offer.terms.receive)
                    if e.offer
                    else (f"{demanded[0].value} photons?" if demanded else "(unparseable)"),
                    "status": e.status,
                    "fillable": e.fillable,
                    "block_height": e.block_height,
                    "problem": e.problem,
                }
            )
        return rows

    try:
        rows = asyncio.run(_run())
    except RxdSdkError as exc:
        raise click.ClickException(f"orderbook read failed: {exc}") from exc

    payload = {"token": token, "side": "want" if want else "offer", "count": len(rows), "orders": rows}
    if ctx.output_mode in ("json", "quiet"):
        click.echo(emit(payload, mode=ctx.output_mode, quiet_field="count"))
        return
    if not rows:
        click.echo("no open orders")
        return
    for r in rows:
        mark = "FILLABLE" if r["fillable"] else f"{r['status']} — {sanitize_terminal(r['problem'], max_len=100)}"
        click.echo(f"{r['offered_utxo']}\n  gives {r['gives']}\n  wants {r['wants']}\n  [{mark}]")


@click.command(name="post")
@click.option("--give", "give_outpoint", required=True, help="Offered UTXO as TXID:VOUT (wallet-owned, given WHOLE).")
@click.option("--receive", "receive_spec", required=True, help="Demanded asset as rxd:AMOUNT or TOKEN:AMOUNT.")
@click.option(
    "--fee", "fee_override", type=int, default=None, help="Advert-tx fee in photons (default: fee-rate estimate)."
)
@click.pass_obj
def swap_post_cmd(ctx: CliContext, give_outpoint: str, receive_spec: str, fee_override: int | None) -> None:
    """Post an order to the on-chain book: offer the --give UTXO for --receive.

    The offered UTXO is given WHOLE and the signed price has NO expiry — it
    stays fillable until you spend the UTXO (``pyrxd swap cancel``). Pre-split
    an exact amount before posting.
    """
    give_txid, give_vout = _parse_outpoint(give_outpoint)
    receive = _parse_asset_spec(receive_spec)

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, give_txid)
            if not 0 <= give_vout < len(give_source.outputs):
                raise UserError(f"vout {give_vout} does not exist in {give_txid}")
            give_out = give_source.outputs[give_vout]
            give_asset = _asset_of(give_out.satoshis, give_out.locking_script.serialize())

            funds = await _collect_funds(ctx, client)
            maker_key = funds.key_for_pkh(_owner_pkh_of(give_out.locking_script.serialize()))
            post = create_rswp_order(
                give_source_tx=give_source,
                give_vout=give_vout,
                maker_key=maker_key,
                receive=receive,
                maker_receive_pkh=maker_key.public_key().hash160(),
            )
            fee = _estimate_fee(ctx, 1, 2, fee_override)
            funding = await _rxd_funding(client, funds, fee + _MIN_FEE_PHOTONS, exclude=(give_txid, give_vout))
            advert_tx = build_advert_tx(
                advert_script=post.advert_script, funding=funding, change_pkh=funds.change_pkh(), fee=fee
            )
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="POST public swap order (no expiry — cancel is the only revocation)",
                        lines=[
                            f"you give   : {_describe_asset(give_asset)}  ({give_txid}:{give_vout}, spent WHOLE)",
                            f"you demand : {_describe_asset(receive)}",
                            f"advert fee : {fee} photons",
                        ],
                    )
                ],
            )
            advert_txid = await client.broadcast(advert_tx.serialize())
            return {
                "advert_txid": str(advert_txid),
                "offered_utxo": f"{give_txid}:{give_vout}",
                "gives": _describe_asset(give_asset),
                "wants": _describe_asset(receive),
            }

    _finish(ctx, _run, quiet_field="advert_txid")


@click.command(name="take")
@click.option(
    "--advert",
    "advert_arg",
    required=True,
    help="The order's OP_RETURN script hex, a raw advert-tx hex, or @path to a file holding either.",
)
@click.option("--fee", "fee_override", type=int, default=None, help="Completion-tx fee in photons.")
@click.pass_obj
def swap_take_cmd(ctx: CliContext, advert_arg: str, fee_override: int | None) -> None:
    """Verify and fill an on-chain order (the offered UTXO's source tx is fetched txid-verified).

    Every advertised claim is checked against the chain before your funds are
    committed; a lying or unfillable advert aborts with the reason.
    """
    order = _decode_advert_arg(advert_arg)
    if order.demanded_outputs is None or len(order.demanded_outputs) != 1:
        raise UserError("order does not have exactly one demanded output", cause="unenforceable demand (design D6)")
    demand = order.demanded_outputs[0]
    demand_asset = _asset_of(demand.value, demand.script)
    if demand_asset.kind != "rxd":
        raise UserError(
            "this CLI can fund RXD-demand orders only (the maker wants an FT)",
            fix="use the pyrxd.swap.rswp library take path with FT funding inputs",
        )

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, order.offered_txid)
            funds = await _collect_funds(ctx, client)
            fee = _estimate_fee(ctx, 1 + 2, 4, fee_override)
            funding = await _rxd_funding(client, funds, demand.value + fee)
            taker_pkh = funds.change_pkh()
            completion = take_rswp_order(
                order,
                give_source_tx=give_source,
                funding=funding,
                taker_receive_pkh=taker_pkh,
                taker_change_pkh=taker_pkh,
                fee=fee,
            )
            gives = _asset_of(
                give_source.outputs[order.offered_utxo_index].satoshis,
                give_source.outputs[order.offered_utxo_index].locking_script.serialize(),
            )
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="FILL swap order",
                        lines=[
                            f"you pay     : {demand.value} photons to the maker",
                            f"you receive : {_describe_asset(gives)}",
                            f"fee         : {fee} photons",
                        ],
                    )
                ],
            )
            txid = await client.broadcast(completion.serialize())
            return {
                "completion_txid": str(txid),
                "paid_photons": demand.value,
                "received": _describe_asset(gives),
            }

    _finish(ctx, _run, quiet_field="completion_txid")


@click.command(name="cancel")
@click.option("--give", "give_outpoint", required=True, help="The posted order's offered UTXO as TXID:VOUT.")
@click.option("--fee", "fee_override", type=int, default=None, help="Cancel-tx fee in photons.")
@click.pass_obj
def swap_cancel_cmd(ctx: CliContext, give_outpoint: str, fee_override: int | None) -> None:
    """Cancel a posted order by self-spending its offered UTXO — the ONLY hard revocation.

    Until this confirms, anyone holding the signed advert can still fill at
    the original price.
    """
    give_txid, give_vout = _parse_outpoint(give_outpoint)

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, give_txid)
            if not 0 <= give_vout < len(give_source.outputs):
                raise UserError(f"vout {give_vout} does not exist in {give_txid}")
            give_out = give_source.outputs[give_vout]
            give_asset = _asset_of(give_out.satoshis, give_out.locking_script.serialize())
            funds = await _collect_funds(ctx, client)
            maker_key = funds.key_for_pkh(_owner_pkh_of(give_out.locking_script.serialize()))
            fee = _estimate_fee(ctx, 2, 2, fee_override)
            funding = None
            if _cancel_needs_fee_funding(give_asset.kind, give_out.satoshis, fee):
                funding = await _rxd_funding(client, funds, fee, exclude=(give_txid, give_vout))
            cancel = build_cancel_tx(
                offered_source_tx=give_source,
                offered_vout=give_vout,
                maker_key=maker_key,
                refund_pkh=maker_key.public_key().hash160(),
                fee=fee,
                funding=funding,
            )
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="CANCEL posted order (self-spend; kills every copy of the signed offer)",
                        lines=[
                            f"reclaims : {_describe_asset(give_asset)}  ({give_txid}:{give_vout})",
                            f"fee      : {fee} photons",
                        ],
                    )
                ],
            )
            txid = await client.broadcast(cancel.serialize())
            return {"cancel_txid": str(txid), "reclaimed": _describe_asset(give_asset)}

    _finish(ctx, _run, quiet_field="cancel_txid")


# --------------------------------------------------------------------------- shared runners


def _decode_advert_arg(advert_arg: str) -> RswpOrder:
    """Accept the OP_RETURN script hex, a raw advert-tx hex, or @file of either."""
    text = advert_arg
    if text.startswith("@"):
        from pathlib import Path

        try:
            text = Path(text[1:]).read_text().strip()
        except OSError as exc:
            raise UserError(f"cannot read advert file: {exc}") from exc
    try:
        blob = bytes.fromhex(text)
    except ValueError as exc:
        raise UserError("advert is not valid hex") from exc
    try:
        return decode_rswp_order(blob)
    except ValidationError:
        pass  # not a bare OP_RETURN script — try it as a whole transaction
    tx = Transaction.from_hex(blob)
    if tx is not None:
        for out in tx.outputs:
            try:
                return decode_rswp_order(out.locking_script.serialize())
            except ValidationError:
                continue
    raise UserError(
        "no decodable RSWP order in the input",
        cause="input is neither an RSWP OP_RETURN script nor a transaction containing one",
        fix="pass the advert output's script hex, or the full advert transaction hex",
    )


def _finish(ctx: CliContext, run, *, quiet_field: str) -> None:
    """Run an async command body; render its payload; map SDK errors to CLI errors."""
    try:
        payload = asyncio.run(run())
    except (UserError, click.ClickException):
        raise
    except RxdSdkError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(emit(payload, mode=ctx.output_mode, quiet_field=quiet_field))

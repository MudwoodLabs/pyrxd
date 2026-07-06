"""``pyrxd swap orders/post/take/cancel/reserve/refund`` — the on-chain RSWP orderbook commands.

Thin CLI over the proven :mod:`pyrxd.swap.rswp` library (design:
docs/plans/2026-07-05-rswp-orderbook-design.md). Same safety posture as the
glyph commands:

* **Read side** (``orders``) never signs and never broadcasts. It talks to a
  Radiant node running ``-swapindex=1`` and re-verifies every row against
  chain data — *fillable* means the maker signature and every advertised
  claim checked out, not that the index said so.
* **Write side** (``post`` / ``take`` / ``cancel`` / ``reserve`` / ``refund``)
  shows a full value summary and asks for confirmation before ANY broadcast
  (``--json`` requires ``--yes``, same gate as the glyph commands). Funding
  comes from the local HD wallet; the offered/give UTXO must be owned by a
  wallet key. Every transaction is built exclusively with
  :mod:`pyrxd.swap.rswp` builders — this module never hand-assembles a
  script or transaction.

Wire/format authority: the maker's offer is signed
``SIGHASH_SINGLE|ANYONECANPAY|FORKID`` — posting publishes a price that stays
fillable until the offered UTXO is spent. ``cancel`` (a self-spend) is the
ONLY hard revocation for a v2 order; the confirmation text says so.

v3 timelocked-refund covenant flows (:mod:`pyrxd.swap.rswp.covenant`)
----------------------------------------------------------------------
``reserve`` puts RXD into a v3 refund covenant; ``post`` auto-detects a
covenant-held ``--give`` (via ``is_refund_covenant``) and posts a v3 advert
instead of a v2 one; ``take`` auto-detects a v3 advert (``expiry_height`` set)
and fills it through the CLTV-aware builder; ``refund`` and ``cancel`` route a
covenant-held ``--give`` to the covenant builders (before-expiry self-spend
for ``cancel``, at/after-expiry CLTV reclaim for ``refund``). Two operator
warnings are MANDATORY reading (both repeated in every relevant confirmation
summary below — see :mod:`pyrxd.swap.rswp.covenant`'s module docstring for
the full detail):

* **Refund txids are third-party malleable.** Track a refund by the
  covenant OUTPOINT it spent, never by the txid the CLI prints.
* **Expiry does not stop fills.** At/after the covenant's expiry, the
  maker's refund RACES any late taker still holding a signed v3 advert —
  "expired" alone does not make the reservation safe; act promptly.

v3 adverts are DROPPED by the deployed Radiant-Core ``-swapindex`` (design
note D1) — ``post``'s v3 path is rollout/testing only until every consumer
that matters parses v3.
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
    build_covenant_cancel_tx,
    build_covenant_refund_tx,
    create_covenant_order,
    create_rswp_order,
    decode_rswp_order,
    is_refund_covenant,
    parse_refund_covenant,
    prepare_covenant_offer,
    take_covenant_order,
    take_rswp_order,
)
from ..swap.rswp.covenant import _inner_p2pkh_pkh
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
    wallet: object = None  # the loaded HdWallet, for deriving a key by pkh beyond the UTXO-bearing set

    def key_for_pkh(self, pkh: bytes) -> PrivateKey:
        # First the UTXO-bearing addresses (the common case, and all we have if `wallet` wasn't threaded).
        for _utxo, _addr, key in self.triples:
            if key.public_key().hash160() == pkh:
                return key
        # Fallback (audit M5): derive from ANY known HD address, not only ones that currently hold a UTXO.
        # A v3 covenant refund/cancel spends only the covenant input, so the owner_pkh address often holds
        # no plain UTXO at reclaim time — yet it is the maker's own address, so its key is derivable. This
        # makes the advertised "guaranteed reclaim" hold without a live UTXO sitting at owner_pkh.
        if self.wallet is not None:
            for rec in getattr(self.wallet, "addresses", {}).values():
                key = self.wallet._privkey_for(rec.change, rec.index)
                if key.public_key().hash160() == pkh:
                    return key
        raise UserError(
            "the owner key for this output is not in this wallet",
            cause="no wallet address (spendable or derived) matches the output's owner pubkey-hash",
            fix="run `pyrxd balance --refresh` to widen HD discovery, or check the outpoint/--wallet",
        )

    def change_pkh(self) -> bytes:
        if not self.triples:
            raise UserError("wallet has no spendable UTXOs", fix="fund the wallet first")
        return self.triples[0][2].public_key().hash160()


async def _collect_funds(ctx: CliContext, client) -> _WalletFunds:
    wallet = _load_wallet(ctx)
    return _WalletFunds(triples=await wallet.collect_spendable(client), wallet=wallet)


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


async def _ft_funding(client, funds: _WalletFunds, ref, target_units: int) -> list[FundingInput]:
    """Greedy FT funding selection: UTXOs of exactly *ref* totalling >= target units.

    Mirrors :func:`_rxd_funding`; the library take paths re-enforce per-ref
    conservation and emit FT change, so over-selection is safe and any other
    token is never picked up here.
    """
    picked: list[FundingInput] = []
    total = 0
    for utxo, _addr, key in sorted(funds.triples, key=lambda t: t[0].value, reverse=True):
        if len(picked) >= _MAX_FUNDING_INPUTS:
            break
        source = await fetch_transaction(client, utxo.tx_hash)
        out = source.outputs[utxo.tx_pos]
        asset = _asset_of(out.satoshis, out.locking_script.serialize())
        if asset.kind != "ft" or asset.ref != ref:
            continue
        picked.append(FundingInput(source_tx=source, vout=utxo.tx_pos, key=key))
        total += asset.amount
        if total >= target_units:
            return picked
    raise UserError(
        f"wallet cannot fund {target_units} units of the demanded FT (found {total} across {len(picked)} UTXOs)",
        fix="acquire the token, consolidate its UTXOs, or fund via the library take path",
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


@click.command(name="reserve")
@click.option("--amount", "amount", required=True, type=int, help="Photons of RXD to reserve into the v3 covenant.")
@click.option(
    "--expiry", "expiry_height", required=True, type=int, help="Block height the CLTV refund branch opens at."
)
@click.option("--fee", "fee_override", type=int, default=None, help="Reservation-tx fee in photons.")
@click.pass_obj
def swap_reserve_cmd(ctx: CliContext, amount: int, expiry_height: int, fee_override: int | None) -> None:
    """Reserve RXD into a v3 timelocked-refund covenant (RXD ONLY — no FT/NFT).

    ``pyrxd swap post --give <the reservation outpoint>`` can then advertise
    it as a v3 order. Two things every operator MUST understand before
    running this:

    \b
    * Reclaim at --expiry is GUARANTEED — `pyrxd swap refund` always works
      at/after that height (barring a lost key).
    * That guarantee does NOT stop a fill: at/after --expiry the refund
      RACES any late taker still holding a signed v3 advert. Cancel with
      `pyrxd swap cancel` before --expiry if you no longer want it live.
    """
    if amount <= 0:
        raise UserError("--amount must be Positive")
    if expiry_height <= 0:
        raise UserError("--expiry must be a Positive block height")

    async def _run() -> dict:
        async with ctx.make_client() as client:
            funds = await _collect_funds(ctx, client)
            owner_pkh = funds.change_pkh()
            fee = _estimate_fee(ctx, 2, 2, fee_override)
            funding = await _rxd_funding(client, funds, amount + fee)
            reserve_tx = prepare_covenant_offer(
                funding=funding,
                photons=amount,
                owner_pkh=owner_pkh,
                expiry_height=expiry_height,
                change_pkh=owner_pkh,
                fee=fee,
            )
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="RESERVE into v3 refund covenant (RXD only)",
                        lines=[
                            f"reserve  : {amount} photons — RXD only, no FT/NFT",
                            f"guaranteed reclaim at height {expiry_height} via `pyrxd swap refund`",
                            "WARNING  : refund races late fills at/after expiry — expiry does Not itself "
                            "invalidate a fill; act promptly.",
                            f"fee      : {fee} photons",
                        ],
                    )
                ],
            )
            txid = await client.broadcast(reserve_tx.serialize())
            return {
                "reservation_txid": str(txid),
                "covenant_outpoint": f"{txid}:0",
                "reserved_photons": amount,
                "expiry_height": expiry_height,
            }

    _finish(ctx, _run, quiet_field="reservation_txid")


@click.command(name="post")
@click.option("--give", "give_outpoint", required=True, help="Offered UTXO as TXID:VOUT (wallet-owned, given WHOLE).")
@click.option("--receive", "receive_spec", required=True, help="Demanded asset as rxd:AMOUNT or TOKEN:AMOUNT.")
@click.option(
    "--fee", "fee_override", type=int, default=None, help="Advert-tx fee in photons (default: fee-rate estimate)."
)
@click.pass_obj
def swap_post_cmd(ctx: CliContext, give_outpoint: str, receive_spec: str, fee_override: int | None) -> None:
    """Post an order to the on-chain book: offer the --give UTXO for --receive.

    A plain P2PKH/FT --give is posted as a v2 order: it is given WHOLE and the
    signed price has NO expiry — it stays fillable until you spend the UTXO
    (``pyrxd swap cancel``). Pre-split an exact amount before posting.

    A --give that rests in a v3 refund covenant (``pyrxd swap reserve``) is
    posted as a v3 order instead (the reservation's expiry rides on the
    advert). WARNING: the deployed Radiant-Core ``-swapindex`` DROPS v3
    adverts — this path is rollout/testing only until every consumer you
    care about parses v3.
    """
    give_txid, give_vout = _parse_outpoint(give_outpoint)
    receive = _parse_asset_spec(receive_spec)

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, give_txid)
            if not 0 <= give_vout < len(give_source.outputs):
                raise UserError(f"vout {give_vout} does not exist in {give_txid}")
            give_out = give_source.outputs[give_vout]
            give_spk = give_out.locking_script.serialize()
            funds = await _collect_funds(ctx, client)

            extra_lines: list[str] = []
            if is_refund_covenant(give_spk):
                owner_pkh, expiry = _inner_p2pkh_pkh(give_spk)
                maker_key = funds.key_for_pkh(owner_pkh)
                give_asset = Asset(kind="rxd", amount=give_out.satoshis)
                post = create_covenant_order(
                    covenant_source_tx=give_source,
                    covenant_vout=give_vout,
                    maker_key=maker_key,
                    receive=receive,
                    maker_receive_pkh=maker_key.public_key().hash160(),
                )
                title = "POST v3 covenant swap order (ROLLOUT/TESTING ONLY)"
                extra_lines = [
                    f"expiry     : height {expiry} (v3 refund covenant)",
                    "WARNING    : the deployed swapindex Drops v3 adverts — rollout/testing only, "
                    "not yet indexed by production nodes.",
                ]
            else:
                give_asset = _asset_of(give_out.satoshis, give_spk)
                maker_key = funds.key_for_pkh(_owner_pkh_of(give_spk))
                post = create_rswp_order(
                    give_source_tx=give_source,
                    give_vout=give_vout,
                    maker_key=maker_key,
                    receive=receive,
                    maker_receive_pkh=maker_key.public_key().hash160(),
                )
                title = "POST public swap order (no expiry — cancel is the only revocation)"

            fee = _estimate_fee(ctx, 1, 2, fee_override)
            funding = await _rxd_funding(client, funds, fee + _MIN_FEE_PHOTONS, exclude=(give_txid, give_vout))
            advert_tx = build_advert_tx(
                advert_script=post.advert_script, funding=funding, change_pkh=funds.change_pkh(), fee=fee
            )
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title=title,
                        lines=[
                            f"you give   : {_describe_asset(give_asset)}  ({give_txid}:{give_vout}, spent WHOLE)",
                            f"you demand : {_describe_asset(receive)}",
                            f"advert fee : {fee} photons",
                            *extra_lines,
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
    committed; a lying or unfillable advert aborts with the reason. An order
    carrying an ``expiry_height`` (v3, covenant-held) is filled through the
    CLTV-aware builder, which refuses to fill at/after expiry — the chain tip
    is fetched fresh (via ElectrumX) and checked BEFORE the wallet is even
    opened, so an unreachable node fails closed with no funds at risk.
    """
    order = _decode_advert_arg(advert_arg)
    if order.demanded_outputs is None or len(order.demanded_outputs) != 1:
        raise UserError("order does not have exactly one demanded output", cause="unenforceable demand (design D6)")
    demand = order.demanded_outputs[0]
    demand_asset = _asset_of(demand.value, demand.script)
    if demand_asset.kind == "nft":
        raise UserError(
            "this CLI cannot fund NFT-demand orders (the maker wants a specific singleton)",
            fix="use the pyrxd.swap.rswp library take path with the singleton as a funding input",
        )

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, order.offered_txid)
            tip_height = None
            if order.expiry_height is not None:
                # Fetched — and the order's freshness checked — BEFORE any wallet
                # access: a dead node fails closed without ever prompting for the
                # mnemonic. See take_covenant_order's docstring: filling at/after
                # expiry races the maker's live refund.
                tip_height = int(await client.get_tip_height())
            funds = await _collect_funds(ctx, client)
            fee = _estimate_fee(ctx, 1 + 2, 4, fee_override)
            if demand_asset.kind == "ft":
                # The demand is paid in tokens; plain RXD only needs to cover the
                # fee (the library enforces per-ref conservation + emits change).
                funding = await _ft_funding(client, funds, demand_asset.ref, demand_asset.amount)
                funding += await _rxd_funding(client, funds, fee)
            else:
                funding = await _rxd_funding(client, funds, demand.value + fee)
            taker_pkh = funds.change_pkh()
            if order.expiry_height is not None:
                completion = take_covenant_order(
                    order,
                    give_source_tx=give_source,
                    funding=funding,
                    taker_receive_pkh=taker_pkh,
                    taker_change_pkh=taker_pkh,
                    fee=fee,
                    current_height=tip_height,
                )
                gives = Asset(kind="rxd", amount=give_source.outputs[order.offered_utxo_index].satoshis)
            else:
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
                        # Show what the taker ACTUALLY pays — the demanded ASSET, not the carrier photons.
                        # For an FT demand `demand.value` is a tiny carrier (e.g. ~546) while the real cost is
                        # `demand_asset.amount` token units; printing photons here understated the cost on the
                        # one screen that exists to obtain informed consent (audit M3).
                        lines=[
                            f"you pay     : {_describe_asset(demand_asset)} to the maker",
                            f"you receive : {_describe_asset(gives)}",
                            f"fee         : {fee} photons",
                        ],
                    )
                ],
            )
            txid = await client.broadcast(completion.serialize())
            return {
                "completion_txid": str(txid),
                "paid": _describe_asset(demand_asset),
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
    the original price. A --give held in a v3 refund covenant is cancelled
    via its SWAP-branch self-spend (works at ANY height, before or after
    expiry); a plain P2PKH/FT --give keeps the v2 self-spend path.
    """
    give_txid, give_vout = _parse_outpoint(give_outpoint)

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, give_txid)
            if not 0 <= give_vout < len(give_source.outputs):
                raise UserError(f"vout {give_vout} does not exist in {give_txid}")
            give_out = give_source.outputs[give_vout]
            give_spk = give_out.locking_script.serialize()
            funds = await _collect_funds(ctx, client)
            extra_lines: list[str] = []
            if is_refund_covenant(give_spk):
                owner_pkh, expiry = _inner_p2pkh_pkh(give_spk)
                maker_key = funds.key_for_pkh(owner_pkh)
                give_asset = Asset(kind="rxd", amount=give_out.satoshis)
                fee = _estimate_fee(ctx, 1, 1, fee_override)
                cancel = build_covenant_cancel_tx(
                    covenant_source_tx=give_source,
                    covenant_vout=give_vout,
                    maker_key=maker_key,
                    refund_pkh=owner_pkh,
                    fee=fee,
                )
                title = "CANCEL v3 covenant reservation (SWAP-branch self-spend, before OR after expiry)"
                extra_lines = [f"covenant expiry: height {expiry} (informational — cancel works at Any height)"]
            else:
                give_asset = _asset_of(give_out.satoshis, give_spk)
                maker_key = funds.key_for_pkh(_owner_pkh_of(give_spk))
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
                title = "CANCEL posted order (self-spend; kills every copy of the signed offer)"

            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title=title,
                        lines=[
                            f"reclaims : {_describe_asset(give_asset)}  ({give_txid}:{give_vout})",
                            f"fee      : {fee} photons",
                            *extra_lines,
                        ],
                    )
                ],
            )
            txid = await client.broadcast(cancel.serialize())
            return {"cancel_txid": str(txid), "reclaimed": _describe_asset(give_asset)}

    _finish(ctx, _run, quiet_field="cancel_txid")


@click.command(name="refund")
@click.option("--give", "give_outpoint", required=True, help="The v3 covenant UTXO to reclaim, as TXID:VOUT.")
@click.option("--fee", "fee_override", type=int, default=None, help="Refund-tx fee in photons.")
@click.pass_obj
def swap_refund_cmd(ctx: CliContext, give_outpoint: str, fee_override: int | None) -> None:
    """Reclaim a v3 covenant reservation via its CLTV refund branch.

    Only mineable AT or AFTER the covenant's expiry height — a node will
    reject this transaction as non-final if broadcast earlier. Two things to
    remember (see :mod:`pyrxd.swap.rswp.covenant`):

    \b
    * The resulting txid is third-party MALLEABLE (the branch selector is
      unsigned scriptSig data) — track this reservation by the covenant
      OUTPOINT you reclaimed, never by the txid this command prints.
    * Filing at/after expiry RACES any late taker still holding a signed
      v3 advert for this same outpoint — cancel first if the order was
      never advertised, or you no longer want it live.
    """
    give_txid, give_vout = _parse_outpoint(give_outpoint)

    async def _run() -> dict:
        async with ctx.make_client() as client:
            give_source = await fetch_transaction(client, give_txid)
            if not 0 <= give_vout < len(give_source.outputs):
                raise UserError(f"vout {give_vout} does not exist in {give_txid}")
            give_out = give_source.outputs[give_vout]
            give_spk = give_out.locking_script.serialize()
            if parse_refund_covenant(give_spk) is None:
                raise UserError(
                    "the --give UTXO is Not a v3 refund covenant",
                    cause="`pyrxd swap refund` only reclaims v3 covenant reservations",
                    fix="use `pyrxd swap cancel` for a plain v2 posted order instead",
                )
            owner_pkh, expiry = _inner_p2pkh_pkh(give_spk)
            funds = await _collect_funds(ctx, client)
            maker_key = funds.key_for_pkh(owner_pkh)
            fee = _estimate_fee(ctx, 1, 1, fee_override)
            refund_tx = build_covenant_refund_tx(
                covenant_source_tx=give_source,
                covenant_vout=give_vout,
                maker_key=maker_key,
                refund_pkh=owner_pkh,
                fee=fee,
            )
            _confirm_or_abort(
                ctx,
                [
                    _BroadcastSummary(
                        title="REFUND v3 covenant reservation (CLTV branch)",
                        lines=[
                            f"reclaims : {give_out.satoshis} photons — RXD only  ({give_txid}:{give_vout})",
                            f"mineable : only at/after height {expiry}",
                            "WARNING  : the refund txid is Malleable — track the OUTPOINT above, never this txid.",
                            f"fee      : {fee} photons",
                        ],
                    )
                ],
            )
            txid = await client.broadcast(refund_tx.serialize())
            return {
                "refund_txid": str(txid),
                "reclaimed_outpoint": f"{give_txid}:{give_vout}",
                "reclaimed_photons": give_out.satoshis,
                "expiry_height": expiry,
            }

    _finish(ctx, _run, quiet_field="refund_txid")


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

"""Read-only client for the on-chain RSWP orderbook (network edge of :mod:`pyrxd.swap.rswp`).

Pulls open orders from a Radiant node running ``-swapindex=1`` (RPCs
``getopenorders`` / ``getopenordersbywant``; in the index since Radiant-Core
2.0.0), then treats every entry as HOSTILE input: the offered source
transaction is fetched with the computed-txid-equals-requested check
(:func:`pyrxd.swap.resolve.fetch_transaction`), the advertisement's claims are
verified against the chain by the :func:`~pyrxd.swap.rswp.orders.rswp_order_to_swap_offer`
bridge, and the maker's ``0xC3`` signature is verified — an order is reported
*fillable* only after all three pass. Orders that fail are still returned,
with ``problem`` set, so a browser can show a lying advertisement for what it
is instead of silently dropping it.

This module never broadcasts and never signs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ...glyph.types import GlyphRef
from ...gravity.swap_order import RswpOrder, parse_price_terms
from ...security.errors import ValidationError
from ...security.types import Txid
from ..resolve import fetch_transaction
from ..types import SwapOffer
from .orders import rswp_order_to_swap_offer, verify_offer_signature
from .wire import swap_token_id


@runtime_checkable
class OrderbookSource(Protocol):
    """Read surface of a Radiant node with ``-swapindex=1`` (and ``-txindex=1`` for source fetch).

    Implementations MUST raise on transport failure or an unreachable/disabled
    index — returning ``[]`` / ``None`` for "could not check" would present a
    healthy-but-empty book (fail-open). The swapindex RPCs raise
    ``Swap index not enabled`` when started without the flag; let that
    propagate.
    """

    async def get_open_orders(self, token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        """``getopenorders <token_ref> <limit> <offset>`` — orders OFFERING the given token id."""
        ...  # pragma: no cover

    async def get_open_orders_by_want(self, want_token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        """``getopenordersbywant <want_token_ref> <limit> <offset>`` — orders WANTING the given token id."""
        ...  # pragma: no cover

    async def get_transaction(self, txid: str | Txid) -> bytes:
        """Raw transaction bytes for *txid*; raise if unknown. (Shape shared with ``ElectrumXClient``
        so :func:`pyrxd.swap.resolve.fetch_transaction` can do its server-honesty check.)"""
        ...  # pragma: no cover

    async def is_unspent(self, txid: str, vout: int) -> bool:
        """Whether the outpoint is currently unspent (``gettxout``, mempool-aware). Raise on failure."""
        ...  # pragma: no cover


@dataclass(frozen=True)
class BookEntry:
    """One orderbook row, verified as far as it could be.

    ``status`` is chain fact (offered UTXO unspent = the order is still open;
    spent = filled or cancelled — the spending tx is the settlement proof).
    ``fillable`` means the full hostile-input pipeline passed and ``offer`` is
    ready for :func:`pyrxd.swap.partial.accept_offer`; otherwise ``problem``
    says exactly which verification failed.
    """

    order: RswpOrder
    status: str  # "open" | "spent"
    fillable: bool
    offer: SwapOffer | None
    problem: str | None
    block_height: int | None


def _order_from_rpc(entry: dict) -> RswpOrder:
    """Rebuild an :class:`RswpOrder` from a ``getopenorders*`` response row.

    The RPC reports 32-byte ids in display (big-endian) hex; the dataclass
    carries them in on-chain pushed orientation, so they are reversed back.
    """
    try:
        version = int(entry["version"])
        want_hex = entry.get("want_tokenid")
        price_terms = bytes.fromhex(entry["price_terms"])
        return RswpOrder(
            version=version,
            flags=int(entry["flags"]),
            offered_type=int(entry["offered_type"]),
            terms_type=int(entry["terms_type"]),
            token_id=bytes.fromhex(entry["tokenid"])[::-1],
            want_token_id=None if want_hex is None else bytes.fromhex(want_hex)[::-1],
            offered_utxo_hash=bytes.fromhex(entry["utxo"]["txid"])[::-1],
            offered_utxo_index=int(entry["utxo"]["vout"]),
            price_terms=price_terms,
            demanded_outputs=parse_price_terms(price_terms),
            signature=bytes.fromhex(entry["signature"]),
            # The deployed index parses v2 only; a future v3-aware index will
            # report an expiry field, at which point this gains a real value.
            expiry_height=None,
        )
    except ValidationError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError(f"malformed swapindex response row: {exc!r}") from exc


class OrderbookClient:
    """Browse the on-chain book through any :class:`OrderbookSource`, verifying before trusting."""

    def __init__(self, source: OrderbookSource) -> None:
        self._source = source

    async def orders_offering(self, ref: GlyphRef | None, *, limit: int = 100, offset: int = 0) -> list[BookEntry]:
        """Open orders OFFERING the given asset (``None`` = native RXD)."""
        rows = await self._source.get_open_orders(swap_token_id(ref).hex(), limit=limit, offset=offset)
        return [await self._verify_row(row) for row in rows]

    async def orders_wanting(self, ref: GlyphRef, *, limit: int = 100, offset: int = 0) -> list[BookEntry]:
        """Open orders WANTING the given Glyph token (the ask side of that token's book)."""
        rows = await self._source.get_open_orders_by_want(swap_token_id(ref).hex(), limit=limit, offset=offset)
        return [await self._verify_row(row) for row in rows]

    async def _verify_row(self, row: dict) -> BookEntry:
        """The hostile-input pipeline for one index row. Transport errors propagate (fail closed);
        per-order verification failures become ``problem`` entries."""
        block_height = row.get("block_height")
        order = _order_from_rpc(row)  # malformed rows raise — an index handing back garbage is transport-level
        unspent = await self._source.is_unspent(order.offered_txid, order.offered_utxo_index)
        status = "open" if unspent else "spent"
        try:
            give_source_tx = await fetch_transaction(self._source, order.offered_txid)
            offer = rswp_order_to_swap_offer(order, give_source_tx=give_source_tx)
            verify_offer_signature(offer)
        except ValidationError as exc:
            return BookEntry(
                order=order, status=status, fillable=False, offer=None, problem=str(exc), block_height=block_height
            )
        return BookEntry(
            order=order,
            status=status,
            fillable=unspent,
            offer=offer,
            problem=None if unspent else "offered UTXO already spent (order filled or cancelled)",
            block_height=block_height,
        )


__all__ = ["BookEntry", "OrderbookClient", "OrderbookSource"]

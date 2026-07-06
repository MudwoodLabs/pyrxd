"""``OrderbookSource`` over RXinDexer's ``swap.*`` ElectrumX extension — the no-swapindex-node transport.

Lets :class:`~pyrxd.swap.rswp.book.OrderbookClient` browse the on-chain RSWP book by
talking to a hosted RXinDexer endpoint instead of running a Radiant node with
``-swapindex=1``. This is the second, follow-up source tracked in
``docs/plans/2026-07-05-rswp-orderbook-design.md`` (D10) — :class:`~pyrxd.swap.rswp.node_rpc.NodeRpcSource`
remains the production default.

**Verified from source, 2026-07-05** (not from memory — see the citations below):

* A fresh fetch of ``Radiant-Core/RXinDexer`` ``main``
  (``electrumx/server/swap_index.py`` + ``electrumx/server/glyph_api.py``,
  upstream state as of 2026-06-30) was read directly, cross-checked against an
  older local checkout of the same files.
* The wired RPC is **``swap.get_orders(base_ref=None, quote_ref=None, limit=50,
  offset=0)``**, registered in ``glyph_api.py``'s ``GLYPH_METHODS`` table — NOT
  the differently-named ``swap.get_open_orders`` / ``swap.get_orderbook`` that
  ``docs/swap-order-wire-format.md`` §Conflicts describes; that doc's method
  names were accurate for an EARLIER upstream shape and are now stale (the
  ``SWAP_METHODS`` table in ``swap_index.py`` that advertised those names was
  dead code — never wired to any session — and has since been removed upstream).
  With only ``base_ref``: open orders offering that token. With both refs: the
  ``{bids, asks}`` orderbook for that pair. **There is no want-token-only
  filter** — see :meth:`RxindexerOrderbookSource.get_open_orders_by_want`.
* ``SwapOrderInfo`` (the indexed row) has **no slot for the raw ``signature``,
  the raw ``price_terms`` blob, ``version``, ``flags``, ``offered_type``, or
  ``terms_type``** — confirmed by reading the dataclass ``__slots__`` in both
  checkouts. ``_parse_rswp_v2`` extracts ``signature``/``price_terms_blob`` as
  LOCAL variables while parsing and never stores them; only derived fields
  (``price``, ``amount``, ``maker_address``, ``status``, …) persist. A
  from-``price_terms``-fix landed upstream 2026-06-01 (commit ``24572c7c``) so
  those DERIVED fields are no longer the ``0``/``null`` garbage the wire-format
  doc's §Conflicts records — but the raw bytes needed to reconstruct a
  signature-verifiable :class:`~pyrxd.gravity.swap_order.RswpOrder` were never
  exposed through ``swap.get_orders`` in either checkout examined.

Because of that last point, **a literal field-name mapping of RXinDexer's
dict onto the ``_order_from_rpc`` row shape is not possible** — the fields
:func:`pyrxd.swap.rswp.book._order_from_rpc` needs (``signature``,
``price_terms``, ``tokenid``, ``utxo.txid``/``utxo.vout``, ``version``,
``flags``, ``offered_type``, ``terms_type``) simply are not in RXinDexer's
response. This source resolves that by using ``swap.get_orders`` for
DISCOVERY ONLY (the advertising tx's ``tx_hash``/``vout``, i.e. WHICH orders
exist for a token), then independently re-derives every RswpOrder field by
fetching that transaction (txid-verified, :func:`pyrxd.swap.resolve.fetch_transaction`)
and running the canonical, already-shipped
:func:`pyrxd.gravity.swap_order.decode_rswp_order` over its OP_RETURN output —
the SAME decode the take path and :class:`NodeRpcSource` rows rely on.
RXinDexer's own decoded/cached fields (price, amount, maker, status) are never
read or trusted by this module; this is consistent with, not a deviation from,
the "treat every index row as HOSTILE" posture the rest of ``pyrxd.swap.rswp``
already documents.

``is_unspent`` similarly does not trust RXinDexer's cached order ``status``
(which is itself a look-aside cache updated on block processing, not a live
chain read, and is exactly the kind of derived field this module treats as
untrusted): it fetches the offered UTXO's own source transaction, derives the
ElectrumX ``scripthash`` of its locking script, and checks
``blockchain.scripthash.listunspent`` (standard base ElectrumX, already
wrapped by :meth:`pyrxd.network.electrumx.ElectrumXClient.get_utxos`) for that
exact ``(txid, vout)`` pair.

**Known, source-verified gaps (not guesses):**

1. ``get_open_orders_by_want`` raises :class:`~pyrxd.security.errors.NetworkError`
   unconditionally — RXinDexer has no index for "orders wanting token X"
   independent of a specific ``base_ref``, so there is no query to perform.
   This is a real capability gap in the upstream RPC surface, not a transport
   hiccup; enumerating every possible ``base_ref`` client-side to fake it would
   be unbounded and is refused rather than attempted.
2. RSWP v3 (expiry-bearing) orders decode fine here (``decode_rswp_order``
   handles v2 and v3), but :func:`pyrxd.swap.rswp.book._order_from_rpc` (which
   this source's rows flow into, unmodified) has no expiry field on its row
   shape and always passes ``expiry_height=None`` — so a v3 row reconstructed
   through :class:`~pyrxd.gravity.swap_order.RswpOrder` will fail its own
   ``version == 3 requires expiry_height`` invariant and raise there. That is
   an existing ``OrderbookSource`` Protocol limitation (shared with any future
   v3-aware source), not something this adapter papers over.
3. This module is EXPERIMENTAL relative to :class:`NodeRpcSource`: it has not
   been exercised against a live RXinDexer endpoint in this change (no such
   endpoint was reachable from this environment) — only against the source
   citations above and a fake-transport unit-test double. Treat it as unproven
   in production until run against a real ``-swapindex``-free RXinDexer.
"""

from __future__ import annotations

from typing import Any

from ...gravity.swap_order import decode_rswp_order
from ...hash import sha256
from ...network.rxindexer import RxinDexerClient, RxinDexerError
from ...security.errors import NetworkError, ValidationError
from ...security.types import Hex32, Txid
from ..resolve import fetch_transaction

_DEFAULT_TIMEOUT_S = 15.0


def _row_from_order(order: Any, *, block_height: int | None) -> dict:
    """Format a freshly re-decoded :class:`~pyrxd.gravity.swap_order.RswpOrder` as the
    display-hex row dict :func:`pyrxd.swap.rswp.book._order_from_rpc` expects — the exact
    inverse of that function's parsing (round-trips byte for byte)."""
    row: dict[str, Any] = {
        "version": order.version,
        "flags": order.flags,
        "offered_type": order.offered_type,
        "terms_type": order.terms_type,
        "tokenid": order.token_id[::-1].hex(),
        "utxo": {"txid": order.offered_utxo_hash[::-1].hex(), "vout": order.offered_utxo_index},
        "price_terms": order.price_terms.hex(),
        "signature": order.signature.hex(),
        "block_height": block_height,
    }
    if order.want_token_id is not None:
        row["want_tokenid"] = order.want_token_id[::-1].hex()
    return row


class RxindexerOrderbookSource:
    """:class:`~pyrxd.swap.rswp.book.OrderbookSource` over an RXinDexer ``swap.get_orders`` endpoint.

    Usage (production, self-managed connection)::

        async with RxindexerOrderbookSource(["wss://rxindexer.example.org:50004"]) as source:
            entries = await OrderbookClient(source).orders_offering(ref)

    Usage (an already-connected client, or a fake transport for tests)::

        source = RxindexerOrderbookSource(transport=my_electrumx_client_or_fake)

    Pass exactly one of *urls* or *transport*. When *urls* is given, this
    source owns the connection (closed by :meth:`close`/``__aexit__``); when
    *transport* is given, the caller owns its lifecycle — this source never
    closes it. *transport* must provide async ``get_transaction(txid) -> bytes``,
    ``get_utxos(script_hash) -> list`` (items with ``.tx_hash``/``.tx_pos``, the
    shape of :class:`pyrxd.network.electrumx.UtxoRecord`), and
    ``call_extension(method, params) -> Any``.
    """

    def __init__(
        self,
        urls: list[str] | None = None,
        *,
        transport: Any | None = None,
        allow_insecure: bool = False,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
    ) -> None:
        if (urls is None) == (transport is None):
            raise ValidationError("pass exactly 1 of urls or transport to RxindexerOrderbookSource, not both/neither")
        self._owns_transport = transport is None
        if transport is not None:
            self._electrumx: Any = transport
        else:
            from ...network.electrumx import ElectrumXClient  # deferred: keep pyrxd.swap.rswp import light (websockets)

            self._electrumx = ElectrumXClient(list(urls or []), allow_insecure=allow_insecure, timeout=timeout_s)
        self._rx = RxinDexerClient(self._electrumx)

    async def __aenter__(self) -> RxindexerOrderbookSource:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_transport:
            await self._electrumx.close()

    # ------------------------------------------------------------- OrderbookSource Protocol

    async def get_open_orders(self, token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        """Orders OFFERING *token_id_hex* — via ``swap.get_orders(base_ref=...)`` for
        discovery, then an independent re-derive of each order (see module docstring)."""
        base_ref = f"{token_id_hex}_0"
        entries = await self._call_swap_get_orders(base_ref=base_ref, limit=limit, offset=offset)
        return [await self._row_from_discovery(entry) for entry in entries]

    async def get_open_orders_by_want(self, want_token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        """Always raises — RXinDexer has no want-token-only order index.

        Verified against 2 checkouts of ``Radiant-Core/RXinDexer`` (2026-07-05,
        see module docstring): ``swap.get_orders`` only filters by ``base_ref``
        (offered token) alone, or by an exact ``(base_ref, quote_ref)`` pair —
        never by ``quote_ref`` alone. There is no bounded way to answer "every
        order wanting token X" without scanning every possible base ref, so
        this raises rather than silently returning an incomplete (or empty,
        fail-open-looking) list.
        """
        raise NetworkError(
            f"RXinDexer has no want-only order filter for token {want_token_id_hex[:12]} (verified against "
            "Radiant-Core/RXinDexer, 2026-07-05: swap.get_orders takes base_ref alone or an exact pair, never "
            "quote_ref alone) — a real API capability gap, not a transport failure"
        )

    async def get_transaction(self, txid: str | Txid) -> bytes:
        raw = await self._electrumx.get_transaction(Txid(str(txid).lower()))
        return bytes(raw)

    async def is_unspent(self, txid: str, vout: int) -> bool:
        """Independently chain-verified — never trusts RXinDexer's cached order ``status``.

        Fetches the offered UTXO's own source tx (txid-verified), derives the
        ElectrumX scripthash of its locking script, and checks
        ``blockchain.scripthash.listunspent`` for this exact outpoint.
        """
        tx = await fetch_transaction(self, txid)
        if not 0 <= vout < len(tx.outputs):
            raise NetworkError(f"vout {vout} is out of range for tx {txid[:12]} (RxindexerOrderbookSource.is_unspent)")
        script_bytes = tx.outputs[vout].locking_script.serialize()
        script_hash = Hex32(sha256(script_bytes)[::-1])
        utxos = await self._electrumx.get_utxos(script_hash)
        wanted_txid = str(Txid(str(txid).lower()))
        return any(u.tx_hash == wanted_txid and u.tx_pos == vout for u in utxos)

    # ------------------------------------------------------------- internals

    async def _call_swap_get_orders(
        self, *, base_ref: str, quote_ref: str | None = None, limit: int, offset: int
    ) -> list[dict]:
        try:
            result = await self._rx.swap_get_orders(base_ref, quote_ref, limit=limit, offset=offset)
        except RxinDexerError as exc:
            raise NetworkError(f"RXinDexer swap.get_orders transport failure: {exc}") from exc
        if isinstance(result, dict) and "error" in result:
            raise NetworkError(f"RXinDexer swap.get_orders returned an error field: {result['error']!r}")
        if not isinstance(result, list):
            raise NetworkError(f"RXinDexer swap.get_orders returned type {type(result).__name__}, not a list")
        return result

    async def _row_from_discovery(self, entry: dict) -> dict:
        """Turn one RXinDexer discovery row (``tx_hash``/``vout`` only trusted) into the
        ``_order_from_rpc`` row shape by independently fetching and decoding the advert."""
        try:
            tx_hash = str(entry["tx_hash"]).lower()
            advert_vout = int(entry["vout"])
        except (KeyError, TypeError, ValueError) as exc:
            raise NetworkError(f"RXinDexer order row is missing a valid tx_hash/vout pair: {exc!r}") from exc
        block_height = entry.get("height")

        tx = await fetch_transaction(self, tx_hash)
        if not 0 <= advert_vout < len(tx.outputs):
            raise ValidationError(f"RXinDexer-reported vout {advert_vout} is out of range for tx {tx_hash[:12]}")
        advert_script = tx.outputs[advert_vout].locking_script.serialize()
        order = decode_rswp_order(advert_script)  # raises ValidationError on a malformed advert (fail closed)
        return _row_from_order(order, block_height=block_height)


__all__ = ["RxindexerOrderbookSource"]

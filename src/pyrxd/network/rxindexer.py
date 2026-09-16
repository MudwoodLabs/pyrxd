"""RXinDexer JSON-RPC client — Radiant indexer extensions over ElectrumX.

RXinDexer (``Radiant-Core/RXinDexer``) is the canonical Radiant indexer.
It extends the base ElectrumX server with three families of methods:

* ``glyph.*``  — Glyph v2 token state (balances, metadata, history)
* ``wave.*``   — WAVE name resolution (REP-3011)
* ``swap.*``   — Radiant Swap DEX state

This module wraps those JSON-RPC methods in typed Python helpers. They all
ride the same WebSocket as the base ``ElectrumXClient`` and reuse its
connection / id-correlation machinery via :meth:`ElectrumXClient.call_extension`.

Why a separate client rather than methods on ``ElectrumXClient``? RXinDexer
extensions are *optional* — a vanilla ElectrumX server won't have them,
and a swap or wallet that talks only to base ElectrumX shouldn't pull in
the indexer-specific types and validation. Composing
``RxinDexerClient(electrumx_client)`` makes the dependency explicit.

Most code should construct ``RxinDexerClient`` with the same
``ElectrumXClient`` instance used for other network operations, sharing
the connection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .electrumx import ElectrumXClient


class RxinDexerError(Exception):
    """Base class for RXinDexer-specific errors."""


class RxinDexerNotFound(RxinDexerError):
    """A lookup returned no result (name not registered, token unknown, etc.)."""


@dataclass(frozen=True)
class IndexerStats:
    """Health summary returned by ``wave.stats`` and similar status RPCs."""

    total_names: int = 0
    tip_height: int = 0
    raw: dict[str, Any] | None = None

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> IndexerStats:
        return cls(
            total_names=int(data.get("total_names", 0)),
            tip_height=int(data.get("tip_height", 0)),
            raw=dict(data),
        )


class RxinDexerClient:
    """Thin wrapper over ``ElectrumXClient`` for RXinDexer extension RPCs.

    Methods are grouped by RPC namespace (``wave_*``, ``glyph_*``,
    ``swap_*``). Each wraps a single RPC call, parses the response into a
    typed result, and converts transport / parse failures into
    :class:`RxinDexerError` subclasses.

    The :class:`pyrxd.glyph.wave.WaveResolver` is built on top of this
    client and is the canonical entry-point for WAVE name resolution
    in higher-level applications.
    """

    def __init__(self, client: ElectrumXClient):
        self.client = client

    # ─────────────────────────────────────────── WAVE ──

    async def wave_resolve(self, name: str) -> dict[str, Any]:
        """Raw ``wave.resolve`` call. Returns the indexer's dict response,
        or ``None`` if the name is not registered. Higher-level callers
        should usually use :class:`pyrxd.glyph.wave.WaveResolver`.
        """
        return await self._call("wave.resolve", [name])

    async def wave_check_available(self, name: str) -> bool:
        """True if `name` is not yet registered on-chain. Takes the BARE LABEL.

        THE ANSWER IS A DICT, AND EVERY DICT IS TRUTHY. Upstream's ``check_available``
        (``electrumx/server/wave_index.py``) always returns a mapping carrying an
        ``available`` key — ``{'available': False, 'ref': ..., 'name': ...}`` for a name that
        is TAKEN, ``{'available': False, 'error': ...}`` for one that fails
        ``validate_wave_name``, ``{'available': True, ...}`` when it is genuinely free. This
        method did ``return bool(result)``, so it answered **True for every one of those** —
        reporting a registered name as available, which is the fail-open direction for a
        method whose entire job is to stop a caller minting over someone else's name.

        Like ``wave.resolve``, the RPC wants the label: ``validate_wave_name`` runs first and
        ``.`` is not in its ``WAVE_CHARS``. Callers passing ``"alice.rxd"`` were answered with
        an error dict — which the old ``bool()`` then reported as *available*. Stripping to the
        label is done by :meth:`pyrxd.glyph.wave.WaveResolver.check_available`; a bare label is
        what this method expects.
        """
        result = await self._call("wave.check_available", [name])
        if not isinstance(result, dict):
            raise RxinDexerError(
                f"wave.check_available returned {type(result).__name__}, expected dict — refusing to guess"
            )
        if "error" in result:
            raise RxinDexerError(f"wave.check_available({name!r}) was refused by the indexer: {result['error']}")
        available = result.get("available")
        if not isinstance(available, bool):
            raise RxinDexerError(
                f"wave.check_available answer has no boolean 'available' key (got {available!r}) — refusing to guess"
            )
        return available

    async def wave_reverse_lookup(self, address: str) -> list[str]:
        """All WAVE names whose OWNER holds the token at `address`, qualified (``alice.rxd``).

        THE INDEXER TAKES A SCRIPTHASH, NOT AN ADDRESS. RXinDexer's ``reverse_lookup(scripthash:
        bytes)`` accepts a 32-byte Electrum scripthash (or its 11-byte hashX) and indexes owners
        by it. This method sent the base58 address and was answered with ``{"error":
        "non-hexadecimal number found in fromhex() arg at position 2"}`` — measured against
        ``electrumx.radiantcore.org`` 2026-09-16, confirmed in ``wave_index.py`` upstream. And it
        returns a list of DICTS (``ref``, ``name``, ``full_name``, ``status``, ``zone``,
        ``owner``), not a list of names, so even a lucky answer would have been rendered as
        ``str(dict)``. Both halves are fixed here.

        Entries flagged ``status == "expired"`` are dropped: upstream keeps a lapsed name listed
        so the owner can see it needs renewal, but it no longer RESOLVES, and this method's
        contract is names that resolve.
        """
        from .electrumx import script_hash_for_address

        script_hash = script_hash_for_address(address)
        result = await self._call("wave.reverse_lookup", [script_hash.hex()])
        if result is None:
            return []
        if isinstance(result, dict) and "error" in result:
            raise RxinDexerError(f"wave.reverse_lookup was refused by the indexer: {result['error']}")
        if not isinstance(result, list):
            raise RxinDexerError(f"wave.reverse_lookup returned {type(result).__name__}, expected list")
        names: list[str] = []
        for item in result:
            if isinstance(item, dict):
                if str(item.get("status") or "").lower() == "expired":
                    continue
                full = item.get("full_name") or item.get("name")
                if not full:
                    continue
                full = str(full)
                names.append(full if "." in full else f"{full}.rxd")
            elif isinstance(item, str):  # an older indexer that returned bare names
                names.append(item if "." in item else f"{item}.rxd")
            else:
                raise RxinDexerError(f"wave.reverse_lookup entry has unexpected shape: {type(item).__name__}")
        return names

    async def wave_get_subdomains(self, name: str) -> list[str]:
        """Subdomains of `name`. Returns empty list if none."""
        result = await self._call("wave.get_subdomains", [name])
        if result is None:
            return []
        if not isinstance(result, list):
            raise RxinDexerError(f"wave.get_subdomains returned {type(result).__name__}, expected list")
        return [str(s) for s in result]

    async def wave_stats(self) -> IndexerStats:
        """Indexer-level WAVE stats — useful for health checks."""
        result = await self._call("wave.stats", [])
        if not isinstance(result, dict):
            raise RxinDexerError(f"wave.stats returned {type(result).__name__}, expected dict")
        return IndexerStats.from_response(result)

    # ─────────────────────────────────────────── Glyph v2 ──
    #
    # These are stubs until concrete consumers need the full surface — listed
    # here so the namespace is reserved and to document where new RPCs go.
    # See https://github.com/Radiant-Core/RXinDexer for the full method list.

    async def glyph_get_token(self, ref: str) -> dict[str, Any] | None:
        """``glyph.get_token`` — fetch a token by its `txid:vout` ref."""
        return await self._call("glyph.get_token", [ref])

    async def glyph_get_balance(self, address: str, token_ref: str | None = None) -> Any:
        """``glyph.get_balance`` — fungible-token balance for an address.

        Pass `token_ref` to scope the query to a specific token; without it,
        the indexer returns all FT balances the address holds.
        """
        params = [address] if token_ref is None else [address, token_ref]
        return await self._call("glyph.get_balance", params)

    async def glyph_get_metadata(self, ref: str) -> dict[str, Any] | None:
        """``glyph.get_metadata`` — decoded CBOR metadata for a token."""
        return await self._call("glyph.get_metadata", [ref])

    # ──────────────────────────── discovery (indexer schema v4) ──
    #
    # Global newest-first asset lists. Cursor-paginated: feed the previous
    # page's ``next_cursor`` back as ``cursor``; cursors are opaque and
    # order-specific. Enables incremental watermark sync — walk once, save the
    # newest ``deploy_height`` seen, then on later runs page newest-first and
    # stop once ``deploy_height`` drops below the watermark.

    async def glyph_get_recent(
        self,
        limit: int = 100,
        cursor: str | None = None,
        token_type: int | None = None,
    ) -> dict[str, Any]:
        """``glyph.get_recent`` — newest-deployed tokens, newest-first.

        Across every type by default; pass ``token_type`` (1=FT, 2=NFT,
        3=DAT, 4=DMINT, 5=WAVE, 6=Container, 7=Authority) to filter.
        Returns ``{"tokens": [...], "next_cursor": str | None}``.
        """
        result = await self._call("glyph.get_recent", [limit, cursor, token_type])
        if not isinstance(result, dict):
            raise RxinDexerError(f"glyph.get_recent returned {type(result).__name__}, expected dict")
        return result

    async def glyph_get_tokens_by_type(
        self,
        token_type: int,
        limit: int = 100,
        cursor: str | None = None,
        order: str = "ref",
    ) -> dict[str, Any]:
        """``glyph.get_tokens_by_type`` — tokens of one type.

        ``order="recent"`` = newest-deployed first (v4 index);
        ``order="ref"`` (default) = legacy stable ref-hash order. Cursors must
        not be reused across a change of ``order``.
        Returns ``{"tokens": [...], "next_cursor": str | None}``.
        """
        if order not in ("ref", "recent"):
            raise ValueError(f"order must be 'ref' or 'recent', got {order!r}")
        result = await self._call("glyph.get_tokens_by_type", [token_type, limit, cursor, order])
        if not isinstance(result, dict):
            raise RxinDexerError(f"glyph.get_tokens_by_type returned {type(result).__name__}, expected dict")
        return result

    # ─────────────────────────────────────────── Swap (RSWP) ──
    #
    # Verified 2026-07-05 against ``Radiant-Core/RXinDexer`` (upstream ``main``,
    # commit range through 2026-06-30) — the RPC is wired in
    # ``electrumx/server/glyph_api.py`` (``GLYPH_METHODS['swap.get_orders']``),
    # NOT in ``electrumx/server/swap_index.py`` as an older internal
    # ``SWAP_METHODS`` table (dead code, since removed) once suggested. There is
    # exactly one confirmed-order query method; see
    # :mod:`pyrxd.swap.rswp.rxindexer_source` for the capability this implies
    # (no want-token-only filter) and why the returned dict fields are used only
    # for order *discovery*, never trusted for signature/price-terms content.

    async def swap_get_orders(
        self,
        base_ref: str | None = None,
        quote_ref: str | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> Any:
        """``swap.get_orders`` — RXinDexer's confirmed swap-order query.

        With only ``base_ref`` (``txid_vout`` or 72-hex, per
        ``glyph_api.py::_parse_ref``): open orders offering that token,
        newest-index-first, server-side ``limit`` clamped to 200. With BOTH
        ``base_ref`` and ``quote_ref``: the ``{bids, asks}`` orderbook for that
        exact pair instead of a flat list. There is NO filter for "orders
        wanting token X" alone (no symmetric quote-only index exists server
        side as of this 2026-07-05 verification) — callers needing that must
        raise rather than approximate it by scanning every base ref.
        """
        return await self._call("swap.get_orders", [base_ref, quote_ref, limit, offset])

    # ─────────────────────────────────────────── transport ──

    async def _call(self, method: str, params: list) -> Any:
        """Shared call wrapper — converts transport errors to RxinDexerError."""
        try:
            return await self.client.call_extension(method, params)
        except Exception as exc:
            raise RxinDexerError(f"{method}({params!r}) failed: {exc}") from exc

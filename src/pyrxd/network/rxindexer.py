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
        """True if `name` is not yet registered on-chain."""
        result = await self._call("wave.check_available", [name])
        return bool(result)

    async def wave_reverse_lookup(self, address: str) -> list[str]:
        """All WAVE names that resolve to `address`."""
        result = await self._call("wave.reverse_lookup", [address])
        if result is None:
            return []
        if not isinstance(result, list):
            raise RxinDexerError(f"wave.reverse_lookup returned {type(result).__name__}, expected list")
        return [str(n) for n in result]

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

    # ─────────────────────────────────────────── transport ──

    async def _call(self, method: str, params: list) -> Any:
        """Shared call wrapper — converts transport errors to RxinDexerError."""
        try:
            return await self.client.call_extension(method, params)
        except Exception as exc:
            raise RxinDexerError(f"{method}({params!r}) failed: {exc}") from exc

"""``OrderbookSource`` over a Radiant node's JSON-RPC — the production book transport.

Talks directly to a node started with ``-swapindex=1`` (plus ``-txindex=1`` so
offered-UTXO source transactions resolve). This is the same surface the hosted
``swap.radiantcore.org`` endpoint proxies. Deliberately minimal: four calls,
no session state beyond the aiohttp connection, and **fail-closed** — any
transport error, HTTP error, or RPC error raises :class:`NetworkError` rather
than returning an empty/None answer that would read as a healthy-but-empty
book (see :class:`pyrxd.swap.rswp.book.OrderbookSource`).

Credentials note: pass ``rpc_user``/``rpc_password`` explicitly rather than
embedding them in the URL, so they never appear in logs or exception reprs.
"""

from __future__ import annotations

from typing import Any

from ...security.errors import NetworkError
from ...security.types import Txid

_DEFAULT_TIMEOUT_S = 15.0


class NodeRpcSource:
    """:class:`~pyrxd.swap.rswp.book.OrderbookSource` over Radiant node JSON-RPC.

    Usage::

        source = NodeRpcSource("http://127.0.0.1:7332", rpc_user="u", rpc_password="p")
        async with source:
            entries = await OrderbookClient(source).orders_offering(ref)
    """

    def __init__(
        self,
        url: str,
        *,
        rpc_user: str | None = None,
        rpc_password: str | None = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
    ) -> None:
        self._url = url
        self._auth = (rpc_user, rpc_password)
        self._timeout_s = timeout_s
        self._session: Any = None  # aiohttp.ClientSession, created lazily

    async def __aenter__(self) -> NodeRpcSource:
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def _call(self, method: str, params: list) -> Any:
        import aiohttp  # deferred: `import pyrxd.swap.rswp` stays aiohttp-free

        if self._session is None:
            auth = None
            if self._auth[0] is not None:
                auth = aiohttp.BasicAuth(self._auth[0], self._auth[1] or "")
            self._session = aiohttp.ClientSession(auth=auth, timeout=aiohttp.ClientTimeout(total=self._timeout_s))
        payload = {"jsonrpc": "1.0", "id": "pyrxd", "method": method, "params": params}
        try:
            async with self._session.post(self._url, json=payload) as resp:
                # Radiant nodes answer RPC-level errors with non-200 + a JSON body;
                # read the body first so the error message survives.
                body = await resp.json(content_type=None)
                err = body.get("error") if isinstance(body, dict) else None
                if err:
                    raise NetworkError(f"node RPC {method} failed: {err.get('message', err)}")
                if resp.status != 200:
                    raise NetworkError(f"node RPC {method} failed: HTTP {resp.status}")
                return body["result"] if isinstance(body, dict) else None
        except NetworkError:
            raise
        except Exception as exc:  # aiohttp/transport/JSON errors — fail closed
            raise NetworkError(f"node RPC {method} transport error: {exc!r}") from exc

    async def get_open_orders(self, token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = await self._call("getopenorders", [token_id_hex, limit, offset])
        if not isinstance(rows, list):
            raise NetworkError("getopenorders returned a non-list result")
        return rows

    async def get_open_orders_by_want(self, want_token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        rows = await self._call("getopenordersbywant", [want_token_id_hex, limit, offset])
        if not isinstance(rows, list):
            raise NetworkError("getopenordersbywant returned a non-list result")
        return rows

    async def get_transaction(self, txid: str | Txid) -> bytes:
        raw = await self._call("getrawtransaction", [str(txid)])
        if not isinstance(raw, str):
            raise NetworkError("getrawtransaction returned a non-hex result")
        return bytes.fromhex(raw)

    async def is_unspent(self, txid: str, vout: int) -> bool:
        # gettxout returns null for a spent/unknown outpoint — that IS the answer
        # (not a transport failure), so a None result maps to False here.
        out = await self._call("gettxout", [str(txid), int(vout), True])
        return isinstance(out, dict)

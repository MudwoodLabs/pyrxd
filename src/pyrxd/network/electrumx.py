"""ElectrumX JSON-RPC client over WebSocket.

Security notes
--------------
* TLS (``wss://``) is required by default.  Bare ``ws://`` connections raise
  ``NetworkError`` unless the caller explicitly passes ``allow_insecure=True``.
* All method arguments are validated against pyrxd security types before any
  network call is made.
* Raw server responses are NEVER embedded in exception messages – only static
  descriptions are surfaced to the caller.
* ``script_hash`` parameters follow the ElectrumX convention: the value is
  ``sha256(locking_script)`` with the bytes reversed (little-endian hash).

Usage
-----
    async with ElectrumXClient(["wss://electrumx.server1.com"]) as client:
        tip = await client.get_tip_height()
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any

import websockets
from websockets.exceptions import WebSocketException

from ..hash import sha256
from ..merkle_path import MerklePath
from ..script.type import P2PKH
from ..security.errors import NetworkError, ValidationError
from ..security.types import BlockHeight, Hex32, RawTx, Satoshis, Txid

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT: float = 30.0


@dataclass
class UtxoRecord:
    """A single unspent transaction output as returned by ElectrumX.

    Attributes
    ----------
    tx_hash:
        Transaction id in hex (little-endian / display order).
    tx_pos:
        Output index within the transaction.
    value:
        Output value in satoshis.
    height:
        Block height at which the output was confirmed (0 = unconfirmed).
    """

    tx_hash: str
    tx_pos: int
    value: int
    height: int


_MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MB


def _coerce_hex32(value: Hex32 | bytes | bytearray | str) -> Hex32:
    """Normalize caller-supplied script_hash to Hex32 at the SDK boundary.

    Accepts Hex32 (passthrough), raw bytes/bytearray of length 32, or a
    hex str of length 64. Anything else raises ValidationError with a
    message that names the offending type — never echoes the value.
    """
    if isinstance(value, Hex32):
        return value
    if isinstance(value, (bytes, bytearray)):
        return Hex32(bytes(value))
    if isinstance(value, str):
        return Hex32.from_hex(value)
    raise ValidationError(f"script_hash must be Hex32, bytes, or hex str; got {type(value).__name__}")


def script_hash_for_address(address: str) -> Hex32:
    """Return the ElectrumX ``script_hash`` for a P2PKH *address*.

    ElectrumX indexes addresses by ``sha256(locking_script)`` with the bytes
    reversed (little-endian display order). This public helper lets callers
    derive the script hash without constructing a full client.

    Parameters
    ----------
    address:
        Base58Check-encoded P2PKH address.

    Returns
    -------
    Hex32
        The 32-byte script hash suitable for ElectrumX RPC calls.
    """
    locking = P2PKH().lock(address)
    digest = sha256(locking.serialize())
    return Hex32(digest[::-1])


class ElectrumXClient:
    """Async ElectrumX JSON-RPC client.

    Parameters
    ----------
    urls:
        One or more ElectrumX server URLs.  The client uses the first URL;
        on disconnect it attempts one reconnect, then raises ``NetworkError``.
    allow_insecure:
        If ``False`` (default) ``ws://`` URLs raise ``NetworkError`` immediately.
        Set to ``True`` only for local testing.
    timeout:
        Per-request timeout in seconds (default 30).
    """

    def __init__(
        self,
        urls: list[str],
        *,
        allow_insecure: bool = False,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        if not urls:
            raise ValidationError("ElectrumXClient requires at least one server URL")
        self._urls = urls
        self._allow_insecure = allow_insecure
        self._timeout = timeout
        self._ws: Any | None = None  # websockets.WebSocketClientProtocol
        self._id_counter: int = 0
        self._id_lock: asyncio.Lock = asyncio.Lock()
        # Send must be serialized across tasks — websockets.send is not
        # safe to call concurrently from multiple coroutines on the same
        # connection (interleaved fragments).
        self._send_lock: asyncio.Lock = asyncio.Lock()
        # Pending requests keyed by JSON-RPC id. Reader task pops the
        # matching entry and resolves its future when a response arrives.
        # Closes ultrareview Stream C #4 (response correlation race).
        # Without per-id correlation, two concurrent _call() invocations
        # could swap responses — caller A awaits recv() and gets caller
        # B's result, because recv() returns whatever message arrives next
        # rather than the one matching A's request id.
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self._reader_task: asyncio.Task[None] | None = None

        # Validate all URLs at construction time (fast-fail).
        for url in self._urls:
            self._validate_url(url)

    # ---------------------------------------------------------------------- context manager

    async def __aenter__(self) -> ElectrumXClient:
        await self._ensure_connected()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying WebSocket connection.

        Cancels the reader task, fails any in-flight requests with
        NetworkError, and closes the socket.
        """
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                # Reader task is being torn down — ignore both cancellation and any final error.
                pass
        self._reader_task = None

        if self._ws is not None:
            try:
                await self._ws.close()
            except (WebSocketException, OSError):
                # Ignore errors on close — the connection is being torn down.
                logger.debug("Error closing ElectrumX WebSocket (ignored)")
            self._ws = None

        self._fail_all_pending(NetworkError("ElectrumX connection closed"))

    # ---------------------------------------------------------------------- public API

    async def get_transaction(self, txid: Txid) -> RawTx:
        """Fetch the raw transaction bytes for *txid*.

        Returns
        -------
        RawTx
            The serialised transaction (> 64 bytes, Merkle-forgery safe).
        """
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        result = await self._call("blockchain.transaction.get", [str(txid), False])
        if not isinstance(result, str):
            raise NetworkError("Unexpected response type for transaction hex")
        try:
            raw = bytes.fromhex(result)
        except ValueError:
            raise NetworkError("Server returned invalid hex for transaction")
        return RawTx(raw)

    async def get_transaction_verbose(self, txid: Txid) -> dict[str, Any]:
        """Fetch the verbose JSON-decoded form of a transaction.

        Calls ``blockchain.transaction.get`` with ``verbose=True`` and
        returns the dict the server provides — including ``confirmations``,
        ``blockhash``, ``blocktime``. Used by confirmation polling.

        Distinct from :meth:`get_transaction` (which returns raw bytes
        for cryptographic operations like merkle-proof checks). Callers
        polling for "is this tx confirmed yet?" want THIS one.
        """
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        result = await self._call("blockchain.transaction.get", [str(txid), True])
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for verbose transaction")
        return result

    async def get_transaction_merkle(self, txid: Txid, height: BlockHeight) -> MerklePath:
        """Fetch the Merkle proof for *txid* at block *height*.

        Returns
        -------
        MerklePath
            A parsed Merkle path object.
        """
        if not isinstance(txid, Txid):
            txid = Txid(txid)
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        result = await self._call("blockchain.transaction.get_merkle", [str(txid), int(height)])
        # ElectrumX returns {"block_height": N, "merkle": [...], "pos": N}
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for transaction merkle")
        try:
            block_height = BlockHeight(int(result["block_height"]))
            merkle_hashes: list[str] = result["merkle"]
            pos: int = int(result["pos"])
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed merkle response from server")

        # Build a MerklePath from the ElectrumX branch format.
        # ElectrumX returns hashes in display (reversed) order; we pass the
        # txid as the leaf and build a linear proof path.
        2 ** len(merkle_hashes)
        path: list = [[{"offset": pos, "hash_str": str(txid), "txid": True}]]
        current_pos = pos
        for _h, sibling_hex in enumerate(merkle_hashes):
            sibling_offset = current_pos ^ 1
            path[0].append({"offset": sibling_offset, "hash_str": sibling_hex})
            current_pos = current_pos >> 1

        try:
            return MerklePath(int(block_height), path)
        except Exception as exc:
            raise NetworkError(f"Could not construct MerklePath: {exc}") from exc

    async def broadcast(self, raw_tx: bytes) -> Txid:
        """Broadcast a raw transaction to the network.

        Parameters
        ----------
        raw_tx:
            Serialised transaction bytes.

        Returns
        -------
        Txid
            The transaction id returned by the server.
        """
        validated = RawTx(raw_tx)
        result = await self._call("blockchain.transaction.broadcast", [validated.hex()])
        if not isinstance(result, str):
            raise NetworkError("Unexpected response type for broadcast result")
        try:
            return Txid(result)
        except ValidationError as exc:
            raise NetworkError("Server returned invalid txid after broadcast") from exc

    async def get_balance(self, script_hash: Hex32 | bytes | str) -> tuple[Satoshis, Satoshis]:
        """Return the confirmed and unconfirmed balance for *script_hash*.

        The ``script_hash`` is ``sha256(locking_script)`` with bytes reversed
        (ElectrumX little-endian convention). Accepts ``Hex32``, raw
        ``bytes`` (length 32), or a hex ``str`` (length 64).

        Returns
        -------
        tuple[Satoshis, Satoshis]
            ``(confirmed, unconfirmed)``
        """
        script_hash = _coerce_hex32(script_hash)
        result = await self._call("blockchain.scripthash.get_balance", [script_hash.hex()])
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for balance")
        try:
            confirmed = Satoshis(int(result["confirmed"]))
            unconfirmed = Satoshis(int(result["unconfirmed"]))
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed balance response from server")
        return confirmed, unconfirmed

    async def get_utxos(self, script_hash: Hex32 | bytes | str) -> list[UtxoRecord]:
        """Return the list of UTXOs for *script_hash*.

        Accepts ``Hex32``, raw ``bytes`` (length 32), or a hex ``str``
        (length 64). Each UTXO is returned as a typed :class:`UtxoRecord`.
        """
        script_hash = _coerce_hex32(script_hash)
        result = await self._call("blockchain.scripthash.listunspent", [script_hash.hex()])
        if not isinstance(result, list):
            raise NetworkError("Unexpected response type for UTXOs")
        try:
            return [
                UtxoRecord(
                    tx_hash=item["tx_hash"],
                    tx_pos=int(item["tx_pos"]),
                    value=int(item["value"]),
                    height=int(item["height"]),
                )
                for item in result
            ]
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed UTXO entry in server response")

    async def get_history(self, script_hash: Hex32 | bytes | str) -> list[dict]:
        """Return the transaction history for *script_hash*.

        Returns a list of ``{"tx_hash": str, "height": int}`` dicts.
        Unconfirmed transactions have ``height`` of 0 or negative.
        """
        script_hash = _coerce_hex32(script_hash)
        result = await self._call("blockchain.scripthash.get_history", [script_hash.hex()])
        if not isinstance(result, list):
            raise NetworkError("Unexpected response type for history")
        try:
            return [{"tx_hash": str(item["tx_hash"]), "height": int(item["height"])} for item in result]
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed history entry in server response")

    async def get_block_header(self, height: BlockHeight) -> bytes:
        """Return the raw 80-byte block header at *height*."""
        if not isinstance(height, BlockHeight):
            height = BlockHeight(height)
        result = await self._call("blockchain.block.header", [int(height)])
        if not isinstance(result, str):
            raise NetworkError("Unexpected response type for block header")
        try:
            header_bytes = bytes.fromhex(result)
        except ValueError:
            raise NetworkError("Server returned invalid hex for block header")
        if len(header_bytes) != 80:
            raise NetworkError(f"Block header must be 80 bytes, got {len(header_bytes)}")
        return header_bytes

    async def get_tip_height(self) -> BlockHeight:
        """Return the current chain tip block height.

        Uses blockchain.block.header with cp_height=0, which is a
        proper one-shot RPC call.  The subscription method
        blockchain.headers.subscribe is avoided here because it installs
        a server-side push subscription; subsequent push notifications would
        arrive interleaved with other _call() responses on a long-lived
        connection.

        Response format: {"height": N, "hex": "..."}
        """
        result = await self._call("blockchain.block.header", [0, 0])
        if not isinstance(result, dict):
            raise NetworkError("Unexpected response type for tip height")
        try:
            height = BlockHeight(int(result["height"]))
        except (KeyError, TypeError, ValueError):
            raise NetworkError("Malformed tip height response from server")
        return height

    # ---------------------------------------------------------------------- internals

    def _validate_url(self, url: str) -> None:
        """Raise NetworkError if *url* is insecure and allow_insecure is False."""
        if url.startswith("ws://") and not self._allow_insecure:
            raise NetworkError("Insecure WebSocket URL rejected. Use wss:// or pass allow_insecure=True.")
        if not (url.startswith("wss://") or url.startswith("ws://")):
            raise NetworkError("URL must start with wss:// or ws:// (got scheme)")

    async def _ensure_connected(self) -> None:
        """Connect to the first available server (if not already connected) and
        ensure the reader task is running.

        With a single URL the previous sequential loop is equivalent; with
        multiple URLs all endpoints are raced in parallel so a single dead
        endpoint no longer adds a full timeout period before failover.
        Closes N18.
        """
        if self._ws is None:
            self._ws = await self._connect_first(self._urls, self._timeout)

        if self._reader_task is None or self._reader_task.done():
            self._reader_task = asyncio.create_task(self._reader_loop())

    async def _connect_first(self, urls: list[str], timeout: float) -> Any:  # websockets.WebSocketClientProtocol
        """Race all *urls* concurrently; return the first successful WebSocket.

        Unlike the previous sequential loop (N18), the worst-case connect
        latency is one ``timeout`` period regardless of how many dead
        endpoints precede the live one.

        Cancellation safety (post-review fix): every successfully-connected
        socket is appended to ``created`` *before* the coroutine returns it,
        so the ``finally`` block can close any socket that wasn't picked as
        the winner — even when the producing task was cancelled mid-flight.
        Without this, a losing ``_try`` whose ``websockets.connect`` resolved
        between ``wait()`` returning and ``task.cancel()`` taking effect
        would leak the socket: ``gather(return_exceptions=True)`` consumes
        the ``CancelledError`` but cannot retrieve the orphaned ws.

        Raises ``NetworkError`` if all connections fail or the overall
        timeout expires before any succeeds.
        """
        created: list[Any] = []  # every ws actually returned by websockets.connect

        async def _try(url: str) -> Any:
            ws = await websockets.connect(url)  # type: ignore[attr-defined]
            created.append(ws)
            return ws

        tasks = [asyncio.create_task(_try(url)) for url in urls]
        winner_ws: Any | None = None
        last_exc: Exception | None = None
        remaining: set[asyncio.Task[Any]] = set(tasks)

        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout

            while remaining:
                time_left = max(0.0, deadline - loop.time())
                done, remaining = await asyncio.wait(
                    remaining,
                    timeout=time_left,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                if not done:
                    last_exc = last_exc or asyncio.TimeoutError(f"No ElectrumX endpoint responded within {timeout}s")
                    break

                for task in done:
                    try:
                        ws = task.result()
                    except Exception as exc:
                        logger.debug("ElectrumX connect failed: %s", exc)
                        last_exc = exc
                        continue

                    if winner_ws is None:
                        winner_ws = ws

                if winner_ws is not None:
                    break

        finally:
            for task in remaining:
                task.cancel()
            if remaining:
                await asyncio.gather(*remaining, return_exceptions=True)
            # Close every connected ws that isn't the winner — covers both
            # "extra winners that completed in the same `done` set" and
            # "sockets that resolved inside a cancelled coroutine."
            for ws in created:
                if ws is winner_ws:
                    continue
                try:
                    await ws.close()
                except Exception:  # nosec B110 — best-effort cleanup of losing race connection
                    pass

        if winner_ws is not None:
            return winner_ws
        raise NetworkError("Failed to connect to any ElectrumX server") from last_exc

    def _fail_all_pending(self, exc: Exception) -> None:
        """Resolve every in-flight future with *exc*; clear the pending map."""
        for fut in list(self._pending.values()):
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    async def _reader_loop(self) -> None:
        """Read messages from the socket and dispatch by JSON-RPC id.

        Runs as a single task per connection. Pops the matching pending
        future for each response's ``id`` and sets its result/exception.
        On socket error or EOF, fails all pending requests and exits;
        the next ``_call`` triggers reconnect via ``_ensure_connected``.

        Orphan responses (id not in ``_pending``, or future already done)
        are logged at debug level and dropped — they cannot be matched
        and trying to "guess" the right caller would re-introduce the
        very swap-bug this design eliminates.
        """
        try:
            while True:
                if self._ws is None:
                    return
                raw = await self._ws.recv()
                # Validate response size before parsing.
                if isinstance(raw, (bytes, bytearray)):
                    if len(raw) > _MAX_RESPONSE_BYTES:
                        # Oversized message — the server is misbehaving;
                        # disconnect and fail all pending so callers retry
                        # against a fresh connection (or another server).
                        self._fail_all_pending(NetworkError("ElectrumX response exceeds maximum allowed size"))
                        return
                    raw_str = raw.decode("utf-8", errors="replace")
                else:
                    if len(raw) > _MAX_RESPONSE_BYTES:
                        self._fail_all_pending(NetworkError("ElectrumX response exceeds maximum allowed size"))
                        return
                    raw_str = raw

                try:
                    data = json.loads(raw_str)
                except json.JSONDecodeError:
                    # One bad message shouldn't poison the whole connection,
                    # but it does mean we can't dispatch this one. Continue.
                    logger.debug("ElectrumX reader skipped non-JSON message")
                    continue

                if not isinstance(data, dict):
                    logger.debug("ElectrumX reader skipped non-dict message")
                    continue

                req_id = data.get("id")
                if not isinstance(req_id, int):
                    # Server pushes (no id) or malformed — drop. Subscribed
                    # notifications are out of scope for this client.
                    logger.debug("ElectrumX reader dropped message without int id")
                    continue

                fut = self._pending.pop(req_id, None)
                if fut is None or fut.done():
                    logger.debug("ElectrumX reader dropped orphan response id=%d", req_id)
                    continue

                if "error" in data and data["error"] is not None:
                    err = data["error"]
                    if isinstance(err, dict):
                        code = err.get("code", "unknown")
                        fut.set_exception(NetworkError(f"ElectrumX RPC error (code {code})"))
                    else:
                        fut.set_exception(NetworkError("ElectrumX RPC error"))
                elif "result" in data:
                    fut.set_result(data["result"])
                else:
                    fut.set_exception(NetworkError("ElectrumX response missing 'result' field"))
        except asyncio.CancelledError:
            # close() asked us to stop — propagate so the awaiter knows.
            self._fail_all_pending(NetworkError("ElectrumX connection closed"))
            raise
        except (WebSocketException, OSError) as exc:
            logger.debug("ElectrumX reader loop ending: %s", exc)
            self._fail_all_pending(NetworkError("ElectrumX connection lost"))
        finally:
            # Ensure next _call triggers a fresh connect.
            self._ws = None

    async def _next_id(self) -> int:
        async with self._id_lock:
            self._id_counter += 1
            return self._id_counter

    async def _call(self, method: str, params: list) -> Any:
        """Send a JSON-RPC request and return the ``result`` field.

        Concurrency model
        -----------------
        Multiple ``_call`` coroutines may run concurrently. Each registers a
        future in ``self._pending`` keyed on its JSON-RPC id; the single
        reader task dispatches responses to the matching future. Sends are
        serialized through ``self._send_lock`` because ``websockets.send``
        is not safe to call concurrently from multiple tasks on the same
        connection.

        Failure handling
        ----------------
        On send failure, timeout, or disconnect, the corresponding future
        is removed and ``NetworkError`` is raised to the caller. The next
        ``_call`` reconnects lazily via ``_ensure_connected`` — there is no
        in-call retry. Callers that want retry semantics should layer it
        above ``_call``.

        Raw server responses are never embedded in exception messages.
        """
        await self._ensure_connected()
        req_id = await self._next_id()
        payload = json.dumps({"id": req_id, "method": method, "params": params})

        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Any] = loop.create_future()
        self._pending[req_id] = fut

        try:
            try:
                async with self._send_lock:
                    if self._ws is None:
                        raise NetworkError("WebSocket connection is not available")
                    await asyncio.wait_for(self._ws.send(payload), timeout=self._timeout)
            except (WebSocketException, OSError) as exc:
                raise NetworkError("ElectrumX request failed (send error)") from exc
            except asyncio.TimeoutError:
                raise NetworkError("ElectrumX request timed out (send)") from None

            try:
                return await asyncio.wait_for(fut, timeout=self._timeout)
            except asyncio.TimeoutError:
                raise NetworkError("ElectrumX request timed out") from None
        finally:
            # Drop the pending entry whether we got a response, errored, or
            # timed out. If the reader has already popped it, this is a no-op.
            self._pending.pop(req_id, None)

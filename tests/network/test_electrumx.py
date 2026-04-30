"""Tests for ElectrumXClient.

Uses lightweight asyncio mocks — no real network connections.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import BlockHeight, RawTx, Txid

# ── Helpers ───────────────────────────────────────────────────────────────────

_VALID_TXID = "a" * 64
# A minimal but valid raw tx (65+ bytes so RawTx validates).
_VALID_RAW_TX = bytes(65)
_VALID_RAW_HEX = _VALID_RAW_TX.hex()


def _make_ws_mock(response_payload: dict):
    """Return a mock websocket that yields *response_payload* once, then hangs.

    The post-correlation reader loop calls ``recv()`` repeatedly until the
    socket closes or errors. A naive ``AsyncMock(return_value=...)`` would
    return the same string on every call without ever yielding control,
    starving the rest of the event loop. Real WebSockets suspend until a
    message arrives — this fixture matches that by hanging on the second
    call so the reader cooperatively waits.
    """
    ws = AsyncMock()
    ws.send = AsyncMock(return_value=None)

    response_str = json.dumps(response_payload)
    state = {"sent": False}

    async def _recv(*args, **kwargs):
        if not state["sent"]:
            state["sent"] = True
            return response_str
        # Mimic a real socket — block until cancelled.
        await asyncio.Event().wait()
        return None  # unreachable; satisfies static analyzers

    ws.recv = _recv
    ws.close = AsyncMock(return_value=None)
    ws.__aenter__ = AsyncMock(return_value=ws)
    ws.__aexit__ = AsyncMock(return_value=None)
    return ws


def _patch_connect(ws_mock):
    """Context-manager that replaces websockets.connect with *ws_mock*."""
    return patch(
        "pyrxd.network.electrumx.websockets.connect",
        return_value=_awaitable(ws_mock),
    )


def _awaitable(value):
    """Wrap a value in a coroutine so await works on it."""

    async def _inner(*args, **kwargs):
        return value

    return _inner()


# ── TLS enforcement tests ─────────────────────────────────────────────────────


def test_insecure_url_raises_without_flag():
    """ws:// without allow_insecure=True must raise NetworkError immediately."""
    with pytest.raises(NetworkError, match="Insecure"):
        ElectrumXClient(["ws://localhost:50001"])


def test_insecure_url_allowed_with_flag():
    """ws:// with allow_insecure=True must not raise at construction."""
    client = ElectrumXClient(["ws://localhost:50001"], allow_insecure=True)
    assert client is not None


def test_wss_url_is_accepted():
    """wss:// URL must not raise at construction."""
    client = ElectrumXClient(["wss://electrumx.example.com"])
    assert client is not None


def test_invalid_scheme_raises():
    """Non-ws/wss scheme must raise NetworkError."""
    with pytest.raises(NetworkError):
        ElectrumXClient(["http://example.com"])


# ── Input validation tests ────────────────────────────────────────────────────


async def test_txid_validated_before_network_call():
    """Non-hex txid must raise ValidationError before any network call."""
    client = ElectrumXClient(["wss://example.com"])
    with pytest.raises(ValidationError):
        await client.get_transaction("../../../etc/passwd")


async def test_txid_wrong_length_raises():
    """A txid shorter than 64 chars must raise ValidationError."""
    client = ElectrumXClient(["wss://example.com"])
    with pytest.raises(ValidationError):
        await client.get_transaction("abcd")


# ── Successful response tests ─────────────────────────────────────────────────


async def test_get_transaction_returns_rawtx():
    """get_transaction with a valid hex response returns RawTx."""
    ws = _make_ws_mock({"id": 1, "result": _VALID_RAW_HEX})

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            result = await client.get_transaction(Txid(_VALID_TXID))

    assert isinstance(result, RawTx)
    assert bytes(result) == _VALID_RAW_TX


async def test_get_transaction_verbose_returns_dict_with_confirmations():
    """get_transaction_verbose returns the full ElectrumX dict.

    Distinct from get_transaction (raw bytes for crypto operations).
    The deploy ceremony's confirmation polling needs the dict form so
    `tx_info.get("confirmations", 0)` actually works — pre-fix it called
    .get() on a RawTx (bytes) and silently AttributeError'd inside a
    broad except, polling forever until timeout.
    """
    verbose_response = {
        "txid": _VALID_TXID,
        "hex": _VALID_RAW_HEX,
        "confirmations": 3,
        "blockhash": "00" * 32,
        "blocktime": 1700000000,
    }
    ws = _make_ws_mock({"id": 1, "result": verbose_response})

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            result = await client.get_transaction_verbose(Txid(_VALID_TXID))

    assert isinstance(result, dict)
    assert result["confirmations"] == 3
    assert result["blockhash"] == "00" * 32


async def test_get_transaction_verbose_rejects_non_dict_response():
    """A non-dict response from the server must raise NetworkError —
    don't silently coerce or return surprising types."""
    from pyrxd.security.errors import NetworkError as _NE

    ws = _make_ws_mock({"id": 1, "result": "not a dict"})

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(_NE):
                await client.get_transaction_verbose(Txid(_VALID_TXID))


async def test_get_tip_height_returns_block_height():
    """get_tip_height with a valid response returns BlockHeight."""
    ws = _make_ws_mock({"id": 1, "result": {"height": 840000, "hex": "00" * 80}})

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            result = await client.get_tip_height()

    assert isinstance(result, BlockHeight)
    assert result == 840000


# ── Error handling tests ──────────────────────────────────────────────────────


async def test_json_rpc_error_raises_network_error():
    """A JSON-RPC error response must raise NetworkError."""
    ws = _make_ws_mock({"id": 1, "error": {"code": -32601, "message": "Method not found"}})

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(NetworkError, match="RPC error"):
                await client.get_tip_height()


async def test_missing_result_field_raises_network_error():
    """A response without a 'result' field must raise NetworkError."""
    ws = _make_ws_mock({"id": 1})  # no 'result', no 'error'

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(NetworkError, match="missing 'result'"):
                await client.get_tip_height()


async def test_timeout_raises_network_error():
    """A request that times out must raise NetworkError."""
    ws = AsyncMock()
    ws.send = AsyncMock(return_value=None)

    # Make recv hang to trigger timeout.
    async def _hang(*args, **kwargs):
        await asyncio.sleep(9999)

    ws.recv = _hang
    ws.close = AsyncMock(return_value=None)

    with _patch_connect(ws):
        client = ElectrumXClient(["wss://example.com"], timeout=0.05)
        # Pre-inject the mock ws to skip initial connect overhead.
        client._ws = ws
        with pytest.raises(NetworkError):
            await client.get_tip_height()


async def test_rpc_error_message_not_leaked_in_exception():
    """The raw server error response must not appear verbatim in the exception str."""
    sensitive_payload = "SECRET_SERVER_DATA_" + "x" * 100
    ws = _make_ws_mock({"id": 1, "error": {"code": -1, "message": sensitive_payload}})

    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            with pytest.raises(NetworkError) as exc_info:
                await client.get_tip_height()

    # The exception message must not contain the raw server message verbatim.
    # (It may contain short parts of it, but not the identifying secret prefix.)
    exc_str = str(exc_info.value)
    assert "SECRET_SERVER_DATA_" not in exc_str


async def test_connection_failure_raises_network_error():
    """A connection failure must raise NetworkError (not propagate raw exception)."""
    import websockets

    async def _failing_connect(*args, **kwargs):
        raise websockets.exceptions.WebSocketException("refused")

    with patch(
        "pyrxd.network.electrumx.websockets.connect",
        side_effect=_failing_connect,
    ):
        client = ElectrumXClient(["wss://example.com"])
        with pytest.raises(NetworkError):
            await client.get_tip_height()


# ── script_hash coercion (0.2.0) ─────────────────────────────────────────────

from pyrxd.network.electrumx import _coerce_hex32
from pyrxd.security.types import Hex32


def test_coerce_hex32_accepts_hex32_passthrough():
    h = Hex32(b"\x00" * 32)
    assert _coerce_hex32(h) is h


def test_coerce_hex32_accepts_raw_bytes():
    result = _coerce_hex32(b"\x11" * 32)
    assert isinstance(result, Hex32)
    assert bytes(result) == b"\x11" * 32


def test_coerce_hex32_accepts_hex_string():
    result = _coerce_hex32("ab" * 32)
    assert isinstance(result, Hex32)
    assert bytes(result) == b"\xab" * 32


def test_coerce_hex32_rejects_wrong_length_hex():
    with pytest.raises(ValidationError):
        _coerce_hex32("ab" * 16)  # too short


def test_coerce_hex32_rejects_invalid_hex():
    with pytest.raises(ValidationError):
        _coerce_hex32("zz" * 32)


def test_coerce_hex32_rejects_other_types():
    with pytest.raises(ValidationError, match="script_hash must be"):
        _coerce_hex32(12345)


async def test_get_utxos_accepts_hex_string():
    """Callers may pass the script_hash as a hex string — the client coerces."""
    ws = _make_ws_mock({"id": 1, "result": []})
    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            result = await client.get_utxos("ab" * 32)
    assert result == []


async def test_get_balance_accepts_raw_bytes():
    ws = _make_ws_mock({"id": 1, "result": {"confirmed": 0, "unconfirmed": 0}})
    with _patch_connect(ws):
        async with ElectrumXClient(["wss://example.com"]) as client:
            confirmed, unconfirmed = await client.get_balance(b"\x11" * 32)
    assert int(confirmed) == 0
    assert int(unconfirmed) == 0


# ---------------------------------------------------------------------------
# broadcast() malformed-response handling — re-review N19 / P0.6
# ---------------------------------------------------------------------------


class TestBroadcastMalformedResponse:
    """ElectrumX servers can return malformed txids in the broadcast response
    (network corruption, buggy server, malicious proxy). Without explicit
    handling these would propagate as untyped errors. The implementation at
    `electrumx.py:241-246` validates the response is a string AND wraps the
    Txid construction so a non-hex response raises NetworkError, not the
    raw ValidationError.
    """

    @pytest.mark.asyncio
    async def test_non_string_response_raises_network_error(self):
        """Server returns a number instead of a hex string."""
        ws = _make_ws_mock({"id": 1, "result": 12345})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                with pytest.raises(NetworkError, match="Unexpected response type for broadcast"):
                    await client.broadcast(_VALID_RAW_TX)

    @pytest.mark.asyncio
    async def test_dict_response_raises_network_error(self):
        """Server returns a dict instead of a hex string."""
        ws = _make_ws_mock({"id": 1, "result": {"txid": "abc"}})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                with pytest.raises(NetworkError, match="Unexpected response type"):
                    await client.broadcast(_VALID_RAW_TX)

    @pytest.mark.asyncio
    async def test_invalid_hex_response_raises_network_error(self):
        """Server returns a string but it's not valid hex (contains 'zz')."""
        bad_txid = "z" * 64
        ws = _make_ws_mock({"id": 1, "result": bad_txid})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                with pytest.raises(NetworkError, match="invalid txid"):
                    await client.broadcast(_VALID_RAW_TX)

    @pytest.mark.asyncio
    async def test_short_txid_response_raises_network_error(self):
        """Server returns hex but wrong length (32 chars instead of 64)."""
        short_txid = "ab" * 16
        ws = _make_ws_mock({"id": 1, "result": short_txid})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                with pytest.raises(NetworkError, match="invalid txid"):
                    await client.broadcast(_VALID_RAW_TX)

    @pytest.mark.asyncio
    async def test_long_txid_response_raises_network_error(self):
        """Server returns hex but too long (128 chars instead of 64)."""
        long_txid = "ab" * 64
        ws = _make_ws_mock({"id": 1, "result": long_txid})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                with pytest.raises(NetworkError, match="invalid txid"):
                    await client.broadcast(_VALID_RAW_TX)

    @pytest.mark.asyncio
    async def test_empty_string_response_raises_network_error(self):
        """Server returns an empty string."""
        ws = _make_ws_mock({"id": 1, "result": ""})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                with pytest.raises(NetworkError, match="invalid txid"):
                    await client.broadcast(_VALID_RAW_TX)

    @pytest.mark.asyncio
    async def test_valid_txid_response_succeeds(self):
        """Sanity: a well-formed 64-char hex txid passes through as Txid."""
        good_txid = "a" * 64
        ws = _make_ws_mock({"id": 1, "result": good_txid})
        with _patch_connect(ws):
            async with ElectrumXClient(["wss://example.com"]) as client:
                result = await client.broadcast(_VALID_RAW_TX)
        assert str(result) == good_txid


# ---------------------------------------------------------------------------
# JSON-RPC response correlation — Stream C #4
# ---------------------------------------------------------------------------
# Pre-fix: a single recv() in _call() meant that whichever caller awaited
# first got whatever message came in first, regardless of id. Two concurrent
# _call() invocations could swap responses. These tests prove the post-fix
# behavior: each _call() future is resolved by the matching id.


class TestResponseCorrelation:
    """Concurrent _call() invocations must each receive the response whose
    JSON-RPC id matches the request they sent — never another caller's.
    """

    def _make_recorded_ws(self, responses_by_method: dict[str, Any]):
        """Mock that records every send and replies based on the *method* the
        caller used. The reply is delivered out-of-order to maximize the
        chance of catching a swap bug.
        """
        ws = AsyncMock()
        send_log: list[dict] = []
        outbox: asyncio.Queue[str] = asyncio.Queue()
        delivered = asyncio.Event()

        async def _send(payload: str) -> None:
            send_log.append(json.loads(payload))

        async def _recv() -> str:
            try:
                msg = await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                # No more queued — block so the reader doesn't hot-spin.
                await asyncio.Event().wait()
                raise  # pragma: no cover
            return msg

        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)
        ws.__aenter__ = AsyncMock(return_value=ws)
        ws.__aexit__ = AsyncMock(return_value=None)
        return ws, send_log, outbox, delivered, responses_by_method

    @pytest.mark.asyncio
    async def test_two_concurrent_calls_get_their_own_responses(self):
        """Fire two _call()s back-to-back, deliver the responses in REVERSE
        order, and assert each caller gets the result keyed to its own id.

        Pre-fix: caller-A would receive caller-B's response (whichever
        message recv() pulled off the wire first). Post-fix: each future
        is resolved by the matching id regardless of arrival order.
        """
        ws = AsyncMock()
        send_log: list[dict] = []
        outbox: asyncio.Queue[str] = asyncio.Queue()

        async def _send(payload: str) -> None:
            send_log.append(json.loads(payload))

        async def _recv() -> str:
            try:
                return await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await asyncio.Event().wait()
                raise  # pragma: no cover

        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)

        # Connect once, inject ws to skip handshake.
        client = ElectrumXClient(["wss://example.com"])
        client._ws = ws

        # Fire two concurrent calls. They will register ids 1 and 2.
        task_a = asyncio.create_task(client._call("blockchain.transaction.get", ["a" * 64, False]))
        task_b = asyncio.create_task(client._call("blockchain.transaction.get", ["b" * 64, False]))
        # Let both register and send.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # Both sends should have happened.
        assert len(send_log) == 2
        # ids are assigned in send order.
        id_a = send_log[0]["id"]
        id_b = send_log[1]["id"]
        assert id_a != id_b

        # Deliver B's response FIRST, then A's. Pre-fix this would swap.
        await outbox.put(json.dumps({"id": id_b, "result": "B-RESULT"}))
        await outbox.put(json.dumps({"id": id_a, "result": "A-RESULT"}))

        result_a = await task_a
        result_b = await task_b

        assert result_a == "A-RESULT"
        assert result_b == "B-RESULT"

        await client.close()

    @pytest.mark.asyncio
    async def test_orphan_response_dropped_does_not_break_pending(self):
        """A response with an id no caller is waiting for must be dropped
        without breaking subsequent _call()s.
        """
        ws = AsyncMock()
        send_log: list[dict] = []
        outbox: asyncio.Queue[str] = asyncio.Queue()

        async def _send(payload: str) -> None:
            send_log.append(json.loads(payload))

        async def _recv() -> str:
            try:
                return await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await asyncio.Event().wait()
                raise  # pragma: no cover

        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)

        client = ElectrumXClient(["wss://example.com"])
        client._ws = ws

        # Push an orphan response with no matching pending future.
        await outbox.put(json.dumps({"id": 9999, "result": "orphan"}))

        # Now make a real call.
        task = asyncio.create_task(client.broadcast(_VALID_RAW_TX))
        await asyncio.sleep(0)
        assert len(send_log) == 1
        good = "a" * 64
        await outbox.put(json.dumps({"id": send_log[0]["id"], "result": good}))

        result = await task
        assert str(result) == good

        await client.close()

    @pytest.mark.asyncio
    async def test_close_fails_pending_calls_with_network_error(self):
        """Closing the client must resolve every in-flight _call() with
        NetworkError — never leave a future hanging.
        """
        ws = AsyncMock()
        outbox: asyncio.Queue[str] = asyncio.Queue()

        async def _send(payload: str) -> None:
            pass

        async def _recv() -> str:
            try:
                return await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await asyncio.Event().wait()
                raise  # pragma: no cover

        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)

        client = ElectrumXClient(["wss://example.com"])
        client._ws = ws

        # Fire a call that will never receive a response.
        task = asyncio.create_task(client.get_tip_height())
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # Close while the call is pending.
        await client.close()

        with pytest.raises(NetworkError, match="closed|lost"):
            _ = await task

    @pytest.mark.asyncio
    async def test_per_call_timeout_does_not_affect_siblings(self):
        """If one _call() times out, other concurrent calls must still
        resolve when their own response arrives.
        """
        ws = AsyncMock()
        send_log: list[dict] = []
        outbox: asyncio.Queue[str] = asyncio.Queue()

        async def _send(payload: str) -> None:
            send_log.append(json.loads(payload))

        async def _recv() -> str:
            try:
                return await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await asyncio.Event().wait()
                raise  # pragma: no cover

        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)

        # Short overall timeout — but long enough that B's response arrives.
        client = ElectrumXClient(["wss://example.com"], timeout=0.5)
        client._ws = ws

        task_a = asyncio.create_task(client.get_tip_height())  # will time out
        task_b = asyncio.create_task(client.broadcast(_VALID_RAW_TX))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert len(send_log) == 2
        id_b = send_log[1]["id"]

        # Resolve B; leave A's response unsent → A times out.
        good_txid = "a" * 64
        await outbox.put(json.dumps({"id": id_b, "result": good_txid}))

        result_b = await task_b
        assert str(result_b) == good_txid

        # A must time out as NetworkError, not propagate the raw
        # asyncio.TimeoutError.
        with pytest.raises(NetworkError, match="timed out"):
            _ = await task_a

        await client.close()

    @pytest.mark.asyncio
    async def test_send_lock_serializes_writes(self):
        """Multiple concurrent _call()s must funnel sends through the
        send_lock so websockets.send is never called concurrently from
        two tasks (which can interleave fragments on the same connection).
        """
        send_in_progress = 0
        max_concurrent_sends = 0
        outbox: asyncio.Queue[str] = asyncio.Queue()
        send_log: list[dict] = []

        async def _send(payload: str) -> None:
            nonlocal send_in_progress, max_concurrent_sends
            send_in_progress += 1
            max_concurrent_sends = max(max_concurrent_sends, send_in_progress)
            # Yield so a second task can attempt to enter if the lock isn't
            # holding it back.
            await asyncio.sleep(0)
            send_in_progress -= 1
            send_log.append(json.loads(payload))

        async def _recv() -> str:
            try:
                return await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await asyncio.Event().wait()
                raise  # pragma: no cover

        ws = AsyncMock()
        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)

        client = ElectrumXClient(["wss://example.com"])
        client._ws = ws

        tasks = [asyncio.create_task(client.get_tip_height()) for _ in range(5)]
        # Give them a chance to all send.
        for _ in range(10):
            await asyncio.sleep(0)

        assert max_concurrent_sends == 1, f"send_lock should serialize sends; max concurrent was {max_concurrent_sends}"

        # Resolve all.
        for entry in send_log:
            await outbox.put(json.dumps({"id": entry["id"], "result": {"height": 1, "hex": "00" * 80}}))
        await asyncio.gather(*tasks)
        await client.close()

    @pytest.mark.asyncio
    async def test_response_without_int_id_is_dropped(self):
        """Server pushes (no id, or non-int id) must be dropped without
        affecting any pending caller.
        """
        ws = AsyncMock()
        send_log: list[dict] = []
        outbox: asyncio.Queue[str] = asyncio.Queue()

        async def _send(payload: str) -> None:
            send_log.append(json.loads(payload))

        async def _recv() -> str:
            try:
                return await asyncio.wait_for(outbox.get(), timeout=5.0)
            except asyncio.TimeoutError:
                await asyncio.Event().wait()
                raise  # pragma: no cover

        ws.send = _send
        ws.recv = _recv
        ws.close = AsyncMock(return_value=None)

        client = ElectrumXClient(["wss://example.com"])
        client._ws = ws

        task = asyncio.create_task(client.get_tip_height())
        await asyncio.sleep(0)

        # Push two malformed messages (no id, then string id), then the real one.
        await outbox.put(json.dumps({"method": "blockchain.headers.subscribe", "params": [{"height": 999}]}))
        await outbox.put(json.dumps({"id": "not-an-int", "result": "bad"}))
        await outbox.put(json.dumps({"id": send_log[0]["id"], "result": {"height": 42, "hex": "00" * 80}}))

        result = await task
        assert int(result) == 42

        await client.close()


# ---------------------------------------------------------------------------
# _connect_first: parallel failover race (N18)
# ---------------------------------------------------------------------------


class TestConnectFirstRace:
    """_connect_first races all URLs simultaneously instead of sequentially.

    A single dead endpoint must not delay failover by a full timeout period.
    Tests use asyncio primitives to simulate fast-responders and slow-dead
    endpoints without any real network I/O.
    """

    async def test_single_url_success(self):
        """Single URL path: _connect_first works trivially."""
        ws_mock = MagicMock()
        ws_mock.close = AsyncMock(return_value=None)

        async def _connect(url):
            return ws_mock

        client = ElectrumXClient(["wss://live.example.com"], allow_insecure=False)
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_connect):
            result = await client._connect_first(["wss://live.example.com"], timeout=5.0)
        assert result is ws_mock

    async def test_first_dead_second_live_resolves_fast(self):
        """Dead first URL must not block; the live second URL wins the race.

        The dead URL never resolves within the test timeout (it hangs until
        cancelled). The live URL resolves instantly. Without parallel racing
        the sequential loop would wait up to `timeout` seconds on the dead
        URL before trying the second — the test would be slow.
        With racing the result arrives almost immediately.
        """
        live_ws = MagicMock()
        live_ws.close = AsyncMock(return_value=None)

        async def _dead(url):
            await asyncio.Event().wait()  # blocks until cancelled

        async def _live(url):
            return live_ws

        connect_map = {
            "wss://dead.example.com": _dead,
            "wss://live.example.com": _live,
        }

        async def _connect(url):
            return await connect_map[url](url)

        client = ElectrumXClient(
            ["wss://dead.example.com", "wss://live.example.com"],
            allow_insecure=False,
        )
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_connect):
            result = await asyncio.wait_for(
                client._connect_first(
                    ["wss://dead.example.com", "wss://live.example.com"],
                    timeout=5.0,
                ),
                timeout=1.0,  # must complete well before the 5s endpoint timeout
            )
        assert result is live_ws

    async def test_all_dead_raises_network_error(self):
        """All failing URLs must raise NetworkError."""
        import websockets

        async def _fail(url):
            raise websockets.exceptions.WebSocketException("refused")

        client = ElectrumXClient(["wss://a.example.com", "wss://b.example.com"])
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_fail):
            with pytest.raises(NetworkError):
                await client._connect_first(["wss://a.example.com", "wss://b.example.com"], timeout=5.0)

    async def test_winner_is_returned_only_once_on_simultaneous_success(self):
        """When two URLs succeed almost simultaneously only one winner is returned.

        The extra winner must be closed to avoid leaking the socket.
        """
        ws_a = MagicMock()
        ws_a.close = AsyncMock(return_value=None)
        ws_b = MagicMock()
        ws_b.close = AsyncMock(return_value=None)

        call_order: list[str] = []

        async def _connect(url):
            # Both resolve instantly — simulates a near-simultaneous race.
            await asyncio.sleep(0)
            if url == "wss://a.example.com":
                call_order.append("a")
                return ws_a
            call_order.append("b")
            return ws_b

        client = ElectrumXClient(["wss://a.example.com", "wss://b.example.com"])
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_connect):
            result = await client._connect_first(["wss://a.example.com", "wss://b.example.com"], timeout=5.0)

        # Exactly one of the two should be the result.
        assert result is ws_a or result is ws_b
        # The losing connection must have been closed.
        if result is ws_a:
            ws_b.close.assert_awaited_once()
        else:
            ws_a.close.assert_awaited_once()

    async def test_timeout_raises_network_error(self):
        """Overall timeout with all-hanging URLs must raise NetworkError promptly."""

        async def _hang(url):
            await asyncio.Event().wait()

        client = ElectrumXClient(["wss://a.example.com", "wss://b.example.com"])
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_hang):
            with pytest.raises(NetworkError):
                await client._connect_first(
                    ["wss://a.example.com", "wss://b.example.com"],
                    timeout=0.05,  # very short so the test is fast
                )

    async def test_every_produced_socket_except_winner_gets_closed(self):
        """Regression for the cancelled-but-connected socket leak.

        Pre-fix the close ran only from the inline ``else: ws.close()``
        branch inside the for-loop over ``done``. That covered the
        "two completed in the same wait() iteration" case but missed
        any task that completed *between* wait() returning and the
        ``task.cancel()`` in finally taking effect — those sockets stayed
        inside the cancelled coroutine frame and ``gather(return_exceptions
        =True)`` consumed the CancelledError without retrieving them.

        Post-fix every successful ``websockets.connect()`` registers the
        ws in a shared ``created`` list, and finally closes every entry
        that isn't the winner. This test exercises the invariant: with
        N URLs all returning real sockets, exactly N-1 get closed,
        regardless of which one wins.
        """
        # Three sockets so the test catches any "off by one" in the
        # close loop — and proves the fix handles >2 endpoints.
        sockets = {
            url: MagicMock(name=url)
            for url in (
                "wss://a.example.com",
                "wss://b.example.com",
                "wss://c.example.com",
            )
        }
        for ws in sockets.values():
            ws.close = AsyncMock(return_value=None)

        async def _connect(url):
            await asyncio.sleep(0)  # one tick: all three race in parallel
            return sockets[url]

        client = ElectrumXClient(list(sockets.keys()))
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_connect):
            result = await client._connect_first(list(sockets.keys()), timeout=5.0)

        # Exactly one survived as the winner.
        assert result in sockets.values()
        # The other two must have been closed.
        losers = [ws for ws in sockets.values() if ws is not result]
        assert len(losers) == 2
        for loser in losers:
            loser.close.assert_awaited_once()
        # And the winner must NOT have been closed.
        result.close.assert_not_awaited()

    async def test_ensure_connected_uses_connect_first(self):
        """_ensure_connected delegates to _connect_first (not a sequential loop)."""
        ws_mock = _make_ws_mock({"id": 1, "result": 100})

        async def _connect(url):
            return ws_mock

        client = ElectrumXClient(["wss://a.example.com", "wss://b.example.com"])
        with patch("pyrxd.network.electrumx.websockets.connect", side_effect=_connect):
            # Patch _connect_first to verify it's called.
            original = client._connect_first
            calls: list[tuple] = []

            async def _tracked(*args, **kwargs):
                calls.append(args)
                return await original(*args, **kwargs)

            client._connect_first = _tracked  # type: ignore[method-assign]
            await client._ensure_connected()

        assert len(calls) == 1, "_connect_first should be called exactly once"

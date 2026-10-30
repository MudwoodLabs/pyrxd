"""A JSON-RPC error that arrives with HTTP 400 reaches the caller with the server's reason.

drpc and Blast refuse a wide ``eth_getLogs`` with HTTP 400 and the reason in a JSON-RPC error body
(recorded 2026-10-30, ``tests/fixtures/recorded_endpoint_replies.json``). web3's session raised on the
status before the body was read, so the reason never reached ``disposition._is_range_limit``. These
pin the rule in ``eth_wallet/rpc.py`` (``_ERROR_BODY_STATUSES``) and its limits: only 400, only a
well-formed JSON-RPC error, only a bounded body, and the body still crosses the key scrubber.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet import rpc as rpc_module
from pyrxd.eth_wallet.disposition import _is_range_limit
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.security.errors import NetworkError

_KEY = "SECRETKEY0123456789abcdefXYZ"
_RANGE = "ranges over 10000 blocks are not supported on free plan"  # drpc's recorded wording


def _serve(status: int, body: Any, split_at: int | None = None) -> tuple[HTTPServer, str]:
    """Answer every POST with ``status`` and ``body`` (a callable of the request id, or bytes).

    With ``split_at``, the body goes out chunked in two pieces with a pause between them, so the
    client's first read sees only the first piece."""

    class _H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            data = body(req.get("id")) if callable(body) else body
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            if split_at is None:
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for piece in (data[:split_at], data[split_at:]):
                self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                self.wfile.flush()
                time.sleep(0.2)
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, *_a: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/v3/{_KEY}"


def _error(message: str, code: int = 35) -> Any:
    return lambda rid: json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}).encode()


def _get_logs(status: int, body: Any, split_at: int | None = None) -> BaseException:
    srv, url = _serve(status, body, split_at)

    async def go() -> None:
        rpc = EthRpc(url, expected_chain_id=1)
        rpc.w3.provider.exception_retry_configuration = None
        try:
            await rpc.get_logs(address="0x" + "11" * 20, from_block=1, to_block=2)
        finally:
            await rpc.close()

    try:
        with pytest.raises(NetworkError) as caught:
            asyncio.run(go())
    finally:
        srv.shutdown()
        srv.server_close()
    return caught.value


def test_a_400_jsonrpc_error_carries_the_servers_reason_to_the_range_rule() -> None:
    exc = _get_logs(400, _error(_RANGE))
    assert _RANGE in str(exc)
    assert _is_range_limit(exc)


def test_a_200_jsonrpc_error_is_unchanged() -> None:
    """Honest baseline: the same error at 200 always reached the rule."""
    exc = _get_logs(200, _error(_RANGE))
    assert _is_range_limit(exc)


def test_a_400_without_a_jsonrpc_error_body_still_fails_on_its_status() -> None:
    exc = _get_logs(400, b"Bad Request: ranges over 10000 blocks")
    assert "400" in str(exc)
    assert "ranges over" not in str(exc)


def test_a_400_body_with_a_result_is_not_read_as_an_answer() -> None:
    """An error body that also carries a ``result`` is refused, so a 400 can never deliver data."""
    exc = _get_logs(
        400,
        lambda rid: json.dumps(
            {"jsonrpc": "2.0", "id": rid, "result": [], "error": {"code": 35, "message": _RANGE}}
        ).encode(),
    )
    assert "400" in str(exc)
    assert _RANGE not in str(exc)


def test_a_400_error_body_sent_in_two_chunks_is_read_whole() -> None:
    exc = _get_logs(400, _error(_RANGE), split_at=20)
    assert _RANGE in str(exc)
    assert _is_range_limit(exc)


def test_an_over_cap_body_is_refused_even_when_its_first_chunk_is_a_whole_error() -> None:
    """The first chunk alone parses; the padding after it puts the body over the cap."""

    def body(rid: Any) -> bytes:
        doc = json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": 35, "message": _RANGE}}).encode()
        return doc + b" " * (rpc_module._MAX_ERROR_BODY_BYTES + 1 - len(doc))

    probe = json.dumps({"jsonrpc": "2.0", "id": 0, "error": {"code": 35, "message": _RANGE}}).encode()
    exc = _get_logs(400, body, split_at=len(probe) + 4)  # past the doc whatever the id's width
    assert "400" in str(exc)
    assert _RANGE not in str(exc)


def test_a_429_with_a_jsonrpc_error_body_stays_an_http_error() -> None:
    """A rate limit means its status; it must not be turned into an RPC answer (or a range limit)."""
    exc = _get_logs(429, _error("request limit reached, try a smaller range", code=-32011))
    assert "429" in str(exc)
    assert not _is_range_limit(exc)


def test_an_oversized_400_body_is_not_read() -> None:
    big = "x" * (rpc_module._MAX_ERROR_BODY_BYTES + 1)
    exc = _get_logs(400, _error(_RANGE + big))
    assert "400" in str(exc)
    assert _RANGE not in str(exc)


def test_a_400_body_one_byte_over_the_cap_is_not_read_even_when_it_parses() -> None:
    """The read stops at cap + 1 bytes, so only the length check refuses a body that is valid JSON
    up to there (here: a small error padded with trailing whitespace to exactly cap + 1)."""

    def body(rid: Any) -> bytes:
        doc = json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": 35, "message": _RANGE}}).encode()
        return doc + b" " * (rpc_module._MAX_ERROR_BODY_BYTES + 1 - len(doc))

    exc = _get_logs(400, body)
    assert "400" in str(exc)
    assert _RANGE not in str(exc)


def test_a_400_body_that_quotes_the_key_is_scrubbed() -> None:
    exc = _get_logs(400, _error(f"{_RANGE} for /v3/{_KEY}"))
    assert _RANGE in str(exc)
    assert _KEY not in "".join(traceback.format_exception(exc))

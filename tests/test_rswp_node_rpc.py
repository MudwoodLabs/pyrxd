"""NodeRpcSource against a real local HTTP server — fail-closed transport semantics.

A tiny stdlib JSON-RPC stub stands in for a Radiant node: enough to prove the
source passes results through, maps RPC errors and malformed results to
``NetworkError`` (never a healthy-looking empty answer), and treats a null
``gettxout`` as "spent" rather than as a failure.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from pyrxd.security.errors import NetworkError
from pyrxd.swap.rswp import NodeRpcSource

_RESPONSES: dict[str, object] = {}
_ERRORS: dict[str, str] = {}
#: Per-method HTTP status override, for the shape a node produces when it fails at the HTTP
#: layer WITHOUT a JSON-RPC error object (a proxy, a crash mid-handler, a captive portal).
#: The status check is the only thing standing between that and a "result" the book trusts.
_STATUSES: dict[str, int] = {}


class _StubRpc(BaseHTTPRequestHandler):
    def do_POST(self):  # BaseHTTPRequestHandler API name
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = body["method"]
        if method in _ERRORS:
            payload = {"result": None, "error": {"code": -1, "message": _ERRORS[method]}, "id": body["id"]}
            status = 500
        else:
            payload = {"result": _RESPONSES.get(method), "error": None, "id": body["id"]}
            status = _STATUSES.get(method, 200)
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence request logging
        pass


@pytest.fixture
def stub_url():
    _RESPONSES.clear()
    _ERRORS.clear()
    _STATUSES.clear()
    server = HTTPServer(("127.0.0.1", 0), _StubRpc)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


async def test_results_pass_through(stub_url) -> None:
    _RESPONSES["getopenorders"] = [{"version": 2}]
    _RESPONSES["getrawtransaction"] = "beef"
    # A real gettxout result describes the output it says is live. `is_unspent` no longer
    # accepts a bare dict — `{}` used to read as UNSPENT, which is the orderbook's
    # `fillable` gate answering "yes" off a response that describes nothing.
    _RESPONSES["gettxout"] = {"value": 1.0, "scriptPubKey": {"hex": "76a914" + "11" * 20 + "88ac"}}
    async with NodeRpcSource(stub_url) as src:
        assert await src.get_open_orders("00" * 32) == [{"version": 2}]
        assert await src.get_transaction("ab" * 32) == b"\xbe\xef"
        assert await src.is_unspent("ab" * 32, 0) is True


async def test_null_gettxout_means_spent_not_error(stub_url) -> None:
    _RESPONSES["gettxout"] = None
    async with NodeRpcSource(stub_url) as src:
        assert await src.is_unspent("ab" * 32, 0) is False


async def test_rpc_error_raises_network_error(stub_url) -> None:
    _ERRORS["getopenorders"] = "Swap index not enabled. Use -swapindex=1 to enable."
    async with NodeRpcSource(stub_url) as src:
        with pytest.raises(NetworkError, match="Swap index not enabled"):
            await src.get_open_orders("00" * 32)


async def test_non_list_orders_result_fails_closed(stub_url) -> None:
    _RESPONSES["getopenordersbywant"] = "surprise"
    async with NodeRpcSource(stub_url) as src:
        with pytest.raises(NetworkError, match="non-list"):
            await src.get_open_orders_by_want("00" * 32)


async def test_unreachable_endpoint_fails_closed() -> None:
    async with NodeRpcSource("http://127.0.0.1:1", timeout_s=2) as src:
        with pytest.raises(NetworkError, match="transport error"):
            await src.get_open_orders("00" * 32)


@pytest.mark.parametrize(
    "result",
    [None, 12, ["ab"], {"hex": "beef"}, True],
    ids=["null", "int", "list", "dict", "bool"],
)
async def test_non_string_rawtransaction_fails_closed(stub_url, result) -> None:
    """``bytes.fromhex(None)`` raises ``TypeError``, not ``NetworkError``.

    Every caller above this — the book client's per-row guard, the take path — handles
    ``NetworkError``. A raw ``TypeError`` escapes all of them as a bare traceback, which is
    the exact failure mode ``_guards`` was written to end. Neutering the ``isinstance``
    check left the suite green.
    """
    _RESPONSES["getrawtransaction"] = result
    async with NodeRpcSource(stub_url) as src:
        with pytest.raises(NetworkError, match="non-hex"):
            await src.get_transaction("ab" * 32)


async def test_http_error_without_an_rpc_error_object_fails_closed(stub_url) -> None:
    """A node (or a proxy in front of one) can fail at the HTTP layer and still return a
    body with a ``result`` and no ``error``. Reading that as an answer is the fail-open:
    the source's contract is that a healthy-but-empty book is never manufactured from a
    failure. The status check is what enforces it, and nothing tested it."""
    _RESPONSES["getopenorders"] = [{"version": 2}]
    _STATUSES["getopenorders"] = 503
    async with NodeRpcSource(stub_url) as src:
        with pytest.raises(NetworkError, match="HTTP 503"):
            await src.get_open_orders("00" * 32)


async def test_a_healthy_200_is_still_accepted(stub_url) -> None:
    """Honest direction: the status check must not refuse a normal answer."""
    _RESPONSES["getopenorders"] = [{"version": 2}]
    async with NodeRpcSource(stub_url) as src:
        assert await src.get_open_orders("00" * 32) == [{"version": 2}]

"""A keyed ``--eth-rpc-url`` must not reach error text, logs or a watchtower page.

Hosted providers put the key in the URL path (``https://host/v3/<KEY>``), and a rate-limited tier
answers 429 routinely. aiohttp's ``ClientResponseError`` quotes the full request URL, and every
``EthRpc`` method wrapped it as ``NetworkError(f"... failed: {exc}")``. Through the real
watchtower path — ``Reconciler`` -> ``ChainObserver`` -> ``RpcEthChainSource`` -> ``EthRpc``
-> ``DedupAlerter`` — and the key was in the CRITICAL page and in the log (``logger.exception``
prints the exception chain, so redacting only the message would still leak it underneath).

These run against a real local HTTP server that answers every request with 429 or 503 — the same
transport aiohttp uses in production — so the exception text is the library's own, not a fixture's.
"""

from __future__ import annotations

import asyncio
import inspect
import io
import json
import logging
import os
import pathlib
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.security.errors import NetworkError

_KEY = "SECRETKEY0123456789abcdefXYZ"
_ART = json.loads((pathlib.Path(__file__).parent / "fixtures" / "EthHtlc.json").read_text())


@pytest.fixture(params=[429, 503])
def keyed_url(request):
    """A server answering every POST with ``request.param``; yields (url, hit-counter)."""
    hits = {"n": 0}
    status = request.param

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            hits["n"] += 1
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}/v3/{_KEY}", hits
    finally:
        srv.shutdown()
        srv.server_close()


def _full_text(exc: BaseException) -> str:
    """Everything ``logger.exception`` / ``--debug`` would print: message, type, and the chain."""
    return "".join(traceback.format_exception(exc))


#: How to call each public coroutine method of EthRpc. KEYED BY THE DERIVED SET (see the test
#: below): a method added to EthRpc without an entry here fails that test rather than going
#: unchecked.
_CALLS = {
    "assert_chain": lambda r: r.assert_chain(),
    "latest_block_timestamp": lambda r: r.latest_block_timestamp(),
    "latest_block_timestamp_quorum": lambda r: r.latest_block_timestamp_quorum(),
    "latest_block_timestamp_min": lambda r: r.latest_block_timestamp_min(),
    "get_code": lambda r: r.get_code("0x" + "11" * 20),
    "get_balance": lambda r: r.get_balance("0x" + "11" * 20),
    "get_transaction_count": lambda r: r.get_transaction_count("0x" + "11" * 20),
    "fee_fields": lambda r: r.fee_fields(),
    "preflight": lambda r: r.preflight({"from": "0x" + "11" * 20, "to": "0x" + "22" * 20, "data": "0x"}),
    "send_raw": lambda r: r.send_raw(b"\x02\x00"),
    "wait_receipt": lambda r: r.wait_receipt("0x" + "ab" * 32, timeout_s=2.0),
    "get_transaction": lambda r: r.get_transaction("0x" + "ab" * 32),
    "get_transaction_receipt": lambda r: r.get_transaction_receipt("0x" + "ab" * 32),
    "finalized_block_number": lambda r: r.finalized_block_number(),
    "block_number": lambda r: r.block_number(),
    "canonical_block_hash": lambda r: r.canonical_block_hash(1),
    "get_logs": lambda r: r.get_logs(address="0x" + "11" * 20),
}
_NOT_A_READ = {"close"}  # tears the session down; raises nothing by design


def test_every_public_coroutine_of_EthRpc_has_an_entry():
    derived = {
        n for n, f in inspect.getmembers(EthRpc, inspect.iscoroutinefunction) if not n.startswith("_")
    } - _NOT_A_READ
    assert derived, "derived nothing — the derivation is broken"
    assert derived == set(_CALLS), {"unchecked": derived - set(_CALLS), "stale": set(_CALLS) - derived}


@pytest.mark.parametrize("method", sorted(_CALLS))
def test_no_EthRpc_failure_quotes_the_key(keyed_url, method):
    url, hits = keyed_url

    async def go():
        rpc = EthRpc(url, expected_chain_id=1)
        # web3 retries a failed request with ~2s of backoff; the last attempt raises the same
        # exception, so skip the wait here (the watchtower test below keeps the default).
        rpc.w3.provider.exception_retry_configuration = None
        try:
            await _CALLS[method](rpc)
        finally:
            await rpc.close()

    before = hits["n"]
    with pytest.raises(Exception) as caught:
        asyncio.run(go())
    assert hits["n"] > before, "no request reached the server, so this proved nothing"
    text = _full_text(caught.value)
    assert _KEY not in text, text
    # Still useful to an operator: it says which host failed and how.
    assert "127.0.0.1" in text


def test_the_server_really_makes_aiohttp_quote_the_key(keyed_url):
    """The control. Without the redacting provider, the very same request DOES quote the key — so
    the tests above are passing because the leak is closed, not because nothing here would leak."""
    import web3

    url, _hits = keyed_url

    async def go():
        w3 = web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url))
        try:
            await w3.eth.chain_id
        finally:
            await w3.provider.disconnect()

    with pytest.raises(Exception) as caught:
        asyncio.run(go())
    assert _KEY in _full_text(caught.value)


def test_a_RAW_contract_read_through_rpc_w3_does_not_quote_the_key(keyed_url):
    """The path that never crosses an EthRpc method: the legs' getter reads go
    ``rpc.w3.eth.contract(...).functions.x().call()`` (via ``read_contract``). The redaction is in
    the provider, which every request crosses, so this is covered too."""
    url, _hits = keyed_url

    async def go():
        rpc = EthRpc(url, expected_chain_id=1)
        try:
            c = rpc.w3.eth.contract(address="0x" + "11" * 20, abi=_ART["abi"])
            await c.functions.hashlock().call()
        finally:
            await rpc.close()

    with pytest.raises(NetworkError) as caught:
        asyncio.run(go())
    assert _KEY not in _full_text(caught.value)


def test_a_keyless_url_keeps_the_original_exception_type_and_chain():
    """The redaction must not change behaviour where there is nothing to hide: with no secret in
    the URL the provider re-raises the library's own exception unchanged."""
    import aiohttp

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(429)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:

        async def go():
            rpc = EthRpc(f"http://127.0.0.1:{srv.server_port}/", expected_chain_id=1)
            try:
                await rpc.get_code("0x" + "11" * 20)
            finally:
                await rpc.close()

        with pytest.raises(NetworkError) as caught:
            asyncio.run(go())
        assert isinstance(caught.value.__cause__, aiohttp.ClientResponseError)
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_watchtower_page_and_log_carry_no_key(keyed_url):
    """End to end, through the real reconciler, observer, eth source and alerter.
    The page is what a webhook channel POSTs to a third party; the log is ``logger.exception``."""
    from pyrxd.gravity.watch import ChainObserver, RpcEthChainSource
    from pyrxd.gravity.watch.adapters import LoggingAlertChannel
    from pyrxd.gravity.watch.alerts import DedupAlerter
    from pyrxd.gravity.watch.reconciler import Reconciler
    from tests.test_watch_quorum import FakeRxd, _eth_policy, _eth_record

    url, hits = keyed_url
    pages = []

    class _Store:
        async def list_active(self):
            return [("swap1", _eth_record())]

    class _Chan:
        async def send(self, page):
            pages.append(page)

    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)  # what `pyrxd-watch` configures (gravity/watch/run.py)

    async def go():
        rpc = EthRpc(url, expected_chain_id=1)
        try:
            rec = Reconciler(
                store=_Store(),
                observer=ChainObserver(eth=RpcEthChainSource(rpc), rxd=FakeRxd(tip=150, cov_confs=51)),
                alerter=DedupAlerter(channel=_Chan()),
                policy=_eth_policy(),
                safety_window_blocks=6,
            )
            await rec.tick()
            for p in pages:
                await LoggingAlertChannel().send(p)
        finally:
            await rpc.close()  # web3 logs "Successfully disconnected from: <uri>" here, at INFO

    try:
        asyncio.run(go())
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
    assert hits["n"] > 0 and pages, "the tick never reached the endpoint or never paged"
    assert all(_KEY not in p.message for p in pages), [p.message for p in pages]
    assert "127.0.0.1" in pages[0].message  # still names the failing host
    log = buf.getvalue()
    assert "reconcile error" in log  # non-vacuity: the logger.exception record was captured
    assert "Successfully disconnected from" in log  # ...and so was the provider's own INFO line
    assert _KEY not in log


def test_the_providers_own_log_lines_carry_no_key_even_at_DEBUG(keyed_url):
    """web3's provider logs its full ``endpoint_uri`` on every request (DEBUG) and on close (INFO)."""
    url, _hits = keyed_url
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    lg = logging.getLogger("web3.providers.AsyncHTTPProvider")
    old = lg.level
    lg.addHandler(handler)
    lg.setLevel(logging.DEBUG)

    async def go():
        rpc = EthRpc(url, expected_chain_id=1)
        try:
            await rpc.block_number()
        finally:
            await rpc.close()

    try:
        with pytest.raises(NetworkError):
            asyncio.run(go())
    finally:
        lg.removeHandler(handler)
        lg.setLevel(old)
    log = buf.getvalue()
    assert "Making request HTTP" in log and "Successfully disconnected from" in log, log
    assert "127.0.0.1" in log
    assert _KEY not in log, log


def test_failed_redacts_text_that_did_NOT_come_through_the_provider():
    """``EthRpc._failed`` is the second layer: it redacts whatever text reaches an ``EthRpc``
    method's error, even text the provider never saw (an exception raised above the transport).
    With the provider layer in place no HTTP failure reaches it unredacted, so it is tested here
    directly — the end-to-end tests above cannot tell whether it is there."""
    url = f"https://rpc.example/v3/{_KEY}"
    rpc = EthRpc(url, expected_chain_id=1)
    inner = RuntimeError(f"upstream said: could not reach {url}")
    try:
        raise ValueError("wrapper with a clean message") from inner
    except ValueError as outer:
        err = rpc._failed("eth_getCode failed", outer)
    assert str(err) == "eth_getCode failed: wrapper with a clean message"
    # The CHAIN quotes the key (inner), so it is cut — or logger.exception would print it.
    assert err.__cause__ is None and err.__suppress_context__
    assert _KEY not in _full_text(err)

    quoted = rpc._failed("eth_getCode failed", RuntimeError(f"429 for url={url}"))
    assert _KEY not in str(quoted) and "rpc.example" in str(quoted)  # the message itself is redacted

    clean = rpc._failed("eth_getCode failed", RuntimeError("timeout"))
    assert isinstance(clean.__cause__, RuntimeError)  # nothing secret: the chain is kept for debugging


# ── a JSON-RPC ERROR BODY that echoes the key: HTTP 200, so no transport exception ─────────────


@pytest.fixture
def echoing_url():
    """Answers every call with HTTP 200 and a JSON-RPC error whose ``message`` and ``data`` repeat
    the request path. web3 raises ``Web3RPCError`` from that body AFTER ``make_request`` returned,
    so the transport-failure redaction never sees it. ``server.revert`` switches to a typed revert
    (code 3 with hex ``data``) for the honest-path check."""
    state = {"revert": False, "hits": 0}

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            state["hits"] += 1
            if state["revert"]:
                err = {"code": 3, "message": "execution reverted", "data": "0x560ff900"}
            else:
                err = {"code": -32000, "message": f"denied for {self.path}", "data": f"path={self.path}"}
            body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": err}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}/v3/{_KEY}", state
    finally:
        srv.shutdown()
        srv.server_close()


def test_the_echoing_server_really_puts_the_key_in_web3s_error(echoing_url):
    """Control: through a plain provider the same body DOES carry the key into the exception."""
    import web3

    url, _state = echoing_url

    async def go():
        w3 = web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url))
        try:
            await w3.eth.get_storage_at("0x" + "11" * 20, 0)
        finally:
            await w3.provider.disconnect()

    with pytest.raises(Exception) as caught:
        asyncio.run(go())
    assert _KEY in _full_text(caught.value)


@pytest.mark.parametrize(
    "call",
    [
        lambda r: r.w3.eth.get_storage_at("0x" + "11" * 20, 0),
        lambda r: r.w3.eth.get_balance("0x" + "11" * 20),
        lambda r: r.get_code("0x" + "11" * 20),
    ],
    ids=["raw-w3-get_storage_at", "raw-w3-get_balance", "EthRpc.get_code"],
)
def test_a_json_rpc_error_body_echoing_the_key_is_redacted(echoing_url, call):
    url, state = echoing_url

    async def go():
        rpc = EthRpc(url, expected_chain_id=1)
        try:
            await call(rpc)
        finally:
            await rpc.close()

    with pytest.raises(Exception) as caught:
        asyncio.run(go())
    assert state["hits"] > 0
    text = _full_text(caught.value)
    assert _KEY not in text, text
    assert "denied for /v3/" in text  # the server's message survives, minus the key


def test_a_claim_refused_on_an_echoed_error_does_not_carry_the_key(echoing_url):
    """The reviewer's path: the claim's settled read fails with the echoing body, and the
    PreRevealAbort it raises quotes that error."""
    from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
    from pyrxd.eth_wallet.locator import EthHtlcLocator
    from pyrxd.security.errors import PreRevealAbort
    from pyrxd.security.secrets import PrivateKeyMaterial

    url, _state = echoing_url
    loc = EthHtlcLocator(
        chain_id=1,
        contract_address="0x" + "11" * 20,
        deploy_tx_hash="0x" + "22" * 32,
        hashlock="0x" + "33" * 32,
        claimant="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        refundee="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        timeout=4_000_000_000,
        amount_wei=1,
    )

    async def go():
        rpc = EthRpc(url, expected_chain_id=1)
        leg = EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial(os.urandom(32)), chain_id=1, artifact=_ART)
        # Reach the settled read: the head reads succeed (fresh head), everything else hits the server.
        now = int(time.time())

        async def _head():
            return now

        rpc.latest_block_timestamp = rpc.latest_block_timestamp_quorum = _head  # type: ignore[method-assign]
        rpc.assert_chain = lambda: asyncio.sleep(0)  # type: ignore[method-assign]
        try:
            await leg.claim(loc, os.urandom(32))
        finally:
            await rpc.close()

    with pytest.raises(PreRevealAbort) as caught:
        asyncio.run(go())
    text = _full_text(caught.value)
    assert "denied for /v3/" in text  # it really failed on the echoed body
    assert _KEY not in text, text


def test_an_error_body_with_no_secret_reaches_web3_unchanged(echoing_url):
    """Honest path: scrubbing must not change what web3 makes of an error that quotes nothing
    secret. A revert-shaped body (code 3, hex ``data``) raises the same exception type with the
    same text through the scrubbing provider as through a plain one."""
    import web3

    url, state = echoing_url
    state["revert"] = True
    tx = {"from": "0x" + "11" * 20, "to": "0x" + "22" * 20, "data": "0x"}

    def raised(make_w3):
        async def go():
            w3 = make_w3()
            try:
                await w3.eth.call(tx)
            finally:
                await w3.provider.disconnect()

        with pytest.raises(Exception) as caught:
            asyncio.run(go())
        return type(caught.value), str(caught.value)

    plain = raised(lambda: web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url)))
    ours = raised(lambda: EthRpc(url, expected_chain_id=1).w3)
    assert ours == plain
    assert "0x560ff900" in ours[1]


# ── EVERY response shape, not only `error` as an object ─────────────────────────────────────────

#: How a server can put the request path (key included) into an HTTP-200 response. Each builds the
#: body from the request id and the echoed path. web3 raises from every one of them.
_MALFORMED = {
    "error-object": lambda rid, echo: {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": echo}},
    "error-string": lambda rid, echo: {"jsonrpc": "2.0", "id": rid, "error": echo},
    "error-list": lambda rid, echo: {"jsonrpc": "2.0", "id": rid, "error": [echo]},
    "no-error-no-result": lambda rid, echo: {"jsonrpc": "2.0", "id": rid, "note": echo},
    "top-level-list": lambda rid, echo: [{"jsonrpc": "2.0", "id": rid, "error": {"code": -1, "message": echo}}],
}


def _serve(make_body):
    hits = {"n": 0}

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            hits["n"] += 1
            body = json.dumps(make_body(req["id"], f"denied for {self.path}")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, hits


@pytest.mark.parametrize("shape", sorted(_MALFORMED))
def test_no_response_shape_carries_the_key_into_a_raw_w3_read(shape):
    import web3

    srv, hits = _serve(_MALFORMED[shape])
    url = f"http://127.0.0.1:{srv.server_port}/v3/{_KEY}"

    def raised(make_w3):
        async def go():
            w3 = make_w3()
            try:
                await w3.eth.get_balance("0x" + "11" * 20)
            finally:
                await w3.provider.disconnect()

        with pytest.raises(Exception) as caught:
            asyncio.run(go())
        return _full_text(caught.value)

    try:
        # Control, per shape: through a plain provider this shape DOES carry the key.
        assert _KEY in raised(lambda: web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url)))
        before = hits["n"]
        text = raised(lambda: EthRpc(url, expected_chain_id=1).w3)
        assert hits["n"] > before
        assert _KEY not in text, text
    finally:
        srv.shutdown()
        srv.server_close()


def test_an_honest_RESULT_is_returned_byte_identical_even_when_it_contains_the_key():
    """``result`` is never rewritten — not even a string that happens to equal a secret part. The
    whole response, as web3 receives it, is identical to what a plain provider hands it."""
    import web3

    weird = {"path": f"/v3/{_KEY}", "nested": [f"{_KEY}", {"k": "0x" + "ab" * 32}], "n": 7}
    srv, _hits = _serve(lambda rid, _echo: {"jsonrpc": "2.0", "id": rid, "result": weird})
    url = f"http://127.0.0.1:{srv.server_port}/v3/{_KEY}"

    async def fetch(make_w3):
        w3 = make_w3()
        try:
            return await w3.provider.make_request("pyrxd_test", [])
        finally:
            await w3.provider.disconnect()

    try:
        plain = asyncio.run(fetch(lambda: web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url))))
        ours = asyncio.run(fetch(lambda: EthRpc(url, expected_chain_id=1).w3))
    finally:
        srv.shutdown()
        srv.server_close()
    assert ours == plain
    assert ours["result"] == weird
    assert json.dumps(ours["result"]) == json.dumps(weird)


# ── a protocol member, or a misshapen response, that echoes the key ─────────────────────────────

#: Each keeps the honest-looking parts and puts the echo where the scrub must not trust it. These
#: are the shapes a values-only scrub that never looked at ``id`` / ``jsonrpc`` / ``code`` /
#: ``result`` let through (web3 quotes them in ``BadResponseFormat``).
_PROTOCOL_LEAKS = {
    "id-echo": lambda rid, echo: {"jsonrpc": "2.0", "id": echo, "result": "0x1"},
    "jsonrpc-echo": lambda rid, echo: {"jsonrpc": echo, "id": rid, "result": "0x1"},
    "string-error-code": lambda rid, echo: {"jsonrpc": "2.0", "id": rid, "error": {"code": echo, "message": "x"}},
    "top-level-list-with-result": lambda rid, echo: [{"jsonrpc": "2.0", "id": rid, "result": echo}],
    "error-and-result": lambda rid, echo: {
        "jsonrpc": "2.0",
        "id": rid,
        "error": {"code": -1, "message": "x"},
        "result": echo,
    },
}


@pytest.mark.parametrize("shape", sorted(_PROTOCOL_LEAKS))
def test_no_misshapen_protocol_member_carries_the_key_into_a_raw_w3_read(shape):
    import web3

    srv, hits = _serve(_PROTOCOL_LEAKS[shape])
    url = f"http://127.0.0.1:{srv.server_port}/v3/{_KEY}"

    def raised(make_w3):
        async def go():
            w3 = make_w3()
            try:
                return await w3.eth.get_balance("0x" + "11" * 20)
            finally:
                await w3.provider.disconnect()

        with pytest.raises(Exception) as caught:
            asyncio.run(go())
        return _full_text(caught.value)

    try:
        # Control, per shape: through a plain provider the key DOES reach the exception.
        assert _KEY in raised(lambda: web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url)))
        before = hits["n"]
        text = raised(lambda: EthRpc(url, expected_chain_id=1).w3)
        assert hits["n"] > before
        assert _KEY not in text, text
    finally:
        srv.shutdown()
        srv.server_close()

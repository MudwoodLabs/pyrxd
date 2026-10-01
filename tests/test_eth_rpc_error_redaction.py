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
import pathlib
import threading
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

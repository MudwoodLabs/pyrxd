"""Real endpoint replies, replayed offline through the production clients.

``tests/fixtures/recorded_endpoint_replies.json`` holds what the public endpoints this repository
names actually answered to a handful of read-only calls (``scripts/record_endpoint_replies.py``,
run once on a host with network access; the fixture says when). The fakes elsewhere in the suite
encode what we BELIEVE servers send. These tests feed what they DID send through the code that
sorts failures, so a classification rule written from documentation is checked against a reply.

Each table below says, per recorded reply, what the production code is meant to do with it. The
tables are keyed by the records in the fixture and the tests assert the two sets match, so
re-recording with a new endpoint or a new probe fails here until someone states the expectation.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import pathlib
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

from pyrxd.eth_wallet import disposition
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.network.electrumx import _rpc_error
from pyrxd.security.errors import NetworkError, PolicyRejection, RpcMethodNotFound

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_FIXTURE = json.loads((_ROOT / "tests" / "fixtures" / "recorded_endpoint_replies.json").read_text())

_spec = importlib.util.spec_from_file_location(
    "record_endpoint_replies", _ROOT / "scripts" / "record_endpoint_replies.py"
)
assert _spec is not None and _spec.loader is not None
recorder = importlib.util.module_from_spec(_spec)
sys.modules["record_endpoint_replies"] = recorder
_spec.loader.exec_module(recorder)


def _host(url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname
    assert host
    return host


# --------------------------------------------------------------------------- the fixture itself


def test_the_fixture_is_a_recording_with_records() -> None:
    assert _FIXTURE["schema"] == 1
    assert _FIXTURE["captured_by"] == "scripts/record_endpoint_replies.py"
    assert _FIXTURE["captured_at"]
    assert len(_FIXTURE["eth"]) > 0
    assert len(_FIXTURE["electrumx"]) > 0


def test_every_recorded_endpoint_is_one_the_recorder_ships() -> None:
    shipped = {url for _, url in recorder.DEFAULT_ETH} | set(recorder.DEFAULT_ELECTRUMX)
    recorded = {r["endpoint"] for r in _FIXTURE["eth"] + _FIXTURE["electrumx"]}
    assert recorded
    assert recorded <= shipped, recorded - shipped


def test_no_recorded_reply_carries_an_ip_address() -> None:
    """The fixture is published; a reply quoting the recorder's address must have been scrubbed."""
    texts = [r.get("body", "") for r in _FIXTURE["eth"]] + [r.get("reply", "") for r in _FIXTURE["electrumx"]]
    assert any(texts)
    for text in texts:
        assert recorder.scrub_ips(text) == text


def test_the_scrubber_does_scrub() -> None:
    """Honest path for the check above: an address IS replaced, a version or a time is not."""
    assert recorder.scrub_ips("limit for 203.0.113.9 / 2001:db8::1") == "limit for <ip> / <ip>"
    assert recorder.scrub_ips("ElectrumX 1.16.0 at 05:30:07") == "ElectrumX 1.16.0 at 05:30:07"


def test_the_recorder_asked_for_the_chunk_the_code_uses() -> None:
    assert recorder.LOG_CHUNK_BLOCKS == disposition.LOG_CHUNK_BLOCKS


# --------------------------------------------------------------------------- ETH: eth_getLogs failures

#: What ``eth_wallet.disposition`` must make of each recorded ``eth_getLogs`` reply:
#: "ok" (a list), "range_limit" (halve the chunk and ask again) or "failure" (record this endpoint
#: as failed; never "no logs", never halve). A rate limit must be "failure": halving on it sends a
#: throttled endpoint a dozen more requests.
_GETLOGS_EXPECTED: dict[tuple[str, str], str] = {
    ("eth.drpc.org", "get_logs_one_block_quiet"): "ok",
    ("eth.drpc.org", "get_logs_chunk_quiet"): "range_limit",  # 400, "ranges over 10000 blocks are not supported"
    ("eth.drpc.org", "get_logs_chunk_busy"): "range_limit",
    ("eth.drpc.org", "get_logs_full_range_busy"): "range_limit",
    ("eth-mainnet.public.blastapi.io", "get_logs_one_block_quiet"): "ok",
    ("eth-mainnet.public.blastapi.io", "get_logs_chunk_quiet"): "range_limit",  # 400, "up to a 10 block range"
    ("eth-mainnet.public.blastapi.io", "get_logs_chunk_busy"): "range_limit",
    ("eth-mainnet.public.blastapi.io", "get_logs_full_range_busy"): "range_limit",
    ("base-mainnet.public.blastapi.io", "get_logs_one_block_quiet"): "ok",
    ("base-mainnet.public.blastapi.io", "get_logs_chunk_quiet"): "range_limit",
    ("base-mainnet.public.blastapi.io", "get_logs_chunk_busy"): "range_limit",
    ("base-mainnet.public.blastapi.io", "get_logs_full_range_busy"): "range_limit",
    ("mainnet.base.org", "get_logs_one_block_quiet"): "failure",  # 429, -32011 "request limit reached"
    ("mainnet.base.org", "get_logs_chunk_quiet"): "failure",
    ("mainnet.base.org", "get_logs_chunk_busy"): "failure",
    ("mainnet.base.org", "get_logs_full_range_busy"): "failure",
    ("base.meowrpc.com", "get_logs_one_block_quiet"): "failure",  # 429, plain-text "Too Many Requests"
    ("base.meowrpc.com", "get_logs_chunk_quiet"): "failure",  # 200, -32000 "eth_getLogs is not supported"
    ("base.meowrpc.com", "get_logs_chunk_busy"): "failure",
    ("base.meowrpc.com", "get_logs_full_range_busy"): "failure",
}

_GETLOGS_RECORDS = {
    (_host(r["endpoint"]), r["probe"]): r
    for r in _FIXTURE["eth"]
    if r["request"]["method"] == "eth_getLogs" and "transport_error" not in r
}


#: The recording shows drpc and Blast refuse a wide range with HTTP 400 and the reason in the body.
#: web3's HTTP provider raises on the 400 status before the body is read, so the text that reaches
#: ``disposition._is_range_limit`` is "400, message='Bad Request'" and the reason is lost: the
#: chunk is never halved, and against drpc (which refuses the 10,000-block chunk the code asks
#: for) or Blast (10 blocks) every log scan fails. That fails safe (a failed scan is never "no
#: logs") but those endpoints never answer. Derived from the recording, not typed: every
#: "range_limit" reply that came back with HTTP 400. Strict: the fix flips these and deletes this.
_KNOWN_LOST_IN_HTTP_400 = {
    key
    for key, expected in _GETLOGS_EXPECTED.items()
    if expected == "range_limit" and _GETLOGS_RECORDS[key]["status"] == 400
}
_LOST_REASON = "the provider's reason is in a 400 body that web3 never reads"


def test_every_recorded_getlogs_reply_has_an_expectation() -> None:
    assert _GETLOGS_RECORDS
    assert set(_GETLOGS_RECORDS) == set(_GETLOGS_EXPECTED)
    assert _KNOWN_LOST_IN_HTTP_400  # the derivation found the replies it describes


class _Replay:
    """A local HTTP server answering every POST with one recorded reply (or a rule's choice of one)."""

    def __init__(self, answer: Any) -> None:
        self.requests: list[dict[str, Any]] = []
        replay = self

        class _H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                replay.requests.append(req)
                status, content_type, body = answer(req)
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type or "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *_a: Any) -> None:
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), _H)
        self.url = f"http://127.0.0.1:{self._srv.server_port}/"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


def _with_id(body: str, req: dict[str, Any]) -> str:
    """The recorded JSON-RPC body with the id of the request being answered (web3 matches on it)."""
    try:
        doc = json.loads(body)
    except ValueError:
        return body  # a plain-text reply stays byte-for-byte what the server sent
    if isinstance(doc, dict) and "id" in doc:
        doc["id"] = req.get("id")
    return json.dumps(doc)


async def _get_logs_through_ethrpc(url: str) -> Any:
    rpc = EthRpc(url, expected_chain_id=1)
    rpc.w3.provider.exception_retry_configuration = None  # one request per call, as recorded
    try:
        return await rpc.get_logs(address=recorder._QUIET_ADDRESS, from_block=1, to_block=2)
    finally:
        await rpc.close()


@pytest.mark.parametrize(
    "key",
    [
        pytest.param(
            k,
            id=f"{k[0]}-{k[1]}",
            marks=pytest.mark.xfail(k in _KNOWN_LOST_IN_HTTP_400, strict=True, reason=_LOST_REASON),
        )
        for k in sorted(_GETLOGS_EXPECTED)
    ],
)
def test_a_recorded_getlogs_reply_is_classified_as_intended(key: tuple[str, str]) -> None:
    record = _GETLOGS_RECORDS[key]
    server = _Replay(lambda req: (record["status"], record.get("content_type", ""), _with_id(record["body"], req)))
    try:
        try:
            result: Any = asyncio.run(_get_logs_through_ethrpc(server.url))
        except Exception as exc:  # the production wrapper's exception, as disposition sees it
            assert isinstance(exc, NetworkError), type(exc)
            got = "range_limit" if disposition._is_range_limit(exc) else "failure"
        else:
            assert result == []
            got = "ok"
    finally:
        server.close()
    assert got == _GETLOGS_EXPECTED[key], (record["status"], record.get("body", "")[:200])


def _drpc_like(limit: int, refusal: dict[str, Any], tip: int) -> Any:
    """Refuse a window of ``limit`` blocks or more with the recorded refusal; answer [] below it.

    The refusal text is the recorded one. The threshold is the recorder's observation (drpc refused
    exactly LOG_CHUNK_BLOCKS blocks; Blast's reply states its own limit), not a measured boundary."""

    def answer(req: dict[str, Any]) -> tuple[int, str, str]:
        method = req["method"]
        if method == "eth_chainId":
            return 200, "application/json", json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": "0x1"})
        if method == "eth_blockNumber":
            return 200, "application/json", json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": hex(tip)})
        assert method == "eth_getLogs", method
        f = req["params"][0]
        span = int(f["toBlock"], 16) - int(f["fromBlock"], 16) + 1
        if span >= limit:
            return refusal["status"], refusal.get("content_type", ""), _with_id(refusal["body"], req)
        return 200, "application/json", json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": []})

    return answer


@pytest.mark.parametrize(
    ("host", "limit"),
    [
        pytest.param(
            host, limit, marks=pytest.mark.xfail(key in _KNOWN_LOST_IN_HTTP_400, strict=True, reason=_LOST_REASON)
        )
        for host, limit in [("eth.drpc.org", disposition.LOG_CHUNK_BLOCKS), ("eth-mainnet.public.blastapi.io", 11)]
        for key in [(host, "get_logs_chunk_quiet")]
    ],
)
def test_a_range_limited_endpoint_still_completes_the_scan(host: str, limit: int) -> None:
    """Liveness under the recorded refusals: the scan halves until the endpoint accepts, and ends."""
    refusal = _GETLOGS_RECORDS[(host, "get_logs_chunk_quiet")]
    tip = 2 * disposition.LOG_CHUNK_BLOCKS
    server = _Replay(_drpc_like(limit, refusal, tip))

    async def go() -> list[Any]:
        rpc = EthRpc(server.url, expected_chain_id=1)
        rpc.w3.provider.exception_retry_configuration = None
        try:
            return await disposition._logs_from_one(rpc, recorder._QUIET_ADDRESS, [], 1, tip)
        finally:
            await rpc.close()

    try:
        assert asyncio.run(go()) == []
        spans = [
            int(r["params"][0]["toBlock"], 16) - int(r["params"][0]["fromBlock"], 16) + 1
            for r in server.requests
            if r["method"] == "eth_getLogs"
        ]
    finally:
        server.close()
    assert spans[0] == disposition.LOG_CHUNK_BLOCKS  # it asked for the full chunk first
    assert sum(s for s in spans if s < limit) == tip  # covering every block exactly once


# --------------------------------------------------------------------------- ElectrumX: JSON-RPC errors

#: What ``network/electrumx.py``'s ``_rpc_error`` is MEANT to make of each recorded ElectrumX error:
#: "network" (a fault: fail over, retry), "method_not_found", or "policy" (the node judged a
#: transaction; never retried on another server, see ``network/failover.py``). No read below is a
#: transaction verdict, so none should be "policy".
_ELECTRUMX_EXPECTED: dict[str, str] = {
    "tx_get_unknown": "network",  # code 2, "daemon error: ... No such mempool or blockchain transaction"
    "tx_get_unknown_verbose": "network",
    "tx_get_malformed": "network",  # code 1, "zz should be a transaction hash"
    "merkle_unknown_tx": "network",  # code 1, "tx ... not in block at height 1"
    "header_beyond_tip": "network",  # code 1, "height N out of range"
    "unknown_method": "method_not_found",  # code -32601
}

#: The recording shows ElectrumX answers a malformed or out-of-range READ with code 1 (its
#: BAD_REQUEST), and ``_POLICY_ERROR_CODES`` treats every code-1 error as a transaction verdict. The
#: failover layer never retries a ``PolicyRejection``, so a server that has not reached a height
#: answers a header read with "node rejected the transaction" and no other server is asked. Strict:
#: the fix flips these to passing and must delete this set.
_KNOWN_MISCLASSIFIED = {"tx_get_malformed", "merkle_unknown_tx", "header_beyond_tip"}


def _electrumx_errors() -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for r in _FIXTURE["electrumx"]:
        if "reply" not in r:
            continue
        msg = json.loads(r["reply"])
        if "error" in msg:
            out.append((_host(r["endpoint"]), r["probe"], msg["error"]))
    return out


def test_every_recorded_electrumx_error_has_an_expectation() -> None:
    probes = {probe for _, probe, _ in _electrumx_errors()}
    assert probes
    assert probes == set(_ELECTRUMX_EXPECTED)


def test_the_recorded_daemon_error_code_is_2_not_1() -> None:
    """``_POLICY_ERROR_CODES`` documents code 1 as ElectrumX's DAEMON_ERROR; the servers say 2."""
    daemon = [err for _, probe, err in _electrumx_errors() if probe == "tx_get_unknown"]
    assert daemon
    assert all(err["code"] == 2 and str(err["message"]).startswith("daemon error") for err in daemon)


def _classify(exc: NetworkError) -> str:
    if isinstance(exc, PolicyRejection):
        return "policy"
    if isinstance(exc, RpcMethodNotFound):
        return "method_not_found"
    return "network"


@pytest.mark.parametrize(
    ("host", "probe", "error"),
    [
        pytest.param(
            h,
            p,
            e,
            id=f"{h}-{p}",
            marks=pytest.mark.xfail(
                p in _KNOWN_MISCLASSIFIED, strict=True, reason="ElectrumX code 1 on a read is not a tx verdict"
            ),
        )
        for h, p, e in _electrumx_errors()
    ],
)
def test_a_recorded_electrumx_error_is_classified_as_intended(host: str, probe: str, error: dict[str, Any]) -> None:
    exc = _rpc_error(error.get("code", "unknown"), error.get("message"))
    assert isinstance(exc, NetworkError)
    assert _classify(exc) == _ELECTRUMX_EXPECTED[probe], (error.get("code"), str(error.get("message"))[:200])

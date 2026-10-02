"""The response scrub must never change an HONEST response, whatever the endpoint URL looks like.

The redacting provider removes the endpoint's credential parts from text a server wrote into a
response, because a server can echo the request path (key included) into an error. The redactor
treats every QUERY VALUE of the URL as a whole-token secret, so an earlier version — which
rewrote every string outside ``result``, keys and protocol members included — broke ordinary
URLs: ``?v=2`` turned ``"jsonrpc": "2.0"`` into ``"<redacted>.0"`` and web3 rejected every
response, ``?x=message`` renamed an error's ``message`` key so honest reverts stopped being
``ContractLogicError``, and ``?id=1`` broke string ids. ``assert_chain`` could not even start.

So: for each of those URL shapes, every call here must come out EXACTLY as it does through a plain
web3 provider — same value, or same exception type and text — while a real key echoed into an
error is still removed. Offline, against a local JSON-RPC server answering with the shapes a real
node uses (the same checks run against Anvil in ``test_eth_leg_anvil_integration.py``).
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("web3", reason="needs the eth extra: pip install 'pyrxd[eth]'")

import web3
from eth_abi import encode

from pyrxd.eth_wallet.rpc import EthRpc

_KEY = "SECRETKEY0123456789abcdefXYZ"
_Z32 = "0x" + "00" * 32
_TX = "0x" + "cd" * 32
_BLOCK = {
    "number": "0x1",
    "hash": "0x" + "11" * 32,
    "parentHash": _Z32,
    "timestamp": "0x5",
    "transactions": [],
    "gasLimit": "0x1c9c380",
    "gasUsed": "0x0",
    "baseFeePerGas": "0x3b9aca00",
    "miner": "0x" + "00" * 20,
    "extraData": "0x",
    "logsBloom": "0x" + "00" * 256,
    "difficulty": "0x0",
    "nonce": "0x0000000000000000",
    "sha3Uncles": _Z32,
    "size": "0x200",
    "stateRoot": _Z32,
    "transactionsRoot": _Z32,
    "receiptsRoot": _Z32,
    "uncles": [],
    "mixHash": _Z32,
}
_RECEIPT = {
    "transactionHash": _TX,
    "blockHash": "0x" + "11" * 32,
    "blockNumber": "0x1",
    "transactionIndex": "0x0",
    "from": "0x" + "aa" * 20,
    "to": "0x" + "bb" * 20,
    "cumulativeGasUsed": "0x5208",
    "gasUsed": "0x5208",
    "effectiveGasPrice": "0x3b9aca00",
    "contractAddress": None,
    "logs": [],
    "logsBloom": "0x" + "00" * 256,
    "status": "0x1",
    "type": "0x2",
}
_REASON_DATA = "0x08c379a0" + encode(["string"], ["nope"]).hex()
_REASON_TO = web3.Web3.to_checksum_address("0x" + "aa" * 20)
_CUSTOM_TO = web3.Web3.to_checksum_address("0x" + "bb" * 20)


def _answer(req: dict, *, string_ids: bool, path: str) -> dict:
    rid = str(req["id"]) if string_ids else req["id"]
    base = {"jsonrpc": "2.0", "id": rid}
    method = req["method"]
    if method == "eth_chainId":
        return {**base, "result": "0x7a69"}
    if method == "eth_getBlockByNumber":
        return {**base, "result": _BLOCK}
    if method == "eth_getTransactionReceipt":
        return {**base, "result": _RECEIPT}
    if method == "eth_call":
        if req["params"][0]["to"].lower() == _REASON_TO.lower():
            return {**base, "error": {"code": 3, "message": "execution reverted: nope", "data": _REASON_DATA}}
        return {**base, "error": {"code": 3, "message": "execution reverted", "data": "0x560ff900"}}
    # Anything else: an error that echoes the request path — the case the scrub exists for.
    return {**base, "error": {"code": -32000, "message": f"denied for {path}", "data": {"path": path}}}


@pytest.fixture(params=[False, True], ids=["int-ids", "string-ids"])
def server(request):
    string_ids = request.param

    class _H(BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if isinstance(req, list):
                out = [_answer(r, string_ids=string_ids, path=self.path) for r in req]
            else:
                out = _answer(req, string_ids=string_ids, path=self.path)
            body = json.dumps(out).encode()
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
        yield f"http://127.0.0.1:{srv.server_port}", string_ids
    finally:
        srv.shutdown()
        srv.server_close()


async def _batch(w3):
    async with w3.batch_requests() as batch:
        batch.add(w3.eth.get_block(1))
        batch.add(w3.eth.get_transaction_receipt(_TX))
        return await batch.async_execute()


CALLS = {
    "chain_id": lambda w3: w3.eth.chain_id,
    "block": lambda w3: w3.eth.get_block(1),
    "receipt": lambda w3: w3.eth.get_transaction_receipt(_TX),
    "revert-reason": lambda w3: w3.eth.call({"to": _REASON_TO, "data": "0x"}),
    "custom-error": lambda w3: w3.eth.call({"to": _CUSTOM_TO, "data": "0x"}),
    "batch": _batch,
}

#: URL suffixes whose query values collide with protocol members, error keys or common text.
SUFFIXES = ["/?v=2", "/?debug=0", "/?x=message", "/?x=code", "/?id=1", "/?x=jsonrpc", "/?x=result", "/?x=error"]


def _outcome(make_w3, call) -> tuple[str, str]:
    async def go():
        w3 = make_w3()
        try:
            return await call(w3)
        finally:
            await w3.provider.disconnect()

    try:
        return ("ok", repr(asyncio.run(go())))
    except Exception as exc:  # the exception IS the outcome being compared
        return (type(exc).__name__, str(exc))


@pytest.mark.parametrize("suffix", SUFFIXES)
@pytest.mark.parametrize("call", sorted(CALLS))
def test_an_honest_response_is_identical_to_a_plain_providers(server, suffix, call):
    base, string_ids = server
    url = base + suffix
    plain = _outcome(lambda: web3.AsyncWeb3(web3.AsyncWeb3.AsyncHTTPProvider(url)), CALLS[call])
    ours = _outcome(lambda: EthRpc(url, expected_chain_id=31337).w3, CALLS[call])
    assert ours == plain
    if not string_ids:
        # Non-vacuity: with ordinary ids the plain provider gets the honest answer, so "identical"
        # means identical to a working call, not to a shared failure.
        expected = {"revert-reason": "ContractLogicError", "custom-error": "ContractCustomError"}.get(call, "ok")
        assert plain[0] == expected, plain


@pytest.mark.parametrize("suffix", ["/?v=2", "/?x=message", "/?id=1"])
def test_assert_chain_works_through_those_urls(server, suffix):
    """The availability failure in one line: the ETH leg could not start."""
    base, _string_ids = server

    async def go():
        rpc = EthRpc(base + suffix, expected_chain_id=31337)
        try:
            await rpc.assert_chain()
        finally:
            await rpc.close()

    asyncio.run(go())


@pytest.mark.parametrize("query", ["?v=2", "?x=message", "?id=1"])
def test_a_real_key_echoed_into_an_error_is_still_removed(server, query):
    """And the scrub still does its job: the key in the path is gone from an echoed error, keys
    and ``code`` intact, while honest calls through the same URL are unaffected."""
    base, _string_ids = server
    url = f"{base}/v3/{_KEY}{query}"

    async def go():
        rpc = EthRpc(url, expected_chain_id=31337)
        try:
            assert await rpc.w3.eth.chain_id == 31337
            await rpc.w3.eth.get_balance("0x" + "11" * 20)
        finally:
            await rpc.close()

    with pytest.raises(Exception) as caught:
        asyncio.run(go())
    text = repr(caught.value) + str(caught.value)
    assert _KEY not in text, text
    assert "denied for" in text and "-32000" in text  # message and code survived

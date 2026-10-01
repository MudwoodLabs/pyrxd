"""``swap status`` / ``recover-preimage`` must tell the operator the truth about their funds.

Every test here drives the REAL click commands (the ``swap`` group, entered directly so a fake
ElectrumX client can be injected) and the REAL counter-leg readers, over a REAL aiohttp session
talking to a local HTTP server. Nothing between the command and the socket is mocked, because
each defect below lived in that span: a null transaction lookup read as "no claim", an empty log
set read as "locked", and an aiohttp exception carrying the operator's keyed URL into the output.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from pyrxd.gravity.watch.eth_adapters import CLAIMED_TOPIC0, REFUNDED_TOPIC0

from .test_swap_recovery import P
from .test_swap_recovery_cmds import (
    ETH_CONTRACT,
    _client,
    _eth_swap,
    _recover,
    _SpentCovenantClient,
    _status,
)
from .test_swap_recovery_cmds import swap as swap_fixture  # noqa: F401 - registered as a fixture by that name

H = hashlib.sha256(P).digest()


@pytest.fixture
def case(request):
    """The cold-recovery scenario from ``test_swap_recovery_cmds`` (keys file, covenant, fee key)."""
    return request.getfixturevalue("swap_fixture")


#: 32 bytes that do NOT hash to H — a Claimed event carrying it is not this swap's claim.
WRONG_P = bytes.fromhex("5a" * 32)
assert hashlib.sha256(WRONG_P).digest() != H

CLAIM_TX = "0x" + "cc" * 32
REFUND_TX = "0x" + "aa" * 32


# --------------------------------------------------------------------------- a real JSON-RPC server


class _Rpc(BaseHTTPRequestHandler):
    """Answers ``eth_getLogs`` / ``eth_getTransactionByHash`` from ``server.scenario``."""

    def do_POST(self) -> None:
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        scenario = self.server.scenario  # type: ignore[attr-defined]
        if req["method"] == "eth_getLogs":
            result: Any = scenario["logs"]
        elif req["method"] == "eth_getTransactionByHash":
            result = scenario["txs"].get(req["params"][0])
        else:
            result = None
        body = json.dumps({"jsonrpc": "2.0", "id": req.get("id", 1), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a: Any) -> None:
        return None


@pytest.fixture
def eth_rpc() -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Rpc)
    srv.scenario = {"logs": [], "txs": {}}  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _url(srv: ThreadingHTTPServer) -> str:
    return f"http://127.0.0.1:{srv.server_port}/"


def _log(topic0: str, data: bytes, tx_hash: str) -> dict[str, Any]:
    return {"address": ETH_CONTRACT, "topics": [topic0], "data": "0x" + data.hex(), "transactionHash": tx_hash}


def _claim_tx(p: bytes = P) -> dict[str, Any]:
    return {"hash": CLAIM_TX, "to": ETH_CONTRACT, "input": "0xbd66528a" + p.hex()}  # claim(bytes32)


def _refund_tx() -> dict[str, Any]:
    return {"hash": REFUND_TX, "to": ETH_CONTRACT, "input": "0x590e1ae3"}  # refund()


def _eth_status(case, srv, *, client=None, output_mode: str = "human"):
    return _status(
        case, "--eth-contract", ETH_CONTRACT, "--eth-rpc-url", _url(srv), client=client, output_mode=output_mode
    )


def _eth_recover(case, srv, output_mode: str = "human"):
    return _recover(case, "--eth-contract", ETH_CONTRACT, "--eth-rpc-url", _url(srv), output_mode=output_mode)


def _counter(res) -> dict[str, Any]:
    assert res.exit_code == 0, res.output
    return json.loads(res.output)["counter_leg"]


# --------------------------------------------------------------------------- 1. ETH counter-leg truth


def test_a_claimed_log_whose_transaction_lookup_is_null_still_yields_p(case, eth_rpc) -> None:
    """THE fund-loss case. The node serves the ``Claimed(p)`` log but returns null for the
    transaction. ``p`` is in the log already held, and this used to read LOCKED / "no preimage has
    been revealed — keep watching" — a taker who obeys loses both legs when the CSV refund opens."""
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {}}

    res = _eth_status(case, eth_rpc)
    assert res.exit_code == 0, res.output
    assert "Counter-leg (ETH): CLAIMED_PREIMAGE_REVEALED" in res.output
    assert "LOCKED" not in res.output.split("Counter-leg")[1]
    assert "no preimage has been revealed" not in res.output
    assert P.hex() not in res.output  # status still never prints p

    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "CLAIMED_PREIMAGE_REVEALED"
    assert counter["preimage_available"] is True
    assert counter["claim_txid"] == CLAIM_TX

    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 0, rec.output
    assert f"preimage p : {P.hex()}" in rec.output
    assert "no preimage has been revealed" not in rec.output
    doc = json.loads(_eth_recover(case, eth_rpc, output_mode="json").output)
    assert doc["preimage_hex"] == P.hex()
    assert doc["claim_txid"] == CLAIM_TX
    assert doc["source"] == "eth_claim_log_data"


def test_a_claimed_log_with_a_null_transaction_on_a_spent_covenant_is_not_refund_now(case, eth_rpc) -> None:
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {}}
    doc = json.loads(
        _eth_status(case, eth_rpc, client=_SpentCovenantClient(case["cov_sh"], tip=130), output_mode="json").output
    )
    assert doc["counter_leg"]["state"] == "CLAIMED_PREIMAGE_REVEALED"
    assert doc["situation"] != "COUNTER_LEG_LOCKED"


def test_an_empty_log_set_is_unknown_never_locked(case, eth_rpc) -> None:
    """No logs is what an unclaimed contract shows — AND what a pruned node shows for a claimed one."""
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [], "txs": {}}

    res = _eth_status(case, eth_rpc)
    assert res.exit_code == 0, res.output
    assert "Counter-leg (ETH): UNKNOWN" in res.output
    assert "Counter-leg (ETH): LOCKED" not in res.output
    assert "returned NO logs" in res.output
    assert "no preimage has been revealed" not in res.output

    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "UNKNOWN"
    assert "pruned node or a log-range limit" in counter["reason"]

    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 2, rec.output  # inconclusive — not exit 1 "not revealed yet"
    assert "inconclusive" in rec.output
    assert "no preimage has been revealed yet" not in rec.output
    assert "keep watching" not in rec.output


def test_an_empty_log_set_on_a_spent_covenant_does_not_claim_the_leg_is_locked(case, eth_rpc) -> None:
    """Pruned logs + a spent covenant used to read COUNTER_LEG_LOCKED — "your ETH is still locked"
    on no evidence at all."""
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [], "txs": {}}
    client = _SpentCovenantClient(case["cov_sh"], tip=130)
    doc = json.loads(_eth_status(case, eth_rpc, client=client, output_mode="json").output)
    assert doc["counter_leg"]["state"] == "UNKNOWN"
    assert doc["situation"] != "COUNTER_LEG_LOCKED"
    assert "still LOCKED" not in doc["chain"]["next_action"]


@pytest.mark.parametrize("with_tx", [False, True], ids=["tx-null", "tx-served"])
def test_a_claimed_event_whose_value_does_not_hash_to_H_is_refused_not_shown(case, eth_rpc, with_tx) -> None:
    """This swap's own contract can only emit Claimed for a preimage of ITS hashlock. A Claimed
    event carrying anything else is the wrong contract or a lying RPC: never the preimage, and
    never 'refunded' either."""
    _eth_swap(case)
    eth_rpc.scenario = {
        "logs": [_log(CLAIMED_TOPIC0, WRONG_P, CLAIM_TX)],
        "txs": {CLAIM_TX: _claim_tx(WRONG_P)} if with_tx else {},
    }
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "ERROR"
    assert counter["preimage_available"] is False
    assert "no value in it hashes to this swap's hashlock" in counter["reason"]
    human = _eth_status(case, eth_rpc)
    assert WRONG_P.hex() not in human.output

    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 1, rec.output
    assert "REFUSED on provenance" in rec.output
    assert "--eth-contract" in rec.output
    assert WRONG_P.hex() not in rec.output
    assert "Preimage RECOVERED" not in rec.output


def test_the_honest_claimed_path_is_unchanged(case, eth_rpc) -> None:
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {CLAIM_TX: _claim_tx()}}
    assert _counter(_eth_status(case, eth_rpc, output_mode="json"))["state"] == "CLAIMED_PREIMAGE_REVEALED"
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 0, rec.output
    assert P.hex() in rec.output


@pytest.mark.parametrize("with_tx", [True, False], ids=["tx-served", "tx-null"])
def test_the_honest_refunded_path_reads_refunded(case, eth_rpc, with_tx) -> None:
    _eth_swap(case)
    eth_rpc.scenario = {
        "logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX)],
        "txs": {REFUND_TX: _refund_tx()} if with_tx else {},
    }
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "SPENT_NO_PREIMAGE"
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 1, rec.output
    assert "no preimage has been revealed yet" in rec.output


def test_logs_that_carry_no_p_with_the_transaction_unretrievable_are_unknown(case, eth_rpc) -> None:
    """An event that is neither Claimed nor Refunded, and no transaction to read: no evidence."""
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log("0x" + "22" * 32, WRONG_P, CLAIM_TX)], "txs": {}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "UNKNOWN"
    assert _eth_recover(case, eth_rpc).exit_code == 2


def test_a_live_covenant_status_with_a_claimed_log_reads_claimed(case, eth_rpc) -> None:
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {}}
    doc = json.loads(_eth_status(case, eth_rpc, client=_client(case, confirmations=5), output_mode="json").output)
    assert doc["chain"]["covenant_state"] == "live"
    assert doc["counter_leg"]["state"] == "CLAIMED_PREIMAGE_REVEALED"

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
    """Answers ``eth_chainId`` / ``eth_getLogs`` / ``eth_getRawTransactionByHash`` / ``eth_getTransactionByHash``."""

    def do_POST(self) -> None:
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        scenario = self.server.scenario  # type: ignore[attr-defined]
        if req["method"] == "eth_chainId":
            result: Any = scenario.get("chain_id", "0x1")  # chain 1: what _signed_raw signs for
        elif req["method"] == "eth_getLogs":
            result = scenario["logs"]
        elif req["method"] == "eth_getTransactionByHash":
            result = scenario["txs"].get(req["params"][0])
        elif req["method"] == "eth_getRawTransactionByHash":
            result = scenario.get("raws", {}).get(req["params"][0])
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


def _signed_raw(data: bytes, *, to: str = ETH_CONTRACT, tx_type: int = 2) -> tuple[str, str]:
    """A REAL signed transaction ``(hash, raw_hex)``, encoded by eth_account (an independent
    encoder, so pyrxd's decoder is checked against something it did not write). Fresh key."""
    eth_account = pytest.importorskip("eth_account")
    from eth_utils import to_checksum_address

    tx: dict[str, Any] = {"nonce": 7, "gas": 60_000, "to": to_checksum_address(to), "value": 0, "data": data}
    tx["chainId"] = 1
    if tx_type == 0:
        tx["gasPrice"] = 10**9
    elif tx_type == 1:
        tx.update(type=1, gasPrice=10**9, accessList=[{"address": tx["to"], "storageKeys": ["0x" + "00" * 32]}])
    else:
        tx.update(type=2, maxFeePerGas=2 * 10**9, maxPriorityFeePerGas=10**9)
    signed = eth_account.Account.create().sign_transaction(tx)
    return "0x" + signed.hash.hex().removeprefix("0x"), "0x" + signed.raw_transaction.hex().removeprefix("0x")


def _honest_refund_scenario(tx_type: int = 2) -> dict[str, Any]:
    """A Refunded() log AND the raw signed refund() transaction that emitted it."""
    tx_hash, raw = _signed_raw(bytes.fromhex("590e1ae3"), tx_type=tx_type)
    return {"logs": [_log(REFUNDED_TOPIC0, b"", tx_hash)], "txs": {}, "raws": {tx_hash: raw}}


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


@pytest.mark.parametrize("tx_type", [0, 1, 2])
def test_a_consistent_refund_from_one_rpc_is_still_only_reported(case, eth_rpc, tx_type) -> None:
    """A Refunded() log AND the raw signed refund() transaction, whose hash pyrxd computes and whose
    ``to`` and selector it decodes from those bytes. Round 4: that is consistent, and it is still one
    server's word — nothing in it shows the transaction was broadcast or mined — so it is
    REFUND_REPORTED_UNCONFIRMED, never SPENT_NO_PREIMAGE. Legacy, EIP-2930 and EIP-1559 envelopes,
    each signed by eth_account (so the decode is also checked against an independent encoder)."""
    _eth_swap(case)
    eth_rpc.scenario = _honest_refund_scenario(tx_type)
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "REFUND_REPORTED_UNCONFIRMED", counter
    assert counter["claim_txid"] == eth_rpc.scenario["logs"][0]["transactionHash"]
    assert "consistent with the log" in counter["reason"]
    assert "second, independent ETH RPC" in counter["reason"]
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 2, rec.output  # inconclusive, never exit 1 "not revealed yet — keep watching"
    assert "cannot confirm from one server" in rec.output
    assert "no preimage has been revealed yet" not in rec.output


# --------------------------------------------------------------------------- the round-4 reviewer probe


def _unsigned_raw(fields: list[Any], tx_type: int) -> tuple[str, str]:
    """A typed transaction whose signature fields are EMPTY — no key ever signed it — and its keccak.

    Encoded by pyrlp, independent of pyrxd's decoder. What a lying RPC can serve for free."""
    rlp = pytest.importorskip("rlp")
    raw = bytes([tx_type]) + rlp.encode(fields)
    from pyrxd.cli.swap_recovery import _keccak256

    return "0x" + _keccak256(raw).hex(), "0x" + raw.hex()


def _probe_unsigned_type2() -> tuple[str, str]:
    to = bytes.fromhex(ETH_CONTRACT[2:])
    # chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList, yParity, r, s
    return _unsigned_raw([1, 0, 0, 0, 60_000, to, 0, bytes.fromhex("590e1ae3"), [], b"", b"", b""], 2)


def _probe_type4() -> tuple[str, str]:
    to = bytes.fromhex(ETH_CONTRACT[2:])
    # EIP-7702: chainId, nonce, maxPriority, maxFee, gas, to, value, data, accessList, authList, yParity, r, s
    return _unsigned_raw([1, 0, 0, 0, 60_000, to, 0, bytes.fromhex("590e1ae3"), [], [], 1, 7, 7], 4)


def _probe_wrong_chain() -> tuple[str, str]:
    """A REAL signature, on a transaction for a chain the swap is not on (chain id 5)."""
    eth_account = pytest.importorskip("eth_account")
    from eth_utils import to_checksum_address

    tx = {
        "nonce": 0,
        "gas": 60_000,
        "to": to_checksum_address(ETH_CONTRACT),
        "value": 0,
        "data": bytes.fromhex("590e1ae3"),
        "chainId": 5,
        "type": 2,
        "maxFeePerGas": 2,
        "maxPriorityFeePerGas": 1,
    }
    signed = eth_account.Account.create().sign_transaction(tx)
    return "0x" + signed.hash.hex().removeprefix("0x"), "0x" + signed.raw_transaction.hex().removeprefix("0x")


_PROBES = {
    "signed-by-any-key": lambda: _signed_raw(bytes.fromhex("590e1ae3")),
    "unsigned": _probe_unsigned_type2,
    "wrong-chain-id": _probe_wrong_chain,
    "type-4": _probe_type4,
}


@pytest.mark.parametrize("probe", sorted(_PROBES))
def test_the_reviewers_fabricated_refund_is_never_definitive(case, eth_rpc, probe) -> None:
    """The round-4 probe: a fake RPC serving a fabricated Refunded() log plus raw bytes whose keccak
    IS the log's transaction hash. Nothing pyrxd checks on those bytes can tell them from a real
    refund, so the verdict must not be definitive — on its own, and beside a taker claim of the
    covenant, where SPENT_NO_PREIMAGE used to read TAKER_CLAIMED_AND_REFUNDED: "MAKER: ... nothing
    left on chain to claim" while the maker could still claim the ETH."""
    from .test_swap_recovery_cmds import _spent_by

    _eth_swap(case)
    tx_hash, raw = _PROBES[probe]()
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", tx_hash)], "txs": {}, "raws": {tx_hash: raw}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] in ("REFUND_REPORTED_UNCONFIRMED", "ERROR"), counter
    doc = json.loads(_eth_status(case, eth_rpc, client=_spent_by(case, "claim"), output_mode="json").output)
    assert doc["situation"] not in ("TAKER_CLAIMED_AND_REFUNDED", "SETTLED", "BOTH_SPENT_OUTCOME_UNKNOWN"), doc
    assert "nothing left" not in doc["chain"]["next_action"].lower()
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code != 0 and "no preimage has been revealed yet" not in rec.output, rec.output


def test_two_refunded_logs_naming_different_transactions_are_refused(case, eth_rpc) -> None:
    """The per-swap contract settles once (``AlreadySettled``): two Refunded() logs in two
    transactions is a self-contradicting answer — ERROR, not a refund, and not 'unconfirmed'."""
    _eth_swap(case)
    first, raw1 = _signed_raw(bytes.fromhex("590e1ae3"))
    second, raw2 = _signed_raw(bytes.fromhex("590e1ae3"))
    eth_rpc.scenario = {
        "logs": [_log(REFUNDED_TOPIC0, b"", first), _log(REFUNDED_TOPIC0, b"", second)],
        "txs": {},
        "raws": {first: raw1, second: raw2},
    }
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "ERROR", counter
    assert "2 different transactions" in counter["reason"]
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 1 and "REFUSED on provenance" in rec.output, rec.output


def test_two_refunded_logs_in_the_same_transaction_are_not_a_contradiction(case, eth_rpc) -> None:
    """Honest-path pair for the refusal above: duplicate logs from ONE transaction (an RPC that
    repeats a log) are still just a refund report — unconfirmed, not refused."""
    _eth_swap(case)
    scenario = _honest_refund_scenario()
    scenario["logs"] = scenario["logs"] * 2
    eth_rpc.scenario = scenario
    assert _counter(_eth_status(case, eth_rpc, output_mode="json"))["state"] == "REFUND_REPORTED_UNCONFIRMED"


def test_a_lying_rpc_hash_field_beside_a_refund_body_is_not_a_refund(case, eth_rpc) -> None:
    """Round-3 F2, the reviewer's exact shape: ``{"hash": X, "to": C, "input": "0x590e1ae3"}`` as
    JSON beside its Refunded() log. Every field is the server's word and ``hash`` was never
    recomputed, so one lying RPC produced SPENT_NO_PREIMAGE and, with a taker claim,
    TAKER_CLAIMED_AND_REFUNDED. Without raw bytes pyrxd can hash, it stays unconfirmed."""
    from .test_swap_recovery_cmds import _spent_by

    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX)], "txs": {REFUND_TX: _refund_tx()}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "REFUND_REPORTED_UNCONFIRMED", counter
    assert "only as JSON" in counter["reason"]
    doc = json.loads(_eth_status(case, eth_rpc, client=_spent_by(case, "claim"), output_mode="json").output)
    assert doc["situation"] == "COVENANT_SPENT", doc["situation"]
    assert "nothing left" not in doc["chain"]["next_action"]
    assert _eth_recover(case, eth_rpc).exit_code == 2


def test_raw_bytes_that_hash_to_a_different_transaction_are_refused(case, eth_rpc) -> None:
    """A REAL signed refund(), served under a log naming a DIFFERENT hash: the computed hash is the
    check, so the server's pairing is not believed."""
    _eth_swap(case)
    _, raw = _signed_raw(bytes.fromhex("590e1ae3"))
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX)], "txs": {}, "raws": {REFUND_TX: raw}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "ERROR", counter
    assert "different transaction" in counter["reason"]
    assert _eth_recover(case, eth_rpc).exit_code != 0


@pytest.mark.parametrize(
    ("data", "to"),
    [
        (bytes.fromhex("bd66528a") + bytes(32), ETH_CONTRACT),  # claim(bytes32) with no p of H: not refund()
        (bytes.fromhex("590e1ae3"), "0x" + "ee" * 20),  # refund() on ANOTHER contract
    ],
)
def test_a_verified_transaction_that_is_not_a_refund_call_to_the_contract_is_unconfirmed(
    case, eth_rpc, data, to
) -> None:
    """The selector and ``to`` are read from the decoded bytes, not the JSON: a hash-valid
    transaction that is not ``refund()`` on THIS contract does not make a Refunded() log definitive."""
    _eth_swap(case)
    tx_hash, raw = _signed_raw(data, to=to)
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", tx_hash)], "txs": {}, "raws": {tx_hash: raw}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] in ("REFUND_REPORTED_UNCONFIRMED", "ERROR"), counter
    assert counter["state"] != "SPENT_NO_PREIMAGE"


def test_a_refunded_log_with_no_transaction_is_unconfirmed_not_refunded(case, eth_rpc) -> None:
    """A Refunded() log alone carries nothing to verify (a claim carries p, which hashes to H). Read
    as "refunded" it told a maker who could still claim the ETH that there was nothing to claim."""
    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX)], "txs": {}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "REFUND_REPORTED_UNCONFIRMED"
    assert "UNCONFIRMED" in counter["reason"] and "you can still claim it" in counter["reason"]
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 2, rec.output  # inconclusive, never "not revealed yet — keep watching"
    assert "inconclusive" in rec.output


def test_a_taker_claim_plus_an_unconfirmed_eth_refund_tells_the_maker_to_claim(case, eth_rpc) -> None:
    """The fund-relevant case: covenant claimed by the taker, and a (possibly lying) RPC reporting
    only a Refunded() log with no transaction. This used to read TAKER_CLAIMED_AND_REFUNDED —
    "MAKER: ... there is nothing left on chain to claim" — while the maker might still claim."""
    from .test_swap_recovery_cmds import _spent_by

    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX)], "txs": {}}
    doc = json.loads(_eth_status(case, eth_rpc, client=_spent_by(case, "claim"), output_mode="json").output)
    assert doc["counter_leg"]["state"] == "REFUND_REPORTED_UNCONFIRMED"
    assert doc["situation"] == "COVENANT_SPENT", doc["situation"]
    assert "nothing left" not in doc["chain"]["next_action"]
    assert "MAKER: check the ETH leg" in doc["chain"]["next_action"]
    assert "claim it with p" in doc["chain"]["next_action"]
    # The same RPC WITH the raw signed refund transaction is STILL one server's word (round 4).
    eth_rpc.scenario = _honest_refund_scenario()
    doc = json.loads(_eth_status(case, eth_rpc, client=_spent_by(case, "claim"), output_mode="json").output)
    assert doc["counter_leg"]["state"] == "REFUND_REPORTED_UNCONFIRMED"
    assert doc["situation"] == "COVENANT_SPENT", doc["situation"]
    assert "nothing left" not in doc["chain"]["next_action"]


def test_a_refunded_log_plus_an_unrecognised_log_is_unknown_not_a_refund(case, eth_rpc) -> None:
    """``all`` Refunded, not ``any``: one Refunded() among other events is not a refund verdict."""
    _eth_swap(case)
    other = _log("0x" + "22" * 32, b"", CLAIM_TX)
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX), other], "txs": {}}
    assert _counter(_eth_status(case, eth_rpc, output_mode="json"))["state"] == "UNKNOWN"


def test_a_returned_transaction_must_be_the_one_requested(case, eth_rpc) -> None:
    """The refund transaction's hash is checked against the log's: an RPC answering the lookup with a
    different transaction is not believed (and is not turned into a definitive refund)."""
    _eth_swap(case)
    wrong = dict(_refund_tx(), hash="0x" + "dd" * 32)
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", REFUND_TX)], "txs": {REFUND_TX: wrong}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "ERROR", counter
    assert "different transaction" in counter["reason"]


def test_a_claimed_log_from_a_foreign_contract_is_never_taken_as_p(case, eth_rpc) -> None:
    """The per-swap contract address IS the provenance: a log carrying a valid p for H but emitted by
    ANOTHER address (an RPC ignoring the address filter, or lying) is not this swap's claim."""
    _eth_swap(case)
    foreign = dict(_log(CLAIMED_TOPIC0, P, CLAIM_TX), address="0x" + "ee" * 20)
    eth_rpc.scenario = {"logs": [foreign], "txs": {}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] != "CLAIMED_PREIMAGE_REVEALED", counter
    assert counter["preimage_available"] is False
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code != 0
    assert P.hex() not in rec.output


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


# --------------------------------------------------------------------------- 2. no keyed URL in any output

FAKE_PATH_SECRET = "FAKEPATHSECRET0123"
FAKE_QUERY_SECRET = "FAKEQUERYSECRET4567"
FAKE_USER_SECRET = "FAKEUSERSECRET89AB"
SECRETS = (FAKE_PATH_SECRET, FAKE_QUERY_SECRET, FAKE_USER_SECRET)


class _Refusing(BaseHTTPRequestHandler):
    """Answers every request with ``server.status`` and records the paths it was asked for."""

    def _reply(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self.server.seen.append(self.path)  # type: ignore[attr-defined]
        self.send_response(self.server.status, "Refused")  # type: ignore[attr-defined]
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST = _reply

    def log_message(self, *a: Any) -> None:
        return None


@pytest.fixture(params=[401, 429])
def refusing(request) -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Refusing)
    srv.status = request.param  # type: ignore[attr-defined]
    srv.seen = []  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _keyed_url(srv: ThreadingHTTPServer) -> str:
    return f"http://{FAKE_USER_SECRET}:pw@127.0.0.1:{srv.server_port}/v2/{FAKE_PATH_SECRET}?apikey={FAKE_QUERY_SECRET}"


def _url_taking_commands() -> dict[str, Any]:
    """Every ``swap`` subcommand that reads from an operator-supplied URL — DERIVED from the group.

    A hand-kept list here would pass vacuously over the next command to grow a URL flag."""
    from pyrxd.cli.swap_cmds import swap_group

    return {
        name: cmd
        for name, cmd in swap_group.commands.items()
        if any(opt.endswith("-url") for p in cmd.params for opt in getattr(p, "opts", ()))
    }


def test_the_derived_command_set_is_not_vacuous() -> None:
    # The two commands this defect was found in must be among those derived; if the derivation
    # ever stops finding them, every leak test below would pass over nothing.
    assert {"status", "recover-preimage"} <= set(_url_taking_commands())


def _args_for(cmd: Any, case: dict[str, Any], url: str) -> list[str]:
    from .test_swap_recovery_cmds import _OUTPOINT

    opts = {opt for p in cmd.params for opt in getattr(p, "opts", ())}
    args = ["--swap-file", str(case["keys"])]
    if "--check-chain" in opts:
        args.append("--check-chain")
    for opt in sorted(o for o in opts if o.endswith("-url")):
        args += [opt, url]
    if "--btc-funding-outpoint" in opts:
        args += ["--btc-funding-outpoint", _OUTPOINT]
    if "--eth-contract" in opts:
        args += ["--eth-contract", ETH_CONTRACT]
    return args


@pytest.mark.parametrize("chain", ["btc", "eth"])
@pytest.mark.parametrize("output_mode", ["human", "json"])
def test_no_command_prints_the_keyed_url_on_an_http_error(case, refusing, chain, output_mode) -> None:
    """An HTTP 401/429 from a keyed endpoint used to print the whole URL — path key, query key and
    all — in ``swap status`` (human and ``--json``), and ``recover-preimage`` escaped as
    "unexpected failure (ClientResponseError)" with the URL as its cause."""
    from .test_swap_recovery_cmds import _ctx, _invoke

    if chain == "eth":
        _eth_swap(case)
    url = _keyed_url(refusing)
    commands = _url_taking_commands()
    for name, cmd in commands.items():
        refusing.seen.clear()  # type: ignore[attr-defined]
        res = _invoke([name, *_args_for(cmd, case, url)], _ctx(_client(case), output_mode=output_mode))
        rendered = res.output + (repr(res.exception) if res.exception else "")
        # The request really went to the keyed URL — otherwise "no secret in the output" is vacuous.
        assert any(FAKE_PATH_SECRET in path for path in refusing.seen), (name, refusing.seen)  # type: ignore[attr-defined]
        for secret in SECRETS:
            assert secret not in rendered, (name, secret, rendered)
        assert res.exception is None or isinstance(res.exception, SystemExit), (name, rendered)
        assert "unexpected failure" not in rendered
        assert f"HTTP {refusing.status}" in rendered, (name, rendered)  # type: ignore[attr-defined]
        assert "127.0.0.1" in rendered  # the host is named; only the parts after it are withheld
    assert commands  # non-vacuity, again, at the point of use


def test_status_json_reports_the_http_error_as_a_counter_leg_error(case, refusing) -> None:
    from .test_swap_recovery_cmds import _OUTPOINT

    res = _status(case, "--btc-funding-outpoint", _OUTPOINT, "--btc-api-url", _keyed_url(refusing), output_mode="json")
    counter = _counter(res)
    assert counter["state"] == "ERROR"
    assert counter["reason"].startswith(f"counter-leg read failed: ClientResponseError (HTTP {refusing.status})")  # type: ignore[attr-defined]
    assert not any(s in res.output for s in SECRETS)


def test_recover_preimage_is_a_clean_network_error_through_the_real_entry_point(case, refusing) -> None:
    """Through ``pyrxd`` itself, not the group: the top-level handler is where the URL escaped."""
    import os
    import subprocess
    import sys

    from .test_swap_recovery_cmds import _OUTPOINT

    url = _keyed_url(refusing)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pyrxd.cli",
            "swap",
            "recover-preimage",
            "--swap-file",
            str(case["keys"]),
            "--btc-funding-outpoint",
            _OUTPOINT,
            "--btc-api-url",
            url,
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        timeout=60,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 2, out  # NetworkBoundaryError, not exit 4 "unexpected failure"
    assert "a chain read failed" in out
    assert "unexpected failure" not in out
    for secret in SECRETS:
        assert secret not in out, out
    assert any(FAKE_PATH_SECRET in p for p in refusing.seen)  # type: ignore[attr-defined]


def test_pyrxd_messages_that_quote_a_url_are_scrubbed_but_kept() -> None:
    """Our own exception text is shown (it carries the useful part) with the URL's secrets removed;
    a library exception's text is dropped whole."""
    from pyrxd.cli.swap_recovery import describe_network_error
    from pyrxd.security.errors import NetworkError

    url = f"https://rpc.example/v2/{FAKE_PATH_SECRET}?apikey={FAKE_QUERY_SECRET}"
    ours = describe_network_error(NetworkError(f"TLS pin mismatch for {url}: rotate the pin"), url)
    assert ours.startswith(
        "NetworkError from rpc.example: TLS pin mismatch for https://rpc.example/v2/<redacted>?apikey=<redacted>"
    )
    assert "rotate the pin" in ours
    assert FAKE_PATH_SECRET not in ours and FAKE_QUERY_SECRET not in ours
    # Pieces of the URL quoted separately are scrubbed too (an RPC body echoing the key).
    echoed = describe_network_error(NetworkError(f"invalid project id {FAKE_PATH_SECRET}"), url)
    assert FAKE_PATH_SECRET not in echoed
    theirs = describe_network_error(RuntimeError(f"boom {url}"), url)
    assert theirs == "RuntimeError from rpc.example"


# --------------------------------------------------------------------------- 3. who spent the covenant


def _btc_counter(monkeypatch, raw: bytes) -> None:
    from pyrxd.btc_wallet.taproot import btc_txid_from_raw

    from .test_swap_recovery_cmds import _FakeEsplora, _serve

    spender = btc_txid_from_raw(raw)
    _serve(monkeypatch, _FakeEsplora({"spent": True, "txid": spender}, tx_hex={spender: raw.hex()}))


def _all_modes(case, client_factory) -> dict[str, Any]:
    from .test_swap_recovery_cmds import _checked_status

    out = {}
    for mode in ("human", "json", "quiet"):
        res = _checked_status(case, client=client_factory(), output_mode=mode)
        assert res.exit_code == 0, res.output
        out[mode] = res.output
    return out


def test_a_maker_refund_plus_the_makers_counter_leg_claim_is_not_settled(case, monkeypatch) -> None:
    """The maker CSV-refunded the RXD covenant AND claimed the taker's BTC with p: the taker lost
    both legs. This used to read SETTLED, "nothing left to claim or refund", directly above the
    counter-leg row that said the BTC had been claimed."""
    from .test_swap_recovery import _claim_tx
    from .test_swap_recovery_cmds import _spent_by

    _btc_counter(monkeypatch, _claim_tx())
    out = _all_modes(case, lambda: _spent_by(case, "refund"))
    assert "situation  : MAKER_REFUNDED_AND_CLAIMED" in out["human"]
    assert "spent by   : MAKER_REFUND" in out["human"]
    assert "The MAKER took BOTH legs" in out["human"]
    assert "SETTLED" not in out["human"]
    doc = json.loads(out["json"])
    assert doc["situation"] == "MAKER_REFUNDED_AND_CLAIMED"
    assert doc["chain"]["covenant_spend"]["kind"] == "MAKER_REFUND"
    assert doc["counter_leg"]["state"] == "CLAIMED_PREIMAGE_REVEALED"
    assert out["quiet"].strip() == "MAKER_REFUNDED_AND_CLAIMED"
    assert P.hex() not in out["human"] + out["json"]


def test_the_eth_maker_refund_plus_claim_is_not_settled_either(case, eth_rpc) -> None:
    from .test_swap_recovery_cmds import _spent_by

    _eth_swap(case)
    eth_rpc.scenario = {"logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {CLAIM_TX: _claim_tx()}}
    doc = json.loads(_eth_status(case, eth_rpc, client=_spent_by(case, "refund"), output_mode="json").output)
    assert doc["situation"] == "MAKER_REFUNDED_AND_CLAIMED"


def test_a_taker_claim_plus_the_takers_counter_leg_refund_is_named_too(case, monkeypatch) -> None:
    from .test_swap_recovery import _refund_tx
    from .test_swap_recovery_cmds import _spent_by

    _btc_counter(monkeypatch, _refund_tx())
    out = _all_modes(case, lambda: _spent_by(case, "claim"))
    assert json.loads(out["json"])["situation"] == "TAKER_CLAIMED_AND_REFUNDED"
    assert out["quiet"].strip() == "TAKER_CLAIMED_AND_REFUNDED"
    assert "The TAKER took BOTH legs" in out["human"]


def test_an_unreadable_covenant_spend_is_unknown_never_settled(case, monkeypatch) -> None:
    """Both legs spent but the covenant's spending transaction cannot be fetched: who received the
    asset is unknown, so the screen must not say SETTLED."""
    from .test_swap_recovery import _claim_tx
    from .test_swap_recovery_cmds import _spent_by

    _btc_counter(monkeypatch, _claim_tx())
    out = _all_modes(case, lambda: _spent_by(case, "claim", serve_spend=False))
    doc = json.loads(out["json"])
    assert doc["situation"] == "BOTH_SPENT_OUTCOME_UNKNOWN"
    assert doc["chain"]["covenant_spend"]["kind"] == "UNKNOWN"
    assert "could not be read" in doc["chain"]["covenant_spend"]["reason"]
    assert out["quiet"].strip() == "BOTH_SPENT_OUTCOME_UNKNOWN"
    assert "SETTLED" not in out["human"]
    assert "NOT a confirmed settlement" in out["human"]


def test_a_server_serving_the_wrong_bytes_for_the_spend_is_not_believed(case, monkeypatch) -> None:
    from .test_swap_recovery import _claim_tx
    from .test_swap_recovery_cmds import _funding_and_spend, _SpentByClient

    funding, spend = _funding_and_spend(case, "refund")
    funding_again, claim = _funding_and_spend(case, "claim")
    assert funding_again.txid() == funding.txid()  # the claim spends the SAME covenant output
    client = _SpentByClient(case, funding, spend)
    # The history names the REFUND; the server serves a CLAIM's bytes under that txid. Believed,
    # this would read TAKER_CLAIM — and with the BTC claimed, SETTLED.
    client._txs[spend.txid()] = claim.serialize()
    _btc_counter(monkeypatch, _claim_tx())
    from .test_swap_recovery_cmds import _checked_status

    doc = json.loads(_checked_status(case, client=client, output_mode="json").output)
    assert doc["chain"]["covenant_spend"]["kind"] == "UNKNOWN"
    assert "do not parse to that txid" in doc["chain"]["covenant_spend"]["reason"]
    assert doc["situation"] == "BOTH_SPENT_OUTCOME_UNKNOWN"


def test_a_maker_refund_with_the_counter_leg_locked_tells_the_taker_to_refund(case, monkeypatch) -> None:
    from .test_swap_recovery_cmds import _FakeEsplora, _serve, _spent_by

    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    out = _all_modes(case, lambda: _spent_by(case, "refund"))
    assert json.loads(out["json"])["situation"] == "COUNTER_LEG_LOCKED"
    assert "The maker CSV-REFUNDED the RXD covenant" in out["human"]
    assert "TAKER: refund your BTC now" in out["human"]


def test_a_taker_claim_with_the_counter_leg_locked_tells_the_maker_to_claim(case, monkeypatch) -> None:
    from .test_swap_recovery_cmds import _FakeEsplora, _serve, _spent_by

    _serve(monkeypatch, _FakeEsplora({"spent": False}))
    out = _all_modes(case, lambda: _spent_by(case, "claim"))
    assert json.loads(out["json"])["situation"] == "COUNTER_LEG_LOCKED"
    assert "MAKER: claim your BTC with p NOW" in out["human"]
    assert "TAKER: refund" not in out["human"]


@pytest.mark.parametrize(
    ("script_hex", "expected"),
    [
        ("51", "refund"),  # what build_htlc_refund_tx pushes
        ("0101", "refund"),  # a non-minimal 1: the covenant's OP_NUMEQUAL takes it the same way
        ("20" + "11" * 32 + "00", "claim"),  # what build_htlc_claim_tx pushes: <p> OP_0
        ("20" + "5a" * 32 + "00", None),  # selector 0 without a preimage of H: no valid claim
        ("52", None),  # neither branch
        ("76", None),  # not push-only
    ],
)
def test_the_branch_is_read_from_the_selector(script_hex, expected) -> None:
    from pyrxd.cli.swap_recovery import classify_covenant_spend_input

    assert classify_covenant_spend_input(bytes.fromhex(script_hex), hashlock=H) == expected


# --------------------------------------------------------------------------- 4/5. depth that was not measured


def _height_client(case, height: int, *, tip: int = 130):
    from pyrxd.network.electrumx import UtxoRecord

    from .test_swap_recovery_cmds import _NoBroadcastClient

    return _NoBroadcastClient(
        {case["cov_sh"]: [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=100_000, height=height)]}, tip=tip
    )


@pytest.mark.parametrize("height", [-1, 0], ids=["mempool-unconfirmed-parent", "mempool"])
def test_a_non_positive_funding_height_is_unconfirmed_not_a_depth(case, height) -> None:
    """ElectrumX reports 0 / -1 for an unconfirmed UTXO. Truthiness took -1 as a funding HEIGHT,
    so the depth came out as tip + 2 and the covenant read REFUND_OPEN — 'claim IMMEDIATELY or the
    maker reclaims it' — for a covenant not yet in any block."""
    res = _status(case, client=_height_client(case, height), output_mode="json")
    assert res.exit_code == 0, res.output
    chain = json.loads(res.output)["chain"]
    assert chain["funding_height"] is None
    assert chain["depth"] is None
    assert chain["situation"] == "LOCKED"
    assert "heights unavailable" in chain["next_action"]
    assert "blocks_to_refund" not in chain
    assert "refund_opens_height" not in chain

    human = _status(case, client=_height_client(case, height))
    assert human.exit_code == 0, human.output
    assert "REFUND_OPEN" not in human.output
    assert "funded@None depth=None" in human.output


def test_a_positive_funding_height_still_measures_a_depth(case) -> None:
    """The honest path beside the refusals above: a mined covenant still gets its depth and count."""
    chain = json.loads(_status(case, client=_height_client(case, 100, tip=104), output_mode="json").output)["chain"]
    assert chain["funding_height"] == 100
    assert chain["depth"] == 5
    assert chain["blocks_to_refund"] == 15
    assert chain["refund_opens_height"] == 120


def test_a_funding_height_above_the_tip_is_not_turned_into_a_depth(case) -> None:
    """Two reads of a moving chain (a lagging tip): funding 140 against tip 130 is no depth at all."""
    chain = json.loads(_status(case, client=_height_client(case, 140, tip=130), output_mode="json").output)["chain"]
    assert chain["depth"] is None
    assert "blocks_to_refund" not in chain
    assert chain["situation"] == "LOCKED"


def test_blocks_to_refund_is_omitted_rather_than_raising_when_depth_is_none(case, monkeypatch) -> None:
    """Item 4's guard on its own: a live covenant with a funding height but no measured depth."""
    from pyrxd.cli import swap_cmds

    async def _read(ctx, spk_hex, hashlock_hex=None):
        return {"covenant_state": "live", "funding_height": 100, "depth": None, "value_photons": 1, "now_height": 130}

    monkeypatch.setattr(swap_cmds, "_read_covenant", _read)
    res = _status(case, output_mode="json")
    assert res.exit_code == 0, res.output
    assert "blocks_to_refund" not in json.loads(res.output)["chain"]


# --------------------------------------------------------------------------- the RPC's chain (round 4)


def _eth_swap_on_chain(case, chain_id: Any) -> None:
    _eth_swap(case)
    doc = json.loads(case["keys"].read_text())
    doc["eth_chain_id"] = chain_id
    case["keys"].write_text(json.dumps(doc))


def test_an_rpc_on_another_chain_is_an_error_for_the_whole_read(case, eth_rpc) -> None:
    """The swap is on Sepolia; the RPC answers for chain 1. Even a Claimed log carrying a valid p
    is not read: nothing that RPC says is about this swap's contract."""
    _eth_swap_on_chain(case, 11155111)
    eth_rpc.scenario = {"chain_id": "0x1", "logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "ERROR", counter
    assert "is on chain 1, the swap is on chain 11155111" in counter["reason"]
    rec = _eth_recover(case, eth_rpc)
    assert rec.exit_code == 1, rec.output
    assert "not on this swap's chain" in rec.output
    assert P.hex() not in rec.output


def test_an_rpc_on_the_swaps_chain_reads_as_before(case, eth_rpc) -> None:
    """Honest path: matching chain ids change nothing, and the check is named in the provenance."""
    _eth_swap_on_chain(case, 11155111)
    eth_rpc.scenario = {"chain_id": "0xaa36a7", "logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "CLAIMED_PREIMAGE_REVEALED", counter
    assert "NOT checked" not in counter["reason"]
    doc = json.loads(_eth_recover(case, eth_rpc, output_mode="json").output)
    assert doc["preimage_hex"] == P.hex()
    assert "the RPC reports chain id 11155111, the chain this swap's recovery file records" in doc["provenance_checks"]


def test_a_file_with_no_chain_id_reads_on_and_says_the_chain_was_not_checked(case, eth_rpc) -> None:
    """Not refused (older files record no chain id), and not silent either."""
    _eth_swap(case)
    eth_rpc.scenario = {"chain_id": "0x5", "logs": [_log(CLAIMED_TOPIC0, P, CLAIM_TX)], "txs": {}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "CLAIMED_PREIMAGE_REVEALED", counter
    assert "records no eth_chain_id, so the RPC's chain was NOT checked" in counter["reason"]
    doc = json.loads(_eth_recover(case, eth_rpc, output_mode="json").output)
    assert any("NOT checked" in c for c in doc["provenance_checks"])


def test_a_transaction_signed_for_another_chain_than_the_rpc_is_refused(case, eth_rpc) -> None:
    """The RPC says chain 1 and serves a refund() signed for chain 5: its answer contradicts itself."""
    _eth_swap(case)
    tx_hash, raw = _probe_wrong_chain()
    eth_rpc.scenario = {"logs": [_log(REFUNDED_TOPIC0, b"", tx_hash)], "txs": {}, "raws": {tx_hash: raw}}
    counter = _counter(_eth_status(case, eth_rpc, output_mode="json"))
    assert counter["state"] == "ERROR", counter
    assert "signed for chain 5, but the RPC reports chain 1" in counter["reason"]


@pytest.mark.parametrize("bad", ["11155111", True, 0, -1, 1.5])
def test_a_malformed_eth_chain_id_in_the_file_is_refused_not_ignored(case, eth_rpc, bad) -> None:
    """Read as "none recorded", a malformed value would switch the chain check off."""
    _eth_swap_on_chain(case, bad)
    res = _eth_status(case, eth_rpc)
    assert res.exit_code != 0
    assert "eth_chain_id must be a positive integer" in res.output


class _EchoOrRedirect(BaseHTTPRequestHandler):
    """``server.mode`` ``"echo"``: a 401 whose reason and body repeat the request path (key
    included). ``"redirect"``: a 307 to the same keyed path with ``&hop=1`` appended, which then
    answers 401 — so the redirect history in the exception carries the key too."""

    def _reply(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        self.server.seen.append(self.path)  # type: ignore[attr-defined]
        if self.server.mode == "redirect" and "hop=1" not in self.path:  # type: ignore[attr-defined]
            self.send_response(307, "Moved")
            self.send_header("Location", self.path + "&hop=1")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"error": f"unauthorized for {self.path}"}).encode()
        self.send_response(401, f"Unauthorized {self.path}")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply

    def log_message(self, *a: Any) -> None:
        return None


@pytest.mark.parametrize("mode", ["echo", "redirect"])
def test_debug_traceback_carries_no_keyed_url(case, mode) -> None:
    """``--debug`` prints the wrapped library exception's traceback (``CliError.show`` ->
    ``__cause__``). That text is aiohttp's, and it quotes the request URL — and here the server
    echoes the key back or redirects to it — so the traceback must go through the redactor too.
    Through the real entry point, so the flag, the command and the printer are all the shipped ones."""
    import os
    import subprocess
    import sys

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _EchoOrRedirect)
    srv.mode = mode  # type: ignore[attr-defined]
    srv.seen = []  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        _eth_swap(case)
        url = _keyed_url(srv)
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "pyrxd.cli",
                "--debug",
                "swap",
                "recover-preimage",
                "--swap-file",
                str(case["keys"]),
                "--eth-contract",
                ETH_CONTRACT,
                "--eth-rpc-url",
                url,
            ],
            capture_output=True,
            text=True,
            env=os.environ.copy(),
            timeout=60,
        )
    finally:
        srv.shutdown()
        srv.server_close()
    out = proc.stdout + proc.stderr
    # Non-vacuity: the keyed URL was really requested, and a traceback really was printed.
    assert any(FAKE_PATH_SECRET in p for p in srv.seen), srv.seen  # type: ignore[attr-defined]
    assert "Traceback (most recent call last)" in out, out
    if mode == "redirect":
        assert any("hop=1" in p for p in srv.seen), srv.seen  # type: ignore[attr-defined]
    for secret in SECRETS:
        assert secret not in out, (secret, out)
    assert "127.0.0.1" in out  # the host is still named


def test_debug_traceback_carries_no_keyed_url_that_lives_only_in_the_config_file(tmp_path) -> None:
    """The key is not on the command line or in the environment — only in ``--config``. ``cli()``
    registers the config's URLs with the redactor as soon as it loads the file, so a library
    exception that quotes the URL (here websockets' ``InvalidURI`` for a user-without-password
    URL) is still scrubbed from the ``--debug`` traceback."""
    import os
    import subprocess
    import sys

    keyed = f"wss://{FAKE_PATH_SECRET}@127.0.0.1:1/"
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'network = "mainnet"\nelectrumx_servers = ["{keyed}"]\n')
    argv = [
        sys.executable,
        "-m",
        "pyrxd.cli",
        "--debug",
        "--config",
        str(cfg),
        "glyph",
        "inspect",
        "--fetch",
        "ab" * 32,
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYRXD_")}
    assert not any(FAKE_PATH_SECRET in a for a in argv)  # the config file is the only place it is
    proc = subprocess.run(argv, capture_output=True, text=True, env=env, timeout=90)
    out = proc.stdout + proc.stderr
    # Non-vacuity: a traceback was printed, and it is the exception that quotes the URI.
    assert "Traceback (most recent call last)" in out, out
    assert "InvalidURI" in out, out
    assert FAKE_PATH_SECRET not in out, out

"""``BitcoinCoreRpcSource.get_outpoint_spender`` (#850 PR 1c): who spent a BTC outpoint, as one node
sees it, and a fail-closed answer whenever that cannot be told.

The node is a scripted stand-in for Bitcoin Core's JSON-RPC (``gettxout``,
``gettxspendingprevout``, ``getrawtransaction``, ``getblockcount``, ``getblockhash``, ``getblock``),
so every path through the method runs against the RPC shapes Core returns. The transactions are
real serialisations, and their txids are derived from the bytes.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from pyrxd.btc_wallet.taproot import BtcOutpoint, btc_input_outpoints_from_raw, btc_txid_from_raw
from pyrxd.network.bitcoin import BitcoinCoreRpcSource
from pyrxd.security.errors import NetworkError

pytestmark = pytest.mark.asyncio

FUNDING = BtcOutpoint(txid=os.urandom(32).hex(), vout=1)
OTHER = BtcOutpoint(txid=os.urandom(32).hex(), vout=0)


def _varint(n: int) -> bytes:
    return bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little")


def _spend(outpoint: BtcOutpoint, marker: bytes, *, value: int = 1000) -> bytes:
    """A minimal segwit transaction spending *outpoint*. *marker* is its witness, which does not
    change the txid; *value* (its one output) does."""
    body = (2).to_bytes(4, "little") + b"\x00\x01" + _varint(1)
    body += outpoint.prevout_bytes() + b"\x00" + (0xFFFFFFFD).to_bytes(4, "little")
    body += _varint(1) + value.to_bytes(8, "little") + _varint(1) + b"\x51"
    body += _varint(1) + _varint(len(marker)) + marker
    return body + (0).to_bytes(4, "little")


def _entry(raw: bytes, *, txid: str | None = None) -> dict[str, Any]:
    """A transaction as ``getrawtransaction … true`` and ``getblock … 2`` describe it."""
    tx_id = txid or btc_txid_from_raw(raw)
    vin = []
    for prevout in btc_input_outpoints_from_raw(raw):
        vin.append({"txid": prevout[:32][::-1].hex(), "vout": int.from_bytes(prevout[32:], "little")})
    return {"txid": tx_id, "hex": raw.hex(), "vin": vin}


class FakeCore:
    """Bitcoin Core as ``get_outpoint_spender`` reads it."""

    def __init__(self) -> None:
        self.unspent = False
        self.mempool_spender: str | None = None
        self.has_spending_rpc = True
        self.funding_height: int | None = 100
        self.tip = 103
        self.blocks: dict[int, list[dict[str, Any]]] = {}
        self.txs: dict[str, dict[str, Any]] = {}
        self.calls: list[str] = []

    async def rpc(self, method: str, params: list) -> Any:
        self.calls.append(method)
        if method == "gettxout":
            return {"value": 0.001, "confirmations": 3} if self.unspent else None
        if method == "gettxspendingprevout":
            if not self.has_spending_rpc:
                raise NetworkError("Bitcoin Core RPC error: Method not found")
            entry: dict[str, Any] = {"txid": params[0][0]["txid"], "vout": params[0][0]["vout"]}
            if self.mempool_spender is not None:
                entry["spendingtxid"] = self.mempool_spender
            return [entry]
        if method == "getrawtransaction":
            if params[0] == FUNDING.txid:
                if self.funding_height is None:
                    return {"txid": FUNDING.txid, "hex": "00"}  # in the mempool: no blockhash
                # Core reports the block hash, not the height (no `blockheight` key).
                return {"txid": FUNDING.txid, "blockhash": f"{self.funding_height:064x}", "confirmations": 4}
            if params[0] in self.txs:
                return self.txs[params[0]]
            raise NetworkError("Bitcoin Core RPC error: No such mempool or blockchain transaction")
        if method == "getblockcount":
            return self.tip
        if method == "getblockhash":
            return f"{params[0]:064x}"
        if method == "getblockheader":
            return {"hash": params[0], "height": int(params[0], 16)}
        if method == "getblock":
            return {"tx": self.blocks.get(int(params[0], 16), [])}
        raise AssertionError(f"unexpected RPC {method}")


def _source(node: FakeCore) -> BitcoinCoreRpcSource:
    source = BitcoinCoreRpcSource("http://node.invalid:18443/", "user", "pass")
    source._rpc = node.rpc  # type: ignore[method-assign]
    return source


async def _spender(node: FakeCore, **kw: Any):
    return await _source(node).get_outpoint_spender(FUNDING.txid, FUNDING.vout, **kw)


async def test_an_unspent_outpoint_has_no_spender() -> None:
    """Honest path: the node holds it unspent, so there is nothing to look for."""
    node = FakeCore()
    node.unspent = True
    assert await _spender(node) is None
    assert node.calls == ["gettxout"]


async def test_a_spender_in_the_mempool_is_found_and_bound_to_its_txid() -> None:
    node = FakeCore()
    raw = _spend(FUNDING, b"mempool")
    node.mempool_spender = btc_txid_from_raw(raw)
    node.txs[node.mempool_spender] = _entry(raw)
    assert bytes(await _spender(node)) == raw
    assert "getblock" not in node.calls


async def test_a_confirmed_spender_is_found_by_reading_the_blocks_since_funding() -> None:
    node = FakeCore()
    raw = _spend(FUNDING, b"mined")
    node.blocks[100] = [_entry(_spend(OTHER, b"unrelated"))]
    node.blocks[102] = [_entry(_spend(OTHER, b"other")), _entry(raw)]
    assert bytes(await _spender(node)) == raw


async def test_a_node_without_gettxspendingprevout_still_finds_a_mined_spender() -> None:
    node = FakeCore()
    node.has_spending_rpc = False
    raw = _spend(FUNDING, b"mined")
    node.blocks[101] = [_entry(raw)]
    assert bytes(await _spender(node)) == raw


async def test_spent_with_no_spender_found_fails_closed() -> None:
    """Not unspent, and nothing spends it in the mempool or the blocks: refuse, never None."""
    node = FakeCore()
    node.blocks[101] = [_entry(_spend(OTHER, b"unrelated"))]
    with pytest.raises(NetworkError, match="no transaction spending it was found"):
        await _spender(node)


async def test_an_unknown_or_unconfirmed_funding_tx_fails_closed() -> None:
    node = FakeCore()
    node.funding_height = None
    with pytest.raises(NetworkError, match="unconfirmed"):
        await _spender(node)


async def test_a_span_longer_than_the_scan_bound_fails_closed() -> None:
    node = FakeCore()
    node.tip = 100 + 50
    with pytest.raises(NetworkError, match="more than this search reads"):
        await _spender(node, max_scan_blocks=49)
    assert "getblock" not in node.calls


async def test_a_mempool_spender_whose_bytes_are_another_tx_fails_closed() -> None:
    """The node names one txid and serves a different transaction's bytes."""
    node = FakeCore()
    claimed = btc_txid_from_raw(_spend(FUNDING, b"same", value=1000))
    node.mempool_spender = claimed
    node.txs[claimed] = _entry(_spend(FUNDING, b"same", value=999), txid=claimed)
    with pytest.raises(NetworkError, match="do not match the requested txid"):
        await _spender(node)


async def test_a_reported_spender_that_does_not_spend_the_outpoint_fails_closed() -> None:
    node = FakeCore()
    raw = _spend(OTHER, b"elsewhere")
    node.mempool_spender = btc_txid_from_raw(raw)
    node.txs[node.mempool_spender] = _entry(raw)
    with pytest.raises(NetworkError, match="does not spend the outpoint"):
        await _spender(node)


async def test_a_block_entry_whose_vin_claims_the_outpoint_but_whose_bytes_do_not_fails_closed() -> None:
    """``vin`` is the node's description; the bytes decide."""
    node = FakeCore()
    raw = _spend(OTHER, b"elsewhere")
    entry = _entry(raw)
    entry["vin"] = [{"txid": FUNDING.txid, "vout": FUNDING.vout}]
    node.blocks[101] = [entry]
    with pytest.raises(NetworkError, match="does not spend the outpoint"):
        await _spender(node)

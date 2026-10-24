"""The reads the BTC disposition reader asks of each source (#850 PR 9a): who spends an outpoint, and
which block holds a transaction. Mocked transports, no network; every refusal has its honest twin."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.network.bitcoin import (
    BitcoinCoreFundingReader,
    BitcoinCoreRpcSource,
    MempoolSpaceFundingReader,
    MultiSourceBtcFundingReader,
)
from pyrxd.security.errors import NetworkError
from tests._fake_btc_chain import FakeBtcChain, FakeBtcSource


def _hex_session(body: bytes) -> MagicMock:
    resp = MagicMock()
    resp.status = 200
    resp.content_type = "text/plain"
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    s = MagicMock()
    s.get = MagicMock(return_value=resp)
    return s


def _esplora(chain: FakeBtcChain, *, outspend: dict, served: bytes | None = None) -> MempoolSpaceFundingReader:
    r = MempoolSpaceFundingReader()
    r._http.outspend = AsyncMock(return_value=outspend)
    if served is not None:
        r._http.session = AsyncMock(return_value=_hex_session(served.hex().encode()))
    return r


# --------------------------------------------------------------------------- Esplora


async def test_esplora_unspent_is_none():
    chain = FakeBtcChain()
    assert await _esplora(chain, outspend={"spent": False}).outpoint_spender(chain.funding_txid, 0) is None


async def test_esplora_returns_the_spender_bound_to_its_txid_and_the_outpoint():
    chain = FakeBtcChain()
    refund = chain.refund_tx()
    r = _esplora(chain, outspend={"spent": True, "txid": t.btc_txid_from_raw(refund)}, served=refund)
    assert await r.outpoint_spender(chain.funding_txid, 0) == refund


async def test_esplora_refuses_bytes_of_another_transaction_than_it_named():
    chain = FakeBtcChain()
    refund, claim = chain.refund_tx(), chain.claim_tx()
    r = _esplora(chain, outspend={"spent": True, "txid": t.btc_txid_from_raw(refund)}, served=claim)
    with pytest.raises(NetworkError):
        await r.outpoint_spender(chain.funding_txid, 0)


async def test_esplora_refuses_a_spender_that_does_not_spend_the_outpoint():
    chain, other = FakeBtcChain(), FakeBtcChain()
    refund = other.refund_tx()
    r = _esplora(chain, outspend={"spent": True, "txid": t.btc_txid_from_raw(refund)}, served=refund)
    with pytest.raises(NetworkError, match="does not spend"):
        await r.outpoint_spender(chain.funding_txid, 0)


@pytest.mark.parametrize("txid", [None, "zz" * 32, "ab" * 31, "ab/" + "c" * 61])
async def test_esplora_spent_without_a_usable_txid_raises(txid):
    chain = FakeBtcChain()
    with pytest.raises(NetworkError, match="names no usable txid"):
        await _esplora(chain, outspend={"spent": True, "txid": txid}).outpoint_spender(chain.funding_txid, 0)


async def test_esplora_tx_block():
    r = MempoolSpaceFundingReader()
    r._http.tx_status = AsyncMock(return_value={"confirmed": False})
    assert await r.tx_block("ab" * 32) is None
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 7, "block_hash": "CD" * 32})
    assert await r.tx_block("ab" * 32) == (7, "cd" * 32)
    r._http.tx_status = AsyncMock(return_value={"confirmed": True, "block_height": 7, "block_hash": "nope"})
    with pytest.raises(NetworkError, match="block hash"):
        await r.tx_block("ab" * 32)


# --------------------------------------------------------------------------- Bitcoin Core


async def test_core_reader_delegates_the_spender_read_to_its_source():
    source = BitcoinCoreRpcSource("http://127.0.0.1:18443/", "u", "p")
    source.get_outpoint_spender = AsyncMock(return_value=b"\x01\x02")  # type: ignore[method-assign]
    reader = BitcoinCoreFundingReader(source._rpc)
    assert await reader.outpoint_spender("ab" * 32, 1) == b"\x01\x02"
    source.get_outpoint_spender.assert_awaited_once()
    assert source.get_outpoint_spender.await_args.args[1] == 1


async def test_core_reader_on_a_bare_rpc_cannot_read_a_spender():
    async def rpc(method, params):  # a plain callable: no source behind it
        raise AssertionError("not reached")

    with pytest.raises(NetworkError, match="cannot read"):
        await BitcoinCoreFundingReader(rpc).outpoint_spender("ab" * 32, 0)


async def test_core_reader_tx_block():
    txid, block = "ab" * 32, "cd" * 32
    answers = {
        "getrawtransaction": {"txid": txid, "blockhash": block},
        "getblockheader": {"hash": block, "height": 12},
    }

    async def rpc(method, params):
        return answers[method]

    reader = BitcoinCoreFundingReader(rpc)
    assert await reader.tx_block(txid) == (12, block)
    answers["getblockheader"] = {"hash": "ee" * 32, "height": 12}
    with pytest.raises(NetworkError, match="another block"):
        await reader.tx_block(txid)
    answers["getrawtransaction"] = {"txid": txid}
    assert await reader.tx_block(txid) is None  # in the mempool


# --------------------------------------------------------------------------- the quorum reader's panel


def test_the_quorum_reader_exposes_one_reader_per_source_and_its_quorum():
    chain = FakeBtcChain()
    sources = [FakeBtcSource(chain) for _ in range(3)]
    readers, quorum = MultiSourceBtcFundingReader(sources, quorum=2).panel()
    assert readers == tuple(sources) and quorum == 2

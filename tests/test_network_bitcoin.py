"""Unit tests for pyrxd.network.bitcoin — all network calls mocked.

Targets (from 2026-04-24 coverage report):
  network/bitcoin.py: 36% → target ≥ 70%

Strategy: mock aiohttp.ClientSession at the session level so each concrete
source uses a controlled fake HTTP layer.  We test each source method's:
  - happy path
  - HTTP error path (non-200)
  - Invalid/malformed response path
  - NetworkError propagation
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.network.bitcoin import (
    BlockstreamSource,
    MempoolSpaceSource,
    MultiSourceBtcDataSource,
    MultiSourceBtcFundingReader,
    _check_response_size,
    _get_hex_bytes,
    _get_json,
)
from pyrxd.security.errors import InsufficientConfirmationsError, NetworkError, ValidationError
from pyrxd.security.types import BlockHeight, Hex32, RawTx, Txid

# ---------------------------------------------------------------------------
# Helpers to build fake aiohttp response objects
# ---------------------------------------------------------------------------


def _fake_resp(status: int, body: bytes, content_type: str = "application/json") -> MagicMock:
    """Return a MagicMock mimicking an aiohttp.ClientResponse."""
    resp = MagicMock()
    resp.status = status
    resp.content_type = content_type
    resp.read = AsyncMock(return_value=body)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    return resp


def _json_resp(data: Any, status: int = 200) -> MagicMock:
    return _fake_resp(status, json.dumps(data).encode(), "application/json")


def _text_resp(text: str, status: int = 200) -> MagicMock:
    return _fake_resp(status, text.encode(), "text/plain")


def _make_session(*responses) -> MagicMock:
    """Create a fake session whose .get() returns responses in order."""
    session = MagicMock()
    session.get = MagicMock(side_effect=list(responses))
    return session


# ---------------------------------------------------------------------------
# _check_response_size
# ---------------------------------------------------------------------------


class TestCheckResponseSize:
    @pytest.mark.asyncio
    async def test_normal_body(self):
        resp = _fake_resp(200, b"hello")
        body = await _check_response_size(resp)
        assert body == b"hello"

    @pytest.mark.asyncio
    async def test_oversized_body_raises(self):
        big = b"\x00" * (10 * 1024 * 1024 + 1)
        resp = _fake_resp(200, big)
        with pytest.raises(NetworkError, match="exceeds maximum"):
            await _check_response_size(resp)


# ---------------------------------------------------------------------------
# _get_json
# ---------------------------------------------------------------------------


class TestGetJson:
    @pytest.mark.asyncio
    async def test_happy_path(self):
        session = MagicMock()
        resp = _json_resp({"key": "value"})
        session.get.return_value = resp
        data = await _get_json(session, "http://example.com/api")
        assert data == {"key": "value"}

    @pytest.mark.asyncio
    async def test_non_200_raises(self):
        session = MagicMock()
        resp = _json_resp({}, status=404)
        session.get.return_value = resp
        with pytest.raises(NetworkError, match="404"):
            await _get_json(session, "http://example.com/api")

    @pytest.mark.asyncio
    async def test_bad_content_type_raises(self):
        session = MagicMock()
        resp = _fake_resp(200, b'{"x":1}', content_type="application/octet-stream")
        session.get.return_value = resp
        with pytest.raises(NetworkError, match="Content-Type"):
            await _get_json(session, "http://example.com/api")

    @pytest.mark.asyncio
    async def test_non_json_body_raises(self):
        session = MagicMock()
        resp = _fake_resp(200, b"not json at all", content_type="text/plain")
        session.get.return_value = resp
        with pytest.raises(NetworkError, match="non-JSON"):
            await _get_json(session, "http://example.com/api")

    @pytest.mark.asyncio
    async def test_client_error_raises(self):
        import aiohttp

        session = MagicMock()
        session.get.side_effect = aiohttp.ClientError("connection refused")
        with pytest.raises(NetworkError, match="HTTP request failed"):
            await _get_json(session, "http://example.com/api")


# ---------------------------------------------------------------------------
# _get_hex_bytes
# ---------------------------------------------------------------------------


class TestGetHexBytes:
    @pytest.mark.asyncio
    async def test_happy_path(self):
        session = MagicMock()
        resp = _text_resp("deadbeef")
        session.get.return_value = resp
        b = await _get_hex_bytes(session, "http://example.com/hex")
        assert b == bytes.fromhex("deadbeef")

    @pytest.mark.asyncio
    async def test_non_200_raises(self):
        session = MagicMock()
        resp = _text_resp("", status=500)
        session.get.return_value = resp
        with pytest.raises(NetworkError, match="500"):
            await _get_hex_bytes(session, "http://example.com/hex")

    @pytest.mark.asyncio
    async def test_invalid_hex_raises(self):
        session = MagicMock()
        resp = _text_resp("not-valid-hex")
        session.get.return_value = resp
        with pytest.raises(NetworkError, match="invalid hex"):
            await _get_hex_bytes(session, "http://example.com/hex")

    @pytest.mark.asyncio
    async def test_wrong_length_raises(self):
        session = MagicMock()
        resp = _text_resp("deadbeef")  # 4 bytes
        session.get.return_value = resp
        with pytest.raises(NetworkError, match="Expected 80"):
            await _get_hex_bytes(session, "http://example.com/hex", expected_len=80)

    @pytest.mark.asyncio
    async def test_client_error_raises(self):
        import aiohttp

        session = MagicMock()
        session.get.side_effect = aiohttp.ClientError("reset")
        with pytest.raises(NetworkError, match="HTTP request failed"):
            await _get_hex_bytes(session, "http://example.com/hex")


# ---------------------------------------------------------------------------
# MempoolSpaceSource
# ---------------------------------------------------------------------------

TXID = Txid("ab" * 32)
TXID_STR = "ab" * 32

# A real, parseable legacy tx + its locally-derived txid, for the F-004 txid-binding
# check in get_raw_tx (returned bytes must hash to the requested txid).
_REAL_TX = (
    bytes.fromhex("02000000")  # version
    + b"\x01"  # 1 input
    + b"\x00" * 32  # prevout txid
    + b"\x00\x00\x00\x00"  # prevout vout
    + b"\x00"  # empty scriptSig
    + b"\xff\xff\xff\xff"  # sequence
    + b"\x01"  # 1 output
    + b"\x00" * 8  # value 0
    + b"\x19"  # script len 25
    + b"\x76\xa9\x14"
    + b"\x00" * 20
    + b"\x88\xac"  # P2PKH (>64-byte tx for RawTx)
    + bytes.fromhex("00000000")  # locktime
)
_REAL_TXID = Txid(hashlib.sha256(hashlib.sha256(_REAL_TX).digest()).digest()[::-1].hex())
HEADER_80 = bytes.fromhex("ff" * 80)
BLOCK_HASH = bytes.fromhex("cd" * 32)


class TestMempoolSpaceSource:
    """All tests patch MempoolSpaceSource._get_session to return a mock session."""

    def _src(self) -> MempoolSpaceSource:
        return MempoolSpaceSource("http://mempool.test/api")

    @pytest.mark.asyncio
    async def test_get_tip_height_happy(self):
        src = self._src()
        resp = _text_resp("800000")
        with patch.object(src, "_get_session", AsyncMock(return_value=_make_session(resp))):
            h = await src.get_tip_height()
        assert int(h) == 800000

    @pytest.mark.asyncio
    async def test_get_tip_height_bad_body_raises(self):
        src = self._src()
        resp = _text_resp("not-a-number")
        with patch.object(src, "_get_session", AsyncMock(return_value=_make_session(resp))):
            with pytest.raises(NetworkError, match="Invalid tip height"):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_tip_height_non200_raises(self):
        src = self._src()
        resp = _text_resp("", status=503)
        with patch.object(src, "_get_session", AsyncMock(return_value=_make_session(resp))):
            with pytest.raises(NetworkError):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_block_hash_happy(self):
        src = self._src()
        resp = _text_resp("cd" * 32)
        with patch.object(src, "_get_session", AsyncMock(return_value=_make_session(resp))):
            h = await src.get_block_hash(BlockHeight(100))
        assert bytes(h) == BLOCK_HASH

    @pytest.mark.asyncio
    async def test_get_block_hash_bad_hex_raises(self):
        src = self._src()
        resp = _text_resp("not-hex")
        with patch.object(src, "_get_session", AsyncMock(return_value=_make_session(resp))):
            with pytest.raises(NetworkError, match="invalid block hash"):
                await src.get_block_hash(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_raw_tx_happy(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 799000})
        hex_resp = _text_resp(_REAL_TX.hex())
        # get_raw_tx also calls get_tip_height
        tip_resp = _text_resp("800000")
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp, tip_resp, hex_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            raw = await src.get_raw_tx(_REAL_TXID, min_confirmations=1)
        assert bytes(raw) == _REAL_TX

    @pytest.mark.asyncio
    async def test_get_raw_tx_unconfirmed_raises(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": False})
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="0 confirmations"):
                await src.get_raw_tx(TXID, min_confirmations=1)

    @pytest.mark.asyncio
    async def test_get_raw_tx_insufficient_confs_raises(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 799990})
        tip_resp = _text_resp("800000")  # 11 confs, need 100
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp, tip_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="11 confirmations"):
                await src.get_raw_tx(TXID, min_confirmations=100)

    @pytest.mark.asyncio
    async def test_get_raw_tx_block_height_above_tip_rejected(self):
        """F-17: a source reporting block_height > tip is inconsistent — reject
        rather than compute garbage confirmations from an under-reported height."""
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 800001})
        tip_resp = _text_resp("800000")  # block_height > tip
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp, tip_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="inconsistent confirmation data"):
                await src.get_raw_tx(TXID, min_confirmations=1)

    @pytest.mark.asyncio
    async def test_get_raw_tx_block_height_below_one_rejected(self):
        """F-17: block_height < 1 is inconsistent — reject."""
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 0})
        tip_resp = _text_resp("800000")
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp, tip_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="inconsistent confirmation data"):
                await src.get_raw_tx(TXID, min_confirmations=1)

    @pytest.mark.asyncio
    async def test_get_tx_block_height_happy(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 799000})
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            h = await src.get_tx_block_height(TXID)
        assert int(h) == 799000

    @pytest.mark.asyncio
    async def test_get_tx_block_height_unconfirmed_raises(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": False})
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="unconfirmed"):
                await src.get_tx_block_height(TXID)

    @pytest.mark.asyncio
    async def test_get_tx_block_height_non_dict_raises(self):
        src = self._src()
        status_resp = _json_resp([1, 2, 3])  # not a dict
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Unexpected tx status"):
                await src.get_tx_block_height(TXID)

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_p2pkh(self):
        src = self._src()
        data = {"vout": [{"scriptpubkey_type": "p2pkh"}]}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            t = await src.get_tx_output_script_type(TXID, 0)
        assert t == "p2pkh"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_unknown(self):
        src = self._src()
        data = {"vout": [{"scriptpubkey_type": "future_type"}]}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            t = await src.get_tx_output_script_type(TXID, 0)
        assert t == "unknown"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_bad_index_raises(self):
        src = self._src()
        data = {"vout": []}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Could not parse output"):
                await src.get_tx_output_script_type(TXID, 99)

    @pytest.mark.asyncio
    async def test_get_merkle_proof_happy(self):
        src = self._src()
        data = {"merkle": ["aa" * 32, "bb" * 32], "pos": 3}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            merkle, pos = await src.get_merkle_proof(TXID, BlockHeight(799000))
        assert pos == 3
        assert len(merkle) == 2

    @pytest.mark.asyncio
    async def test_get_merkle_proof_bad_response_raises(self):
        src = self._src()
        resp = _json_resp({"bad": "structure"})
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Malformed merkle"):
                await src.get_merkle_proof(TXID, BlockHeight(799000))

    @pytest.mark.asyncio
    async def test_close_session(self):
        src = self._src()
        mock_session = AsyncMock()
        mock_session.closed = False
        src._session = mock_session
        await src.close()
        mock_session.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_header_chain(self):
        # get_header_chain fetches N headers concurrently — each needs 2 calls
        # (get_block_hash then get_block_header_hex)
        src = self._src()
        hash_resp_1 = _text_resp("cd" * 32)
        header_resp_1 = _text_resp("ff" * 80)
        hash_resp_2 = _text_resp("de" * 32)
        header_resp_2 = _text_resp("ee" * 80)
        session = MagicMock()
        session.get = MagicMock(side_effect=[hash_resp_1, header_resp_1, hash_resp_2, header_resp_2])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            chain = await src.get_header_chain(BlockHeight(100), count=2)
        assert len(chain) == 2
        assert chain[0] == bytes.fromhex("ff" * 80)

    @pytest.mark.asyncio
    async def test_get_header_chain_zero_count_raises(self):
        src = self._src()
        with pytest.raises(ValidationError):
            await src.get_header_chain(BlockHeight(100), count=0)

    @pytest.mark.asyncio
    async def test_get_header_chain_fetch_error_raises(self):
        src = self._src()
        # First hash fetch succeeds, header fetch raises
        hash_resp = _text_resp("cd" * 32)
        bad_resp = _text_resp("", status=503)
        session = MagicMock()
        session.get = MagicMock(side_effect=[hash_resp, bad_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Failed to fetch header"):
                await src.get_header_chain(BlockHeight(100), count=1)


# ---------------------------------------------------------------------------
# BlockstreamSource (same HTTP shape as MempoolSpaceSource)
# ---------------------------------------------------------------------------


class TestBlockstreamSource:
    def _src(self) -> BlockstreamSource:
        return BlockstreamSource("http://blockstream.test/api")

    @pytest.mark.asyncio
    async def test_get_tip_height_happy(self):
        src = self._src()
        resp = _text_resp("801000")
        with patch.object(src, "_get_session", AsyncMock(return_value=_make_session(resp))):
            h = await src.get_tip_height()
        assert int(h) == 801000

    @pytest.mark.asyncio
    async def test_get_tip_height_client_error(self):
        import aiohttp

        src = self._src()
        session = MagicMock()
        session.get.side_effect = aiohttp.ClientError("connection refused")
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="HTTP request failed"):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_tx_block_height_happy(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 798000})
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            h = await src.get_tx_block_height(TXID)
        assert int(h) == 798000

    @pytest.mark.asyncio
    async def test_get_tx_block_height_unconfirmed_raises(self):
        src = self._src()
        resp = _json_resp({"confirmed": False})
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="unconfirmed"):
                await src.get_tx_block_height(TXID)

    @pytest.mark.asyncio
    async def test_get_raw_tx_happy(self):
        src = self._src()
        status_resp = _json_resp({"confirmed": True, "block_height": 799000})
        tip_resp = _text_resp("800000")
        hex_resp = _text_resp(_REAL_TX.hex())
        session = MagicMock()
        session.get = MagicMock(side_effect=[status_resp, tip_resp, hex_resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            raw = await src.get_raw_tx(_REAL_TXID, min_confirmations=1)
        assert bytes(raw) == _REAL_TX

    @pytest.mark.asyncio
    async def test_get_merkle_proof_happy(self):
        src = self._src()
        data = {"merkle": ["cc" * 32], "pos": 1}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            _merkle, pos = await src.get_merkle_proof(TXID, BlockHeight(799000))
        assert pos == 1

    @pytest.mark.asyncio
    async def test_close(self):
        src = self._src()
        mock_session = AsyncMock()
        mock_session.closed = False
        src._session = mock_session
        await src.close()
        mock_session.close.assert_awaited_once()


# ---------------------------------------------------------------------------
# MultiSourceBtcDataSource
# ---------------------------------------------------------------------------


class TestMultiSourceBtcDataSource:
    def _make_source(self, tip=800000) -> MagicMock:
        src = AsyncMock()
        src.get_tip_height = AsyncMock(return_value=BlockHeight(tip))
        src.get_block_hash = AsyncMock(return_value=Hex32(bytes.fromhex("cd" * 32)))
        src.get_raw_tx = AsyncMock(return_value=RawTx(_REAL_TX))
        src.get_tx_block_height = AsyncMock(return_value=BlockHeight(799000))
        src.get_tx_output_script_type = AsyncMock(return_value="p2pkh")
        src.get_merkle_proof = AsyncMock(return_value=(["aa" * 32], 3))
        src.get_block_header_hex = AsyncMock(return_value=bytes.fromhex("ff" * 80))
        src.get_header_chain = AsyncMock(return_value=[bytes.fromhex("ff" * 80)])
        return src

    @pytest.mark.asyncio
    async def test_get_tip_height_quorum(self):
        s1, s2 = self._make_source(800000), self._make_source(800000)
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        h = await multi.get_tip_height()
        assert int(h) == 800000

    @pytest.mark.asyncio
    async def test_get_tip_height_no_quorum_raises(self):
        s1 = self._make_source(800000)
        s2 = self._make_source(799999)  # disagrees
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        with pytest.raises(NetworkError, match="quorum not reached"):
            await multi.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_raw_tx_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        raw = await multi.get_raw_tx(_REAL_TXID, min_confirmations=1)
        assert bytes(raw) == _REAL_TX

    @pytest.mark.asyncio
    async def test_get_tx_block_height_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        h = await multi.get_tx_block_height(TXID)
        assert int(h) == 799000

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        t = await multi.get_tx_output_script_type(TXID, 0)
        assert t == "p2pkh"

    @pytest.mark.asyncio
    async def test_get_block_hash_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        h = await multi.get_block_hash(BlockHeight(100))
        assert bytes(h) == bytes.fromhex("cd" * 32)

    @pytest.mark.asyncio
    async def test_get_merkle_proof_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        _merkle, pos = await multi.get_merkle_proof(TXID, BlockHeight(799000))
        assert pos == 3

    @pytest.mark.asyncio
    async def test_get_block_header_hex_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        h = await multi.get_block_header_hex(BlockHeight(100))
        assert h == bytes.fromhex("ff" * 80)

    @pytest.mark.asyncio
    async def test_get_header_chain_quorum(self):
        s1, s2 = self._make_source(), self._make_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        chain = await multi.get_header_chain(BlockHeight(100), count=1)
        assert chain == [bytes.fromhex("ff" * 80)]

    @pytest.mark.asyncio
    async def test_empty_sources_raises(self):
        with pytest.raises(ValidationError):
            MultiSourceBtcDataSource([], quorum=2)

    @pytest.mark.asyncio
    async def test_quorum_impossible_raises(self):
        s1 = self._make_source()
        multi = MultiSourceBtcDataSource([s1], quorum=2)
        with pytest.raises(NetworkError, match="Not enough sources"):
            await multi.get_tip_height()

    @pytest.mark.asyncio
    async def test_one_source_fails_still_reaches_quorum(self):
        s1 = self._make_source()
        s2 = AsyncMock()
        s2.get_tip_height = AsyncMock(side_effect=NetworkError("timeout"))
        multi = MultiSourceBtcDataSource([s1, s2], quorum=1)
        h = await multi.get_tip_height()
        assert int(h) == 800000


# ---------------------------------------------------------------------------
# MultiSourceBtcFundingReader (audit 2026-05-29 F-17 quorum reader)
# ---------------------------------------------------------------------------


def _fake_reader(*, confs=None, amount=None, confs_exc=None, amount_exc=None):
    """A duck-typed funding reader whose confirmations / amount are scriptable."""
    r = MagicMock()
    r.confirmations = AsyncMock(return_value=confs, side_effect=confs_exc)
    r.read_output_amount_sats = AsyncMock(return_value=amount, side_effect=amount_exc)
    return r


class TestMultiSourceBtcFundingReader:
    TXID = "ab" * 32

    def test_constructor_rejects_too_few_readers_for_quorum(self):
        with pytest.raises(ValidationError, match="quorum"):
            MultiSourceBtcFundingReader([_fake_reader(confs=3)], quorum=2)

    def test_default_mainnet_wires_three_endpoints(self):
        reader = MultiSourceBtcFundingReader.default_mainnet()
        assert len(reader._readers) == 3
        assert reader._quorum == 2
        assert reader._dust_cap_sats == 10_000

    @pytest.mark.asyncio
    async def test_confirmations_returns_minimum_across_sources(self):
        # All three respond with different depths -> the conservative MINIMUM is used.
        reader = MultiSourceBtcFundingReader(
            [_fake_reader(confs=5), _fake_reader(confs=3), _fake_reader(confs=4)], quorum=2
        )
        assert await reader.confirmations(self.TXID) == 3

    @pytest.mark.asyncio
    async def test_confirmations_defends_against_over_reporter(self):
        # One source OVER-reports depth (10); the honest two say 3 -> min 3 (F-17 attack defeated).
        reader = MultiSourceBtcFundingReader(
            [_fake_reader(confs=10), _fake_reader(confs=3), _fake_reader(confs=3)], quorum=2
        )
        assert await reader.confirmations(self.TXID) == 3

    @pytest.mark.asyncio
    async def test_confirmations_above_dust_fails_closed_without_quorum(self):
        # Only one source responds; default value_sats=None -> quorum required -> raise.
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(confs=6),
                _fake_reader(confs_exc=NetworkError("down")),
                _fake_reader(confs_exc=NetworkError("down")),
            ],
            quorum=2,
        )
        with pytest.raises(NetworkError, match="quorum"):
            await reader.confirmations(self.TXID)

    @pytest.mark.asyncio
    async def test_confirmations_below_dust_accepts_single_source(self):
        # value_sats below the cap -> a single responding source is acceptable.
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(confs=6),
                _fake_reader(confs_exc=NetworkError("down")),
                _fake_reader(confs_exc=NetworkError("down")),
            ],
            quorum=2,
            dust_cap_sats=10_000,
        )
        assert await reader.confirmations(self.TXID, value_sats=1_000) == 6

    @pytest.mark.asyncio
    async def test_read_amount_above_dust_requires_quorum_agreement(self):
        # Above-cap amount agreed by 2 of 3 -> returned; conf depth quorum'd separately.
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(confs=6, amount=50_000),
                _fake_reader(confs=6, amount=50_000),
                _fake_reader(confs=6, amount=50_000),
            ],
            quorum=2,
        )
        assert await reader.read_output_amount_sats(self.TXID, 0, min_confirmations=6) == 50_000

    @pytest.mark.asyncio
    async def test_read_amount_above_dust_disagreement_fails_closed(self):
        # Above-cap amount: each source reports a DIFFERENT value -> no quorum -> raise.
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(confs=6, amount=50_000),
                _fake_reader(confs=6, amount=49_999),
                _fake_reader(confs=6, amount=51_000),
            ],
            quorum=2,
        )
        with pytest.raises(NetworkError, match="corroborated by only"):
            await reader.read_output_amount_sats(self.TXID, 0, min_confirmations=6)

    @pytest.mark.asyncio
    async def test_read_amount_insufficient_confs_raises(self):
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(confs=2, amount=50_000),
                _fake_reader(confs=2, amount=50_000),
                _fake_reader(confs=3, amount=50_000),
            ],
            quorum=2,
        )
        with pytest.raises(InsufficientConfirmationsError):
            await reader.read_output_amount_sats(self.TXID, 0, min_confirmations=6)

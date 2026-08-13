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
    BitcoinCoreFundingReader,
    BlockstreamSource,
    MempoolSpaceSource,
    MultiSourceBtcDataSource,
    MultiSourceBtcFundingReader,
    _check_response_size,
    _get_hex_bytes,
    _get_json,
    choose_funding_reader,
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
        # The body must identify the tx we asked for: `_assert_tx_identity` now binds
        # `/tx/{txid}` responses, so a source cannot answer about a different transaction.
        data = {"txid": str(TXID), "vout": [{"scriptpubkey_type": "p2pkh"}]}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            t = await src.get_tx_output_script_type(TXID, 0)
        assert t == "p2pkh"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_unknown(self):
        src = self._src()
        data = {"txid": str(TXID), "vout": [{"scriptpubkey_type": "future_type"}]}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            t = await src.get_tx_output_script_type(TXID, 0)
        assert t == "unknown"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_bad_index_raises(self):
        src = self._src()
        data = {"txid": str(TXID), "vout": []}
        resp = _json_resp(data)
        session = MagicMock()
        session.get = MagicMock(side_effect=[resp])
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Could not parse output"):
                await src.get_tx_output_script_type(TXID, 99)

    @pytest.mark.asyncio
    async def test_get_merkle_proof_happy(self):
        src = self._src()
        data = {"block_height": 799000, "merkle": ["aa" * 32, "bb" * 32], "pos": 3}
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
        data = {"block_height": 799000, "merkle": ["cc" * 32], "pos": 1}
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
        """Availability floor: fewer sources ANSWERING than the quorum still fails closed.

        This case used to be written as "two sources one block apart", asserting that ordinary
        block propagation was a refusable disagreement. It is not — see the skew tests below.
        The refusal that remains is about how many sources replied at all.
        """
        s1 = self._make_source(800000)
        s2 = self._make_source(799999)
        s2.get_tip_height = AsyncMock(side_effect=NetworkError("down"))
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        with pytest.raises(NetworkError, match="quorum not reached"):
            await multi.get_tip_height()

    # -- tip height: honest skew is not a disagreement -------------------------------------
    #
    # A block takes time to propagate, so sources one (occasionally two) blocks apart is the
    # normal reading, not evidence of a liar. Routing tip height through the exact-match quorum
    # made every one of these raise, and the caller is an HTLC confirmation wait on a chain with
    # neither RBF nor CPFP — an abort there during a timelock race costs funds.

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("heights", "quorum", "expected"),
        [
            ([900_000, 900_001], 1, 900_000),  # 2 sources, 1 block apart
            ([900_000, 900_001], 2, 900_000),  # same, at the corroborating quorum
            ([900_000, 900_000, 900_001, 900_001], 2, 900_000),  # an EVEN split
            ([900_000, 900_000, 900_001], 2, 900_000),  # majority behind
            ([900_001, 900_000, 900_000], 2, 900_000),  # order must not matter
        ],
    )
    async def test_get_tip_height_tolerates_honest_propagation_skew(self, heights, quorum, expected):
        srcs = [self._make_source(h) for h in heights]
        multi = MultiSourceBtcDataSource(srcs, quorum=quorum)
        assert int(await multi.get_tip_height()) == expected

    @pytest.mark.asyncio
    async def test_get_tip_height_refuses_an_inflated_tip_from_a_lying_minority(self):
        """The property the quorum gate exists for. An inflated tip overstates confirmation
        depth, so it must never be the answer — and the liar must be discarded, not raise."""
        srcs = [self._make_source(900_000), self._make_source(900_000), self._make_source(999_999)]
        multi = MultiSourceBtcDataSource(srcs, quorum=2)
        assert int(await multi.get_tip_height()) == 900_000

    @pytest.mark.asyncio
    async def test_get_tip_height_refuses_an_inflated_tip_from_a_colluding_pair(self):
        """Two colluding sources must not outvote three honest ones — the quorum is a FLOOR,
        the decision is a strict majority of the sources that answered."""
        srcs = [self._make_source(h) for h in (999_999, 999_999, 900_000, 900_000, 900_000)]
        multi = MultiSourceBtcDataSource(srcs, quorum=2)
        assert int(await multi.get_tip_height()) == 900_000

    @pytest.mark.asyncio
    async def test_get_tip_height_refuses_a_deflated_tip_from_a_lying_minority(self):
        """The mirror property, and the reason this is not a plain ``min()``: one stuck source
        reporting 0 would otherwise pin the answer at 0 and stall every confirmation wait."""
        srcs = [self._make_source(900_000), self._make_source(900_000), self._make_source(0)]
        multi = MultiSourceBtcDataSource(srcs, quorum=2)
        assert int(await multi.get_tip_height()) == 900_000

    @pytest.mark.asyncio
    async def test_get_tip_height_at_full_quorum_takes_the_majority_not_the_minimum(self):
        """Raising ``quorum`` must not make the tip more deflatable — it used to.

        This test previously asserted the minimum, on the reasoning that
        ``quorum == len(sources)`` means unanimity-or-nothing and the most
        pessimistic source should win. That reasoning is what let a single
        source reporting 0 return 0: at five sources with ``quorum=5`` the
        answer was ``heights[4]``, the minimum, so the configuration an
        operator picks for MORE assurance was the one a lone liar could
        deflate. See the companion assertion below.

        The majority is now over the configured sources regardless of quorum,
        so with three honest sources one propagation step apart the answer is
        the height two of the three corroborate. The cost is real and
        deliberate: this reads one block less pessimistic than the lowest
        source. Discarding the bottom reading is exactly what makes a stuck
        source harmless, and it cannot be had both ways.
        """
        srcs = [self._make_source(h) for h in (900_002, 900_001, 900_000)]
        multi = MultiSourceBtcDataSource(srcs, quorum=3)
        assert int(await multi.get_tip_height()) == 900_001

        deflating = [self._make_source(h) for h in (900_000, 900_000, 0)]
        assert int(await MultiSourceBtcDataSource(deflating, quorum=3).get_tip_height()) == 900_000

    # -- deterministic reads: the largest group wins, and a tie fails closed ----------------

    @pytest.mark.asyncio
    @pytest.mark.parametrize("order", [(0, 0, 0, 1, 1), (1, 1, 0, 0, 0), (0, 1, 0, 1, 0)])
    async def test_deterministic_read_lets_the_majority_beat_a_colluding_pair(self, order):
        """Three honest sources must not be vetoed by two colluding ones, at ANY position.

        Refusing whenever two values both reached the quorum closed the positional flaw by
        handing the minority a veto instead — still a minority deciding the outcome.
        """
        honest, liar = bytes.fromhex("aa" * 32), bytes.fromhex("bb" * 32)
        srcs = []
        for pick in order:
            s = self._make_source()
            s.get_block_hash = AsyncMock(return_value=Hex32(liar if pick else honest))
            srcs.append(s)
        multi = MultiSourceBtcDataSource(srcs, quorum=2)
        assert bytes(await multi.get_block_hash(BlockHeight(100))) == honest

    @pytest.mark.asyncio
    async def test_deterministic_read_refuses_an_exact_tie(self):
        """A 2-2 tie means half the sources are lying or forked. There is no majority truth to
        find, and every tie-break on the VALUE is grindable by a source that chooses what it
        reports — so this fails closed, deterministically and without regard to order."""
        srcs = []
        for h in ("aa", "aa", "bb", "bb"):
            s = self._make_source()
            s.get_block_hash = AsyncMock(return_value=Hex32(bytes.fromhex(h * 32)))
            srcs.append(s)
        multi = MultiSourceBtcDataSource(srcs, quorum=2)
        with pytest.raises(NetworkError, match="tied at 2 source"):
            await multi.get_block_hash(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_deterministic_read_refuses_a_value_only_a_sub_quorum_minority_backs(self):
        """The inflation direction for exact-match reads: a single dissenter neither wins nor
        raises, and a value nobody corroborates to the quorum is refused outright."""
        srcs = []
        for h in ("aa", "bb", "cc"):
            s = self._make_source()
            s.get_block_hash = AsyncMock(return_value=Hex32(bytes.fromhex(h * 32)))
            srcs.append(s)
        multi = MultiSourceBtcDataSource(srcs, quorum=2)
        with pytest.raises(NetworkError, match="quorum not reached"):
            await multi.get_block_hash(BlockHeight(100))

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
    async def test_two_configured_sources_with_one_down_cannot_cross_check(self):
        """Two sources is a request for cross-checking; losing one loses the check.

        This previously returned the surviving source's word on the strength of
        ``quorum=1``. A tip height is fund-critical — it is the numerator of
        confirmation depth — and one unverified source's claim is exactly what
        the multi-source class exists to avoid. Since the majority is now over
        the CONFIGURED sources, one of two answering fails closed.

        An operator who genuinely wants single-source trust configures a single
        source, where the majority is that source; the case below shows that
        still works, so this is not a guard refusing valid work.
        """
        s1 = self._make_source()
        s2 = AsyncMock()
        s2.get_tip_height = AsyncMock(side_effect=NetworkError("timeout"))
        multi = MultiSourceBtcDataSource([s1, s2], quorum=1)
        with pytest.raises(NetworkError, match="majority of the configured sources"):
            await multi.get_tip_height()

    @pytest.mark.asyncio
    async def test_a_deliberately_single_source_still_works(self):
        """The honest-path pair for the refusal above."""
        multi = MultiSourceBtcDataSource([self._make_source()], quorum=1)
        assert int(await multi.get_tip_height()) == 800000

    @pytest.mark.asyncio
    async def test_three_sources_tolerate_one_outage(self):
        """Outage tolerance is what a third source buys."""
        s3 = AsyncMock()
        s3.get_tip_height = AsyncMock(side_effect=NetworkError("timeout"))
        multi = MultiSourceBtcDataSource([self._make_source(), self._make_source(), s3], quorum=2)
        assert int(await multi.get_tip_height()) == 800000


# ---------------------------------------------------------------------------
# MultiSourceBtcFundingReader (audit 2026-05-29 F-17 quorum reader)
# ---------------------------------------------------------------------------


def _fake_reader(*, confs=None, amount=None, confs_exc=None, amount_exc=None, output=None, output_exc=None):
    """A duck-typed funding reader whose confirmations / amount / confirmed-unspent output are
    scriptable (``output`` is the ``(scriptPubKey, value_sats)`` pair)."""
    r = MagicMock()
    r.confirmations = AsyncMock(return_value=confs, side_effect=confs_exc)
    r.read_output_amount_sats = AsyncMock(return_value=amount, side_effect=amount_exc)
    r.read_confirmed_unspent_output = AsyncMock(return_value=output, side_effect=output_exc)
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

    # -- confirmed-unspent output (the maker-side counter-funding gate's read) --

    @pytest.mark.asyncio
    async def test_read_confirmed_unspent_output_above_dust_requires_quorum_agreement(self):
        spk = bytes.fromhex("5120" + "11" * 32)
        reader = MultiSourceBtcFundingReader(
            [_fake_reader(output=(spk, 50_000)), _fake_reader(output=(spk, 50_000)), _fake_reader(output=(spk, 9))],
            quorum=2,
        )
        assert await reader.read_confirmed_unspent_output(self.TXID, 0) == (spk, 50_000)

    @pytest.mark.asyncio
    async def test_read_confirmed_unspent_output_disagreement_fails_closed(self):
        """A single MITM'd source must not be able to certify a funding output: above the dust cap
        the exact (scriptPubKey, value) pair needs the quorum."""
        spk = bytes.fromhex("5120" + "11" * 32)
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(output=(spk, 50_000)),
                _fake_reader(output=(spk, 49_000)),
                _fake_reader(output=(bytes.fromhex("0014" + "22" * 20), 50_000)),
            ],
            quorum=2,
        )
        with pytest.raises(NetworkError, match="corroborated by only"):
            await reader.read_confirmed_unspent_output(self.TXID, 0)

    @pytest.mark.asyncio
    async def test_read_confirmed_unspent_output_no_source_fails_closed(self):
        reader = MultiSourceBtcFundingReader(
            [
                _fake_reader(output_exc=NetworkError("spent")),
                _fake_reader(output_exc=NetworkError("down")),
            ],
            quorum=2,
        )
        with pytest.raises(NetworkError, match="no source returned"):
            await reader.read_confirmed_unspent_output(self.TXID, 0)


# ---------------------------------------------------------------------------
# choose_funding_reader (F-17 value routing)
# ---------------------------------------------------------------------------


class TestChooseFundingReader:
    def test_at_or_below_dust_cap_picks_single(self):
        single, multi = object(), object()
        assert choose_funding_reader(10_000, single=single, multi=multi, dust_cap_sats=10_000) is single
        assert choose_funding_reader(1, single=single, multi=multi, dust_cap_sats=10_000) is single

    def test_above_dust_cap_picks_multi(self):
        single, multi = object(), object()
        assert choose_funding_reader(10_001, single=single, multi=multi, dust_cap_sats=10_000) is multi

    def test_factories_are_lazy(self):
        calls = {"single": 0, "multi": 0}

        def mk_single():
            calls["single"] += 1
            return "SINGLE"

        def mk_multi():
            calls["multi"] += 1
            return "MULTI"

        # Above cap -> only the multi factory runs.
        assert choose_funding_reader(50_000, single=mk_single, multi=mk_multi) == "MULTI"
        assert calls == {"single": 0, "multi": 1}
        # Below cap -> only the single factory runs.
        assert choose_funding_reader(500, single=mk_single, multi=mk_multi) == "SINGLE"
        assert calls == {"single": 1, "multi": 1}

    def test_negative_value_rejected(self):
        with pytest.raises(ValidationError):
            choose_funding_reader(-1, single=object(), multi=object())


# ─────────────────────────────────────────────── BitcoinCoreFundingReader


class _FakeBtcRpc:
    """A fake async bitcoind ``rpc(method, params)`` returning canned getrawtransaction / gettxout."""

    def __init__(self, getrawtransaction=None, gettxout=None):
        self._grt = getrawtransaction
        self._gto = gettxout
        self.calls: list = []

    async def __call__(self, method, params=None):
        self.calls.append((method, list(params or [])))
        if method == "getrawtransaction":
            if isinstance(self._grt, Exception):
                raise self._grt
            return self._grt
        if method == "gettxout":
            if isinstance(self._gto, Exception):
                raise self._gto
            return self._gto
        raise AssertionError(f"unexpected rpc method {method}")


_TXID = "ab" * 32


class TestBitcoinCoreFundingReader:
    async def test_confirmations_confirmed(self):
        reader = BitcoinCoreFundingReader(_FakeBtcRpc({"txid": _TXID, "confirmations": 5, "vout": []}))
        assert await reader.confirmations(_TXID) == 5

    async def test_confirmations_unconfirmed_returns_zero(self):
        # No 'confirmations' field == in the mempool -> 0, so the reorg gate fails closed.
        reader = BitcoinCoreFundingReader(_FakeBtcRpc({"txid": _TXID, "vout": []}))
        assert await reader.confirmations(_TXID) == 0

    async def test_confirmations_non_dict_raises(self):
        reader = BitcoinCoreFundingReader(_FakeBtcRpc("not-a-dict"))
        with pytest.raises(NetworkError, match="verbose object"):
            await reader.confirmations(_TXID)

    async def test_read_output_amount_sats_exact_decimal_conversion(self):
        # BTC -> sats must be EXACT: 0.001 -> 100_000 (a naive float *1e8 lands on 99999.999… -> truncates).
        grt = {"txid": _TXID, "confirmations": 6, "vout": [{"value": 0.001}, {"value": 1.23456789}]}
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(grt))
        assert await reader.read_output_amount_sats(_TXID, 0, min_confirmations=1) == 100_000
        assert await reader.read_output_amount_sats(_TXID, 1, min_confirmations=1) == 123_456_789

    async def test_read_output_amount_sats_insufficient_confs(self):
        grt = {"txid": _TXID, "confirmations": 2, "vout": [{"value": 0.001}]}
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(grt))
        with pytest.raises(InsufficientConfirmationsError):
            await reader.read_output_amount_sats(_TXID, 0, min_confirmations=6)

    async def test_read_output_amount_sats_unconfirmed_fails_closed(self):
        # Unconfirmed (confs=0) against any positive min_confirmations -> fail closed.
        grt = {"txid": _TXID, "vout": [{"value": 0.001}]}
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(grt))
        with pytest.raises(InsufficientConfirmationsError):
            await reader.read_output_amount_sats(_TXID, 0, min_confirmations=1)

    async def test_read_output_amount_sats_bad_vout_raises(self):
        grt = {"txid": _TXID, "confirmations": 6, "vout": [{"value": 0.001}]}
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(grt))
        with pytest.raises(NetworkError, match="output value"):
            await reader.read_output_amount_sats(_TXID, 5, min_confirmations=1)  # vout index out of range

    async def test_rejects_non_callable_rpc(self):
        with pytest.raises(ValidationError, match="async callable"):
            BitcoinCoreFundingReader("not-callable")

    async def test_txid_of_delegates_to_btc_txid_from_raw(self):
        from pyrxd.btc_wallet.taproot import btc_txid_from_raw

        # A minimal structurally-valid non-segwit tx (1 in, 1 out): txid_of must match the pure serializer.
        raw = bytes.fromhex(
            "0100000001" + "00" * 32 + "00000000" + "00" + "ffffffff" + "01" + "00" * 8 + "00" + "00000000"
        )
        reader = BitcoinCoreFundingReader(_FakeBtcRpc())
        assert await reader.txid_of(raw) == btc_txid_from_raw(raw)

    async def test_read_confirmed_unspent_output_binds_spk_and_value(self):
        # gettxout of a confirmed UNSPENT output: returns (on-chain scriptPubKey bytes, value in sats).
        gto = {"value": 0.001, "confirmations": 3, "scriptPubKey": {"hex": "51201234" + "00" * 30}}
        fake = _FakeBtcRpc(gettxout=gto)
        reader = BitcoinCoreFundingReader(fake)
        spk, sats = await reader.read_confirmed_unspent_output(_TXID, 0)
        assert spk == bytes.fromhex("51201234" + "00" * 30)
        assert sats == 100_000
        # gettxout was called with include_mempool=False (confirmed UTXO set only).
        assert ("gettxout", [_TXID, 0, False]) in fake.calls

    async def test_read_confirmed_unspent_output_spent_or_unknown_fails_closed(self):
        # gettxout returns null for a spent / unconfirmed / unknown output -> fail closed.
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(gettxout=None))
        with pytest.raises(NetworkError, match="returned null"):
            await reader.read_confirmed_unspent_output(_TXID, 0)

    async def test_read_confirmed_unspent_output_missing_spk_fails_closed(self):
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(gettxout={"value": 0.001, "scriptPubKey": {}}))
        with pytest.raises(NetworkError, match="scriptPubKey"):
            await reader.read_confirmed_unspent_output(_TXID, 0)

    async def test_read_confirmed_unspent_output_missing_value_fails_closed(self):
        reader = BitcoinCoreFundingReader(_FakeBtcRpc(gettxout={"scriptPubKey": {"hex": "0014" + "00" * 20}}))
        with pytest.raises(NetworkError, match="no value"):
            await reader.read_confirmed_unspent_output(_TXID, 0)

"""Coverage gap tests — sixth batch.

Targets:
  - network/bitcoin.py: BitcoinCoreRpcSource (mostly uncovered)
  - network/bitcoin.py: BlockstreamSource error branches
  - network/bitcoin.py: MultiSourceBtcDataSource remaining branches
  - transaction_preimage.py: _get_push_refs OP_PUSHDATA variants (lines 36, 38, 40)
  - spv/witness.py: truncation error paths inside strip_witness body
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.network.bitcoin import (
    BitcoinCoreRpcSource,
    BlockstreamSource,
    MempoolSpaceSource,
    MultiSourceBtcDataSource,
)
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import BlockHeight, Hex32, RawTx, Txid


# ──────────────────────────────────────────────────────────────────────────────
# Helpers (mirrors test_network_bitcoin.py helpers)
# ──────────────────────────────────────────────────────────────────────────────

def _fake_resp(status: int, body: bytes, content_type: str = "application/json") -> MagicMock:
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


def _rpc_resp(result: Any, error=None, status: int = 200) -> MagicMock:
    """Build a JSON-RPC response."""
    body = {"jsonrpc": "1.1", "id": 1, "result": result, "error": error}
    return _fake_resp(status, json.dumps(body).encode(), "application/json")


def _rpc_error_resp(message: str) -> MagicMock:
    """Build a JSON-RPC error response."""
    body = {"jsonrpc": "1.1", "id": 1, "result": None, "error": {"message": message, "code": -1}}
    return _fake_resp(status=500, body=json.dumps(body).encode(), content_type="application/json")


def _make_session(*responses) -> MagicMock:
    session = MagicMock()
    session.get = MagicMock(side_effect=list(responses))
    session.post = MagicMock(side_effect=list(responses))
    return session


# ──────────────────────────────────────────────────────────────────────────────
# BitcoinCoreRpcSource
# ──────────────────────────────────────────────────────────────────────────────

class TestBitcoinCoreRpcSource:

    def _src(self):
        return BitcoinCoreRpcSource("http://localhost:8332/", "user", "pass")

    @pytest.mark.asyncio
    async def test_get_tip_height_happy(self):
        src = self._src()
        session = _make_session(_rpc_resp(840000))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_tip_height()
        assert int(result) == 840000

    @pytest.mark.asyncio
    async def test_get_tip_height_invalid_result_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("not-a-number"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_block_hash_happy(self):
        src = self._src()
        block_hash = "aa" * 32
        session = _make_session(_rpc_resp(block_hash))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_block_hash(BlockHeight(100))
        assert isinstance(result, Hex32)

    @pytest.mark.asyncio
    async def test_get_block_hash_non_dict_result_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp(12345))  # not a string
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_hash(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_block_hash_invalid_hex_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("not-hex!!"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_hash(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_block_hash_accepts_plain_height(self):
        """get_block_hash should accept raw int height."""
        src = self._src()
        block_hash = "bb" * 32
        session = _make_session(_rpc_resp(block_hash))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_block_hash(100)  # raw int
        assert isinstance(result, Hex32)

    @pytest.mark.asyncio
    async def test_get_block_header_hex_happy(self):
        src = self._src()
        block_hash_hex = "cc" * 32
        header_hex = "dd" * 80
        hash_resp = _rpc_resp(block_hash_hex)
        header_resp = _rpc_resp(header_hex)
        session = _make_session(hash_resp, header_resp)
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            header = await src.get_block_header_hex(BlockHeight(200))
        assert header == bytes.fromhex(header_hex)

    @pytest.mark.asyncio
    async def test_get_block_header_hex_non_str_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("cc" * 32), _rpc_resp(42))  # header not a string
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_header_hex(BlockHeight(200))

    @pytest.mark.asyncio
    async def test_get_block_header_hex_invalid_hex_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("cc" * 32), _rpc_resp("not-hex!"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_header_hex(BlockHeight(200))

    @pytest.mark.asyncio
    async def test_get_block_header_hex_wrong_length_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("cc" * 32), _rpc_resp("ee" * 40))  # 40 bytes, not 80
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_header_hex(BlockHeight(200))

    @pytest.mark.asyncio
    async def test_get_header_chain_happy(self):
        src = self._src()
        block_hash = "cc" * 32
        header_hex = "dd" * 80
        # For count=2: 2 calls each need a hash + header = 4 total posts
        responses = [
            _rpc_resp(block_hash), _rpc_resp(header_hex),
            _rpc_resp(block_hash), _rpc_resp(header_hex),
        ]
        session = _make_session(*responses)
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            headers = await src.get_header_chain(BlockHeight(100), 2)
        assert len(headers) == 2
        assert all(h == bytes.fromhex(header_hex) for h in headers)

    @pytest.mark.asyncio
    async def test_get_header_chain_zero_count_raises(self):
        src = self._src()
        with pytest.raises(ValidationError):
            await src.get_header_chain(BlockHeight(100), 0)

    @pytest.mark.asyncio
    async def test_get_header_chain_fetch_failure_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("cc" * 32), _rpc_resp("invalid-hex"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_header_chain(BlockHeight(100), 1)

    @pytest.mark.asyncio
    async def test_get_raw_tx_happy(self):
        src = self._src()
        raw_hex = "aa" * 65
        data = {"confirmations": 10, "hex": raw_hex}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_raw_tx(Txid("ab" * 32), min_confirmations=6)
        assert bytes(result) == bytes.fromhex(raw_hex)

    @pytest.mark.asyncio
    async def test_get_raw_tx_insufficient_confs_raises(self):
        src = self._src()
        raw_hex = "aa" * 65
        data = {"confirmations": 2, "hex": raw_hex}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="confirmations"):
                await src.get_raw_tx(Txid("ab" * 32), min_confirmations=6)

    @pytest.mark.asyncio
    async def test_get_raw_tx_non_dict_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("not-a-dict"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx(Txid("ab" * 32))

    @pytest.mark.asyncio
    async def test_get_raw_tx_missing_hex_field_raises(self):
        src = self._src()
        data = {"confirmations": 10, "hex": 12345}  # hex not a string
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx(Txid("ab" * 32))

    @pytest.mark.asyncio
    async def test_get_raw_tx_invalid_hex_raises(self):
        src = self._src()
        data = {"confirmations": 10, "hex": "not-valid-hex!!!"}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx(Txid("ab" * 32))

    @pytest.mark.asyncio
    async def test_get_tx_block_height_happy(self):
        src = self._src()
        data = {"blockheight": 750000}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_tx_block_height(Txid("ab" * 32))
        assert int(result) == 750000

    @pytest.mark.asyncio
    async def test_get_tx_block_height_missing_blockheight_raises(self):
        src = self._src()
        data = {"confirmations": 5}  # no blockheight field
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="unconfirmed"):
                await src.get_tx_block_height(Txid("ab" * 32))

    @pytest.mark.asyncio
    async def test_get_tx_block_height_non_dict_raises(self):
        src = self._src()
        session = _make_session(_rpc_resp("oops"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tx_block_height(Txid("ab" * 32))

    @pytest.mark.asyncio
    async def test_get_tx_block_height_coerces_str_txid(self):
        src = self._src()
        data = {"blockheight": 123456}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_tx_block_height("ab" * 32)  # str, not Txid
        assert int(result) == 123456

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_p2pkh(self):
        src = self._src()
        data = {"vout": [{"scriptPubKey": {"type": "pubkeyhash"}}]}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_tx_output_script_type(Txid("ab" * 32), 0)
        assert result == "p2pkh"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_unknown(self):
        src = self._src()
        data = {"vout": [{"scriptPubKey": {"type": "nulldata"}}]}
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_tx_output_script_type(Txid("ab" * 32), 0)
        assert result == "unknown"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_bad_index_raises(self):
        src = self._src()
        data = {"vout": []}  # empty vout
        session = _make_session(_rpc_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tx_output_script_type(Txid("ab" * 32), 5)

    @pytest.mark.asyncio
    async def test_get_merkle_proof_raises(self):
        """BitcoinCoreRpcSource.get_merkle_proof always raises (not implemented)."""
        src = self._src()
        with pytest.raises(NetworkError, match="not directly available"):
            await src.get_merkle_proof(Txid("ab" * 32), BlockHeight(100))

    @pytest.mark.asyncio
    async def test_rpc_error_response_raises(self):
        """RPC error payload (result=null, error set) should raise NetworkError."""
        src = self._src()
        session = _make_session(_rpc_error_resp("Method not found"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="Method not found"):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_rpc_non_json_response_raises(self):
        src = self._src()
        bad_resp = _fake_resp(200, b"not json", "text/plain")
        session = MagicMock()
        session.post = MagicMock(return_value=bad_resp)
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="non-JSON"):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_rpc_http_error_raises(self):
        """Non-200/500 HTTP status should raise NetworkError."""
        src = self._src()
        bad_resp = _fake_resp(403, b'{"error": "forbidden"}', "application/json")
        session = MagicMock()
        session.post = MagicMock(return_value=bad_resp)
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError, match="RPC HTTP error"):
                await src.get_tip_height()

    @pytest.mark.asyncio
    async def test_close_session(self):
        src = self._src()
        session = MagicMock()
        session.closed = False
        session.close = AsyncMock()
        src._session = session
        await src.close()
        session.close.assert_awaited_once()
        assert src._session is None

    @pytest.mark.asyncio
    async def test_close_already_closed(self):
        src = self._src()
        session = MagicMock()
        session.closed = True  # Already closed
        src._session = session
        await src.close()  # Should not raise


# ──────────────────────────────────────────────────────────────────────────────
# BlockstreamSource — additional error branches
# ──────────────────────────────────────────────────────────────────────────────

class TestBlockstreamSourceAdditional:

    def _src(self):
        return BlockstreamSource()

    @pytest.mark.asyncio
    async def test_get_block_hash_happy(self):
        src = self._src()
        hash_hex = "aa" * 32
        session = MagicMock()
        session.get = MagicMock(return_value=_text_resp(hash_hex))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_block_hash(BlockHeight(500))
        assert isinstance(result, Hex32)

    @pytest.mark.asyncio
    async def test_get_block_hash_non200_raises(self):
        src = self._src()
        session = MagicMock()
        session.get = MagicMock(return_value=_text_resp("not found", status=404))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_hash(BlockHeight(500))

    @pytest.mark.asyncio
    async def test_get_block_hash_bad_hex_raises(self):
        src = self._src()
        session = MagicMock()
        session.get = MagicMock(return_value=_text_resp("not-hex!!"))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_block_hash(BlockHeight(500))

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_unknown(self):
        src = self._src()
        data = {"vout": [{"scriptpubkey_type": "nonstandard"}]}
        session = MagicMock()
        session.get = MagicMock(return_value=_json_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_tx_output_script_type(Txid("ab" * 32), 0)
        assert result == "unknown"

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_bad_index_raises(self):
        src = self._src()
        data = {"vout": []}
        session = MagicMock()
        session.get = MagicMock(return_value=_json_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_tx_output_script_type(Txid("ab" * 32), 99)

    @pytest.mark.asyncio
    async def test_get_merkle_proof_bad_response_raises(self):
        src = self._src()
        data = {"no_merkle_key": True}
        session = MagicMock()
        session.get = MagicMock(return_value=_json_resp(data))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_merkle_proof(Txid("ab" * 32), BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_header_chain_happy(self):
        src = self._src()
        hash_hex = "cc" * 32
        header_hex = "dd" * 80
        # get_block_header_hex calls get_block_hash then _get_hex_bytes
        # _get_hex_bytes expects a hex-encoded text body
        session = MagicMock()
        resps = iter([_text_resp(hash_hex), _text_resp(header_hex)])
        session.get = MagicMock(side_effect=lambda *a, **kw: next(resps))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            headers = await src.get_header_chain(BlockHeight(100), 1)
        assert len(headers) == 1

    @pytest.mark.asyncio
    async def test_get_header_chain_zero_count_raises(self):
        src = self._src()
        with pytest.raises(ValidationError):
            await src.get_header_chain(BlockHeight(100), 0)

    @pytest.mark.asyncio
    async def test_get_raw_tx_min_confirmations_zero(self):
        """min_confirmations=0 should skip the tip fetch."""
        src = self._src()
        status_data = {"confirmed": True, "block_height": 800000}
        raw_hex = "aa" * 65
        session = MagicMock()
        resps = iter([_json_resp(status_data), _text_resp(raw_hex)])
        session.get = MagicMock(side_effect=lambda *a, **kw: next(resps))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_raw_tx(Txid("ab" * 32), min_confirmations=0)
        assert bytes(result) == bytes.fromhex(raw_hex)


# ──────────────────────────────────────────────────────────────────────────────
# MempoolSpaceSource — additional error branches
# ──────────────────────────────────────────────────────────────────────────────

class TestMempoolSpaceSourceAdditional:

    def _src(self):
        return MempoolSpaceSource()

    @pytest.mark.asyncio
    async def test_get_raw_tx_min_confirmations_zero(self):
        """min_confirmations=0 should skip the tip fetch."""
        src = self._src()
        status_data = {"confirmed": True, "block_height": 800000}
        raw_hex = "aa" * 65
        session = MagicMock()
        resps = iter([_json_resp(status_data), _text_resp(raw_hex)])
        session.get = MagicMock(side_effect=lambda *a, **kw: next(resps))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            result = await src.get_raw_tx(Txid("ab" * 32), min_confirmations=0)
        assert bytes(result) == bytes.fromhex(raw_hex)

    @pytest.mark.asyncio
    async def test_get_raw_tx_invalid_hex_raises(self):
        src = self._src()
        status_data = {"confirmed": True, "block_height": 800000}
        session = MagicMock()
        resps = iter([
            _json_resp(status_data),
            _json_resp(840000),  # tip height
            _text_resp("not valid hex!!"),
        ])
        session.get = MagicMock(side_effect=lambda *a, **kw: next(resps))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx(Txid("ab" * 32), min_confirmations=1)

    @pytest.mark.asyncio
    async def test_get_raw_tx_non200_raises(self):
        src = self._src()
        status_data = {"confirmed": True, "block_height": 800000}
        session = MagicMock()
        resps = iter([
            _json_resp(status_data),
            _json_resp(840000),  # tip height
            _text_resp("not found", status=404),
        ])
        session.get = MagicMock(side_effect=lambda *a, **kw: next(resps))
        with patch.object(src, "_get_session", AsyncMock(return_value=session)):
            with pytest.raises(NetworkError):
                await src.get_raw_tx(Txid("ab" * 32), min_confirmations=1)

    @pytest.mark.asyncio
    async def test_close_already_none(self):
        src = MempoolSpaceSource()
        src._session = None
        await src.close()  # Should not raise


# ──────────────────────────────────────────────────────────────────────────────
# MultiSourceBtcDataSource — remaining branches
# ──────────────────────────────────────────────────────────────────────────────

class TestMultiSourceAdditional:
    """Cover branches in MultiSourceBtcDataSource not hit by existing tests."""

    def _make_mock_source(self, height=840000, block_hash="aa" * 32, raw_hex="bb" * 65,
                          script_type="p2pkh", tx_block_height=800000):
        s = MagicMock()
        s.get_tip_height = AsyncMock(return_value=BlockHeight(height))
        s.get_block_hash = AsyncMock(return_value=Hex32(bytes.fromhex(block_hash)))
        s.get_block_header_hex = AsyncMock(return_value=bytes.fromhex("cc" * 80))
        s.get_header_chain = AsyncMock(return_value=[bytes.fromhex("cc" * 80)])
        s.get_raw_tx = AsyncMock(return_value=RawTx(bytes.fromhex(raw_hex)))
        s.get_tx_block_height = AsyncMock(return_value=BlockHeight(tx_block_height))
        s.get_tx_output_script_type = AsyncMock(return_value=script_type)
        s.get_merkle_proof = AsyncMock(return_value=(["hash1", "hash2"], 0))
        return s

    @pytest.mark.asyncio
    async def test_get_header_chain_quorum(self):
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        result = await multi.get_header_chain(BlockHeight(100), 1)
        assert result == [bytes.fromhex("cc" * 80)]

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_no_quorum_raises(self):
        """If sources disagree, quorum not reached → NetworkError."""
        s1 = self._make_mock_source(script_type="p2pkh")
        s2 = self._make_mock_source(script_type="p2sh")
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        with pytest.raises(NetworkError, match="quorum"):
            await multi.get_tx_output_script_type(Txid("ab" * 32), 0)

    @pytest.mark.asyncio
    async def test_get_block_hash_no_quorum_raises(self):
        s1 = self._make_mock_source(block_hash="aa" * 32)
        s2 = self._make_mock_source(block_hash="bb" * 32)
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        with pytest.raises(NetworkError, match="quorum"):
            await multi.get_block_hash(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_block_header_hex_no_quorum_raises(self):
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        s2.get_block_header_hex = AsyncMock(return_value=bytes.fromhex("dd" * 80))
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        with pytest.raises(NetworkError, match="quorum"):
            await multi.get_block_header_hex(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_merkle_proof_no_quorum_raises(self):
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        s2.get_merkle_proof = AsyncMock(return_value=(["hash_different"], 1))
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        with pytest.raises(NetworkError, match="quorum"):
            await multi.get_merkle_proof(Txid("ab" * 32), BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_tx_block_height_coerces_str_txid(self):
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        result = await multi.get_tx_block_height("ab" * 32)  # raw str
        assert int(result) == 800000

    @pytest.mark.asyncio
    async def test_get_tx_output_script_type_coerces_str_txid(self):
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        result = await multi.get_tx_output_script_type("ab" * 32, 0)
        assert result == "p2pkh"

    @pytest.mark.asyncio
    async def test_get_merkle_proof_coerces_str_txid(self):
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        multi = MultiSourceBtcDataSource([s1, s2], quorum=2)
        result = await multi.get_merkle_proof("ab" * 32, 100)  # raw str + int
        assert result == (["hash1", "hash2"], 0)

    @pytest.mark.asyncio
    async def test_require_quorum_with_exceptions(self):
        """One source raises, one succeeds — with quorum=1 should return the value."""
        s1 = self._make_mock_source()
        s2 = self._make_mock_source()
        s2.get_tip_height = AsyncMock(side_effect=NetworkError("down"))
        multi = MultiSourceBtcDataSource([s1, s2], quorum=1)
        result = await multi.get_tip_height()
        assert int(result) == 840000


# ──────────────────────────────────────────────────────────────────────────────
# transaction_preimage.py — _get_push_refs OP_PUSHDATA variants
# ──────────────────────────────────────────────────────────────────────────────

class TestGetPushRefs:
    """Test _get_push_refs for OP_PUSHDATA1/2/4 variants (lines 36, 38, 40)."""

    def _make_ref(self, n=1) -> bytes:
        """36-byte push ref: OP_PUSH_REF(0xd0) + 36 bytes."""
        return bytes([0xd0]) + bytes(range(n, n + 36))

    def _build_script_with_pushdata(self, opcode: int, data: bytes) -> bytes:
        """Build a script byte string with a given PUSHDATA opcode."""
        length = len(data)
        if opcode == 0x4c:  # OP_PUSHDATA1
            return bytes([opcode, length]) + data
        elif opcode == 0x4d:  # OP_PUSHDATA2
            return bytes([opcode]) + length.to_bytes(2, "little") + data
        elif opcode == 0x4e:  # OP_PUSHDATA4
            return bytes([opcode]) + length.to_bytes(4, "little") + data
        raise ValueError(f"Unknown opcode {opcode}")

    def test_pushdata1_skipped(self):
        """OP_PUSHDATA1 with non-ref data should be skipped (no refs returned)."""
        from pyrxd.transaction.transaction_preimage import _get_push_refs
        data = b"\xff" * 16
        script = self._build_script_with_pushdata(0x4c, data)
        refs = _get_push_refs(script)
        assert refs == []

    def test_pushdata2_skipped(self):
        from pyrxd.transaction.transaction_preimage import _get_push_refs
        data = b"\xff" * 100
        script = self._build_script_with_pushdata(0x4d, data)
        refs = _get_push_refs(script)
        assert refs == []

    def test_pushdata4_skipped(self):
        from pyrxd.transaction.transaction_preimage import _get_push_refs
        data = b"\xff" * 200
        script = self._build_script_with_pushdata(0x4e, data)
        refs = _get_push_refs(script)
        assert refs == []

    def test_push_ref_opcode_extracted(self):
        """OP_PUSH_REF (0xd0) followed by 36 bytes should be extracted."""
        from pyrxd.transaction.transaction_preimage import _get_push_refs
        ref_data = bytes(range(36))
        script = bytes([0xd0]) + ref_data
        refs = _get_push_refs(script)
        assert len(refs) == 1
        assert refs[0] == ref_data  # ref is the 36 bytes after the opcode

    def test_mixed_script_only_refs_extracted(self):
        from pyrxd.transaction.transaction_preimage import _get_push_refs
        ref_data = bytes(range(36))
        # OP_PUSHDATA1 (skip) + OP_PUSH_REF (extract)
        script = self._build_script_with_pushdata(0x4c, b"\xab" * 10) + bytes([0xd0]) + ref_data
        refs = _get_push_refs(script)
        # The ref extracted starts from opcode + data
        assert len(refs) == 1

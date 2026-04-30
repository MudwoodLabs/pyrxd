"""Coverage gap tests — fourth batch.

Targets (from 2026-04-24 coverage report):
- merkle_path.py        (59% → target ≥ 80%)
- network/electrumx.py  (73% → target ≥ 85%)
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.merkle_path import MerklePath
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord, _coerce_hex32
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import BlockHeight, Hex32, Txid

# ---------------------------------------------------------------------------
# Helpers — build minimal MerklePaths for testing
# ---------------------------------------------------------------------------


def _leaf_hash(n: int) -> str:
    """Return a deterministic 64-char hex string suitable for a hash field."""
    return format(n, "064x")


def _simple_path(block_height: int = 1000) -> MerklePath:
    """Single-tx Merkle path with one sibling (depth-1 tree)."""
    txid = _leaf_hash(1)
    sibling = _leaf_hash(2)
    # pos=0, sibling is at pos=1
    path = [
        [
            {"offset": 0, "hash_str": txid, "txid": True},
            {"offset": 1, "hash_str": sibling},
        ]
    ]
    return MerklePath(block_height, path)


def _duplicate_path(block_height: int = 1000) -> MerklePath:
    """Single-tx path where sibling is a duplicate."""
    txid = _leaf_hash(1)
    path = [
        [
            {"offset": 0, "hash_str": txid, "txid": True},
            {"offset": 1, "duplicate": True},
        ]
    ]
    return MerklePath(block_height, path)


# ---------------------------------------------------------------------------
# MerklePath — construction
# ---------------------------------------------------------------------------


class TestMerklePathConstruction:
    def test_simple_path(self):
        mp = _simple_path()
        assert mp.block_height == 1000

    def test_duplicate_path(self):
        mp = _duplicate_path()
        assert mp.block_height == 1000

    def test_empty_level_zero_raises(self):
        with pytest.raises(ValueError, match="Empty level"):
            MerklePath(100, [[]])

    def test_duplicate_offset_raises(self):
        txid = _leaf_hash(1)
        path = [
            [
                {"offset": 0, "hash_str": txid, "txid": True},
                {"offset": 0, "hash_str": txid},  # duplicate offset
            ]
        ]
        with pytest.raises(ValueError, match="Duplicate offset"):
            MerklePath(100, path)


# ---------------------------------------------------------------------------
# MerklePath — to_binary / from_binary / to_hex / from_hex roundtrip
# ---------------------------------------------------------------------------


class TestMerklePathSerialization:
    def test_to_from_binary_roundtrip(self):
        mp = _simple_path()
        binary = mp.to_binary()
        mp2 = MerklePath.from_binary(binary)
        assert mp2.block_height == mp.block_height
        assert len(mp2.path) == len(mp.path)

    def test_to_from_hex_roundtrip(self):
        mp = _simple_path()
        hex_str = mp.to_hex()
        mp2 = MerklePath.from_hex(hex_str)
        assert mp2.block_height == mp.block_height

    def test_duplicate_flag_serialized(self):
        mp = _duplicate_path()
        binary = mp.to_binary()
        mp2 = MerklePath.from_binary(binary)
        # Reconstruct — duplicate leaf should survive
        level = mp2.path[0]
        dup_leaves = [l for l in level if l.get("duplicate")]
        assert len(dup_leaves) == 1

    def test_txid_flag_serialized(self):
        mp = _simple_path()
        binary = mp.to_binary()
        mp2 = MerklePath.from_binary(binary)
        txid_leaves = [l for l in mp2.path[0] if l.get("txid")]
        assert len(txid_leaves) == 1


# ---------------------------------------------------------------------------
# MerklePath — compute_root
# ---------------------------------------------------------------------------


class TestMerklePathComputeRoot:
    def test_compute_root_with_txid(self):
        mp = _simple_path()
        txid = _leaf_hash(1)
        root = mp.compute_root(txid)
        assert isinstance(root, str) and len(root) == 64

    def test_compute_root_without_txid(self):
        mp = _simple_path()
        root = mp.compute_root()
        assert isinstance(root, str) and len(root) == 64

    def test_compute_root_unknown_txid_raises(self):
        mp = _simple_path()
        with pytest.raises(ValueError, match="does not contain"):
            mp.compute_root("ff" * 32)

    def test_compute_root_duplicate(self):
        mp = _duplicate_path()
        txid = _leaf_hash(1)
        root = mp.compute_root(txid)
        assert isinstance(root, str)

    def test_compute_root_consistent(self):
        mp = _simple_path()
        txid = _leaf_hash(1)
        root1 = mp.compute_root(txid)
        root2 = mp.compute_root(txid)
        assert root1 == root2


# ---------------------------------------------------------------------------
# MerklePath — combine
# ---------------------------------------------------------------------------


class TestMerklePathCombine:
    def _twin_paths(self):
        """Two paths at the same block height with the same root."""
        txid_a = _leaf_hash(1)
        txid_b = _leaf_hash(2)
        # Path A: tx at offset 0, sibling (tx B's hash) at offset 1
        path_a = [
            [
                {"offset": 0, "hash_str": txid_a, "txid": True},
                {"offset": 1, "hash_str": txid_b},
            ]
        ]
        # Path B: tx at offset 1, sibling (tx A's hash) at offset 0
        path_b = [
            [
                {"offset": 1, "hash_str": txid_b, "txid": True},
                {"offset": 0, "hash_str": txid_a},
            ]
        ]
        return MerklePath(500, path_a), MerklePath(500, path_b)

    def test_combine_same_height_and_root(self):
        mp_a, mp_b = self._twin_paths()
        mp_a.compute_root()
        mp_a.combine(mp_b)
        # Combined path should have more leaves
        assert len(mp_a.path[0]) >= 2

    def test_combine_different_height_raises(self):
        mp_a = _simple_path(block_height=100)
        mp_b = _simple_path(block_height=200)
        with pytest.raises(ValueError, match="block height"):
            mp_a.combine(mp_b)

    def test_combine_different_root_raises(self):
        # Same height but different leaves → different root
        txid1 = _leaf_hash(1)
        sibling1 = _leaf_hash(2)
        path_a = [[{"offset": 0, "hash_str": txid1, "txid": True}, {"offset": 1, "hash_str": sibling1}]]
        txid2 = _leaf_hash(3)
        sibling2 = _leaf_hash(4)
        path_b = [[{"offset": 0, "hash_str": txid2, "txid": True}, {"offset": 1, "hash_str": sibling2}]]
        mp_a = MerklePath(100, path_a)
        mp_b = MerklePath(100, path_b)
        with pytest.raises(ValueError, match="same root"):
            mp_a.combine(mp_b)


# ---------------------------------------------------------------------------
# MerklePath — trim
# ---------------------------------------------------------------------------


class TestMerklePathTrim:
    def test_trim_does_not_raise(self):
        mp, _ = TestMerklePathCombine()._twin_paths()
        mp.trim()  # Should not raise

    def test_combined_then_trim(self):
        tc = TestMerklePathCombine()
        mp_a, mp_b = tc._twin_paths()
        mp_a.combine(mp_b)
        # After combine, trim is called internally — should still be valid
        root = mp_a.compute_root()
        assert isinstance(root, str)


# ---------------------------------------------------------------------------
# MerklePath — find_or_compute_leaf
# ---------------------------------------------------------------------------


class TestFindOrComputeLeaf:
    def test_find_existing_leaf(self):
        mp = _simple_path()
        leaf = mp.find_or_compute_leaf(0, 1)
        assert leaf is not None
        assert leaf["offset"] == 1

    def test_compute_missing_leaf_at_height_zero(self):
        mp = _simple_path()
        # Offset 5 doesn't exist at height 0 — should return None
        result = mp.find_or_compute_leaf(0, 5)
        assert result is None


# ---------------------------------------------------------------------------
# MerklePath — verify (async, mocked chain tracker)
# ---------------------------------------------------------------------------


class TestMerklePathVerify:
    @pytest.mark.asyncio
    async def test_verify_valid(self):
        mp = _simple_path()
        txid = _leaf_hash(1)
        root = mp.compute_root(txid)

        mock_tracker = AsyncMock()
        mock_tracker.is_valid_root_for_height = AsyncMock(return_value=True)

        result = await mp.verify(txid, mock_tracker)
        assert result is True
        mock_tracker.is_valid_root_for_height.assert_awaited_once_with(root, 1000)

    @pytest.mark.asyncio
    async def test_verify_invalid(self):
        mp = _simple_path()
        txid = _leaf_hash(1)

        mock_tracker = AsyncMock()
        mock_tracker.is_valid_root_for_height = AsyncMock(return_value=False)

        result = await mp.verify(txid, mock_tracker)
        assert result is False


# ---------------------------------------------------------------------------
# _coerce_hex32
# ---------------------------------------------------------------------------


class TestCoerceHex32:
    def test_passthrough_hex32(self):
        h = Hex32(bytes.fromhex("ab" * 32))
        assert _coerce_hex32(h) is h

    def test_from_bytes(self):
        raw = bytes.fromhex("cd" * 32)
        result = _coerce_hex32(raw)
        assert isinstance(result, Hex32)

    def test_from_bytearray(self):
        raw = bytearray(bytes.fromhex("ef" * 32))
        result = _coerce_hex32(raw)
        assert isinstance(result, Hex32)

    def test_from_hex_str(self):
        result = _coerce_hex32("ab" * 32)
        assert isinstance(result, Hex32)

    def test_bad_type_raises(self):
        with pytest.raises(ValidationError):
            _coerce_hex32(12345)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ElectrumXClient — construction
# ---------------------------------------------------------------------------


class TestElectrumXClientConstruction:
    def test_empty_urls_raises(self):
        with pytest.raises(ValidationError, match="at least one"):
            ElectrumXClient([])

    def test_insecure_url_raises(self):
        with pytest.raises(NetworkError, match="Insecure"):
            ElectrumXClient(["ws://example.com"])

    def test_insecure_url_allowed(self):
        client = ElectrumXClient(["ws://example.com"], allow_insecure=True)
        assert client is not None

    def test_bad_scheme_raises(self):
        with pytest.raises(NetworkError, match="wss://"):
            ElectrumXClient(["http://example.com"])

    def test_wss_valid(self):
        client = ElectrumXClient(["wss://electrumx.example.com"])
        assert client is not None


# ---------------------------------------------------------------------------
# ElectrumXClient — public API (mocked _call)
# ---------------------------------------------------------------------------

TXID_STR = "ab" * 32
RAW_TX_HEX = "aa" * 65  # must be > 64 bytes for RawTx


class TestElectrumXClientAPI:
    def _client(self) -> ElectrumXClient:
        return ElectrumXClient(["wss://example.com"])

    @pytest.mark.asyncio
    async def test_get_transaction_happy(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=RAW_TX_HEX)):
            raw = await client.get_transaction(Txid(TXID_STR))
        assert bytes(raw) == bytes.fromhex(RAW_TX_HEX)

    @pytest.mark.asyncio
    async def test_get_transaction_non_str_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=12345)):
            with pytest.raises(NetworkError, match="Unexpected response"):
                await client.get_transaction(Txid(TXID_STR))

    @pytest.mark.asyncio
    async def test_get_transaction_bad_hex_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value="not-hex")):
            with pytest.raises(NetworkError, match="invalid hex"):
                await client.get_transaction(Txid(TXID_STR))

    @pytest.mark.asyncio
    async def test_get_tip_height_happy(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value={"height": 800000})):
            h = await client.get_tip_height()
        assert int(h) == 800000

    @pytest.mark.asyncio
    async def test_get_tip_height_non_dict_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=[800000])):
            with pytest.raises(NetworkError, match="Unexpected response"):
                await client.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_tip_height_bad_structure_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value={"bad_key": 0})):
            with pytest.raises(NetworkError, match="Malformed"):
                await client.get_tip_height()

    @pytest.mark.asyncio
    async def test_get_block_header_happy(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value="ff" * 80)):
            header = await client.get_block_header(BlockHeight(100))
        assert len(header) == 80

    @pytest.mark.asyncio
    async def test_get_block_header_wrong_length_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value="deadbeef")):
            with pytest.raises(NetworkError, match="80 bytes"):
                await client.get_block_header(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_block_header_non_str_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=12345)):
            with pytest.raises(NetworkError, match="Unexpected response"):
                await client.get_block_header(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_get_block_header_bad_hex_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value="not-hex")):
            with pytest.raises(NetworkError, match="invalid hex"):
                await client.get_block_header(BlockHeight(100))

    @pytest.mark.asyncio
    async def test_broadcast_happy(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=TXID_STR)):
            txid = await client.broadcast(bytes.fromhex("aa" * 65))
        assert str(txid) == TXID_STR

    @pytest.mark.asyncio
    async def test_broadcast_non_str_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=12345)):
            with pytest.raises(NetworkError, match="Unexpected response"):
                await client.broadcast(bytes.fromhex("aa" * 65))

    @pytest.mark.asyncio
    async def test_broadcast_invalid_txid_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value="not-a-txid")):
            with pytest.raises(NetworkError, match="invalid txid"):
                await client.broadcast(bytes.fromhex("aa" * 65))

    @pytest.mark.asyncio
    async def test_get_balance_happy(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value={"confirmed": 1000, "unconfirmed": 0})):
            conf, unconf = await client.get_balance("ab" * 32)
        assert int(conf) == 1000
        assert int(unconf) == 0

    @pytest.mark.asyncio
    async def test_get_balance_non_dict_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value=[1000])):
            with pytest.raises(NetworkError, match="Unexpected response"):
                await client.get_balance("ab" * 32)

    @pytest.mark.asyncio
    async def test_get_balance_malformed_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value={"bad_key": 0})):
            with pytest.raises(NetworkError, match="Malformed"):
                await client.get_balance("ab" * 32)

    @pytest.mark.asyncio
    async def test_get_utxos_happy(self):
        client = self._client()
        utxos = [{"tx_hash": TXID_STR, "tx_pos": 0, "value": 10000, "height": 100}]
        with patch.object(client, "_call", AsyncMock(return_value=utxos)):
            result = await client.get_utxos("ab" * 32)
        assert len(result) == 1
        assert isinstance(result[0], UtxoRecord)
        assert result[0].tx_hash == TXID_STR
        assert result[0].tx_pos == 0
        assert result[0].value == 10000
        assert result[0].height == 100

    @pytest.mark.asyncio
    async def test_get_utxos_non_list_raises(self):
        client = self._client()
        with patch.object(client, "_call", AsyncMock(return_value={})):
            with pytest.raises(NetworkError, match="Unexpected response"):
                await client.get_utxos("ab" * 32)

    @pytest.mark.asyncio
    async def test_close_connected(self):
        client = self._client()
        mock_ws = AsyncMock()
        client._ws = mock_ws
        await client.close()
        mock_ws.close.assert_awaited_once()
        assert client._ws is None

    @pytest.mark.asyncio
    async def test_close_not_connected(self):
        client = self._client()
        client._ws = None
        await client.close()  # should not raise


# ---------------------------------------------------------------------------
# ElectrumXClient — _call internals (response parsing)
# ---------------------------------------------------------------------------


class TestElectrumXCallParsing:
    def _client(self) -> ElectrumXClient:
        # Short timeout so timeout-paths (malformed reader messages that get
        # dropped) don't stall the suite for 30s.
        return ElectrumXClient(["wss://example.com"], timeout=0.2)

    def _make_ws(self, responses: list) -> MagicMock:
        """Return a fake WebSocket that yields responses in order, then hangs.

        The post-correlation reader calls ``recv()`` continuously. Once the
        scripted responses are exhausted we must block (real WebSocket
        behavior) so the reader doesn't crash on StopAsyncIteration and
        leave the test hanging on a different code path.
        """
        ws = MagicMock()
        ws.send = AsyncMock()

        iterator = iter(responses)

        async def _recv():
            try:
                return next(iterator)
            except StopIteration:
                # No more scripted responses — block so the reader stays
                # waiting like a real socket would.
                await asyncio.Event().wait()
                return None  # unreachable; satisfies static analyzers

        ws.recv = _recv
        ws.close = AsyncMock()
        return ws

    @pytest.mark.asyncio
    async def test_call_rpc_error_with_code(self):
        client = self._client()
        resp = json.dumps({"id": 1, "result": None, "error": {"code": 404, "message": "not found"}})
        ws = self._make_ws([resp])
        client._ws = ws
        with pytest.raises(NetworkError, match="code 404"):
            await client._call("some.method", [])

    @pytest.mark.asyncio
    async def test_call_rpc_error_non_dict(self):
        client = self._client()
        resp = json.dumps({"id": 1, "result": None, "error": "simple error string"})
        ws = self._make_ws([resp])
        client._ws = ws
        with pytest.raises(NetworkError, match="RPC error"):
            await client._call("some.method", [])

    @pytest.mark.asyncio
    async def test_call_missing_result_field_raises(self):
        client = self._client()
        resp = json.dumps({"id": 1})  # no 'result'
        ws = self._make_ws([resp])
        client._ws = ws
        with pytest.raises(NetworkError, match="missing 'result'"):
            await client._call("some.method", [])

    @pytest.mark.asyncio
    async def test_call_non_json_message_dropped(self):
        """Non-JSON wire bytes are dropped by the reader and do NOT poison
        a pending caller — they just don't dispatch. The call subsequently
        times out (default contract: callers rely on timeout, not malformed
        pollution, to bound wait time).
        """
        client = self._client()
        ws = self._make_ws(["not json at all"])
        client._ws = ws
        with pytest.raises(NetworkError, match="timed out"):
            await client._call("some.method", [])

    @pytest.mark.asyncio
    async def test_call_non_dict_message_dropped(self):
        """Non-dict JSON (e.g. a top-level list) is dropped and the call
        times out — same contract as non-JSON. The reader will not match
        a pending future against a malformed message.
        """
        client = self._client()
        resp = json.dumps([1, 2, 3])  # list, not dict
        ws = self._make_ws([resp])
        client._ws = ws
        with pytest.raises(NetworkError, match="timed out"):
            await client._call("some.method", [])

    @pytest.mark.asyncio
    async def test_call_oversized_bytes_raises(self):
        client = self._client()
        big = b"x" * (10 * 1024 * 1024 + 1)
        ws = self._make_ws([big])
        client._ws = ws
        with pytest.raises(NetworkError, match="exceeds maximum"):
            await client._call("some.method", [])

    @pytest.mark.asyncio
    async def test_call_oversized_str_raises(self):
        client = self._client()
        big = "x" * (10 * 1024 * 1024 + 1)
        ws = self._make_ws([big])
        client._ws = ws
        with pytest.raises(NetworkError, match="exceeds maximum"):
            await client._call("some.method", [])

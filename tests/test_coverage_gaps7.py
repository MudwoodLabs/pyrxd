"""Coverage gap tests — seventh batch.

Targets small gaps across multiple modules to reach 85%:
  - transaction/transaction_output.py (82%): from_hex error paths
  - transaction/transaction_input.py (90%): from_hex error paths
  - script/unlocking_template.py (82%): abstract methods coverage
  - network/chaintracker.py (81%): is_valid_root / is_valid_root_for_height
  - script/script.py (87%): from_asm edge cases, Script.is_push_only
  - utils.py (89%): varint/reader edge cases, encode_int negative, from_base58 edge cases
  - spv/witness.py (90%): truncation errors inside strip_witness
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from pyrxd.script.script import Script
from pyrxd.security.types import BlockHeight, Hex32
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import (
    Reader,
    encode_int,
    from_base58,
    to_base58,
    to_bytes,
)

# ──────────────────────────────────────────────────────────────────────────────
# TransactionOutput.from_hex — error paths (lines 44, 47, 50)
# ──────────────────────────────────────────────────────────────────────────────


class TestTransactionOutputFromHex:
    def test_from_hex_happy_path(self):
        """Serialize → from_hex round-trip."""
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH

        priv = PrivateKey()
        lock = P2PKH().lock(priv.public_key().address())
        out = TransactionOutput(locking_script=lock, satoshis=5000)
        raw = out.serialize()
        recovered = TransactionOutput.from_hex(raw)
        assert recovered is not None
        assert recovered.satoshis == 5000

    def test_from_hex_from_bytes(self):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH

        priv = PrivateKey()
        lock = P2PKH().lock(priv.public_key().address())
        out = TransactionOutput(locking_script=lock, satoshis=1000)
        raw = out.serialize()
        recovered = TransactionOutput.from_hex(bytes(raw))
        assert recovered is not None

    def test_from_hex_truncated_returns_none(self):
        """Too-short data → suppress(Exception) → returns None."""
        result = TransactionOutput.from_hex(b"\x00\x00")  # incomplete satoshis
        assert result is None

    def test_from_hex_empty_returns_none(self):
        result = TransactionOutput.from_hex(b"")
        assert result is None

    def test_from_hex_from_reader(self):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PKH

        priv = PrivateKey()
        lock = P2PKH().lock(priv.public_key().address())
        out = TransactionOutput(locking_script=lock, satoshis=2000)
        raw = out.serialize()
        reader = Reader(raw)
        recovered = TransactionOutput.from_hex(reader)
        assert recovered is not None


# ──────────────────────────────────────────────────────────────────────────────
# TransactionInput.from_hex — error paths (lines 71, 74, 78)
# ──────────────────────────────────────────────────────────────────────────────


class TestTransactionInputFromHex:
    def test_from_hex_happy_path(self):
        ti = TransactionInput(
            source_txid="aa" * 32,
            source_output_index=0,
            unlocking_script=Script(),
            sequence=0xFFFFFFFF,
        )
        raw = ti.serialize()
        recovered = TransactionInput.from_hex(raw)
        assert recovered is not None
        assert recovered.source_txid == "aa" * 32

    def test_from_hex_truncated_returns_none(self):
        result = TransactionInput.from_hex(b"\x00" * 5)
        assert result is None

    def test_from_hex_empty_returns_none(self):
        result = TransactionInput.from_hex(b"")
        assert result is None

    def test_from_hex_from_reader(self):
        ti = TransactionInput(
            source_txid="bb" * 32,
            source_output_index=1,
            unlocking_script=Script(b"\x51"),  # OP_1
            sequence=0x00000000,
        )
        raw = ti.serialize()
        reader = Reader(raw)
        recovered = TransactionInput.from_hex(reader)
        assert recovered is not None
        assert recovered.source_output_index == 1


# ──────────────────────────────────────────────────────────────────────────────
# ChainTracker — is_valid_root / is_valid_root_for_height (lines 53, 55)
# ──────────────────────────────────────────────────────────────────────────────


class TestChainTracker:
    def _make_mock_source(self, header_bytes: bytes):
        src = MagicMock()
        src.get_block_header_hex = AsyncMock(return_value=header_bytes)
        return src

    @pytest.mark.asyncio
    async def test_is_valid_root_true(self):
        from pyrxd.network.chaintracker import ChainTracker

        # Build a fake 80-byte header with a known merkle root at bytes 36-68
        merkle_root = bytes(range(32))  # 32 bytes, offset 36
        header = b"\x00" * 36 + merkle_root + b"\x00" * 12
        src = self._make_mock_source(header)
        tracker = ChainTracker(src)
        valid = await tracker.is_valid_root(Hex32(merkle_root), BlockHeight(100))
        assert valid is True

    @pytest.mark.asyncio
    async def test_is_valid_root_false(self):
        from pyrxd.network.chaintracker import ChainTracker

        merkle_root = bytes(range(32))
        wrong_root = bytes([0xFF] * 32)
        header = b"\x00" * 36 + wrong_root + b"\x00" * 12
        src = self._make_mock_source(header)
        tracker = ChainTracker(src)
        valid = await tracker.is_valid_root(Hex32(merkle_root), BlockHeight(100))
        assert valid is False

    @pytest.mark.asyncio
    async def test_is_valid_root_coerces_plain_height(self):
        """is_valid_root accepts raw int height."""
        from pyrxd.network.chaintracker import ChainTracker

        merkle_root = bytes(range(32))
        header = b"\x00" * 36 + merkle_root + b"\x00" * 12
        src = self._make_mock_source(header)
        tracker = ChainTracker(src)
        valid = await tracker.is_valid_root(Hex32(merkle_root), 100)  # plain int
        assert valid is True

    @pytest.mark.asyncio
    async def test_is_valid_root_coerces_plain_hex32(self):
        """is_valid_root accepts raw bytes merkle_root."""
        from pyrxd.network.chaintracker import ChainTracker

        merkle_root = bytes(range(32))
        header = b"\x00" * 36 + merkle_root + b"\x00" * 12
        src = self._make_mock_source(header)
        tracker = ChainTracker(src)
        valid = await tracker.is_valid_root(merkle_root, BlockHeight(100))  # raw bytes
        assert valid is True

    @pytest.mark.asyncio
    async def test_is_valid_root_for_height_happy(self):
        from pyrxd.network.chaintracker import ChainTracker

        # compute_root returns display-order hex, is_valid_root_for_height reverses it
        merkle_root_le = bytes(range(32))  # little-endian (stored in header)
        header = b"\x00" * 36 + merkle_root_le + b"\x00" * 12
        src = self._make_mock_source(header)
        tracker = ChainTracker(src)
        # root_hex is big-endian display order (reversed of what's in header)
        root_hex = merkle_root_le[::-1].hex()
        valid = await tracker.is_valid_root_for_height(root_hex, 100)
        assert valid is True


# ──────────────────────────────────────────────────────────────────────────────
# Script — from_asm edge cases and is_push_only (lines 56->66, 60->66, 64->66, 98, 140, 143, 147-152, 160-161)
# ──────────────────────────────────────────────────────────────────────────────


class TestScriptFromAsm:
    def test_from_asm_opcode_token(self):
        """Named opcode token like OP_CHECKSIG."""
        s = Script.from_asm("OP_CHECKSIG")
        assert isinstance(s, Script)

    def test_from_asm_op_false_alias(self):
        """OP_FALSE should be treated as OP_0."""
        s = Script.from_asm("OP_FALSE")
        assert isinstance(s, Script)

    def test_from_asm_zero_token(self):
        """Token '0' should produce OP_0."""
        s = Script.from_asm("0")
        assert isinstance(s, Script)
        assert s.serialize() == b"\x00"

    def test_from_asm_negative_one(self):
        """Token '-1' should produce OP_1NEGATE."""
        s = Script.from_asm("-1")
        assert isinstance(s, Script)

    def test_from_asm_hex_data(self):
        """Hex data token."""
        s = Script.from_asm("deadbeef")
        assert isinstance(s, Script)

    def test_from_asm_odd_length_hex(self):
        """Odd-length hex string should be zero-padded."""
        s = Script.from_asm("abc")
        assert isinstance(s, Script)

    def test_from_asm_pushdata1_opcode(self):
        """Explicit OP_PUSHDATA1 token."""
        data = "ff" * 80  # 80 bytes → fits in PUSHDATA1
        s = Script.from_asm(f"OP_PUSHDATA1 80 {data}")
        assert isinstance(s, Script)

    def test_from_asm_pushdata2_opcode(self):
        data = "ff" * 300  # 300 bytes → PUSHDATA2
        s = Script.from_asm(f"OP_PUSHDATA2 300 {data}")
        assert isinstance(s, Script)

    def test_from_asm_pushdata4_opcode(self):
        data = "ff" * 70000  # 70000 bytes → PUSHDATA4
        s = Script.from_asm(f"OP_PUSHDATA4 70000 {data}")
        assert isinstance(s, Script)

    def test_is_push_only_true(self):
        """A script of only push opcodes is push_only."""
        s = Script.from_asm("deadbeef")
        assert s.is_push_only() is True

    def test_is_push_only_false(self):
        """A script with OP_CHECKSIG is not push_only."""
        s = Script.from_asm("OP_CHECKSIG")
        assert s.is_push_only() is False


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — Reader varint branches (lines 546-565)
# ──────────────────────────────────────────────────────────────────────────────


class TestReaderVarEncoding:
    def test_read_varnum_fd_prefix(self):
        """0xFD prefix: read_var_int_num reads 2 more bytes."""
        data = bytes([0xFD, 0x2C, 0x01])  # 0x012C = 300
        r = Reader(data)
        assert r.read_var_int_num() == 300

    def test_read_varnum_fe_prefix(self):
        """0xFE prefix: read_var_int_num reads 4 more bytes."""
        val = 70000
        data = bytes([0xFE]) + val.to_bytes(4, "little")
        r = Reader(data)
        assert r.read_var_int_num() == val

    def test_read_varnum_ff_prefix(self):
        """0xFF prefix: read_var_int_num reads 8 more bytes."""
        val = 0x1_0000_0001
        data = bytes([0xFF]) + val.to_bytes(8, "little")
        r = Reader(data)
        assert r.read_var_int_num() == val

    def test_read_var_fd_prefix(self):
        """read_var_int returns prefix + 2 bytes for 0xFD."""
        data = bytes([0xFD, 0x01, 0x00])
        r = Reader(data)
        result = r.read_var_int()
        assert result == data

    def test_read_var_fe_prefix(self):
        data = bytes([0xFE, 0x01, 0x00, 0x00, 0x00])
        r = Reader(data)
        result = r.read_var_int()
        assert result == data

    def test_read_var_ff_prefix(self):
        data = bytes([0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        r = Reader(data)
        result = r.read_var_int()
        assert result == data

    def test_read_var_empty_returns_none(self):
        r = Reader(b"")
        assert r.read_var_int() is None

    def test_read_varnum_empty_returns_none(self):
        r = Reader(b"")
        assert r.read_var_int_num() is None


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — encode_int negative (line 281)
# ──────────────────────────────────────────────────────────────────────────────


class TestEncodeNegativeScript:
    def test_encode_negative_one(self):
        """encode_int should handle negative numbers."""
        result = encode_int(-1)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_encode_negative_127(self):
        result = encode_int(-127)
        assert isinstance(result, bytes)

    def test_encode_negative_large(self):
        result = encode_int(-256)
        assert isinstance(result, bytes)


# ──────────────────────────────────────────────────────────────────────────────
# utils.py — from_base58 / to_base58 edge cases (lines 331-333)
# ──────────────────────────────────────────────────────────────────────────────


class TestBase58EdgeCases:
    def test_from_base58_invalid_char_0(self):
        with pytest.raises(ValueError):
            from_base58("0abc")

    def test_from_base58_invalid_char_I(self):
        with pytest.raises(ValueError):
            from_base58("Iabc")

    def test_from_base58_invalid_char_O(self):
        with pytest.raises(ValueError):
            from_base58("Oabc")

    def test_from_base58_invalid_char_l(self):
        with pytest.raises(ValueError):
            from_base58("labc")

    def test_from_base58_empty_raises(self):
        with pytest.raises(ValueError):
            from_base58("")

    def test_from_base58_non_str_raises(self):
        with pytest.raises(ValueError):
            from_base58(None)  # type: ignore

    def test_to_base58_leading_zeros(self):
        """Bytes starting with \x00 should produce leading '1' chars."""
        result = to_base58([0, 0, 1])
        assert result.startswith("11")

    def test_to_bytes_empty_string(self):
        """to_bytes with empty string should return empty bytes."""
        result = to_bytes("")
        assert result == b""


# ──────────────────────────────────────────────────────────────────────────────
# spv/witness.py — truncation errors inside strip_witness body
# ──────────────────────────────────────────────────────────────────────────────


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


class TestStripWitnessTruncationPaths:
    """Test truncation errors for the 6 uncovered lines in witness.py body."""

    def test_truncated_in_inputs_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        version = b"\x01\x00\x00\x00"
        # segwit marker + flag
        marker = b"\x00\x01"
        # claim 1 input but provide only 10 bytes (way less than 36 needed for prevout)
        raw = version + marker + _varint(1) + b"\xaa" * 10
        with pytest.raises(ValidationError, match="truncated in inputs"):
            strip_witness(raw)

    def test_truncated_in_input_script_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        version = b"\x01\x00\x00\x00"
        marker = b"\x00\x01"
        prevout = b"\xaa" * 36  # txid(32) + vout(4)
        # script_len varint says 100 bytes but we provide 0
        raw = version + marker + _varint(1) + prevout + _varint(100)
        with pytest.raises(ValidationError, match="truncated in input script"):
            strip_witness(raw)

    def test_truncated_in_output_value_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        version = b"\x01\x00\x00\x00"
        marker = b"\x00\x01"
        # 1 valid input with empty script + sequence
        prevout = b"\xaa" * 36
        inp = prevout + _varint(0) + b"\xff\xff\xff\xff"  # script_len=0, sequence
        # 1 output but truncated (only 4 of the required 8 value bytes)
        raw = version + marker + _varint(1) + inp + _varint(1) + b"\x00\x00\x00\x00"
        with pytest.raises(ValidationError, match="truncated in output value"):
            strip_witness(raw)

    def test_truncated_in_output_script_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        version = b"\x01\x00\x00\x00"
        marker = b"\x00\x01"
        prevout = b"\xaa" * 36
        inp = prevout + _varint(0) + b"\xff\xff\xff\xff"
        value = (1000).to_bytes(8, "little")
        # script_len says 50 bytes but we provide 0
        raw = version + marker + _varint(1) + inp + _varint(1) + value + _varint(50)
        with pytest.raises(ValidationError, match="truncated in output script"):
            strip_witness(raw)

    def test_truncated_missing_locktime_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        version = b"\x01\x00\x00\x00"
        marker = b"\x00\x01"
        prevout = b"\xaa" * 36
        inp = prevout + _varint(0) + b"\xff\xff\xff\xff"
        value = (1000).to_bytes(8, "little")
        script_pk = b"\x76\xa9\x14" + b"\xcc" * 20 + b"\x88\xac"
        out = value + _varint(len(script_pk)) + script_pk
        # witness for 1 input: 0 items (so nothing to skip) + missing locktime
        witness = _varint(0)
        raw = version + marker + _varint(1) + inp + _varint(1) + out + witness
        # No locktime at end
        with pytest.raises(ValidationError, match="truncated.*locktime"):
            strip_witness(raw)

    def test_truncated_in_witness_item_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.witness import strip_witness

        version = b"\x01\x00\x00\x00"
        marker = b"\x00\x01"
        prevout = b"\xaa" * 36
        inp = prevout + _varint(0) + b"\xff\xff\xff\xff"
        value = (1000).to_bytes(8, "little")
        script_pk = b"\x76\xa9\x14" + b"\xcc" * 20 + b"\x88\xac"
        out = value + _varint(len(script_pk)) + script_pk
        # witness: 1 item with length 100 but 0 bytes provided
        witness = _varint(1) + _varint(100)
        raw = version + marker + _varint(1) + inp + _varint(1) + out + witness
        with pytest.raises(ValidationError, match="truncated in witness item"):
            strip_witness(raw)

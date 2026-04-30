"""Coverage gap tests — third batch.

Targets (from 2026-04-24 coverage report):
- utils.py                     (50% → target ≥ 75%)
- transaction/transaction.py   (64% → target ≥ 80%): BEEF/EF, from_beef
- transaction_preimage.py      (67% → target ≥ 80%): SIGHASH variants
"""

from __future__ import annotations

import pytest

from pyrxd.constants import SIGHASH
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import (
    Reader,
    Writer,
    bits_to_bytes,
    bytes_to_bits,
    decode_address,
    deserialize_ecdsa_der,
    deserialize_ecdsa_recoverable,
    encode,
    encode_int,
    encode_pushdata,
    from_base58,
    from_base58_check,
    get_pushdata_code,
    randbytes,
    serialize_ecdsa_der,
    serialize_ecdsa_recoverable,
    serialize_text,
    text_digest,
    to_base58,
    to_base58_check,
    to_bytes,
    to_hex,
    to_utf8,
    unsigned_to_bytes,
    unsigned_to_varint,
    validate_address,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pk(n: int = 1) -> PrivateKey:
    return PrivateKey(n)


def _p2pkh(pk: PrivateKey) -> Script:
    return P2PKH().lock(pk.address())


def _src_tx(pk: PrivateKey, satoshis: int) -> Transaction:
    locking = _p2pkh(pk)
    return Transaction(tx_inputs=[], tx_outputs=[TransactionOutput(locking, satoshis)])


def _tx_in(pk: PrivateKey, src: Transaction, idx: int = 0) -> TransactionInput:
    return TransactionInput(
        source_transaction=src,
        source_output_index=idx,
        unlocking_script_template=P2PKH().unlock(pk),
    )


# ---------------------------------------------------------------------------
# utils.py — unsigned_to_varint
# ---------------------------------------------------------------------------


class TestUnsignedToVarint:
    def test_single_byte(self):
        assert unsigned_to_varint(0) == b"\x00"
        assert unsigned_to_varint(0xFC) == b"\xfc"

    def test_fd_prefix(self):
        result = unsigned_to_varint(0xFD)
        assert result[0] == 0xFD
        assert len(result) == 3

    def test_fe_prefix(self):
        result = unsigned_to_varint(0x10000)
        assert result[0] == 0xFE
        assert len(result) == 5

    def test_ff_prefix(self):
        result = unsigned_to_varint(0x100000000)
        assert result[0] == 0xFF
        assert len(result) == 9

    def test_overflow_raises(self):
        with pytest.raises(OverflowError):
            unsigned_to_varint(0xFFFFFFFFFFFFFFFF + 1)

    def test_negative_raises(self):
        with pytest.raises(OverflowError):
            unsigned_to_varint(-1)


# ---------------------------------------------------------------------------
# utils.py — unsigned_to_bytes
# ---------------------------------------------------------------------------


class TestUnsignedToBytes:
    def test_small_value(self):
        result = unsigned_to_bytes(1)
        assert result == b"\x01"

    def test_zero(self):
        result = unsigned_to_bytes(0)
        assert result == b"\x00"

    def test_little_endian(self):
        result = unsigned_to_bytes(256, "little")
        assert result == b"\x00\x01"


# ---------------------------------------------------------------------------
# utils.py — encode_pushdata
# ---------------------------------------------------------------------------


class TestEncodePushdata:
    def test_empty_minimal(self):
        result = encode_pushdata(b"")
        assert result == b"\x00"  # OP_0

    def test_single_byte_1_to_16(self):
        result = encode_pushdata(b"\x01")
        assert result == b"\x51"  # OP_1

    def test_single_byte_0x81(self):
        result = encode_pushdata(b"\x81")
        assert result == b"\x4f"  # OP_1NEGATE

    def test_non_minimal_empty_raises(self):
        with pytest.raises(ValidationError):
            encode_pushdata(b"", minimal_push=False)

    def test_non_minimal_pushdata(self):
        result = encode_pushdata(b"hello", minimal_push=False)
        assert b"hello" in result

    def test_pushdata1_range(self):
        data = b"\xab" * 80
        result = encode_pushdata(data)
        assert result[0] == 0x4C  # OP_PUSHDATA1
        assert result[1] == 80

    def test_pushdata2_range(self):
        data = b"\xcd" * 300
        result = encode_pushdata(data)
        assert result[0] == 0x4D  # OP_PUSHDATA2


# ---------------------------------------------------------------------------
# utils.py — get_pushdata_code
# ---------------------------------------------------------------------------


class TestGetPushdataCode:
    def test_direct_push(self):
        assert get_pushdata_code(0x4B) == b"\x4b"

    def test_pushdata1(self):
        code = get_pushdata_code(0x4C)
        assert code[0] == 0x4C

    def test_pushdata2(self):
        code = get_pushdata_code(256)
        assert code[0] == 0x4D

    def test_pushdata4(self):
        code = get_pushdata_code(0x10000)
        assert code[0] == 0x4E

    def test_too_large_raises(self):
        with pytest.raises(ValueError, match="too long"):
            get_pushdata_code(0x1_0000_0000)


# ---------------------------------------------------------------------------
# utils.py — encode_int
# ---------------------------------------------------------------------------


class TestEncodeInt:
    def test_zero(self):
        assert encode_int(0) == b"\x00"  # OP_0

    def test_positive(self):
        result = encode_int(5)
        assert len(result) > 0

    def test_negative(self):
        result = encode_int(-1)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# utils.py — deserialize_ecdsa_der / serialize_ecdsa_der
# ---------------------------------------------------------------------------


class TestECDSADer:
    def test_roundtrip(self):
        pk = _pk(42)
        msg = b"test"
        sig = pk.sign(msg)
        r, s = deserialize_ecdsa_der(sig)
        reencoded = serialize_ecdsa_der((r, s))
        r2, s2 = deserialize_ecdsa_der(reencoded)
        assert r == r2 and s == s2

    def test_invalid_tag_raises(self):
        with pytest.raises((ValueError,)):
            deserialize_ecdsa_der(b"\x00" + b"\x04" + b"\x02\x01\x01\x02\x01\x01")

    def test_high_s_clamped(self):
        from pyrxd.curve import curve

        r = 1
        s = curve.n - 1  # high-s, should be clamped to 1
        reencoded = serialize_ecdsa_der((r, s))
        _r2, s2 = deserialize_ecdsa_der(reencoded)
        assert s2 <= curve.n // 2


# ---------------------------------------------------------------------------
# utils.py — recoverable ECDSA
# ---------------------------------------------------------------------------


class TestECDSARecoverable:
    def test_roundtrip(self):
        sig_tuple = (12345, 67890, 0)
        serialized = serialize_ecdsa_recoverable(sig_tuple)
        _r, _s, rec = deserialize_ecdsa_recoverable(serialized)
        assert rec == 0

    def test_bad_length_raises(self):
        with pytest.raises(ValidationError, match="invalid length"):
            deserialize_ecdsa_recoverable(b"\x00" * 10)

    def test_bad_recovery_id_raises(self):
        # r+s = 64 bytes + invalid rec_id byte
        with pytest.raises(ValidationError, match="invalid recovery id"):
            deserialize_ecdsa_recoverable(b"\x00" * 64 + b"\x05")

    def test_bad_rec_id_in_serialize_raises(self):
        with pytest.raises(ValidationError, match="invalid recovery id"):
            serialize_ecdsa_recoverable((1, 2, 10))


# ---------------------------------------------------------------------------
# utils.py — bytes_to_bits / bits_to_bytes
# ---------------------------------------------------------------------------


class TestBitConversions:
    def test_bytes_to_bits_str(self):
        bits = bytes_to_bits("ff")
        assert bits == "11111111"

    def test_bytes_to_bits_bytes(self):
        bits = bytes_to_bits(b"\x00")
        assert bits == "00000000"

    def test_bits_to_bytes(self):
        result = bits_to_bytes("11111111")
        assert result == b"\xff"

    def test_roundtrip(self):
        original = b"\xde\xad\xbe\xef"
        assert bits_to_bytes(bytes_to_bits(original)) == original


# ---------------------------------------------------------------------------
# utils.py — randbytes
# ---------------------------------------------------------------------------


class TestRandbytes:
    def test_correct_length(self):
        assert len(randbytes(32)) == 32
        assert len(randbytes(16)) == 16


# ---------------------------------------------------------------------------
# utils.py — to_bytes / to_hex / to_utf8 / encode
# ---------------------------------------------------------------------------


class TestConversionHelpers:
    def test_to_bytes_bytes(self):
        assert to_bytes(b"hello") == b"hello"

    def test_to_bytes_empty_str(self):
        assert to_bytes("") == b""

    def test_to_bytes_hex(self):
        assert to_bytes("deadbeef", "hex") == bytes.fromhex("deadbeef")

    def test_to_bytes_hex_odd_length(self):
        assert to_bytes("f", "hex") == b"\x0f"

    def test_to_bytes_base64(self):
        import base64

        encoded = base64.b64encode(b"hello").decode()
        assert to_bytes(encoded, "base64") == b"hello"

    def test_to_bytes_utf8(self):
        assert to_bytes("hello") == b"hello"

    def test_to_bytes_other_type(self):
        assert to_bytes(bytearray(b"\x01\x02")) == b"\x01\x02"

    def test_to_hex(self):
        assert to_hex(b"\xde\xad") == "dead"

    def test_to_utf8(self):
        assert to_utf8([104, 105]) == "hi"

    def test_encode_hex(self):
        result = encode([0xDE, 0xAD], "hex")
        assert result == "dead"

    def test_encode_utf8(self):
        result = encode([104, 105], "utf8")
        assert result == "hi"

    def test_encode_passthrough(self):
        arr = [1, 2, 3]
        assert encode(arr) == arr


# ---------------------------------------------------------------------------
# utils.py — base58 helpers
# ---------------------------------------------------------------------------


class TestBase58Helpers:
    def test_from_to_base58_roundtrip(self):
        data = [1, 2, 3, 4, 5]
        encoded = to_base58(data)
        decoded = from_base58(encoded)
        assert decoded == data

    def test_from_base58_invalid_chars_raises(self):
        with pytest.raises(ValueError):
            from_base58("0Invalid")

    def test_from_base58_empty_raises(self):
        with pytest.raises(ValueError):
            from_base58("")

    def test_to_base58_check_roundtrip(self):
        data = [10, 20, 30]
        encoded = to_base58_check(data)
        result = from_base58_check(encoded)
        assert result["data"] == data

    def test_to_base58_check_bad_checksum_raises(self):
        # Corrupt last byte
        data = [10, 20, 30]
        encoded = list(to_base58_check(data))
        # Replace last character to corrupt checksum
        encoded[-1] = "z" if encoded[-1] != "z" else "y"
        with pytest.raises(ValueError, match="checksum"):
            from_base58_check("".join(encoded))

    def test_from_base58_check_hex_encoding(self):
        data = [0xAB, 0xCD]
        encoded = to_base58_check(data)
        result = from_base58_check(encoded, enc="hex")
        assert result["data"] == "abcd"


# ---------------------------------------------------------------------------
# utils.py — decode_address / validate_address
# ---------------------------------------------------------------------------


class TestAddressUtils:
    def test_decode_mainnet(self):
        pk = _pk(1)
        addr = pk.address()
        pkh, _network = decode_address(addr)
        assert len(pkh) == 20

    def test_decode_invalid_raises(self):
        with pytest.raises(ValueError, match="invalid P2PKH address"):
            decode_address("not-an-address")

    def test_validate_valid(self):
        addr = _pk(1).address()
        assert validate_address(addr) is True

    def test_validate_invalid(self):
        assert validate_address("bad-address") is False

    def test_validate_network_match(self):
        from pyrxd.constants import Network

        addr = _pk(1).address()
        assert validate_address(addr, Network.MAINNET) is True


# ---------------------------------------------------------------------------
# utils.py — serialize_text / text_digest
# ---------------------------------------------------------------------------


class TestTextHelpers:
    def test_serialize_text(self):
        result = serialize_text("hello")
        assert result[0] == 5  # varint length
        assert result[1:] == b"hello"

    def test_text_digest(self):
        result = text_digest("hello")
        assert b"hello" in result
        assert b"Bitcoin Signed Message" in result


# ---------------------------------------------------------------------------
# utils.py — Writer / Reader
# ---------------------------------------------------------------------------


class TestWriterReader:
    def test_write_uint8(self):
        w = Writer()
        w.write_uint8(42)
        assert w.to_bytes() == b"\x2a"

    def test_write_int8(self):
        w = Writer()
        w.write_int8(-1)
        assert w.to_bytes() == b"\xff"

    def test_write_uint16_be(self):
        w = Writer()
        w.write_uint16_be(256)
        assert w.to_bytes() == b"\x01\x00"

    def test_write_int16_be(self):
        w = Writer()
        w.write_int16_be(-1)
        assert w.to_bytes() == b"\xff\xff"

    def test_write_uint16_le(self):
        w = Writer()
        w.write_uint16_le(256)
        assert w.to_bytes() == b"\x00\x01"

    def test_write_int16_le(self):
        w = Writer()
        w.write_int16_le(-1)
        assert w.to_bytes() == b"\xff\xff"

    def test_write_uint32_be(self):
        w = Writer()
        w.write_uint32_be(1)
        assert w.to_bytes() == b"\x00\x00\x00\x01"

    def test_write_int32_be(self):
        w = Writer()
        w.write_int32_be(-1)
        assert w.to_bytes() == b"\xff\xff\xff\xff"

    def test_write_uint32_le(self):
        w = Writer()
        w.write_uint32_le(1)
        assert w.to_bytes() == b"\x01\x00\x00\x00"

    def test_write_int32_le(self):
        w = Writer()
        w.write_int32_le(-1)
        assert w.to_bytes() == b"\xff\xff\xff\xff"

    def test_write_uint64_be(self):
        w = Writer()
        w.write_uint64_be(1)
        assert len(w.to_bytes()) == 8

    def test_write_uint64_le(self):
        w = Writer()
        w.write_uint64_le(1)
        assert len(w.to_bytes()) == 8

    def test_write_reverse(self):
        w = Writer()
        w.write_reverse(b"\x01\x02\x03")
        assert w.to_bytes() == b"\x03\x02\x01"

    def test_write_var_int_num(self):
        w = Writer()
        w.write_var_int_num(0xFD)
        data = w.to_bytes()
        assert data[0] == 0xFD

    def test_reader_var_int_fd(self):
        r = Reader(b"\xfd\x01\x00")
        assert r.read_var_int_num() == 1

    def test_reader_var_int_fe(self):
        r = Reader(b"\xfe\x01\x00\x00\x00")
        assert r.read_var_int_num() == 1

    def test_reader_var_int_ff(self):
        r = Reader(b"\xff\x01\x00\x00\x00\x00\x00\x00\x00")
        assert r.read_var_int_num() == 1

    def test_reader_read_int8(self):
        r = Reader(b"\xff")
        assert r.read_int8() == -1

    def test_reader_read_uint16_be(self):
        r = Reader(b"\x01\x00")
        assert r.read_uint16_be() == 256

    def test_reader_read_int16_be(self):
        r = Reader(b"\xff\xff")
        assert r.read_int16_be() == -1

    def test_reader_read_uint16_le(self):
        r = Reader(b"\x00\x01")
        assert r.read_uint16_le() == 256

    def test_reader_read_int16_le(self):
        r = Reader(b"\xff\xff")
        assert r.read_int16_le() == -1

    def test_reader_read_uint32_be(self):
        r = Reader(b"\x00\x00\x00\x01")
        assert r.read_uint32_be() == 1

    def test_reader_read_int32_be(self):
        r = Reader(b"\xff\xff\xff\xff")
        assert r.read_int32_be() == -1

    def test_reader_read_int32_le(self):
        r = Reader(b"\xff\xff\xff\xff")
        assert r.read_int32_le() == -1

    def test_reader_read_var_int_bytes_fd(self):
        r = Reader(b"\xfd\x01\x00")
        vi = r.read_var_int()
        assert vi is not None

    def test_reader_read_var_int_bytes_fe(self):
        r = Reader(b"\xfe\x01\x00\x00\x00")
        vi = r.read_var_int()
        assert vi is not None

    def test_reader_read_var_int_bytes_ff(self):
        r = Reader(b"\xff\x01\x00\x00\x00\x00\x00\x00\x00")
        vi = r.read_var_int()
        assert vi is not None

    def test_reader_eof(self):
        r = Reader(b"\x01")
        r.read(1)
        assert r.eof() is True

    def test_reader_read_returns_none_at_eof(self):
        r = Reader(b"")
        assert r.read(1) is None

    def test_reader_read_reverse(self):
        r = Reader(b"\x01\x02\x03")
        result = r.read_reverse(3)
        assert result == b"\x03\x02\x01"

    def test_reader_read_bytes(self):
        r = Reader(b"\xab\xcd")
        assert r.read_bytes(2) == b"\xab\xcd"

    def test_reader_read_bytes_eof_returns_empty(self):
        r = Reader(b"")
        assert r.read_bytes(5) == b""


# ---------------------------------------------------------------------------
# transaction/transaction.py — EF format (to_ef error paths)
# ---------------------------------------------------------------------------


class TestTransactionEF:
    def test_to_ef_no_source_tx_raises(self):
        pk = _pk(500)
        tx_in = TransactionInput(
            source_txid="aa" * 32,
            source_output_index=0,
            unlocking_script=Script("00"),
        )
        tx_out = TransactionOutput(_p2pkh(pk), 1000)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
        with pytest.raises(ValueError, match="source transactions"):
            tx.to_ef()

    def test_to_ef_source_txid_branch(self):
        pk = _pk(501)
        # Input with explicit source_txid (non-zero) — takes the txid branch in to_ef
        locking = _p2pkh(pk)
        src_out = TransactionOutput(locking, 10_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        # Manually set txid on src_tx so it has a known string
        actual_txid = src_tx.txid()
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=Script("00"),
        )
        tx_in.source_txid = actual_txid  # explicit non-zero txid
        tx_out = TransactionOutput(locking, 9_000)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
        ef = tx.to_ef()
        assert isinstance(ef, bytes) and len(ef) > 0

    def test_to_ef_no_source_txid_uses_hash(self):
        pk = _pk(502)
        locking = _p2pkh(pk)
        src_out = TransactionOutput(locking, 10_000)
        src_tx = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src_tx,
            source_output_index=0,
            unlocking_script=Script("00"),
        )
        # Leave source_txid as default (None or empty) to hit the .hash() branch
        tx_in.source_txid = "00" * 32
        tx_out = TransactionOutput(locking, 9_000)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
        ef = tx.to_ef()
        assert isinstance(ef, bytes) and len(ef) > 0


# ---------------------------------------------------------------------------
# transaction_preimage.py — SIGHASH variants
# ---------------------------------------------------------------------------


class TestPreimageSighashVariants:
    def _build_tx(self, pk: PrivateKey, satoshis: int = 50_000):
        src = _src_tx(pk, satoshis)
        tx_in = _tx_in(pk, src)
        tx_out = TransactionOutput(_p2pkh(pk), satoshis - 1000)
        return Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])

    def test_sighash_none(self):
        pk = _pk(700)
        tx = self._build_tx(pk)
        tx.inputs[0].sighash = SIGHASH.FORKID | SIGHASH.NONE
        # Should produce a preimage without raising
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes) and len(preimage) > 0

    def test_sighash_single_in_range(self):
        pk = _pk(701)
        tx = self._build_tx(pk)
        tx.inputs[0].sighash = SIGHASH.FORKID | SIGHASH.SINGLE
        # Input 0 has a corresponding output[0] — single branch
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes) and len(preimage) > 0

    def test_sighash_single_out_of_range(self):
        pk = _pk(702)
        src = _src_tx(pk, 50_000)
        tx_in1 = _tx_in(pk, src)
        tx_in2 = _tx_in(pk, src)
        # Two inputs, one output — input[1] has no corresponding output
        tx_out = TransactionOutput(_p2pkh(pk), 48_000)
        tx = Transaction(tx_inputs=[tx_in1, tx_in2], tx_outputs=[tx_out])
        tx.inputs[1].sighash = SIGHASH.FORKID | SIGHASH.SINGLE
        preimage = tx.preimage(1)
        assert isinstance(preimage, bytes) and len(preimage) > 0

    def test_sighash_anyonecanpay(self):
        pk = _pk(703)
        tx = self._build_tx(pk)
        tx.inputs[0].sighash = SIGHASH.FORKID | SIGHASH.ALL | SIGHASH.ANYONECANPAY
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes) and len(preimage) > 0

    def test_sighash_anyonecanpay_single(self):
        pk = _pk(704)
        tx = self._build_tx(pk)
        tx.inputs[0].sighash = SIGHASH.FORKID | SIGHASH.SINGLE | SIGHASH.ANYONECANPAY
        preimage = tx.preimage(0)
        assert isinstance(preimage, bytes) and len(preimage) > 0

    def test_estimated_byte_length_with_signed_input(self):
        """estimated_byte_length when unlocking_script is already set."""
        pk = _pk(705)
        locking = _p2pkh(pk)
        src_out = TransactionOutput(locking, 10_000)
        src = Transaction(tx_inputs=[], tx_outputs=[src_out])
        tx_in = TransactionInput(
            source_transaction=src,
            source_output_index=0,
            unlocking_script=Script("00" * 107),  # pre-signed
        )
        tx_out = TransactionOutput(locking, 9_000)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[tx_out])
        est = tx.estimated_byte_length()
        actual = tx.byte_length()
        # With pre-signed script, estimated should equal actual
        assert est == actual

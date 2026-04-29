"""Tests for pyrxd.security.types."""

from __future__ import annotations

import pytest

from pyrxd.security.errors import ValidationError
from pyrxd.security.types import (
    BlockHeight,
    Hex20,
    Hex32,
    Nbits,
    Photons,
    RawTx,
    Satoshis,
    SighashFlag,
    Txid,
)


class TestTxid:
    VALID = "a" * 64

    def test_valid(self) -> None:
        t = Txid(self.VALID)
        assert t == self.VALID
        assert isinstance(t, str)

    def test_rejects_63_chars(self) -> None:
        with pytest.raises(ValidationError):
            Txid("a" * 63)

    def test_rejects_65_chars(self) -> None:
        with pytest.raises(ValidationError):
            Txid("a" * 65)

    def test_rejects_uppercase(self) -> None:
        with pytest.raises(ValidationError):
            Txid("A" * 64)

    def test_rejects_non_hex(self) -> None:
        # 'g' is not a valid hex digit.
        with pytest.raises(ValidationError):
            Txid("g" * 64)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError):
            Txid(b"a" * 64)  # type: ignore[arg-type]

    def test_immutable(self) -> None:
        # str subclass; attribute mutation not allowed.
        t = Txid(self.VALID)
        with pytest.raises(AttributeError):
            t.something = "x"  # type: ignore[attr-defined]


class TestHex32:
    def test_valid(self) -> None:
        h = Hex32(b"\x01" * 32)
        assert h == b"\x01" * 32
        assert isinstance(h, bytes)

    def test_rejects_31_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Hex32(b"\x01" * 31)

    def test_rejects_33_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Hex32(b"\x01" * 33)

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Hex32("a" * 32)  # type: ignore[arg-type]

    def test_accepts_bytearray(self) -> None:
        h = Hex32(bytearray(32))
        assert len(h) == 32


class TestHex20:
    def test_valid(self) -> None:
        h = Hex20(b"\x00" * 20)
        assert len(h) == 20

    def test_rejects_19_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Hex20(b"\x00" * 19)

    def test_rejects_21_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Hex20(b"\x00" * 21)

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Hex20(12345)  # type: ignore[arg-type]


class TestSatoshis:
    def test_valid_zero(self) -> None:
        s = Satoshis(0)
        assert s == 0

    def test_valid_max(self) -> None:
        s = Satoshis(Satoshis.MAX)
        assert s == Satoshis.MAX

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            Satoshis(-1)

    def test_rejects_above_max(self) -> None:
        with pytest.raises(ValidationError):
            Satoshis(Satoshis.MAX + 1)

    def test_rejects_float(self) -> None:
        with pytest.raises(ValidationError):
            Satoshis(1.5)  # type: ignore[arg-type]

    def test_rejects_bool(self) -> None:
        # bool is an int subclass; must not be accepted as a satoshi amount.
        with pytest.raises(ValidationError):
            Satoshis(True)  # type: ignore[arg-type]

    def test_rejects_string(self) -> None:
        with pytest.raises(ValidationError):
            Satoshis("100")  # type: ignore[arg-type]


class TestPhotons:
    def test_valid_zero(self) -> None:
        assert Photons(0) == 0

    def test_valid_large(self) -> None:
        # No hard cap; just >= 0.
        p = Photons(10**20)
        assert p == 10**20

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            Photons(-1)

    def test_rejects_float(self) -> None:
        with pytest.raises(ValidationError):
            Photons(0.5)  # type: ignore[arg-type]


class TestBlockHeight:
    def test_valid_zero(self) -> None:
        assert BlockHeight(0) == 0

    def test_valid_large(self) -> None:
        assert BlockHeight(1_000_000) == 1_000_000

    def test_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            BlockHeight(-1)

    def test_rejects_above_ceiling(self) -> None:
        with pytest.raises(ValidationError):
            BlockHeight(BlockHeight.MAX + 1)

    def test_rejects_bool(self) -> None:
        with pytest.raises(ValidationError):
            BlockHeight(True)  # type: ignore[arg-type]


class TestNbits:
    # Block 840000 test vector: uint32 0x17053894 (exponent 0x17, mantissa 0x053894).
    # Little-endian wire bytes: 94 38 05 17.
    BLOCK_840000_NBITS = bytes.fromhex("94380517")

    def test_valid_block_840000(self) -> None:
        n = Nbits(self.BLOCK_840000_NBITS)
        assert n == self.BLOCK_840000_NBITS

    def test_valid_small_exponent(self) -> None:
        # exponent=3, mantissa=1 -> target=1
        n = Nbits(bytes.fromhex("01000003"))
        assert len(n) == 4

    def test_rejects_exponent_over_1d(self) -> None:
        # exponent = 0x1e, mantissa = 0x000001 -> byte layout: 01 00 00 1e
        with pytest.raises(ValidationError, match="exponent"):
            Nbits(bytes.fromhex("0100001e"))

    def test_rejects_max_exponent(self) -> None:
        # exponent = 0xff -> reject
        with pytest.raises(ValidationError, match="exponent"):
            Nbits(bytes.fromhex("010000ff"))

    def test_rejects_mantissa_sign_bit_set(self) -> None:
        # mantissa high bit set: mantissa = 0x800000, exponent = 0x1d
        # wire bytes little-endian: mantissa[0]=0x00, mantissa[1]=0x00,
        # mantissa[2]=0x80, exponent=0x1d -> 00 00 80 1d
        with pytest.raises(ValidationError, match="sign bit"):
            Nbits(bytes.fromhex("0000801d"))

    def test_rejects_mantissa_zero(self) -> None:
        # mantissa = 0, exponent = 0x1d -> 00 00 00 1d
        with pytest.raises(ValidationError, match="zero"):
            Nbits(bytes.fromhex("0000001d"))

    def test_rejects_3_byte_input(self) -> None:
        with pytest.raises(ValidationError, match="4 bytes"):
            Nbits(b"\x00\x00\x00")

    def test_rejects_5_byte_input(self) -> None:
        with pytest.raises(ValidationError, match="4 bytes"):
            Nbits(b"\x00\x00\x00\x00\x00")

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValidationError):
            Nbits(0x17053894)  # type: ignore[arg-type]

    def test_accepts_bytearray(self) -> None:
        n = Nbits(bytearray(self.BLOCK_840000_NBITS))
        assert n == self.BLOCK_840000_NBITS


class TestRawTx:
    def test_valid_65_bytes(self) -> None:
        # Exactly 65 bytes is the smallest valid raw tx (just above the 64-byte
        # Merkle-ambiguity defense threshold).
        raw = b"\x00" * 65
        r = RawTx(raw)
        assert len(r) == 65

    def test_valid_large_tx(self) -> None:
        raw = b"\x00" * 1024
        r = RawTx(raw)
        assert len(r) == 1024

    def test_rejects_exactly_64_bytes(self) -> None:
        # CRITICAL: 64-byte "transactions" are rejected as the Merkle forgery
        # defense. A 64-byte sequence could be an internal Merkle node.
        with pytest.raises(ValidationError, match="Merkle"):
            RawTx(b"\x00" * 64)

    def test_rejects_63_bytes(self) -> None:
        with pytest.raises(ValidationError):
            RawTx(b"\x00" * 63)

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            RawTx(b"")

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValidationError):
            RawTx("a" * 100)  # type: ignore[arg-type]


class TestSighashFlag:
    def test_valid_sighash_all(self) -> None:
        f = SighashFlag(SighashFlag.SIGHASH_ALL)
        assert f == 0x41

    def test_valid_sighash_none(self) -> None:
        assert SighashFlag(SighashFlag.SIGHASH_NONE) == 0x42

    def test_valid_sighash_single(self) -> None:
        assert SighashFlag(SighashFlag.SIGHASH_SINGLE) == 0x43

    def test_valid_anyonecanpay_variants(self) -> None:
        assert SighashFlag(SighashFlag.SIGHASH_ALL_ANYONECANPAY) == 0xC1
        assert SighashFlag(SighashFlag.SIGHASH_NONE_ANYONECANPAY) == 0xC2
        assert SighashFlag(SighashFlag.SIGHASH_SINGLE_ANYONECANPAY) == 0xC3

    def test_rejects_zero(self) -> None:
        with pytest.raises(ValidationError):
            SighashFlag(0x00)

    def test_rejects_0xff(self) -> None:
        with pytest.raises(ValidationError):
            SighashFlag(0xFF)

    def test_rejects_legacy_sighash_all(self) -> None:
        # Without the FORKID bit: not valid on Radiant.
        with pytest.raises(ValidationError):
            SighashFlag(0x01)

    def test_rejects_bool(self) -> None:
        with pytest.raises(ValidationError):
            SighashFlag(True)  # type: ignore[arg-type]

    def test_rejects_non_int(self) -> None:
        with pytest.raises(ValidationError):
            SighashFlag("0x41")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _FixedBytes.from_hex — error paths (closes coverage gap on types.py 91-99)
# ---------------------------------------------------------------------------

class TestFixedBytesFromHex:
    def test_from_hex_rejects_non_str(self) -> None:
        from pyrxd.security.types import Hex32
        with pytest.raises(ValidationError, match="requires str"):
            Hex32.from_hex(b"\x00" * 32)  # type: ignore[arg-type]

    def test_from_hex_rejects_non_str_int(self) -> None:
        from pyrxd.security.types import Hex32
        with pytest.raises(ValidationError, match="requires str"):
            Hex32.from_hex(42)  # type: ignore[arg-type]

    def test_from_hex_rejects_invalid_hex(self) -> None:
        from pyrxd.security.types import Hex32
        # 64 chars but contains non-hex 'z'
        with pytest.raises(ValidationError, match="invalid hex"):
            Hex32.from_hex("z" * 64)

    def test_from_hex_rejects_odd_length(self) -> None:
        from pyrxd.security.types import Hex32
        # Odd-length hex string is invalid
        with pytest.raises(ValidationError, match="invalid hex"):
            Hex32.from_hex("0" * 63)

    def test_from_hex_rejects_wrong_length(self) -> None:
        from pyrxd.security.types import Hex32
        # 60 chars decodes to 30 bytes, not 32 — caught by Hex32 length check
        with pytest.raises(ValidationError):
            Hex32.from_hex("0" * 60)

    def test_from_hex_accepts_valid(self) -> None:
        from pyrxd.security.types import Hex32
        h = Hex32.from_hex("0" * 64)
        assert isinstance(h, Hex32)
        assert bytes(h) == b"\x00" * 32

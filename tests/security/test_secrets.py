"""Tests for pyrxd.security.secrets."""

from __future__ import annotations

import pytest

from pyrxd.security.errors import KeyMaterialError
from pyrxd.security.secrets import PrivateKeyMaterial, SecretBytes

# secp256k1 curve order
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class TestSecretBytesRepr:
    def test_repr_does_not_leak(self) -> None:
        secret = b"\xde\xad\xbe\xef" * 8
        s = SecretBytes(secret)
        r = repr(s)
        assert "deadbeef" not in r
        assert r == "<SecretBytes:32b>"

    def test_str_does_not_leak(self) -> None:
        secret = b"\xca\xfe" * 16
        s = SecretBytes(secret)
        out = str(s)
        assert "cafe" not in out
        assert out == "<SecretBytes:32b>"

    def test_repr_reports_length(self) -> None:
        assert repr(SecretBytes(b"")) == "<SecretBytes:0b>"
        assert repr(SecretBytes(b"abc")) == "<SecretBytes:3b>"

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(TypeError):
            SecretBytes("string-not-bytes")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            SecretBytes(12345)  # type: ignore[arg-type]


class TestSecretBytesEquality:
    def test_equal_bytes_are_equal(self) -> None:
        a = SecretBytes(b"\x01\x02\x03")
        b = SecretBytes(b"\x01\x02\x03")
        assert a == b

    def test_unequal_bytes_are_not_equal(self) -> None:
        a = SecretBytes(b"\x01\x02\x03")
        b = SecretBytes(b"\x01\x02\x04")
        assert a != b

    def test_equality_with_non_secretbytes_returns_notimplemented(self) -> None:
        # hmac.compare_digest only handles same-type; a SecretBytes should
        # never compare equal to a plain bytes object.
        a = SecretBytes(b"\x01\x02\x03")
        assert (a == b"\x01\x02\x03") is False

    def test_inequality_roundtrip(self) -> None:
        a = SecretBytes(b"\x01")
        b = SecretBytes(b"\x02")
        assert a != b
        assert (a == b) is False
        assert a != "other type"


class TestSecretBytesHash:
    def test_hash_raises_typeerror(self) -> None:
        s = SecretBytes(b"\x01" * 32)
        with pytest.raises(TypeError):
            hash(s)

    def test_cannot_be_used_in_set(self) -> None:
        s = SecretBytes(b"\x01" * 32)
        with pytest.raises(TypeError):
            set().add(s)

    def test_cannot_be_used_as_dict_key(self) -> None:
        s = SecretBytes(b"\x01" * 32)
        with pytest.raises(TypeError):
            {}[s] = 1


class TestSecretBytesLen:
    def test_len_reflects_input(self) -> None:
        assert len(SecretBytes(b"")) == 0
        assert len(SecretBytes(b"abc")) == 3
        assert len(SecretBytes(b"\x00" * 64)) == 64


class TestSecretBytesZeroize:
    def test_zeroize_clears_buffer(self) -> None:
        s = SecretBytes(b"\xff" * 32)
        s.zeroize()
        # After zeroize, unsafe_raw_bytes must refuse to return secrets.
        with pytest.raises(KeyMaterialError):
            s.unsafe_raw_bytes()

    def test_zeroize_idempotent(self) -> None:
        s = SecretBytes(b"\xff" * 32)
        s.zeroize()
        # Second call must not raise.
        s.zeroize()

    def test_zeroize_empty_buffer(self) -> None:
        s = SecretBytes(b"")
        s.zeroize()  # must not raise on empty input

    def test_underlying_bytearray_is_zeroed(self) -> None:
        # White-box: after zeroize, the internal bytearray must be all zero
        # (before the access guard trips in unsafe_raw_bytes).
        s = SecretBytes(b"\xab\xcd\xef")
        s.zeroize()
        assert bytes(s._buf) == b"\x00\x00\x00"


class TestSecretBytesUnsafeRawBytes:
    def test_returns_original_bytes(self) -> None:
        data = b"\x12\x34\x56\x78" * 8
        s = SecretBytes(data)
        assert s.unsafe_raw_bytes() == data

    def test_returns_immutable_copy(self) -> None:
        data = b"\x01\x02\x03"
        s = SecretBytes(data)
        out = s.unsafe_raw_bytes()
        assert isinstance(out, bytes)
        # Mutating the internal buffer should not affect a previously-
        # returned bytes copy.
        s._buf[0] = 0xFF
        assert out == data


class TestSecretBytesFromHex:
    def test_valid_hex(self) -> None:
        s = SecretBytes.from_hex("deadbeef")
        assert s.unsafe_raw_bytes() == b"\xde\xad\xbe\xef"

    def test_empty_hex(self) -> None:
        s = SecretBytes.from_hex("")
        assert len(s) == 0

    def test_invalid_hex_raises(self) -> None:
        with pytest.raises(KeyMaterialError):
            SecretBytes.from_hex("not-hex!")

    def test_invalid_hex_does_not_leak_input(self) -> None:
        bad = "deadbeefnothex" * 4
        try:
            SecretBytes.from_hex(bad)
        except KeyMaterialError as e:
            assert bad not in str(e)
            assert bad not in repr(e)

    def test_non_string_input_raises(self) -> None:
        with pytest.raises(KeyMaterialError):
            SecretBytes.from_hex(b"deadbeef")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- PrivateKeyMaterial


class TestPrivateKeyMaterialValidation:
    def test_valid_32_byte_key(self) -> None:
        pk = PrivateKeyMaterial(b"\x01" * 32)
        assert len(pk) == 32

    def test_rejects_31_bytes(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial(b"\x01" * 31)

    def test_rejects_33_bytes(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial(b"\x01" * 33)

    def test_rejects_empty(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial(b"")

    def test_rejects_scalar_zero(self) -> None:
        with pytest.raises(KeyMaterialError, match="zero"):
            PrivateKeyMaterial(b"\x00" * 32)

    def test_rejects_scalar_equal_to_N(self) -> None:
        with pytest.raises(KeyMaterialError, match="curve order"):
            PrivateKeyMaterial(_N.to_bytes(32, "big"))

    def test_rejects_scalar_above_N(self) -> None:
        with pytest.raises(KeyMaterialError, match="curve order"):
            PrivateKeyMaterial((_N + 1).to_bytes(32, "big"))

    def test_rejects_max_uint256(self) -> None:
        with pytest.raises(KeyMaterialError, match="curve order"):
            PrivateKeyMaterial(b"\xff" * 32)

    def test_accepts_scalar_N_minus_1(self) -> None:
        pk = PrivateKeyMaterial((_N - 1).to_bytes(32, "big"))
        assert len(pk) == 32

    def test_accepts_scalar_one(self) -> None:
        key = (1).to_bytes(32, "big")
        pk = PrivateKeyMaterial(key)
        assert pk.unsafe_raw_bytes() == key

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial("string")  # type: ignore[arg-type]


class TestPrivateKeyMaterialRepr:
    def test_repr_leaks_nothing(self) -> None:
        # Construct with a specific key and verify repr contains no trace.
        key = b"\x01\x02\x03\x04" * 8
        pk = PrivateKeyMaterial(key)
        assert repr(pk) == "<PrivateKeyMaterial>"
        assert "01020304" not in repr(pk)
        assert str(pk) == "<PrivateKeyMaterial>"

    def test_repr_no_length_hint(self) -> None:
        # Unlike SecretBytes, the subclass hides length too.
        key = (1).to_bytes(32, "big")
        pk = PrivateKeyMaterial(key)
        assert "32" not in repr(pk)


class TestPrivateKeyMaterialFromWif:
    # Well-known Bitcoin-wiki WIF test vectors. Both are synthetic test data.
    COMPRESSED_WIF = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"
    UNCOMPRESSED_WIF = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"

    def test_valid_compressed_wif(self) -> None:
        pk = PrivateKeyMaterial.from_wif(self.COMPRESSED_WIF)
        assert len(pk) == 32

    def test_valid_uncompressed_wif(self) -> None:
        pk = PrivateKeyMaterial.from_wif(self.UNCOMPRESSED_WIF)
        assert len(pk) == 32

    def test_invalid_wif_raises(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif("not-a-wif-at-all")

    def test_invalid_wif_does_not_leak_input(self) -> None:
        bad = "L1aW4aubDFB7yfras2S1mN3bqg9nwysy8nkoLmJebSLD5BWv3ENZ"  # bad checksum
        try:
            PrivateKeyMaterial.from_wif(bad)
        except KeyMaterialError as e:
            # Neither args nor stringified form may contain the input.
            assert bad not in str(e)
            assert bad not in repr(e)
            for a in e.args:
                assert a != bad

    def test_non_string_wif_raises(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif(b"bytes-not-str")  # type: ignore[arg-type]

    def test_wrong_length_wif_raises(self) -> None:
        # base58check valid but wrong payload length -> invalid WIF length.
        # Use an address (25 bytes decoded) which is not a WIF.
        addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"  # known base58check
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif(addr)


class TestFromWifInternalEdges:
    """Edge cases exercising the internal base58check decoder in from_wif."""

    def test_empty_wif_rejected(self) -> None:
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif("")

    def test_all_ones_wif_rejected(self) -> None:
        # "1" decodes to bytes [0], payload far too short for base58check.
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif("1")

    def test_leading_ones_preserved_but_rejected_as_wif(self) -> None:
        # Leading "1"s mean leading zero bytes after decode. Payload is short
        # so WIF validation must still reject.
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif("11111")

    def test_invalid_char_in_wif(self) -> None:
        # '0' is not in the base58 alphabet.
        with pytest.raises(KeyMaterialError):
            PrivateKeyMaterial.from_wif("L0aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ")


class TestZeroizeBufferLockFallback:
    """Exercises the fallback path in zeroize when ctypes.memset cannot lock the buffer."""

    def test_zeroize_fallback_when_memset_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:

        from pyrxd.security import secrets as secrets_mod

        # Force ctypes.memset to raise so the Python-level fallback runs.
        def bad_memset(*args: object, **kwargs: object) -> None:
            raise TypeError("simulated buffer lock failure")

        monkeypatch.setattr(secrets_mod.ctypes, "memset", bad_memset)

        s = SecretBytes(b"\xab\xcd\xef\x12")
        s.zeroize()
        # Fallback must still produce a zeroed buffer.
        assert bytes(s._buf) == b"\x00\x00\x00\x00"
        assert s._zeroed is True


class TestPrivateKeyMaterialGenerate:
    def test_generate_returns_private_key_material(self) -> None:
        pk = PrivateKeyMaterial.generate()
        assert isinstance(pk, PrivateKeyMaterial)

    def test_generate_produces_valid_keys(self) -> None:
        # Run 10 times. Each call must produce a 32-byte key in [1, N-1].
        for _ in range(10):
            pk = PrivateKeyMaterial.generate()
            assert len(pk) == 32
            scalar = int.from_bytes(pk.unsafe_raw_bytes(), "big")
            assert 1 <= scalar < _N

    def test_generate_produces_distinct_keys(self) -> None:
        # Birthday bound: 10 draws of a 256-bit random -> collisions impossible.
        seen = set()
        for _ in range(10):
            pk = PrivateKeyMaterial.generate()
            raw = pk.unsafe_raw_bytes()
            seen.add(raw)
        assert len(seen) == 10


# ---------------------------------------------------------------------------
# Pickling / copy guards — SecretBytes refuses serialization
# ---------------------------------------------------------------------------


class TestSecretBytesSerializationGuards:
    """Closes coverage gap: SecretBytes must refuse pickle/copy/deepcopy
    so secret material cannot leak via accidental serialization."""

    def test_pickle_raises_typeerror(self):
        import pickle

        sb = SecretBytes(b"secret-payload-do-not-leak" + b"\x00" * 6)
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(sb)

    def test_copy_raises_typeerror(self):
        import copy

        sb = SecretBytes(b"secret-payload-do-not-leak" + b"\x00" * 6)
        with pytest.raises(TypeError, match="cannot be copied"):
            copy.copy(sb)

    def test_deepcopy_raises_typeerror(self):
        import copy

        sb = SecretBytes(b"secret-payload-do-not-leak" + b"\x00" * 6)
        with pytest.raises(TypeError, match="cannot be deep-copied"):
            copy.deepcopy(sb)

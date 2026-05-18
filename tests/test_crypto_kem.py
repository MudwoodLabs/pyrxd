"""Tests for ``pyrxd.crypto.kem`` — X25519 + HKDF + CEK wrapping.

Three layers, matching the AEAD test file:

1. Photonic interop vectors — derive the same X25519 pubkey, the same
   HKDF output, and unwrap a Photonic-generated wrapped CEK.
2. Round-trip — wrap then unwrap, assert recovered == original.
3. Footguns — wrong privkey, wrong AAD, tampered ciphertext, malformed sizes.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest

from pyrxd.crypto.kem import (
    WRAPPED_CEK_SIZE,
    X25519_KEY_SIZE,
    hkdf_sha256,
    unwrap_cek_x25519,
    wrap_cek_x25519,
    x25519_ecdh,
    x25519_public_key,
)

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "photonic_timelock_vectors.json"


@pytest.fixture(scope="module")
def photonic_vectors() -> dict:
    return json.loads(FIXTURES_PATH.read_text())


# ────────────────────────────────────────────── Photonic interop ──


class TestPhotonicInterop:
    def test_hkdf_sha256_byte_equal(self, photonic_vectors):
        v = photonic_vectors["hkdf_sha256"]
        ikm = bytes.fromhex(v["ikm"])
        salt = bytes.fromhex(v["salt"])
        info = bytes.fromhex(v["info"])
        expected = bytes.fromhex(v["derived"])

        result = hkdf_sha256(ikm, salt, info, v["output_length"])
        assert result == expected

    def test_x25519_pubkey_derivation(self, photonic_vectors):
        v = photonic_vectors["x25519"]
        sk = bytes.fromhex(v["sk_a"])
        expected_pk = bytes.fromhex(v["pk_a"])
        assert x25519_public_key(sk) == expected_pk

    def test_x25519_ecdh_byte_equal(self, photonic_vectors):
        v = photonic_vectors["x25519"]
        sk_a = bytes.fromhex(v["sk_a"])
        pk_b = bytes.fromhex(v["pk_b"])
        expected_shared = bytes.fromhex(v["shared_secret_a_to_b"])
        assert x25519_ecdh(sk_a, pk_b) == expected_shared

    def test_x25519_ecdh_is_symmetric(self, photonic_vectors):
        """A → B ECDH equals B → A ECDH."""
        v = photonic_vectors["x25519"]
        sk_a = bytes.fromhex(v["sk_a"])
        sk_b = bytes.fromhex(v["sk_b"])
        pk_a = bytes.fromhex(v["pk_a"])
        pk_b = bytes.fromhex(v["pk_b"])
        assert x25519_ecdh(sk_a, pk_b) == x25519_ecdh(sk_b, pk_a)

    def test_unwrap_photonic_wrapped_cek(self, photonic_vectors):
        """The critical interop test: Photonic wrapped a CEK; pyrxd unwraps
        and recovers the same bytes. If this fails, pyrxd cannot decrypt
        Photonic-encrypted Glyph payloads."""
        v = photonic_vectors["wrap_cek_x25519"]
        recipient_sk = bytes.fromhex(v["recipient_sk"])
        wrapped = bytes.fromhex(v["wrapped_cek"])
        ephemeral_pub = bytes.fromhex(v["ephemeral_x25519_pub"])
        aad = bytes.fromhex(v["aad"])
        expected_cek = bytes.fromhex(v["original_cek"])

        recovered = unwrap_cek_x25519(wrapped, ephemeral_pub, recipient_sk, aad)
        assert recovered == expected_cek


# ────────────────────────────────────────────── round-trip ──


class TestRoundTrip:
    def test_wrap_unwrap_round_trip(self):
        cek = secrets.token_bytes(32)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)
        aad = b"some-aad"

        wrapped = wrap_cek_x25519(cek, recipient_pk, aad)
        recovered = unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, recipient_sk, aad)
        assert recovered == cek

    def test_wrap_with_empty_aad(self):
        cek = secrets.token_bytes(32)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)

        wrapped = wrap_cek_x25519(cek, recipient_pk)
        recovered = unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, recipient_sk)
        assert recovered == cek

    def test_wrapped_size_invariant(self):
        cek = secrets.token_bytes(32)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)
        wrapped = wrap_cek_x25519(cek, recipient_pk)
        assert len(wrapped.wrapped_cek) == WRAPPED_CEK_SIZE
        assert len(wrapped.ephemeral_pubkey) == X25519_KEY_SIZE

    def test_two_wraps_produce_different_ciphertext(self):
        """Wrap is non-deterministic (random ephemeral + nonce)."""
        cek = secrets.token_bytes(32)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)
        a = wrap_cek_x25519(cek, recipient_pk)
        b = wrap_cek_x25519(cek, recipient_pk)
        assert a.wrapped_cek != b.wrapped_cek
        assert a.ephemeral_pubkey != b.ephemeral_pubkey


# ────────────────────────────────────────────── footguns ──


class TestFootguns:
    def _make_wrap(self, aad=b""):
        cek = secrets.token_bytes(32)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)
        wrapped = wrap_cek_x25519(cek, recipient_pk, aad)
        return cek, recipient_sk, wrapped

    def test_unwrap_with_wrong_privkey_fails(self):
        _cek, _sk, wrapped = self._make_wrap()
        wrong_sk = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="AEAD decryption failed"):
            unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, wrong_sk)

    def test_unwrap_with_wrong_aad_fails(self):
        _cek, sk, wrapped = self._make_wrap(aad=b"good-aad")
        with pytest.raises(ValueError, match="AEAD decryption failed"):
            unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, sk, b"bad-aad")

    def test_unwrap_tampered_ciphertext_fails(self):
        _cek, sk, wrapped = self._make_wrap()
        bad = bytearray(wrapped.wrapped_cek)
        bad[-1] ^= 0x01  # flip a bit in the Poly1305 tag
        with pytest.raises(ValueError, match="AEAD decryption failed"):
            unwrap_cek_x25519(bytes(bad), wrapped.ephemeral_pubkey, sk)

    def test_unwrap_tampered_ephemeral_fails(self):
        _cek, sk, wrapped = self._make_wrap()
        bad_pub = bytearray(wrapped.ephemeral_pubkey)
        bad_pub[0] ^= 0x01  # different point → different shared secret → wrong KEK
        with pytest.raises(ValueError, match="AEAD decryption failed"):
            unwrap_cek_x25519(wrapped.wrapped_cek, bytes(bad_pub), sk)

    def test_wrap_rejects_wrong_cek_size(self):
        with pytest.raises(ValueError, match="cek must be 32"):
            wrap_cek_x25519(bytes(16), bytes(32))

    def test_wrap_rejects_wrong_pubkey_size(self):
        with pytest.raises(ValueError, match="recipient_pubkey must be 32"):
            wrap_cek_x25519(bytes(32), bytes(16))

    def test_unwrap_rejects_wrong_wrapped_size(self):
        with pytest.raises(ValueError, match="wrapped_cek must be"):
            unwrap_cek_x25519(bytes(50), bytes(32), bytes(32))

    def test_hkdf_rejects_oversize_length(self):
        # RFC 5869 caps at 255 * hash_len
        with pytest.raises(ValueError, match="HKDF output length"):
            hkdf_sha256(b"ikm", b"salt", b"info", length=255 * 32 + 1)

    def test_hkdf_rejects_zero_length(self):
        with pytest.raises(ValueError, match="HKDF output length"):
            hkdf_sha256(b"ikm", b"salt", b"info", length=0)

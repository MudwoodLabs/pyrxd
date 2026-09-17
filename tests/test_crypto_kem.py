"""Tests for ``pyrxd.crypto.kem`` — X25519 + HKDF + CEK wrapping.

Three layers, matching the AEAD test file:

1. Photonic interop vectors — derive the same X25519 pubkey, the same
   HKDF output, and unwrap a Photonic-generated wrapped CEK.
2. Round-trip — wrap then unwrap, assert recovered == original.
3. Footguns — wrong privkey, wrong AAD, tampered ciphertext, malformed sizes.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

import pytest

from pyrxd.crypto.aead import encrypt_xchacha20_poly1305
from pyrxd.crypto.kem import (
    KEK_DERIVATION_INFO,
    LEGACY_KEK_DERIVATION_INFO,
    WRAPPED_CEK_SIZE,
    X25519_KEY_SIZE,
    hkdf_sha256,
    unwrap_cek_x25519,
    unwrap_cek_x25519_detailed,
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
    """Unwrap now tries two known KEK derivations before giving up (the current
    mode-bound info string, then the pre-2026-05-22 one pyrxd emitted through 0.24.0),
    so a failure is no longer a single AEAD tag failure and no longer says so. The
    property under test is unchanged: every one of these must still be refused, and the
    message must not distinguish WHICH input was wrong — wrong key, wrong AAD and
    tampered bytes are deliberately indistinguishable."""

    def _make_wrap(self, aad=b""):
        cek = secrets.token_bytes(32)
        recipient_sk = secrets.token_bytes(32)
        recipient_pk = x25519_public_key(recipient_sk)
        wrapped = wrap_cek_x25519(cek, recipient_pk, aad)
        return cek, recipient_sk, wrapped

    def test_unwrap_with_wrong_privkey_fails(self):
        _cek, _sk, wrapped = self._make_wrap()
        wrong_sk = secrets.token_bytes(32)
        with pytest.raises(ValueError, match="could not unwrap CEK under any known KEK derivation"):
            unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, wrong_sk)

    def test_unwrap_with_wrong_aad_fails(self):
        _cek, sk, wrapped = self._make_wrap(aad=b"good-aad")
        with pytest.raises(ValueError, match="could not unwrap CEK under any known KEK derivation"):
            unwrap_cek_x25519(wrapped.wrapped_cek, wrapped.ephemeral_pubkey, sk, b"bad-aad")

    def test_unwrap_tampered_ciphertext_fails(self):
        _cek, sk, wrapped = self._make_wrap()
        bad = bytearray(wrapped.wrapped_cek)
        bad[-1] ^= 0x01  # flip a bit in the Poly1305 tag
        with pytest.raises(ValueError, match="could not unwrap CEK under any known KEK derivation"):
            unwrap_cek_x25519(bytes(bad), wrapped.ephemeral_pubkey, sk)

    def test_unwrap_tampered_ephemeral_fails(self):
        _cek, sk, wrapped = self._make_wrap()
        bad_pub = bytearray(wrapped.ephemeral_pubkey)
        bad_pub[0] ^= 0x01  # different point → different shared secret → wrong KEK
        with pytest.raises(ValueError, match="could not unwrap CEK under any known KEK derivation"):
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


class TestTheKekInfoStringMatchesPhotonicAgain:
    """pyrxd wrapped CEKs under `b"glyph-kek-v1"` from v0.6.0 to 0.24.0.

    That was correct when written — Photonic used the same string — but Photonic split
    classical from hybrid on 2026-05-22 (6e235207) as a downgrade-protection fix, binding
    the HKDF info to the mode so stripping the ML-KEM ciphertext cannot still decrypt. From
    then on pyrxd and Photonic derived different KEKs and could not exchange content, while
    the docstrings, CHANGELOG and `pyrxd/__init__.py` all still claimed byte-compatibility.

    The interop fixture could not catch it: it was generated 2026-05-18, four days BEFORE
    the upstream change, and records `photonic_commit: "UNKNOWN"`. It asserted agreement
    with a Photonic that no longer exists.
    """

    def test_wrap_emits_the_mode_bound_classical_string(self):
        assert KEK_DERIVATION_INFO == b"glyph-kek-classical-v1"

    def test_the_legacy_string_is_still_known_but_never_emitted(self):
        assert LEGACY_KEK_DERIVATION_INFO == b"glyph-kek-v1"
        sk = os.urandom(32)
        w = wrap_cek_x25519(os.urandom(32), x25519_public_key(sk), b"aad")
        # Proven by construction: the wrap is readable under the CURRENT info and not the legacy one.
        assert unwrap_cek_x25519_detailed(w.wrapped_cek, w.ephemeral_pubkey, sk, b"aad").legacy_info is False

    def test_a_legacy_wrapped_cek_is_still_readable_and_says_so(self):
        """Content pyrxd encrypted before this change must not become unreadable — that
        would be a worse failure than the interop break it fixes."""
        sk = os.urandom(32)
        cek = os.urandom(32)
        eph_priv = os.urandom(32)
        shared = x25519_ecdh(eph_priv, x25519_public_key(sk))
        legacy_kek = hkdf_sha256(shared, salt=None, info=LEGACY_KEK_DERIVATION_INFO, length=32)
        nonce = os.urandom(24)
        wrapped = nonce + encrypt_xchacha20_poly1305(cek, legacy_kek, nonce, b"aad")

        out = unwrap_cek_x25519_detailed(wrapped, x25519_public_key(eph_priv), sk, b"aad")
        assert out.cek == cek
        assert out.legacy_info is True, "the caller must be told these bytes are legacy"

    def test_the_legacy_fallback_can_be_refused(self):
        sk = os.urandom(32)
        cek = os.urandom(32)
        eph_priv = os.urandom(32)
        shared = x25519_ecdh(eph_priv, x25519_public_key(sk))
        legacy_kek = hkdf_sha256(shared, salt=None, info=LEGACY_KEK_DERIVATION_INFO, length=32)
        nonce = os.urandom(24)
        wrapped = nonce + encrypt_xchacha20_poly1305(cek, legacy_kek, nonce, b"aad")

        with pytest.raises(ValueError):
            unwrap_cek_x25519(wrapped, x25519_public_key(eph_priv), sk, b"aad", allow_legacy_info=False)

    def test_the_hybrid_string_is_never_emitted_by_pyrxd(self):
        """pyrxd has no ML-KEM path, so it must never derive under the hybrid info — a
        wrap that did would be claiming post-quantum protection it does not implement."""
        assert b"hybrid" not in KEK_DERIVATION_INFO
        assert b"hybrid" not in LEGACY_KEK_DERIVATION_INFO

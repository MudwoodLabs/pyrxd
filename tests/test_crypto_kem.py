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
        Photonic-encrypted Glyph payloads.

        ``allow_legacy_info=False`` IS THE POINT OF THIS TEST. Until 2026-09-21 the
        fixture predated upstream's classical/hybrid KEK split, so this test passed
        through the legacy retry and proved only that the fallback worked -- while
        interop had in fact been broken for four months. A test that can be satisfied
        by the compatibility shim cannot detect the incompatibility the shim exists for.
        """
        v = photonic_vectors["wrap_cek_x25519"]
        recipient_sk = bytes.fromhex(v["recipient_sk"])
        wrapped = bytes.fromhex(v["wrapped_cek"])
        ephemeral_pub = bytes.fromhex(v["ephemeral_x25519_pub"])
        aad = bytes.fromhex(v["aad"])
        expected_cek = bytes.fromhex(v["original_cek"])

        detailed = unwrap_cek_x25519_detailed(wrapped, ephemeral_pub, recipient_sk, aad, allow_legacy_info=False)
        assert detailed.cek == expected_cek
        assert detailed.legacy_info is False, (
            "this vector must unwrap under the CURRENT derivation; if it only works "
            "via the legacy retry the fixture is stale and proves nothing about interop"
        )

    def test_the_pre_split_vector_still_reads_and_reports_itself(self, photonic_vectors):
        """The legacy retry has a real regression case, separate from the interop one.

        Kept apart on purpose: mixing them is what made the interop test vacuous.
        """
        v = photonic_vectors["wrap_cek_x25519_legacy_info"]
        detailed = unwrap_cek_x25519_detailed(
            bytes.fromhex(v["wrapped_cek"]),
            bytes.fromhex(v["ephemeral_x25519_pub"]),
            bytes.fromhex(v["recipient_sk"]),
            bytes.fromhex(v["aad"]),
        )
        assert detailed.cek == bytes.fromhex(v["original_cek"])
        assert detailed.legacy_info is True

        with pytest.raises(ValueError):
            unwrap_cek_x25519_detailed(
                bytes.fromhex(v["wrapped_cek"]),
                bytes.fromhex(v["ephemeral_x25519_pub"]),
                bytes.fromhex(v["recipient_sk"]),
                bytes.fromhex(v["aad"]),
                allow_legacy_info=False,
            )


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
    mode-bound info string, then the pre-split one pyrxd emitted through 0.24.0),
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

    That is the string Photonic used before `8e6bb6e` (2026-05-16), which split classical from
    hybrid as a downgrade-protection fix, binding the HKDF info to the mode so stripping the
    ML-KEM ciphertext cannot still decrypt. pyrxd's `kem.py` was first committed on
    2026-05-18, two days AFTER that split, so it was never correct against the upstream code
    of its day: pyrxd and Photonic derived different KEKs and could not exchange content,
    while the docstrings, CHANGELOG and `pyrxd/__init__.py` all claimed byte-compatibility.

    The interop fixture could not catch it: it was generated 2026-05-18 -- also AFTER the
    split -- from an unrecorded checkout (`photonic_commit: "UNKNOWN"`) that evidently did not
    carry the change, since its wrap only opens under the pre-split string.
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


class TestTheAppPathVector:
    """A recipient wrap Photonic's WALLET made, not one its library was handed an AAD for.

    Every other wrap vector in the fixture was produced by calling `wrapCEK` from
    `packages/lib/src/encryption.ts` with an AAD the generator chose. That proves the KEM
    matches and says nothing about what the wallet binds, because the library takes the AAD
    from its caller. The wallet's caller is `encryptContent` in
    `packages/app/src/encryptionService.ts`, and it binds the UTF-8 TEXT of
    `crypto.cek_hash`. pyrxd's `build_timelock_mint` bound the raw 32-byte digest, so even
    with the KEK info fixed, Photonic's `decryptContent` could not open a pyrxd recipient
    wrap, and the library-level vectors were structurally unable to show it.

    `app_encrypt_content_recipient` was generated through `encryptContent` itself
    (`scripts/gen-photonic-vectors/gen-app-path-vector.ts`), with every RNG draw recorded in
    order and checked against the output by role, and Photonic's `decryptContent` opened it,
    handed the ciphertext directly, before it was written. So:

    - pyrxd opening it STRICTLY under `cek_wrap_aad` is the Photonic -> pyrxd direction;
    - pyrxd's own mint, fed the same randomness, reproducing it BYTE FOR BYTE is the
      pyrxd -> Photonic direction for the decryptContent step Photonic's unlock screen calls
      once it has the ciphertext.

    WHAT THIS DOES NOT SHOW: that Photonic's unlock SCREEN reaches that step for a pyrxd
    mint. Before it calls `decryptContent` it must fetch the ciphertext, and
    `EncryptedContentUnlock.tsx` (`assertStorageAvailable`) refuses unless the envelope
    carries `main.b` or both `crypto.locator` and `crypto.locator_nonce`. pyrxd writes
    neither `main.b` nor `locator_nonce`, so per that source a pyrxd timelock mint stops at
    "Storage Locator Missing" in Photonic's UI. That gap predates this change and is not
    closed by it.
    """

    @pytest.fixture()
    def v(self, photonic_vectors) -> dict:
        return photonic_vectors["app_encrypt_content_recipient"]

    @staticmethod
    def _draw(v: dict, role: str) -> bytes:
        (hit,) = [d["hex"] for d in v["rng_draws"] if d["role"] == role]
        return bytes.fromhex(hit)

    def test_the_vector_is_what_it_says(self, v):
        """The roles the generator recorded, re-derived here from the vector's own bytes."""
        from pyrxd.glyph.encrypted_content import EncryptedContentStub
        from pyrxd.glyph.timelock import compute_cek_hash, format_cek_hash

        stub = EncryptedContentStub.from_dict(v["metadata"])
        (rec,) = stub.crypto.recipients
        assert v["photonic_commit"] == "becf41a731e78ab98fdd88652527d7dda12784c6"
        assert x25519_public_key(bytes.fromhex(v["recipient_sk"])).hex() == v["recipient_pk"]
        assert stub.crypto.cek_hash == format_cek_hash(compute_cek_hash(self._draw(v, "cek")))
        assert rec.epk == x25519_public_key(self._draw(v, "ephemeral_x25519_priv"))
        assert rec.wrapped_cek[:24] == self._draw(v, "wrap_nonce")
        assert bytes.fromhex(v["encrypted_content"])[:24] == self._draw(v, "chunk_nonce_0")
        # And pyrxd reads Photonic's metadata without losing or reshaping a field.
        assert stub.to_dict() == v["metadata"]

    def test_pyrxd_opens_the_app_wrap_strictly_under_the_text_aad(self, v):
        from pyrxd.crypto.aead import ChunkedCiphertext, EncryptedChunk, decrypt_chunked
        from pyrxd.glyph.encrypted_content import EncryptedContentStub
        from pyrxd.glyph.timelock import cek_wrap_aad, parse_cek_hash

        stub = EncryptedContentStub.from_dict(v["metadata"])
        (rec,) = stub.crypto.recipients
        aad = cek_wrap_aad(stub.crypto.cek_hash)
        assert aad == stub.crypto.cek_hash.encode() and len(aad) == 71

        detailed = unwrap_cek_x25519_detailed(
            rec.wrapped_cek, rec.epk, bytes.fromhex(v["recipient_sk"]), aad, allow_legacy_info=False
        )
        assert detailed.cek == self._draw(v, "cek")
        assert detailed.legacy_info is False

        # One chunk: Photonic's layout is nonce(24) || ciphertext+tag.
        blob = bytes.fromhex(v["encrypted_content"])
        assert stub.main.chunks == 1
        plaintext_hash = parse_cek_hash(stub.main.hash)
        chunked = ChunkedCiphertext(
            chunks=[EncryptedChunk(ciphertext=blob[24:], nonce=blob[:24])], plaintext_hash=plaintext_hash
        )
        assert decrypt_chunked(chunked, detailed.cek, plaintext_hash) == bytes.fromhex(v["plaintext"])

    def test_the_raw_digest_aad_does_not_open_it(self, v):
        """The control: if the raw digest also opened it, the AAD would not be load-bearing and
        the test above would prove nothing about which one the wallet binds."""
        from pyrxd.glyph.encrypted_content import EncryptedContentStub
        from pyrxd.glyph.timelock import parse_cek_hash

        stub = EncryptedContentStub.from_dict(v["metadata"])
        (rec,) = stub.crypto.recipients
        with pytest.raises(ValueError, match="could not unwrap CEK"):
            unwrap_cek_x25519(
                rec.wrapped_cek,
                rec.epk,
                bytes.fromhex(v["recipient_sk"]),
                parse_cek_hash(stub.crypto.cek_hash),
                allow_legacy_info=True,
            )

    def test_pyrxds_mint_reproduces_the_app_wrap_byte_for_byte(self, v, monkeypatch):
        """Through the production entry point. Only the RNG is replayed; the wrap, its AAD and
        the chunk encryption all run for real, so a different AAD is a different ciphertext."""
        import secrets as secrets_module

        from pyrxd.glyph.timelock import (
            TimelockParams,
            TimelockRecipient,
            build_timelock_mint,
            cek_wrap_aad,
        )

        # pyrxd draws in this order: the chunk nonce (encrypt_chunked), then the wrap's
        # ephemeral key and nonce. Photonic's CEK and locator draws have no pyrxd counterpart.
        queue = [self._draw(v, "chunk_nonce_0"), self._draw(v, "ephemeral_x25519_priv"), self._draw(v, "wrap_nonce")]

        def replay(n: int) -> bytes:
            nxt = queue.pop(0)
            assert len(nxt) == n, f"pyrxd asked for {n} random bytes where the vector recorded {len(nxt)}"
            return nxt

        monkeypatch.setattr(secrets_module, "token_bytes", replay)
        build = build_timelock_mint(
            name=v["name"],
            content_type=v["content_type"],
            plaintext=bytes.fromhex(v["plaintext"]),
            params=TimelockParams(mode="block", unlock_at=1),
            cek=self._draw(v, "cek"),
            recipients=[TimelockRecipient(kid="x25519", public_key=bytes.fromhex(v["recipient_pk"]))],
        )
        monkeypatch.undo()
        assert queue == [], "pyrxd consumed fewer random draws than the vector recorded"

        mine, theirs = build.stub.to_dict(), v["metadata"]
        assert mine["crypto"]["cek_hash"] == theirs["crypto"]["cek_hash"]
        assert mine["main"] == theirs["main"]
        assert mine["crypto"]["recipients"] == theirs["crypto"]["recipients"], (
            "pyrxd's recipient wrap differs from the one Photonic's app made from the same inputs"
        )
        blob = b"".join(c.nonce + c.ciphertext for c in build.ciphertext.chunks)
        assert blob.hex() == v["encrypted_content"]

        # Said directly as well as by equality: the mint's wrap opens strictly under the text AAD.
        (rec,) = build.stub.crypto.recipients
        opened = unwrap_cek_x25519_detailed(
            rec.wrapped_cek,
            rec.epk,
            bytes.fromhex(v["recipient_sk"]),
            cek_wrap_aad(build.cek_hash),
            allow_legacy_info=False,
        )
        assert opened.cek == build.cek

    def test_cek_wrap_aad_refuses_the_digest(self):
        """Handing it the 32-byte digest is exactly the 0.24.0 mistake; it must not be encoded."""
        from pyrxd.glyph.timelock import cek_wrap_aad

        with pytest.raises(TypeError, match="STRING"):
            cek_wrap_aad(bytes(32))  # type: ignore[arg-type]

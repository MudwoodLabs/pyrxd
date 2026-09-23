"""Tests for ``pyrxd.glyph.encrypted_content`` types.

Two layers:

1. Photonic interop — parse the ``output_metadata`` dicts from the bridge
   fixture (which are what Photonic's ``addTimelockToMetadata`` produces)
   and assert round-trip back to a byte-identical dict.
2. Round-trip — build types in pyrxd, serialize, deserialize, assert
   equality.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyrxd.glyph.encrypted_content import (
    WRAP_ALG_X25519,
    CryptoMetadata,
    CryptoRecipient,
    EncryptedContentStub,
    EncryptionMetadata,
    TimelockSpec,
)

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "photonic_timelock_vectors.json"


@pytest.fixture(scope="module")
def photonic_vectors() -> dict:
    return json.loads(FIXTURES_PATH.read_text())


# ────────────────────────────────────────────── Photonic interop ──


class TestPhotonicInteropMetadata:
    def test_parse_block_mode_metadata(self, photonic_vectors):
        v = photonic_vectors["timelock_metadata_block_mode"]
        photonic_metadata = v["output_metadata"]
        stub = EncryptedContentStub.from_dict(photonic_metadata)
        assert stub.p == [2, 8, 9]
        assert stub.crypto.timelock is not None
        assert stub.crypto.timelock.mode == "block"
        assert stub.crypto.timelock.unlock_at == v["unlock_at"]

    def test_parse_time_mode_metadata(self, photonic_vectors):
        v = photonic_vectors["timelock_metadata_time_mode"]
        photonic_metadata = v["output_metadata"]
        stub = EncryptedContentStub.from_dict(photonic_metadata)
        assert stub.p == [2, 8, 9]
        assert stub.crypto.timelock is not None
        assert stub.crypto.timelock.mode == "time"
        assert stub.crypto.timelock.unlock_at == v["unlock_at"]
        assert stub.crypto.timelock.hint == v["hint"]

    def test_round_trip_byte_identical_block(self, photonic_vectors):
        """Parse Photonic-emitted metadata, re-serialize, compare dicts."""
        v = photonic_vectors["timelock_metadata_block_mode"]
        photonic_metadata = v["output_metadata"]
        stub = EncryptedContentStub.from_dict(photonic_metadata)
        re_emitted = stub.to_dict()
        assert re_emitted == photonic_metadata, "round-trip changed the metadata — pyrxd and Photonic disagree on shape"

    def test_round_trip_byte_identical_time(self, photonic_vectors):
        v = photonic_vectors["timelock_metadata_time_mode"]
        photonic_metadata = v["output_metadata"]
        stub = EncryptedContentStub.from_dict(photonic_metadata)
        re_emitted = stub.to_dict()
        assert re_emitted == photonic_metadata


# ────────────────────────────────────────────── construction + round-trip ──


class TestEncryptionMetadata:
    def test_round_trip(self):
        m = EncryptionMetadata(
            type="image/png",
            hash="sha256:" + "ab" * 32,
            size=12345,
            chunks=1,
        )
        assert EncryptionMetadata.from_dict(m.to_dict()) == m

    def test_normalizes_unprefixed_hash(self):
        m = EncryptionMetadata(type="x", hash="AB" * 32)
        d = m.to_dict()
        assert d["hash"] == "sha256:" + "ab" * 32, "hash must be lowercased + prefixed"


class TestCryptoRecipient:
    def test_round_trip_x25519_only(self):
        r = CryptoRecipient(
            kid="recipient-key-1",
            alg=WRAP_ALG_X25519,
            wrapped_cek=b"\x00" * 72,
            epk=b"\x11" * 32,
        )
        assert CryptoRecipient.from_dict(r.to_dict()) == r

    def test_round_trip_with_mlkem(self):
        r = CryptoRecipient(
            kid="kid",
            alg="x25519mlkem768-hkdf-xchacha20poly1305",
            wrapped_cek=b"\x00" * 72,
            epk=b"\x11" * 32,
            mlkem_ct=b"\x22" * 1088,
        )
        assert CryptoRecipient.from_dict(r.to_dict()) == r


class TestTimelockSpec:
    def test_round_trip_block_mode(self):
        t = TimelockSpec(mode="block", unlock_at=425046, cek_hash="sha256:" + "ab" * 32)
        assert TimelockSpec.from_dict(t.to_dict()) == t

    def test_round_trip_time_mode_with_hint(self):
        t = TimelockSpec(
            mode="time",
            unlock_at=1_700_000_000,
            cek_hash="sha256:" + "ab" * 32,
            hint="auction reveal",
        )
        assert TimelockSpec.from_dict(t.to_dict()) == t

    def test_omits_empty_hint(self):
        t = TimelockSpec(mode="block", unlock_at=1, cek_hash="sha256:" + "ab" * 32)
        assert "hint" not in t.to_dict()


class TestCryptoMetadata:
    def test_round_trip_with_timelock(self):
        c = CryptoMetadata(
            cek_hash="sha256:" + "ab" * 32,
            timelock=TimelockSpec(mode="block", unlock_at=10, cek_hash="sha256:" + "ab" * 32),
        )
        assert CryptoMetadata.from_dict(c.to_dict()) == c

    def test_round_trip_with_recipients(self):
        c = CryptoMetadata(
            cek_hash="sha256:" + "ab" * 32,
            recipients=[
                CryptoRecipient(
                    kid="k1",
                    alg=WRAP_ALG_X25519,
                    wrapped_cek=b"\x00" * 72,
                    epk=b"\x11" * 32,
                ),
            ],
        )
        assert CryptoMetadata.from_dict(c.to_dict()) == c

    def test_omits_optional_fields_when_none(self):
        c = CryptoMetadata(cek_hash="sha256:" + "ab" * 32)
        d = c.to_dict()
        assert "locator" not in d
        assert "locator_hash" not in d
        assert "recipients" not in d  # empty list is omitted
        assert "timelock" not in d


class TestEncryptedContentStub:
    def test_round_trip(self):
        stub = EncryptedContentStub(
            p=[2, 8, 9],
            type="image/png",
            name="Test",
            main=EncryptionMetadata(type="image/png", hash="sha256:" + "ab" * 32),
            crypto=CryptoMetadata(
                cek_hash="sha256:" + "ab" * 32,
                timelock=TimelockSpec(
                    mode="block",
                    unlock_at=10,
                    cek_hash="sha256:" + "ab" * 32,
                ),
            ),
        )
        assert EncryptedContentStub.from_dict(stub.to_dict()) == stub


# ──────────────────────────────── empty content, as Photonic encodes it ──


class TestEmptyContentAsPhotonicEncodesIt:
    """Zero bytes of content are ZERO chunks to Photonic, and pyrxd refused that.

    Photonic's `encryptChunked` computes `Math.ceil(plaintext.length / CHUNK_SIZE)`, so a
    0-byte `encryptContent` records `main: {size: 0, chunks: 0}` and no ciphertext at all.
    `EncryptionMetadata.from_dict` refused any `chunks < 1` as "nonsensical", and
    `decode_payload` logs and DROPS a field that fails to parse, so a Photonic-minted empty
    token decoded with no `encrypted_main` — a guard refusing honest output.

    Zero chunks is only sensible with zero bytes. `{size: 0, chunks: 0}` is accepted; zero
    chunks with any content is still refused, as is a negative count. pyrxd itself still
    writes one empty chunk for empty content (`encrypt_chunked`), and that stays readable.

    `app_encrypt_content_recipient_empty` is Photonic's real output, generated through its app
    service by `scripts/gen-photonic-vectors/gen-app-path-vector.ts` and decrypted by its own
    `decryptContent` before it was written.
    """

    @pytest.fixture()
    def v(self, photonic_vectors) -> dict:
        return photonic_vectors["app_encrypt_content_recipient_empty"]

    def test_the_vector_is_photonics_zero_chunk_encoding(self, v):
        """The premise, read from the vector rather than assumed."""
        assert v["metadata"]["main"]["size"] == 0
        assert v["metadata"]["main"]["chunks"] == 0
        assert v["encrypted_content"] == ""
        assert v["photonic_commit"] == "becf41a731e78ab98fdd88652527d7dda12784c6"

    def test_pyrxd_reads_photonics_empty_content_and_opens_it(self, v):
        from pyrxd.crypto.aead import ChunkedCiphertext, decrypt_chunked
        from pyrxd.crypto.kem import unwrap_cek_x25519
        from pyrxd.glyph.timelock import cek_wrap_aad, parse_cek_hash

        stub = EncryptedContentStub.from_dict(v["metadata"])
        assert (stub.main.size, stub.main.chunks) == (0, 0)
        assert stub.to_dict() == v["metadata"], "read back must not reshape Photonic's fields"
        (rec,) = stub.crypto.recipients
        cek = unwrap_cek_x25519(
            rec.wrapped_cek,
            rec.epk,
            bytes.fromhex(v["recipient_sk"]),
            cek_wrap_aad(stub.crypto.cek_hash),
            allow_legacy_info=False,
        )
        plaintext_hash = parse_cek_hash(stub.main.hash)
        assert decrypt_chunked(ChunkedCiphertext(chunks=[], plaintext_hash=plaintext_hash), cek, plaintext_hash) == b""

    def test_decode_payload_keeps_it_instead_of_dropping_it(self, v):
        """Through the production read path: the field used to be logged and dropped here."""
        import cbor2

        from pyrxd.glyph.payload import decode_payload

        m = decode_payload(cbor2.dumps(v["metadata"], canonical=True))
        assert m.encrypted_main is not None, "Photonic's empty encrypted main was dropped"
        assert (m.encrypted_main.size, m.encrypted_main.chunks) == (0, 0)

    def test_pyrxds_own_one_empty_chunk_is_still_read(self):
        m = EncryptionMetadata.from_dict({"type": "x", "hash": "sha256:" + "ab" * 32, "size": 0, "chunks": 1})
        assert (m.size, m.chunks) == (0, 1)

    @pytest.mark.parametrize("size", [1, 70_000])
    def test_zero_chunks_with_content_is_still_refused(self, size):
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="nonsensical size/chunks"):
            EncryptionMetadata.from_dict({"type": "x", "hash": "sha256:" + "ab" * 32, "size": size, "chunks": 0})

    def test_a_negative_chunk_count_is_still_refused(self):
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="nonsensical size/chunks"):
            EncryptionMetadata.from_dict({"type": "x", "hash": "sha256:" + "ab" * 32, "size": 0, "chunks": -1})

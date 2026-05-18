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

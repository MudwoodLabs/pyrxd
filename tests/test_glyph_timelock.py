"""Tests for ``pyrxd.glyph.timelock`` — TIMELOCK builder + state helpers.

Three layers:

1. Photonic interop — reproduce Photonic's ``addTimelockToMetadata``
   output dict using the same fixed inputs from the bridge fixture, and
   assert byte-equal output.
2. CEK hash round-trip — compute, format, parse, verify.
3. State helpers — is_unlocked / get_unlock_remaining across modes
   and clock-supplied / clock-missing cases.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pyrxd.glyph.encrypted_content import (
    KEY_FORMAT_WRAPPED,
    SCHEME_CHUNKED_AEAD_V1,
    CryptoMetadata,
    EncryptedContentStub,
    EncryptionMetadata,
    TimelockSpec,
)
from pyrxd.glyph.timelock import (
    TimelockParams,
    add_timelock_to_metadata,
    compute_cek_hash,
    format_cek_hash,
    get_unlock_remaining,
    is_unlocked,
    parse_cek_hash,
    verify_cek_reveal,
)
from pyrxd.glyph.types import GlyphProtocol
from pyrxd.security.errors import ValidationError

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "photonic_timelock_vectors.json"


@pytest.fixture(scope="module")
def photonic_vectors() -> dict:
    return json.loads(FIXTURES_PATH.read_text())


def _bridge_cek() -> bytes:
    """The CEK used by the bridge script: ``(i*17+1) & 0xff`` for i in 0..31."""
    return bytes((i * 17 + 1) & 0xFF for i in range(32))


def _bridge_stub_for_block_mode() -> EncryptedContentStub:
    """Reconstruct the input stub the bridge script feeds to addTimelockToMetadata."""
    cek = _bridge_cek()
    cek_hash = format_cek_hash(compute_cek_hash(cek))
    pt_small = b"hello, photonic timelock interop"
    return EncryptedContentStub(
        p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
        type="image/png",
        name="Sealed Test #1",
        main=EncryptionMetadata(
            type="image/png",
            hash=format_cek_hash(hashlib.sha256(pt_small).digest()),
            size=len(pt_small),
            chunks=1,
            scheme=SCHEME_CHUNKED_AEAD_V1,
        ),
        crypto=CryptoMetadata(
            mode="encrypted",
            key_format=KEY_FORMAT_WRAPPED,
            cek_hash=cek_hash,
        ),
    )


def _bridge_stub_for_time_mode() -> EncryptedContentStub:
    """Reconstruct the time-mode input stub (PT_LARGE plaintext)."""
    cek = _bridge_cek()
    cek_hash = format_cek_hash(compute_cek_hash(cek))
    pt_large = bytes((i * 13 + 3) & 0xFF for i in range(8192))
    return EncryptedContentStub(
        p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
        type="application/octet-stream",
        name="Sealed Test #2",
        main=EncryptionMetadata(
            type="application/octet-stream",
            hash=format_cek_hash(hashlib.sha256(pt_large).digest()),
            size=len(pt_large),
            chunks=1,
            scheme=SCHEME_CHUNKED_AEAD_V1,
        ),
        crypto=CryptoMetadata(
            mode="encrypted",
            key_format=KEY_FORMAT_WRAPPED,
            cek_hash=cek_hash,
        ),
    )


# ────────────────────────────────────────────── CEK hash helpers ──


class TestCEKHashHelpers:
    def test_compute_cek_hash_matches_bridge(self, photonic_vectors):
        v = photonic_vectors["cek_hash_commitment"]
        cek = bytes.fromhex(v["cek"])
        expected_bytes = bytes.fromhex(v["cek_hash_bytes"])
        assert compute_cek_hash(cek) == expected_bytes

    def test_format_cek_hash_matches_bridge(self, photonic_vectors):
        v = photonic_vectors["cek_hash_commitment"]
        cek = bytes.fromhex(v["cek"])
        h = compute_cek_hash(cek)
        assert format_cek_hash(h) == v["cek_hash_string"]

    def test_format_then_parse_round_trip(self):
        h = compute_cek_hash(b"x" * 32)
        s = format_cek_hash(h)
        assert parse_cek_hash(s) == h

    def test_parse_accepts_mixed_case_prefix(self):
        h = compute_cek_hash(b"x" * 32)
        s = "SHA256:" + h.hex().upper()
        # parse_cek_hash lowercases the prefix check; hex is parsed
        # case-insensitive by bytes.fromhex
        assert parse_cek_hash(s) == h

    def test_parse_rejects_missing_prefix(self):
        with pytest.raises(ValueError, match="sha256: prefix"):
            parse_cek_hash("ab" * 32)

    def test_parse_rejects_wrong_hex_length(self):
        with pytest.raises(ValueError, match="64 hex chars"):
            parse_cek_hash("sha256:abcd")

    def test_compute_rejects_wrong_cek_size(self):
        with pytest.raises(ValueError, match="CEK must be 32"):
            compute_cek_hash(b"\x00" * 31)

    def test_verify_cek_reveal_accepts_string_commitment(self):
        cek = b"y" * 32
        commitment = format_cek_hash(compute_cek_hash(cek))
        assert verify_cek_reveal(cek, commitment)

    def test_verify_cek_reveal_accepts_bytes_commitment(self):
        cek = b"y" * 32
        assert verify_cek_reveal(cek, compute_cek_hash(cek))

    def test_verify_cek_reveal_rejects_wrong_cek(self):
        cek = b"y" * 32
        wrong = b"z" * 32
        commitment = format_cek_hash(compute_cek_hash(cek))
        assert not verify_cek_reveal(wrong, commitment)


# ────────────────────────────────────────────── Photonic interop builder ──


class TestPhotonicInteropBuilder:
    def test_block_mode_output_byte_equal(self, photonic_vectors):
        v = photonic_vectors["timelock_metadata_block_mode"]
        cek = _bridge_cek()
        stub = _bridge_stub_for_block_mode()
        result = add_timelock_to_metadata(
            stub,
            cek,
            TimelockParams(mode="block", unlock_at=v["unlock_at"]),
        )
        pyrxd_dict = result.metadata.to_dict()
        photonic_dict = v["output_metadata"]
        assert pyrxd_dict == photonic_dict, (
            "pyrxd's add_timelock_to_metadata output differs from Photonic's "
            "addTimelockToMetadata output — wire format diverges"
        )

    def test_time_mode_output_byte_equal(self, photonic_vectors):
        v = photonic_vectors["timelock_metadata_time_mode"]
        cek = _bridge_cek()
        stub = _bridge_stub_for_time_mode()
        result = add_timelock_to_metadata(
            stub,
            cek,
            TimelockParams(mode="time", unlock_at=v["unlock_at"], hint=v["hint"]),
        )
        pyrxd_dict = result.metadata.to_dict()
        photonic_dict = v["output_metadata"]
        assert pyrxd_dict == photonic_dict

    def test_block_mode_commitment_matches(self, photonic_vectors):
        v = photonic_vectors["timelock_metadata_block_mode"]
        cek = _bridge_cek()
        stub = _bridge_stub_for_block_mode()
        result = add_timelock_to_metadata(
            stub,
            cek,
            TimelockParams(mode="block", unlock_at=v["unlock_at"]),
        )
        assert result.metadata.crypto.timelock is not None
        assert (
            result.metadata.crypto.timelock.cek_hash == v["output_commitment"]["cekHash"].lower()
            or result.metadata.crypto.timelock.cek_hash == f"sha256:{v['output_commitment']['cekHash'].lower()}"
        )


# ────────────────────────────────────────────── builder semantics ──


class TestBuilderSemantics:
    def _make_encrypted_stub(self) -> EncryptedContentStub:
        cek = b"k" * 32
        return EncryptedContentStub(
            p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
            type="text/plain",
            name="test",
            main=EncryptionMetadata(
                type="text/plain",
                hash=format_cek_hash(b"\x00" * 32),
            ),
            crypto=CryptoMetadata(cek_hash=format_cek_hash(compute_cek_hash(cek))),
        )

    def test_appends_timelock_to_protocols(self):
        stub = self._make_encrypted_stub()
        cek = b"k" * 32
        result = add_timelock_to_metadata(
            stub,
            cek,
            TimelockParams(mode="block", unlock_at=100),
        )
        assert GlyphProtocol.TIMELOCK in result.metadata.p
        assert GlyphProtocol.ENCRYPTED in result.metadata.p
        assert GlyphProtocol.NFT in result.metadata.p

    def test_idempotent_protocol_addition(self):
        stub = self._make_encrypted_stub()
        # Pre-stuff TIMELOCK into the protocol list — should not double-add
        stub_with_tl = EncryptedContentStub(
            p=[*stub.p, GlyphProtocol.TIMELOCK],
            type=stub.type,
            name=stub.name,
            main=stub.main,
            crypto=stub.crypto,
        )
        cek = b"k" * 32
        result = add_timelock_to_metadata(
            stub_with_tl,
            cek,
            TimelockParams(mode="block", unlock_at=100),
        )
        assert result.metadata.p.count(GlyphProtocol.TIMELOCK) == 1

    def test_rejects_stub_without_encrypted(self):
        cek = b"k" * 32
        stub_no_enc = EncryptedContentStub(
            p=[GlyphProtocol.NFT],
            type="text/plain",
            name="t",
            main=EncryptionMetadata(type="text/plain", hash=format_cek_hash(b"\x00" * 32)),
            crypto=CryptoMetadata(cek_hash=format_cek_hash(compute_cek_hash(cek))),
        )
        with pytest.raises(ValidationError, match="ENCRYPTED"):
            add_timelock_to_metadata(
                stub_no_enc,
                cek,
                TimelockParams(mode="block", unlock_at=100),
            )

    def test_rejects_wrong_cek_size(self):
        stub = self._make_encrypted_stub()
        with pytest.raises(ValueError, match="32 bytes"):
            add_timelock_to_metadata(
                stub,
                b"\x00" * 31,
                TimelockParams(mode="block", unlock_at=100),
            )

    def test_rejects_invalid_mode(self):
        stub = self._make_encrypted_stub()
        with pytest.raises(ValueError, match="mode must be"):
            add_timelock_to_metadata(
                stub,
                b"k" * 32,
                TimelockParams(mode="ridiculous", unlock_at=100),  # type: ignore[arg-type]
            )

    def test_hint_propagates(self):
        stub = self._make_encrypted_stub()
        result = add_timelock_to_metadata(
            stub,
            b"k" * 32,
            TimelockParams(mode="time", unlock_at=1_700_000_000, hint="see-me-later"),
        )
        assert result.metadata.crypto.timelock is not None
        assert result.metadata.crypto.timelock.hint == "see-me-later"

    def test_returns_cek_for_off_chain_storage(self):
        stub = self._make_encrypted_stub()
        cek = b"k" * 32
        result = add_timelock_to_metadata(
            stub,
            cek,
            TimelockParams(mode="block", unlock_at=100),
        )
        assert result.cek_for_caller_to_store == cek


# ────────────────────────────────────────────── state helpers ──


class TestStateHelpers:
    def _locked_block_stub(self, unlock_at: int) -> EncryptedContentStub:
        cek = b"k" * 32
        return EncryptedContentStub(
            p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            type="text/plain",
            name="t",
            main=EncryptionMetadata(type="text/plain", hash=format_cek_hash(b"\x00" * 32)),
            crypto=CryptoMetadata(
                cek_hash=format_cek_hash(compute_cek_hash(cek)),
                timelock=TimelockSpec(
                    mode="block",
                    unlock_at=unlock_at,
                    cek_hash=format_cek_hash(compute_cek_hash(cek)),
                ),
            ),
        )

    def _locked_time_stub(self, unlock_at: int) -> EncryptedContentStub:
        cek = b"k" * 32
        return EncryptedContentStub(
            p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED, GlyphProtocol.TIMELOCK],
            type="text/plain",
            name="t",
            main=EncryptionMetadata(type="text/plain", hash=format_cek_hash(b"\x00" * 32)),
            crypto=CryptoMetadata(
                cek_hash=format_cek_hash(compute_cek_hash(cek)),
                timelock=TimelockSpec(
                    mode="time",
                    unlock_at=unlock_at,
                    cek_hash=format_cek_hash(compute_cek_hash(cek)),
                ),
            ),
        )

    def test_non_timelock_token_is_always_unlocked(self):
        cek = b"k" * 32
        stub = EncryptedContentStub(
            p=[GlyphProtocol.NFT, GlyphProtocol.ENCRYPTED],
            type="text/plain",
            name="t",
            main=EncryptionMetadata(type="text/plain", hash=format_cek_hash(b"\x00" * 32)),
            crypto=CryptoMetadata(cek_hash=format_cek_hash(compute_cek_hash(cek))),
        )
        assert is_unlocked(stub)
        assert get_unlock_remaining(stub) == 0

    def test_block_mode_locked_before_unlock(self):
        stub = self._locked_block_stub(unlock_at=500)
        assert not is_unlocked(stub, current_block=499)
        assert is_unlocked(stub, current_block=500)
        assert is_unlocked(stub, current_block=501)

    def test_block_mode_remaining(self):
        stub = self._locked_block_stub(unlock_at=500)
        assert get_unlock_remaining(stub, current_block=480) == 20
        assert get_unlock_remaining(stub, current_block=500) == 0
        assert get_unlock_remaining(stub, current_block=520) == 0

    def test_time_mode_locked_before_unlock(self):
        stub = self._locked_time_stub(unlock_at=1_700_000_000)
        assert not is_unlocked(stub, current_time=1_699_999_999)
        assert is_unlocked(stub, current_time=1_700_000_000)
        assert is_unlocked(stub, current_time=1_700_000_001)

    def test_block_mode_without_block_returns_locked(self):
        stub = self._locked_block_stub(unlock_at=500)
        assert not is_unlocked(stub)  # no current_block supplied
        assert get_unlock_remaining(stub) == 0  # can't compute

    def test_time_mode_without_time_returns_locked(self):
        stub = self._locked_time_stub(unlock_at=1_700_000_000)
        assert not is_unlocked(stub)

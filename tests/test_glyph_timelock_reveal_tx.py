"""Tests for ``pyrxd.glyph.timelock_reveal_tx``.

Critical interop guarantee: pyrxd can parse Photonic-emitted reveal-proof
scripts byte-for-byte. Round-trip in pyrxd produces semantically-equivalent
proofs (canonical CBOR may differ from Photonic's 2-byte map-length form;
both spec-valid).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyrxd.glyph.timelock import compute_cek_hash, format_cek_hash
from pyrxd.glyph.timelock_reveal_tx import (
    GLYPH_MAGIC_BYTES,
    REVEAL_ACTION,
    REVEAL_MARKER,
    REVEAL_VERSION,
    RevealProof,
    create_reveal_proof,
    parse_reveal_proof_script,
    validate_reveal_proof,
)

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "photonic_timelock_vectors.json"


@pytest.fixture(scope="module")
def photonic_vectors() -> dict:
    return json.loads(FIXTURES_PATH.read_text())


def _bridge_cek() -> bytes:
    return bytes((i * 17 + 1) & 0xFF for i in range(32))


# ────────────────────────────────────────────── Photonic interop ──


class TestPhotonicInteropParse:
    """The critical gate: pyrxd parses Photonic's emitted OP_RETURN scripts."""

    @pytest.mark.parametrize(
        "vector_key",
        [
            "reveal_proof_block_mode",
            "reveal_proof_time_mode",
            "reveal_proof_with_hint",
        ],
    )
    def test_parse_photonic_reveal_script(self, photonic_vectors, vector_key):
        v = photonic_vectors[vector_key]
        script = bytes.fromhex(v["op_return_script_hex"])
        parsed = parse_reveal_proof_script(script)
        assert parsed is not None, f"failed to parse Photonic reveal script for {vector_key}"

        expected = v["proof"]
        assert parsed.v == expected["v"]
        assert parsed.p == expected["p"]
        assert parsed.action == expected["action"]
        assert parsed.token_ref == expected["token_ref"]
        assert parsed.cek == expected["cek"]
        assert parsed.cek_hash == expected["cek_hash"]
        if "hint" in expected:
            assert parsed.hint == expected["hint"]
        else:
            assert parsed.hint == ""

    def test_parse_returns_valid_proof_for_known_cek(self, photonic_vectors):
        """Round-trip: parsed proof should validate against the expected
        CEK + token_ref from the fixture."""
        v = photonic_vectors["reveal_proof_block_mode"]
        script = bytes.fromhex(v["op_return_script_hex"])
        proof = parse_reveal_proof_script(script)
        assert proof is not None

        result = validate_reveal_proof(
            proof,
            expected_token_ref=v["token_ref"],
            expected_cek_hash=f"sha256:{compute_cek_hash(_bridge_cek()).hex()}",
        )
        assert result.valid, f"validation failed: {result.error}"


# ────────────────────────────────────────────── construction ──


class TestCreateRevealProof:
    def test_returns_script_and_proof(self):
        token_ref = "a" * 64 + ":0"
        cek = b"k" * 32
        script, proof = create_reveal_proof(token_ref, cek)
        assert isinstance(script, bytes)
        assert isinstance(proof, RevealProof)

    def test_script_starts_with_op_return_then_magic(self):
        script, _ = create_reveal_proof("a" * 64 + ":0", b"k" * 32)
        assert script[0] == 0x6A  # OP_RETURN
        # Next is push of "gly" magic = `03 676c79`
        assert script[1] == 0x03
        assert script[2:5] == GLYPH_MAGIC_BYTES

    def test_script_version_marker_bytes(self):
        script, _ = create_reveal_proof("a" * 64 + ":0", b"k" * 32)
        # After OP_RETURN + magic push: `01 02 01 09` (version + marker pushes)
        assert script[5:7] == bytes([0x01, REVEAL_VERSION])
        assert script[7:9] == bytes([0x01, REVEAL_MARKER])

    def test_proof_fields_correct(self):
        token_ref = "a" * 64 + ":0"
        cek = b"k" * 32
        _, proof = create_reveal_proof(token_ref, cek)
        assert proof.v == REVEAL_VERSION
        assert proof.p == [REVEAL_MARKER]
        assert proof.action == REVEAL_ACTION
        assert proof.token_ref == token_ref
        assert proof.cek == cek.hex()
        assert proof.cek_hash == format_cek_hash(compute_cek_hash(cek))

    def test_hint_propagates(self):
        _, proof = create_reveal_proof("a" * 64 + ":0", b"k" * 32, hint="auction")
        assert proof.hint == "auction"

    def test_no_hint_omitted_from_proof_dict(self):
        _, proof = create_reveal_proof("a" * 64 + ":0", b"k" * 32)
        assert "hint" not in proof.to_dict()

    def test_cek_hash_override_must_match(self):
        cek = b"k" * 32
        correct = format_cek_hash(compute_cek_hash(cek))
        # Correct override is fine.
        create_reveal_proof("a" * 64 + ":0", cek, cek_hash_override=correct)
        # Wrong override is rejected.
        wrong = "sha256:" + ("ab" * 32)
        with pytest.raises(ValueError, match="does not match"):
            create_reveal_proof("a" * 64 + ":0", cek, cek_hash_override=wrong)

    def test_rejects_wrong_cek_size(self):
        with pytest.raises(ValueError, match="CEK must be 32"):
            create_reveal_proof("a" * 64 + ":0", b"k" * 31)

    def test_rejects_malformed_token_ref(self):
        with pytest.raises(ValueError, match="txid:vout"):
            create_reveal_proof("not-a-valid-ref", b"k" * 32)
        with pytest.raises(ValueError, match="txid:vout"):
            create_reveal_proof("a" * 64, b"k" * 32)  # missing :vout


# ────────────────────────────────────────────── round-trip ──


class TestRoundTrip:
    def test_create_then_parse(self):
        token_ref = "b" * 64 + ":3"
        cek = bytes(range(32))
        script, original = create_reveal_proof(token_ref, cek, hint="test hint")
        parsed = parse_reveal_proof_script(script)
        assert parsed == original

    def test_round_trip_no_hint(self):
        script, original = create_reveal_proof("b" * 64 + ":3", bytes(range(32)))
        parsed = parse_reveal_proof_script(script)
        assert parsed is not None
        assert parsed == original
        assert parsed.hint == ""


# ────────────────────────────────────────────── parser footguns ──


class TestParserFootguns:
    def test_parse_empty_script_returns_none(self):
        assert parse_reveal_proof_script(b"") is None

    def test_parse_non_op_return_returns_none(self):
        # First byte must be OP_RETURN
        script = b"\x76\x03\x67\x6c\x79"  # OP_DUP + push gly
        assert parse_reveal_proof_script(script) is None

    def test_parse_wrong_magic_returns_none(self):
        script = b"\x6a\x03abc\x01\x02\x01\x09\x01\xa0"
        assert parse_reveal_proof_script(script) is None

    def test_parse_wrong_version_returns_none(self):
        script = b"\x6a\x03\x67\x6c\x79\x01\xff\x01\x09\x01\xa0"  # version 0xff
        assert parse_reveal_proof_script(script) is None

    def test_parse_wrong_marker_returns_none(self):
        script = b"\x6a\x03\x67\x6c\x79\x01\x02\x01\xff\x01\xa0"  # marker 0xff
        assert parse_reveal_proof_script(script) is None

    def test_parse_truncated_returns_none(self):
        # Has all the prefix bytes but truncated mid-CBOR
        script = b"\x6a\x03\x67\x6c\x79\x01\x02\x01\x09\x4c\xfe" + b"\x00" * 10  # claims 254 bytes, only has 10
        assert parse_reveal_proof_script(script) is None

    def test_parse_malformed_cbor_returns_none(self):
        # Valid prefix, then a single 0xff byte (CBOR "break" / invalid here)
        script = b"\x6a\x03\x67\x6c\x79\x01\x02\x01\x09\x01\xff"
        assert parse_reveal_proof_script(script) is None


# ────────────────────────────────────────────── validation ──


class TestValidateRevealProof:
    def _good_proof(self, token_ref="a" * 64 + ":0", cek=b"k" * 32):
        _, proof = create_reveal_proof(token_ref, cek)
        return proof, cek

    def test_valid_proof_accepts(self):
        proof, cek = self._good_proof()
        result = validate_reveal_proof(
            proof,
            expected_token_ref="a" * 64 + ":0",
            expected_cek_hash=format_cek_hash(compute_cek_hash(cek)),
        )
        assert result.valid
        assert result.error == ""

    def test_valid_proof_without_explicit_commitment_check(self):
        proof, _cek = self._good_proof()
        result = validate_reveal_proof(proof, expected_token_ref="a" * 64 + ":0")
        assert result.valid

    def test_wrong_token_ref_rejected(self):
        proof, _cek = self._good_proof()
        result = validate_reveal_proof(proof, expected_token_ref="b" * 64 + ":0")
        assert not result.valid
        assert "token_ref" in result.error

    def test_wrong_expected_commitment_rejected(self):
        proof, _cek = self._good_proof()
        wrong_commit = format_cek_hash(b"\x00" * 32)
        result = validate_reveal_proof(
            proof,
            expected_token_ref="a" * 64 + ":0",
            expected_cek_hash=wrong_commit,
        )
        assert not result.valid
        assert "commitment" in result.error

    def test_tampered_cek_self_consistency_fails(self):
        proof, _cek = self._good_proof()
        # Construct a tampered proof where cek hex doesn't hash to cek_hash
        bad_proof = RevealProof(
            v=proof.v,
            p=proof.p,
            action=proof.action,
            token_ref=proof.token_ref,
            cek="ff" * 32,  # different CEK
            cek_hash=proof.cek_hash,  # but unchanged hash
        )
        result = validate_reveal_proof(bad_proof, expected_token_ref="a" * 64 + ":0")
        assert not result.valid
        assert "self-consistency" in result.error

    def test_malformed_cek_hex_rejected(self):
        proof, _cek = self._good_proof()
        bad = RevealProof(
            v=proof.v,
            p=proof.p,
            action=proof.action,
            token_ref=proof.token_ref,
            cek="not hex!" * 8,  # 64 chars but not hex
            cek_hash=proof.cek_hash,
        )
        result = validate_reveal_proof(bad, expected_token_ref="a" * 64 + ":0")
        assert not result.valid

    def test_malformed_cek_hash_rejected(self):
        proof, _cek = self._good_proof()
        bad = RevealProof(
            v=proof.v,
            p=proof.p,
            action=proof.action,
            token_ref=proof.token_ref,
            cek=proof.cek,
            cek_hash="not-a-valid-format",
        )
        result = validate_reveal_proof(bad, expected_token_ref="a" * 64 + ":0")
        assert not result.valid
        assert "malformed" in result.error or "self-consistency" in result.error

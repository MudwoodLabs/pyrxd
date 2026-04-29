"""Tests for MUT, CONTAINER, and WAVE GlyphBuilder methods, and updated GlyphInspector."""
from __future__ import annotations

import pytest

from pyrxd.glyph.builder import (
    ContainerRevealScripts,
    GlyphBuilder,
    MutableRevealScripts,
)
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.script import (
    MUTABLE_NFT_SCRIPT_RE,
    build_mutable_nft_script,
    build_nft_locking_script,
    parse_mutable_nft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

TXID = "aa" * 32
TXID2 = "cc" * 32
PKH = Hex20(bytes.fromhex("bb" * 20))
REF = GlyphRef(txid=Txid(TXID), vout=0)
CHILD_REF = GlyphRef(txid=Txid(TXID2), vout=1)


def _cbor(protocol: list[int], name: str = "test") -> bytes:
    cbor_bytes, _ = encode_payload(GlyphMetadata(name=name, protocol=protocol))
    return cbor_bytes


MUT_CBOR = _cbor([GlyphProtocol.NFT, GlyphProtocol.MUT], "mut-test")
CONTAINER_CBOR = _cbor([GlyphProtocol.NFT, GlyphProtocol.CONTAINER], "container-test")
WAVE_CBOR = _cbor(
    [GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE], "myname.rxd"
)

BUILDER = GlyphBuilder()
INSPECTOR = GlyphInspector()


# ---------------------------------------------------------------------------
# MUT builder tests
# ---------------------------------------------------------------------------


class TestPrepareMutableReveal:
    def test_returns_mutable_reveal_scripts(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert isinstance(result, MutableRevealScripts)

    def test_nft_script_is_63_bytes(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.nft_script) == 63

    def test_contract_script_is_174_bytes(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.contract_script) == 174

    def test_contract_script_matches_mutable_re(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert MUTABLE_NFT_SCRIPT_RE.fullmatch(result.contract_script.hex())

    def test_payload_hash_is_32_bytes(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.payload_hash) == 32

    def test_ref_matches_commit_txid_and_vout(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 3, MUT_CBOR, PKH)
        assert result.ref.txid == TXID
        assert result.ref.vout == 3

    def test_payload_hash_embedded_in_contract_script(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        parsed = parse_mutable_nft_script(result.contract_script)
        assert parsed is not None
        _, embedded_hash = parsed
        assert embedded_hash == result.payload_hash

    def test_contract_ref_matches_nft_ref(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        parsed = parse_mutable_nft_script(result.contract_script)
        assert parsed is not None
        contract_ref, _ = parsed
        assert contract_ref == result.ref

    def test_scriptsig_suffix_not_empty(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.scriptsig_suffix) > 0

    def test_scriptsig_suffix_starts_with_gly_marker(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert b"gly" in result.scriptsig_suffix

    def test_raises_when_protocol_missing_mut(self):
        nft_only_cbor = _cbor([GlyphProtocol.NFT], "bad")
        with pytest.raises(ValidationError, match="MUT"):
            BUILDER.prepare_mutable_reveal(TXID, 0, nft_only_cbor, PKH)

    def test_raises_on_invalid_cbor(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_mutable_reveal(TXID, 0, b"\xff\xfe\xfd", PKH)

    def test_different_vouts_produce_different_refs(self):
        r0 = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        r1 = BUILDER.prepare_mutable_reveal(TXID, 1, MUT_CBOR, PKH)
        assert r0.ref != r1.ref
        assert r0.nft_script != r1.nft_script

    def test_nft_script_starts_with_singleton_opcode(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert result.nft_script[0] == 0xD8  # OP_PUSHINPUTREFSINGLETON


# ---------------------------------------------------------------------------
# CONTAINER builder tests
# ---------------------------------------------------------------------------


class TestPrepareContainerReveal:
    def test_returns_container_reveal_scripts(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert isinstance(result, ContainerRevealScripts)

    def test_no_child_ref_yields_63_byte_script(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert len(result.locking_script) == 63
        assert result.child_ref is None

    def test_with_child_ref_yields_100_byte_script(self):
        result = BUILDER.prepare_container_reveal(
            TXID, 0, CONTAINER_CBOR, PKH, child_ref=CHILD_REF
        )
        assert len(result.locking_script) == 100
        assert result.child_ref == CHILD_REF

    def test_child_ref_prefix_opcode(self):
        result = BUILDER.prepare_container_reveal(
            TXID, 0, CONTAINER_CBOR, PKH, child_ref=CHILD_REF
        )
        assert result.locking_script[0] == 0xD0  # OP_PUSHINPUTREF (non-singleton)

    def test_child_ref_bytes_embedded(self):
        result = BUILDER.prepare_container_reveal(
            TXID, 0, CONTAINER_CBOR, PKH, child_ref=CHILD_REF
        )
        child_wire = CHILD_REF.to_bytes()
        assert result.locking_script[1:37] == child_wire

    def test_nft_body_appended_after_child_ref(self):
        result_no_child = BUILDER.prepare_container_reveal(
            TXID, 0, CONTAINER_CBOR, PKH
        )
        result_with_child = BUILDER.prepare_container_reveal(
            TXID, 0, CONTAINER_CBOR, PKH, child_ref=CHILD_REF
        )
        # NFT body (63 bytes) should be the suffix of the 100-byte script
        assert result_with_child.locking_script[37:] == result_no_child.locking_script

    def test_raises_when_protocol_missing_container(self):
        nft_only_cbor = _cbor([GlyphProtocol.NFT], "bad")
        with pytest.raises(ValidationError, match="CONTAINER"):
            BUILDER.prepare_container_reveal(TXID, 0, nft_only_cbor, PKH)

    def test_scriptsig_suffix_contains_gly(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert b"gly" in result.scriptsig_suffix

    def test_ref_matches_commit_params(self):
        result = BUILDER.prepare_container_reveal(TXID, 2, CONTAINER_CBOR, PKH)
        assert result.ref.txid == TXID
        assert result.ref.vout == 2

    def test_empty_container_child_ref_is_none(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert result.child_ref is None


# ---------------------------------------------------------------------------
# WAVE builder tests
# ---------------------------------------------------------------------------


class TestPrepareWaveReveal:
    def test_returns_mutable_reveal_scripts(self):
        result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        assert isinstance(result, MutableRevealScripts)

    def test_nft_script_is_63_bytes(self):
        result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        assert len(result.nft_script) == 63

    def test_contract_script_is_174_bytes(self):
        result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        assert len(result.contract_script) == 174

    def test_raises_when_name_empty(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "")

    def test_raises_when_name_too_long(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "a" * 256)

    def test_raises_when_name_has_control_chars(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "bad\x00name")

    def test_raises_when_protocol_missing_wave(self):
        mut_only_cbor = _cbor([GlyphProtocol.NFT, GlyphProtocol.MUT], "mut")
        with pytest.raises(ValidationError, match="WAVE"):
            BUILDER.prepare_wave_reveal(TXID, 0, mut_only_cbor, PKH, "name")

    def test_raises_when_protocol_missing_mut(self):
        # GlyphMetadata validates protocol combos — WAVE without MUT raises at
        # metadata construction time before we even get to the builder.
        with pytest.raises(ValidationError):
            _cbor([GlyphProtocol.NFT, GlyphProtocol.WAVE], "name")

    def test_raises_when_cbor_name_mismatch(self):
        with pytest.raises(ValidationError, match="name"):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "different.rxd")

    def test_wave_uses_same_two_output_structure_as_mut(self):
        wave_result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        # Both outputs present
        assert wave_result.nft_script
        assert wave_result.contract_script
        assert MUTABLE_NFT_SCRIPT_RE.fullmatch(wave_result.contract_script.hex())

    def test_255_char_name_is_valid(self):
        name = "a" * 255
        cbor_255, _ = encode_payload(
            GlyphMetadata(name=name, protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE])
        )
        # Should not raise
        result = BUILDER.prepare_wave_reveal(TXID, 0, cbor_255, PKH, name)
        assert len(result.nft_script) == 63


# ---------------------------------------------------------------------------
# GlyphInspector MUT detection tests
# ---------------------------------------------------------------------------


class TestInspectorMutDetection:
    def test_detects_mutable_script(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert len(glyphs) == 1
        assert glyphs[0].glyph_type == "mut"

    def test_mutable_glyph_type_is_mut(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert glyphs[0].glyph_type == "mut"

    def test_mutable_ref_extracted_correctly(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert glyphs[0].ref == REF

    def test_mutable_metadata_is_none(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert glyphs[0].metadata is None

    def test_nft_still_detected_alongside_mut(self):
        nft_script = build_nft_locking_script(PKH, REF)
        mutable_script = build_mutable_nft_script(GlyphRef(txid=Txid(TXID2), vout=0), b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, nft_script), (546, mutable_script)])
        types = {g.glyph_type for g in glyphs}
        assert "nft" in types
        assert "mut" in types

    def test_plain_script_not_detected_as_mut(self):
        plain = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        glyphs = INSPECTOR.find_glyphs([(1000, plain)])
        assert glyphs == []

    def test_mut_vout_index_is_correct(self):
        plain = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(1000, plain), (546, mutable_script)])
        assert glyphs[0].vout == 1

    def test_mut_from_prepare_mutable_reveal(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        glyphs = INSPECTOR.find_glyphs([(546, result.contract_script)])
        assert glyphs[0].glyph_type == "mut"

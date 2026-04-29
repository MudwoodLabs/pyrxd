"""Tests for pyrxd.glyph — Phase 1c: Glyph NFT/FT protocol support."""
from __future__ import annotations

import struct

import cbor2
import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.inspector import GlyphInspector, GlyphOutput
from pyrxd.glyph.payload import (
    GLY_MARKER,
    build_reveal_scriptsig_suffix,
    decode_payload,
    encode_payload,
)
from pyrxd.glyph.script import (
    build_commit_locking_script,
    build_ft_locking_script,
    build_nft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    hash_payload,
    is_ft_script,
    is_nft_script,
)
from pyrxd.glyph.types import GlyphFt, GlyphMedia, GlyphMetadata, GlyphNft, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

KNOWN_TXID = "a" * 64                    # 64 hex chars
KNOWN_PKH = bytes(range(20))             # 20 distinct bytes
KNOWN_REF = GlyphRef(txid=Txid(KNOWN_TXID), vout=0)
KNOWN_HEX20 = Hex20(KNOWN_PKH)

SIMPLE_TXID = "01" * 32                  # 0101...01 (64 chars)
SIMPLE_REF = GlyphRef(txid=Txid(SIMPLE_TXID), vout=0)

NFT_METADATA = GlyphMetadata(
    protocol=[GlyphProtocol.NFT],
    name="Test NFT",
    token_type="art",
    attrs={"artist": "Alice"},
)

FT_METADATA = GlyphMetadata(
    protocol=[GlyphProtocol.FT],
    name="Test Token",
    ticker="TST",
    description="A test fungible token",
)


# ---------------------------------------------------------------------------
# 1. Script construction
# ---------------------------------------------------------------------------

class TestScriptConstruction:
    def test_nft_script_is_63_bytes(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert len(script) == 63

    def test_ft_script_is_75_bytes(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert len(script) == 75

    def test_nft_script_passes_nft_classifier(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert is_nft_script(script.hex())

    def test_ft_script_passes_ft_classifier(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert is_ft_script(script.hex())

    def test_nft_script_does_not_pass_ft_classifier(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert not is_ft_script(script.hex())

    def test_ft_script_does_not_pass_nft_classifier(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert not is_nft_script(script.hex())

    def test_random_bytes_do_not_pass_either_classifier(self):
        random_hex = "deadbeef" * 8
        assert not is_nft_script(random_hex)
        assert not is_ft_script(random_hex)

    def test_empty_string_does_not_pass_classifiers(self):
        assert not is_nft_script("")
        assert not is_ft_script("")

    def test_nft_script_starts_with_d8(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert script[0] == 0xd8

    def test_ft_script_starts_with_p2pkh(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert script[:3] == b'\x76\xa9\x14'

    def test_ft_script_has_conservation_epilogue(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        # Last 12 bytes are FT conservation epilogue
        assert script[-12:] == bytes.fromhex("dec0e9aa76e378e4a269e69d")


# ---------------------------------------------------------------------------
# 2. GlyphRef encoding / round-trip
# ---------------------------------------------------------------------------

class TestGlyphRefEncoding:
    def test_roundtrip(self):
        ref = GlyphRef(txid=Txid(KNOWN_TXID), vout=7)
        recovered = GlyphRef.from_bytes(ref.to_bytes())
        assert recovered.txid == ref.txid
        assert recovered.vout == ref.vout

    def test_known_wire_bytes(self):
        # Simple txid: "01" * 32 → bytes are all 0x01 → reversed = all 0x01
        ref = GlyphRef(txid=Txid(SIMPLE_TXID), vout=0)
        wire = ref.to_bytes()
        assert len(wire) == 36
        assert wire[:32] == bytes([0x01] * 32)        # reversed txid (still all 0x01)
        assert wire[32:] == struct.pack('<I', 0)       # vout=0 LE

    def test_vout_encoded_le(self):
        ref = GlyphRef(txid=Txid(SIMPLE_TXID), vout=256)
        wire = ref.to_bytes()
        assert wire[32:] == struct.pack('<I', 256)

    def test_35_byte_input_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef.from_bytes(bytes(35))

    def test_37_byte_input_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef.from_bytes(bytes(37))

    def test_negative_vout_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid(KNOWN_TXID), vout=-1)

    def test_vout_overflow_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid(KNOWN_TXID), vout=0x1_0000_0000)

    def test_max_vout_is_valid(self):
        ref = GlyphRef(txid=Txid(KNOWN_TXID), vout=0xFFFFFFFF)
        recovered = GlyphRef.from_bytes(ref.to_bytes())
        assert recovered.vout == 0xFFFFFFFF


# ---------------------------------------------------------------------------
# 3. Script extraction
# ---------------------------------------------------------------------------

class TestScriptExtraction:
    def test_extract_ref_from_nft_script(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        ref = extract_ref_from_nft_script(script)
        assert ref.txid == KNOWN_REF.txid
        assert ref.vout == KNOWN_REF.vout

    def test_extract_pkh_from_nft_script(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        pkh = extract_owner_pkh_from_nft_script(script)
        assert bytes(pkh) == bytes(KNOWN_HEX20)

    def test_extract_ref_from_ft_script(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        ref = extract_ref_from_ft_script(script)
        assert ref.txid == KNOWN_REF.txid
        assert ref.vout == KNOWN_REF.vout

    def test_extract_pkh_from_ft_script(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        pkh = extract_owner_pkh_from_ft_script(script)
        assert bytes(pkh) == bytes(KNOWN_HEX20)

    def test_ft_script_to_nft_extractor_raises(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        with pytest.raises(ValidationError):
            extract_ref_from_nft_script(script)

    def test_nft_script_to_ft_extractor_raises(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        with pytest.raises(ValidationError):
            extract_ref_from_ft_script(script)

    def test_short_script_nft_extractor_raises(self):
        with pytest.raises(ValidationError):
            extract_ref_from_nft_script(bytes(10))

    def test_short_script_ft_extractor_raises(self):
        with pytest.raises(ValidationError):
            extract_ref_from_ft_script(bytes(10))


# ---------------------------------------------------------------------------
# 4. CBOR payload encode/decode
# ---------------------------------------------------------------------------

class TestCborPayload:
    def test_nft_roundtrip(self):
        cbor_bytes, _ = encode_payload(NFT_METADATA)
        recovered = decode_payload(cbor_bytes)
        assert recovered.protocol == NFT_METADATA.protocol
        assert recovered.name == NFT_METADATA.name
        assert recovered.token_type == NFT_METADATA.token_type
        assert recovered.attrs == NFT_METADATA.attrs

    def test_ft_roundtrip(self):
        cbor_bytes, _ = encode_payload(FT_METADATA)
        recovered = decode_payload(cbor_bytes)
        assert recovered.protocol == FT_METADATA.protocol
        assert recovered.name == FT_METADATA.name
        assert recovered.ticker == FT_METADATA.ticker
        assert recovered.description == FT_METADATA.description

    def test_hash_is_deterministic(self):
        data = b"hello glyph"
        h1 = hash_payload(data)
        h2 = hash_payload(data)
        assert h1 == h2

    def test_hash_is_32_bytes(self):
        h = hash_payload(b"test")
        assert len(h) == 32

    def test_hash_differs_for_different_inputs(self):
        h1 = hash_payload(b"data1")
        h2 = hash_payload(b"data2")
        assert h1 != h2

    def test_malformed_cbor_raises(self):
        # b'\x1e' is an unknown unsigned integer subtype — cbor2 raises a decode error
        with pytest.raises(ValidationError, match="Invalid CBOR"):
            decode_payload(b"\x1e")

    def test_cbor_without_p_field_raises(self):
        bad_cbor = cbor2.dumps({"name": "no protocol"})
        with pytest.raises(ValidationError, match="missing 'p' field"):
            decode_payload(bad_cbor)

    def test_cbor_non_map_raises(self):
        list_cbor = cbor2.dumps([1, 2, 3])
        with pytest.raises(ValidationError, match="must be a map"):
            decode_payload(list_cbor)

    def test_nft_with_media_roundtrip(self):
        media = GlyphMedia(mime_type="image/png", data=b"\x89PNG" + bytes(10))
        meta = GlyphMetadata(
            protocol=[GlyphProtocol.NFT],
            name="Art NFT",
            main=media,
        )
        cbor_bytes, _ = encode_payload(meta)
        recovered = decode_payload(cbor_bytes)
        assert recovered.main is not None
        assert recovered.main.mime_type == "image/png"
        assert recovered.main.data == media.data

    def test_encode_payload_returns_32_byte_hash(self):
        _, payload_hash = encode_payload(NFT_METADATA)
        assert len(payload_hash) == 32


# ---------------------------------------------------------------------------
# 5. ScriptSig suffix
# ---------------------------------------------------------------------------

class TestScriptSigSuffix:
    def test_suffix_starts_with_gly_push(self):
        cbor_bytes, _ = encode_payload(NFT_METADATA)
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        # First 4 bytes: 03 + "gly"
        assert suffix[:4] == b'\x03gly'

    def test_suffix_small_payload_direct_push(self):
        # cbor < 76 bytes → direct length byte
        small_cbor = cbor2.dumps({"p": [2]})
        assert len(small_cbor) <= 75
        suffix = build_reveal_scriptsig_suffix(small_cbor)
        # After gly push (4 bytes), length byte then data
        assert suffix[4] == len(small_cbor)

    def test_suffix_medium_payload_uses_pushdata1(self):
        # Create payload that is 76-255 bytes by adding a long name
        meta = GlyphMetadata(protocol=[2], name="x" * 200)
        cbor_bytes = cbor2.dumps(meta.to_cbor_dict())
        assert 76 <= len(cbor_bytes) <= 255
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        # After gly push (4 bytes): OP_PUSHDATA1 (0x4c) + length byte
        assert suffix[4] == 0x4c
        assert suffix[5] == len(cbor_bytes)

    def test_oversized_payload_raises(self):
        # 65536+ bytes cbor payload
        huge_cbor = bytes(65536)
        with pytest.raises(ValidationError, match="too large"):
            build_reveal_scriptsig_suffix(huge_cbor)


# ---------------------------------------------------------------------------
# 6. Inspector
# ---------------------------------------------------------------------------

class TestGlyphInspector:
    def _make_outputs(self, *scripts: bytes) -> list[tuple[int, bytes]]:
        """Wrap scripts as (satoshis, script) pairs."""
        return [(546, s) for s in scripts]

    def test_detects_nft_output(self):
        nft_script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(nft_script))
        assert len(results) == 1
        assert results[0].glyph_type == "nft"
        assert results[0].vout == 0

    def test_detects_ft_output(self):
        ft_script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(ft_script))
        assert len(results) == 1
        assert results[0].glyph_type == "ft"

    def test_ignores_plain_p2pkh(self):
        # Standard P2PKH: 76 a9 14 <20 bytes> 88 ac  (25 bytes)
        p2pkh = b'\x76\xa9\x14' + bytes(20) + b'\x88\xac'
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(p2pkh))
        assert results == []

    def test_detects_mixed_outputs(self):
        nft_script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        ft_script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        p2pkh = b'\x76\xa9\x14' + bytes(20) + b'\x88\xac'
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(p2pkh, nft_script, ft_script))
        assert len(results) == 2
        assert results[0].vout == 1
        assert results[0].glyph_type == "nft"
        assert results[1].vout == 2
        assert results[1].glyph_type == "ft"

    def test_extract_reveal_returns_none_for_p2pkh_scriptsig(self):
        # Typical P2PKH scriptSig: <sig(71-73b)> <pubkey(33b)>
        sig = bytes([0x47]) + bytes(71)      # push 71 bytes
        pubkey = bytes([0x21]) + bytes(33)   # push 33 bytes
        scriptsig = sig + pubkey
        inspector = GlyphInspector()
        assert inspector.extract_reveal_metadata(scriptsig) is None

    def test_extract_reveal_metadata_with_valid_scriptsig(self):
        """Construct a reveal scriptSig manually and verify parsing."""
        cbor_bytes, _ = encode_payload(NFT_METADATA)
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)

        # Prepend dummy sig + pubkey
        dummy_sig = bytes([0x47]) + bytes(71)     # push 71 bytes (sig placeholder)
        dummy_pubkey = bytes([0x21]) + bytes(33)  # push 33 bytes (pubkey placeholder)
        scriptsig = dummy_sig + dummy_pubkey + suffix

        inspector = GlyphInspector()
        result = inspector.extract_reveal_metadata(scriptsig)
        assert result is not None
        assert result.name == NFT_METADATA.name
        assert result.protocol == NFT_METADATA.protocol

    def test_extract_reveal_empty_scriptsig_returns_none(self):
        inspector = GlyphInspector()
        assert inspector.extract_reveal_metadata(b"") is None

    def test_find_glyphs_nft_ref_matches(self):
        nft_script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(nft_script))
        assert results[0].ref.txid == KNOWN_REF.txid
        assert results[0].ref.vout == KNOWN_REF.vout

    def test_find_glyphs_ft_ref_matches(self):
        ft_script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(ft_script))
        assert results[0].ref.txid == KNOWN_REF.txid
        assert results[0].ref.vout == KNOWN_REF.vout


# ---------------------------------------------------------------------------
# 7. Builder
# ---------------------------------------------------------------------------

class TestGlyphBuilder:
    def _make_commit_params(self, metadata: GlyphMetadata = NFT_METADATA) -> CommitParams:
        return CommitParams(
            metadata=metadata,
            owner_pkh=KNOWN_HEX20,
            change_pkh=KNOWN_HEX20,
            funding_satoshis=1_000_000,
        )

    def test_prepare_commit_returns_32_byte_hash(self):
        builder = GlyphBuilder()
        result = builder.prepare_commit(self._make_commit_params())
        assert len(result.payload_hash) == 32

    def test_prepare_commit_cbor_bytes_nonempty(self):
        builder = GlyphBuilder()
        result = builder.prepare_commit(self._make_commit_params())
        assert len(result.cbor_bytes) > 0

    def test_prepare_commit_script_nonempty(self):
        builder = GlyphBuilder()
        result = builder.prepare_commit(self._make_commit_params())
        assert len(result.commit_script) > 0

    def test_prepare_commit_estimated_fee_positive(self):
        builder = GlyphBuilder()
        result = builder.prepare_commit(self._make_commit_params())
        assert result.estimated_fee > 0

    def test_prepare_reveal_nft_returns_63_byte_script(self):
        builder = GlyphBuilder()
        commit_result = builder.prepare_commit(self._make_commit_params(NFT_METADATA))
        reveal_params = RevealParams(
            commit_txid=KNOWN_TXID,
            commit_vout=0,
            commit_value=546,
            cbor_bytes=commit_result.cbor_bytes,
            owner_pkh=KNOWN_HEX20,
            is_nft=True,
        )
        scripts = builder.prepare_reveal(reveal_params)
        assert len(scripts.locking_script) == 63

    def test_prepare_reveal_ft_returns_75_byte_script(self):
        builder = GlyphBuilder()
        commit_result = builder.prepare_commit(self._make_commit_params(FT_METADATA))
        reveal_params = RevealParams(
            commit_txid=KNOWN_TXID,
            commit_vout=0,
            commit_value=546,
            cbor_bytes=commit_result.cbor_bytes,
            owner_pkh=KNOWN_HEX20,
            is_nft=False,
        )
        scripts = builder.prepare_reveal(reveal_params)
        assert len(scripts.locking_script) == 75

    def test_prepare_reveal_scriptsig_suffix_starts_with_gly(self):
        builder = GlyphBuilder()
        commit_result = builder.prepare_commit(self._make_commit_params())
        reveal_params = RevealParams(
            commit_txid=KNOWN_TXID,
            commit_vout=0,
            commit_value=546,
            cbor_bytes=commit_result.cbor_bytes,
            owner_pkh=KNOWN_HEX20,
            is_nft=True,
        )
        scripts = builder.prepare_reveal(reveal_params)
        assert scripts.scriptsig_suffix[:4] == b'\x03gly'

    def test_build_transfer_nft_returns_63_bytes(self):
        builder = GlyphBuilder()
        script = builder.build_transfer_locking_script(KNOWN_REF, KNOWN_HEX20, is_nft=True)
        assert len(script) == 63

    def test_build_transfer_ft_returns_75_bytes(self):
        builder = GlyphBuilder()
        script = builder.build_transfer_locking_script(KNOWN_REF, KNOWN_HEX20, is_nft=False)
        assert len(script) == 75

    def test_build_transfer_nft_passes_classifier(self):
        builder = GlyphBuilder()
        script = builder.build_transfer_locking_script(KNOWN_REF, KNOWN_HEX20, is_nft=True)
        assert is_nft_script(script.hex())

    def test_build_transfer_ft_passes_classifier(self):
        builder = GlyphBuilder()
        script = builder.build_transfer_locking_script(KNOWN_REF, KNOWN_HEX20, is_nft=False)
        assert is_ft_script(script.hex())


# ---------------------------------------------------------------------------
# 8. Security / rejection cases
# ---------------------------------------------------------------------------

class TestSecurityRejection:
    def test_glyph_media_data_over_100kb_raises(self):
        with pytest.raises(ValidationError, match="too large"):
            GlyphMedia(mime_type="image/png", data=bytes(100_001))

    def test_glyph_media_exactly_100kb_is_valid(self):
        media = GlyphMedia(mime_type="image/png", data=bytes(100_000))
        assert len(media.data) == 100_000

    def test_glyph_ref_negative_vout_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid(KNOWN_TXID), vout=-1)

    def test_glyph_ref_vout_over_max_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid(KNOWN_TXID), vout=0x1_0000_0000)

    def test_bad_mime_type_no_slash_raises(self):
        with pytest.raises(ValidationError, match="Invalid MIME type"):
            GlyphMedia(mime_type="imagepng", data=b"\x89PNG")

    def test_empty_mime_type_raises(self):
        with pytest.raises(ValidationError, match="Invalid MIME type"):
            GlyphMedia(mime_type="", data=b"data")

    def test_commit_script_wrong_hash_len_raises(self):
        with pytest.raises(ValidationError, match="32 bytes"):
            build_commit_locking_script(bytes(31), KNOWN_HEX20)

    def test_commit_script_empty_hash_raises(self):
        with pytest.raises(ValidationError):
            build_commit_locking_script(b"", KNOWN_HEX20)

    def test_invalid_txid_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("not_a_valid_txid"), vout=0)

    def test_invalid_txid_too_short_raises(self):
        with pytest.raises(ValidationError):
            GlyphRef(txid=Txid("ab" * 31), vout=0)   # 62 chars, not 64


# ---------------------------------------------------------------------------
# 9. GlyphProtocol enum
# ---------------------------------------------------------------------------

class TestGlyphProtocol:
    def test_protocol_values(self):
        assert GlyphProtocol.FT == 1
        assert GlyphProtocol.NFT == 2
        assert GlyphProtocol.DAT == 3
        assert GlyphProtocol.DMINT == 4
        assert GlyphProtocol.MUT == 5
        assert GlyphProtocol.BURN == 6
        assert GlyphProtocol.CONTAINER == 7
        assert GlyphProtocol.WAVE == 11

    def test_protocol_in_metadata(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT])
        assert list(meta.protocol) == [2]

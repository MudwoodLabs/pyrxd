"""Tests for pyrxd.glyph — Phase 1c: Glyph NFT/FT protocol support."""

from __future__ import annotations

import struct

import cbor2
import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import (
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
from pyrxd.glyph.types import GlyphMedia, GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

KNOWN_TXID = "a" * 64  # 64 hex chars
KNOWN_PKH = bytes(range(20))  # 20 distinct bytes
KNOWN_REF = GlyphRef(txid=Txid(KNOWN_TXID), vout=0)
KNOWN_HEX20 = Hex20(KNOWN_PKH)

SIMPLE_TXID = "01" * 32  # 0101...01 (64 chars)
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

    def test_is_ft_script_requires_hex_str_not_bytes(self):
        from pyrxd.script.script import Script

        script_bytes = Script(build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)).serialize()
        assert is_ft_script(script_bytes.hex())
        with pytest.raises(TypeError):
            is_ft_script(script_bytes)  # type: ignore[arg-type]

    def test_nft_script_starts_with_d8(self):
        script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert script[0] == 0xD8

    def test_ft_script_starts_with_p2pkh(self):
        script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert script[:3] == b"\x76\xa9\x14"

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
        assert wire[:32] == bytes([0x01] * 32)  # reversed txid (still all 0x01)
        assert wire[32:] == struct.pack("<I", 0)  # vout=0 LE

    def test_vout_encoded_le(self):
        ref = GlyphRef(txid=Txid(SIMPLE_TXID), vout=256)
        wire = ref.to_bytes()
        assert wire[32:] == struct.pack("<I", 256)

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


class TestGlyphRefFromContractHex:
    """Parsing the explorer/UI display form: txid (display order) + vout BE."""

    # RBG mainnet contract id; the trailing "00000004" reads as 4 (big-endian).
    RBG_CONTRACT = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a800000004"
    RBG_TXID = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8"
    NON_PALINDROMIC_TXID = "0123456789abcdef" * 4  # 64 chars, reversal-distinct

    def test_decodes_real_world_contract(self):
        ref = GlyphRef.from_contract_hex(self.RBG_CONTRACT)
        assert ref.txid == self.RBG_TXID
        assert ref.vout == 4

    def test_vout_is_big_endian(self):
        # Contract tail "00000100" reads as 256 in big-endian.
        contract = "ab" * 32 + "00000100"
        ref = GlyphRef.from_contract_hex(contract)
        assert ref.vout == 256

    def test_vout_zero(self):
        contract = "cd" * 32 + "00000000"
        ref = GlyphRef.from_contract_hex(contract)
        assert ref.vout == 0

    def test_vout_max(self):
        contract = "ef" * 32 + "ffffffff"
        ref = GlyphRef.from_contract_hex(contract)
        assert ref.vout == 0xFFFFFFFF

    def test_round_trip(self):
        # Build a contract string from a known ref, then recover it.
        ref = GlyphRef(txid=Txid(self.NON_PALINDROMIC_TXID), vout=42)
        contract = ref.txid + ref.vout.to_bytes(4, "big").hex()
        recovered = GlyphRef.from_contract_hex(contract)
        assert recovered == ref

    def test_short_string_raises(self):
        with pytest.raises(ValidationError, match="72 hex chars"):
            GlyphRef.from_contract_hex("ab" * 32 + "0000")  # 68 chars

    def test_long_string_raises(self):
        with pytest.raises(ValidationError, match="72 hex chars"):
            GlyphRef.from_contract_hex("ab" * 32 + "0000000000")  # 74 chars

    def test_non_hex_in_vout_raises(self):
        with pytest.raises(ValidationError, match="non-hex"):
            GlyphRef.from_contract_hex("ab" * 32 + "zzzzzzzz")

    def test_non_str_input_raises(self):
        with pytest.raises(ValidationError, match="must be str"):
            GlyphRef.from_contract_hex(b"\x00" * 36)  # type: ignore[arg-type]

    def test_distinct_from_from_bytes(self):
        """``from_contract_hex`` and ``from_bytes`` parse different formats:
        contract uses display-order txid + big-endian vout; wire uses
        reversed txid + little-endian vout."""
        ref = GlyphRef(txid=Txid(self.NON_PALINDROMIC_TXID), vout=4)
        wire_hex = ref.to_bytes().hex()  # reversed txid + vout LE
        contract_hex = ref.txid + ref.vout.to_bytes(4, "big").hex()
        # Same ref, different serialisations.
        assert wire_hex != contract_hex
        assert wire_hex[:64] != contract_hex[:64]  # txid byte order differs
        assert wire_hex[64:] != contract_hex[64:]  # vout endianness differs (for vout=4)
        # Both round-trip to the same ref via their respective decoders.
        assert GlyphRef.from_bytes(bytes.fromhex(wire_hex)) == ref
        assert GlyphRef.from_contract_hex(contract_hex) == ref


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
        assert suffix[:4] == b"\x03gly"

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
        assert suffix[4] == 0x4C
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
        p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(p2pkh))
        assert results == []

    def test_detects_mixed_outputs(self):
        nft_script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        ft_script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        inspector = GlyphInspector()
        results = inspector.find_glyphs(self._make_outputs(p2pkh, nft_script, ft_script))
        assert len(results) == 2
        assert results[0].vout == 1
        assert results[0].glyph_type == "nft"
        assert results[1].vout == 2
        assert results[1].glyph_type == "ft"

    def test_extract_reveal_returns_none_for_p2pkh_scriptsig(self):
        # Typical P2PKH scriptSig: <sig(71-73b)> <pubkey(33b)>
        sig = bytes([0x47]) + bytes(71)  # push 71 bytes
        pubkey = bytes([0x21]) + bytes(33)  # push 33 bytes
        scriptsig = sig + pubkey
        inspector = GlyphInspector()
        assert inspector.extract_reveal_metadata(scriptsig) is None

    def test_extract_reveal_metadata_with_valid_scriptsig(self):
        """Construct a reveal scriptSig manually and verify parsing."""
        cbor_bytes, _ = encode_payload(NFT_METADATA)
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)

        # Prepend dummy sig + pubkey
        dummy_sig = bytes([0x47]) + bytes(71)  # push 71 bytes (sig placeholder)
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

    def test_extract_reveal_handles_op_pushdata4(self):
        """V1 dMint deploys carry CBOR bodies larger than 65,535 bytes
        (the RBG GLYPH deploy embeds a 65,430-byte PNG, total CBOR body
        65,569 bytes). The reveal scriptSig serialises that with
        OP_PUSHDATA4 (0x4e) because OP_PUSHDATA2's max is 65535.

        Before this fix the walker hit OP_PUSHDATA4 and bailed out
        before finding the 'gly' marker — the metadata silently
        disappeared from the inspect tool's output on every real V1
        deploy. Regression test pinned by mainnet GLYPH (b965b32d…9dd6
        vin 0)."""
        # Build a 70 KB CBOR body — large enough to require OP_PUSHDATA4.
        large_body = cbor2.dumps(
            {
                "p": [1, 4],
                "ticker": "GLYPH",
                "name": "Glyph Protocol",
                "desc": "x" * (70_000 - 100),  # pad to >65535 bytes
            }
        )
        assert len(large_body) > 65_535
        # OP_PUSHDATA4: 0x4e + 4-byte LE length + payload
        push_data4 = bytes([0x4E]) + len(large_body).to_bytes(4, "little") + large_body
        # 'gly' marker: 3-byte direct push of b"gly"
        gly_marker = bytes([0x03]) + b"gly"
        dummy_sig = bytes([0x47]) + bytes(71)
        dummy_pubkey = bytes([0x21]) + bytes(33)
        scriptsig = dummy_sig + dummy_pubkey + gly_marker + push_data4

        inspector = GlyphInspector()
        result = inspector.extract_reveal_metadata(scriptsig)
        assert result is not None
        assert result.ticker == "GLYPH"
        assert result.name == "Glyph Protocol"

    def test_decode_payload_unwraps_cbor_tag_64_for_main_blob(self):
        """Photonic Wallet wraps embedded media in CBOR tag 64 (uint8-array).
        Real V1 dMint deploys (e.g. GLYPH) carry ``main.b = CBORTag(64,
        <png bytes>)``. Before this fix ``decode_payload`` raised
        TypeError on ``bytes(CBORTag)`` and the entire reveal metadata
        was discarded."""
        from pyrxd.glyph.payload import decode_payload

        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100  # 108 bytes synthetic PNG
        body = cbor2.dumps(
            {
                "p": [1, 4],
                "ticker": "TAG64",
                "name": "Tag64 Token",
                "main": {
                    "t": "image/png",
                    "b": cbor2.CBORTag(64, png_bytes),
                },
            }
        )
        meta = decode_payload(body)
        assert meta.ticker == "TAG64"
        assert meta.main is not None
        assert meta.main.mime_type == "image/png"
        assert meta.main.data == png_bytes

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

    def test_find_glyphs_populates_owner_pkh_for_nft(self):
        nft_script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        results = GlyphInspector().find_glyphs(self._make_outputs(nft_script))
        assert results[0].owner_pkh is not None
        assert bytes(results[0].owner_pkh) == bytes(KNOWN_HEX20)

    def test_find_glyphs_populates_owner_pkh_for_ft(self):
        ft_script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        results = GlyphInspector().find_glyphs(self._make_outputs(ft_script))
        assert results[0].owner_pkh is not None
        assert bytes(results[0].owner_pkh) == bytes(KNOWN_HEX20)

    def test_find_glyphs_classifies_dmint_contract_output(self):
        from pyrxd.glyph.dmint import DmintDeployParams, build_dmint_contract_script

        contract_ref = GlyphRef(txid="aa" * 32, vout=1)
        token_ref = GlyphRef(txid="bb" * 32, vout=0)
        params = DmintDeployParams(
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=1000,
            reward=100,
            difficulty=10,
        )
        script = build_dmint_contract_script(params)
        results = GlyphInspector().find_glyphs(self._make_outputs(script))
        assert len(results) == 1
        assert results[0].glyph_type == "dmint"
        # `ref` is the contract's own outpoint (the contract UTXO's identity).
        assert results[0].ref == contract_ref
        # The token this contract mints lives on the parsed dmint state.
        assert results[0].dmint_state is not None
        assert results[0].dmint_state.token_ref == token_ref
        # No owner_pkh on dmint contracts (they're not P2PKH-locked).
        assert results[0].owner_pkh is None

    def test_find_glyphs_does_not_misclassify_ft_as_dmint(self):
        """Regression: an FT lock script must NOT be picked up by the dmint
        branch — that was the original confusion. is_ft_script wins first."""
        ft_script = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        results = GlyphInspector().find_glyphs(self._make_outputs(ft_script))
        assert len(results) == 1
        assert results[0].glyph_type == "ft"

    def test_glyph_output_extra_fields_default_none(self):
        """Existing callers constructing GlyphOutput with the original 5
        positional args must still work — owner_pkh and dmint_state default."""
        nft_script = build_nft_locking_script(KNOWN_HEX20, KNOWN_REF)
        from pyrxd.glyph.inspector import GlyphOutput

        out = GlyphOutput(
            vout=0,
            glyph_type="nft",
            ref=KNOWN_REF,
            metadata=None,
            script=nft_script,
        )
        assert out.owner_pkh is None
        assert out.dmint_state is None

    def test_find_reveal_metadata_walks_all_inputs(self):
        cbor_bytes, _ = encode_payload(NFT_METADATA)
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        dummy_sig = bytes([0x47]) + bytes(71)
        dummy_pubkey = bytes([0x21]) + bytes(33)
        reveal_scriptsig = dummy_sig + dummy_pubkey + suffix
        plain_scriptsig = dummy_sig + dummy_pubkey

        # Reveal scriptSig at input index 2 — earlier inputs are plain P2PKH.
        scriptsigs = [plain_scriptsig, plain_scriptsig, reveal_scriptsig]
        result = GlyphInspector().find_reveal_metadata(scriptsigs)
        assert result is not None
        idx, metadata = result
        assert idx == 2
        assert metadata.name == NFT_METADATA.name

    def test_find_reveal_metadata_returns_none_when_no_metadata(self):
        dummy_sig = bytes([0x47]) + bytes(71)
        dummy_pubkey = bytes([0x21]) + bytes(33)
        plain = dummy_sig + dummy_pubkey
        assert GlyphInspector().find_reveal_metadata([plain, plain]) is None

    def test_find_reveal_metadata_returns_first_match(self):
        cbor_bytes, _ = encode_payload(NFT_METADATA)
        suffix = build_reveal_scriptsig_suffix(cbor_bytes)
        dummy_sig = bytes([0x47]) + bytes(71)
        dummy_pubkey = bytes([0x21]) + bytes(33)
        reveal = dummy_sig + dummy_pubkey + suffix
        # Two reveal scriptsigs — first match wins (input 0).
        result = GlyphInspector().find_reveal_metadata([reveal, reveal])
        assert result is not None
        assert result[0] == 0


# ---------------------------------------------------------------------------
# 6b. Commit-script helpers + dmint classifier
# ---------------------------------------------------------------------------


class TestCommitScriptHelpers:
    PAYLOAD_HASH = bytes(range(32))
    OWNER_PKH_BYTES = bytes(range(40, 60))

    def test_is_commit_script_accepts_nft_variant(self):
        from pyrxd.glyph.script import build_commit_locking_script, is_commit_script

        s = build_commit_locking_script(self.PAYLOAD_HASH, Hex20(self.OWNER_PKH_BYTES), is_nft=True)
        assert is_commit_script(s.hex())

    def test_is_commit_script_accepts_ft_variant(self):
        from pyrxd.glyph.script import build_commit_locking_script, is_commit_script

        s = build_commit_locking_script(self.PAYLOAD_HASH, Hex20(self.OWNER_PKH_BYTES), is_nft=False)
        assert is_commit_script(s.hex())

    def test_is_commit_nft_distinguishes_from_ft(self):
        from pyrxd.glyph.script import (
            build_commit_locking_script,
            is_commit_ft_script,
            is_commit_nft_script,
        )

        nft = build_commit_locking_script(self.PAYLOAD_HASH, Hex20(self.OWNER_PKH_BYTES), is_nft=True)
        ft = build_commit_locking_script(self.PAYLOAD_HASH, Hex20(self.OWNER_PKH_BYTES), is_nft=False)
        assert is_commit_nft_script(nft.hex())
        assert not is_commit_nft_script(ft.hex())
        assert is_commit_ft_script(ft.hex())
        assert not is_commit_ft_script(nft.hex())

    def test_is_commit_script_rejects_p2pkh(self):
        from pyrxd.glyph.script import is_commit_script

        p2pkh = (b"\x76\xa9\x14" + bytes(20) + b"\x88\xac").hex()
        assert not is_commit_script(p2pkh)

    def test_extract_payload_hash_round_trips(self):
        from pyrxd.glyph.script import (
            build_commit_locking_script,
            extract_payload_hash_from_commit_script,
        )

        s = build_commit_locking_script(self.PAYLOAD_HASH, Hex20(self.OWNER_PKH_BYTES), is_nft=True)
        assert extract_payload_hash_from_commit_script(s) == self.PAYLOAD_HASH

    def test_extract_owner_pkh_round_trips(self):
        from pyrxd.glyph.script import (
            build_commit_locking_script,
            extract_owner_pkh_from_commit_script,
        )

        s = build_commit_locking_script(self.PAYLOAD_HASH, Hex20(self.OWNER_PKH_BYTES), is_nft=False)
        assert bytes(extract_owner_pkh_from_commit_script(s)) == self.OWNER_PKH_BYTES

    def test_extract_payload_hash_rejects_non_commit(self):
        from pyrxd.glyph.script import (
            build_ft_locking_script,
            extract_payload_hash_from_commit_script,
        )

        ft = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        with pytest.raises(ValidationError, match="Not a valid commit script"):
            extract_payload_hash_from_commit_script(ft)


class TestIsDmintContractScript:
    def _params(self) -> object:
        from pyrxd.glyph.dmint import DmintDeployParams

        return DmintDeployParams(
            contract_ref=GlyphRef(txid="aa" * 32, vout=1),
            token_ref=GlyphRef(txid="bb" * 32, vout=0),
            max_height=1000,
            reward=100,
            difficulty=10,
        )

    def test_true_for_built_contract_script(self):
        from pyrxd.glyph.dmint import build_dmint_contract_script
        from pyrxd.glyph.script import is_dmint_contract_script

        s = build_dmint_contract_script(self._params())
        assert is_dmint_contract_script(s) is True

    def test_false_for_p2pkh(self):
        from pyrxd.glyph.script import is_dmint_contract_script

        p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        assert is_dmint_contract_script(p2pkh) is False

    def test_false_for_ft_lock_script(self):
        """REGRESSION: the original user bug — an FT lock must NOT be classified
        as a dmint contract output. They share neither length nor layout, but
        defensive: confirm explicitly."""
        from pyrxd.glyph.script import build_ft_locking_script, is_dmint_contract_script

        ft = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        assert is_dmint_contract_script(ft) is False

    def test_false_for_empty(self):
        from pyrxd.glyph.script import is_dmint_contract_script

        assert is_dmint_contract_script(b"") is False

    def test_false_for_truncated_dmint_script(self):
        from pyrxd.glyph.dmint import build_dmint_contract_script
        from pyrxd.glyph.script import is_dmint_contract_script

        full = build_dmint_contract_script(self._params())
        assert is_dmint_contract_script(full[:50]) is False


# ---------------------------------------------------------------------------
# 6c. V1 dMint contract parser (real mainnet bytes from RBG)
# ---------------------------------------------------------------------------

# RBG ($RBG / RadiantBulldog) is a real dMint token deployed on Radiant
# mainnet at block 228704. These three contract scripts come from the reveal
# tx ``c5c296ebff5869c6e2b208ce0cd04be479a9f10d33cf73608f0a5efc2d6b55b6``
# vouts 0, 5, and 9 respectively (three of the 10 dMint contracts spawned
# by the reveal). They share an identical template — the only on-chain
# difference is the contractRef vout (1, 6, and 10 respectively).
#
# Capturing real mainnet bytes is the strongest possible regression test:
# if the V1 parser ever drifts from what's actually deployed, these tests
# break.

_RBG_DMINT_V1_VOUT_0 = bytes.fromhex(
    "0400000000d8a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4"
    "01000000d0a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4"
    "000000000330ff66023818085c8fc2f5285c8f02bd5175c0c855797ea8597959797ea87e5a7a7eaa"
    "bc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0c"
    "dec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d"
    "635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e988"
    "5379cc519d75686d7551"
)
_RBG_DMINT_V1_VOUT_5 = bytes.fromhex(
    "0400000000d8a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4"
    "06000000d0a8a296afde31eb80c3484f09da7eb31546990baf76fd8bff9a58fbbe53c45db4"
    "000000000330ff66023818085c8fc2f5285c8f02bd5175c0c855797ea8597959797ea87e5a7a7eaa"
    "bc01147f77587f040000000088817600a269a269577ae500a069567ae600a06901d053797e0c"
    "dec0e9aa76e378e4a269e69d7eaa76e47b9d547a818b76537a9c537ade789181547ae6939d"
    "635279cd01d853797e016a7e886778de519d547854807ec0eb557f777e5379ec78885379eac0e988"
    "5379cc519d75686d7551"
)


class TestV1DmintParser:
    """Parse real on-chain V1 dMint bytes (the only format on Radiant today)."""

    RBG_TXID = "b45dc453befb589aff8bfd76af0b994615b37eda094f48c380eb31deaf96a2a8"

    def test_parses_real_rbg_contract(self):
        from pyrxd.glyph.dmint import DaaMode, DmintAlgo, DmintState

        state = DmintState.from_script(_RBG_DMINT_V1_VOUT_0)
        assert state.is_v1 is True
        assert state.contract_ref.txid == self.RBG_TXID
        assert state.contract_ref.vout == 1
        assert state.token_ref.txid == self.RBG_TXID
        assert state.token_ref.vout == 0
        assert state.height == 0
        assert state.max_height == 6_750_000
        assert state.reward == 6_200
        assert state.algo is DmintAlgo.SHA256D
        assert state.daa_mode is DaaMode.FIXED
        # V1 fields that aren't encoded on-chain return sentinel zeros.
        assert state.target_time == 0
        assert state.last_time == 0

    def test_contract_ref_vout_varies_across_slots(self):
        """The 10 dmint contracts share template; only contractRef.vout differs."""
        from pyrxd.glyph.dmint import DmintState

        s0 = DmintState.from_script(_RBG_DMINT_V1_VOUT_0)
        s5 = DmintState.from_script(_RBG_DMINT_V1_VOUT_5)
        assert s0.contract_ref.vout == 1
        assert s5.contract_ref.vout == 6
        # Everything else is identical.
        assert s0.token_ref == s5.token_ref
        assert s0.max_height == s5.max_height
        assert s0.reward == s5.reward
        assert s0.algo == s5.algo

    def test_total_supply_matches_rbg_disclosure(self):
        """RBG total supply = max_height × reward = 41,850,000,000 photons."""
        from pyrxd.glyph.dmint import DmintState

        state = DmintState.from_script(_RBG_DMINT_V1_VOUT_0)
        assert state.max_height * state.reward == 41_850_000_000

    def test_dispatcher_falls_through_v2_to_v1(self):
        """``DmintState.from_script`` tries V2 first, then V1. On V1 bytes
        the V2 parser must raise ValidationError; the dispatcher must catch
        that and successfully invoke V1 — never reach the user."""
        from pyrxd.glyph.dmint import DmintState
        from pyrxd.security.errors import ValidationError

        # V2 parser raises directly on V1 bytes.
        with pytest.raises(ValidationError):
            DmintState._from_v2_script(_RBG_DMINT_V1_VOUT_0)
        # But the dispatcher returns successfully.
        assert DmintState.from_script(_RBG_DMINT_V1_VOUT_0).is_v1 is True

    def test_is_dmint_contract_script_accepts_v1(self):
        """REGRESSION: before this PR the classifier rejected every V1
        contract on mainnet because it only knew about V2. Locks the fix."""
        from pyrxd.glyph.script import is_dmint_contract_script

        assert is_dmint_contract_script(_RBG_DMINT_V1_VOUT_0) is True
        assert is_dmint_contract_script(_RBG_DMINT_V1_VOUT_5) is True

    def test_v1_rejects_p2pkh(self):
        """A plain P2PKH must not match V1 epilogue fingerprint."""
        from pyrxd.glyph.dmint import DmintState
        from pyrxd.security.errors import ValidationError

        p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        with pytest.raises(ValidationError):
            DmintState._from_v1_script(p2pkh)

    def test_v1_rejects_ft_script(self):
        """An FT lock starts with 76a9... — V1's first byte must be 0x04
        (push-4 for height). FT must NOT match."""
        from pyrxd.glyph.dmint import DmintState
        from pyrxd.glyph.script import build_ft_locking_script
        from pyrxd.security.errors import ValidationError

        ft = build_ft_locking_script(KNOWN_HEX20, KNOWN_REF)
        with pytest.raises(ValidationError):
            DmintState._from_v1_script(ft)

    def test_v1_rejects_corrupted_epilogue(self):
        """Tweaking one byte of the V1 fingerprint must break the match."""
        from pyrxd.glyph.dmint import DmintState
        from pyrxd.security.errors import ValidationError

        # Corrupt byte 100 (mid-epilogue, well inside the fingerprint region).
        corrupted = bytearray(_RBG_DMINT_V1_VOUT_0)
        corrupted[100] = (corrupted[100] + 1) & 0xFF
        with pytest.raises(ValidationError):
            DmintState._from_v1_script(bytes(corrupted))

    def test_v1_rejects_wrong_algo_byte(self):
        """The algo byte must be 0xaa, 0xee, or 0xef — anything else fails."""
        from pyrxd.glyph.dmint import DmintState
        from pyrxd.security.errors import ValidationError

        # The algo selector is at offset 95+19 = 114 in the script
        # (95 = position of OP_STATESEPARATOR; 19 = epilogue-relative offset).
        corrupted = bytearray(_RBG_DMINT_V1_VOUT_0)
        assert corrupted[114] == 0xAA  # confirm we're patching the right byte
        corrupted[114] = 0x99  # not a valid algo selector
        with pytest.raises(ValidationError):
            DmintState._from_v1_script(bytes(corrupted))

    def test_inspector_classifies_v1_in_find_glyphs(self):
        """`find_glyphs` returns a `dmint`-typed entry for a real V1 contract."""
        from pyrxd.glyph.inspector import GlyphInspector

        results = GlyphInspector().find_glyphs([(1, _RBG_DMINT_V1_VOUT_0)])
        assert len(results) == 1
        assert results[0].glyph_type == "dmint"
        assert results[0].dmint_state is not None
        assert results[0].dmint_state.is_v1 is True

    def test_v1_blake3_algo_byte_decodes(self):
        """V1 supports three algo bytes — patch the RBG fixture to BLAKE3
        (0xee) and confirm the parser picks it up."""
        from pyrxd.glyph.dmint import DmintAlgo, DmintState

        buf = bytearray(_RBG_DMINT_V1_VOUT_0)
        # Algo selector lives at script offset 114 (= bd-position 95 + 19).
        assert buf[114] == 0xAA  # sanity: fixture is SHA256D
        buf[114] = 0xEE  # OP_BLAKE3
        state = DmintState.from_script(bytes(buf))
        assert state.is_v1 is True
        assert state.algo is DmintAlgo.BLAKE3

    def test_v1_k12_algo_byte_decodes(self):
        """V1 K12 algo byte (0xef) parses correctly."""
        from pyrxd.glyph.dmint import DmintAlgo, DmintState

        buf = bytearray(_RBG_DMINT_V1_VOUT_0)
        buf[114] = 0xEF  # OP_K12
        state = DmintState.from_script(bytes(buf))
        assert state.algo is DmintAlgo.K12

    def test_combined_error_message_names_both_versions(self):
        """When neither V2 nor V1 matches, the error message must surface
        both attempted-version errors so callers don't have to guess which
        version they had."""
        from pyrxd.glyph.dmint import DmintState

        p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
        with pytest.raises(ValidationError) as excinfo:
            DmintState.from_script(p2pkh)
        msg = str(excinfo.value)
        assert "V2:" in msg
        assert "V1:" in msg
        assert "not a dMint contract" in msg

    def test_v1_dispatch_in_mint_builder(self):
        """``build_dmint_mint_tx`` dispatches V1 contracts to the V1 mint path.

        V1 mint requires a funding_utxo (V1 contracts are singletons; the
        miner pays reward + fee from a separate plain-RXD input). V1 also
        requires ``current_time=0`` since V1 has no DAA. A V2-width nonce
        against a V1 contract is rejected with a typed ``ValidationError``.
        """
        from pyrxd.glyph.dmint import (
            DmintContractUtxo,
            DmintMinerFundingUtxo,
            DmintState,
            build_dmint_mint_tx,
        )

        v1_state = DmintState.from_script(_RBG_DMINT_V1_VOUT_0)
        assert v1_state.is_v1 is True

        # Live RBG-style contract: singleton with 1 photon
        utxo = DmintContractUtxo(
            txid="aa" * 32,
            vout=0,
            value=1,
            script=_RBG_DMINT_V1_VOUT_0,
            state=v1_state,
        )
        # Funding UTXO covers reward + fee
        funding = DmintMinerFundingUtxo(
            txid="ee" * 32,
            vout=0,
            value=100_000_000,
            script=b"\x76\xa9\x14" + bytes(20) + b"\x88\xac",
        )

        # V1 nonce width is 4 bytes; passing 4 bytes must succeed.
        result = build_dmint_mint_tx(
            contract_utxo=utxo,
            nonce=b"\x00" * 4,
            miner_pkh=bytes(20),
            current_time=0,
            funding_utxo=funding,
        )
        assert result.updated_state.is_v1 is True
        assert result.updated_state.height == v1_state.height + 1

        # A V2-width nonce against a V1 contract is an error.
        with pytest.raises(ValidationError, match="V1 nonce"):
            build_dmint_mint_tx(
                contract_utxo=utxo,
                nonce=b"\x00" * 8,
                miner_pkh=bytes(20),
                current_time=0,
                funding_utxo=funding,
            )


class TestV1MatchEpilogue:
    """Direct unit tests for the ``_match_v1_epilogue`` helper.

    The helper is internal but worth pinning directly so the tests don't
    have to construct a full state-walk to exercise its boundaries.
    """

    def test_returns_algo_on_match(self):
        from pyrxd.glyph.dmint import DmintAlgo, _match_v1_epilogue

        # The RBG fixture's epilogue starts at offset 95.
        algo = _match_v1_epilogue(_RBG_DMINT_V1_VOUT_0, 95)
        assert algo is DmintAlgo.SHA256D

    def test_returns_none_when_start_at_end(self):
        from pyrxd.glyph.dmint import _match_v1_epilogue

        assert _match_v1_epilogue(_RBG_DMINT_V1_VOUT_0, len(_RBG_DMINT_V1_VOUT_0)) is None

    def test_returns_none_when_start_just_short(self):
        """``start`` 1 byte before the real epilogue position must reject —
        the epilogue prefix won't match at that offset."""
        from pyrxd.glyph.dmint import _match_v1_epilogue

        assert _match_v1_epilogue(_RBG_DMINT_V1_VOUT_0, 94) is None

    def test_returns_none_when_remaining_bytes_too_short(self):
        """If fewer than ``_V1_EPILOGUE_LEN`` bytes remain after ``start``,
        the length guard must fire before any byte comparison."""
        from pyrxd.glyph.dmint import _match_v1_epilogue

        # Take only the first 100 bytes — not enough for a 145-byte epilogue.
        truncated = _RBG_DMINT_V1_VOUT_0[:100]
        assert _match_v1_epilogue(truncated, 0) is None

    def test_returns_none_for_invalid_algo_byte(self):
        from pyrxd.glyph.dmint import _match_v1_epilogue

        buf = bytearray(_RBG_DMINT_V1_VOUT_0)
        buf[114] = 0xAB  # not in {0xaa, 0xee, 0xef}
        assert _match_v1_epilogue(bytes(buf), 95) is None

    def test_returns_none_when_prefix_corrupted(self):
        """One byte off in the fixed prefix region (offsets 95-113) must reject."""
        from pyrxd.glyph.dmint import _match_v1_epilogue

        buf = bytearray(_RBG_DMINT_V1_VOUT_0)
        buf[100] = (buf[100] + 1) & 0xFF  # mid-prefix byte
        assert _match_v1_epilogue(bytes(buf), 95) is None

    def test_returns_none_when_suffix_corrupted(self):
        """One byte off in the fixed suffix region must reject."""
        from pyrxd.glyph.dmint import _match_v1_epilogue

        buf = bytearray(_RBG_DMINT_V1_VOUT_0)
        # Last byte of the script — well inside the suffix region.
        buf[-1] = (buf[-1] + 1) & 0xFF
        assert _match_v1_epilogue(bytes(buf), 95) is None


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
        assert scripts.scriptsig_suffix[:4] == b"\x03gly"

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

    def test_mime_type_at_256_char_boundary_is_valid(self):
        """256 chars is the per-IANA generous cap. Real-world MIME
        types max out around 75; this leaves headroom for parameters
        without ever being a meaningful expansion vector."""
        # "image/" prefix (6) + 250 chars to hit exactly 256.
        boundary = "image/" + "x" * 250
        assert len(boundary) == 256
        media = GlyphMedia(mime_type=boundary, data=b"x")
        assert len(media.mime_type) == 256

    def test_mime_type_over_256_chars_raises(self):
        """Defends downstream display callers (e.g. the browser inspect
        tool's ``main`` summary) from a 64KB CBOR mime_type that
        overflows render frames. See GitHub issue #52."""
        over = "image/" + "x" * 251  # 257 chars
        with pytest.raises(ValidationError, match="MIME type too long"):
            GlyphMedia(mime_type=over, data=b"x")

    def test_decode_payload_caps_hostile_mime_type(self):
        """End-to-end: a CBOR payload with a giant mime_type is
        rejected at decode time, not silently propagated to GlyphMedia
        (where it would also be caught — we want the loud error from
        the decoder, with the field name the reader can grep for)."""
        import cbor2

        from pyrxd.glyph.payload import decode_payload

        evil = cbor2.dumps({"p": [GlyphProtocol.NFT.value], "main": {"t": "a" * 65000 + "/b", "b": b"\x00" * 10}})
        with pytest.raises(ValidationError, match="main.t.*too long"):
            decode_payload(evil)

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
            GlyphRef(txid=Txid("ab" * 31), vout=0)  # 62 chars, not 64


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

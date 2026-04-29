"""CBOR cross-decoder test: pyrxd encode ↔ RXinDexer decode.

RXinDexer (Pinball/RXinDexer/indexer/script_utils.py) is a Python reference
implementation built against Photonic Wallet's lib/token.ts logic.  It uses
cbor2, the same library pyrxd uses.  Asserting that pyrxd-encoded payloads
round-trip through RXinDexer's decoder confirms we are on Photonic's canonical
CBOR path and that every field (including the new dMint fields) is encoded with
keys and types that the reference indexer accepts.

The harness is deliberately standalone — it copies the two functions it needs
from script_utils.py rather than importing the whole RXinDexer package, so it
runs without adding RXinDexer to pyrxd's dependencies.
"""
from __future__ import annotations

import sys
import os
import cbor2
import pytest

from pyrxd.glyph.payload import build_reveal_scriptsig_suffix, encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Minimal port of RXinDexer's decode_glyph_from_script
# Source: Pinball/RXinDexer/indexer/script_utils.py
# Copied verbatim so the test has no import-time dependency on RXinDexer.
# ---------------------------------------------------------------------------

_GLYPH_MARKER = b"gly"


def _parse_script_chunks(script_bytes: bytes) -> list[dict]:
    chunks = []
    i = 0
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1
        if 1 <= opcode <= 75:
            buf = script_bytes[i : i + opcode]
            i += opcode
            chunks.append({"opcodenum": opcode, "buf": buf})
        elif opcode == 0x4C:
            n = script_bytes[i]; i += 1
            chunks.append({"opcodenum": opcode, "buf": script_bytes[i : i + n]}); i += n
        elif opcode == 0x4D:
            n = int.from_bytes(script_bytes[i : i + 2], "little"); i += 2
            chunks.append({"opcodenum": opcode, "buf": script_bytes[i : i + n]}); i += n
        elif opcode == 0x4E:
            n = int.from_bytes(script_bytes[i : i + 4], "little"); i += 4
            chunks.append({"opcodenum": opcode, "buf": script_bytes[i : i + n]}); i += n
        elif opcode == 0x00:
            chunks.append({"opcodenum": opcode, "buf": b""})
        else:
            chunks.append({"opcodenum": opcode, "buf": None})
    return chunks


def _rxindexer_decode(script_bytes: bytes) -> dict | None:
    """Port of RXinDexer decode_glyph_from_script — finds gly marker, decodes CBOR."""
    chunks = _parse_script_chunks(script_bytes)
    for idx, chunk in enumerate(chunks):
        if chunk.get("opcodenum") != 3 or chunk.get("buf") != _GLYPH_MARKER:
            continue
        if idx + 1 >= len(chunks):
            return None
        payload_buf = chunks[idx + 1].get("buf")
        if not payload_buf:
            return None
        def _tag_hook(decoder, tag):
            return tag.value
        decoded = cbor2.loads(payload_buf, tag_hook=_tag_hook)
        if not isinstance(decoded, dict) or not isinstance(decoded.get("p"), list):
            return None
        payload = {}
        for k, v in decoded.items():
            if not isinstance(v, dict):
                payload[k] = v
        return {"payload": payload}
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _encode_and_decode(metadata: GlyphMetadata) -> dict:
    """Encode via pyrxd, decode via RXinDexer reference. Returns payload dict."""
    cbor_bytes, _ = encode_payload(metadata)
    script = build_reveal_scriptsig_suffix(cbor_bytes)
    result = _rxindexer_decode(script)
    assert result is not None, "RXinDexer decoder returned None — not recognised as a Glyph"
    return result["payload"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProtocolField:
    def test_nft_protocol_round_trips(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Test NFT")
        payload = _encode_and_decode(meta)
        assert payload["p"] == [2]

    def test_ft_protocol_round_trips(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="Test FT", ticker="TST")
        payload = _encode_and_decode(meta)
        assert payload["p"] == [1]

    def test_dmint_ft_protocol_round_trips(self):
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="Test Token")
        payload = _encode_and_decode(meta)
        assert GlyphProtocol.FT in payload["p"]
        assert GlyphProtocol.DMINT in payload["p"]

    def test_dmint_only_protocol_raises(self):
        # [4] alone is blocked — prepare_reveal requires FT=1 to be present.
        with pytest.raises(ValidationError):
            GlyphMetadata.for_dmint_ft(
                ticker="TST", name="Test Token", protocol=[GlyphProtocol.DMINT]
            )


class TestCoreFields:
    def test_name_round_trips(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="My Token")
        payload = _encode_and_decode(meta)
        assert payload["name"] == "My Token"

    def test_ticker_round_trips(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="Coin", ticker="XYZ")
        payload = _encode_and_decode(meta)
        assert payload["ticker"] == "XYZ"

    def test_description_uses_desc_key(self):
        # Photonic uses "desc", not "description" — verify pyrxd emits "desc"
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="T", description="hello")
        payload = _encode_and_decode(meta)
        assert payload.get("desc") == "hello"
        assert "description" not in payload

    def test_empty_name_omitted(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT])
        payload = _encode_and_decode(meta)
        assert "name" not in payload

    def test_empty_ticker_omitted(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="T")
        payload = _encode_and_decode(meta)
        assert "ticker" not in payload

    def test_empty_description_omitted(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="T")
        payload = _encode_and_decode(meta)
        assert "desc" not in payload


class TestDecimalsField:
    def test_decimals_zero_omitted(self):
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="TST", decimals=0)
        payload = _encode_and_decode(meta)
        assert "decimals" not in payload

    def test_decimals_nonzero_round_trips(self):
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="TST", decimals=8)
        payload = _encode_and_decode(meta)
        assert payload["decimals"] == 8

    def test_decimals_is_int_not_string(self):
        meta = GlyphMetadata.for_dmint_ft(ticker="TST", name="TST", decimals=6)
        payload = _encode_and_decode(meta)
        assert isinstance(payload["decimals"], int)


class TestImageFields:
    def test_image_url_uses_image_key(self):
        # Photonic key is "image" — verify pyrxd emits "image" not "image_url"
        meta = GlyphMetadata(
            protocol=[GlyphProtocol.FT],
            name="T",
            image_url="https://example.org/test-logo.png",
        )
        payload = _encode_and_decode(meta)
        assert payload.get("image") == "https://example.org/test-logo.png"
        assert "image_url" not in payload

    def test_image_ipfs_round_trips(self):
        meta = GlyphMetadata(
            protocol=[GlyphProtocol.FT],
            name="T",
            image_ipfs="ipfs://bafybeiabc123",
        )
        payload = _encode_and_decode(meta)
        assert payload.get("image_ipfs") == "ipfs://bafybeiabc123"

    def test_image_sha256_round_trips(self):
        sha = "a" * 64
        meta = GlyphMetadata(
            protocol=[GlyphProtocol.FT],
            name="T",
            image_sha256=sha,
        )
        payload = _encode_and_decode(meta)
        assert payload.get("image_sha256") == sha

    def test_empty_image_fields_omitted(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT], name="T")
        payload = _encode_and_decode(meta)
        assert "image" not in payload
        assert "image_ipfs" not in payload
        assert "image_sha256" not in payload


class TestFhcPayload:
    """Full reference CBOR payload — the exact shape that will go on-chain."""

    def test_fhc_payload_all_fields_round_trip(self):
        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST",
            name="Test Token",
            decimals=0,
            description="Platform credits for the issuing application.",
            image_url="https://example.org/test-logo.png",
            image_ipfs="ipfs://bafybeiabc123placeholder",
            image_sha256="a" * 64,
        )
        payload = _encode_and_decode(meta)

        assert payload["p"] == [GlyphProtocol.FT, GlyphProtocol.DMINT]
        assert payload["ticker"] == "TST"
        assert payload["name"] == "Test Token"
        assert payload["desc"] == "Platform credits for the issuing application."
        assert payload["image"] == "https://example.org/test-logo.png"
        assert payload["image_ipfs"] == "ipfs://bafybeiabc123placeholder"
        assert payload["image_sha256"] == "a" * 64
        assert "decimals" not in payload  # 0 is omitted

    def test_fhc_payload_cbor_is_deterministic(self):
        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST",
            name="Test Token",
            image_url="https://example.org/test-logo.png",
        )
        cbor1, hash1 = encode_payload(meta)
        cbor2_bytes, hash2 = encode_payload(meta)
        assert cbor1 == cbor2_bytes, "CBOR encoding is not deterministic across two calls"
        assert hash1 == hash2

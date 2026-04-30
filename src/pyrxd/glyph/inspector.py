from __future__ import annotations

from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

from .payload import GLY_MARKER, decode_payload
from .script import (
    MUTABLE_NFT_SCRIPT_RE,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    is_ft_script,
    is_nft_script,
    parse_mutable_nft_script,
)
from .types import GlyphMetadata, GlyphRef


@dataclass
class GlyphOutput:
    """A detected Glyph in a transaction output."""

    vout: int
    glyph_type: str  # "nft" or "ft"
    ref: GlyphRef
    metadata: GlyphMetadata | None  # None if this is a transfer (no reveal)
    script: bytes


class GlyphInspector:
    """
    Parse raw transaction bytes to find Glyph outputs.
    Pure — no network access.
    """

    def find_glyphs(self, tx_outputs: list[tuple[int, bytes]]) -> list[GlyphOutput]:
        """
        Given list of (satoshis, script_bytes) outputs, return detected Glyphs.
        """
        results = []
        for vout, (_satoshis, script) in enumerate(tx_outputs):
            script_hex = script.hex()
            if is_nft_script(script_hex):
                ref = extract_ref_from_nft_script(script)
                results.append(
                    GlyphOutput(
                        vout=vout,
                        glyph_type="nft",
                        ref=ref,
                        metadata=None,
                        script=script,
                    )
                )
            elif is_ft_script(script_hex):
                ref = extract_ref_from_ft_script(script)
                results.append(
                    GlyphOutput(
                        vout=vout,
                        glyph_type="ft",
                        ref=ref,
                        metadata=None,
                        script=script,
                    )
                )
            elif MUTABLE_NFT_SCRIPT_RE.fullmatch(script_hex):
                parsed = parse_mutable_nft_script(script)
                if parsed is not None:
                    ref, _ = parsed
                    results.append(
                        GlyphOutput(
                            vout=vout,
                            glyph_type="mut",
                            ref=ref,
                            metadata=None,
                            script=script,
                        )
                    )
        return results

    def extract_reveal_metadata(self, scriptsig: bytes) -> GlyphMetadata | None:
        """
        Parse a reveal TX scriptSig to extract CBOR metadata.

        scriptSig format: <sig> <pubkey> <"gly"> <CBOR>
        Returns None if this is not a reveal scriptSig.
        """
        try:
            return self._parse_reveal_scriptsig(scriptsig)
        except (ValidationError, Exception):
            return None

    def _parse_reveal_scriptsig(self, scriptsig: bytes) -> GlyphMetadata | None:
        """Walk the scriptSig push-data stack to find 'gly' marker + CBOR."""
        pos = 0
        items = []
        while pos < len(scriptsig):
            opcode = scriptsig[pos]
            pos += 1
            if 1 <= opcode <= 75:
                items.append(scriptsig[pos : pos + opcode])
                pos += opcode
            elif opcode == 0x4C:  # OP_PUSHDATA1
                length = scriptsig[pos]
                pos += 1
                items.append(scriptsig[pos : pos + length])
                pos += length
            elif opcode == 0x4D:  # OP_PUSHDATA2
                length = int.from_bytes(scriptsig[pos : pos + 2], "little")
                pos += 2
                items.append(scriptsig[pos : pos + length])
                pos += length
            else:
                break  # non-push opcode, stop

        # Look for 'gly' marker item followed by CBOR
        for i, item in enumerate(items):
            if item == GLY_MARKER and i + 1 < len(items):
                return decode_payload(items[i + 1])
        return None

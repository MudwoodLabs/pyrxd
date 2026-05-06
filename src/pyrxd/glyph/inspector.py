from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pyrxd.security.errors import ValidationError

from .payload import GLY_MARKER, decode_payload
from .script import (
    MUTABLE_NFT_SCRIPT_RE,
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    is_ft_script,
    is_nft_script,
    parse_mutable_nft_script,
)
from .types import GlyphMetadata, GlyphRef

if TYPE_CHECKING:
    # Avoid runtime import cycle: dmint.py imports from .script, which is
    # imported here. TYPE_CHECKING keeps the annotation usable for type tools
    # without forcing a circular load at import time.
    from pyrxd.security.types import Hex20

    from .dmint import DmintState


@dataclass
class GlyphOutput:
    """A detected Glyph in a transaction output.

    Fields added after the original five are optional with defaults so callers
    that destructure the original shape continue to work unchanged. ``ref`` is
    the glyph's identifying outpoint — for ``dmint`` outputs that's the
    ``contract_ref`` (the contract UTXO's own outpoint); the token the contract
    mints lives in ``dmint_state.token_ref``.
    """

    vout: int
    glyph_type: str  # "nft", "ft", "mut", "dmint"
    ref: GlyphRef
    metadata: GlyphMetadata | None  # None if this is a transfer (no reveal)
    script: bytes
    owner_pkh: Hex20 | None = None  # set for nft/ft/mut (None for dmint)
    dmint_state: DmintState | None = field(default=None)  # set for dmint outputs


class GlyphInspector:
    """
    Parse raw transaction bytes to find Glyph outputs.
    Pure — no network access.
    """

    def find_glyphs(self, tx_outputs: list[tuple[int, bytes]]) -> list[GlyphOutput]:
        """
        Given list of (satoshis, script_bytes) outputs, return detected Glyphs.

        Detects NFT singletons, FT locks, mutable NFTs, and dMint contract
        outputs. Plain P2PKH and unrecognised scripts are silently skipped.
        Commit-output classification lives outside ``find_glyphs`` because a
        commit has no meaningful ``ref`` until its reveal lands.
        """
        # Local import: dmint.py imports from .script which imports from
        # .types — pulling DmintState in at module load completes the cycle.
        from .dmint import DmintState

        results = []
        for vout, (_satoshis, script) in enumerate(tx_outputs):
            script_hex = script.hex()
            if is_nft_script(script_hex):
                results.append(
                    GlyphOutput(
                        vout=vout,
                        glyph_type="nft",
                        ref=extract_ref_from_nft_script(script),
                        metadata=None,
                        script=script,
                        owner_pkh=extract_owner_pkh_from_nft_script(script),
                    )
                )
            elif is_ft_script(script_hex):
                results.append(
                    GlyphOutput(
                        vout=vout,
                        glyph_type="ft",
                        ref=extract_ref_from_ft_script(script),
                        metadata=None,
                        script=script,
                        owner_pkh=extract_owner_pkh_from_ft_script(script),
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
            else:
                # dMint contract scripts are variable-length and don't have a
                # fingerprint regex — DmintState.from_script is the parser. Try
                # it last so the cheap regex/predicate branches above short-
                # circuit on the common cases. Non-dmint scripts raise
                # ValidationError (length, opcode, or ref-decode mismatch);
                # any other exception is a real bug worth surfacing.
                try:
                    state = DmintState.from_script(script)
                except ValidationError:
                    continue
                results.append(
                    GlyphOutput(
                        vout=vout,
                        glyph_type="dmint",
                        ref=state.contract_ref,
                        metadata=None,
                        script=script,
                        dmint_state=state,
                    )
                )
        return results

    def extract_reveal_metadata(self, scriptsig: bytes) -> GlyphMetadata | None:
        """Parse a reveal TX scriptSig to extract CBOR metadata.

        scriptSig format: ``<sig> <pubkey> <"gly"> <CBOR>``.
        Returns ``None`` if this is not a reveal scriptSig (or if the CBOR
        is malformed / unrecognised).

        Catches ``Exception`` broadly because *every* call site here crosses
        a trust boundary: scriptSigs from network-fetched txs are attacker-
        controlled, and the CBOR decoder + push-data walker may raise
        anything from ``ValidationError`` to ``cbor2.CBORDecodeError`` to
        ``IndexError`` on truncated input. Returning ``None`` is the
        contract callers expect.
        """
        try:
            return self._parse_reveal_scriptsig(scriptsig)
        except Exception:
            return None

    def find_reveal_metadata(self, scriptsigs: list[bytes]) -> tuple[int, GlyphMetadata] | None:
        """Walk every input scriptSig and return the first reveal metadata found.

        Returns ``(input_index, metadata)`` for the first input whose scriptSig
        embeds a ``gly`` marker followed by parseable CBOR; ``None`` if no
        input does. Distinct from :meth:`extract_reveal_metadata` (which checks
        a single scriptSig) — diagnostic callers want to know *which* input
        carried the metadata, and that the inspector looked beyond input 0.
        """
        for idx, scriptsig in enumerate(scriptsigs):
            metadata = self.extract_reveal_metadata(scriptsig)
            if metadata is not None:
                return idx, metadata
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

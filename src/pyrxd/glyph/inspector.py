from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pyrxd.security.errors import ValidationError

from .payload import GLY_MARKER, decode_payload, decode_update_payload
from .script import (
    MUTABLE_NFT_SCRIPT_RE,
    extract_owner_pkh_from_ft_script,
    extract_owner_pkh_from_nft_script,
    extract_ref_from_ft_script,
    extract_ref_from_nft_script,
    is_ft_script,
    is_legacy_container_script,
    is_nft_script,
    parse_legacy_container_script,
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
    glyph_type: str  # "nft", "ft", "mut", "dmint", "container-legacy"
    ref: GlyphRef
    metadata: GlyphMetadata | None  # None if this is a transfer (no reveal)
    script: bytes
    owner_pkh: Hex20 | None = None  # set for nft/ft/mut/container-legacy (None for dmint)
    dmint_state: DmintState | None = field(default=None)  # set for dmint outputs
    # Only ``container-legacy`` outputs set these. ``spendable=False`` means the
    # output is dead — no scriptSig can satisfy it (see
    # :func:`pyrxd.glyph.script.is_legacy_container_script`). Every other
    # ``glyph_type`` leaves it ``True``.
    spendable: bool = True
    child_ref: GlyphRef | None = None


@dataclass(frozen=True)
class GlyphEnvelope:
    """What a scriptSig's ``gly`` marker turned out to be carrying.

    Three states, and the third is the reason this type exists:

    * ``payload``  — a full token payload (has ``p``); ``metadata`` is set.
    * ``update``   — a partial update, mutated fields only; ``fields`` is set.
    * ``unreadable`` — the marker is present and neither reader accepted what followed;
      ``reason`` says what both refusals were.

    ``unreadable`` is NOT an error condition to swallow. It is the honest answer to "is
    anything being published here", and it is the one a caller must not confuse with "no". A
    reader that reports ``None`` for an envelope it cannot parse tells the user a name was
    never updated when the truth is that the update could not be read — the reassuring answer,
    and the wrong one.
    """

    kind: str  # "payload" | "update" | "unreadable"
    metadata: GlyphMetadata | None = None
    fields: dict | None = None
    reason: str = ""

    @property
    def is_readable(self) -> bool:
        return self.kind in ("payload", "update")


class GlyphInspector:
    """
    Parse raw transaction bytes to find Glyph outputs.
    Pure — no network access.
    """

    def find_glyphs(self, tx_outputs: list[tuple[int, bytes]]) -> list[GlyphOutput]:
        """
        Given list of (satoshis, script_bytes) outputs, return detected Glyphs.

        Detects NFT singletons, FT locks, mutable NFTs, dMint contract outputs,
        and the dead pre-0.15.0 container-with-child-ref shape. Plain P2PKH and
        unrecognised scripts are silently skipped. Commit-output classification
        lives outside ``find_glyphs`` because a commit has no meaningful ``ref``
        until its reveal lands.

        A **CONTAINER** reports as ``"nft"``: its locking script *is* the NFT
        singleton, so no script-level classifier can distinguish one, here or in
        any other implementation. Container-ness is an envelope property — read
        it from the reveal metadata (``GlyphProtocol.CONTAINER`` in
        :attr:`~pyrxd.glyph.types.GlyphMetadata.protocol`, surfaced by
        :attr:`GlyphMetadata.is_container` and
        :func:`pyrxd.glyph.wave.classify_glyph_metadata`). ``GlyphScanner``
        does this join for you.
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
            elif is_legacy_container_script(script_hex):
                # Reported so a holder of one is told what it is. It is NOT a
                # routable token: `spendable=False`, and GlyphScanner will not
                # hand it back as a GlyphNft.
                parsed_container = parse_legacy_container_script(script)
                if parsed_container is not None:
                    container_ref, child_ref, owner = parsed_container
                    results.append(
                        GlyphOutput(
                            vout=vout,
                            glyph_type="container-legacy",
                            ref=container_ref,
                            metadata=None,
                            script=script,
                            owner_pkh=owner,
                            spendable=False,
                            child_ref=child_ref,
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

    def classify_glyph_scriptsig(self, scriptsig: bytes) -> GlyphEnvelope | None:
        """What kind of ``gly`` envelope, if any, does this scriptSig carry?

        THE POINT OF THIS METHOD IS THE THIRD ANSWER. :meth:`extract_reveal_metadata` returns
        ``None`` both when there is no glyph here and when there is one it could not parse, and
        those are opposite facts: the first means "nothing to report", the second means "something
        is being published that I cannot read". Collapsing them makes the blind case look like the
        empty one, and the blind case is the more confident-sounding of the two.

        That is not hypothetical. Measured on the mainnet chain for `custodian-gate-x7f3.rxd`,
        three of four transactions carry the marker and the reveal parser decoded exactly one — so
        "this WAVE name was never updated" and "I cannot read WAVE updates" produced identical
        output, and the wrong one is the reassuring one.

        :returns: ``None`` when no push equals the ``gly`` marker — genuinely not a glyph
            scriptSig. Otherwise a :class:`GlyphEnvelope` whose ``kind`` is ``"payload"`` (a full
            token payload), ``"update"`` (a partial update — mutated fields only), or
            ``"unreadable"`` (the marker is there and neither reader accepted what followed).
        """
        # The PREFIX view, not the strict one. A MUT-contract unlock ends in real opcodes
        # (`OP_1 OP_1 OP_0 OP_0` on the mainnet WAVE updates), so `_scriptsig_pushes` reports
        # None for it — and treating that None as "no glyph here" is the exact collapse this
        # method exists to prevent. The envelope is in the pushes that were read.
        items, _complete = self._walk_pushes(scriptsig)
        if not items:
            return None

        for i, item in enumerate(items):
            if item != GLY_MARKER:
                continue
            if i + 1 >= len(items):
                return GlyphEnvelope(kind="unreadable", reason="'gly' marker is the last push — no payload follows")
            blob = items[i + 1]
            try:
                return GlyphEnvelope(kind="payload", metadata=decode_payload(blob))
            except Exception as payload_exc:
                try:
                    return GlyphEnvelope(kind="update", fields=decode_update_payload(blob))
                except Exception as update_exc:
                    # BOTH reasons, because either one alone misleads. "missing 'p'" reads as
                    # "this was an update" and "not a map" reads as "this was a payload"; the
                    # honest report is that neither reader accepted it.
                    return GlyphEnvelope(
                        kind="unreadable",
                        reason=f"not a payload ({payload_exc}); not an update ({update_exc})",
                    )
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

    def parse_mint_scriptsig(self, scriptsig: bytes) -> dict | None:
        """Decode a dMint mint-claim scriptSig into its 4 canonical pushes.

        A V1/V2 dMint mint claim spends the contract UTXO with a scriptSig
        of the form::

            V1 (nonce_width=4): <0x04 nonce(4)> <0x20 inputHash(32)> <0x20 outputHash(32)> <OP_0>  → 72 bytes
            V2 (nonce_width=8): <0x08 nonce(8)> <0x20 inputHash(32)> <0x20 outputHash(32)> <OP_0>  → 76 bytes

        Where:

        * ``nonce`` — little-endian PoW nonce found by the miner.
        * ``inputHash`` — ``SHA256d(funding_input_locking_script)``. NOT a
          preimage half; the on-chain covenant recomputes
          ``SHA256(inputHash || outputHash)`` from these literal pushes.
        * ``outputHash`` — ``SHA256d(OP_RETURN_msg_script at vout[2])``.
        * ``OP_0`` — the sentinel push the V1/V2 covenant requires.

        Verified against mainnet V1 mint ``146a4d68…f3c`` and the V1 mint
        ``c9fdcd34…e530``.

        Returns a dict with ``nonce_hex``, ``input_hash``, ``output_hash``,
        ``version_hint`` (``"v1"`` | ``"v2"`` | ``None``), and
        ``scriptsig_length`` — or ``None`` if the scriptSig doesn't match
        the canonical 4-push shape.

        Catches ``Exception`` broadly because every call site crosses a
        trust boundary: scriptSigs from network-fetched txs are attacker-
        controlled. Non-mint inputs (P2PKH funding inputs, plain RXD
        spends, etc.) return ``None``.
        """
        try:
            items = self._scriptsig_pushes(scriptsig)
        except Exception:
            return None
        if items is None or len(items) != 4:
            return None
        nonce, input_hash, output_hash, sentinel = items
        if len(nonce) not in (4, 8):
            return None
        if len(input_hash) != 32 or len(output_hash) != 32:
            return None
        # The sentinel is ``OP_0`` which pushes the empty byte string.
        if sentinel != b"":
            return None
        version_hint = "v1" if len(nonce) == 4 else "v2"
        return {
            "nonce_hex": nonce.hex(),
            "input_hash": input_hash.hex(),
            "output_hash": output_hash.hex(),
            "version_hint": version_hint,
            "scriptsig_length": len(scriptsig),
        }

    @staticmethod
    def _walk_pushes(scriptsig: bytes) -> tuple[list[bytes], bool]:
        """Walk push-data opcodes; return ``(items read, whole script consumed)``.

        THE SECOND ELEMENT IS THE POINT. A mint scriptSig is pure-push, but a MUT-contract
        unlock is not: measured on mainnet, a WAVE update scriptSig is
        ``PUSH "gly" PUSHDATA <cbor> <sig> <pubkey> OP_1 OP_1 OP_0 OP_0`` — the glyph envelope
        comes FIRST and the contract arguments follow as real opcodes. A walker that reports
        only "this script is not pure-push" throws away the envelope it already read, which is
        how pyrxd came to be unable to see any glyph update at all.

        Recognises ``OP_0`` (0x00) as an empty push, the direct push range (0x01-0x4b), and the
        three PUSHDATA opcodes. Stops at the first non-push opcode or truncated push and reports
        ``False``; a script that ends cleanly reports ``True``.
        """
        pos = 0
        items: list[bytes] = []
        n = len(scriptsig)
        while pos < n:
            op = scriptsig[pos]
            pos += 1
            if op == 0x00:  # OP_0 — push empty
                items.append(b"")
                continue
            if 1 <= op <= 75:
                end = pos + op
                if end > n:
                    return items, False
                items.append(scriptsig[pos:end])
                pos = end
                continue
            if op == 0x4C:  # OP_PUSHDATA1
                if pos + 1 > n:
                    return items, False
                length = scriptsig[pos]
                pos += 1
                end = pos + length
                if end > n:
                    return items, False
                items.append(scriptsig[pos:end])
                pos = end
                continue
            if op == 0x4D:  # OP_PUSHDATA2
                if pos + 2 > n:
                    return items, False
                length = int.from_bytes(scriptsig[pos : pos + 2], "little")
                pos += 2
                end = pos + length
                if end > n:
                    return items, False
                items.append(scriptsig[pos:end])
                pos = end
                continue
            if op == 0x4E:  # OP_PUSHDATA4
                if pos + 4 > n:
                    return items, False
                length = int.from_bytes(scriptsig[pos : pos + 4], "little")
                pos += 4
                end = pos + length
                if end > n:
                    return items, False
                items.append(scriptsig[pos:end])
                pos = end
                continue
            return items, False  # a non-push opcode: stop, keep what was read
        return items, True

    @staticmethod
    def _scriptsig_pushes(scriptsig: bytes) -> list[bytes] | None:
        """Pushes, or ``None`` if the script is not pure-push.

        Unchanged contract, now expressed over :meth:`_walk_pushes` so there is one walker
        rather than two that can drift. Callers that only accept pure-push scripts (mint
        scriptSigs) keep the strict answer; :meth:`classify_glyph_scriptsig` wants the prefix.
        """
        items, complete = GlyphInspector._walk_pushes(scriptsig)
        return items if complete else None

    def _parse_reveal_scriptsig(self, scriptsig: bytes) -> GlyphMetadata | None:
        """Walk the scriptSig push-data stack to find 'gly' marker + CBOR.

        Handles all four push-data opcodes including OP_PUSHDATA4 (0x4e):
        V1 dMint deploy reveals on Radiant mainnet carry CBOR bodies > 65535
        bytes (the GLYPH deploy's body is 65,569 bytes including a PNG), which
        forces OP_PUSHDATA4. Without 0x4e support the walker bails out
        before reaching the 'gly' marker that follows it.
        """
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
            elif opcode == 0x4E:  # OP_PUSHDATA4
                length = int.from_bytes(scriptsig[pos : pos + 4], "little")
                pos += 4
                items.append(scriptsig[pos : pos + length])
                pos += length
            else:
                break  # non-push opcode, stop

        # Look for 'gly' marker item followed by CBOR
        for i, item in enumerate(items):
            if item == GLY_MARKER and i + 1 < len(items):
                return decode_payload(items[i + 1])
        return None

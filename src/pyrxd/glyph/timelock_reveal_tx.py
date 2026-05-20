"""Glyph TIMELOCK reveal-transaction primitives (Photonic-compatible).

Mirrors Photonic Wallet's ``packages/lib/src/reveal.ts`` for the
*proof* / *script* layer. The wrapping transaction (funding inputs +
change output, signing) is left to pyrxd's existing transaction
machinery — this module produces the OP_RETURN script bytes that go
*inside* a reveal tx, plus parser + validator counterparts.

On-chain OP_RETURN format::

    OP_RETURN <gly> <0x02> <0x09> <CBOR(RevealProof)>

where:

- ``<gly>`` = 3-byte ASCII magic (``676c79``)
- ``0x02`` = REVEAL_VERSION (matches Photonic's burn-proof pattern)
- ``0x09`` = REVEAL_MARKER (also the GLYPH_TIMELOCK protocol id)
- CBOR proof = a 6- or 7-key map (the 7th is the optional ``hint``)

RevealProof shape::

    {
      "v": 2,
      "p": [9],
      "action": "reveal",
      "token_ref": "<txid>:<vout>",
      "cek": "<32-byte CEK as 64-hex lowercase>",
      "cek_hash": "sha256:<32-byte hash as 64-hex lowercase>",
      "hint": "<optional human note>",
    }

CBOR byte-equivalence note: pyrxd uses ``cbor2`` which produces
canonical CBOR (shortest map-length encoding). Photonic's ``cbor-x``
library uses a fixed 2-byte map-length header. Both are spec-valid CBOR;
both decode to the same dict. **pyrxd's emit may produce different bytes
than Photonic's emit for the same logical reveal proof, but pyrxd's
parser accepts both.** For an indexer or wallet doing semantic
validation of the reveal proof, this distinction is invisible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import cbor2

from ..constants import OpCode
from ..utils import encode_pushdata
from .timelock import compute_cek_hash, parse_cek_hash

#: Magic bytes prefix on every Glyph OP_RETURN output. "gly" in ASCII.
GLYPH_MAGIC_BYTES = bytes.fromhex("676c79")

#: Version byte. Matches Photonic's REVEAL_VERSION = 0x02.
REVEAL_VERSION = 0x02

#: Marker byte. Equals GLYPH_TIMELOCK protocol id (9).
REVEAL_MARKER = 0x09

#: Required action string in the CBOR proof.
REVEAL_ACTION = "reveal"

#: Regex enforcing "txid:vout" form for token_ref.
_TOKEN_REF_RE = re.compile(r"^[0-9a-fA-F]{64}:[0-9]+$")


@dataclass(frozen=True)
class RevealProof:
    """Parsed reveal proof, mirroring Photonic's ``RevealProof`` type."""

    v: int  # always REVEAL_VERSION = 2
    p: list[int]  # always [REVEAL_MARKER] = [9]
    action: str  # always "reveal"
    token_ref: str  # "txid:vout"
    cek: str  # 64-hex
    cek_hash: str  # "sha256:<hex>"
    hint: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "v": self.v,
            "p": list(self.p),
            "action": self.action,
            "token_ref": self.token_ref,
            "cek": self.cek,
            "cek_hash": self.cek_hash,
        }
        if self.hint:
            d["hint"] = self.hint
        return d

    @classmethod
    def from_dict(cls, d: dict) -> RevealProof:
        return cls(
            v=int(d["v"]),
            p=[int(x) for x in d["p"]],
            action=str(d["action"]),
            token_ref=str(d["token_ref"]),
            cek=str(d["cek"]),
            cek_hash=str(d["cek_hash"]),
            hint=str(d.get("hint", "")),
        )


# ──────────────────────────────────────────────────── proof construction ──


def create_reveal_proof(
    token_ref: str,
    cek: bytes,
    *,
    hint: str = "",
    cek_hash_override: str | None = None,
) -> tuple[bytes, RevealProof]:
    """Build the OP_RETURN script bytes + the structured RevealProof.

    Matches Photonic's ``createRevealProof`` signature/behavior:

    - ``token_ref`` must be ``"<64-hex txid>:<vout>"`` form
    - ``cek`` must be exactly 32 bytes
    - ``cek_hash_override``, if provided, must equal ``sha256(cek)`` —
      otherwise raises. Useful when the caller wants to surface a
      pre-known commitment string in error messages.

    Returns ``(script_bytes, proof)`` where:
    - ``script_bytes`` is the full OP_RETURN script ready to put as a
      0-value output in the reveal tx
    - ``proof`` is the structured :class:`RevealProof` for introspection

    See module docstring for the CBOR byte-equivalence caveat: pyrxd's
    encoder produces canonical CBOR which differs in byte layout from
    Photonic's cbor-x encoder. Both are spec-valid; both round-trip via
    :func:`parse_reveal_proof_script`.
    """
    if len(cek) != 32:
        raise ValueError(f"CEK must be 32 bytes, got {len(cek)}")
    if not _TOKEN_REF_RE.fullmatch(token_ref):
        raise ValueError(f"token_ref must be 'txid:vout' (64 hex + ':' + decimal), got {token_ref!r}")

    cek_hex = cek.hex()
    computed_hash_hex = compute_cek_hash(cek).hex()
    if cek_hash_override:
        normalized = cek_hash_override.replace("sha256:", "").replace("SHA256:", "").lower()
        if normalized != computed_hash_hex:
            raise ValueError(
                f"CEK does not match provided cek_hash_override (expected {normalized!r}, got {computed_hash_hex!r})"
            )
        cek_hash_str = cek_hash_override if cek_hash_override.lower().startswith("sha256:") else f"sha256:{normalized}"
    else:
        cek_hash_str = f"sha256:{computed_hash_hex}"

    proof = RevealProof(
        v=REVEAL_VERSION,
        p=[REVEAL_MARKER],
        action=REVEAL_ACTION,
        token_ref=token_ref,
        cek=cek_hex,
        cek_hash=cek_hash_str,
        hint=hint,
    )

    encoded_proof = cbor2.dumps(proof.to_dict())

    script = (
        OpCode.OP_RETURN
        + encode_pushdata(GLYPH_MAGIC_BYTES, minimal_push=False)
        + encode_pushdata(bytes([REVEAL_VERSION]), minimal_push=False)
        + encode_pushdata(bytes([REVEAL_MARKER]), minimal_push=False)
        + encode_pushdata(encoded_proof, minimal_push=False)
    )
    return script, proof


# ──────────────────────────────────────────────────── proof parsing ──


def _walk_pushdata(script: bytes) -> list[bytes]:
    """Yield each pushed item from a pure-push script.

    Returns ``[]`` if the script contains any non-push opcode in the middle
    of where pushes should be. Skips a leading OP_RETURN (0x6a) if present.
    """
    pos = 0
    items: list[bytes] = []
    n = len(script)

    # Skip leading OP_RETURN if present.
    if pos < n and script[pos] == 0x6A:
        pos += 1

    while pos < n:
        op = script[pos]
        pos += 1

        if op == 0x00:
            items.append(b"")
            continue
        if 1 <= op <= 75:
            end = pos + op
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        if op == 0x4C:  # PUSHDATA1
            if pos + 1 > n:
                return []
            length = script[pos]
            pos += 1
            end = pos + length
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        if op == 0x4D:  # PUSHDATA2
            if pos + 2 > n:
                return []
            length = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            end = pos + length
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        if op == 0x4E:  # PUSHDATA4
            if pos + 4 > n:
                return []
            length = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            end = pos + length
            if end > n:
                return []
            items.append(script[pos:end])
            pos = end
            continue
        # Any other opcode in a pure-push context → not a reveal-proof script.
        return []
    return items


def parse_reveal_proof_script(script: bytes) -> RevealProof | None:
    """Parse a reveal-proof OP_RETURN script. Returns ``None`` if the
    script is not a well-formed Glyph TIMELOCK reveal proof.

    Decodes the bridge fixture's ``op_return_script_hex`` correctly
    (verified via the test ``test_parse_photonic_reveal_script``).
    """
    if not script or script[0] != 0x6A:
        return None

    items = _walk_pushdata(script)
    # Expect 4 items: magic + version + marker + CBOR
    if len(items) != 4:
        return None
    magic, ver, marker, cbor_bytes = items
    if magic != GLYPH_MAGIC_BYTES:
        return None
    if len(ver) != 1 or ver[0] != REVEAL_VERSION:
        return None
    if len(marker) != 1 or marker[0] != REVEAL_MARKER:
        return None

    try:
        decoded = cbor2.loads(cbor_bytes)
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None

    # Required fields with type checks.
    try:
        if decoded.get("action") != REVEAL_ACTION:
            return None
        if not isinstance(decoded.get("token_ref"), str):
            return None
        if not isinstance(decoded.get("cek"), str):
            return None
        if not isinstance(decoded.get("cek_hash"), str):
            return None
        return RevealProof.from_dict(decoded)
    except Exception:
        return None


# ──────────────────────────────────────────────────── validation ──


@dataclass(frozen=True)
class RevealValidation:
    """Result of :func:`validate_reveal_proof`.

    - ``valid``: True iff every check passed
    - ``error``: short human-readable failure reason if ``valid`` is False
    - ``proof``: the parsed proof if it was at least well-formed (so the
      caller can introspect malformed-but-decodable proofs)
    """

    valid: bool
    error: str = ""
    proof: RevealProof | None = None


def validate_reveal_proof(
    proof: RevealProof,
    *,
    expected_token_ref: str,
    expected_cek_hash: str | None = None,
) -> RevealValidation:
    """Validate a parsed reveal proof's correctness.

    Checks performed:
      1. ``action == "reveal"`` (re-checked even though the parser already did)
      2. ``token_ref == expected_token_ref``
      3. ``sha256(cek) == cek_hash`` (self-consistency — proves the CEK
         the proof publishes actually hashes to the commitment in the
         proof itself)
      4. If ``expected_cek_hash`` is provided, ``cek_hash`` matches it
         (this is the on-chain commitment from the original mint)

    Returns :class:`RevealValidation` with ``valid=True`` on success.
    """
    if proof.action != REVEAL_ACTION:
        return RevealValidation(valid=False, error=f"action must be {REVEAL_ACTION!r}", proof=proof)

    if proof.token_ref != expected_token_ref:
        return RevealValidation(
            valid=False,
            error=f"token_ref mismatch: expected {expected_token_ref!r}, got {proof.token_ref!r}",
            proof=proof,
        )

    # Self-consistency: sha256(cek) == cek_hash
    try:
        cek_bytes = bytes.fromhex(proof.cek)
    except ValueError:
        return RevealValidation(valid=False, error="cek is not valid hex", proof=proof)
    if len(cek_bytes) != 32:
        return RevealValidation(
            valid=False,
            error=f"cek must decode to 32 bytes, got {len(cek_bytes)}",
            proof=proof,
        )

    actual_hash_hex = compute_cek_hash(cek_bytes).hex()
    try:
        claimed_hash_bytes = parse_cek_hash(proof.cek_hash)
    except ValueError as exc:
        return RevealValidation(
            valid=False,
            error=f"cek_hash malformed: {exc}",
            proof=proof,
        )
    if actual_hash_hex != claimed_hash_bytes.hex():
        return RevealValidation(
            valid=False,
            error=f"cek_hash self-consistency failed: sha256(cek)={actual_hash_hex} "
            f"but proof.cek_hash claims {claimed_hash_bytes.hex()}",
            proof=proof,
        )

    # Cross-check against the on-chain commitment.
    if expected_cek_hash is not None:
        try:
            expected_bytes = parse_cek_hash(expected_cek_hash)
        except ValueError as exc:
            return RevealValidation(
                valid=False,
                error=f"expected_cek_hash malformed: {exc}",
                proof=proof,
            )
        if actual_hash_hex != expected_bytes.hex():
            return RevealValidation(
                valid=False,
                error=f"cek does not match on-chain commitment: expected {expected_bytes.hex()}, got {actual_hash_hex}",
                proof=proof,
            )

    return RevealValidation(valid=True, proof=proof)


__all__ = [
    "GLYPH_MAGIC_BYTES",
    "REVEAL_ACTION",
    "REVEAL_MARKER",
    "REVEAL_VERSION",
    "RevealProof",
    "RevealValidation",
    "create_reveal_proof",
    "parse_reveal_proof_script",
    "validate_reveal_proof",
]

from __future__ import annotations

import logging
from typing import Literal

import cbor2

from pyrxd.security.errors import ValidationError

from .dmint import DmintCborPayload
from .script import hash_payload
from .types import GlyphCreator, GlyphMedia, GlyphMetadata, GlyphPolicy, GlyphRights, GlyphRoyalty

_log = logging.getLogger(__name__)

GLY_MARKER = b"gly"


def encode_payload(metadata: GlyphMetadata) -> tuple[bytes, bytes]:
    """
    Encode GlyphMetadata to CBOR (RFC 8949 canonical / deterministic form).

    Returns (cbor_bytes, payload_hash_32bytes).
    The 'gly' marker is NOT included in cbor_bytes but IS prepended in scriptSig.

    ``canonical=True`` makes the encoding deterministic across Python versions
    and across source-code refactors that change the ordering of optional
    fields in ``to_cbor_dict``. Map keys are sorted in length-then-lex order
    per RFC 8949 §4.2.1; integer fields use the smallest possible
    representation; floats use shortest unambiguous form. Two encoders
    that both follow the spec produce byte-identical output for the same
    logical payload — required for any future indexer that re-encodes
    metadata to verify against the on-chain commit hash.
    """
    cbor_bytes = cbor2.dumps(metadata.to_cbor_dict(), canonical=True)
    return cbor_bytes, hash_payload(cbor_bytes)


def _cbor_str(d: dict, key: str, max_len: int) -> str:
    """Extract a string field from a CBOR dict, enforcing type and length."""
    v = d.get(key, "")
    if v == "":
        return ""
    if not isinstance(v, str):
        raise ValidationError(f"CBOR field {key!r} must be a text string, got {type(v).__name__!r}")
    if len(v) > max_len:
        raise ValidationError(f"CBOR field {key!r} too long: {len(v)} > {max_len}")
    return v


_MAX_CBOR_PAYLOAD_BYTES = 262_144  # 256 KB hard cap — protects against DoS on decode
# Why 256 KB and not 64 KB: real V1 dMint deploys carry embedded media in the
# CBOR `main` field. The Radiant Glyph Protocol deploy
# (a443d9df…878b commit / b965b32d…9dd6 reveal) has a 65,569-byte CBOR body
# including a logo PNG — just above the prior 64 KB cap. 256 KB is still
# orders of magnitude smaller than _MAX_RAW_TX_BYTES (4 MB) and leaves headroom
# for higher-resolution embedded media without re-litigating the cap each time.
_MAX_ATTRS_COUNT = 64  # unreasonable beyond this; prevents memory bombs

# Per-IANA, real MIME types are short — even very obscure registered
# values top out around 75 chars (e.g. ``application/vnd.openxmlformats-
# officedocument.wordprocessingml.document``). 256 is generous and
# leaves room for parameters (``; charset=…``) without ever being a
# meaningful expansion vector. A higher cap was attacker-surface for
# downstream display strings constructed from this field — see
# https://github.com/MudwoodLabs/pyrxd/issues/52.
_MAX_MIME_TYPE_CHARS = 256


def _decode_attrs(raw: object) -> dict[str, str]:
    """Decode the 'attrs' CBOR field, enforcing count and type constraints."""
    if not isinstance(raw, dict):
        return {}
    if len(raw) > _MAX_ATTRS_COUNT:
        raise ValidationError(f"'attrs' map too large: {len(raw)} entries > {_MAX_ATTRS_COUNT}")
    return {str(k): str(v) for k, v in raw.items()}


def _decode_decimals(raw: object) -> int:
    """Decode the 'decimals' CBOR field, rejecting floats and non-integers."""
    if isinstance(raw, bool):
        raise ValidationError("'decimals' must be an integer, not bool")
    if isinstance(raw, float):
        raise ValidationError(
            f"'decimals' must be an integer, got float {raw!r}. CBOR floats truncate silently — use an integer."
        )
    if not isinstance(raw, int):
        raise ValidationError(f"'decimals' must be an integer, got {type(raw).__name__!r}")
    return raw


def decode_payload(cbor_bytes: bytes) -> GlyphMetadata:
    """Decode CBOR bytes (without 'gly' marker) to GlyphMetadata."""
    if len(cbor_bytes) > _MAX_CBOR_PAYLOAD_BYTES:
        raise ValidationError(f"CBOR payload too large: {len(cbor_bytes)} > {_MAX_CBOR_PAYLOAD_BYTES} bytes")
    try:
        d = cbor2.loads(cbor_bytes)
    except Exception as e:
        raise ValidationError("Invalid CBOR payload") from e

    if not isinstance(d, dict):
        raise ValidationError("CBOR payload must be a map")
    if "p" not in d or not isinstance(d["p"], list):
        raise ValidationError("CBOR payload missing 'p' field")

    main = None
    if "main" in d:
        m = d["main"]
        if isinstance(m, dict) and "t" in m and "b" in m:
            mime_type = str(m["t"])
            if len(mime_type) > _MAX_MIME_TYPE_CHARS:
                raise ValidationError(
                    f"CBOR field 'main.t' (mime_type) too long: {len(mime_type)} > {_MAX_MIME_TYPE_CHARS}"
                )
            # Photonic Wallet wraps embedded binary blobs in CBOR tag 64
            # (uint8-array), so v1 dMint deploys like RBG's GLYPH carry
            # ``main.b = CBORTag(64, <png bytes>)``. Tag-aware unwrap is
            # required — calling ``bytes()`` on a CBORTag raises TypeError.
            blob = m["b"]
            if isinstance(blob, cbor2.CBORTag):
                blob = blob.value
            main = GlyphMedia(mime_type=mime_type, data=bytes(blob))

    version = d.get("v")
    if version is not None:
        try:
            version = int(version)
        except (TypeError, ValueError) as e:
            raise ValidationError("CBOR field 'v' must be an integer") from e

    dmint_params = None
    if "dmint" in d:
        dm = d["dmint"]
        if not isinstance(dm, dict):
            raise ValidationError("CBOR field 'dmint' must be a map")
        dmint_params = DmintCborPayload.from_cbor_dict(dm)

    creator = None
    if "creator" in d:
        c = d["creator"]
        try:
            creator = GlyphCreator.from_cbor_dict(c if isinstance(c, dict) else str(c))
        except (ValidationError, KeyError, ValueError) as e:
            _log.warning("decode_payload: malformed 'creator' field ignored: %s", e)

    royalty = None
    if "royalty" in d and isinstance(d["royalty"], dict):
        try:
            royalty = GlyphRoyalty.from_cbor_dict(d["royalty"])
        except (ValidationError, KeyError, ValueError) as e:
            _log.warning("decode_payload: malformed 'royalty' field ignored: %s", e)

    policy = None
    if "policy" in d and isinstance(d["policy"], dict):
        try:
            policy = GlyphPolicy.from_cbor_dict(d["policy"])
        except (ValidationError, KeyError, ValueError) as e:
            _log.warning("decode_payload: malformed 'policy' field ignored: %s", e)

    rights = None
    if "rights" in d and isinstance(d["rights"], dict):
        try:
            rights = GlyphRights.from_cbor_dict(d["rights"])
        except (ValidationError, KeyError, ValueError) as e:
            _log.warning("decode_payload: malformed 'rights' field ignored: %s", e)

    return GlyphMetadata(
        protocol=d["p"],
        name=_cbor_str(d, "name", 64),
        ticker=_cbor_str(d, "ticker", 16),
        description=_cbor_str(d, "desc", 1000),
        token_type=_cbor_str(d, "type", 64),
        main=main,
        attrs=_decode_attrs(d.get("attrs", {})),
        loc=_cbor_str(d, "loc", 512),
        loc_hash=_cbor_str(d, "loc_hash", 128),
        decimals=_decode_decimals(d.get("decimals", 0)),
        image_url=_cbor_str(d, "image", 512),
        image_ipfs=_cbor_str(d, "image_ipfs", 128),
        image_sha256=_cbor_str(d, "image_sha256", 64),
        v=version,
        dmint_params=dmint_params,
        creator=creator,
        royalty=royalty,
        policy=policy,
        rights=rights,
        created=_cbor_str(d, "created", 64),
        commit_outpoint=_cbor_str(d, "commit_outpoint", 128),
    )


def build_reveal_scriptsig_suffix(cbor_bytes: bytes) -> bytes:
    """
    Return the 'gly' + CBOR portion of the reveal scriptSig.

    The full scriptSig is: <sig> <pubkey> <this suffix>
    Caller is responsible for prepending sig + pubkey push-data.

    Push opcode is selected from the CBOR payload length:
    direct push (≤75 B), OP_PUSHDATA1 (≤255 B), OP_PUSHDATA2 (≤65535 B),
    or OP_PUSHDATA4 (≤``_MAX_CBOR_PAYLOAD_BYTES``). The mainnet GLYPH
    reveal at ``b965b32d…9dd6`` used a 65,569-byte payload via PUSHDATA4
    — capping at PUSHDATA2 would have left pyrxd unable to build the
    same shape the live Radiant indexers parse without complaint.
    Added 2026-05-11 per red-team finding R3.
    """
    # Push 'gly' marker (3 bytes)
    gly_push = b"\x03" + GLY_MARKER
    # Push CBOR bytes
    cbor_len = len(cbor_bytes)
    if cbor_len <= 75:
        cbor_push = bytes([cbor_len]) + cbor_bytes
    elif cbor_len <= 255:
        cbor_push = b"\x4c" + bytes([cbor_len]) + cbor_bytes  # OP_PUSHDATA1
    elif cbor_len <= 65535:
        cbor_push = b"\x4d" + cbor_len.to_bytes(2, "little") + cbor_bytes  # OP_PUSHDATA2
    elif cbor_len <= _MAX_CBOR_PAYLOAD_BYTES:
        cbor_push = b"\x4e" + cbor_len.to_bytes(4, "little") + cbor_bytes  # OP_PUSHDATA4
    else:
        raise ValidationError(f"CBOR payload too large for script: {cbor_len} > {_MAX_CBOR_PAYLOAD_BYTES}")
    return gly_push + cbor_push


def _push_minimal_int(n: int) -> bytes:
    """Minimal push encoding for non-negative scriptSig index integers."""
    if n == 0:
        return b"\x00"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    # General LE encoding (no sign bit needed — indices are always non-negative)
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    if result[-1] & 0x80:
        result.append(0x00)  # add zero byte to keep positive
    payload = bytes(result)
    length = len(payload)
    if length < 0x4C:
        return bytes([length]) + payload
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + payload
    raise ValidationError("_push_minimal_int: value too large")


def build_mutable_scriptsig(
    operation: Literal["mod", "sl"],
    cbor_bytes: bytes,
    contract_output_index: int,
    ref_hash_index: int,
    ref_index: int,
    token_output_index: int,
) -> bytes:
    """Build the scriptSig for spending a mutable NFT contract input.

    The mutable NFT script expects the scriptSig stack (bottom→top):
        gly_marker | cbor_payload | operation | contract_output_index |
        ref_hash_index | ref_index | token_output_index

    :param operation:             ``"mod"`` (modify — update payload hash) or
                                  ``"sl"`` (seal — burn the mutable contract).
    :param cbor_bytes:            CBOR-encoded metadata for the new state.
    :param contract_output_index: Output index of the mutable contract in the tx.
    :param ref_hash_index:        Index into the refdatasummary for this token.
    :param ref_index:             Index of the singleton ref in token output data.
    :param token_output_index:    Output index of the token in the tx.
    """
    if operation not in ("mod", "sl"):
        raise ValidationError(f"operation must be 'mod' or 'sl', got {operation!r}")
    if not cbor_bytes:
        raise ValidationError("cbor_bytes must not be empty")
    for name, val in (
        ("contract_output_index", contract_output_index),
        ("ref_hash_index", ref_hash_index),
        ("ref_index", ref_index),
        ("token_output_index", token_output_index),
    ):
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValidationError(f"{name} must be a non-negative integer, got {val!r}")

    op_bytes = operation.encode()  # b'mod' or b'sl'

    def _push_bytes(b: bytes) -> bytes:
        n = len(b)
        if n <= 75:
            return bytes([n]) + b
        if n <= 255:
            return b"\x4c" + bytes([n]) + b
        if n <= 65535:
            return b"\x4d" + n.to_bytes(2, "little") + b
        raise ValidationError("push_bytes: data too large")

    return (
        b"\x03"
        + GLY_MARKER  # PUSH 3 + "gly"
        + _push_bytes(cbor_bytes)  # PUSH cbor
        + _push_bytes(op_bytes)  # PUSH "mod" or "sl"
        + _push_minimal_int(contract_output_index)
        + _push_minimal_int(ref_hash_index)
        + _push_minimal_int(ref_index)
        + _push_minimal_int(token_output_index)
    )

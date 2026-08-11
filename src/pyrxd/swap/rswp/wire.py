"""RSWP on-chain swap-order wire format — the WRITE side (encoder).

Byte-compatible with the canonical producer (Photonic-Wallet
``buildSwapAdvertisementScript``) and accepted by the strictest consumer (the
Radiant-Core ``-swapindex`` parser, ``src/index/swapindex.cpp``). The READ side
(decoder) lives in :mod:`pyrxd.gravity.swap_order` and is re-exported from
:mod:`pyrxd.swap.rswp`; the encoder here round-trips through it.

Encoder rules that are load-bearing (the node is stricter than our decoder —
see docs/plans/2026-07-05-rswp-orderbook-design.md):

* ``version`` / ``flags`` / ``offeredType`` / ``termsType`` are 1-byte **direct
  data pushes** (``0x01 <b>``), never ``OP_N`` — the node requires
  ``data.size() == 1`` and ``GetOp`` yields empty data for ``OP_N``, so an
  ``OP_2`` version byte makes the node silently drop the order.
* the script starts with a **bare** ``OP_RETURN`` (no ``OP_FALSE`` prefix — the
  node checks ``scriptPubKey[0] == OP_RETURN``), so this module builds raw
  bytes instead of using :class:`pyrxd.script.type.OpReturn`.
* ``tokenID`` / ``wantTokenID`` / ``offeredUTXOHash`` are pushed in internal
  little-endian orientation (display bytes reversed).
* ``offeredUTXOIndex`` is ``OP_0`` for 0, else a minimal-``CScriptNum`` direct
  push — matching Photonic ``encodeScriptNum``. The node decodes it with
  ``CScriptNum(data, false, 4)``, so the encoding must fit 4 bytes.
* ``priceTerms`` is ONE push (the node concatenates middle pushes, but the
  canonical producer emits exactly one).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from ...glyph.types import GlyphRef
from ...gravity.swap_order import DemandedOutput
from ...security.errors import ValidationError
from ...security.types import Txid
from ...utils import encode_pushdata, encode_script_num, unsigned_to_varint

RSWP_MAGIC = b"RSWP"
RSWP_VERSION_V2 = 0x02
RSWP_VERSION_V3 = 0x03
FLAG_HAS_WANT = 0x01
FLAG_HAS_EXPIRY = 0x02

#: RSWP token id of the native-RXD side (display and wire form coincide).
RXD_TOKEN_ID = b"\x00" * 32

# Photonic ContractType enum (packages/app/src/types.ts) — the `offeredType`
# byte. NOTE: NFT=1 and FT=2, *not* the FT=1/NFT=2 ordering one might guess.
CONTRACT_TYPE_RXD = 0
CONTRACT_TYPE_NFT = 1
CONTRACT_TYPE_FT = 2
CONTRACT_TYPE_VAULT = 3

_OP_RETURN = b"\x6a"
_OP_0 = b"\x00"

# The node parses the vout with `CScriptNum(data, false, 4)` (max 4 bytes) and
# `getint32`, so anything above INT32_MAX cannot be advertised.
_MAX_ADVERTISABLE_VOUT = 0x7FFFFFFF


def swap_token_id(ref: GlyphRef | None) -> bytes:
    """The 32-byte RSWP token id in DISPLAY orientation (== node RPC ``tokenid`` hex).

    ``sha256`` of the 36-byte little-endian script-operand ref (exactly
    ``GlyphRef.to_bytes()`` — the bytes ``OP_PUSHINPUTREF`` pushes); all-zero
    for native RXD. Matches Photonic ``assetToSwapTokenId``, which reverses the
    display ref to little-endian before hashing. The on-chain advertisement
    pushes these bytes REVERSED (:func:`encode_rswp_advert` does that).
    """
    if ref is None:
        return RXD_TOKEN_ID
    return hashlib.sha256(ref.to_bytes()).digest()


def encode_price_terms(outputs: Sequence[DemandedOutput]) -> bytes:
    """Serialize demanded outputs as the Photonic ``MultiTxOutV1`` blob.

    ``CompactSize(count) || [value(8 LE) || CompactSize(len(script)) || script]*``.
    Round-trips through :func:`pyrxd.gravity.swap_order.parse_price_terms`.
    """
    if not outputs:
        # NB: phrased with a digit — 8+ all-lowercase words trip the BIP-39
        # redaction heuristic in security.errors and would print "<redacted>".
        raise ValidationError("price terms require at least 1 demanded output")
    blob = unsigned_to_varint(len(outputs))
    for out in outputs:
        if not 0 <= out.value <= 0xFFFFFFFFFFFFFFFF:
            raise ValidationError(f"demanded output value {out.value} does not fit in 8 bytes")
        if not out.script:
            raise ValidationError("a demanded output requires a non-empty script")
        blob += out.value.to_bytes(8, "little") + unsigned_to_varint(len(out.script)) + out.script
    return blob


def _scriptnum_push(n: int) -> bytes:
    """``OP_0`` for 0, else a minimal-CScriptNum DIRECT data push (Photonic ``encodeScriptNum``).

    Shares the number encoding with the rest of the SDK
    (:func:`~pyrxd.utils.encode_script_num`) and deliberately NOT the push
    policy: ``minimal_push=False`` keeps 1..16 as ``01 0n`` instead of folding
    them into ``OP_1``..``OP_16``. Photonic's reader takes these fields
    positionally, so folding would change a frame the network already accepts.
    That split — one number encoder, two push policies — is exactly why the two
    are separate functions rather than one "obvious" merge.
    """
    if n == 0:
        return _OP_0
    return encode_pushdata(encode_script_num(n), minimal_push=False)


def _byte_push(field: str, value: int) -> bytes:
    """A 1-byte direct data push — the only form the node accepts for the small fields."""
    if not 0 <= value <= 0xFF:
        raise ValidationError(f"RSWP {field} must be one byte, got {value}")
    return encode_pushdata(bytes([value]), minimal_push=False)


def encode_rswp_order(
    *,
    offered_type: int,
    token_id: bytes,
    want_token_id: bytes | None,
    offered_txid: str | Txid,
    offered_vout: int,
    price_terms: bytes,
    signature: bytes,
    expiry_height: int | None = None,
    terms_type: int = 0x01,
) -> bytes:
    """Build the RSWP advertisement ``OP_RETURN`` script (v2, or v3 when *expiry_height* is given).

    *token_id* / *want_token_id* are in DISPLAY orientation (as returned by
    :func:`swap_token_id`); *offered_txid* is the display (big-endian) txid.
    Both are pushed byte-reversed, as the chain expects. Pass
    ``want_token_id=None`` when the want side is native RXD (flag bit 0 stays
    clear — Photonic behavior); passing :data:`RXD_TOKEN_ID` is equivalent.
    Round-trips through :func:`pyrxd.gravity.swap_order.decode_rswp_order`.

    *signature* is the maker input's ENTIRE scriptSig
    (``PUSH(DER||0xC3) PUSH(pubkey)``), not a bare signature.

    v3 (*expiry_height* set) additionally pushes a 4-byte LE block height
    between the want-token id and the outpoint and sets flag bit ``0x02``.
    v3 adverts are DROPPED by the current Radiant-Core swapindex — post v2
    unless every consumer you care about parses v3 (design note D1).
    """
    if len(token_id) != 32:
        raise ValidationError(f"token_id must be 32 bytes, got {len(token_id)}")
    if want_token_id is not None and len(want_token_id) != 32:
        raise ValidationError(f"want_token_id must be 32 bytes, got {len(want_token_id)}")
    if want_token_id == RXD_TOKEN_ID:
        want_token_id = None  # RXD want side: omit the field and clear the flag, like Photonic
    if not 0 <= offered_vout <= _MAX_ADVERTISABLE_VOUT:
        raise ValidationError(f"offered_vout {offered_vout} cannot be advertised (node reads a 4-byte CScriptNum)")
    if expiry_height is not None and not 1 <= expiry_height <= 0xFFFFFFFF:
        raise ValidationError(f"expiry_height {expiry_height} must fit an unsigned 4-byte block height")
    if not price_terms:
        raise ValidationError("price_terms must not be empty")
    if not signature:
        raise ValidationError("signature must not be empty")
    txid_bytes = bytes.fromhex(str(Txid(str(offered_txid))))
    version = RSWP_VERSION_V3 if expiry_height is not None else RSWP_VERSION_V2
    flags = (FLAG_HAS_WANT if want_token_id is not None else 0) | (FLAG_HAS_EXPIRY if expiry_height is not None else 0)

    script = _OP_RETURN
    script += encode_pushdata(RSWP_MAGIC, minimal_push=False)
    script += _byte_push("version", version)
    script += _byte_push("flags", flags)
    script += _byte_push("offeredType", offered_type)
    script += _byte_push("termsType", terms_type)
    script += encode_pushdata(token_id[::-1], minimal_push=False)
    if want_token_id is not None:
        script += encode_pushdata(want_token_id[::-1], minimal_push=False)
    if expiry_height is not None:
        script += encode_pushdata(expiry_height.to_bytes(4, "little"), minimal_push=False)
    script += encode_pushdata(txid_bytes[::-1], minimal_push=False)
    script += _scriptnum_push(offered_vout)
    script += encode_pushdata(price_terms, minimal_push=False)
    script += encode_pushdata(signature, minimal_push=False)
    return script

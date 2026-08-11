"""Decoder for the Radiant on-chain swap-order ("RSWP") OP_RETURN wire format — the READ side.

Decodes a **v2 or v3** RSWP order advertised in an ``OP_RETURN`` output into structured fields, including the
Photonic ``MultiTxOutV1`` ``price_terms`` (the outputs the maker demands). This is the **canonical**
decode: it follows the on-chain producer (Photonic-Wallet) and the consensus-node parser
(Radiant-Core ``swapindex.cpp``). It matches current ``Radiant-Core/RXinDexer``, which decodes the same
``MultiTxOutV1``. (RXinDexer *historically* mis-decoded ``price_terms`` as small integers and produced
garbage against real orders; that was fixed upstream 2026-06-01, commit ``24572c7c``.) See
``docs/swap-order-wire-format.md`` §Conflicts. Read-only: this builds and signs nothing.

The frame (pushes after ``OP_RETURN``): ``"RSWP" version flags offeredType termsType tokenID
[wantTokenID] [expiryHeight] offeredUTXOHash offeredUTXOIndex priceTerms… signature``. The tail rule
(node ``swapindex.cpp:642-659``): of the remaining pushes, ``price_terms = concat(tail[:-1])`` and
``signature = tail[-1]`` (require ``len(tail) >= 2``).

**v3** (Photonic ``docs/swap-offer-expiry-cancellation.md`` §4) bumps the version byte to ``0x03`` and,
when flag bit ``0x02`` is set, inserts a 4-byte little-endian absolute ``expiry_height`` between the
want-token id and the outpoint. The v2 field layout is otherwise unchanged. NOTE: the deployed
Radiant-Core swapindex parses v2 only and *drops* v3 adverts — decode support here is part of the
cross-repo v3 parser rollout, not evidence of live-network support.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..constants import OpCode
from ..security.errors import ValidationError
from ..utils import Reader

_RSWP_MAGIC = b"RSWP"
_FLAG_HAS_WANT = 0x01
_FLAG_HAS_EXPIRY = 0x02  # v3 only
_RXD_TOKEN_ID = b"\x00" * 32


@dataclass(frozen=True)
class DemandedOutput:
    """One output the maker demands (a parsed ``MultiTxOutV1`` entry)."""

    value: int  # satoshis/photons (8-byte LE)
    script: bytes  # raw scriptPubKey the maker wants paid


@dataclass(frozen=True)
class RswpOrder:
    """A decoded v2/v3 RSWP swap order. ``price_terms`` is the raw opaque blob; ``demanded_outputs`` is the
    parsed ``MultiTxOutV1`` view (``None`` if the blob isn't valid MultiTxOutV1 — use ``price_terms``)."""

    version: int
    flags: int
    offered_type: int
    terms_type: int
    token_id: bytes  # 32 bytes; all-zero == RXD-native offered side
    want_token_id: bytes | None  # 32 bytes iff flags & FLAG_HAS_WANT
    offered_utxo_hash: bytes  # 32 bytes, internal (little-endian) txid of the offered UTXO
    offered_utxo_index: int  # vout
    price_terms: bytes  # opaque concat of the middle pushes
    demanded_outputs: list[DemandedOutput] | None  # parsed MultiTxOutV1, or None
    signature: bytes  # the full scriptSig: PUSH(DER||0xC3) PUSH(pubkey)
    expiry_height: int | None = None  # v3 only: absolute block height (4-byte LE on the wire)

    def __post_init__(self) -> None:
        # v3 iff expiry (Photonic emits v3 exactly when an expiry is present; a
        # v2 frame has no field to carry one). Keeps hand-built orders honest.
        if self.version == 2 and self.expiry_height is not None:
            raise ValidationError("a v2 RSWP order cannot carry an expiry_height")
        if self.version == 3 and self.expiry_height is None:
            raise ValidationError("a v3 RSWP order requires an expiry_height")

    @property
    def offered_txid(self) -> str:
        """Display (big-endian) txid of the offered UTXO."""
        return self.offered_utxo_hash[::-1].hex()

    @property
    def offered_is_rxd(self) -> bool:
        """True iff the offered side is native RXD (token_id all-zero)."""
        return self.token_id == _RXD_TOKEN_ID


def _items(op_return_script: bytes) -> list:
    """Post-``OP_RETURN`` pushes as a list of ``bytes`` (data push) or ``int`` (OP_0 / OP_1..OP_16).

    Strict, node-matching walk (review MEDIUM): a push whose DECLARED length exceeds the bytes actually
    present is REJECTED — Radiant-Core ``GetOp`` returns false on a truncated push and drops the advert, but
    ``Script``'s chunk parser silently CLAMPS it, so pyrxd would otherwise decode (and show as fillable) a
    frame the canonical book never indexes. Non-minimal / PUSHDATA-form pushes are still accepted (the node
    is lenient there); only truncation is a hard error.
    """
    if not op_return_script or op_return_script[0] != bytes(OpCode.OP_RETURN)[0]:
        raise ValidationError("not an OP_RETURN script")
    out: list = []
    i, n = 1, len(op_return_script)
    while i < n:
        op = op_return_script[i]
        i += 1
        if op == 0x00:  # OP_0
            out.append(0)
        elif 0x51 <= op <= 0x60:  # OP_1..OP_16
            out.append(op - 0x50)
        elif op <= 0x4B or op in (0x4C, 0x4D, 0x4E):
            if op <= 0x4B:
                plen = op
            else:
                width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
                if i + width > n:
                    raise ValidationError("truncated push-length prefix in RSWP frame")
                plen = int.from_bytes(op_return_script[i : i + width], "little")
                i += width
            data = op_return_script[i : i + plen]
            if len(data) != plen:
                raise ValidationError("truncated push in RSWP frame (declared length exceeds available bytes)")
            i += plen
            out.append(bytes(data))
        else:
            raise ValidationError(f"unexpected opcode 0x{op:02x} in RSWP frame")
    return out


def _decode_scriptnum(data: bytes) -> int:
    """Decode a minimal ``CScriptNum`` (little-endian, sign bit in the MSB)."""
    if not data:
        return 0
    n = int.from_bytes(data, "little")
    if data[-1] & 0x80:  # negative
        n &= ~(0x80 << (8 * (len(data) - 1)))
        return -n
    return n


def _clean_var_int(r: Reader) -> int | None:
    """``read_var_int_num`` adapted to this parser's "report, do not raise" contract.

    ``read_var_int_num`` refuses non-canonical and truncated CompactSize (audit F-15),
    which is right for ``Transaction`` deserialization but is not how this reader speaks:
    a malformed length prefix simply means the blob is *not clean MultiTxOutV1*, and that
    verdict is returned as ``None``. ``parse_price_terms_lenient`` is documented never to
    raise, and ``decode_rswp_order`` documents ``ValidationError`` only.
    """
    try:
        return r.read_var_int_num()
    except ValidationError:
        return None


def parse_price_terms(blob: bytes) -> list[DemandedOutput] | None:
    """Parse a ``MultiTxOutV1`` ``price_terms`` blob into demanded outputs, or ``None`` if it is not
    clean MultiTxOutV1. (Photonic's reader has a bare ``value(8 LE) || script(rest)`` fallback — see
    :func:`parse_price_terms_lenient`.)"""
    r = Reader(blob)
    count = _clean_var_int(r)
    if count is None or count <= 0 or count > 10_000:
        return None
    outs: list[DemandedOutput] = []
    for _ in range(count):
        vb = r.read_bytes(8)
        if vb is None or len(vb) != 8:
            return None
        slen = _clean_var_int(r)
        # Bound slen by the blob length: a script can never exceed the remaining blob, and an
        # unbounded slen (a 0xff varint up to 2**64-1) would otherwise reach BytesIO.read and raise
        # OverflowError — leaking out of the public decode_rswp_order, which documents ValidationError
        # only. Reject out-of-range lengths as "not clean MultiTxOutV1" (None), the documented outcome.
        # A zero-length demanded script is not a real demand (the encoder refuses it too) — reject for
        # round-trip fidelity (review LOW).
        if slen is None or slen <= 0 or slen > len(blob):
            return None
        script = r.read_bytes(slen)
        if script is None or len(script) != slen:
            return None
        outs.append(DemandedOutput(value=int.from_bytes(vb, "little"), script=script))
    if not r.eof():  # trailing bytes => not clean MultiTxOutV1
        return None
    return outs


def parse_price_terms_lenient(blob: bytes) -> list[DemandedOutput] | None:
    """MultiTxOutV1, else Photonic's bare ``value(8 LE) || script(rest)`` fallback, else ``None``."""
    strict = parse_price_terms(blob)
    if strict is not None:
        return strict
    if len(blob) >= 8:
        return [DemandedOutput(value=int.from_bytes(blob[:8], "little"), script=blob[8:])]
    return None


def decode_rswp_order(op_return_script: bytes) -> RswpOrder:
    """Decode a v2/v3 RSWP ``OP_RETURN`` script into an :class:`RswpOrder`. Raises ``ValidationError``
    on a malformed / unknown-version / non-RSWP frame, including a version/expiry-flag mismatch
    (``version == 3`` iff flag ``0x02`` — a mis-gated 4-byte push would otherwise be silently folded
    into ``price_terms`` by the greedy tail rule)."""
    items = _items(op_return_script)
    i = 0

    def _data(field: str, length: int | None = None) -> bytes:
        nonlocal i
        if i >= len(items) or not isinstance(items[i], bytes):
            raise ValidationError(f"RSWP frame: expected a data push for {field}")
        v = items[i]
        if length is not None and len(v) != length:
            raise ValidationError(f"RSWP {field}: expected {length} bytes, got {len(v)}")
        i += 1
        return v

    def _small_int(field: str) -> int:
        """A 1-byte value field. The consensus node (swapindex.cpp) requires a 1-byte DIRECT data push
        (``data.size() == 1``) and DROPS an ``OP_N``-encoded value (``GetOp`` yields empty data for ``OP_N``),
        so we mirror that strictness: an ``OP_N`` here decodes to a frame the live index never accepted, and
        treating it as valid would make pyrxd disagree with the canonical book (selective-disclosure lever)."""
        nonlocal i
        if i >= len(items):
            raise ValidationError(f"RSWP frame truncated at {field}")
        v = items[i]
        i += 1
        if isinstance(v, bytes) and len(v) == 1:
            return v[0]
        raise ValidationError(f"RSWP {field}: expected a 1-byte direct data push (the node drops OP_N here)")

    if _data("magic", 4) != _RSWP_MAGIC:
        raise ValidationError("not an RSWP order (missing magic)")
    version = _small_int("version")
    if version not in (2, 3):
        raise ValidationError(f"unsupported RSWP version {version} (this decoder handles v2/v3)")
    flags = _small_int("flags")
    if bool(flags & _FLAG_HAS_EXPIRY) != (version == 3):
        raise ValidationError(f"RSWP version {version} is inconsistent with expiry flag 0x02 (v3 iff expiry)")
    offered_type = _small_int("offeredType")
    terms_type = _small_int("termsType")
    token_id = _data("tokenID", 32)
    want_token_id = _data("wantTokenID", 32) if (flags & _FLAG_HAS_WANT) else None
    expiry_height = int.from_bytes(_data("expiryHeight", 4), "little") if (flags & _FLAG_HAS_EXPIRY) else None
    offered_utxo_hash = _data("offeredUTXOHash", 32)
    # offeredUTXOIndex: OP_0..OP_16 OR a minimal CScriptNum push.
    if i >= len(items):
        raise ValidationError("RSWP frame truncated at offeredUTXOIndex")
    idx_item = items[i]
    i += 1
    if isinstance(idx_item, int):  # OP_0..OP_16 — the node accepts these via DecodeOP_N
        offered_utxo_index = idx_item
    else:
        # The node reads the vout with CScriptNum(data, false, 4), which rejects a push > 4 bytes. Mirror
        # that cap so pyrxd never accepts an offered-index the live index dropped.
        if len(idx_item) > 4:
            raise ValidationError("RSWP offeredUTXOIndex: CScriptNum push exceeds 4 bytes (node drops it)")
        offered_utxo_index = _decode_scriptnum(idx_item)

    tail = items[i:]
    if len(tail) < 2 or not all(isinstance(t, bytes) for t in tail):
        raise ValidationError("RSWP frame: tail must be >= 2 data pushes (priceTerms… + signature)")
    price_terms = b"".join(tail[:-1])
    signature = tail[-1]

    return RswpOrder(
        version=version,
        flags=flags,
        offered_type=offered_type,
        terms_type=terms_type,
        token_id=token_id,
        want_token_id=want_token_id,
        offered_utxo_hash=offered_utxo_hash,
        offered_utxo_index=offered_utxo_index,
        price_terms=price_terms,
        demanded_outputs=parse_price_terms(price_terms),
        signature=signature,
        expiry_height=expiry_height,
    )

"""Decoder for the Radiant on-chain swap-order ("RSWP") OP_RETURN wire format — the READ side.

Decodes a **v2** RSWP order advertised in an ``OP_RETURN`` output into structured fields, including the
Photonic ``MultiTxOutV1`` ``price_terms`` (the outputs the maker demands). This is the **canonical**
decode: it follows the on-chain producer (Photonic-Wallet) and the consensus-node parser
(Radiant-Core ``swapindex.cpp``). It matches current ``Radiant-Core/RXinDexer``, which decodes the same
``MultiTxOutV1``. (RXinDexer *historically* mis-decoded ``price_terms`` as small integers and produced
garbage against real orders; that was fixed upstream 2026-06-01, commit ``24572c7c``.) See
``docs/swap-order-wire-format.md`` §Conflicts. Read-only: this builds and signs nothing.

The frame (pushes after ``OP_RETURN``): ``"RSWP" version flags offeredType termsType tokenID
[wantTokenID] offeredUTXOHash offeredUTXOIndex priceTerms… signature``. The tail rule (node
``swapindex.cpp:642-659``): of the remaining pushes, ``price_terms = concat(tail[:-1])`` and
``signature = tail[-1]`` (require ``len(tail) >= 2``).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..constants import OpCode
from ..script import Script
from ..security.errors import ValidationError
from ..utils import Reader

_RSWP_MAGIC = b"RSWP"
_FLAG_HAS_WANT = 0x01
_RXD_TOKEN_ID = b"\x00" * 32


@dataclass(frozen=True)
class DemandedOutput:
    """One output the maker demands (a parsed ``MultiTxOutV1`` entry)."""

    value: int  # satoshis/photons (8-byte LE)
    script: bytes  # raw scriptPubKey the maker wants paid


@dataclass(frozen=True)
class RswpOrder:
    """A decoded v2 RSWP swap order. ``price_terms`` is the raw opaque blob; ``demanded_outputs`` is the
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

    @property
    def offered_txid(self) -> str:
        """Display (big-endian) txid of the offered UTXO."""
        return self.offered_utxo_hash[::-1].hex()

    @property
    def offered_is_rxd(self) -> bool:
        """True iff the offered side is native RXD (token_id all-zero)."""
        return self.token_id == _RXD_TOKEN_ID


def _items(op_return_script: bytes) -> list:
    """Post-``OP_RETURN`` pushes as a list of ``bytes`` (data push) or ``int`` (OP_0 / OP_1..OP_16)."""
    chunks = Script(op_return_script).chunks
    if not chunks or chunks[0].op != bytes(OpCode.OP_RETURN):
        raise ValidationError("not an OP_RETURN script")
    out: list = []
    for c in chunks[1:]:
        if c.data is not None:
            out.append(c.data)
        elif c.op == b"\x00":  # OP_0
            out.append(0)
        elif b"\x51" <= c.op <= b"\x60":  # OP_1..OP_16
            out.append(c.op[0] - 0x50)
        else:
            raise ValidationError(f"unexpected opcode 0x{c.op.hex()} in RSWP frame")
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


def parse_price_terms(blob: bytes) -> list[DemandedOutput] | None:
    """Parse a ``MultiTxOutV1`` ``price_terms`` blob into demanded outputs, or ``None`` if it is not
    clean MultiTxOutV1. (Photonic's reader has a bare ``value(8 LE) || script(rest)`` fallback — see
    :func:`parse_price_terms_lenient`.)"""
    r = Reader(blob)
    count = r.read_var_int_num()
    if count is None or count <= 0 or count > 10_000:
        return None
    outs: list[DemandedOutput] = []
    for _ in range(count):
        vb = r.read_bytes(8)
        if vb is None or len(vb) != 8:
            return None
        slen = r.read_var_int_num()
        if slen is None or slen < 0:
            return None
        script = r.read_bytes(slen) if slen else b""
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
    """Decode a v2 RSWP ``OP_RETURN`` script into an :class:`RswpOrder`. Raises ``ValidationError`` on a
    malformed / non-v2 / non-RSWP frame."""
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
        """A 1-byte value field, which minimal-push encoding may emit as OP_0/OP_1..OP_16."""
        nonlocal i
        if i >= len(items):
            raise ValidationError(f"RSWP frame truncated at {field}")
        v = items[i]
        i += 1
        if isinstance(v, int):
            return v
        if len(v) == 1:
            return v[0]
        raise ValidationError(f"RSWP {field}: expected a 1-byte value")

    if _data("magic", 4) != _RSWP_MAGIC:
        raise ValidationError("not an RSWP order (missing magic)")
    version = _small_int("version")
    if version != 2:
        raise ValidationError(f"unsupported RSWP version {version} (this decoder handles v2)")
    flags = _small_int("flags")
    offered_type = _small_int("offeredType")
    terms_type = _small_int("termsType")
    token_id = _data("tokenID", 32)
    want_token_id = _data("wantTokenID", 32) if (flags & _FLAG_HAS_WANT) else None
    offered_utxo_hash = _data("offeredUTXOHash", 32)
    # offeredUTXOIndex: OP_0..OP_16 OR a minimal CScriptNum push.
    if i >= len(items):
        raise ValidationError("RSWP frame truncated at offeredUTXOIndex")
    idx_item = items[i]
    i += 1
    offered_utxo_index = idx_item if isinstance(idx_item, int) else _decode_scriptnum(idx_item)

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
    )

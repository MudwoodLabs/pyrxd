"""The one CompactSize (Bitcoin "varint") codec.

Every length prefix in every transaction, block, and witness the SDK parses is a
CompactSize, so this is the first thing a hostile byte string meets. Consensus
asks one question about it — *is this the shortest encoding of this value?* — and
this module holds the one answer.

It exists because the codebase held seven.
--------------------------------------------------------------------------------
As of the commit that added this module the tree contained seven independent
CompactSize readers, and they did not agree:

* ``spv/proof.py`` — rejected non-minimal (audit 2026-05-29 F-15)
* ``spv/witness.py`` — rejected non-minimal (audit 2026-05-29 F-15)
* ``utils.py`` (``Reader.read_var_int_num``) — rejected non-minimal (PR #413)
* ``btc_wallet/taproot.py`` ``_iter_witness_stack`` — **accepted** non-minimal
* ``btc_wallet/taproot.py`` ``btc_txid_from_raw`` — **accepted** non-minimal
* ``btc_wallet/taproot.py`` ``btc_spend_fields_from_raw`` — **accepted**
* ``btc_wallet/taproot.py`` ``btc_input_outpoints_from_raw`` — **accepted**

Four of the seven lived in one module, and the audit that fixed the other three
never saw them, because nothing in the tree could enumerate them. That is the
whole failure mode: a consensus rule implemented more than once drifts, and the
copies nobody remembered are the ones still holding the old answer.

The writing side was in the same state — five hand-written encoders across
``utils.py``, ``gravity/transactions.py``, ``btc_wallet/payment.py``,
``btc_wallet/taproot.py`` and ``spv/witness.py``. They happened to agree, which
is luck rather than a property, and a writer that disagrees with the reader is
an SDK emitting transactions it would itself refuse to parse.

The rules, and why each is a rejection rather than a shrug
---------------------------------------------------------
**Non-minimal (overlong) encodings are refused.** ``fd 01 00`` and ``01`` both
decode to 1, but only ``01`` is valid: Bitcoin and Radiant both reject the
overlong form at deserialization, so a transaction containing one can never
exist on chain. Accepting it has two concrete consequences, both observed:

* the SDK reports as valid a transaction no node will accept; and
* ``Transaction.from_hex(blob).serialize()`` re-emits the *canonical* encoding,
  so the bytes do not round-trip — an 87-byte blob whose input count was written
  ``fd 01 00`` comes back 85 bytes long, and ``txid()`` returns the id of a
  transaction those bytes are not. Anything binding a txid to bytes it was
  handed is then comparing against a value the bytes do not hash to.

**Truncated operands are refused.** ``int.from_bytes`` zero-extends a short
read, so ``fd 01`` used to decode silently as 1 rather than raising. A parser
that invents zero bytes off the end of an attacker-supplied buffer is a parser
that can be steered.

Callers wanting a *tolerant* reader (``_iter_witness_stack`` deliberately never
raises while scraping a witness) should catch
:class:`~pyrxd.security.errors.ValidationError` around these functions rather
than writing another lenient copy. Likewise ``spv/proof.py`` re-raises as
``SpvVerificationError`` and ``Reader.read_var_int_num`` returns ``None`` at
true end of input. The rule lives here; the error policy belongs at the call
site, and separating them is what stopped seven copies of the rule existing to
support four different error policies.
"""

from __future__ import annotations

from .security.errors import ValidationError

__all__ = [
    "COMPACT_SIZE_MAX",
    "PREFIX_WIDTHS",
    "encode_compact_size",
    "read_compact_size",
]

#: CompactSize prefix byte -> (operand width in bytes, largest value the SHORTER
#: encoding already covers). A decoded value at or below that floor means a
#: shorter encoding existed, so this one is non-canonical.
#:
#: One table, because the three-way ``0xFD``/``0xFE``/``0xFF`` split was
#: previously spelled out in seven readers, five writers, and
#: ``Reader.read_var_int``.
PREFIX_WIDTHS: dict[int, tuple[int, int]] = {
    0xFD: (2, 0xFC),
    0xFE: (4, 0xFFFF),
    0xFF: (8, 0xFFFFFFFF),
}

#: The largest value a CompactSize can carry (the 8-byte form is unsigned 64-bit).
COMPACT_SIZE_MAX: int = 0xFFFFFFFFFFFFFFFF


def read_compact_size(buf: bytes, pos: int = 0) -> tuple[int, int]:
    """Read the CompactSize at ``buf[pos:]``; return ``(value, next_pos)``.

    Raises :class:`~pyrxd.security.errors.ValidationError` on a read past the
    end, a truncated operand, or a non-minimal encoding. It never returns a
    value it had to invent bytes to produce.
    """
    if pos < 0:
        raise ValidationError(f"negative varint offset: {pos}")
    if pos >= len(buf):
        raise ValidationError("varint read past end of buffer")

    first = buf[pos]
    if first < 0xFD:
        return first, pos + 1

    width, floor = PREFIX_WIDTHS[first]
    end = pos + 1 + width
    if end > len(buf):
        raise ValidationError(f"truncated {width}-byte varint")
    value = int.from_bytes(buf[pos + 1 : end], "little")
    if value <= floor:
        raise ValidationError(f"non-canonical varint: 0x{first:02X} prefix encodes {value} (<= {floor})")
    return value, end


def encode_compact_size(n: int) -> bytes:
    """Encode ``n`` as a **canonical** CompactSize — the shortest form that fits.

    The inverse of :func:`read_compact_size`: every output of this function is
    accepted by it, and every value it accepts round-trips back to the same
    bytes. That mutual property is what makes non-minimal input detectable at
    all, and it is asserted directly in ``tests/test_compactsize.py``.
    """
    if not isinstance(n, int) or isinstance(n, bool):
        raise ValidationError(f"varint must be an int, got {type(n).__name__}")
    if n < 0:
        raise ValidationError(f"varint cannot be negative: {n}")
    if n > COMPACT_SIZE_MAX:
        raise ValidationError(f"varint exceeds 64-bit range: {n}")
    if n < 0xFD:
        return bytes([n])
    # Walk the same table the reader uses, narrowest first, and take the first
    # width that can hold `n`. Driving both directions off PREFIX_WIDTHS is what
    # makes "the encoder emits exactly what the decoder calls canonical" a
    # structural property rather than a coincidence two literals happen to share:
    # this form's ceiling is 2**(8*width) - 1, and the reader's floor for the
    # NEXT prefix is that same number.
    for prefix, (width, _floor) in PREFIX_WIDTHS.items():
        if n >= 1 << (8 * width):
            continue  # does not fit; a wider form is needed
        return bytes([prefix]) + n.to_bytes(width, "little")
    raise ValidationError(f"varint exceeds 64-bit range: {n}")  # pragma: no cover - guarded above

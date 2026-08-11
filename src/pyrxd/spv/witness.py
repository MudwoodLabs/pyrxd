"""Witness stripping for segwit / taproot transactions.

The canonical Bitcoin txid is ``hash256`` of the non-witness serialization. For
a segwit tx, that means we must drop the marker byte (0x00), flag byte (0x01),
and all witness stacks before hashing. This matches ``bitcoinjs-lib``'s
``Transaction.fromHex(x).toHex()`` with no witness attached.
"""

from __future__ import annotations

from pyrxd.compactsize import encode_compact_size, read_compact_size
from pyrxd.security.errors import ValidationError

__all__ = ["strip_witness"]

# Thin aliases onto the one CompactSize codec (:mod:`pyrxd.compactsize`), kept as
# module-private names because the rest of this file and its tests read better
# with them. Audit 2026-05-29 F-15 — rejecting non-canonical CompactSize — now
# lives in exactly one place. This module used to state it a second time, and
# four further statements in ``btc_wallet/taproot.py`` had drifted to the
# opposite verdict without anything noticing.
_read_varint = read_compact_size
_encode_varint = encode_compact_size


def strip_witness(raw_tx: bytes) -> bytes:
    """Strip witness data from a segwit / taproot tx.

    Returns the legacy non-witness serialization whose ``hash256`` matches the txid.
    If the tx already has no segwit marker, returns the input unchanged.

    Wire format:
        Legacy:  version(4) + inputs + outputs + locktime(4)
        Segwit:  version(4) + marker(0x00) + flag(0x01) + inputs + outputs +
                 witness[] + locktime(4)

    Raises:
        ValidationError: if the tx is too short or the serialization is malformed.
    """
    if len(raw_tx) < 10:
        raise ValidationError("raw_tx too short")

    # Check for segwit marker. Byte 4 in legacy format is the first byte of
    # the input-count varint; a value of 0x00 means 0 inputs (never valid for
    # a real tx), so it unambiguously signals segwit encoding.
    if raw_tx[4] != 0x00:
        return raw_tx  # Already legacy serialization.

    if raw_tx[5] != 0x01:
        raise ValidationError(f"unexpected segwit flag byte: {raw_tx[5]:#x}")

    # Segwit: rebuild without marker/flag and without witness stacks.
    version = raw_tx[0:4]
    pos = 6  # skip version(4) + marker(1) + flag(1)

    # Read inputs.
    input_count, pos = _read_varint(raw_tx, pos)
    inputs_start = pos
    for _ in range(input_count):
        if pos + 36 > len(raw_tx):
            raise ValidationError("raw_tx truncated in inputs")
        pos += 36  # prevout (32 txid + 4 vout)
        script_len, pos = _read_varint(raw_tx, pos)
        if pos + script_len + 4 > len(raw_tx):
            raise ValidationError("raw_tx truncated in input script/sequence")
        pos += script_len + 4  # script + sequence
    inputs_bytes = raw_tx[inputs_start:pos]

    # Read outputs.
    output_count, pos = _read_varint(raw_tx, pos)
    outputs_start = pos
    for _ in range(output_count):
        if pos + 8 > len(raw_tx):
            raise ValidationError("raw_tx truncated in output value")
        pos += 8
        script_len, pos = _read_varint(raw_tx, pos)
        if pos + script_len > len(raw_tx):
            raise ValidationError("raw_tx truncated in output script")
        pos += script_len
    outputs_bytes = raw_tx[outputs_start:pos]

    # Skip witness data (one stack per input).
    for _ in range(input_count):
        item_count, pos = _read_varint(raw_tx, pos)
        for _ in range(item_count):
            item_len, pos = _read_varint(raw_tx, pos)
            if pos + item_len > len(raw_tx):
                raise ValidationError("raw_tx truncated in witness item")
            pos += item_len

    # Read locktime.
    if pos + 4 > len(raw_tx):
        raise ValidationError("raw_tx truncated: missing locktime")
    locktime = raw_tx[pos : pos + 4]

    return (
        version + _encode_varint(input_count) + inputs_bytes + _encode_varint(output_count) + outputs_bytes + locktime
    )

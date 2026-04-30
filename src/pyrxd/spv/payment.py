"""Bitcoin payment-output verification for SPV proofs.

Supports the four standard output types the covenant's generator dispatches on:
P2PKH, P2WPKH, P2SH, and P2TR.

Audit defenses applied (see docs/audits/02 and docs/audits/03):
    * Finding 02-F-11: enforce full-output byte boundary before any parsing.
    * Finding 02-F-5: full hash match (not just prefix) + value > 0 + threshold.
    * Finding 03-C2: explicitly reject OP_RETURN outputs as payments.
"""

from __future__ import annotations

import struct

from pyrxd.security.errors import SpvVerificationError, ValidationError

__all__ = ["P2PKH", "P2SH", "P2TR", "P2WPKH", "verify_payment"]

# Output type constants.
P2PKH = "p2pkh"
P2WPKH = "p2wpkh"
P2SH = "p2sh"
P2TR = "p2tr"

# Expected script lengths by type (bytes of the scriptPubKey itself).
_OUTPUT_SCRIPT_LENGTHS = {
    P2PKH: 25,  # OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    P2WPKH: 22,  # OP_0 <20>
    P2SH: 23,  # OP_HASH160 <20> OP_EQUAL
    P2TR: 34,  # OP_1 <32>
}

# Script prefix/suffix patterns (everything except the hash bytes).
_SCRIPT_PATTERNS = {
    P2PKH: (b"\x76\xa9\x14", b"\x88\xac"),  # 3 + 20 + 2
    P2WPKH: (b"\x00\x14", b""),  # 2 + 20
    P2SH: (b"\xa9\x14", b"\x87"),  # 2 + 20 + 1
    P2TR: (b"\x51\x20", b""),  # 2 + 32 (Taproot uses 32-byte x-only pubkey)
}


def verify_payment(
    raw_tx: bytes,
    output_offset: int,
    expected_hash: bytes,
    output_type: str,
    min_satoshis: int,
) -> None:
    """Verify a specific output in ``raw_tx`` pays ``expected_hash`` at least ``min_satoshis``.

    Args:
        raw_tx: Full raw transaction bytes (witness-stripped if segwit).
        output_offset: Byte offset within ``raw_tx`` where this output begins.
        expected_hash: 20 bytes for P2PKH / P2WPKH / P2SH; 32 bytes for P2TR.
        output_type: One of the module constants above.
        min_satoshis: Minimum acceptable value (must be > 0 and <= value).

    Raises:
        ValidationError: on bad arguments (unknown type, wrong hash length, etc.).
        SpvVerificationError: on any verification failure.
    """
    if output_type not in _SCRIPT_PATTERNS:
        raise ValidationError(f"unknown output_type: {output_type!r}")

    script_len = _OUTPUT_SCRIPT_LENGTHS[output_type]
    # Output layout: 8-byte LE value + 1-byte script length + script bytes.
    # (All standard outputs have script length < 253, so varint == 1 byte.)
    min_output_size = 8 + 1 + script_len

    # Audit 02-F-11: enforce full-output boundary up front.
    if output_offset < 0:
        raise ValidationError("output_offset must be non-negative")
    if output_offset + min_output_size > len(raw_tx):
        raise SpvVerificationError(
            f"output at offset {output_offset} truncated: "
            f"need {min_output_size} bytes, only {len(raw_tx) - output_offset} available"
        )

    # Parse 8-byte LE value.
    value = struct.unpack_from("<Q", raw_tx, output_offset)[0]

    # Audit 02-F-5: value must be > 0 and >= min_satoshis.
    if value == 0:
        raise SpvVerificationError("output value is 0")
    if value < min_satoshis:
        raise SpvVerificationError(f"output value {value} sats < required {min_satoshis} sats")

    # Parse script length (1-byte varint for standard outputs).
    script_len_byte = raw_tx[output_offset + 8]
    if script_len_byte != script_len:
        raise SpvVerificationError(
            f"script length {script_len_byte} does not match expected {script_len} for {output_type}"
        )

    script_start = output_offset + 9
    script = raw_tx[script_start : script_start + script_len]
    if len(script) != script_len:
        raise SpvVerificationError("script truncated")

    # Audit 03-C2: reject OP_RETURN outputs.
    if script[0] == 0x6A:
        raise SpvVerificationError("OP_RETURN output cannot be used as payment")

    # Hash length validation.
    hash_len = 32 if output_type == P2TR else 20
    if output_type == P2TR and len(expected_hash) != 32:
        raise ValidationError("P2TR expected_hash must be 32 bytes")
    if output_type != P2TR and len(expected_hash) != 20:
        raise ValidationError(f"{output_type} expected_hash must be 20 bytes")

    prefix, suffix = _SCRIPT_PATTERNS[output_type]
    hash_start = len(prefix)

    # Prefix check.
    if script[:hash_start] != prefix:
        raise SpvVerificationError(f"script prefix mismatch for {output_type}")

    # Audit 02-F-5: exact hash comparison (not just prefix-is-familiar).
    actual_hash = script[hash_start : hash_start + hash_len]
    if actual_hash != expected_hash:
        raise SpvVerificationError("payment hash mismatch")

    # Suffix check (where applicable).
    if suffix:
        actual_suffix = script[hash_start + hash_len :]
        if actual_suffix != suffix:
            raise SpvVerificationError(f"script suffix mismatch for {output_type}")

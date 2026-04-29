"""Single-header Bitcoin proof-of-work verifier.

Ported from ``reference/reference_verify.js`` in the gravity-rxd prototype.
The algorithm mirrors the on-chain covenant byte-for-byte so that a header
accepted here is a header accepted by the covenant (minus RadiantScript
compiler bugs). See docs/audits/02-bitcoin-spv-crypto-correctness.md.
"""

from __future__ import annotations

import hashlib
import struct

from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.security.types import Nbits

__all__ = ["hash256", "verify_header_pow"]


def hash256(data: bytes) -> bytes:
    """Double SHA-256, Bitcoin's standard hash function."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def verify_header_pow(header: bytes) -> bytes:
    """Verify a single 80-byte Bitcoin block header's proof of work.

    Returns the header hash (little-endian, 32 bytes) on success.

    Raises:
        ValidationError: if ``header`` is not 80 bytes or ``nBits`` is malformed.
        SpvVerificationError: if the PoW check fails (hash >= target).
    """
    if len(header) != 80:
        raise ValidationError(f"header must be 80 bytes, got {len(header)}")

    # Extract nBits (bytes 72-76, LE encoding: [mantissa[0..2], exponent]).
    nbits_raw = header[72:76]
    # Validate via Nbits type: rejects exponent > 0x1d, negative mantissa, zero
    # mantissa. This is the audit 02-F-3 defense and MUST happen before
    # Python tries to compute zeros(exponent - 3), which would otherwise
    # either raise a generic ValueError or build a bogus target.
    Nbits(nbits_raw)

    exponent = nbits_raw[3]
    mantissa_le = nbits_raw[0:3]

    # Build 32-byte LE target: zeros(exp-3) + mantissa_LE + zeros(32-exp).
    # Nbits has guaranteed exponent <= 0x1d (29) and exponent field is a
    # single byte (0..255). For well-formed mainnet headers exponent >= 3.
    # The Nbits validator rejects exponent > 0x1d; we additionally guard
    # exponent < 3 here (zeroLow negative slice would silently produce
    # wrong-length buffer in JS; Python bytes(-n) is a ValueError).
    if exponent < 3:
        raise ValidationError(f"Nbits exponent {exponent} < 3 is not supported")

    target_le = bytes(exponent - 3) + mantissa_le + bytes(32 - exponent)
    if len(target_le) != 32:
        # Internal invariant — with exponent validated 3..0x1d the arithmetic
        # must yield exactly 32. Raise a hard error rather than assert so the
        # check is not stripped by `python -O`.
        raise RuntimeError("internal invariant violated: target length != 32")

    # Hash the header (little-endian natural form).
    hash_le = hash256(header)

    # Reverse to big-endian for MSB-first comparison.
    hash_be = hash_le[::-1]
    target_be = target_le[::-1]

    # 8x 4-byte MSB-first unsigned chunk comparison: hash_BE < target_BE.
    # This precisely mirrors the RadiantScript covenant's chunked compare.
    for i in range(8):
        h_chunk = struct.unpack_from(">I", hash_be, i * 4)[0]
        t_chunk = struct.unpack_from(">I", target_be, i * 4)[0]
        if h_chunk < t_chunk:
            return hash_le  # hash < target
        if h_chunk > t_chunk:
            raise SpvVerificationError("header PoW invalid: hash >= target")
        # equal chunk: continue to next chunk

    # All eight chunks equal -> hash == target. Bitcoin requires strict <.
    raise SpvVerificationError("header PoW invalid: hash equals target")

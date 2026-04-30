"""N-header Bitcoin chain verifier.

Ported from ``reference/reference_chain.js``. For each header:

1. Verify PoW (hash < target derived from nBits).
2. Verify chain link: ``header[i].prevHash == hash256(header[i-1])``.

Optionally verifies a chain anchor — ``header[0].prevHash`` must equal a
caller-supplied 32-byte LE hash. This implements the audit 05-F-3 /
``CHAIN_ANCHOR.md`` defense against testnet / alternate-chain forgery.
"""

from __future__ import annotations

from pyrxd.security.errors import SpvVerificationError, ValidationError

from .pow import verify_header_pow

__all__ = ["verify_chain"]


def verify_chain(headers: list[bytes], chain_anchor: bytes | None = None) -> list[bytes]:
    """Verify a chain of N consecutive 80-byte Bitcoin block headers.

    Args:
        headers: List of 80-byte headers in chain order.
        chain_anchor: Optional 32-byte LE hash. If provided,
            ``headers[0].prevHash`` must equal this value.

    Returns:
        List of header hashes in little-endian (32 bytes each).

    Raises:
        ValidationError: on malformed input (wrong length, empty list, etc.).
        SpvVerificationError: on PoW failure, broken chain link, or anchor mismatch.
    """
    if not headers:
        raise ValidationError("headers list is empty")
    if chain_anchor is not None and len(chain_anchor) != 32:
        raise ValidationError("chain_anchor must be 32 bytes")

    hashes: list[bytes] = []
    prev_hash: bytes | None = None

    for i, header in enumerate(headers):
        if len(header) != 80:
            raise ValidationError(f"header[{i}] must be 80 bytes, got {len(header)}")

        # Chain link / anchor check.
        prev_hash_field = header[4:36]  # prevHash at bytes 4..36, LE
        if i == 0:
            if chain_anchor is not None and prev_hash_field != chain_anchor:
                raise SpvVerificationError("headers[0].prevHash does not match chain_anchor")
        else:
            if prev_hash_field != prev_hash:
                raise SpvVerificationError(
                    f"chain link broken at header[{i}]: prevHash does not match hash of header[{i - 1}]"
                )

        # PoW check (also returns the header's hash).
        header_hash = verify_header_pow(header)
        hashes.append(header_hash)
        prev_hash = header_hash

    return hashes

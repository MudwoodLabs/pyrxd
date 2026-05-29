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


def verify_chain(
    headers: list[bytes],
    chain_anchor: bytes | None = None,
    expected_nbits: bytes | None = None,
    expected_nbits_next: bytes | None = None,
) -> list[bytes]:
    """Verify a chain of N consecutive 80-byte Bitcoin block headers.

    Args:
        headers: List of 80-byte headers in chain order.
        chain_anchor: Optional 32-byte LE hash. If provided,
            ``headers[0].prevHash`` must equal this value.
        expected_nbits: Optional 4-byte wire nBits. If provided, EVERY header's
            nBits field (bytes 72:76) must equal ``expected_nbits`` (or
            ``expected_nbits_next`` when supplied). This mirrors the on-chain
            covenant's ``nBits ∈ {expectedNBits, expectedNBitsNext}`` pin
            (audit 2026-05-29 F-01/F-03): without it the verifier accepts ANY
            well-formed difficulty, so a cheaply-mined min-difficulty chain off
            a real anchor would pass. PoW-vs-own-nBits alone is NOT a network-
            difficulty check. ``None`` disables enforcement — UNSAFE for any
            sole-authority (covenant-less) use; only the on-chain covenant's
            pin protects the deprecated swap.
        expected_nbits_next: Optional 2nd accepted nBits value (the retarget
            window). Only consulted when ``expected_nbits`` is provided.

    Returns:
        List of header hashes in little-endian (32 bytes each).

    Raises:
        ValidationError: on malformed input (wrong length, empty list, etc.).
        SpvVerificationError: on PoW failure, broken chain link, anchor
            mismatch, or nBits-pin mismatch.
    """
    if not headers:
        raise ValidationError("headers list is empty")
    if chain_anchor is not None and len(chain_anchor) != 32:
        raise ValidationError("chain_anchor must be 32 bytes")
    if expected_nbits is not None and len(expected_nbits) != 4:
        raise ValidationError("expected_nbits must be 4 bytes (wire nBits)")
    if expected_nbits_next is not None and len(expected_nbits_next) != 4:
        raise ValidationError("expected_nbits_next must be 4 bytes (wire nBits)")
    # When only expected_nbits is given, the second accepted value defaults to it
    # (mirrors build_gravity_offer, where expected_nbits_next defaults to expected_nbits).
    allowed_nbits: frozenset[bytes] | None = None
    if expected_nbits is not None:
        allowed_nbits = frozenset(
            {bytes(expected_nbits), bytes(expected_nbits_next if expected_nbits_next is not None else expected_nbits)}
        )

    hashes: list[bytes] = []
    prev_hash: bytes | None = None

    for i, header in enumerate(headers):
        if len(header) != 80:
            raise ValidationError(f"header[{i}] must be 80 bytes, got {len(header)}")

        # Audit 2026-05-29 F-01/F-03: enforce the committed nBits pin on every
        # header (mirror the covenant's OP_BOOLOR check) before trusting PoW.
        if allowed_nbits is not None and header[72:76] not in allowed_nbits:
            raise SpvVerificationError(
                f"header[{i}] nBits {header[72:76].hex()} does not match the committed "
                f"expected_nbits {sorted(b.hex() for b in allowed_nbits)} "
                "(forged-difficulty / wrong-retarget-window defense)"
            )

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

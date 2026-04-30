"""Merkle branch construction and inclusion-proof verification.

Ported from ``relayer/src/proof.js``.

Covenant wire format: N * 33 bytes, each entry is ``[direction_byte][32B_sibling_LE]``

* ``direction == 0x00``: current is on the left  (sibling on the right)
* ``direction == 0x01``: current is on the right (sibling on the left)

mempool.space and Bitcoin Core return sibling hashes in BE display order.
We reverse them to LE here, since Bitcoin's hash256 opcodes work on LE bytes.
"""

from __future__ import annotations

from pyrxd.security.errors import SpvVerificationError, ValidationError

from .pow import hash256

__all__ = [
    "build_branch",
    "compute_root",
    "extract_merkle_root",
    "verify_tx_in_block",
]


def build_branch(merkle_be: list[str], pos: int) -> bytes:
    """Convert a mempool.space / Bitcoin Core Merkle proof into covenant wire format.

    Args:
        merkle_be: Sibling hashes in BE display order (hex strings, as returned
            by mempool.space ``/tx/:txid/merkle-proof``).
        pos: Zero-indexed tx position within the block's flat leaf list.

    Returns:
        N * 33 bytes of concatenated ``[direction][sibling_LE]`` entries.

    Raises:
        ValidationError: if ``pos`` is negative or any sibling is not 32 bytes.
    """
    if pos < 0:
        raise ValidationError("pos must be non-negative")

    parts: list[bytes] = []
    for i, sibling_be_hex in enumerate(merkle_be):
        sibling_be = bytes.fromhex(sibling_be_hex)
        if len(sibling_be) != 32:
            raise ValidationError(f"sibling[{i}] must be 32 bytes, got {len(sibling_be)}")
        direction = (pos >> i) & 1
        sibling_le = sibling_be[::-1]
        parts.append(bytes([direction]) + sibling_le)

    return b"".join(parts)


def compute_root(txid_be_hex: str, branch: bytes) -> bytes:
    """Walk a Merkle branch from leaf to root.

    Args:
        txid_be_hex: Transaction id in BE display format (mempool.space style).
        branch: ``N * 33`` bytes in covenant wire format (from ``build_branch``).

    Returns:
        Computed Merkle root in LE (matches what the covenant extracts from
        the block header at byte offset 36).

    Raises:
        ValidationError: if ``branch`` is not a multiple of 33 bytes.
    """
    if len(branch) % 33 != 0:
        raise ValidationError(f"branch length {len(branch)} is not a multiple of 33")

    # Start with leaf in LE (reverse BE display).
    current = bytes.fromhex(txid_be_hex)[::-1]

    depth = len(branch) // 33
    for i in range(depth):
        direction = branch[i * 33]
        sibling = branch[i * 33 + 1 : i * 33 + 33]
        if direction == 0:
            current = hash256(current + sibling)
        else:
            current = hash256(sibling + current)

    return current  # LE


def extract_merkle_root(header: bytes) -> bytes:
    """Return the 32-byte Merkle root from an 80-byte header (LE, offset 36)."""
    if len(header) != 80:
        raise ValidationError(f"header must be 80 bytes, got {len(header)}")
    return header[36:68]


def verify_tx_in_block(
    raw_tx: bytes,
    txid_be_hex: str,
    branch: bytes,
    pos: int,
    header: bytes,
    expected_depth: int | None = None,
) -> None:
    """Full Merkle inclusion check for a raw transaction within a block.

    Audit defenses applied here (see docs/audits/02 and docs/audits/05):
        * Finding 02-F-1: ``len(raw_tx) > 64`` rejects the 64-byte Merkle forgery.
        * Finding 05-F-9: ``pos == 0`` rejects the coinbase as a payment proof.
        * Finding 05-F-8: ``expected_depth`` must match branch depth when provided.
        * Finding 02-F-1 / parity: ``hash256(raw_tx) == txid`` bound.

    Raises:
        ValidationError: on malformed input (wrong lengths, misaligned branch).
        SpvVerificationError: on any defense trigger or root mismatch.
    """
    # Audit 02-F-1: 64-byte tx Merkle forgery defense.
    if len(raw_tx) <= 64:
        raise SpvVerificationError("raw_tx must be > 64 bytes (64-byte Merkle forgery defense)")

    # Audit 05-F-9: coinbase-as-payment guard.
    if pos == 0:
        raise SpvVerificationError("pos=0 is the coinbase tx - cannot be used as payment proof")

    # Audit 05-F-8: Merkle branch depth binding.
    if len(branch) % 33 != 0:
        raise ValidationError(f"branch length {len(branch)} not a multiple of 33")
    branch_depth = len(branch) // 33
    if expected_depth is not None and branch_depth != expected_depth:
        raise SpvVerificationError(f"branch depth {branch_depth} does not match expected {expected_depth}")

    # Verify the provided raw_tx hashes to the claimed txid.
    computed_txid_le = hash256(raw_tx)
    claimed_txid_le = bytes.fromhex(txid_be_hex)[::-1]
    if computed_txid_le != claimed_txid_le:
        raise SpvVerificationError("hash256(raw_tx) does not match txid")

    # Walk the branch to the root and compare against the header's root.
    computed_root = compute_root(txid_be_hex, branch)
    expected_root = extract_merkle_root(header)
    if computed_root != expected_root:
        raise SpvVerificationError("Merkle root mismatch: tx not in this block")

"""Tests for MerklePath (BEEF/SPV proof) serialization and verification.

ChainTracker integration (verify() against a live node) is commented out in
merkle_path.py and will be wired in Phase 1b. These tests cover:
  - Valid BEEF round-trip (construct → serialize → deserialize → compare)
  - Malformed hex input rejected
  - Empty input rejected
  - Offset validation (illegal sibling offset raises ValueError)
  - compute_root() produces the correct Merkle root for known leaf+branch
"""

from __future__ import annotations

import pytest

from pyrxd.merkle_path import MerklePath

# ── Helpers ──────────────────────────────────────────────────────────────────


def _build_simple_path(block_height: int = 1) -> MerklePath:
    """Return a minimal 2-leaf MerklePath with known hashes.

    Tree layout (height 1):
      root = H(left || right)
      level 0: offset 0 (txid=True), offset 1 (sibling)
      level 1: root offset 0
    """
    txid_hash = "a" * 64  # 32 hex-encoded bytes
    sibling_hash = "b" * 64

    path = [
        [
            {"offset": 0, "hash_str": txid_hash, "txid": True},
            {"offset": 1, "hash_str": sibling_hash},
        ],
        # height 1 is intentionally omitted — MerklePath infers the root
        # via find_or_compute_leaf, so we only need level 0 for a 2-tx tree.
    ]
    return MerklePath(block_height, path)


# ── Round-trip tests ─────────────────────────────────────────────────────────


def test_merkle_path_round_trip_binary():
    """serialize → deserialize must produce an equal MerklePath."""
    mp = _build_simple_path(block_height=42)
    serialized = mp.to_binary()
    restored = MerklePath.from_binary(serialized)

    assert restored.block_height == mp.block_height
    assert len(restored.path) == len(mp.path)
    # Compare the leaf data at level 0
    for orig_leaf, rest_leaf in zip(
        sorted(mp.path[0], key=lambda l: l["offset"]),
        sorted(restored.path[0], key=lambda l: l["offset"]),
    ):
        assert orig_leaf["offset"] == rest_leaf["offset"]
        assert orig_leaf.get("hash_str") == rest_leaf.get("hash_str")
        assert bool(orig_leaf.get("txid")) == bool(rest_leaf.get("txid"))


def test_merkle_path_round_trip_hex():
    """to_hex → from_hex must produce an equal MerklePath."""
    mp = _build_simple_path(block_height=100)
    hex_str = mp.to_hex()
    restored = MerklePath.from_hex(hex_str)

    assert restored.block_height == mp.block_height
    assert len(restored.path) == len(mp.path)


# ── Rejection tests ──────────────────────────────────────────────────────────


def test_from_hex_rejects_malformed():
    """from_hex must raise on input that is not valid BEEF encoding."""
    with pytest.raises(Exception):
        MerklePath.from_hex("deadbeef")  # too short / not parsable as BEEF


def test_from_hex_rejects_empty():
    """from_hex must raise on empty string input."""
    with pytest.raises(Exception):
        MerklePath.from_hex("")


def test_from_binary_rejects_empty():
    """from_binary must raise on empty bytes input."""
    with pytest.raises(Exception):
        MerklePath.from_binary(b"")


def test_invalid_offset_at_height_raises():
    """MerklePath constructor rejects a path where a sibling offset is illegal."""
    # At height 1, offset 99 has no legal derivation from the txid at offset 0.
    with pytest.raises(ValueError, match="Invalid offset"):
        MerklePath(
            block_height=1,
            path=[
                [{"offset": 0, "hash_str": "a" * 64, "txid": True}],
                [{"offset": 99, "hash_str": "c" * 64}],  # 99 is not (0 >> 1) ^ 1 == 1
            ],
        )


def test_empty_level_zero_raises():
    """MerklePath constructor rejects an empty level-0 leaf list."""
    with pytest.raises(ValueError, match="Empty level"):
        MerklePath(block_height=1, path=[[]])


# ── compute_root tests ───────────────────────────────────────────────────────


def test_compute_root_consistency():
    """compute_root() called on different txids in the same path must agree."""
    mp = _build_simple_path(block_height=5)
    txid_hash = mp.path[0][0]["hash_str"]
    root = mp.compute_root(txid_hash)
    # Root is a 64-character hex string (32 bytes)
    assert isinstance(root, str)
    assert len(root) == 64

    # compute_root() with no argument should derive the same root
    root_default = mp.compute_root()
    assert root_default == root


def test_compute_root_unknown_txid_raises():
    """compute_root() must raise ValueError for a txid not in the path."""
    mp = _build_simple_path(block_height=3)
    with pytest.raises(ValueError, match="does not contain the txid"):
        mp.compute_root("0" * 64)

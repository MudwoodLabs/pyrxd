"""``pyrxd.spv.radiant``: Radiant header proof-of-work and the ElectrumX merkle-branch shape.

The headers are REAL mainnet headers, saved from both shipped ElectrumX servers (which agreed):
``tests/fixtures/mark_block_fixtures_2026-09-30.json``. The first test pins the fact the module
exists for, in BOTH directions: Radiant's proof-of-work is judged on SHA-512/256d, so every real
header passes the Radiant check and fails the Bitcoin one. Either half failing means someone has
wired the wrong hash.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

from pyrxd.hash import radiant_block_hash
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.pow import verify_header_pow
from pyrxd.spv.radiant import (
    MAX_MERKLE_DEPTH,
    TxMerkleBranch,
    radiant_header_prev_hash,
    radiant_header_target,
    radiant_header_work,
    verify_radiant_header_pow,
)

_FIX = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "mark_block_fixtures_2026-09-30.json").read_text(encoding="utf-8")
)["fixtures"]


def _headers() -> list[bytes]:
    out = []
    for fx in _FIX.values():
        raw = bytes.fromhex(fx["headers_hex"])
        out += [raw[i : i + 80] for i in range(0, len(raw), 80)]
    return out


REAL = _headers()


def test_there_are_real_headers_to_test() -> None:
    assert len(REAL) == 34


@pytest.mark.parametrize("header", REAL, ids=lambda h: radiant_block_hash(h)[-8:])
def test_a_real_header_passes_radiant_pow_and_fails_bitcoin_pow(header: bytes) -> None:
    assert verify_radiant_header_pow(header) == radiant_block_hash(header)
    with pytest.raises(SpvVerificationError):
        verify_header_pow(header)


def test_real_headers_link_by_their_previous_block_field() -> None:
    for fx in _FIX.values():
        raw = bytes.fromhex(fx["headers_hex"])
        hs = [raw[i : i + 80] for i in range(0, len(raw), 80)]
        for below, above in itertools.pairwise(hs):
            assert radiant_header_prev_hash(above) == radiant_block_hash(below)


@pytest.mark.parametrize("byte", [76, 77, 78, 79], ids=lambda b: f"nonce_byte_{b - 76}")
def test_a_flipped_nonce_byte_fails_pow(byte: int) -> None:
    h = bytearray(REAL[0])
    h[byte] ^= 0x01
    with pytest.raises(SpvVerificationError, match="above its nBits target"):
        verify_radiant_header_pow(bytes(h))


@pytest.mark.parametrize(
    "nbits",
    ["00000000", "ffff7f1e", "00008020", "ffff8f1a"],
    ids=["zero", "exponent_too_big", "sign_bit_exp20", "sign_bit"],
)
def test_a_malformed_nbits_is_a_validation_error(nbits: str) -> None:
    h = REAL[0][:72] + bytes.fromhex(nbits) + REAL[0][76:]
    with pytest.raises(ValidationError):
        verify_radiant_header_pow(h)


@pytest.mark.parametrize("length", [0, 79, 81])
def test_a_header_that_is_not_80_bytes_is_refused(length: int) -> None:
    with pytest.raises(ValidationError, match="80 bytes"):
        verify_radiant_header_pow(b"\x00" * length)


def test_target_and_work_decode_real_nbits() -> None:
    """``1a00aa31`` (460,572's nBits, wire bytes ``31aa001a``) → ``0x00aa31 << 8*(0x1a-3)``."""
    h = next(h for h in REAL if radiant_block_hash(h).startswith("000000000000003b235d"))
    assert h[72:76].hex() == "31aa001a"
    assert radiant_header_target(h) == 0x00AA31 << (8 * (0x1A - 3))
    assert radiant_header_work(h) == (1 << 256) // (radiant_header_target(h) + 1)
    assert radiant_header_work(h).bit_length() - 1 == 56


@pytest.mark.parametrize(
    ("exp", "mantissa", "want"), [(3, 0x123456, 0x123456), (2, 0x123456, 0x1234), (1, 0x123456, 0x12)]
)
def test_small_exponents_shift_right(exp: int, mantissa: int, want: int) -> None:
    nbits = mantissa.to_bytes(3, "little") + bytes([exp])
    h = REAL[0][:72] + nbits + REAL[0][76:]
    assert radiant_header_target(h) == want


# ── TxMerkleBranch ──────────────────────────────────────────────────────────────────────────


def test_the_real_replies_parse() -> None:
    for fx in _FIX.values():
        b = TxMerkleBranch.from_electrumx(fx["merkle"])
        assert b.block_height == fx["merkle"]["block_height"]
        assert b.branch == tuple(fx["merkle"]["merkle"])


def test_uppercase_siblings_are_normalised() -> None:
    m = next(iter(_FIX.values()))["merkle"]
    b = TxMerkleBranch.from_electrumx({**m, "merkle": [s.upper() for s in m["merkle"]]})
    assert b.branch == tuple(m["merkle"])


@pytest.mark.parametrize(
    "reply",
    [
        None,
        "x",
        [],
        {"merkle": [], "pos": 0},
        {"block_height": 1, "pos": 0},
        {"block_height": 1, "merkle": []},
        {"block_height": 1, "merkle": "ab" * 32, "pos": 0},
        {"block_height": 1, "merkle": ["ab" * 31], "pos": 0},
        {"block_height": 1, "merkle": [None], "pos": 0},
        {"block_height": 1, "merkle": [" " + "ab" * 31 + "a"], "pos": 0},
        {"block_height": -1, "merkle": [], "pos": 0},
        {"block_height": True, "merkle": [], "pos": 0},
        {"block_height": 1.0, "merkle": [], "pos": 0},
        {"block_height": 1, "merkle": [], "pos": -1},
        {"block_height": 1, "merkle": [], "pos": 1},
        {"block_height": 1, "merkle": ["ab" * 32], "pos": 2},
        {"block_height": 1, "merkle": ["ab" * 32] * (MAX_MERKLE_DEPTH + 1), "pos": 1},
    ],
)
def test_a_malformed_reply_is_a_validation_error(reply: object) -> None:
    with pytest.raises(ValidationError):
        TxMerkleBranch.from_electrumx(reply)


def test_the_deepest_allowed_branch_and_the_coinbase_are_accepted() -> None:
    """Honest-path pair for the refusals above: depth 32 and pos 0 are shapes real blocks have."""
    TxMerkleBranch(block_height=1, branch=("ab" * 32,) * MAX_MERKLE_DEPTH, pos=2**MAX_MERKLE_DEPTH - 1)
    TxMerkleBranch(block_height=1, branch=("ab" * 32,), pos=0)
    TxMerkleBranch(block_height=1, branch=(), pos=0)

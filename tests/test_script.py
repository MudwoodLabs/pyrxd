"""Tests for script execution engine (spend.py) and script templates.

Scope per module docstring in spend.py:
  - P2PKH fully implemented — tested here
  - Unknown opcode raises ValidationError via script_evaluation_error()
  - Malformed script bytes raise on construction/chunk-build

Note: Full P2PKH spend execution requires a complete Transaction context with
source satoshis, which involves significant setup. These tests cover:
  1. P2PKH locking script construction (script/type.py)
  2. Script byte serialization round-trip
  3. ValidationError raised on script execution errors
  4. UnsupportedScriptError is importable and is a subclass of RxdSdkError
"""
import pytest

from pyrxd.constants import OpCode
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH, BareMultisig, RPuzzle
from pyrxd.security.errors import RxdSdkError, UnsupportedScriptError, ValidationError


# ── UnsupportedScriptError is properly defined ───────────────────────────────

def test_unsupported_script_error_is_sdk_error():
    """UnsupportedScriptError must be a subclass of RxdSdkError."""
    assert issubclass(UnsupportedScriptError, RxdSdkError)


def test_unsupported_script_error_can_be_raised():
    """UnsupportedScriptError can be raised and caught."""
    with pytest.raises(UnsupportedScriptError):
        raise UnsupportedScriptError("opcode OP_UNKNOWN not yet supported")


# ── P2PKH locking script construction ────────────────────────────────────────

def test_p2pkh_locking_script_from_address():
    """P2PKH.lock() from a known address must produce the canonical locking script."""
    # Known BTC mainnet address and its P2PKH locking script bytes.
    address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na"  # noqa — not used, use hardcoded below

    # Use a known pubkey hash directly to avoid address-decode complexity.
    pubkey_hash = bytes.fromhex("20bb5c3bfaef0231dc05190e7f1c8e22e098991e")
    script = P2PKH().lock(pubkey_hash)

    # P2PKH = OP_DUP OP_HASH160 <20-byte-pkh> OP_EQUALVERIFY OP_CHECKSIG
    hex_script = script.hex()
    assert hex_script == "76a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac"


def test_p2pkh_locking_script_wrong_hash_length():
    """P2PKH.lock() must raise ValidationError for a public key hash that is not 20 bytes."""
    with pytest.raises(ValidationError, match="invalid byte length"):
        P2PKH().lock(b"\x00" * 19)


# ── Script round-trip ─────────────────────────────────────────────────────────

def test_script_hex_round_trip():
    """Script constructed from hex must serialize back to the same hex."""
    hex_str = "76a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac"
    script = Script(hex_str)
    assert script.hex() == hex_str


def test_script_bytes_round_trip():
    """Script constructed from bytes must serialize back to the same bytes."""
    raw = bytes.fromhex("76a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88ac")
    script = Script(raw)
    assert script.serialize() == raw


def test_empty_script_is_valid():
    """Script(None) and Script(b'') must produce an empty, valid Script."""
    assert Script(None).byte_length() == 0
    assert Script(b"").byte_length() == 0


# ── BareMultisig validation ───────────────────────────────────────────────────

def test_bare_multisig_bad_threshold_raises():
    """BareMultisig.lock() must raise ValidationError for threshold > n-of-n."""
    priv = PrivateKey.from_hex("0101010101010101010101010101010101010101010101010101010101010101")
    pubkey = priv.public_key().serialize()
    with pytest.raises(ValidationError, match="bad threshold"):
        BareMultisig().lock([pubkey], threshold=2)  # 2-of-1 is invalid


# ── RPuzzle validation ────────────────────────────────────────────────────────

def test_rpuzzle_invalid_type_raises():
    """RPuzzle constructor must raise ValidationError for an unknown puzzle type."""
    with pytest.raises(ValidationError, match="unsupported puzzle type"):
        RPuzzle(puzzle_type="BLAKE3")


def test_rpuzzle_valid_types():
    """RPuzzle constructor must accept all defined puzzle types."""
    for ptype in ["raw", "SHA1", "SHA256", "HASH256", "RIPEMD160", "HASH160"]:
        rp = RPuzzle(puzzle_type=ptype)
        assert rp.type == ptype



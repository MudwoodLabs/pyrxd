"""Property-based tests for pyrxd using Hypothesis.

Coverage targets:
  1. Transaction serialize/deserialize round-trip
  2. Type constructors: Txid, BlockHeight, RawTx, Hex32, Satoshis, Photons, SighashFlag, Nbits
  3. Cryptographic round-trips: sign/verify, DER serialize/deserialize, WIF encode/decode
  4. Script encode/decode: from_asm(to_asm()) identity, encode_int for arbitrary integers
  5. strip_witness: never raises anything other than ValidationError
  6. MerklePath construction: valid structure succeeds; invalid raises ValueError, not panic

Hypothesis finds counterexamples by generating random inputs and checking invariants.
Any test marked with FINDING: in its docstring documents a real bug discovered.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from pyrxd.keys import PrivateKey
from pyrxd.merkle_path import MerklePath
from pyrxd.script.script import Script
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import (
    BlockHeight,
    Hex32,
    Nbits,
    Photons,
    RawTx,
    Satoshis,
    SighashFlag,
    Txid,
)
from pyrxd.spv.witness import strip_witness

# ── Imports under test ───────────────────────────────────────────────────────
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import deserialize_ecdsa_der, encode_int, serialize_ecdsa_der

# ── Shared strategies ────────────────────────────────────────────────────────

# A valid 64-char lowercase hex string (Txid)
_hex_64 = st.text(
    alphabet="0123456789abcdef",
    min_size=64,
    max_size=64,
)

# Raw bytes that are strictly longer than 64 (RawTx)
_raw_tx_bytes = st.binary(min_size=65, max_size=512)

# Valid secp256k1 scalar range (1 .. n-1)
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_valid_scalar = st.integers(min_value=1, max_value=_SECP256K1_N - 1)

# Script bytes: up to 520 bytes (Bitcoin's max pushdata)
_script_bytes = st.binary(min_size=0, max_size=520)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _minimal_transaction(version: int = 1, locktime: int = 0) -> Transaction:
    """Return a valid minimal transaction with one input and one output."""
    src_txid = "a" * 64
    locking = Script(bytes.fromhex("76a914" + "00" * 20 + "88ac"))  # P2PKH-like
    Transaction(
        tx_inputs=[],
        tx_outputs=[TransactionOutput(locking_script=locking, satoshis=1_000)],
        version=1,
        locktime=0,
    )
    # Manually set txid so it's stable
    tx_input = TransactionInput(
        source_txid=src_txid,
        source_output_index=0,
        unlocking_script=Script(b""),
        sequence=0xFFFFFFFF,
    )
    tx = Transaction(
        tx_inputs=[tx_input],
        tx_outputs=[TransactionOutput(locking_script=locking, satoshis=900)],
        version=version,
        locktime=locktime,
    )
    return tx


def _build_simple_merkle_path(block_height: int, txid_hash: str, sibling_hash: str) -> MerklePath:
    """Construct a minimal valid 2-leaf MerklePath."""
    path = [
        [
            {"offset": 0, "hash_str": txid_hash, "txid": True},
            {"offset": 1, "hash_str": sibling_hash},
        ],
    ]
    return MerklePath(block_height, path)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Transaction serialize / deserialize round-trip
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    version=st.integers(min_value=1, max_value=0xFFFFFFFF),
    locktime=st.integers(min_value=0, max_value=0xFFFFFFFF),
)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_transaction_serialize_roundtrip(version, locktime):
    """Transaction.serialize() → Transaction.from_hex() must recover version and locktime."""
    tx = _minimal_transaction(version=version, locktime=locktime)
    serialized = tx.serialize()
    restored = Transaction.from_hex(serialized)

    assert restored is not None, "from_hex returned None for a valid serialized transaction"
    assert restored.version == tx.version
    assert restored.locktime == tx.locktime
    assert len(restored.inputs) == len(tx.inputs)
    assert len(restored.outputs) == len(tx.outputs)


@given(satoshis=st.integers(min_value=0, max_value=2_100_000_000_000_000))
@settings(max_examples=200)
def test_transaction_output_satoshis_roundtrip(satoshis):
    """Output satoshis must survive serialize → deserialize unchanged."""
    locking = Script(bytes.fromhex("76a914" + "00" * 20 + "88ac"))
    src_txid = "b" * 64
    tx_input = TransactionInput(
        source_txid=src_txid,
        source_output_index=0,
        unlocking_script=Script(b""),
        sequence=0xFFFFFFFF,
    )
    tx = Transaction(
        tx_inputs=[tx_input],
        tx_outputs=[TransactionOutput(locking_script=locking, satoshis=satoshis)],
        version=1,
        locktime=0,
    )
    serialized = tx.serialize()
    restored = Transaction.from_hex(serialized)

    assert restored is not None
    assert restored.outputs[0].satoshis == satoshis


@given(script_data=_script_bytes)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_transaction_locking_script_roundtrip(script_data):
    """Locking script bytes must survive serialize → deserialize unchanged."""
    locking = Script(script_data)
    src_txid = "c" * 64
    tx_input = TransactionInput(
        source_txid=src_txid,
        source_output_index=0,
        unlocking_script=Script(b""),
        sequence=0xFFFFFFFF,
    )
    tx = Transaction(
        tx_inputs=[tx_input],
        tx_outputs=[TransactionOutput(locking_script=locking, satoshis=500)],
        version=1,
        locktime=0,
    )
    serialized = tx.serialize()
    restored = Transaction.from_hex(serialized)

    assert restored is not None
    assert restored.outputs[0].locking_script.serialize() == script_data


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Type constructors — valid inputs succeed, invalid raise ValidationError
# ═══════════════════════════════════════════════════════════════════════════════


@given(value=_hex_64)
@settings(max_examples=300)
def test_txid_accepts_valid_64char_hex(value):
    """Txid must accept any 64-char lowercase hex string without raising."""
    t = Txid(value)
    assert isinstance(t, str)
    assert len(t) == 64


@given(
    value=st.one_of(
        st.integers(),
        st.none(),
        st.binary(),
        # Too short: 0–63 chars of valid hex chars
        st.text(alphabet="0123456789abcdef", min_size=0, max_size=63),
        # Too long: 65–128 chars of valid hex chars
        st.text(alphabet="0123456789abcdef", min_size=65, max_size=128),
        # Right length but contains uppercase letters (mixed, guaranteed non-lowercase)
        st.text(alphabet="ABCDEF", min_size=64, max_size=64),  # pure uppercase A-F
    )
)
@settings(max_examples=200)
def test_txid_rejects_invalid(value):
    """Txid must raise ValidationError for all invalid inputs, never panic."""
    with pytest.raises(ValidationError):
        Txid(value)


@given(value=st.integers(min_value=0, max_value=10_000_000))
@settings(max_examples=300)
def test_blockheight_accepts_valid(value):
    """BlockHeight accepts non-negative integers up to the ceiling."""
    bh = BlockHeight(value)
    assert int(bh) == value


@given(
    value=st.one_of(
        st.integers(min_value=10_000_001),  # above ceiling
        st.integers(max_value=-1),  # negative
        st.floats(),
        st.booleans(),
        st.none(),
    )
)
@settings(max_examples=200)
def test_blockheight_rejects_invalid(value):
    """BlockHeight raises ValidationError for all invalid inputs."""
    with pytest.raises(ValidationError):
        BlockHeight(value)


@given(value=_raw_tx_bytes)
@settings(max_examples=200)
def test_rawtx_accepts_over_64_bytes(value):
    """RawTx must accept any bytes strictly longer than 64 bytes."""
    r = RawTx(value)
    assert bytes(r) == value


@given(value=st.binary(max_size=64))
@settings(max_examples=200)
def test_rawtx_rejects_64_or_fewer_bytes(value):
    """RawTx must raise ValidationError for any input <= 64 bytes."""
    with pytest.raises(ValidationError):
        RawTx(value)


@given(value=st.binary(min_size=32, max_size=32))
@settings(max_examples=200)
def test_hex32_accepts_exactly_32_bytes(value):
    """Hex32 must accept any 32-byte value."""
    h = Hex32(value)
    assert bytes(h) == value


@given(
    value=st.one_of(
        st.binary(min_size=0, max_size=31),
        st.binary(min_size=33),
    )
)
@settings(max_examples=200)
def test_hex32_rejects_wrong_length(value):
    """Hex32 must raise ValidationError for any bytes not exactly 32 long."""
    with pytest.raises(ValidationError):
        Hex32(value)


@given(value=st.integers(min_value=0, max_value=2_100_000_000_000_000))
@settings(max_examples=200)
def test_satoshis_accepts_valid(value):
    """Satoshis must accept the full valid range [0, BTC_MAX_SATS]."""
    s = Satoshis(value)
    assert int(s) == value


@given(
    value=st.one_of(
        st.integers(min_value=2_100_000_000_000_001),
        st.integers(max_value=-1),
        st.booleans(),
        st.floats(),
    )
)
@settings(max_examples=200)
def test_satoshis_rejects_invalid(value):
    """Satoshis raises ValidationError for out-of-range or wrong-type inputs."""
    with pytest.raises(ValidationError):
        Satoshis(value)


@given(value=st.integers(min_value=0, max_value=10**18))
@settings(max_examples=200)
def test_photons_accepts_non_negative(value):
    """Photons must accept any non-negative integer."""
    p = Photons(value)
    assert int(p) == value


@given(flag=st.sampled_from([0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3]))
@settings(max_examples=50)
def test_sighashflag_accepts_all_valid(flag):
    """SighashFlag must accept every valid flag byte."""
    sf = SighashFlag(flag)
    assert int(sf) == flag


@given(flag=st.integers(min_value=0, max_value=0xFF).filter(lambda x: x not in {0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3}))
@settings(max_examples=200)
def test_sighashflag_rejects_invalid(flag):
    """SighashFlag rejects every integer not in the valid set."""
    with pytest.raises(ValidationError):
        SighashFlag(flag)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Cryptographic round-trips
# ═══════════════════════════════════════════════════════════════════════════════


@given(message=st.binary(min_size=1, max_size=256))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_sign_verify_roundtrip(message):
    """PrivateKey.sign() → PublicKey.verify() must always hold for any message."""
    key = PrivateKey()
    sig = key.sign(message)
    assert key.verify(sig, message), "sign/verify round-trip failed"


@given(scalar=_valid_scalar)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_sign_verify_with_known_scalar(scalar):
    """sign/verify must hold when the key is constructed from an arbitrary valid scalar."""
    key = PrivateKey(scalar)
    message = b"test message for property-based testing"
    sig = key.sign(message)
    assert key.verify(sig, message)


@given(message=st.binary(min_size=1, max_size=256))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_ecdsa_der_roundtrip(message):
    """serialize_ecdsa_der → deserialize_ecdsa_der must recover the same (r, s) pair."""
    key = PrivateKey()
    sig = key.sign(message)
    r, s = deserialize_ecdsa_der(sig)

    # r and s must be positive integers within the curve order
    assert 0 < r < _SECP256K1_N
    assert 0 < s <= _SECP256K1_N // 2  # low-s enforced

    # Re-serializing must produce an equivalent DER blob
    re_serialized = serialize_ecdsa_der((r, s))
    r2, s2 = deserialize_ecdsa_der(re_serialized)
    assert r2 == r
    assert s2 == s


@given(scalar=_valid_scalar)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_wif_encode_decode_roundtrip(scalar):
    """WIF encode → decode must recover the same private key bytes."""
    key = PrivateKey(scalar)
    wif = key.wif()
    # Reconstruct from WIF string — PrivateKey(wif_str) decodes it
    key2 = PrivateKey(wif)
    assert key.serialize() == key2.serialize(), "WIF round-trip changed the key bytes"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Script encode / decode
# ═══════════════════════════════════════════════════════════════════════════════


@given(num=st.integers(min_value=-(2**31), max_value=2**31))
@settings(max_examples=300)
def test_encode_int_produces_valid_pushdata(num):
    """encode_int must return non-empty bytes for any integer without raising."""
    result = encode_int(num)
    assert isinstance(result, bytes)
    assert len(result) >= 1


@given(data=st.binary(min_size=0, max_size=75))
@settings(max_examples=200)
def test_script_serialize_roundtrip_raw_bytes(data):
    """Script constructed from bytes must round-trip through serialize()."""
    s = Script(data)
    assert s.serialize() == data


@given(data=st.binary(min_size=0, max_size=520))
@settings(max_examples=200)
def test_script_byte_length_matches_data(data):
    """Script.byte_length() must equal len(data) for any raw byte input."""
    s = Script(data)
    assert s.byte_length() == len(data)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. strip_witness — must not panic; only ValidationError or success
# ═══════════════════════════════════════════════════════════════════════════════


@given(data=st.binary(min_size=0, max_size=512))
@settings(max_examples=300)
def test_strip_witness_never_panics(data):
    """strip_witness(arbitrary_bytes) must either return bytes or raise
    ValidationError. Any other exception type is a bug."""
    try:
        result = strip_witness(data)
        assert isinstance(result, bytes)
    except ValidationError:
        pass  # expected for malformed input
    except Exception as exc:
        pytest.fail(
            f"strip_witness raised unexpected {type(exc).__name__}: {exc}\n  input ({len(data)} bytes): {data.hex()}"
        )


@given(data=st.binary(min_size=10, max_size=512).filter(lambda b: b[4] != 0x00))
@settings(max_examples=200)
def test_strip_witness_passthrough_for_legacy(data):
    """If byte[4] != 0x00, strip_witness must return the input unchanged."""
    try:
        result = strip_witness(data)
        assert result is data or result == data
    except ValidationError:
        pass  # still acceptable — the rest of the bytes may be malformed


@given(data=st.binary(max_size=9))
@settings(max_examples=100)
def test_strip_witness_rejects_too_short(data):
    """strip_witness must raise ValidationError for inputs shorter than 10 bytes."""
    with pytest.raises(ValidationError):
        strip_witness(data)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MerklePath construction — valid succeeds, invalid raises ValueError
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    block_height=st.integers(min_value=0, max_value=900_000),
    txid_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    sibling_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
)
@settings(max_examples=200)
def test_merkle_path_valid_construction(block_height, txid_hash, sibling_hash):
    """MerklePath(valid_structure) must succeed and produce a usable object."""
    mp = _build_simple_merkle_path(block_height, txid_hash, sibling_hash)
    assert mp.block_height == block_height
    assert len(mp.path) == 1
    assert len(mp.path[0]) == 2


@given(
    block_height=st.integers(min_value=0, max_value=900_000),
    txid_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    sibling_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
)
@settings(max_examples=200)
def test_merkle_path_binary_roundtrip(block_height, txid_hash, sibling_hash):
    """MerklePath.to_binary() → MerklePath.from_binary() must preserve structure."""
    mp = _build_simple_merkle_path(block_height, txid_hash, sibling_hash)
    serialized = mp.to_binary()
    restored = MerklePath.from_binary(serialized)

    assert restored.block_height == mp.block_height
    assert len(restored.path) == len(mp.path)

    for orig_leaf, rest_leaf in zip(
        sorted(mp.path[0], key=lambda l: l["offset"]),
        sorted(restored.path[0], key=lambda l: l["offset"]),
    ):
        assert orig_leaf["offset"] == rest_leaf["offset"]
        assert orig_leaf.get("hash_str") == rest_leaf.get("hash_str")


@given(
    block_height=st.integers(min_value=0, max_value=900_000),
    offset_a=st.integers(min_value=0, max_value=100),
    offset_b=st.integers(min_value=0, max_value=100),
    txid_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
    sibling_hash=st.text(alphabet="0123456789abcdef", min_size=64, max_size=64),
)
@settings(max_examples=200)
def test_merkle_path_duplicate_offset_raises_valueerror(block_height, offset_a, offset_b, txid_hash, sibling_hash):
    """Duplicate offsets at the same level must raise ValueError, not panic."""
    assume(offset_a == offset_b)  # force the duplicate condition
    path = [
        [
            {"offset": offset_a, "hash_str": txid_hash, "txid": True},
            {"offset": offset_b, "hash_str": sibling_hash},
        ],
    ]
    with pytest.raises(ValueError):
        MerklePath(block_height, path)


def test_merkle_path_empty_level_raises_valueerror():
    """An empty level 0 must raise ValueError."""
    with pytest.raises(ValueError):
        MerklePath(1, [[]])  # empty list at level 0


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Nbits type constructor — valid/invalid
# ═══════════════════════════════════════════════════════════════════════════════


@given(
    # exponent in [1..0x1D], mantissa: 24-bit non-zero without sign bit
    exponent=st.integers(min_value=1, max_value=0x1D),
    mantissa=st.integers(min_value=1, max_value=0x7FFFFF),
)
@settings(max_examples=200)
def test_nbits_accepts_valid(exponent, mantissa):
    """Nbits must accept a valid 4-byte little-endian encoding."""
    raw = bytes(
        [
            mantissa & 0xFF,
            (mantissa >> 8) & 0xFF,
            (mantissa >> 16) & 0xFF,
            exponent,
        ]
    )
    nb = Nbits(raw)
    assert len(nb) == 4


@given(
    exponent=st.integers(min_value=0x1E, max_value=0xFF),
    mantissa=st.integers(min_value=1, max_value=0x7FFFFF),
)
@settings(max_examples=100)
def test_nbits_rejects_large_exponent(exponent, mantissa):
    """Nbits must raise ValidationError when exponent > 0x1D."""
    raw = bytes([mantissa & 0xFF, (mantissa >> 8) & 0xFF, (mantissa >> 16) & 0xFF, exponent])
    with pytest.raises(ValidationError):
        Nbits(raw)


@given(
    exponent=st.integers(min_value=1, max_value=0x1D),
    # mantissa with sign bit set: bit 23 is 1
    mantissa=st.integers(min_value=0x800000, max_value=0xFFFFFF),
)
@settings(max_examples=100)
def test_nbits_rejects_negative_mantissa(exponent, mantissa):
    """Nbits must reject mantissa with sign bit set."""
    raw = bytes([mantissa & 0xFF, (mantissa >> 8) & 0xFF, (mantissa >> 16) & 0xFF, exponent])
    with pytest.raises(ValidationError):
        Nbits(raw)

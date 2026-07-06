"""RSWP wire layer: encoder↔decoder round-trip properties + node-strictness byte pins.

The encoder must satisfy the STRICTEST consumer (Radiant-Core ``swapindex.cpp``),
which is stricter than pyrxd's own decoder — so the byte-pin tests here assert the
exact push forms (1-byte direct pushes, ``OP_0``/minimal-CScriptNum vout, bare
``OP_RETURN`` prefix), not just decodability.
"""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Txid
from pyrxd.swap.rswp import (
    RXD_TOKEN_ID,
    DemandedOutput,
    RswpOrder,
    decode_rswp_order,
    encode_price_terms,
    encode_rswp_order,
    parse_price_terms,
    swap_token_id,
)

# ------------------------------------------------------------------ strategies

_txid_hex = st.binary(min_size=32, max_size=32).map(lambda b: b.hex())
_ref = st.builds(
    lambda txid, vout: GlyphRef(txid=Txid(txid), vout=vout),
    _txid_hex,
    st.integers(min_value=0, max_value=0xFFFFFFFF),
)
_demanded_output = st.builds(
    DemandedOutput,
    value=st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    script=st.binary(min_size=1, max_size=200),  # exercises direct + PUSHDATA1 pushes
)
_vout = st.one_of(
    st.integers(min_value=0, max_value=20),
    st.sampled_from([0, 1, 16, 17, 127, 128, 255, 256, 0x7FFF, 0x8000, 0x7FFFFFFF]),
)


@given(
    offered_ref=st.one_of(st.none(), _ref),
    want_ref=st.one_of(st.none(), _ref),
    offered_type=st.integers(min_value=0, max_value=255),
    offered_txid=_txid_hex,
    offered_vout=_vout,
    outputs=st.lists(_demanded_output, min_size=1, max_size=5),
    signature=st.binary(min_size=1, max_size=120),
    expiry_height=st.one_of(st.none(), st.integers(min_value=1, max_value=0xFFFFFFFF)),
)
def test_encode_decode_round_trip(
    offered_ref, want_ref, offered_type, offered_txid, offered_vout, outputs, signature, expiry_height
) -> None:
    """Everything the encoder writes, the canonical decoder reads back verbatim (v2 and v3)."""
    token_id = swap_token_id(offered_ref)
    want_token_id = None if want_ref is None else swap_token_id(want_ref)
    price_terms = encode_price_terms(outputs)
    script = encode_rswp_order(
        offered_type=offered_type,
        token_id=token_id,
        want_token_id=want_token_id,
        offered_txid=offered_txid,
        offered_vout=offered_vout,
        price_terms=price_terms,
        signature=signature,
        expiry_height=expiry_height,
    )
    order = decode_rswp_order(script)

    assert order.version == (3 if expiry_height is not None else 2)
    assert order.expiry_height == expiry_height
    assert order.offered_type == offered_type
    assert order.terms_type == 1
    # 32-byte ids travel byte-reversed on chain (display digest ↔ pushed form).
    assert order.token_id == (token_id if token_id == RXD_TOKEN_ID else token_id[::-1])
    if want_token_id is None:
        assert order.want_token_id is None
    else:
        assert order.want_token_id == want_token_id[::-1]
    assert order.offered_txid == offered_txid
    assert order.offered_utxo_index == offered_vout
    assert order.price_terms == price_terms
    assert order.demanded_outputs == outputs
    assert order.signature == signature


@given(outputs=st.lists(_demanded_output, min_size=1, max_size=8))
def test_price_terms_round_trip(outputs) -> None:
    assert parse_price_terms(encode_price_terms(outputs)) == outputs


# ------------------------------------------------------------------ token id


def test_swap_token_id_rxd_is_all_zeros() -> None:
    assert swap_token_id(None) == b"\x00" * 32


def test_swap_token_id_hashes_the_le_script_operand_ref() -> None:
    """sha256 of the 36-byte little-endian ref (GlyphRef.to_bytes()) — the exact
    bytes OP_PUSHINPUTREF pushes; matches Photonic assetToSwapTokenId, which
    reverses the display ref before hashing."""
    ref = GlyphRef(txid=Txid("ee" * 31 + "01"), vout=1)
    le_ref = bytes.fromhex(str(ref.txid))[::-1] + (1).to_bytes(4, "little")
    assert swap_token_id(ref) == hashlib.sha256(le_ref).digest()


# ------------------------------------------------------------------ node-strictness byte pins


def _fixed_order_script(**overrides) -> bytes:
    params = dict(
        offered_type=0,
        token_id=RXD_TOKEN_ID,
        want_token_id=swap_token_id(GlyphRef(txid=Txid("cc" * 32), vout=2)),
        offered_txid="ab" * 32,
        offered_vout=0,
        price_terms=encode_price_terms([DemandedOutput(value=1234, script=b"\x51")]),
        signature=b"\x01\x02\x03",
    )
    params.update(overrides)
    return encode_rswp_order(**params)


def test_frame_starts_with_bare_op_return() -> None:
    """The node checks scriptPubKey[0] == OP_RETURN — an OP_FALSE prefix (pyrxd's
    OpReturn template default) would make the node skip the advertisement."""
    assert _fixed_order_script()[0] == 0x6A


def test_small_fields_are_one_byte_direct_pushes_never_op_n() -> None:
    """swapindex requires data.size()==1 for version/flags/offeredType/termsType;
    GetOp yields EMPTY data for OP_N, so OP_2 as the version byte drops the order."""
    script = _fixed_order_script()
    # OP_RETURN, PUSH4 "RSWP", then: 01 02 (version), 01 01 (flags=HAS_WANT),
    # 01 00 (offeredType=0 — NOT OP_0), 01 01 (termsType).
    prefix = bytes([0x6A, 0x04]) + b"RSWP" + bytes([0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x01, 0x01])
    assert script.startswith(prefix)


def test_vout_zero_is_op_0_and_small_vouts_are_scriptnum_pushes() -> None:
    """Photonic encodeScriptNum: 0 → empty buffer (OP_0); n → minimal LE with sign pad,
    as a DIRECT push (radiantjs never converts buffers to OP_N)."""
    tail_zero = _fixed_order_script(offered_vout=0)
    tail_one = _fixed_order_script(offered_vout=1)
    tail_128 = _fixed_order_script(offered_vout=128)  # sign bit → 0x00 pad
    # locate the vout push right after the 32-byte outpoint push (0x20 prefix + 32 bytes)
    outpoint_push = bytes([0x20]) + bytes.fromhex("ab" * 32)[::-1]
    for script, expected in ((tail_zero, b"\x00"), (tail_one, b"\x01\x01"), (tail_128, b"\x02\x80\x00")):
        at = script.index(outpoint_push) + len(outpoint_push)
        assert script[at : at + len(expected)] == expected


def test_token_ids_are_pushed_byte_reversed() -> None:
    want = swap_token_id(GlyphRef(txid=Txid("cc" * 32), vout=2))
    script = _fixed_order_script()
    assert want[::-1] in script and want not in script


# ------------------------------------------------------------------ malformed / mismatch rejection


def test_v2_frame_with_expiry_flag_rejected() -> None:
    """flag 0x02 on a v2 frame: the frame has no field to carry an expiry — the greedy
    tail rule would otherwise silently mis-slice the frame."""
    script = bytearray(_fixed_order_script())
    # flags byte is the second 1-byte field: ...RSWP | 01 02 | 01 <flags> ...
    at = script.index(b"RSWP") + 4 + 2 + 1
    script[at] |= 0x02
    with pytest.raises(ValidationError, match="inconsistent with expiry flag"):
        decode_rswp_order(bytes(script))


def test_v3_frame_without_expiry_flag_rejected() -> None:
    script = bytearray(_fixed_order_script())  # v2 layout, no expiry field
    at = script.index(b"RSWP") + 4 + 1  # version byte inside its push
    script[at] = 0x03
    with pytest.raises(ValidationError, match="inconsistent with expiry flag"):
        decode_rswp_order(bytes(script))


def test_hand_built_rswp_order_enforces_v3_iff_expiry() -> None:
    kwargs = dict(
        version=2,
        flags=0,
        offered_type=0,
        terms_type=1,
        token_id=b"\x00" * 32,
        want_token_id=None,
        offered_utxo_hash=b"\xaa" * 32,
        offered_utxo_index=0,
        price_terms=b"",
        demanded_outputs=None,
        signature=b"\x01",
    )
    with pytest.raises(ValidationError, match="cannot carry an expiry"):
        RswpOrder(**{**kwargs, "expiry_height": 5})
    with pytest.raises(ValidationError, match="requires an expiry"):
        RswpOrder(**{**kwargs, "version": 3})


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"token_id": b"\x00" * 31}, "32 bytes"),
        ({"offered_vout": -1}, "cannot be advertised"),
        ({"offered_vout": 0x80000000}, "cannot be advertised"),  # node reads a 4-byte CScriptNum
        ({"expiry_height": 0}, "expiry_height"),
        ({"expiry_height": 0x1_0000_0000}, "expiry_height"),
        ({"price_terms": b""}, "price_terms"),
        ({"signature": b""}, "signature"),
        ({"offered_type": 256}, "one byte"),
    ],
)
def test_encoder_rejects_out_of_range_params(kwargs, match) -> None:
    with pytest.raises(ValidationError, match=match):
        _fixed_order_script(**kwargs)


def test_encode_price_terms_rejects_bad_inputs() -> None:
    with pytest.raises(ValidationError, match="at least 1"):
        encode_price_terms([])
    with pytest.raises(ValidationError, match="8 bytes"):
        encode_price_terms([DemandedOutput(value=2**64, script=b"\x51")])
    with pytest.raises(ValidationError, match="non-empty script"):
        encode_price_terms([DemandedOutput(value=1, script=b"")])


def test_rxd_want_token_id_is_equivalent_to_none() -> None:
    """Passing the all-zero id explicitly must behave exactly like None (flag clear,
    field omitted) — Photonic's hasWantToken check."""
    assert _fixed_order_script(want_token_id=None) == _fixed_order_script(want_token_id=RXD_TOKEN_ID)

"""Tests for the RSWP on-chain swap-order decoder (read side)."""

from __future__ import annotations

import pytest

from pyrxd.gravity.swap_order import DemandedOutput, decode_rswp_order, parse_price_terms, parse_price_terms_lenient
from pyrxd.security.errors import ValidationError

_OP_RETURN = b"\x6a"


def _push(data: bytes) -> bytes:
    """A canonical data push (1-byte length prefix; data <= 75 bytes)."""
    assert len(data) <= 75
    return bytes([len(data)]) + data


def _op_n(n: int) -> bytes:
    """OP_0 / OP_1..OP_16 as a single opcode byte."""
    return b"\x00" if n == 0 else bytes([0x50 + n])


def _frame(pushes: list[bytes]) -> bytes:
    return _OP_RETURN + b"".join(pushes)


def _v2_frame(
    *,
    flags=0,
    offered_type=0,
    terms_type=1,
    token_id=b"\x00" * 32,
    want=None,
    offered_hash=b"\xaa" * 32,
    idx_item=_op_n(0),
    tail: list[bytes] | None = None,
) -> bytes:
    pushes = [
        _push(b"RSWP"),
        _push(b"\x02"),
        _push(bytes([flags])),
        _push(bytes([offered_type])),
        _push(bytes([terms_type])),
        _push(token_id),
    ]
    if want is not None:
        pushes.append(_push(want))
    pushes += [_push(offered_hash), idx_item] + (tail or [])
    return _frame(pushes)


# --------------------------------------------------------------------------- frame reassembly


def test_radiant_core_verified_vector_frame_reassembly():
    # From docs/swap-order-wire-format.md (Radiant-Core feature_swap.py): two price-term pushes
    # 0102030405 + 060708090a + signature 04050607 → price_terms="0102030405060708090a", sig="04050607".
    order = decode_rswp_order(
        _v2_frame(
            tail=[
                _push(bytes.fromhex("0102030405")),
                _push(bytes.fromhex("060708090a")),
                _push(bytes.fromhex("04050607")),
            ]
        )
    )
    assert order.version == 2
    assert order.price_terms.hex() == "0102030405060708090a"
    assert order.signature.hex() == "04050607"
    assert order.demanded_outputs is None  # this synthetic blob isn't valid MultiTxOutV1


def test_want_token_id_present_iff_flag():
    want = b"\xbb" * 32
    with_want = decode_rswp_order(_v2_frame(flags=0x01, want=want, tail=[_push(b"pt"), _push(b"sig")]))
    assert with_want.flags == 0x01 and with_want.want_token_id == want
    without = decode_rswp_order(_v2_frame(flags=0x00, tail=[_push(b"pt"), _push(b"sig")]))
    assert without.want_token_id is None


def test_offered_utxo_index_opcode_and_scriptnum():
    # OP_0 → vout 0
    o0 = decode_rswp_order(_v2_frame(idx_item=_op_n(0), tail=[_push(b"pt"), _push(b"sig")]))
    assert o0.offered_utxo_index == 0
    # a CScriptNum push for a vout > 16 (e.g. 300 = 0x2c 0x01 LE)
    o300 = decode_rswp_order(_v2_frame(idx_item=_push(bytes.fromhex("2c01")), tail=[_push(b"pt"), _push(b"sig")]))
    assert o300.offered_utxo_index == 300


def test_offered_txid_and_rxd_flag():
    internal = bytes.fromhex("01" + "00" * 31)  # internal (little-endian); display txid = reversed
    o = decode_rswp_order(_v2_frame(offered_hash=internal, token_id=b"\x00" * 32, tail=[_push(b"pt"), _push(b"sig")]))
    assert o.offered_txid == internal[::-1].hex() == "00" * 31 + "01"
    assert o.offered_is_rxd is True


# --------------------------------------------------------------------------- price_terms (MultiTxOutV1)


def test_parse_multitxoutv1_single_output():
    script = bytes.fromhex("76a914" + "33" * 20 + "88ac")  # a P2PKH
    blob = b"\x01" + (1000).to_bytes(8, "little") + bytes([len(script)]) + script  # count=1
    outs = parse_price_terms(blob)
    assert outs == [DemandedOutput(value=1000, script=script)]


def test_decode_with_real_multitxoutv1_price_terms():
    script = bytes.fromhex("76a914" + "44" * 20 + "88ac")
    pt = b"\x01" + (50_000).to_bytes(8, "little") + bytes([len(script)]) + script
    order = decode_rswp_order(_v2_frame(tail=[_push(pt), _push(b"\x04\x05\x06\x07")]))
    assert order.demanded_outputs == [DemandedOutput(value=50_000, script=script)]


def test_lenient_fallback_for_non_multitxoutv1():
    # The Photonic bare fallback: value(8 LE) || script(rest).
    blob = (7).to_bytes(8, "little") + b"\xde\xad\xbe\xef"
    assert parse_price_terms(blob) is None  # not clean MultiTxOutV1
    lenient = parse_price_terms_lenient(blob)
    assert lenient == [DemandedOutput(value=7, script=b"\xde\xad\xbe\xef")]


# --------------------------------------------------------------------------- error cases


def test_rejects_non_op_return():
    with pytest.raises(ValidationError, match="OP_RETURN"):
        decode_rswp_order(bytes.fromhex("76a914" + "00" * 20 + "88ac"))


def test_rejects_missing_magic():
    with pytest.raises(ValidationError, match="magic"):
        decode_rswp_order(_frame([_push(b"XXXX"), _push(b"\x02")]))


def test_rejects_non_v2_version():
    with pytest.raises(ValidationError, match="version"):
        decode_rswp_order(_frame([_push(b"RSWP"), _push(b"\x01")]))


def test_rejects_short_tail():
    # Only one tail push (no separate signature) → must be >= 2.
    with pytest.raises(ValidationError, match="tail"):
        decode_rswp_order(_v2_frame(tail=[_push(b"onlyone")]))

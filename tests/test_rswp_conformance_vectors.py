"""Re-derive every published RSWP conformance vector byte-for-byte.

``conformance/rswp-order-vectors.json`` is the cross-implementation contract
(same shape as the dMint-v2 suite): if the encoder ever drifts from the
published hex, this fails CI — the JSON cannot silently rot. The reassembly
vector additionally locks the DECODER to the Radiant-Core tail rule.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pyrxd.glyph.types import GlyphRef
from pyrxd.security.types import Txid
from pyrxd.swap.rswp import (
    DemandedOutput,
    decode_rswp_order,
    encode_price_terms,
    encode_rswp_order,
    swap_token_id,
)

_VECTORS = json.loads((Path(__file__).parent.parent / "conformance" / "rswp-order-vectors.json").read_text())


def _ref(d: dict | None) -> GlyphRef | None:
    return None if d is None else GlyphRef(txid=Txid(d["txid"]), vout=int(d["vout"]))


def _price_terms(outputs: list[dict]) -> bytes:
    return encode_price_terms(
        [DemandedOutput(value=int(o["value"]), script=bytes.fromhex(o["script_hex"])) for o in outputs]
    )


def test_schema_marker() -> None:
    assert _VECTORS["schema"] == "radiant-rswp-order/1"


@pytest.mark.parametrize("vec", _VECTORS["token_id_vectors"], ids=lambda v: v["id"])
def test_token_id_vectors(vec: dict) -> None:
    assert swap_token_id(_ref(vec["ref"])).hex() == vec["token_id_display_hex"]


@pytest.mark.parametrize("vec", _VECTORS["price_terms_vectors"], ids=lambda v: v["id"])
def test_price_terms_vectors(vec: dict) -> None:
    assert _price_terms(vec["outputs"]).hex() == vec["price_terms_hex"]


@pytest.mark.parametrize("vec", _VECTORS["frame_vectors"], ids=lambda v: v["id"])
def test_frame_vectors_re_derive(vec: dict) -> None:
    p = vec["params"]
    script = encode_rswp_order(
        offered_type=int(p["offered_type"]),
        token_id=swap_token_id(_ref(p["token_ref"])),
        want_token_id=None if p["want_token_ref"] is None else swap_token_id(_ref(p["want_token_ref"])),
        offered_txid=p["offered_txid"],
        offered_vout=int(p["offered_vout"]),
        price_terms=_price_terms(p["price_terms_outputs"]),
        signature=bytes.fromhex(p["signature_hex"]),
        expiry_height=p["expiry_height"],
    )
    assert script.hex() == vec["advert_script_hex"]


@pytest.mark.parametrize("vec", _VECTORS["frame_vectors"], ids=lambda v: v["id"])
def test_frame_vectors_decode_back(vec: dict) -> None:
    """The published frames are also decodable — a second implementation can
    round-trip either direction against this file."""
    p = vec["params"]
    order = decode_rswp_order(bytes.fromhex(vec["advert_script_hex"]))
    assert order.version == (3 if p["expiry_height"] is not None else 2)
    assert order.expiry_height == p["expiry_height"]
    assert order.offered_txid == p["offered_txid"]
    assert order.offered_utxo_index == int(p["offered_vout"])
    assert order.signature.hex() == p["signature_hex"]
    assert order.price_terms == _price_terms(p["price_terms_outputs"])


def test_reassembly_vector_locks_decoder_tail_rule() -> None:
    vec = _VECTORS["reassembly_vector"]
    order = decode_rswp_order(bytes.fromhex(vec["frame_hex"]))
    assert order.price_terms.hex() == vec["expected"]["price_terms_hex"]
    assert order.signature.hex() == vec["expected"]["signature_hex"]


@pytest.mark.parametrize("vec", _VECTORS["covenant_vectors"]["vectors"], ids=lambda v: v["id"])
def test_covenant_vectors_re_derive_and_parse_back(vec: dict) -> None:
    from pyrxd.swap.rswp import build_refund_covenant_script, parse_refund_covenant

    spk = build_refund_covenant_script(bytes.fromhex(vec["owner_pkh_hex"]), int(vec["expiry_height"]))
    assert spk.hex() == vec["covenant_spk_hex"]
    inner, expiry = parse_refund_covenant(bytes.fromhex(vec["covenant_spk_hex"]))
    assert expiry == int(vec["expiry_height"])
    assert inner[3:23].hex() == vec["owner_pkh_hex"]


@pytest.mark.parametrize("vec", _VECTORS["mainnet_anchors"], ids=lambda v: v["id"])
def test_mainnet_anchor_decodes_to_the_recorded_rpc_row(vec: dict) -> None:
    """Byte-anchored live-mainnet vector (see ``vec["description"]``/``vec["queried_2026-07-05"]``
    for the full provenance trail): ``advert_script_hex`` is the raw on-chain RSWP advert located at
    ``vec["source"]`` (``mainnet:<txid>:<vout>``). This locks the decoder to that real advert AND
    cross-checks every field against the ``getswaphistory`` RPC row recorded alongside it — a second,
    independent implementation (the swapindex) parsed the same bytes and reported the same fields."""
    exp = vec["expected"]
    order = decode_rswp_order(bytes.fromhex(vec["advert_script_hex"]))

    assert order.version == exp["version"]
    assert order.flags == exp["flags"]
    assert order.offered_type == exp["offered_type"]
    assert order.terms_type == exp["terms_type"]
    assert order.token_id[::-1].hex() == exp["token_id_display_hex"]
    assert order.want_token_id is not None
    assert order.want_token_id[::-1].hex() == exp["want_token_id_display_hex"]
    assert order.offered_txid == exp["offered_txid"]
    assert order.offered_utxo_index == exp["offered_vout"]
    assert order.price_terms.hex() == exp["price_terms_hex"]
    assert order.signature.hex() == exp["signature_hex"]
    assert order.demanded_outputs is not None and len(order.demanded_outputs) == 1
    assert order.demanded_outputs[0].value == exp["demanded_output_value"]
    assert order.demanded_outputs[0].script.hex() == exp["demanded_output_script_hex"]

    # Cross-check against the raw swapindex RPC row recorded alongside the vector: the decoder's
    # output and the live node's own indexed row must agree field-for-field.
    row = vec["rpc_cross_check_row"]["row"]
    assert row["version"] == exp["version"]
    assert row["flags"] == exp["flags"]
    assert row["offered_type"] == exp["offered_type"]
    assert row["terms_type"] == exp["terms_type"]
    assert row["tokenid"] == exp["token_id_display_hex"]
    assert row["want_tokenid"] == exp["want_token_id_display_hex"]
    assert row["utxo"]["txid"] == exp["offered_txid"]
    assert row["utxo"]["vout"] == exp["offered_vout"]
    assert row["price_terms"] == exp["price_terms_hex"]
    assert row["signature"] == exp["signature_hex"]

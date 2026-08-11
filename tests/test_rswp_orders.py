"""RSWP order flows (post / take / cancel) — offline, pure-path, adversarial.

The take bridge is the trust boundary: everything an on-chain advertisement
*claims* must be re-verified against what the chain *holds*. Each security
invariant from the design note (docs/plans/2026-07-05-rswp-orderbook-design.md)
appears here as an explicit case.
"""

from __future__ import annotations

import pytest

from pyrxd.constants import SIGHASH
from pyrxd.glyph.script import build_ft_locking_script, extract_ref_from_ft_script, is_ft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.partial import _is_p2pkh
from pyrxd.swap.rswp import (
    RswpOrder,
    build_advert_tx,
    build_cancel_tx,
    create_rswp_order,
    decode_rswp_order,
    prepare_offered_utxo,
    rswp_order_to_swap_offer,
    swap_token_id,
    take_rswp_order,
    verify_offer_signature,
)
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

# These fixtures work in TOY photon values (hundreds or a few thousand, not the millions
# a real Radiant fee costs), so their fees sit far below the chain's relay floor by
# design: what they test is conservation arithmetic, signature binding and parsing, not
# fee sizing. Those builders now GATE `fee` against that floor, so the opt-out is stated
# here explicitly rather than left implicit. The floor itself is proven offline in
# tests/test_swap_and_nft_fee_floors.py and at a real node in
# tests/test_fee_floor_boundary_regtest_e2e.py.
_TOY_FEE_POLICY = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)


_REF_G = GlyphRef(txid=Txid("aa" * 32), vout=0)  # token the maker gives
_REF_R = GlyphRef(txid=Txid("bb" * 32), vout=1)  # token the maker wants


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()
    return k, k.public_key().hash160()


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_src(pkh: bytes, ref: GlyphRef, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), value))
    return tx


def _classify(out: TransactionOutput) -> tuple[str, int, GlyphRef | None]:
    s = out.locking_script.serialize()
    if is_ft_script(s.hex()):
        return ("ft", out.satoshis, extract_ref_from_ft_script(s))
    assert _is_p2pkh(s)
    return ("rxd", out.satoshis, None)


def _post_and_decode(give_source_tx, maker_key, receive, maker_pkh):
    """Maker posts; the advert travels the chain as bytes; a taker decodes it fresh."""
    post = create_rswp_order(
        give_source_tx=give_source_tx,
        give_vout=0,
        maker_key=maker_key,
        receive=receive,
        maker_receive_pkh=maker_pkh,
    )
    return post, decode_rswp_order(post.advert_script)


# ─────────────────────────────── happy paths ─────────────────────────────────


def test_post_take_rxd_for_ft_full_loop() -> None:
    """Maker offers 1000 RXD, demands 50 FT — through the ADVERT bytes, not the envelope."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _post, order = _post_and_decode(src, mk, Asset("ft", 50, _REF_R), mk_pkh)

    assert order.offered_is_rxd and order.want_token_id == swap_token_id(_REF_R)[::-1]
    assert order.offered_txid == src.txid() and order.offered_utxo_index == 0

    tx = take_rswp_order(
        order,
        give_source_tx=src,
        funding=[FundingInput(_ft_src(tk_pkh, _REF_R, 60), 0, tk), FundingInput(_rxd_src(tk_pkh, 5000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
        fee_policy=_TOY_FEE_POLICY,
    )
    assert _classify(tx.outputs[0]) == ("ft", 50, _REF_R)  # maker's demand, index 0 (SINGLE)
    assert _classify(tx.outputs[1]) == ("rxd", 1000, None)  # taker receives the offered RXD
    kinds = [_classify(o) for o in tx.outputs]
    assert ("ft", 10, _REF_R) in kinds  # taker FT change
    assert all(i.unlocking_script is not None for i in tx.inputs)  # broadcast-ready


def test_post_take_ft_for_rxd_full_loop() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _ft_src(mk_pkh, _REF_G, 777)
    _post, order = _post_and_decode(src, mk, Asset("rxd", 900), mk_pkh)

    assert order.token_id == swap_token_id(_REF_G)[::-1]
    assert order.want_token_id is None and order.flags == 0  # RXD want side: field omitted

    tx = take_rswp_order(
        order,
        give_source_tx=src,
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=200,
        fee_policy=_TOY_FEE_POLICY,
    )
    assert _classify(tx.outputs[0]) == ("rxd", 900, None)
    assert _classify(tx.outputs[1]) == ("ft", 777, _REF_G)


def test_bridge_offer_equals_private_envelope() -> None:
    """The advert round-trip reconstructs byte-identical partial/source hex to the
    maker's own envelope — the bridge adds no drift."""
    mk, mk_pkh = _key()
    src = _ft_src(mk_pkh, _REF_G, 500)
    post, order = _post_and_decode(src, mk, Asset("rxd", 400), mk_pkh)
    bridged = rswp_order_to_swap_offer(order, give_source_tx=src)
    assert bridged == post.offer


def test_verify_offer_signature_accepts_fresh_offer() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _post, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    verify_offer_signature(rswp_order_to_swap_offer(order, give_source_tx=src))  # does not raise


def test_prepare_offered_utxo_mints_exact_amount_at_vout0() -> None:
    mk, mk_pkh = _key()
    funding = [FundingInput(_ft_src(mk_pkh, _REF_G, 120), 0, mk), FundingInput(_rxd_src(mk_pkh, 3000), 0, mk)]
    tx = prepare_offered_utxo(
        funding=funding, asset=Asset("ft", 100, _REF_G), owner_pkh=mk_pkh, change_pkh=mk_pkh, fee=200
    )
    assert _classify(tx.outputs[0]) == ("ft", 100, _REF_G)
    kinds = [_classify(o) for o in tx.outputs]
    assert ("ft", 20, _REF_G) in kinds  # token change conserved
    # and the minted UTXO is immediately offerable:
    create_rswp_order(give_source_tx=tx, give_vout=0, maker_key=mk, receive=Asset("rxd", 500), maker_receive_pkh=mk_pkh)


def test_build_advert_tx_wraps_script_at_output0_value0() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    post, _ = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    tx = build_advert_tx(
        advert_script=post.advert_script,
        funding=[FundingInput(_rxd_src(mk_pkh, 2000), 0, mk)],
        change_pkh=mk_pkh,
        fee=400,
    )
    assert tx.outputs[0].satoshis == 0
    assert tx.outputs[0].locking_script.serialize() == post.advert_script
    assert decode_rswp_order(tx.outputs[0].locking_script.serialize()).offered_txid == src.txid()
    assert _classify(tx.outputs[1]) == ("rxd", 1600, None)  # change


# Cancel fees that actually clear Radiant's relay floor for the shape being built.
# MEASURED over 150 builds with fresh keys (DER signatures are 69-71 bytes, so the size
# varies run to run): the RXD cancel is 190-192 B (floor <= 1,920,000 photons) and the
# FT-with-funding cancel is 421-424 B (floor <= 4,240,000). The old fixtures paid 200 and
# 300 photons — roughly 10,000x under — and asserted the result was fine, which is why
# nothing offline caught the missing guard: they described a chain state that cannot exist.
_CANCEL_FEE_RXD = 2_500_000
_CANCEL_FEE_FT = 5_000_000


def test_cancel_rxd_offer_returns_value_to_maker() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 10_000_000)
    tx = build_cancel_tx(offered_source_tx=src, offered_vout=0, maker_key=mk, refund_pkh=mk_pkh, fee=_CANCEL_FEE_RXD)
    assert _classify(tx.outputs[0]) == ("rxd", 10_000_000 - _CANCEL_FEE_RXD, None)


def test_cancel_ft_offer_conserves_token_with_rxd_fee_funding() -> None:
    mk, mk_pkh = _key()
    src = _ft_src(mk_pkh, _REF_G, 100)
    tx = build_cancel_tx(
        offered_source_tx=src,
        offered_vout=0,
        maker_key=mk,
        refund_pkh=mk_pkh,
        fee=_CANCEL_FEE_FT,
        funding=[FundingInput(_rxd_src(mk_pkh, 10_000_000), 0, mk)],
    )
    kinds = [_classify(o) for o in tx.outputs]
    assert ("ft", 100, _REF_G) in kinds  # full token amount back — conservation
    assert ("rxd", 10_000_000 - _CANCEL_FEE_FT, None) in kinds


# ─────────────────────────────── adversarial ─────────────────────────────────


def _order_with(order: RswpOrder, **overrides) -> RswpOrder:
    fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
    fields.update(overrides)
    return RswpOrder(**fields)


def test_tampered_demanded_value_breaks_maker_signature() -> None:
    """Invariant 1: inflating the maker's demand in the advert invalidates the sig."""
    from pyrxd.gravity.swap_order import DemandedOutput
    from pyrxd.swap.rswp import encode_price_terms

    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    inflated = [DemandedOutput(value=6000, script=order.demanded_outputs[0].script)]
    tampered = _order_with(order, price_terms=encode_price_terms(inflated), demanded_outputs=inflated)
    with pytest.raises(ValidationError, match="signature does not validate"):
        take_rswp_order(
            tampered,
            give_source_tx=src,
            funding=[FundingInput(_rxd_src(tk_pkh, 9000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )


def test_sighash_flag_0xc2_rejected() -> None:
    """Invariant 6 (security F1): NONE|ANYONECANPAY|FORKID verifies pre- AND
    post-completion while binding no outputs — must be refused outright."""
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)

    # Forge a maker partial signed 0xC2 and advertise it.
    from pyrxd.transaction.transaction_input import TransactionInput

    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=src,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(mk),
            sighash=SIGHASH.NONE_ANYONECANPAY_FORKID,
        )
    )
    tx.add_output(TransactionOutput(P2PKH().lock(mk_pkh), 600))
    tx.sign(bypass=True)
    signature = tx.inputs[0].unlocking_script.serialize()
    assert signature not in (None, b"")

    from pyrxd.gravity.swap_order import DemandedOutput
    from pyrxd.swap.rswp import encode_price_terms, encode_rswp_order

    advert = encode_rswp_order(
        offered_type=0,
        token_id=swap_token_id(None),
        want_token_id=None,
        offered_txid=src.txid(),
        offered_vout=0,
        price_terms=encode_price_terms([DemandedOutput(value=600, script=P2PKH().lock(mk_pkh).serialize())]),
        signature=signature,
    )
    order = decode_rswp_order(advert)
    with pytest.raises(ValidationError, match="sighash"):
        rswp_order_to_swap_offer(order, give_source_tx=src)


def test_lying_token_id_rejected() -> None:
    """Invariant 7: advert claims an FT token id, UTXO actually holds a different token."""
    mk, mk_pkh = _key()
    src = _ft_src(mk_pkh, _REF_G, 500)
    _, order = _post_and_decode(src, mk, Asset("rxd", 400), mk_pkh)
    lying = _order_with(order, token_id=swap_token_id(_REF_R)[::-1])
    with pytest.raises(ValidationError, match="token_id does not match"):
        rswp_order_to_swap_offer(lying, give_source_tx=src)


def test_lying_want_token_id_rejected() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("ft", 50, _REF_R), mk_pkh)
    lying = _order_with(order, want_token_id=swap_token_id(_REF_G)[::-1])
    with pytest.raises(ValidationError, match="want_token_id does not match"):
        rswp_order_to_swap_offer(lying, give_source_tx=src)


def test_lying_offered_type_rejected() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    lying = _order_with(order, offered_type=2)  # claims FT, holds RXD
    with pytest.raises(ValidationError, match="offeredType does not match"):
        rswp_order_to_swap_offer(lying, give_source_tx=src)


def test_multi_output_demand_refused() -> None:
    """Invariant 4: SINGLE signs only output[0]; extra demands are unenforceable."""
    from pyrxd.gravity.swap_order import DemandedOutput
    from pyrxd.swap.rswp import encode_price_terms

    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    two = [order.demanded_outputs[0], DemandedOutput(value=1, script=P2PKH().lock(mk_pkh).serialize())]
    doubled = _order_with(order, price_terms=encode_price_terms(two), demanded_outputs=two)
    with pytest.raises(ValidationError, match="exactly one"):
        rswp_order_to_swap_offer(doubled, give_source_tx=src)


def test_wrong_source_tx_rejected() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    other = _rxd_src(mk_pkh, 999_999)
    with pytest.raises(ValidationError, match="does not hash to the advertised"):
        rswp_order_to_swap_offer(order, give_source_tx=other)


def test_negative_and_out_of_range_vout_rejected() -> None:
    """Invariant 9 (security F7): a hostile CScriptNum vout must fail as a clean
    ValidationError before any TransactionInput is constructed."""
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    for hostile in (-1, 1, 2**33):
        bad = _order_with(order, offered_utxo_index=hostile)
        with pytest.raises(ValidationError, match="not present in give_source_tx"):
            rswp_order_to_swap_offer(bad, give_source_tx=src)


def test_unfundable_demand_value_rejected() -> None:
    """Invariant 8 (security F6): a demand above MAX_MONEY is never 'fillable'."""
    from pyrxd.gravity.swap_order import DemandedOutput

    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    huge = [DemandedOutput(value=2**64 - 1, script=order.demanded_outputs[0].script)]
    bad = _order_with(order, price_terms=b"\x01" + (2**64 - 1).to_bytes(8, "little"), demanded_outputs=huge)
    with pytest.raises(ValidationError, match="outside the fundable range"):
        rswp_order_to_swap_offer(bad, give_source_tx=src)


def test_v3_expiry_order_refused_for_take() -> None:
    """v3 orders sit in a refund covenant this module cannot spend (design D13)."""
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    v3 = _order_with(order, version=3, flags=order.flags | 0x02, expiry_height=1000)
    with pytest.raises(ValidationError, match="not yet takeable"):
        rswp_order_to_swap_offer(v3, give_source_tx=src)


def test_demanded_op_return_script_rejected() -> None:
    """A demanded output that is not a spendable P2PKH/FT script (e.g. OP_RETURN)
    cannot be classified — refused rather than blindly paid."""
    from pyrxd.gravity.swap_order import DemandedOutput
    from pyrxd.swap.rswp import encode_price_terms

    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    _, order = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    weird = [DemandedOutput(value=600, script=b"\x6a\x04test")]
    bad = _order_with(order, price_terms=encode_price_terms(weird), demanded_outputs=weird)
    with pytest.raises(ValidationError, match="unsupported asset"):
        rswp_order_to_swap_offer(bad, give_source_tx=src)


def test_advert_tx_refuses_ft_funding() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    post, _ = _post_and_decode(src, mk, Asset("rxd", 600), mk_pkh)
    with pytest.raises(ValidationError, match="plain RXD"):
        build_advert_tx(
            advert_script=post.advert_script,
            funding=[FundingInput(_ft_src(mk_pkh, _REF_G, 100), 0, mk)],
            change_pkh=mk_pkh,
            fee=50,
        )

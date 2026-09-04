"""RSWP v3 refund covenant — bytes, parsing, and the full offline flow.

Byte layout mirrors Photonic ``swapRefundCovenant.ts`` (wallet-side
regtest-proven): ``63 <inner> 67 <expiryPush> b1 75 <inner> 68``, selectors
``OP_1``/``OP_0`` appended after ``<sig> <pubkey>``. The consensus proof for
pyrxd's builders lives in ``tests/test_rswp_v3_regtest_e2e.py``.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Txid
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import (
    RswpOrder,
    build_covenant_cancel_tx,
    build_covenant_refund_tx,
    build_refund_covenant_script,
    create_covenant_order,
    decode_rswp_order,
    is_refund_covenant,
    parse_refund_covenant,
    prepare_covenant_offer,
    take_covenant_order,
)
from pyrxd.swap.rswp.covenant import (
    LOCKTIME_HEIGHT_THRESHOLD,
    REFUND_SEQUENCE,
    encode_expiry_height,
    is_expired,
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


_EXPIRY = 840_000


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()
    return k, k.public_key().hash160()


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _reserved(maker: PrivateKey, photons: int = 10_000, expiry: int = _EXPIRY) -> Transaction:
    """A funded covenant reservation at vout 0 (offline)."""
    pkh = maker.public_key().hash160()
    return prepare_covenant_offer(
        funding=[FundingInput(_rxd_src(pkh, photons + 5_000), 0, maker)],
        photons=photons,
        owner_pkh=pkh,
        expiry_height=expiry,
        change_pkh=pkh,
        fee=1_000,
        fee_policy=_TOY_FEE_POLICY,
    )


# --------------------------------------------------------------------------- expiry encoding


@pytest.mark.parametrize(
    ("height", "expected"),
    [(1, "01"), (127, "7f"), (128, "8000"), (0x8000, "008000"), (840_000, "40d10c"), (499_999_999, "ff64cd1d")],
)
def test_expiry_height_minimal_scriptnum(height: int, expected: str) -> None:
    assert encode_expiry_height(height).hex() == expected


@pytest.mark.parametrize("bad", [0, -1, LOCKTIME_HEIGHT_THRESHOLD, LOCKTIME_HEIGHT_THRESHOLD + 5])
def test_expiry_height_rejects_non_heights(bad: int) -> None:
    with pytest.raises(ValidationError):
        encode_expiry_height(bad)


def test_expiry_boundary_is_tip_gte_expiry() -> None:
    assert not is_expired(_EXPIRY, _EXPIRY - 1)
    assert is_expired(_EXPIRY, _EXPIRY)  # filled-iff height < expiry (Photonic D12)
    assert is_expired(_EXPIRY, _EXPIRY + 1)


# --------------------------------------------------------------------------- script build/parse


def test_covenant_layout_bytes() -> None:
    _, pkh = _key()
    spk = build_refund_covenant_script(pkh, _EXPIRY)
    inner = P2PKH().lock(pkh).serialize()
    assert spk == b"\x63" + inner + b"\x67" + bytes([3]) + bytes.fromhex("40d10c") + b"\xb1\x75" + inner + b"\x68"


def test_parse_round_trip() -> None:
    _, pkh = _key()
    spk = build_refund_covenant_script(pkh, _EXPIRY)
    inner, expiry = parse_refund_covenant(spk)
    assert inner == P2PKH().lock(pkh).serialize() and expiry == _EXPIRY


@given(height=st.integers(min_value=1, max_value=LOCKTIME_HEIGHT_THRESHOLD - 1))
def test_parse_round_trip_all_heights(height: int) -> None:
    _, pkh = PrivateKey(), b"\x11" * 20
    spk = build_refund_covenant_script(pkh, height)
    assert parse_refund_covenant(spk) == (P2PKH().lock(pkh).serialize(), height)


def test_tampered_covenant_with_differing_branches_rejected() -> None:
    """A covenant whose two inner branches differ is NOT a swap-refund covenant —
    a maker could otherwise put their key in the refund arm and someone else's
    in the swap arm while displaying as a normal reservation."""
    _, pkh_a = _key()
    _, pkh_b = _key()
    inner_a = P2PKH().lock(pkh_a).serialize()
    inner_b = P2PKH().lock(pkh_b).serialize()
    expiry = encode_expiry_height(_EXPIRY)
    forged = b"\x63" + inner_a + b"\x67" + bytes([len(expiry)]) + expiry + b"\xb1\x75" + inner_b + b"\x68"
    assert parse_refund_covenant(forged) is None


def test_non_minimal_expiry_push_rejected() -> None:
    _, pkh = _key()
    inner = P2PKH().lock(pkh).serialize()
    padded = (127).to_bytes(2, "little")  # 0x7f 0x00 — non-minimal
    forged = b"\x63" + inner + b"\x67" + bytes([len(padded)]) + padded + b"\xb1\x75" + inner + b"\x68"
    assert parse_refund_covenant(forged) is None


@pytest.mark.parametrize("spk", [b"", b"\x51", b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"])
def test_non_covenant_scripts_are_not_covenants(spk: bytes) -> None:
    assert not is_refund_covenant(spk)


# --------------------------------------------------------------------------- full offline v3 loop


def test_reserve_post_take_full_loop() -> None:
    maker, mk_pkh = _key()
    taker, tk_pkh = _key()
    reserved = _reserved(maker)  # 10_000 photons in the covenant at vout 0

    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)
    assert order.version == 3 and order.expiry_height == _EXPIRY

    tx = take_covenant_order(
        order,
        give_source_tx=reserved,
        funding=[FundingInput(_rxd_src(tk_pkh, 20_000), 0, taker)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=1_000,
        fee_policy=_TOY_FEE_POLICY,
        current_height=_EXPIRY - 10,
    )
    assert tx.outputs[0].satoshis == 9_000  # maker demand at index 0 (SINGLE)
    assert tx.outputs[1].satoshis == 10_000  # taker receives the reserved RXD
    assert tx.inputs[0].unlocking_script.serialize().endswith(b"\x51")  # SWAP selector
    assert all(i.unlocking_script is not None for i in tx.inputs)


def test_take_refused_at_and_after_expiry() -> None:
    maker, mk_pkh = _key()
    taker, tk_pkh = _key()
    reserved = _reserved(maker)
    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)
    for tip in (_EXPIRY, _EXPIRY + 100):
        with pytest.raises(ValidationError, match="expired"):
            take_covenant_order(
                order,
                give_source_tx=reserved,
                funding=[FundingInput(_rxd_src(tk_pkh, 20_000), 0, taker)],
                taker_receive_pkh=tk_pkh,
                taker_change_pkh=tk_pkh,
                fee=1_000,
                fee_policy=_TOY_FEE_POLICY,
                current_height=tip,
            )


def test_tampered_demand_breaks_covenant_order_signature() -> None:
    maker, mk_pkh = _key()
    taker, tk_pkh = _key()
    reserved = _reserved(maker)
    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)
    from pyrxd.gravity.swap_order import DemandedOutput
    from pyrxd.swap.rswp import encode_price_terms

    inflated = [DemandedOutput(value=90_000, script=order.demanded_outputs[0].script)]
    fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
    fields.update(price_terms=encode_price_terms(inflated), demanded_outputs=inflated)
    with pytest.raises(ValidationError, match="signature does NOT validate"):
        take_covenant_order(
            RswpOrder(**fields),
            give_source_tx=reserved,
            funding=[FundingInput(_rxd_src(tk_pkh, 200_000), 0, taker)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=1_000,
            fee_policy=_TOY_FEE_POLICY,
            current_height=_EXPIRY - 10,
        )


def test_advertised_expiry_must_match_the_chain() -> None:
    """A lying advert cannot shorten/lengthen the on-chain expiry."""
    maker, mk_pkh = _key()
    taker, tk_pkh = _key()
    reserved = _reserved(maker)
    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)
    fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
    fields["expiry_height"] = _EXPIRY + 1_000  # advert lies: claims a later expiry
    with pytest.raises(ValidationError, match="does not match the covenant"):
        take_covenant_order(
            RswpOrder(**fields),
            give_source_tx=reserved,
            funding=[FundingInput(_rxd_src(tk_pkh, 20_000), 0, taker)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=1_000,
            fee_policy=_TOY_FEE_POLICY,
            current_height=_EXPIRY - 10,
        )


def test_lying_v3_metadata_rejected() -> None:
    """Red-team L1: the v3 take enforces the same advertised-metadata-vs-reality
    checks as the v2 bridge (token_id / offeredType / want_token_id / bounds)."""
    maker, mk_pkh = _key()
    taker, tk_pkh = _key()
    reserved = _reserved(maker)
    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)

    def _take(mutated: RswpOrder, tip: int = _EXPIRY - 10) -> None:
        take_covenant_order(
            mutated,
            give_source_tx=reserved,
            funding=[FundingInput(_rxd_src(tk_pkh, 20_000), 0, taker)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=1_000,
            fee_policy=_TOY_FEE_POLICY,
            current_height=tip,
        )

    def _mutate(**overrides) -> RswpOrder:
        fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
        fields.update(overrides)
        return RswpOrder(**fields)

    from pyrxd.swap.rswp import swap_token_id

    other_ref = GlyphRef(txid=Txid("ef" * 32), vout=3)
    with pytest.raises(ValidationError, match="token_id must be all-zero"):
        _take(_mutate(token_id=swap_token_id(other_ref)[::-1]))
    with pytest.raises(ValidationError, match="offeredType"):
        _take(_mutate(offered_type=2))
    with pytest.raises(ValidationError, match="want_token_id does not match"):
        _take(_mutate(want_token_id=swap_token_id(other_ref)[::-1], flags=order.flags | 0x01))
    with pytest.raises(ValidationError, match="fee must be non-negative"):
        take_covenant_order(
            order,
            give_source_tx=reserved,
            funding=[FundingInput(_rxd_src(tk_pkh, 20_000), 0, taker)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=-1,
            fee_policy=_TOY_FEE_POLICY,
            current_height=_EXPIRY - 10,
        )


def test_negative_fee_refused_on_refund_and_cancel() -> None:
    """Red-team L3: a negative fee would build a money-creating, consensus-invalid tx."""
    maker, mk_pkh = _key()
    reserved = _reserved(maker)
    for builder in (build_covenant_refund_tx, build_covenant_cancel_tx):
        with pytest.raises(ValidationError, match="non-negative"):
            builder(covenant_source_tx=reserved, covenant_vout=0, maker_key=maker, refund_pkh=mk_pkh, fee=-5)


def test_near_p2pkh_funding_refused() -> None:
    """Red-team L2: a 25-byte near-P2PKH funding script (wrong suffix) must be
    refused up front, not fail at consensus after signing."""
    maker, mk_pkh = _key()
    fake = Transaction()
    fake.add_output(TransactionOutput(Script(b"\x76\xa9\x14" + b"\x11" * 20 + b"\x87\xac"), 20_000))
    with pytest.raises(ValidationError, match="plain P2PKH"):
        prepare_covenant_offer(
            funding=[FundingInput(fake, 0, maker)],
            photons=10_000,
            owner_pkh=mk_pkh,
            expiry_height=_EXPIRY,
            change_pkh=mk_pkh,
            fee=1_000,
            fee_policy=_TOY_FEE_POLICY,
        )


def test_create_order_requires_inner_ownership() -> None:
    maker, _ = _key()
    other, other_pkh = _key()
    reserved = _reserved(maker)
    with pytest.raises(ValidationError, match="does not own"):
        create_covenant_order(
            covenant_source_tx=reserved,
            covenant_vout=0,
            maker_key=other,
            receive=Asset("rxd", 9_000),
            maker_receive_pkh=other_pkh,
        )


# --------------------------------------------------------------------------- refund / cancel builders


def test_refund_tx_shape() -> None:
    maker, mk_pkh = _key()
    reserved = _reserved(maker)
    tx = build_covenant_refund_tx(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        refund_pkh=mk_pkh,
        fee=1_000,
        fee_policy=_TOY_FEE_POLICY,
    )
    assert tx.locktime == _EXPIRY
    assert tx.inputs[0].sequence == REFUND_SEQUENCE
    assert tx.inputs[0].unlocking_script.serialize().endswith(b"\x00")  # REFUND selector
    assert tx.outputs[0].satoshis == 9_000


def test_cancel_tx_shape() -> None:
    maker, mk_pkh = _key()
    reserved = _reserved(maker)
    tx = build_covenant_cancel_tx(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        refund_pkh=mk_pkh,
        fee=1_000,
        fee_policy=_TOY_FEE_POLICY,
    )
    assert tx.locktime == 0  # swap branch: no timelock
    assert tx.inputs[0].unlocking_script.serialize().endswith(b"\x51")  # SWAP selector
    assert tx.outputs[0].satoshis == 9_000


def test_v2_bridge_still_refuses_covenant_gives() -> None:
    """No shared-code seam was added: a covenant UTXO advertised WITHOUT expiry
    (a v2-disguised reservation) still fails the v2 bridge's classification."""
    from pyrxd.swap.rswp import rswp_order_to_swap_offer

    maker, mk_pkh = _key()
    reserved = _reserved(maker)
    post = create_covenant_order(
        covenant_source_tx=reserved,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    order = decode_rswp_order(post.advert_script)
    fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
    fields.update(version=2, flags=order.flags & ~0x02, expiry_height=None)
    with pytest.raises(ValidationError, match="unsupported asset"):
        rswp_order_to_swap_offer(RswpOrder(**fields), give_source_tx=reserved)


def test_ft_inner_refused_everywhere() -> None:
    """FT-in-covenant is consensus-blocked (FT codeScript epilogue) — the RXD-only
    restriction must hold at parse level for the flow builders."""
    from pyrxd.glyph.script import build_ft_locking_script
    from pyrxd.security.types import Hex20
    from pyrxd.swap.rswp.covenant import _inner_p2pkh_pkh

    _, pkh = _key()
    ref = GlyphRef(txid=Txid("ab" * 32), vout=0)
    inner = (
        bytes.fromhex(build_ft_locking_script(Hex20(pkh), ref))
        if isinstance(build_ft_locking_script(Hex20(pkh), ref), str)
        else build_ft_locking_script(Hex20(pkh), ref)
    )
    inner_bytes = inner if isinstance(inner, bytes) else bytes.fromhex(inner)
    expiry = encode_expiry_height(_EXPIRY)
    spk = b"\x63" + inner_bytes + b"\x67" + bytes([len(expiry)]) + expiry + b"\xb1\x75" + inner_bytes + b"\x68"
    assert parse_refund_covenant(spk) is not None  # structurally valid covenant…
    with pytest.raises(ValidationError, match="not P2PKH"):
        _inner_p2pkh_pkh(spk)  # …but the RXD-only gate refuses it


def test_reservation_too_small_to_fund_its_own_refund_is_refused() -> None:
    """Audit F3: a reservation the maker could not later refund.

    This asserted `match="below the dust floor"`, and the guard was sized to dust
    alone — 546 photons — while a refund pays its fee out of the covenant value and
    needs the relay floor for its own size PLUS dust. Everything from 546 up to
    ~2,000,000 was accepted and then unrefundable at any fee, under a CLI screen
    promising "Reclaim at --expiry is GUARANTEED". The message changed with the
    guard; 100 photons is still refused, now for the reason that was always meant.
    """
    maker, mk_pkh = _key()
    with pytest.raises(ValidationError, match="cannot fund its own refund"):
        prepare_covenant_offer(
            funding=[FundingInput(_rxd_src(mk_pkh, 10_000), 0, maker)],
            photons=100,  # < 546
            owner_pkh=mk_pkh,
            expiry_height=_EXPIRY,
            change_pkh=mk_pkh,
            fee=1_000,
            fee_policy=_TOY_FEE_POLICY,
        )

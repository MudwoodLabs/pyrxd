"""FT-demand fills in the v3 covenant take — per-ref conservation, offline.

The reserved side is RXD-only (consensus); the DEMAND side may be a Glyph FT.
Conservation is single-ref by construction (D6: exactly one demanded output):
FT-in of the demanded ref covers the demand, surplus returns as FT change,
and any other token in the funding is refused rather than burned/stranded.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script, is_ft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import create_covenant_order, decode_rswp_order, prepare_covenant_offer, take_covenant_order
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_EXPIRY = 840_000
_FT_REF = GlyphRef(txid=Txid("dd" * 32), vout=0)
_OTHER_REF = GlyphRef(txid=Txid("ee" * 32), vout=1)


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


def _posted_ft_demand(maker: PrivateKey, *, reserved: int = 10_000, demand_ft: int = 50):
    pkh = maker.public_key().hash160()
    reservation = prepare_covenant_offer(
        funding=[FundingInput(_rxd_src(pkh, reserved + 5_000), 0, maker)],
        photons=reserved,
        owner_pkh=pkh,
        expiry_height=_EXPIRY,
        change_pkh=pkh,
        fee=1_000,
    )
    post = create_covenant_order(
        covenant_source_tx=reservation,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("ft", demand_ft, _FT_REF),
        maker_receive_pkh=pkh,
    )
    return reservation, decode_rswp_order(post.advert_script)


def _take(order, reservation, taker, funding, fee=1_000, tip=_EXPIRY - 10):
    tk_pkh = taker.public_key().hash160()
    return take_covenant_order(
        order,
        give_source_tx=reservation,
        funding=funding,
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=fee,
        current_height=tip,
    )


def test_ft_demand_fill_with_exact_funding() -> None:
    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)
    assert order.version == 3 and order.want_token_id is not None

    tx = _take(
        order,
        reservation,
        taker,
        [FundingInput(_ft_src(tk_pkh, _FT_REF, 50), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)],
    )
    out0 = tx.outputs[0].locking_script.serialize()
    assert is_ft_script(out0.hex()) and tx.outputs[0].satoshis == 50  # maker's FT demand at index 0
    assert tx.outputs[1].satoshis == 10_000  # taker receives the reserved RXD
    assert tx.inputs[0].unlocking_script.serialize().endswith(b"\x51")
    # conservation: no FT change output for exact funding
    assert sum(1 for o in tx.outputs if is_ft_script(o.locking_script.serialize().hex())) == 1


def test_ft_demand_surplus_returns_as_ft_change() -> None:
    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)

    # Fund with a surplus that clears the dust floor (a sub-dust FT change is un-relayable and now raises —
    # see test_ft_demand_sub_dust_surplus_rejected): 600 funded, 50 demanded -> 550 change (>= 546).
    tx = _take(
        order,
        reservation,
        taker,
        [FundingInput(_ft_src(tk_pkh, _FT_REF, 600), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)],
    )
    ft_outs = [o for o in tx.outputs if is_ft_script(o.locking_script.serialize().hex())]
    assert [o.satoshis for o in ft_outs] == [50, 550]  # demand + change, conserved exactly
    total_in = 10_000 + 600 + 5_000
    assert total_in - sum(o.satoshis for o in tx.outputs) == 1_000  # fee exact


def test_ft_demand_sub_dust_surplus_rejected() -> None:
    """RM-8: an FT change surplus below the dust floor would make an un-relayable (opaquely-failing) take —
    refuse with a clear error instead (folding to fee would burn tokens)."""
    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)  # demand = 50 FT
    with pytest.raises(ValidationError, match="dust"):
        _take(
            order,
            reservation,
            taker,
            [FundingInput(_ft_src(tk_pkh, _FT_REF, 80), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)],
        )


def test_covenant_order_nft_demand_rejected() -> None:
    """RH-2 (audit HIGH): an nft demand would silently degrade to a dust P2PKH output that create_covenant_order
    then signs as the price — the reserved RXD becomes spendable for dust and the maker loses it. Refuse it."""
    maker, pkh = _key()
    reservation = prepare_covenant_offer(
        funding=[FundingInput(_rxd_src(pkh, 15_000), 0, maker)],
        photons=10_000,
        owner_pkh=pkh,
        expiry_height=_EXPIRY,
        change_pkh=pkh,
        fee=1_000,
    )
    with pytest.raises(ValidationError, match="nft"):
        create_covenant_order(
            covenant_source_tx=reservation,
            covenant_vout=0,
            maker_key=maker,
            receive=Asset("nft", 600, _FT_REF),
            maker_receive_pkh=pkh,
        )


def test_ft_underfunding_refused() -> None:
    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)
    with pytest.raises(ValidationError, match="lacks 20 units of the demanded FT"):
        _take(
            order,
            reservation,
            taker,
            [FundingInput(_ft_src(tk_pkh, _FT_REF, 30), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)],
        )


def test_wrong_ref_ft_funding_refused() -> None:
    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)
    with pytest.raises(ValidationError, match="burned or stranded"):
        _take(
            order,
            reservation,
            taker,
            [FundingInput(_ft_src(tk_pkh, _OTHER_REF, 80), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)],
        )


def test_nft_funding_refused() -> None:
    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)
    nft = Transaction()
    nft.add_output(TransactionOutput(Script(build_nft_locking_script(Hex20(tk_pkh), _OTHER_REF)), 600))
    # Pre-NFT-support main refuses via _asset_of ("unsupported asset"); once the
    # NFT branch lands, the same input hits the explicit funding guard instead.
    with pytest.raises(ValidationError, match="burned or stranded|unsupported asset"):
        _take(
            order,
            reservation,
            taker,
            [
                nft and FundingInput(nft, 0, taker),
                FundingInput(_ft_src(tk_pkh, _FT_REF, 50), 0, taker),
                FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker),
            ],
        )


def test_rxd_demand_path_unchanged() -> None:
    """The original RXD-demand fill still works byte-for-byte semantics."""
    maker, mk_pkh = _key()
    taker, tk_pkh = _key()
    reservation = prepare_covenant_offer(
        funding=[FundingInput(_rxd_src(mk_pkh, 15_000), 0, maker)],
        photons=10_000,
        owner_pkh=mk_pkh,
        expiry_height=_EXPIRY,
        change_pkh=mk_pkh,
        fee=1_000,
    )
    post = create_covenant_order(
        covenant_source_tx=reservation,
        covenant_vout=0,
        maker_key=maker,
        receive=Asset("rxd", 9_000),
        maker_receive_pkh=mk_pkh,
    )
    tx = _take(
        decode_rswp_order(post.advert_script), reservation, taker, [FundingInput(_rxd_src(tk_pkh, 20_000), 0, taker)]
    )
    assert tx.outputs[0].satoshis == 9_000 and tx.outputs[1].satoshis == 10_000


def test_tampered_ft_demand_amount_breaks_signature() -> None:
    from pyrxd.gravity.swap_order import DemandedOutput, RswpOrder
    from pyrxd.swap.rswp import encode_price_terms

    maker, _ = _key()
    taker, tk_pkh = _key()
    reservation, order = _posted_ft_demand(maker)
    deflated = [DemandedOutput(value=1, script=order.demanded_outputs[0].script)]
    fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
    fields.update(price_terms=encode_price_terms(deflated), demanded_outputs=deflated)
    with pytest.raises(ValidationError, match="signature does NOT validate"):
        _take(
            RswpOrder(**fields),
            reservation,
            taker,
            [FundingInput(_ft_src(tk_pkh, _FT_REF, 50), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)],
        )


def test_tampered_ft_demand_script_breaks_signature() -> None:
    """Red-team hunt 3 hardening: tamper the demanded SCRIPT (ref and owner),
    keeping the advert metadata CONSISTENT so only the signature can object —
    SINGLE's hash_outputs + Radiant's hashOutputHashes both bind the script."""
    from pyrxd.gravity.swap_order import DemandedOutput, RswpOrder
    from pyrxd.swap.rswp import encode_price_terms, swap_token_id

    maker, _ = _key()
    taker, tk_pkh = _key()
    _, attacker_pkh = _key()
    reservation, order = _posted_ft_demand(maker)

    def _mutate_with(script: bytes, want_id: bytes | None) -> RswpOrder:
        outs = [DemandedOutput(value=order.demanded_outputs[0].value, script=script)]
        fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
        fields.update(price_terms=encode_price_terms(outs), demanded_outputs=outs)
        if want_id is not None:
            fields["want_token_id"] = want_id
        return RswpOrder(**fields)

    funding = [FundingInput(_ft_src(tk_pkh, _OTHER_REF, 50), 0, taker), FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker)]
    # (a) different REF, want_token_id updated to match it (metadata coherent).
    swapped_ref = build_ft_locking_script(Hex20(order.demanded_outputs[0].script[3:23]), _OTHER_REF)
    with pytest.raises(ValidationError, match="signature does NOT validate"):
        _take(_mutate_with(swapped_ref, swap_token_id(_OTHER_REF)[::-1]), reservation, taker, funding)
    # (b) same ref, different OWNER pkh (metadata untouched and still coherent).
    funding_same_ref = [
        FundingInput(_ft_src(tk_pkh, _FT_REF, 50), 0, taker),
        FundingInput(_rxd_src(tk_pkh, 5_000), 0, taker),
    ]
    swapped_owner = build_ft_locking_script(Hex20(attacker_pkh), _FT_REF)
    with pytest.raises(ValidationError, match="signature does NOT validate"):
        _take(_mutate_with(swapped_owner, None), reservation, taker, funding_same_ref)

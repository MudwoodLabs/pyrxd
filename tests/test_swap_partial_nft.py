"""NFT singleton support in the same-chain swap (``pyrxd.swap``) + RSWP integration.

The singleton discipline is the point: an NFT ref present anywhere in a swap
must appear EXACTLY once on each side — consensus permits burning a singleton
(no backstop; see the deployed-covenant finding), so the builder is the only
thing standing between a buggy completion and a destroyed NFT.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_nft_locking_script, extract_owner_pkh_from_nft_script, is_nft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, SwapOffer, accept_offer, create_offer
from pyrxd.swap.rswp import build_cancel_tx, create_rswp_order, decode_rswp_order, take_rswp_order
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_NFT_REF = GlyphRef(txid=Txid("aa" * 32), vout=0)
_NFT_REF2 = GlyphRef(txid=Txid("bb" * 32), vout=1)
_FT_REF = GlyphRef(txid=Txid("cc" * 32), vout=0)


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()
    return k, k.public_key().hash160()


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _nft_src(pkh: bytes, ref: GlyphRef, carrier: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_nft_locking_script(Hex20(pkh), ref)), carrier))
    return tx


def _out_kinds(tx: Transaction) -> list[str]:
    return ["nft" if is_nft_script(o.locking_script.serialize().hex()) else "other" for o in tx.outputs]


# ─────────────────────────────── happy paths ─────────────────────────────────


def test_nft_for_rxd() -> None:
    """Maker sells an NFT for RXD; the taker receives the singleton whole."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_nft_src(mk_pkh, _NFT_REF, 600),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 5_000),
        maker_receive_pkh=mk_pkh,
    )
    assert offer.terms.give == Asset("nft", 600, _NFT_REF)
    tx = accept_offer(
        SwapOffer.from_dict(offer.to_dict()),
        funding=[FundingInput(_rxd_src(tk_pkh, 9_000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert tx.outputs[0].satoshis == 5_000  # maker's RXD demand
    nft_out = tx.outputs[1].locking_script.serialize()
    assert is_nft_script(nft_out.hex()) and tx.outputs[1].satoshis == 600
    assert bytes(extract_owner_pkh_from_nft_script(nft_out)) == tk_pkh  # taker owns it now
    assert _out_kinds(tx).count("nft") == 1  # exactly-one singleton output


def test_rxd_for_nft() -> None:
    """Maker buys a specific NFT with RXD; taker funds with the singleton + fee RXD."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 5_000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("nft", 600, _NFT_REF),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        SwapOffer.from_dict(offer.to_dict()),
        funding=[FundingInput(_nft_src(tk_pkh, _NFT_REF, 600), 0, tk), FundingInput(_rxd_src(tk_pkh, 2_000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    out0 = tx.outputs[0].locking_script.serialize()
    assert is_nft_script(out0.hex()) and bytes(extract_owner_pkh_from_nft_script(out0)) == mk_pkh
    assert tx.outputs[1].satoshis == 5_000  # taker receives the maker's RXD
    assert _out_kinds(tx).count("nft") == 1


def test_nft_for_ft() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    from pyrxd.glyph.script import build_ft_locking_script

    ft_src = Transaction()
    ft_src.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(tk_pkh), _FT_REF)), 80))
    offer = create_offer(
        give_source_tx=_nft_src(mk_pkh, _NFT_REF, 600),
        give_vout=0,
        maker_key=mk,
        receive=Asset("ft", 50, _FT_REF),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        SwapOffer.from_dict(offer.to_dict()),
        funding=[FundingInput(ft_src, 0, tk), FundingInput(_rxd_src(tk_pkh, 3_000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert _out_kinds(tx).count("nft") == 1  # the singleton moved, exactly once


# ─────────────────────────────── singleton discipline ────────────────────────


def test_taker_missing_demanded_nft_rejected() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 5_000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("nft", 600, _NFT_REF),
        maker_receive_pkh=mk_pkh,
    )
    with pytest.raises(ValidationError, match="funding lacks the NFT singleton"):
        accept_offer(
            SwapOffer.from_dict(offer.to_dict()),
            funding=[FundingInput(_rxd_src(tk_pkh, 9_000), 0, tk)],  # no NFT
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_wrong_nft_rejected() -> None:
    """Funding with a DIFFERENT singleton than demanded fails both directions
    (the demanded ref is missing AND the provided one would burn)."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 5_000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("nft", 600, _NFT_REF),
        maker_receive_pkh=mk_pkh,
    )
    with pytest.raises(ValidationError, match="NFT singleton"):
        accept_offer(
            SwapOffer.from_dict(offer.to_dict()),
            funding=[
                FundingInput(_nft_src(tk_pkh, _NFT_REF2, 600), 0, tk),
                FundingInput(_rxd_src(tk_pkh, 9_000), 0, tk),
            ],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_stray_nft_funding_would_burn_rejected() -> None:
    """An extra singleton slipped into funding with no matching output = a burn —
    the builder must refuse rather than destroy it."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 5_000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 3_000),
        maker_receive_pkh=mk_pkh,
    )
    with pytest.raises(ValidationError, match="would BURN the NFT singleton"):
        accept_offer(
            SwapOffer.from_dict(offer.to_dict()),
            funding=[
                FundingInput(_nft_src(tk_pkh, _NFT_REF, 600), 0, tk),
                FundingInput(_rxd_src(tk_pkh, 9_000), 0, tk),
            ],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_nft_carrier_value_mismatch_is_not_the_singleton() -> None:
    """The demanded output's carrier value is signature-bound; a taker's singleton
    with a different carrier still satisfies the ref (value flows via change)."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 5_000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("nft", 600, _NFT_REF),  # maker wants carrier 600
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        SwapOffer.from_dict(offer.to_dict()),
        funding=[FundingInput(_nft_src(tk_pkh, _NFT_REF, 550), 0, tk), FundingInput(_rxd_src(tk_pkh, 2_000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert tx.outputs[0].satoshis == 600  # signature-bound demand honored
    total_in = 5_000 + 550 + 2_000
    assert total_in - sum(o.satoshis for o in tx.outputs) == 300


# ─────────────────────────────── RSWP integration ────────────────────────────


def test_rswp_nft_order_full_loop() -> None:
    """Post an NFT→RXD order to the book format and take it from the advert bytes."""
    from pyrxd.swap.rswp import swap_token_id

    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _nft_src(mk_pkh, _NFT_REF, 600)
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("rxd", 5_000), maker_receive_pkh=mk_pkh
    )
    order = decode_rswp_order(post.advert_script)
    assert order.offered_type == 1  # ContractType.NFT (verified from Photonic source)
    assert order.token_id == swap_token_id(_NFT_REF)[::-1]

    tx = take_rswp_order(
        order,
        give_source_tx=src,
        funding=[FundingInput(_rxd_src(tk_pkh, 9_000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert _out_kinds(tx).count("nft") == 1


def test_rswp_nft_cancel_returns_singleton() -> None:
    mk, mk_pkh = _key()
    src = _nft_src(mk_pkh, _NFT_REF, 600)
    tx = build_cancel_tx(
        offered_source_tx=src,
        offered_vout=0,
        maker_key=mk,
        refund_pkh=mk_pkh,
        # An NFT cancel returns the full carrier (a singleton has no change path), so the
        # fee comes entirely from the plain-RXD funding input. Both are sized to clear
        # Radiant's relay floor for this shape — the old 300-photon fee built a cancel no
        # node would relay, which for the ONLY revocation mechanism is a fund-safety bug.
        fee=5_000_000,
        funding=[FundingInput(_rxd_src(mk_pkh, 10_000_000), 0, mk)],
    )
    out0 = tx.outputs[0].locking_script.serialize()
    assert is_nft_script(out0.hex()) and tx.outputs[0].satoshis == 600
    assert bytes(extract_owner_pkh_from_nft_script(out0)) == mk_pkh


def test_rswp_lying_nft_offered_type_rejected() -> None:
    """Advert claims FT (2) for a UTXO that really holds an NFT — refused at the bridge."""
    from pyrxd.gravity.swap_order import RswpOrder
    from pyrxd.swap.rswp import rswp_order_to_swap_offer

    mk, mk_pkh = _key()
    src = _nft_src(mk_pkh, _NFT_REF, 600)
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("rxd", 5_000), maker_receive_pkh=mk_pkh
    )
    order = decode_rswp_order(post.advert_script)
    fields = {f: getattr(order, f) for f in RswpOrder.__dataclass_fields__}
    fields["offered_type"] = 2
    with pytest.raises(ValidationError, match="offeredType does not match"):
        rswp_order_to_swap_offer(RswpOrder(**fields), give_source_tx=src)

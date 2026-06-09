"""Tests for the same-chain partial-transaction swap API (issue #123).

Covers the four asset directions (RXD/FT × give/receive), token
conservation + change, and — most importantly — the adversarial cases the
issue calls out: a taker must never be trickable by caller-supplied
amounts or a tampered offer. The maker's SINGLE|ANYONECANPAY signature is
the enforcement; these tests prove it.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import (
    build_ft_locking_script,
    extract_owner_pkh_from_ft_script,
    extract_ref_from_ft_script,
    is_ft_script,
)
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, SwapOffer, accept_offer, create_offer
from pyrxd.swap.partial import _is_p2pkh
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_REF_G = GlyphRef(txid=Txid("aa" * 32), vout=0)
_REF_R = GlyphRef(txid=Txid("bb" * 32), vout=1)


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


def _roundtrip(offer):
    """Send the offer through dict serialization, as a real transport would."""
    return SwapOffer.from_dict(offer.to_dict())


def _classify(out: TransactionOutput) -> tuple[str, int, GlyphRef | None]:
    s = out.locking_script.serialize()
    if is_ft_script(s.hex()):
        return ("ft", out.satoshis, extract_ref_from_ft_script(s))
    assert _is_p2pkh(s)
    return ("rxd", out.satoshis, None)


def _assert_balanced(tx: Transaction, maker_give: int, funding_total: int, fee: int) -> None:
    total_in = maker_give + funding_total
    total_out = sum(o.satoshis for o in tx.outputs)
    assert total_in - total_out == fee
    assert all(i.unlocking_script is not None for i in tx.inputs)  # broadcast-ready


# ─────────────────────────────── happy paths ─────────────────────────────────


def test_rxd_for_rxd() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 600),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        _roundtrip(offer),
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=200,
    )
    # out0 maker receives 600 rxd; out1 taker receives the 1000 rxd given.
    assert _classify(tx.outputs[0]) == ("rxd", 600, None)
    assert _classify(tx.outputs[1]) == ("rxd", 1000, None)
    _assert_balanced(tx, 1000, 2000, 200)


def test_ft_for_rxd() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        _roundtrip(offer),
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert _classify(tx.outputs[0]) == ("rxd", 800, None)  # maker receive
    assert _classify(tx.outputs[1]) == ("ft", 1000, _REF_G)  # taker receives the FT
    # taker receives the FT under their own pkh
    assert extract_owner_pkh_from_ft_script(tx.outputs[1].locking_script.serialize()) == Hex20(tk_pkh)
    _assert_balanced(tx, 1000, 2000, 300)


def test_rxd_for_ft() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("ft", 50, _REF_R),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        _roundtrip(offer),
        funding=[
            FundingInput(_ft_src(tk_pkh, _REF_R, 60), 0, tk),  # taker pays FT (60, wants 50 to maker)
            FundingInput(_rxd_src(tk_pkh, 5000), 0, tk),  # rxd for fee + change
        ],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert _classify(tx.outputs[0]) == ("ft", 50, _REF_R)  # maker receives 50 FT
    assert _classify(tx.outputs[1]) == ("rxd", 1000, None)  # taker receives the rxd given
    # FT change of 10 (60 - 50) returns to taker; rxd change = 6060-50-1000-10-300 = 4700
    kinds = [_classify(o) for o in tx.outputs]
    assert ("ft", 10, _REF_R) in kinds
    assert ("rxd", 4700, None) in kinds
    _assert_balanced(tx, 1000, 5060, 300)


def test_ft_for_ft() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 100),
        give_vout=0,
        maker_key=mk,
        receive=Asset("ft", 30, _REF_R),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        _roundtrip(offer),
        funding=[
            FundingInput(_ft_src(tk_pkh, _REF_R, 40), 0, tk),
            FundingInput(_rxd_src(tk_pkh, 5000), 0, tk),
        ],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    kinds = [_classify(o) for o in tx.outputs]
    assert _classify(tx.outputs[0]) == ("ft", 30, _REF_R)  # maker receives R_r
    assert _classify(tx.outputs[1]) == ("ft", 100, _REF_G)  # taker receives R_g
    assert ("ft", 10, _REF_R) in kinds  # FT change of R_r to taker
    assert ("rxd", 4700, None) in kinds  # rxd change
    _assert_balanced(tx, 100, 5040, 300)


def test_exact_funding_no_rxd_change() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    # funding == receive + fee exactly → no rxd change output.
    tx = accept_offer(
        _roundtrip(offer),
        funding=[FundingInput(_rxd_src(tk_pkh, 900), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=100,
    )
    assert len(tx.outputs) == 2  # maker receive + taker FT only
    _assert_balanced(tx, 1000, 900, 100)


def test_sub_dust_change_folded_into_fee() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    # 900 funding, fee 90 → would-be change 10 (< dust) is folded into the fee.
    tx = accept_offer(
        _roundtrip(offer),
        funding=[FundingInput(_rxd_src(tk_pkh, 900), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=90,
    )
    assert len(tx.outputs) == 2  # no dust change output
    total_out = sum(o.satoshis for o in tx.outputs)
    assert (1000 + 900) - total_out == 100  # effective fee = stated 90 + 10 folded


def test_offer_dict_roundtrip() -> None:
    mk, mk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    again = SwapOffer.from_dict(offer.to_dict())
    assert again == offer
    assert again.terms.give == Asset("ft", 1000, _REF_G)
    assert again.terms.receive == Asset("rxd", 800)


# ─────────────────────────────── adversarial ─────────────────────────────────


def test_create_offer_rejects_non_owned_utxo() -> None:
    mk, _ = _key()
    _, other_pkh = _key()
    with pytest.raises(ValidationError, match="does not own"):
        create_offer(
            give_source_tx=_rxd_src(other_pkh, 1000),  # owned by someone else
            give_vout=0,
            maker_key=mk,
            receive=Asset("rxd", 600),
            maker_receive_pkh=other_pkh,
        )


def test_tampered_declared_give_terms_rejected() -> None:
    """A lying offer that overstates what the maker gives is rejected — the
    taker re-derives the real given asset from the chain, not the terms."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 100),  # really only 100 FT
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    d = offer.to_dict()
    d["terms"]["give"]["amount"] = 100000  # claim a much bigger give
    with pytest.raises(ValidationError, match="give terms do not match"):
        accept_offer(
            SwapOffer.from_dict(d),
            funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_tampered_receive_output_breaks_maker_signature() -> None:
    """Editing the maker's receive output (to extract more from the taker)
    invalidates the maker's SINGLE signature → rejected."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    partial = Transaction.from_hex(bytes.fromhex(offer.partial_tx_hex))
    partial.outputs[0].satoshis = 5000  # maker now appears to demand 5000
    tampered = SwapOffer(
        partial_tx_hex=partial.serialize().hex(),
        give_source_tx_hex=offer.give_source_tx_hex,
        give_vout=offer.give_vout,
        terms=offer.terms,
    )
    with pytest.raises(ValidationError, match="signature does not validate|receive terms do not match"):
        accept_offer(
            tampered,
            funding=[FundingInput(_rxd_src(tk_pkh, 9000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_substituted_give_source_tx_rejected() -> None:
    """Swapping in a different source tx (claiming a bigger given asset) is
    caught by the outpoint-hash check."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 100),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    d = offer.to_dict()
    d["give_source_tx_hex"] = _ft_src(mk_pkh, _REF_G, 100000).serialize().hex()  # different tx
    with pytest.raises(ValidationError, match="does not match the maker input"):
        accept_offer(
            SwapOffer.from_dict(d),
            funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_underfunded_rejected() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    with pytest.raises(ValidationError, match="short of covering"):
        accept_offer(
            _roundtrip(offer),
            funding=[FundingInput(_rxd_src(tk_pkh, 500), 0, tk)],  # < 800 + fee
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
        )


def test_insufficient_ft_funding_rejected() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("ft", 50, _REF_R),  # maker wants 50 FT
        maker_receive_pkh=mk_pkh,
    )
    with pytest.raises(ValidationError, match="lacks .* units of FT"):
        accept_offer(
            _roundtrip(offer),
            funding=[
                FundingInput(_ft_src(tk_pkh, _REF_R, 30), 0, tk),  # only 30, need 50
                FundingInput(_rxd_src(tk_pkh, 500), 0, tk),
            ],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=100,
        )


def test_taker_receive_amount_is_derived_not_assumed() -> None:
    """The taker's received amount always equals the maker's real given
    amount — there is no caller knob to get it wrong (the wild failure
    mode from the issue)."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 777),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 800),
        maker_receive_pkh=mk_pkh,
    )
    tx = accept_offer(
        _roundtrip(offer),
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    assert _classify(tx.outputs[1]) == ("ft", 777, _REF_G)  # exactly what the maker gave

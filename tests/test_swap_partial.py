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
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, SwapOffer, accept_offer, create_offer
from pyrxd.swap.partial import _is_p2pkh
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
        fee_policy=_TOY_FEE_POLICY,
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
        fee_policy=_TOY_FEE_POLICY,
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
        fee_policy=_TOY_FEE_POLICY,
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
        fee_policy=_TOY_FEE_POLICY,
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
        fee_policy=_TOY_FEE_POLICY,
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
        fee_policy=_TOY_FEE_POLICY,
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
            fee_policy=_TOY_FEE_POLICY,
        )


def test_tampered_receive_output_is_caught_by_the_receive_terms_gate() -> None:
    """Editing the maker's receive output (to extract more from the taker) is rejected.

    Named for the gate that actually fires. This test used to be called
    ``..._breaks_maker_signature`` and matched the alternation
    ``"signature does not validate|receive terms do not match"``, which cannot
    distinguish the two gates — and it was the wrong one: the receive-terms
    reconciliation runs BEFORE ``_verify_owner_signature``, so editing output[0]
    trips the terms gate first and the signature gate is never reached. The
    alternation hid that, and it also let the terms gate be deleted with the suite
    green. The signature gate is exercised on its own in the test below, and the
    terms gate's non-redundant duty (a valid signature over terms that do not match
    what was advertised) in ``test_advertised_receive_cheaper_than_signed_is_refused``.
    """
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
    with pytest.raises(ValidationError, match="receive terms do not match"):
        accept_offer(
            tampered,
            funding=[FundingInput(_rxd_src(tk_pkh, 9000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )


def test_tampered_receive_output_also_breaks_the_maker_signature() -> None:
    """The signature gate, isolated: keep the DECLARED terms in step with the edit so the
    receive-terms gate passes, and the maker's SINGLE signature — which commits to
    output[0] — is what refuses it. No alternation: this asserts the signature message
    only, so it can only pass if `_verify_owner_signature` is genuinely reached and fires.
    """
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
    d = offer.to_dict()
    d["terms"]["receive"]["amount"] = 5000  # ...and the advert is updated to agree
    d["partial_tx_hex"] = partial.serialize().hex()
    with pytest.raises(ValidationError, match="signature does not validate"):
        accept_offer(
            SwapOffer.from_dict(d),
            funding=[FundingInput(_rxd_src(tk_pkh, 9000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )


def test_advertised_receive_cheaper_than_signed_is_refused() -> None:
    """FALS-02: the maker SIGNS an expensive demand and ADVERTISES a cheap one.

    This is the case the receive-terms reconciliation exists for, and the only one that
    detects its removal. The partial transaction is untouched, so the maker's signature
    over the 9,000-photon output is perfectly valid — every signature check passes. The
    sole thing binding the advertised price to the signed price is the comparison of
    ``offer.terms.receive`` against the asset actually sitting in ``partial.outputs[0]``.
    Delete it and the taker funds 9,000 photons believing the price is 600, overpaying by
    8,400.

    Reachable on the direct/hand-delivered ``pyrxd.swap.accept_offer`` path that
    third-party integrators drive over their own transport, where a hostile maker's
    signature over the expensive demand is genuine. (The CLI's book path derives both
    sides from one object, so the comparison is tautological there — which is exactly why
    no existing test covered this.)
    """
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    offer = create_offer(
        give_source_tx=_ft_src(mk_pkh, _REF_G, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 9000),  # what the maker actually SIGNED
        maker_receive_pkh=mk_pkh,
    )
    d = offer.to_dict()
    d["terms"]["receive"]["amount"] = 600  # what the maker ADVERTISES
    cheap = SwapOffer.from_dict(d)

    # The signature is untouched and valid — prove it, so a failure below cannot be
    # mistaken for the signature gate firing.
    from pyrxd.swap.rswp import verify_offer_signature

    verify_offer_signature(offer)

    with pytest.raises(ValidationError, match="receive terms do not match"):
        accept_offer(
            cheap,
            funding=[FundingInput(_rxd_src(tk_pkh, 20_000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )


def _offer_signed_with(*, src: Transaction, key, sighash, receive_pkh: bytes, receive_value: int, terms):
    """Build an offer whose maker input is signed with an arbitrary key and sighash flag.

    Bypasses ``create_offer`` (which hardcodes the correct key and 0xC3) so the taker-side
    gates can be tested against an offer pyrxd itself would never emit — the case that
    matters, since a hostile maker signs with their own tooling.
    """
    from pyrxd.transaction.transaction_input import TransactionInput

    tx = Transaction()
    tx.add_input(
        TransactionInput(
            source_transaction=src,
            source_output_index=0,
            unlocking_script_template=P2PKH().unlock(key),
            sighash=sighash,
        )
    )
    tx.add_output(TransactionOutput(P2PKH().lock(receive_pkh), receive_value))
    tx.sign(bypass=True)
    return SwapOffer(
        partial_tx_hex=tx.serialize().hex(),
        give_source_tx_hex=src.serialize().hex(),
        give_vout=0,
        terms=terms,
    )


def test_offer_signed_0xc2_is_refused_on_the_direct_accept_path() -> None:
    """FALS-03: the offer sighash pin, exercised on the path where it is load-bearing.

    ``NONE|ANYONECANPAY|FORKID`` (0xC2) is the one flag that verifies both before AND
    after the taker completes the transaction while committing to no outputs at all — so
    the "verified" signature binds nothing about the price. A flag matrix through
    ``accept_offer`` with the pin disabled showed 0x41/0x42/0x43/0xC1 are still caught by
    the post-completion re-verification; only 0xC2 gets through, letting a transport
    attacker inflate output[0] and the advertised terms together while the taker overpays.

    The rule used to be spelled in three places. The test that named 0xC2
    (``tests/test_rswp_orders.py::test_sighash_flag_0xc2_rejected``) went through
    ``rswp_order_to_swap_offer`` and so hit the ``rswp/orders.py`` copy; the copy in
    ``swap/partial.py`` — the one guarding the direct ``accept_offer`` and
    ``verify_offer_signature`` entry points — had its raise branch execute zero times
    across the whole suite and could be deleted silently. All three now delegate to
    ``swap.partial.require_offer_sighash``; this test covers the direct path.
    """
    from pyrxd.constants import SIGHASH
    from pyrxd.swap.rswp import verify_offer_signature

    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    honest = create_offer(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("rxd", 600), maker_receive_pkh=mk_pkh
    )
    forged = _offer_signed_with(
        src=src,
        key=mk,
        sighash=SIGHASH.NONE_ANYONECANPAY_FORKID,  # 0xC2
        receive_pkh=mk_pkh,
        receive_value=600,
        terms=honest.terms,
    )

    with pytest.raises(ValidationError, match="sighash 0xc2"):
        accept_offer(
            forged,
            funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )
    # The read-only pre-check a browser uses must refuse it too — otherwise the order
    # would be labelled fillable.
    with pytest.raises(ValidationError, match="sighash 0xc2"):
        verify_offer_signature(forged)


def test_maker_pubkey_must_own_the_prevout() -> None:
    """FALS-08: the maker's pubkey must hash to the prevout's owner PKH.

    An impostor can produce a signature that VALIDATES — they sign the same preimage with
    their own key — so the signature check alone cannot tell an owner from a stranger.
    This binding is the only thing that does. With it disabled,
    ``verify_offer_signature`` labels a forged offer fillable and ``accept_offer`` returns
    a signed, broadcast-ready transaction for an offer whose maker input is signed by a
    key that does not own the prevout. (Consensus would still reject it at
    OP_EQUALVERIFY, so the harm is a wasted round trip and a forged row shown as
    fillable — bounded, but nothing in the suite noticed the gate was gone.)
    """
    from pyrxd.constants import SIGHASH
    from pyrxd.swap.rswp import verify_offer_signature

    mk, mk_pkh = _key()
    impostor, impostor_pkh = _key()  # a valid signature, from the wrong key
    tk, tk_pkh = _key()
    assert impostor_pkh != mk_pkh
    src = _rxd_src(mk_pkh, 1000)  # prevout owned by mk
    honest = create_offer(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("rxd", 600), maker_receive_pkh=mk_pkh
    )
    forged = _offer_signed_with(
        src=src,
        key=impostor,
        sighash=SIGHASH.SINGLE_ANYONECANPAY_FORKID,  # correct flag; wrong signer
        receive_pkh=mk_pkh,
        receive_value=600,
        terms=honest.terms,
    )

    with pytest.raises(ValidationError, match="pubkey does not match the prevout owner"):
        accept_offer(
            forged,
            funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )
    with pytest.raises(ValidationError, match="pubkey does not match the prevout owner"):
        verify_offer_signature(forged)


def test_injected_extra_output_rejected() -> None:
    """RH-1 (audit HIGH): a maker's SINGLE|ANYONECANPAY signature binds only output[0], so an offer carrying
    an EXTRA unsigned output would be funded from the TAKER's inputs (silent overpay; the maker pockets the
    injected amount while the advertised terms look fair). accept_offer and verify_offer_signature must
    refuse any offer whose partial tx has more than one input/output."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    _atk, atk_pkh = _key()
    offer = create_offer(
        give_source_tx=_rxd_src(mk_pkh, 1000),
        give_vout=0,
        maker_key=mk,
        receive=Asset("rxd", 600),
        maker_receive_pkh=mk_pkh,
    )
    partial = Transaction.from_hex(bytes.fromhex(offer.partial_tx_hex))
    partial.add_output(TransactionOutput(P2PKH().lock(atk_pkh), 500_000))  # unsigned injected payout to the maker
    tampered = SwapOffer(
        partial_tx_hex=partial.serialize().hex(),
        give_source_tx_hex=offer.give_source_tx_hex,
        give_vout=offer.give_vout,
        terms=offer.terms,
    )
    with pytest.raises(ValidationError, match="one maker input and one output"):
        accept_offer(
            tampered,
            funding=[FundingInput(_rxd_src(tk_pkh, 600_000), 0, tk)],
            taker_receive_pkh=tk_pkh,
            taker_change_pkh=tk_pkh,
            fee=300,
            fee_policy=_TOY_FEE_POLICY,
        )
    from pyrxd.swap.rswp.orders import verify_offer_signature

    with pytest.raises(ValidationError, match="one maker input and one output"):
        verify_offer_signature(tampered)


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
            fee_policy=_TOY_FEE_POLICY,
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
            fee_policy=_TOY_FEE_POLICY,
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
            fee_policy=_TOY_FEE_POLICY,
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
        fee_policy=_TOY_FEE_POLICY,
    )
    assert _classify(tx.outputs[1]) == ("ft", 777, _REF_G)  # exactly what the maker gave

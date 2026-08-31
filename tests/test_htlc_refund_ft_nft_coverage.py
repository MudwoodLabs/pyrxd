"""The FT and NFT REFUND path, which had no coverage anywhere (#510 item 3).

`build_htlc_refund_tx` was exercised only over `_rxd_cov()`. The dual-node regtest suite imports
only `build_htlc_covenant_rxd`, and the cross-chain e2e gives FT/NFT one parametrised happy-path
CLAIM whose refund and mutual-refund tests default to `"rxd"`.

This is the path that recovers a stalled maker's asset. The FT and NFT holder scripts are not the
RXD one — FT welds a `codeScriptHash` epilogue and NFT carries a singleton ref, at 75 and 63 bytes
against RXD's 25 — so a wrong weld, a wrong holder script, or wrong CSV-maturity math on those
shapes would have shipped with every test green.

Deliberately at the BUILDER level, over all three variants. The covenant is what consensus
enforces, and the refund selector, the BIP68 encoding and the single-output holder binding are
properties of the built transaction, not of any chain fixture.
"""

from __future__ import annotations

import pytest

from pyrxd.constants import BIP68_MIN_TX_VERSION, SEQUENCE_LOCKTIME_DISABLE_FLAG
from pyrxd.gravity.htlc_covenant import (
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_refund_tx
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

_H = bytes.fromhex("a" * 64)
_TAKER_PKH = b"\x11" * 20
_MAKER_PKH = b"\x22" * 20
_CARRIER = 100_000
# 1000 tokens IS 1000 photons on Radiant (1 photon = 1 token unit), so an FT covenant's amount and
# its carrier value are the same number by construction — see the #505 correction. Using distinct
# values here would build a UTXO that cannot exist on chain.
_FT_AMOUNT = 100_000


def _fee(value: int = 10_000_000) -> FeeInput:
    key = PrivateKey(bytes.fromhex("33" * 32))
    pkh = bytes(Hex20(key.public_key().hash160()))
    spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    return FeeInput(txid="ab" * 32, vout=0, value=value, scriptpubkey=spk, wif=key.wif())


def _cov(variant: str, csv: int = 6):
    if variant == "rxd":
        return build_htlc_covenant_rxd(
            amount=_CARRIER, taker_pkh=_TAKER_PKH, maker_pkh=_MAKER_PKH, hashlock=_H, refund_csv=csv
        )
    if variant == "ft":
        return build_htlc_covenant_ft(
            genesis_txid="ab" * 32,
            genesis_vout=0,
            amount=_FT_AMOUNT,
            taker_pkh=_TAKER_PKH,
            maker_pkh=_MAKER_PKH,
            hashlock=_H,
            refund_csv=csv,
        )
    return build_htlc_covenant_nft(
        genesis_txid="cd" * 32,
        genesis_vout=1,
        nft_carrier_value=_CARRIER,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=_H,
        refund_csv=csv,
    )


VARIANTS = ["rxd", "ft", "nft"]


@pytest.mark.parametrize("variant", VARIANTS)
class TestTheRefundPathBuildsForEveryAssetVariant:
    def test_the_selector_is_OP_1_alone(self, variant: str) -> None:
        """Refund is function index 1: scriptSig is JUST OP_1 — no preimage, no signature. The
        signature-free property is why anyone can broadcast the refund after maturity (#521)."""
        cov = _cov(variant)
        tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=_CARRIER, fee=_fee())
        assert tx.inputs[0].unlocking_script.serialize() == b"\x51"

    def test_it_is_v2_and_the_nSequence_carries_the_CSV(self, variant: str) -> None:
        """`CheckSequenceLocks` returns false below v2, so a v1 refund is unspendable until
        maturity and then still rejected. The FT/NFT holder shapes do not change this, but nothing
        proved that."""
        cov = _cov(variant, csv=6)
        tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=_CARRIER, fee=_fee())
        assert tx.version == BIP68_MIN_TX_VERSION
        assert tx.inputs[0].sequence == 6
        # IMPORTED, never hand-typed. A transcription cannot notice the thing it transcribed
        # moving — and the repo's own guard caught this line written as `1 << 31`.
        assert not tx.inputs[0].sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG, (
            "the disable bit switches the relative lock off entirely"
        )

    @pytest.mark.parametrize("csv", [1, 6, 144, 0xFFFF])
    def test_the_nSequence_tracks_the_covenant_csv(self, variant: str, csv: int) -> None:
        """Including the BIP68 block-count ceiling. A refund whose nSequence disagrees with the
        covenant's own `refund_csv` is either unspendable or spendable too early."""
        cov = _cov(variant, csv=csv)
        tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=_CARRIER, fee=_fee())
        assert tx.inputs[0].sequence == csv

    def test_the_single_output_pays_the_MAKER_holder(self, variant: str) -> None:
        """The covenant enforces `outputs.length == 1` and pins `hash256(output[0].script)` to the
        maker's holder. For FT that holder carries the codeScriptHash weld and for NFT the
        singleton ref — different scripts, different lengths, same binding, and neither was ever
        checked on the refund side."""
        cov = _cov(variant)
        tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=_CARRIER, fee=_fee())
        assert len(tx.outputs) == 1
        assert tx.outputs[0].locking_script.serialize() == cov.maker_holder_script
        assert tx.outputs[0].satoshis == _CARRIER
        assert len(tx.inputs) == 2  # covenant + fee

    def test_the_refund_pays_the_MAKER_not_the_taker(self, variant: str) -> None:
        """The direction that matters. A refund paying the taker's holder would hand the asset to
        the counterparty on the maker's own recovery path, and the two scripts differ only in the
        embedded pkh — the easiest possible transposition to make and the hardest to notice."""
        cov = _cov(variant)
        tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=_CARRIER, fee=_fee())
        assert tx.outputs[0].locking_script.serialize() != cov.taker_holder_script


@pytest.mark.parametrize("variant", VARIANTS)
def test_the_holder_scripts_really_do_differ_by_variant(variant: str) -> None:
    """Guards the tests above against passing for a boring reason.

    If FT and NFT silently produced the RXD holder script, every assertion here would still pass
    while testing nothing variant-specific. Pinning the shapes as distinct is what makes the
    parametrisation meaningful rather than decorative.
    """
    cov = _cov(variant)
    rxd = _cov("rxd")
    if variant == "rxd":
        assert len(cov.maker_holder_script) == len(rxd.maker_holder_script)
    else:
        assert cov.maker_holder_script != rxd.maker_holder_script
        assert len(cov.maker_holder_script) > len(rxd.maker_holder_script), (
            "an FT weld / NFT ref should make the holder LONGER than the bare P2PKH"
        )


@pytest.mark.parametrize("variant", VARIANTS)
def test_a_fee_input_that_cannot_pay_is_refused_on_every_variant(variant: str) -> None:
    """The maker's exit must not build an unrelayable transaction. Radiant has no RBF and no CPFP,
    so a refund that cannot pay its own way has no remedy."""
    cov = _cov(variant)
    with pytest.raises(ValidationError):
        build_htlc_refund_tx(
            covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=_CARRIER, fee=_fee(value=1)
        )

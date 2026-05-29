"""Tests for the productized Radiant HTLC SPEND builders (gravity.htlc_spend).

PROVENANCE NOTE — what these tests CAN and CANNOT pin:
The spike recorded the funded covenant SPKs in full (so ``htlc_covenant`` is tested
byte-for-byte against mainnet), but it did NOT save the full Radiant claim/refund TX
hexes — only the resulting txids, without the exact fee-input outpoints/values. So a
byte-for-byte / txid reproduction of the Radiant spend tx is NOT possible from the
recorded vectors (unlike the BTC claim tx, whose full hex IS stored). These tests pin
the STRUCTURE the mainnet-accepted spends used — the OP_0 (claim) / OP_1 (refund)
selectors, the SINGLE covenant output bound to the pinned holder script, the v2 +
nSequence=refund_csv BIP68 wiring, and that the claim reveals a scrapeable preimage —
plus fail-closed validation. Whether the Radiant interpreter ACCEPTS these spends is
the e2e regtest milestone (step 5), not a unit test.

(The legacy ``tests/test_htlc_spend.py`` exercises the SPIKE scripts directly; this
file exercises the productized ``src/`` builders, which must agree with it.)
"""

from __future__ import annotations

import hashlib

import pytest

from pyrxd.gravity.htlc_covenant import (
    build_htlc_covenant_ft,
    build_htlc_covenant_nft,
    build_htlc_covenant_rxd,
)
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

_P = bytes.fromhex("11" * 32)
_H = hashlib.sha256(_P).digest()


def _fee(value: int = 10_000_000) -> FeeInput:
    key = PrivateKey(bytes.fromhex("33" * 32))
    pkh = bytes(Hex20(key.public_key().hash160()))
    spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
    return FeeInput(txid="ab" * 32, vout=0, value=value, scriptpubkey=spk, wif=key.wif())


def test_fee_input_repr_does_not_leak_wif_f019():
    # F-019: the WIF is a private key — it must not appear in repr/logs/tracebacks.
    fee = _fee()
    r = repr(fee)
    assert "wif=" not in r
    assert fee.wif not in r


def _rxd_cov(csv: int = 6):
    return build_htlc_covenant_rxd(
        amount=100_000, taker_pkh=b"\x11" * 20, maker_pkh=b"\x22" * 20, hashlock=_H, refund_csv=csv
    )


def _scrape(tx_bytes: bytes, h: bytes) -> bytes | None:
    for i in range(len(tx_bytes) - 31):
        cand = tx_bytes[i : i + 32]
        if hashlib.sha256(cand).digest() == h:
            return cand
    return None


# --------------------------------------------------------------------------- claim shape


def test_claim_scriptsig_is_preimage_then_op0_selector():
    cov = _rxd_cov()
    tx = build_htlc_claim_tx(
        covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, preimage=_P, fee=_fee()
    )
    ss = tx.inputs[0].unlocking_script.serialize()
    assert ss[0] == 0x20  # direct push of 32 bytes
    assert ss[1:33] == _P  # the preimage (FIRST / under the selector)
    assert ss[33:] == b"\x00"  # OP_0 claim selector (LAST / on top)


def test_claim_single_output_to_taker_holder():
    cov = _rxd_cov()
    tx = build_htlc_claim_tx(
        covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, preimage=_P, fee=_fee()
    )
    assert len(tx.outputs) == 1  # covenant enforces outputs.length == 1
    assert tx.outputs[0].locking_script.serialize() == cov.taker_holder_script
    assert tx.outputs[0].satoshis == 100_000  # the carrier value
    assert len(tx.inputs) == 2  # covenant + fee
    assert tx.version == 1  # claim has no relative timelock


def test_claim_reveals_scrapeable_preimage():
    cov = _rxd_cov()
    tx = build_htlc_claim_tx(
        covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, preimage=_P, fee=_fee()
    )
    assert _scrape(tx.serialize(), _H) == _P


def test_claim_holder_binding_ft_and_nft():
    ft = build_htlc_covenant_ft(
        genesis_txid="ab" * 32,
        genesis_vout=0,
        amount=1000,
        taker_pkh=b"\x11" * 20,
        maker_pkh=b"\x22" * 20,
        hashlock=_H,
        refund_csv=6,
    )
    nft = build_htlc_covenant_nft(
        genesis_txid="cd" * 32,
        genesis_vout=1,
        nft_carrier_value=1000,
        taker_pkh=b"\x33" * 20,
        maker_pkh=b"\x44" * 20,
        hashlock=_H,
        refund_csv=6,
    )
    for cov in (ft, nft):
        tx = build_htlc_claim_tx(
            covenant=cov, covenant_outpoint="ef" * 32 + ":0", carrier_value=1000, preimage=_P, fee=_fee()
        )
        assert len(tx.outputs) == 1
        assert tx.outputs[0].locking_script.serialize() == cov.taker_holder_script
        # the covenant pins hash256(holder); confirm the output script matches it.
        assert hashlib.sha256(hashlib.sha256(cov.taker_holder_script).digest()).digest() == cov.expected_taker_hash


# --------------------------------------------------------------------------- refund shape


def test_refund_scriptsig_is_op1_selector_only():
    cov = _rxd_cov(csv=6)
    tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, fee=_fee())
    # refund = function index 1 -> scriptSig is JUST OP_1 (no preimage, no sig).
    assert tx.inputs[0].unlocking_script.serialize() == b"\x51"


def test_refund_is_v2_with_csv_nsequence():
    cov = _rxd_cov(csv=6)
    tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, fee=_fee())
    assert tx.version == 2  # BIP68 requires v2
    assert tx.inputs[0].sequence == 6  # nSequence encodes refund_csv (block count)
    assert tx.inputs[0].sequence < 0xFFFFFFFF  # disable-flag clear -> lock engages
    assert tx.inputs[1].sequence == 0xFFFFFFFE  # fee input < FINAL, carries no lock


def test_refund_single_output_to_maker_holder():
    cov = _rxd_cov()
    tx = build_htlc_refund_tx(covenant=cov, covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, fee=_fee())
    assert len(tx.outputs) == 1
    assert tx.outputs[0].locking_script.serialize() == cov.maker_holder_script  # refund pays the MAKER
    assert tx.outputs[0].satoshis == 100_000


def test_refund_nsequence_tracks_covenant_csv():
    tx = build_htlc_refund_tx(
        covenant=_rxd_cov(csv=12), covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, fee=_fee()
    )
    assert tx.inputs[0].sequence == 12


# --------------------------------------------------------------------------- agreement with the spike builders


def test_productized_refund_selector_matches_legacy_spike_op1():
    """The productized refund selector (OP_1) must match the legacy spike's settled
    selector — a regression here means every refund spend would be rejected on-chain
    (refund is function index 1, NOT 0; claim is 0)."""
    tx = build_htlc_refund_tx(
        covenant=_rxd_cov(), covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, fee=_fee()
    )
    assert tx.inputs[0].unlocking_script.serialize() == b"\x51"  # OP_1, the legacy-proven selector


# --------------------------------------------------------------------------- fail-closed validation


def test_claim_rejects_wrong_preimage():
    with pytest.raises(ValidationError, match="does not hash to the covenant hashlock"):
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint="cd" * 32 + ":0",
            carrier_value=100_000,
            preimage=bytes.fromhex("99" * 32),
            fee=_fee(),
        )


def test_claim_rejects_non_32_byte_preimage():
    with pytest.raises(ValidationError, match="preimage must be 32 bytes"):
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint="cd" * 32 + ":0",
            carrier_value=100_000,
            preimage=b"\x11" * 16,
            fee=_fee(),
        )


@pytest.mark.parametrize(
    "bad", ["nocolon", "ab:0:1", "xy" * 32 + ":0", "ab" * 32 + ":-1", "ab" * 32 + ":notint", "ab" * 30 + ":0"]
)
def test_outpoint_validation_fail_closed(bad):
    with pytest.raises(ValidationError):
        build_htlc_refund_tx(covenant=_rxd_cov(), covenant_outpoint=bad, carrier_value=100_000, fee=_fee())


def test_carrier_value_must_be_positive():
    with pytest.raises(ValidationError, match="carrier_value .* must be a positive int"):
        build_htlc_refund_tx(covenant=_rxd_cov(), covenant_outpoint="cd" * 32 + ":0", carrier_value=0, fee=_fee())


def test_fee_below_dust_fail_closed():
    with pytest.raises(ValidationError, match="below the dust floor"):
        build_htlc_claim_tx(
            covenant=_rxd_cov(),
            covenant_outpoint="cd" * 32 + ":0",
            carrier_value=100_000,
            preimage=_P,
            fee=_fee(value=100),
        )


def test_builders_reject_non_covenant_and_non_fee():
    with pytest.raises(ValidationError, match="covenant must be an HtlcCovenant"):
        build_htlc_claim_tx(
            covenant=object(), covenant_outpoint="cd" * 32 + ":0", carrier_value=1, preimage=_P, fee=_fee()
        )  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="covenant must be an HtlcCovenant"):
        build_htlc_refund_tx(covenant=object(), covenant_outpoint="cd" * 32 + ":0", carrier_value=1, fee=_fee())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="fee must be a FeeInput"):
        build_htlc_claim_tx(
            covenant=_rxd_cov(), covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, preimage=_P, fee=object()
        )  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="fee must be a FeeInput"):
        build_htlc_refund_tx(
            covenant=_rxd_cov(), covenant_outpoint="cd" * 32 + ":0", carrier_value=100_000, fee=object()
        )  # type: ignore[arg-type]


def test_push_encoder_edges():
    from pyrxd.gravity.htlc_spend import _push

    assert _push(b"") == b"\x00"
    assert _push(b"\x01" * 75) == bytes([75]) + b"\x01" * 75  # direct push boundary
    assert _push(b"\x01" * 100)[:2] == b"\x4c\x64"  # PUSHDATA1
    assert _push(b"\x01" * 300)[:3] == b"\x4d\x2c\x01"  # PUSHDATA2
    with pytest.raises(ValidationError, match="64 KB"):
        _push(b"\x00" * 0x10000)


# --------------------------------------------------------------------------- FeeInput validation


@pytest.mark.parametrize(
    "kw,match",
    [
        ({"txid": "xy" * 32}, "txid must be hex"),
        ({"txid": "ab" * 30}, "64-char hex"),
        ({"vout": -1}, "vout must be a non-negative int"),
        ({"value": 0}, "value must be a positive int"),
        ({"scriptpubkey": b""}, "scriptpubkey must be non-empty"),
    ],
)
def test_fee_input_validation(kw, match):
    base = dict(
        txid="ab" * 32, vout=0, value=1000, scriptpubkey=b"\x76\xa9", wif=PrivateKey(bytes.fromhex("33" * 32)).wif()
    )
    base.update(kw)
    with pytest.raises(ValidationError, match=match):
        FeeInput(**base)

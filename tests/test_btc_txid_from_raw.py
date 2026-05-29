"""Tests for btc_txid_from_raw — the local, node-free BTC txid serializer.

This is the reorg gate's ``txid_of`` (P-SAFE-2): on mainnet there is no node to
decoderawtransaction, so the taker derives the txid of the EXACT bytes p was scraped
from. A wrong/silent txid would let the gate read confs of the wrong tx, so the
function is fail-closed and the correctness bar is byte-for-byte against REAL
witness-bearing mainnet transactions.

The golden vectors are the mainnet-proven P2TR HTLC claim + funding txs recorded in
the spike (.live_swap_nft.json) — real segwit txs, exactly the format the gate parses.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.security.errors import ValidationError

_SPIKE = Path(__file__).resolve().parent.parent / "docs" / "brainstorms" / "gravity-ref-spike"


def _vector(name: str) -> dict:
    path = _SPIKE / name
    if not path.exists():
        pytest.skip(f"mainnet golden vector {name} not present")
    return json.loads(path.read_text())


# --------------------------------------------------------------------------- golden vectors (real mainnet witness txs)


def test_reproduces_mainnet_claim_txid():
    v = _vector(".live_swap_nft.json")
    assert t.btc_txid_from_raw(bytes.fromhex(v["btc_claim_tx_hex"])) == v["btc_claim_txid"]


def test_reproduces_mainnet_funding_txid():
    v = _vector(".live_swap_nft.json")
    assert t.btc_txid_from_raw(bytes.fromhex(v["btc_funding_tx_hex"])) == v["btc_funding_txid"]


# --------------------------------------------------------------------------- locally-built tx round-trip


def test_locally_built_claim_tx_yields_valid_txid():
    maker = coincurve.PrivateKey(os.urandom(32))
    taker = coincurve.PrivateKey(os.urandom(32))
    claim_xo = coincurve.PublicKeyXOnly.from_secret(maker.secret).format()
    refund_xo = coincurve.PublicKeyXOnly.from_secret(taker.secret).format()
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    htlc = t.build_htlc(
        hashlock=h,
        claim_pubkey_xonly=claim_xo,
        refund_pubkey_xonly=refund_xo,
        timeout=t.Timelock(3, t.TimeUnit.BLOCKS),
        network="bcrt",
    )
    loc = htlc.with_funding(t.BtcOutpoint("ab" * 32, 0), 100_000)
    raw = t.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=maker.secret,
        to_scriptpubkey=b"\x00\x14" + b"\x11" * 20,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    txid = t.btc_txid_from_raw(raw)
    assert len(txid) == 64 and all(c in "0123456789abcdef" for c in txid)
    # Deterministic: same bytes -> same txid.
    assert t.btc_txid_from_raw(raw) == txid


def test_legacy_nonsegwit_tx_txid():
    # A minimal legacy (no marker/flag) tx: version + 1 vin (null) + 0 vout + locktime.
    # txid = hash256(whole)[::-1] since there's no witness section to strip.
    raw = (
        bytes.fromhex("02000000")  # version
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"  # 1 input, empty scriptSig
        + b"\x00"  # 0 outputs
        + bytes.fromhex("00000000")  # locktime
    )
    expected = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
    assert t.btc_txid_from_raw(raw) == expected


def test_verify_raw_matches_txid_binds_returned_bytes_f004():
    # F-004: the transport must reject tx bytes whose locally-derived txid != the
    # requested txid (a MITM'd source returning a *different* tx than asked for, which
    # would let the reorg gate measure the wrong tx's depth).
    from pyrxd.network.bitcoin import _verify_raw_matches_txid
    from pyrxd.security.errors import NetworkError
    from pyrxd.security.types import Txid

    raw = (
        bytes.fromhex("02000000")
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"
        + b"\x00"
        + bytes.fromhex("00000000")
    )
    real = t.btc_txid_from_raw(raw)
    _verify_raw_matches_txid(raw, Txid(real))  # exact match -> no raise
    with pytest.raises(NetworkError, match="do not match the requested txid"):
        _verify_raw_matches_txid(raw, Txid("11" * 32))


# --------------------------------------------------------------------------- fail-closed on malformed input


@pytest.mark.parametrize(
    "raw",
    [
        b"",  # empty
        b"\x02\x00\x00",  # truncated version
        b"\x02\x00\x00\x00\x00\x01",  # segwit marker but truncated
        bytes.fromhex("0200000000"),  # zero inputs after segwit-less header is malformed
    ],
)
def test_fail_closed_on_truncated_or_malformed(raw):
    with pytest.raises(ValidationError):
        t.btc_txid_from_raw(raw)


def test_fail_closed_on_trailing_bytes():
    v = _vector(".live_swap_nft.json")
    raw = bytes.fromhex(v["btc_claim_tx_hex"]) + b"\xff"
    with pytest.raises(ValidationError, match="trailing bytes"):
        t.btc_txid_from_raw(raw)


# --------------------------------------------------------------------------- structural defense branches


def _vi(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def test_multibyte_compactsize_input_count_parses():
    """A 0xFD-prefixed (multi-byte CompactSize) input count is parsed correctly — the
    txid still round-trips. Builds a legacy tx with 1 input declared via 0xFD,0x01."""
    raw = (
        bytes.fromhex("02000000")
        + b"\xfd\x01\x00"  # CompactSize 1 as 0xFD 0x0001 (multi-byte form)
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"  # 1 input
        + b"\x00"  # 0 outputs
        + bytes.fromhex("00000000")  # locktime
    )
    txid = t.btc_txid_from_raw(raw)
    assert len(txid) == 64


def test_fail_closed_on_oversize_input_count():
    raw = bytes.fromhex("02000000") + _vi(200_000) + bytes.fromhex("00000000")
    with pytest.raises(ValidationError, match="bad input count"):
        t.btc_txid_from_raw(raw)


def test_fail_closed_on_oversize_output_count():
    # 1 valid input, then an absurd output count.
    raw = (
        bytes.fromhex("02000000")
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"
        + _vi(200_000)  # bad output count
        + bytes.fromhex("00000000")
    )
    with pytest.raises(ValidationError, match="bad output count"):
        t.btc_txid_from_raw(raw)


def test_fail_closed_on_scriptsig_length_overrun():
    # scriptSig length claims more bytes than the tx contains.
    raw = (
        bytes.fromhex("02000000")
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + _vi(5000)
        + b"\x11\x11"  # claims 5000, has 2
    )
    with pytest.raises(ValidationError):
        t.btc_txid_from_raw(raw)


def test_fail_closed_on_truncated_witness():
    """A real segwit tx truncated mid-witness must fail closed — the parser cannot skip
    a witness that runs off the end, so it can't silently emit a txid."""
    v = _vector(".live_swap_nft.json")
    raw = bytes.fromhex(v["btc_claim_tx_hex"])
    with pytest.raises(ValidationError):
        t.btc_txid_from_raw(raw[:-6])


def test_fail_closed_on_segwit_witness_item_length_overrun():
    """A segwit witness item whose CompactSize length exceeds the tx is rejected.
    Hand-built minimal segwit tx: 1 input, 0 outputs, a witness item claiming 5000
    bytes but only 2 present."""
    raw = (
        bytes.fromhex("02000000")
        + b"\x00\x01"  # marker + flag
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"  # 1 input
        + b"\x00"  # 0 outputs
        + b"\x01"
        + _vi(5000)
        + b"\x11\x11"  # witness: 1 item claiming 5000, has 2
        + bytes.fromhex("00000000")  # locktime
    )
    with pytest.raises(ValidationError, match="witness item length out of range"):
        t.btc_txid_from_raw(raw)


def test_fail_closed_on_scriptpubkey_length_overrun():
    # 1 valid input, then an output whose scriptPubKey length exceeds the tx.
    raw = (
        bytes.fromhex("02000000")
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"  # 1 input
        + b"\x01"
        + b"\x00" * 8
        + _vi(5000)
        + b"\x22\x22"  # 1 output: value + claims 5000-byte spk, has 2
    )
    with pytest.raises(ValidationError, match="scriptPubKey length out of range"):
        t.btc_txid_from_raw(raw)


def test_fail_closed_on_oversize_witness_item_count():
    raw = (
        bytes.fromhex("02000000")
        + b"\x00\x01"  # marker + flag
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"  # 1 input
        + b"\x00"  # 0 outputs
        + _vi(200_000)  # witness: absurd item count
        + bytes.fromhex("00000000")
    )
    with pytest.raises(ValidationError, match="bad witness item count"):
        t.btc_txid_from_raw(raw)


# --------------------------------------------------------------------------- btc_input_outpoints_from_raw (claim-tx provenance gate)


def test_input_outpoints_round_trip_with_prevout_bytes():
    """The extracted 36-byte prevout equals ``BtcOutpoint.prevout_bytes()`` of the funded
    outpoint — the exact equality the coordinator's claim-tx provenance gate relies on."""
    maker = coincurve.PrivateKey(os.urandom(32))
    taker = coincurve.PrivateKey(os.urandom(32))
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    htlc = t.build_htlc(
        hashlock=h,
        claim_pubkey_xonly=coincurve.PublicKeyXOnly.from_secret(maker.secret).format(),
        refund_pubkey_xonly=coincurve.PublicKeyXOnly.from_secret(taker.secret).format(),
        timeout=t.Timelock(3, t.TimeUnit.BLOCKS),
        network="bcrt",
    )
    funding = t.BtcOutpoint("ab" * 32, 0)
    loc = htlc.with_funding(funding, 100_000)
    raw = t.build_claim_tx(
        locator=loc,
        preimage=p,
        claim_privkey=maker.secret,
        to_scriptpubkey=b"\x00\x14" + b"\x11" * 20,
        fee_sats=500,
        aux_rand=os.urandom(32),
    )
    assert funding.prevout_bytes() in t.btc_input_outpoints_from_raw(raw)


def test_input_outpoints_legacy_null_prevout():
    raw = (
        bytes.fromhex("02000000")
        + b"\x01"
        + b"\x00" * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"  # 1 input, null prevout, empty scriptSig
        + b"\x00"  # 0 outputs
        + bytes.fromhex("00000000")
    )
    assert t.btc_input_outpoints_from_raw(raw) == [b"\x00" * 36]


def test_input_outpoints_mainnet_claim_spends_funding():
    v = _vector(".live_swap_nft.json")
    prevouts = t.btc_input_outpoints_from_raw(bytes.fromhex(v["btc_claim_tx_hex"]))
    funding_txid_le = bytes.fromhex(v["btc_funding_txid"])[::-1]
    assert any(po[:32] == funding_txid_le for po in prevouts)


@pytest.mark.parametrize("raw", [b"", b"\x02\x00\x00", bytes.fromhex("0200000000")])
def test_input_outpoints_fail_closed_on_malformed(raw):
    with pytest.raises(ValidationError):
        t.btc_input_outpoints_from_raw(raw)

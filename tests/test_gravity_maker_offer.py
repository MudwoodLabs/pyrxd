"""Tests for build_maker_offer_tx — the Maker-side MakerOffer funding tx (C2)."""

from __future__ import annotations

import hashlib
import time

import pytest

from pyrxd.gravity import (
    GravityOffer,
    MakerOfferResult,
    build_maker_offer_tx,
)
from pyrxd.gravity.codehash import (
    compute_p2sh_address_from_redeem,
    compute_p2sh_script_pubkey,
    hash256,
)
from pyrxd.gravity.covenant import build_gravity_offer
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_privkey() -> PrivateKeyMaterial:
    return PrivateKeyMaterial(b"\x12" * 32)


def _maker_pkh(privkey: PrivateKeyMaterial) -> bytes:
    import coincurve
    pub = coincurve.PrivateKey(privkey.unsafe_raw_bytes()).public_key.format(compressed=True)
    return hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()


def _maker_pub(privkey: PrivateKeyMaterial) -> bytes:
    import coincurve
    return coincurve.PrivateKey(privkey.unsafe_raw_bytes()).public_key.format(compressed=True)


def _make_offer(privkey: PrivateKeyMaterial, **kwargs) -> GravityOffer:
    pkh = _maker_pkh(privkey)
    pub = _maker_pub(privkey)
    taker_priv = PrivateKeyMaterial(b"\x34" * 32)
    import coincurve
    taker_raw = taker_priv.unsafe_raw_bytes()
    taker_pub = coincurve.PrivateKey(taker_raw).public_key.format(compressed=True)
    taker_pkh = hashlib.new("ripemd160", hashlib.sha256(taker_pub).digest()).digest()

    defaults = dict(
        maker_pkh=pkh,
        maker_pk=pub,
        taker_pk=taker_pub,
        taker_radiant_pkh=taker_pkh,
        btc_receive_hash=b"\xcc" * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=b"\xdd" * 32,
        expected_nbits=bytes.fromhex("ffff001d"),
        anchor_height=800_000,
        merkle_depth=12,
        claim_deadline=int(time.time()) + 48 * 3600,
        photons_offered=500_000,
        accept_short_deadline=False,
    )
    defaults.update(kwargs)
    return build_gravity_offer(**defaults)


FAKE_TXID = "aa" * 32
FAKE_VOUT = 0


# ---------------------------------------------------------------------------
# Basic structure tests
# ---------------------------------------------------------------------------

class TestBuildMakerOfferTxStructure:
    def test_returns_maker_offer_result(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
            maker_privkey=pk,
        )
        assert isinstance(result, MakerOfferResult)

    def test_txid_is_hash256_of_raw_tx(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
            maker_privkey=pk,
        )
        raw = bytes.fromhex(result.tx_hex)
        expected_txid = hash256(raw)[::-1].hex()
        assert result.txid == expected_txid

    def test_tx_size_matches_hex_length(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
            maker_privkey=pk,
        )
        assert result.tx_size == len(bytes.fromhex(result.tx_hex))

    def test_single_output_receives_funding_minus_fee(self):
        # Single-output mode (no change_address): the P2SH locks the full
        # funding minus the miner fee, so surplus above photons_offered
        # stays with the covenant for later claim/finalize fees.
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 50_000,
            fee_sats=10_000,
            maker_privkey=pk,
        )
        assert result.output_photons == offer.photons_offered + 40_000

    def test_single_output_exact_funding_equals_photons_offered(self):
        # When funding exactly covers photons_offered + fee, the P2SH output
        # equals photons_offered.
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
            maker_privkey=pk,
        )
        assert result.output_photons == offer.photons_offered

    def test_fee_sats_reported(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 15_000,
            fee_sats=15_000,
            maker_privkey=pk,
        )
        assert result.fee_sats == 15_000


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

class TestMakerOfferTxWireFormat:
    def _build(self, pk=None, **kwargs):
        pk = pk or _make_privkey()
        offer = _make_offer(pk)
        return build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
            maker_privkey=pk,
            **kwargs,
        ), offer

    def test_version_is_2(self):
        result, _ = self._build()
        raw = bytes.fromhex(result.tx_hex)
        assert raw[:4] == (2).to_bytes(4, "little")

    def test_locktime_is_zero(self):
        result, _ = self._build()
        raw = bytes.fromhex(result.tx_hex)
        assert raw[-4:] == (0).to_bytes(4, "little")

    def test_input_count_is_one(self):
        result, _ = self._build()
        raw = bytes.fromhex(result.tx_hex)
        assert raw[4] == 0x01

    def test_output_count_is_one_without_change(self):
        result, offer = self._build()
        raw = bytes.fromhex(result.tx_hex)
        # The P2SH SPK is 23 bytes. Output = value(8) + varint(1) + spk(23) = 32 bytes.
        # The output count varint (0x01) must appear immediately before it.
        p2sh_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.offer_redeem_hex))
        offer_output = offer.photons_offered.to_bytes(8, "little") + bytes([len(p2sh_spk)]) + p2sh_spk
        idx = raw.find(offer_output)
        assert idx > 0
        # Byte immediately before the first output is the output count
        output_count_byte = raw[idx - 1]
        assert output_count_byte == 0x01

    def test_offer_p2sh_address_matches_redeem(self):
        result, offer = self._build()
        expected = compute_p2sh_address_from_redeem(bytes.fromhex(offer.offer_redeem_hex))
        assert result.offer_p2sh == expected

    def test_p2sh_script_pubkey_in_raw_tx(self):
        result, offer = self._build()
        raw = bytes.fromhex(result.tx_hex)
        p2sh_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.offer_redeem_hex))
        assert p2sh_spk in raw

    def test_funding_txid_reversed_in_input(self):
        result, _ = self._build()
        raw = bytes.fromhex(result.tx_hex)
        reversed_txid = bytes.fromhex(FAKE_TXID)[::-1]
        assert reversed_txid in raw

    def test_scriptsig_contains_maker_pubkey(self):
        pk = _make_privkey()
        result, _ = self._build(pk=pk)
        raw = bytes.fromhex(result.tx_hex)
        pub = _maker_pub(pk)
        assert pub in raw

    def test_sequence_is_ffffffff(self):
        result, _ = self._build()
        raw = bytes.fromhex(result.tx_hex)
        assert bytes([0xFF, 0xFF, 0xFF, 0xFF]) in raw


# ---------------------------------------------------------------------------
# Change output
# ---------------------------------------------------------------------------

class TestMakerOfferTxChange:
    def _make_maker_address(self, pk: PrivateKeyMaterial) -> str:
        from pyrxd.base58 import base58check_encode
        pkh = _maker_pkh(pk)
        return base58check_encode(b"\x00" + pkh)

    def test_surplus_without_change_address_stays_in_p2sh(self):
        # Regression: the builder previously rejected surplus without a
        # change_address. That was wrong — a real trade needs the surplus in
        # the P2SH to fund claim/finalize tx fees that deduct from the
        # covenant output while staying above the photons_offered floor.
        pk = _make_privkey()
        offer = _make_offer(pk)
        surplus = 10_000
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 20_000,  # 10k surplus after fee
            fee_sats=10_000,
            maker_privkey=pk,
        )
        assert result.output_photons == offer.photons_offered + surplus
        # And only one output — no change.
        raw = bytes.fromhex(result.tx_hex)
        p2sh_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.offer_redeem_hex))
        offer_output = result.output_photons.to_bytes(8, "little") + bytes([len(p2sh_spk)]) + p2sh_spk
        idx = raw.find(offer_output)
        assert idx > 0
        assert raw[idx - 1] == 0x01  # output count = 1

    def test_single_output_below_covenant_floor_raises(self):
        # Covenant forfeit enforces output >= photons_offered, so if funding
        # is too small to cover that floor, reject early.
        pk = _make_privkey()
        offer = _make_offer(pk)
        with pytest.raises(ValidationError, match="photons_offered"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid=FAKE_TXID,
                funding_vout=FAKE_VOUT,
                funding_photons=offer.photons_offered + 5_000,  # fee 10k → output < floor
                fee_sats=10_000,
                maker_privkey=pk,
            )

    def test_with_change_address_creates_two_outputs(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        change_addr = self._make_maker_address(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 20_000,
            fee_sats=10_000,
            maker_privkey=pk,
            change_address=change_addr,
        )
        assert isinstance(result, MakerOfferResult)
        raw = bytes.fromhex(result.tx_hex)
        # Output count byte should be 0x02
        # It's after: version(4) + varint(1 input) + input(variable)
        # We verify both P2SH SPK and P2PKH SPK appear in raw tx
        p2sh_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.offer_redeem_hex))
        assert p2sh_spk in raw
        pkh = _maker_pkh(pk)
        p2pkh_spk = b"\x76\xa9\x14" + pkh + b"\x88\xac"
        assert p2pkh_spk in raw

    def test_change_amount_is_surplus_minus_fee(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        change_addr = self._make_maker_address(pk)
        surplus = 30_000
        fee = 10_000
        funding = offer.photons_offered + fee + surplus
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=funding,
            fee_sats=fee,
            maker_privkey=pk,
            change_address=change_addr,
        )
        raw = bytes.fromhex(result.tx_hex)
        # Change = surplus = 30_000; find it as 8-byte LE in the tx
        change_le = surplus.to_bytes(8, "little")
        assert change_le in raw

    def test_exact_funding_no_change_needed(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=FAKE_VOUT,
            funding_photons=offer.photons_offered + 10_000,  # exact: offer + fee
            fee_sats=10_000,
            maker_privkey=pk,
        )
        assert isinstance(result, MakerOfferResult)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestMakerOfferTxValidation:
    def test_insufficient_funding_raises(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        with pytest.raises(ValidationError, match="Insufficient funding"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid=FAKE_TXID,
                funding_vout=FAKE_VOUT,
                funding_photons=offer.photons_offered - 1,  # too small
                fee_sats=10_000,
                maker_privkey=pk,
            )

    def test_fee_exceeds_surplus_raises(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        with pytest.raises(ValidationError, match="Insufficient funding"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid=FAKE_TXID,
                funding_vout=FAKE_VOUT,
                funding_photons=offer.photons_offered,  # nothing left for fee
                fee_sats=10_000,
                maker_privkey=pk,
            )

    def test_different_keys_produce_different_signatures(self):
        pk1 = PrivateKeyMaterial(b"\x11" * 32)
        pk2 = PrivateKeyMaterial(b"\x22" * 32)
        offer1 = _make_offer(pk1)
        offer2 = _make_offer(pk2)
        r1 = build_maker_offer_tx(
            offer=offer1, funding_txid=FAKE_TXID, funding_vout=0,
            funding_photons=offer1.photons_offered + 10_000, fee_sats=10_000,
            maker_privkey=pk1,
        )
        r2 = build_maker_offer_tx(
            offer=offer2, funding_txid=FAKE_TXID, funding_vout=0,
            funding_photons=offer2.photons_offered + 10_000, fee_sats=10_000,
            maker_privkey=pk2,
        )
        assert r1.tx_hex != r2.tx_hex

    def test_deterministic_with_same_inputs(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        kwargs = dict(
            offer=offer, funding_txid=FAKE_TXID, funding_vout=0,
            funding_photons=offer.photons_offered + 10_000, fee_sats=10_000,
            maker_privkey=pk,
        )
        r1 = build_maker_offer_tx(**kwargs)
        r2 = build_maker_offer_tx(**kwargs)
        assert r1.tx_hex == r2.tx_hex


# ---------------------------------------------------------------------------
# Integration: offer built from real covenant artifact
# ---------------------------------------------------------------------------

class TestMakerOfferWithRealCovenant:
    def test_offer_p2sh_is_valid_radiant_address(self):
        pk = _make_privkey()
        offer = _make_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=FAKE_TXID,
            funding_vout=0,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
            maker_privkey=pk,
        )
        # Address should be a base58check string starting with '3' (P2SH mainnet)
        # or any valid base58check — just verify it decodes without error
        from pyrxd.base58 import base58check_decode
        decoded = base58check_decode(result.offer_p2sh)
        assert len(decoded) == 21
        assert decoded[0] == 0x05  # P2SH version byte

    def test_txid_changes_with_different_offer_redeem(self):
        pk = _make_privkey()
        offer1 = _make_offer(pk, btc_satoshis=100_000)
        offer2 = _make_offer(pk, btc_satoshis=200_000)
        r1 = build_maker_offer_tx(
            offer=offer1, funding_txid=FAKE_TXID, funding_vout=0,
            funding_photons=offer1.photons_offered + 10_000, fee_sats=10_000,
            maker_privkey=pk,
        )
        r2 = build_maker_offer_tx(
            offer=offer2, funding_txid=FAKE_TXID, funding_vout=0,
            funding_photons=offer2.photons_offered + 10_000, fee_sats=10_000,
            maker_privkey=pk,
        )
        # Different offer redeem → different P2SH SPK → different output → different txid
        assert r1.txid != r2.txid

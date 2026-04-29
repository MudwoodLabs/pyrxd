"""Tests for GravityTrade high-level orchestrator (Phase 3b).

Covers:
* TradeConfig validation
* GravityTrade.claim() happy path
* GravityTrade.claim() broadcast failure propagation
* GravityTrade.wait_confirmations() success on first poll
* GravityTrade.wait_confirmations() success after N polls
* GravityTrade.wait_confirmations() timeout raises NetworkError
* GravityTrade.wait_confirmations() tx-not-found timeout
* GravityTrade.finalize() happy path (mocked SPV)
* GravityTrade.finalize() SPV verification failure propagates
* GravityTrade._resolve_btc_tx_height with explicit height
* _find_output_zero_offset native-segwit layout
* _find_output_zero_offset P2SH-P2WPKH layout
* _find_output_zero_offset multi-input rejection
* _find_output_zero_offset unknown scriptSig length rejection
"""

from __future__ import annotations

import asyncio
import hashlib
import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.gravity.trade import (
    ConfirmationStatus,
    GravityTrade,
    TradeConfig,
    _find_output_zero_offset,
)
from pyrxd.gravity.transactions import build_claim_tx, build_finalize_tx
from pyrxd.gravity.types import ClaimResult, FinalizeResult, GravityOffer
from pyrxd.network.bitcoin import BtcDataSource
from pyrxd.network.electrumx import ElectrumXClient
from pyrxd.security.errors import NetworkError, SpvVerificationError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.security.types import BlockHeight, RawTx, Txid


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# A 32-byte mock chain anchor (LE bytes representing a known block hash)
ANCHOR = bytes.fromhex("00" * 32)
TAKER_PKH = bytes.fromhex("aa" * 20)

# Minimal valid GravityOffer with synthetic redeem scripts (not executable on
# chain — just enough bytes to pass validation in build_claim_tx / types).
# offer_redeem_hex: arbitrary 33 bytes (> 0, < 76 for single push)
OFFER_REDEEM = bytes([0x51] * 33)   # OP_1 x33 — fictional script
CLAIMED_REDEEM = bytes([0x52] * 33)  # OP_2 x33


def make_offer(**kwargs) -> GravityOffer:
    defaults: dict = dict(
        btc_receive_hash=bytes.fromhex("bb" * 20),
        btc_receive_type="p2wpkh",
        btc_satoshis=10_000,
        chain_anchor=ANCHOR,
        anchor_height=100,
        merkle_depth=1,
        taker_radiant_pkh=TAKER_PKH,
        claim_deadline=1_800_000_000,  # far future
        photons_offered=10_000_000,
        offer_redeem_hex=OFFER_REDEEM.hex(),
        claimed_redeem_hex=CLAIMED_REDEEM.hex(),
    )
    defaults.update(kwargs)
    if "expected_code_hash_hex" not in defaults:
        from pyrxd.gravity.codehash import compute_p2sh_code_hash
        defaults["expected_code_hash_hex"] = compute_p2sh_code_hash(
            bytes.fromhex(defaults["claimed_redeem_hex"])
        ).hex()
    return GravityOffer(**defaults)


def make_taker_privkey() -> PrivateKeyMaterial:
    # scalar = 1 (min valid secp256k1 privkey)
    return PrivateKeyMaterial(b"\x00" * 31 + b"\x01")


# ---------------------------------------------------------------------------
# Mock network helpers
# ---------------------------------------------------------------------------


def mock_electrumx(broadcast_txid: str = "aa" * 32) -> AsyncMock:
    """Return a mock ElectrumXClient."""
    client = AsyncMock(spec=ElectrumXClient)
    client.broadcast.return_value = Txid(broadcast_txid)
    return client


def mock_btc_source() -> AsyncMock:
    """Return a mock BtcDataSource."""
    src = AsyncMock(spec=BtcDataSource)
    src.get_tip_height.return_value = BlockHeight(900_000)
    return src


# ---------------------------------------------------------------------------
# TradeConfig validation
# ---------------------------------------------------------------------------


class TestTradeConfig:
    def test_defaults_are_valid(self):
        cfg = TradeConfig()
        assert cfg.min_btc_confirmations == 6
        assert cfg.poll_interval_seconds == 60
        assert cfg.max_poll_attempts == 120

    def test_min_confirmations_zero_raises(self):
        with pytest.raises(ValidationError):
            TradeConfig(min_btc_confirmations=0)

    def test_poll_interval_nonpositive_raises(self):
        with pytest.raises(ValidationError):
            TradeConfig(poll_interval_seconds=0)
        with pytest.raises(ValidationError):
            TradeConfig(poll_interval_seconds=-1)

    def test_max_poll_attempts_zero_raises(self):
        with pytest.raises(ValidationError):
            TradeConfig(max_poll_attempts=0)

    def test_custom_values_accepted(self):
        cfg = TradeConfig(min_btc_confirmations=1, poll_interval_seconds=5, max_poll_attempts=3)
        assert cfg.min_btc_confirmations == 1


# ---------------------------------------------------------------------------
# _find_output_zero_offset
# ---------------------------------------------------------------------------


def _build_stripped_tx(scriptsig: bytes) -> bytes:
    """Build a minimal 1-input 1-output stripped (no-witness) tx for testing."""
    version = struct.pack("<I", 2)
    prevout = b"\xaa" * 32 + struct.pack("<I", 0)  # 36 bytes
    sequence = struct.pack("<I", 0xFFFFFFFF)
    output_value = struct.pack("<Q", 1000)
    output_script = b"\x76\xa9\x14" + b"\xcc" * 20 + b"\x88\xac"  # P2PKH
    output_script_encoded = bytes([len(output_script)]) + output_script
    output = output_value + output_script_encoded

    scriptsig_len = bytes([len(scriptsig)])
    input_bytes = prevout + scriptsig_len + scriptsig + sequence
    tx = version + bytes([1]) + input_bytes + bytes([1]) + output
    return tx


class TestFindOutputZeroOffset:
    def test_native_segwit_empty_scriptsig(self):
        tx = _build_stripped_tx(b"")
        # 4 + 1 + 36 + 1 + 0 + 4 + 1 = 47
        offset = _find_output_zero_offset(tx)
        assert offset == 47

    def test_p2sh_p2wpkh_23byte_scriptsig(self):
        tx = _build_stripped_tx(b"\x16" + b"\x00\x14" + b"\xcc" * 20)  # 23 bytes
        # 4 + 1 + 36 + 1 + 23 + 4 + 1 = 70
        offset = _find_output_zero_offset(tx)
        assert offset == 70

    def test_multi_input_rejected(self):
        tx = _build_stripped_tx(b"")
        # Patch input count to 2
        patched = bytearray(tx)
        patched[4] = 2
        with pytest.raises(ValidationError, match="exactly 1 input"):
            _find_output_zero_offset(bytes(patched))

    def test_unknown_scriptsig_length_rejected(self):
        tx = _build_stripped_tx(b"\x00" * 5)  # 5-byte scriptSig — not 0 or 23
        with pytest.raises(ValidationError, match="Unsupported scriptSig"):
            _find_output_zero_offset(tx)

    def test_empty_tx_raises(self):
        with pytest.raises((ValidationError, IndexError)):
            _find_output_zero_offset(b"\x02\x00\x00\x00")


# ---------------------------------------------------------------------------
# GravityTrade.claim()
# ---------------------------------------------------------------------------


class TestGravityTradeClaim:
    @pytest.mark.asyncio
    async def test_claim_broadcasts_and_returns_result(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        offer = make_offer()
        privkey = make_taker_privkey()

        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc)

        with patch("pyrxd.gravity.trade.build_claim_tx") as mock_build:
            fake_result = ClaimResult(
                tx_hex="deadbeef",
                txid="cc" * 32,
                tx_size=200,
                offer_p2sh="fake_offer_p2sh",
                claimed_p2sh="fake_claimed_p2sh",
                fee_sats=1000,
                output_photons=9_000_000,
            )
            mock_build.return_value = fake_result
            result = await trade.claim(
                offer=offer,
                offer_txid="aa" * 32,
                offer_vout=0,
                offer_photons=10_000_000,
                fee_sats=1000,
                taker_privkey=privkey,
            )

        assert result.txid == "cc" * 32
        rxd.broadcast.assert_awaited_once()
        # Verify accept_short_deadline forwarded from config
        mock_build.assert_called_once_with(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=10_000_000,
            fee_sats=1000,
            taker_privkey=privkey,
            accept_short_deadline=False,
        )

    @pytest.mark.asyncio
    async def test_claim_propagates_broadcast_error(self):
        rxd = mock_electrumx()
        rxd.broadcast.side_effect = NetworkError("broadcast failed")
        btc = mock_btc_source()
        offer = make_offer()
        privkey = make_taker_privkey()

        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc)

        with patch("pyrxd.gravity.trade.build_claim_tx") as mock_build:
            mock_build.return_value = ClaimResult(
                tx_hex="deadbeef",
                txid="cc" * 32,
                tx_size=200,
                offer_p2sh="p",
                claimed_p2sh="p",
                fee_sats=1000,
                output_photons=9_000_000,
            )
            with pytest.raises(NetworkError, match="broadcast failed"):
                await trade.claim(
                    offer=offer,
                    offer_txid="aa" * 32,
                    offer_vout=0,
                    offer_photons=10_000_000,
                    fee_sats=1000,
                    taker_privkey=privkey,
                )

    @pytest.mark.asyncio
    async def test_claim_passes_accept_short_deadline(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        offer = make_offer()
        privkey = make_taker_privkey()
        cfg = TradeConfig(accept_short_deadline=True)
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)

        with patch("pyrxd.gravity.trade.build_claim_tx") as mock_build:
            mock_build.return_value = ClaimResult(
                tx_hex="00",
                txid="cc" * 32,
                tx_size=1,
                offer_p2sh="p",
                claimed_p2sh="p",
                fee_sats=1,
                output_photons=1,
            )
            await trade.claim(
                offer=offer,
                offer_txid="aa" * 32,
                offer_vout=0,
                offer_photons=10,
                fee_sats=1,
                taker_privkey=privkey,
            )
        _, kwargs = mock_build.call_args
        assert kwargs["accept_short_deadline"] is True


# ---------------------------------------------------------------------------
# GravityTrade.wait_confirmations()
# ---------------------------------------------------------------------------


class TestWaitConfirmations:
    VALID_TXID = "ab" * 32

    @pytest.mark.asyncio
    async def test_confirmed_on_first_poll(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        raw = RawTx(b"\x02\x00\x00\x00" + b"\x00" * 70)
        btc.get_raw_tx.return_value = raw

        cfg = TradeConfig(min_btc_confirmations=1, poll_interval_seconds=0.01, max_poll_attempts=3)
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)

        status = await trade.wait_confirmations(self.VALID_TXID)
        assert status.confirmed is True
        assert status.confirmations >= 1

    @pytest.mark.asyncio
    async def test_confirmed_after_second_poll(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        raw = RawTx(b"\x02\x00\x00\x00" + b"\x00" * 70)

        # First call (min_conf=0): tx visible in mempool
        # Second call (min_conf=1): first poll not confirmed, second poll confirmed
        call_count = {"n": 0}
        async def fake_get_raw_tx(txid, min_confirmations=6):
            call_count["n"] += 1
            if min_confirmations == 0:
                return raw  # always visible
            if call_count["n"] <= 2:
                raise NetworkError("not yet confirmed")
            return raw  # confirmed on 3rd overall call
        btc.get_raw_tx.side_effect = fake_get_raw_tx

        cfg = TradeConfig(min_btc_confirmations=1, poll_interval_seconds=0.01, max_poll_attempts=5)
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)
        status = await trade.wait_confirmations(self.VALID_TXID)
        assert status.confirmed is True

    @pytest.mark.asyncio
    async def test_timeout_raises_network_error(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        raw = RawTx(b"\x02\x00\x00\x00" + b"\x00" * 70)

        async def fake_get_raw_tx(txid, min_confirmations=6):
            if min_confirmations == 0:
                return raw
            raise NetworkError("still waiting")
        btc.get_raw_tx.side_effect = fake_get_raw_tx

        cfg = TradeConfig(min_btc_confirmations=6, poll_interval_seconds=0.01, max_poll_attempts=2)
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)

        with pytest.raises(NetworkError):
            await trade.wait_confirmations(self.VALID_TXID)

    @pytest.mark.asyncio
    async def test_tx_not_found_timeout(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        btc.get_raw_tx.side_effect = NetworkError("not found")

        cfg = TradeConfig(min_btc_confirmations=1, poll_interval_seconds=0.01, max_poll_attempts=2)
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)

        with pytest.raises(NetworkError):
            await trade.wait_confirmations(self.VALID_TXID)

    @pytest.mark.asyncio
    async def test_invalid_txid_raises_validation_error(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc)

        with pytest.raises(ValidationError):
            await trade.wait_confirmations("not_a_txid")

    @pytest.mark.asyncio
    async def test_min_confirmations_override(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        raw = RawTx(b"\x02\x00\x00\x00" + b"\x00" * 70)
        btc.get_raw_tx.return_value = raw

        cfg = TradeConfig(min_btc_confirmations=6, poll_interval_seconds=0.01, max_poll_attempts=3)
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)

        status = await trade.wait_confirmations(self.VALID_TXID, min_confirmations=1)
        assert status.confirmations == 1


# ---------------------------------------------------------------------------
# GravityTrade.finalize()
# ---------------------------------------------------------------------------


def _make_stripped_p2wpkh_tx() -> bytes:
    """Build a minimal stripped P2WPKH tx for mocking the BTC source."""
    version = struct.pack("<I", 2)
    prevout = b"\x01" * 36
    sequence = struct.pack("<I", 0xFFFFFFFF)
    output_value = struct.pack("<Q", 20_000)
    # P2WPKH output: OP_0 OP_PUSH20 <pkh>
    pkh = b"\xbb" * 20
    output_script = b"\x00\x14" + pkh
    output_encoded = bytes([len(output_script)]) + output_script
    output = output_value + output_encoded

    input_bytes = prevout + bytes([0]) + sequence  # empty scriptSig
    tx = version + bytes([1]) + input_bytes + bytes([1]) + output
    return tx


class TestGravityTradeFinalize:
    VALID_BTC_TXID = "ab" * 32

    def _make_trade(self, rxd=None, btc=None, cfg=None):
        rxd = rxd or mock_electrumx()
        btc = btc or mock_btc_source()
        cfg = cfg or TradeConfig(min_btc_confirmations=1, poll_interval_seconds=0.01)
        return GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg), rxd, btc

    @pytest.mark.asyncio
    async def test_finalize_happy_path(self):
        trade, rxd, btc = self._make_trade()
        offer = make_offer()

        stripped_tx = _make_stripped_p2wpkh_tx()
        btc.get_raw_tx.return_value = RawTx(stripped_tx)
        btc.get_merkle_proof.return_value = (["cd" * 32], 1)
        btc.get_header_chain.return_value = [b"\x00" * 80]

        fake_finalize_result = FinalizeResult(
            tx_hex="deadbeef",
            txid="ee" * 32,
            tx_size=300,
            fee_sats=1000,
            output_photons=8_000_000,
        )

        with (
            patch("pyrxd.gravity.trade.strip_witness", return_value=stripped_tx),
            patch("pyrxd.gravity.trade.SpvProofBuilder") as MockBuilder,
            patch("pyrxd.gravity.trade.build_finalize_tx", return_value=fake_finalize_result),
        ):
            mock_proof = MagicMock()
            MockBuilder.return_value.build.return_value = mock_proof

            result = await trade.finalize(
                btc_txid=self.VALID_BTC_TXID,
                offer=offer,
                claimed_txid="cc" * 32,
                claimed_vout=0,
                claimed_photons=9_000_000,
                taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=1000,
                btc_tx_height=101,
            )

        assert result.txid == "ee" * 32
        rxd.broadcast.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_finalize_spv_failure_propagates(self):
        trade, rxd, btc = self._make_trade()
        offer = make_offer()

        stripped_tx = _make_stripped_p2wpkh_tx()
        btc.get_raw_tx.return_value = RawTx(stripped_tx)
        btc.get_merkle_proof.return_value = (["cd" * 32], 1)
        btc.get_header_chain.return_value = [b"\x00" * 80]

        with (
            patch("pyrxd.gravity.trade.strip_witness", return_value=stripped_tx),
            patch("pyrxd.gravity.trade.SpvProofBuilder") as MockBuilder,
        ):
            MockBuilder.return_value.build.side_effect = SpvVerificationError("bad proof")

            with pytest.raises(SpvVerificationError, match="bad proof"):
                await trade.finalize(
                    btc_txid=self.VALID_BTC_TXID,
                    offer=offer,
                    claimed_txid="cc" * 32,
                    claimed_vout=0,
                    claimed_photons=9_000_000,
                    taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    fee_sats=1000,
                    btc_tx_height=101,
                )

        # Should not have broadcast anything
        rxd.broadcast.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_finalize_tx_height_before_anchor_raises(self):
        trade, rxd, btc = self._make_trade()
        offer = make_offer(anchor_height=200)

        stripped_tx = _make_stripped_p2wpkh_tx()
        btc.get_raw_tx.return_value = RawTx(stripped_tx)
        btc.get_merkle_proof.return_value = (["cd" * 32], 1)

        with patch("pyrxd.gravity.trade.strip_witness", return_value=stripped_tx):
            with pytest.raises(ValidationError, match="must be > anchor_height"):
                await trade.finalize(
                    btc_txid=self.VALID_BTC_TXID,
                    offer=offer,
                    claimed_txid="cc" * 32,
                    claimed_vout=0,
                    claimed_photons=9_000_000,
                    taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    fee_sats=1000,
                    btc_tx_height=150,  # < anchor_height=200
                )

    @pytest.mark.asyncio
    async def test_finalize_invalid_btc_txid_raises(self):
        trade, rxd, btc = self._make_trade()
        offer = make_offer()

        with pytest.raises(ValidationError):
            await trade.finalize(
                btc_txid="not_a_txid",
                offer=offer,
                claimed_txid="cc" * 32,
                claimed_vout=0,
                claimed_photons=9_000_000,
                taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=1000,
                btc_tx_height=101,
            )

    @pytest.mark.asyncio
    async def test_finalize_empty_header_chain_raises(self):
        trade, rxd, btc = self._make_trade()
        offer = make_offer()

        stripped_tx = _make_stripped_p2wpkh_tx()
        btc.get_raw_tx.return_value = RawTx(stripped_tx)
        btc.get_merkle_proof.return_value = (["cd" * 32], 1)
        btc.get_header_chain.return_value = []  # empty!

        with patch("pyrxd.gravity.trade.strip_witness", return_value=stripped_tx):
            with pytest.raises(NetworkError, match="empty header chain"):
                await trade.finalize(
                    btc_txid=self.VALID_BTC_TXID,
                    offer=offer,
                    claimed_txid="cc" * 32,
                    claimed_vout=0,
                    claimed_photons=9_000_000,
                    taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    fee_sats=1000,
                    btc_tx_height=101,
                )


# ---------------------------------------------------------------------------
# build_finalize_tx minimum_output_photons validation
# ---------------------------------------------------------------------------


class TestBuildFinalizeTxMinimumOutput:
    """Unit tests for the minimum_output_photons pre-flight check."""

    def _make_fake_proof(self):
        proof = MagicMock()
        proof.headers = []
        proof.branch = b"\x00" * 32
        proof.raw_tx = b"\x00" * 100
        return proof

    def test_output_below_minimum_raises(self):
        # 147M - 55M = 92M < 100M minimum → must raise before building
        proof = self._make_fake_proof()
        with pytest.raises(ValidationError, match="below the covenant"):
            build_finalize_tx(
                spv_proof=proof,
                claimed_redeem_hex="deadbeef",
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=147_000_000,
                to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=55_000_000,
                minimum_output_photons=100_000_000,
            )

    def test_error_message_includes_shortfall(self):
        # 147M - 55M = 92M; shortfall = 100M - 92M = 8M
        proof = self._make_fake_proof()
        with pytest.raises(ValidationError, match="8000000"):
            build_finalize_tx(
                spv_proof=proof,
                claimed_redeem_hex="deadbeef",
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=147_000_000,
                to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=55_000_000,
                minimum_output_photons=100_000_000,
            )

    def test_output_exactly_at_minimum_passes_check(self):
        # 155M - 55M = 100M == minimum → no floor error raised
        proof = self._make_fake_proof()
        try:
            build_finalize_tx(
                spv_proof=proof,
                claimed_redeem_hex="deadbeef",
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=155_000_000,
                to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=55_000_000,
                minimum_output_photons=100_000_000,
            )
        except ValidationError as exc:
            assert "below the covenant" not in str(exc), (
                f"Unexpected floor ValidationError: {exc}"
            )

    def test_no_minimum_zero_default_skips_check(self):
        # Default minimum_output_photons=0 → no floor check (backwards compat)
        # A tiny output is fine as far as the floor check is concerned.
        proof = self._make_fake_proof()
        try:
            build_finalize_tx(
                spv_proof=proof,
                claimed_redeem_hex="deadbeef",
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=10_000,
                to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=1_000,
                minimum_output_photons=0,
            )
        except ValidationError as exc:
            assert "below the covenant" not in str(exc), (
                f"Floor check fired with minimum=0, should be skipped: {exc}"
            )


# ---------------------------------------------------------------------------
# Deadline proximity warning (audit 04-S1 forfeit race)
# ---------------------------------------------------------------------------


class TestDeadlineProximityWarning:
    """GravityTrade.finalize() emits WARNING log when claim_deadline is close."""

    def _make_trade_with_mocked_finalize_internals(self, offer, warning_seconds=7200):
        """Return a (trade, rxd_mock, btc_mock) tuple with finalize internals stubbed."""
        rxd = mock_electrumx()
        btc = mock_btc_source()
        cfg = TradeConfig(
            min_btc_confirmations=1,
            deadline_warning_seconds=warning_seconds,
        )
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc, config=cfg)
        return trade, rxd, btc

    @pytest.mark.asyncio
    async def test_warning_emitted_when_deadline_close(self, caplog):
        import time

        # Set deadline 30 minutes from now (within the 2h default warning window)
        soon = int(time.time()) + 1800
        # anchor_height must be close to btc_tx_height to pass the sanity check
        offer = make_offer(claim_deadline=soon, anchor_height=900_000, merkle_depth=20)

        trade, rxd, btc = self._make_trade_with_mocked_finalize_internals(offer)

        # Stub out everything except the deadline check
        trade._resolve_btc_tx_height = AsyncMock(return_value=BlockHeight(900_010))
        trade._broadcast_radiant = AsyncMock(return_value="aa" * 32)

        fake_proof = MagicMock()
        fake_proof.headers = []
        fake_proof.branch = b"\x00" * 32
        fake_proof.raw_tx = b"\x00" * 100
        mock_builder = MagicMock()
        mock_builder.build.return_value = fake_proof

        with patch("pyrxd.gravity.trade.SpvProofBuilder", return_value=mock_builder), \
             patch("pyrxd.gravity.trade.build_finalize_tx") as mock_build, \
             patch("pyrxd.gravity.trade.strip_witness", return_value=b"\x01\x00\x00\x00" + b"\x00" * 200), \
             patch("pyrxd.gravity.trade._find_output_zero_offset", return_value=47):
            mock_result = MagicMock()
            mock_result.tx_hex = "aa" * 100
            mock_result.txid = "aa" * 32
            mock_build.return_value = mock_result

            btc.get_raw_tx.return_value = RawTx(b"\x01\x00\x00\x00" + b"\x00" * 200)
            btc.get_merkle_proof.return_value = (["aa" * 32], 0)
            btc.get_header_chain.return_value = [b"\x00" * 80] * 10

            import logging
            with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.trade"):
                await trade.finalize(
                    btc_txid="bb" * 32,
                    offer=offer,
                    claimed_txid="cc" * 32,
                    claimed_vout=0,
                    claimed_photons=200_000_000,
                    taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    fee_sats=1_000_000,
                    btc_tx_height=900_010,
                )

        assert any("URGENT" in r.message or "deadline" in r.message.lower() for r in caplog.records), \
            f"Expected deadline warning in logs, got: {[r.message for r in caplog.records]}"

    @pytest.mark.asyncio
    async def test_no_warning_when_deadline_far(self, caplog):
        import time

        # Deadline 48 hours away — should not warn
        far = int(time.time()) + 48 * 3600
        offer = make_offer(claim_deadline=far, anchor_height=900_000, merkle_depth=20)

        trade, rxd, btc = self._make_trade_with_mocked_finalize_internals(offer)
        trade._resolve_btc_tx_height = AsyncMock(return_value=BlockHeight(900_010))
        trade._broadcast_radiant = AsyncMock(return_value="aa" * 32)

        fake_proof = MagicMock()
        mock_builder = MagicMock()
        mock_builder.build.return_value = fake_proof

        with patch("pyrxd.gravity.trade.SpvProofBuilder", return_value=mock_builder), \
             patch("pyrxd.gravity.trade.build_finalize_tx") as mock_build, \
             patch("pyrxd.gravity.trade.strip_witness", return_value=b"\x01\x00\x00\x00" + b"\x00" * 200), \
             patch("pyrxd.gravity.trade._find_output_zero_offset", return_value=47):
            mock_result = MagicMock()
            mock_result.tx_hex = "aa" * 100
            mock_result.txid = "aa" * 32
            mock_build.return_value = mock_result

            btc.get_raw_tx.return_value = RawTx(b"\x01\x00\x00\x00" + b"\x00" * 200)
            btc.get_merkle_proof.return_value = (["aa" * 32], 0)
            btc.get_header_chain.return_value = [b"\x00" * 80] * 10

            import logging
            with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.trade"):
                await trade.finalize(
                    btc_txid="bb" * 32,
                    offer=offer,
                    claimed_txid="cc" * 32,
                    claimed_vout=0,
                    claimed_photons=200_000_000,
                    taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    fee_sats=1_000_000,
                    btc_tx_height=900_010,
                )

        deadline_warns = [
            r for r in caplog.records
            if "URGENT" in r.message or ("deadline" in r.message.lower() and "passed" in r.message.lower())
        ]
        assert not deadline_warns, f"Unexpected deadline warnings: {[r.message for r in deadline_warns]}"

    @pytest.mark.asyncio
    async def test_warning_emitted_when_deadline_passed(self, caplog):
        import time

        # Deadline 10 minutes in the past
        past = int(time.time()) - 600
        offer = make_offer(claim_deadline=past, anchor_height=900_000, merkle_depth=20)

        trade, rxd, btc = self._make_trade_with_mocked_finalize_internals(offer)
        trade._resolve_btc_tx_height = AsyncMock(return_value=BlockHeight(900_010))
        trade._broadcast_radiant = AsyncMock(return_value="aa" * 32)

        mock_builder = MagicMock()
        mock_builder.build.return_value = MagicMock()

        with patch("pyrxd.gravity.trade.SpvProofBuilder", return_value=mock_builder), \
             patch("pyrxd.gravity.trade.build_finalize_tx") as mock_build, \
             patch("pyrxd.gravity.trade.strip_witness", return_value=b"\x01\x00\x00\x00" + b"\x00" * 200), \
             patch("pyrxd.gravity.trade._find_output_zero_offset", return_value=47):
            mock_result = MagicMock()
            mock_result.tx_hex = "aa" * 100
            mock_result.txid = "aa" * 32
            mock_build.return_value = mock_result

            btc.get_raw_tx.return_value = RawTx(b"\x01\x00\x00\x00" + b"\x00" * 200)
            btc.get_merkle_proof.return_value = (["aa" * 32], 0)
            btc.get_header_chain.return_value = [b"\x00" * 80] * 10

            import logging
            with caplog.at_level(logging.WARNING, logger="pyrxd.gravity.trade"):
                await trade.finalize(
                    btc_txid="bb" * 32,
                    offer=offer,
                    claimed_txid="cc" * 32,
                    claimed_vout=0,
                    claimed_photons=200_000_000,
                    taker_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                    fee_sats=1_000_000,
                    btc_tx_height=900_010,
                )

        assert any("passed" in r.message.lower() for r in caplog.records), \
            f"Expected 'passed' deadline warning, got: {[r.message for r in caplog.records]}"

    def test_deadline_warning_disabled_with_zero(self):
        # deadline_warning_seconds=0 → no validation error, check is disabled
        cfg = TradeConfig(deadline_warning_seconds=0)
        assert cfg.deadline_warning_seconds == 0

    def test_deadline_warning_negative_raises(self):
        with pytest.raises(ValidationError):
            TradeConfig(deadline_warning_seconds=-1)


# ---------------------------------------------------------------------------
# GravityTrade._resolve_btc_tx_height (explicit path)
# ---------------------------------------------------------------------------


class TestResolveBtcTxHeight:
    @pytest.mark.asyncio
    async def test_explicit_height_returned_directly(self):
        rxd = mock_electrumx()
        btc = mock_btc_source()
        trade = GravityTrade(radiant_network=rxd, bitcoin_source=btc)

        height = await trade._resolve_btc_tx_height(Txid("ab" * 32), provided_height=12345)
        assert int(height) == 12345
        btc.get_tip_height.assert_not_awaited()
        btc.get_raw_tx.assert_not_awaited()

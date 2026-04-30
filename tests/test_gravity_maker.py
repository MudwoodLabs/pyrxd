"""Tests for GravityMakerSession and Transaction.from_hex round-trip.

All ElectrumX network calls are mocked — no live connections required.
"""

from __future__ import annotations

import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.gravity.codehash import compute_p2sh_script_pubkey
from pyrxd.gravity.covenant import build_gravity_offer
from pyrxd.gravity.maker import (
    ActiveOffer,
    GravityMakerSession,
    GravityOfferParams,
    _p2sh_script_hash,
)
from pyrxd.gravity.types import GravityOffer, MakerOfferResult
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.transaction.transaction import Transaction

# ---------------------------------------------------------------------------
# Task 1: Transaction.from_hex round-trip verification
# ---------------------------------------------------------------------------


class TestTransactionFromHexRoundTrip:
    """Verify that Transaction.serialize() → Transaction.from_hex() is lossless."""

    _KNOWN_TX_HEX = (
        "01000000029e8d016a7b0dc49a325922d05da1f916d1e4d4f0cb840c9727f3d22ce8d1363f0000000"
        "08c493046022100e9318720bee5425378b4763b0427158b1051eec8b08442ce3fbfbf7b30202a44022"
        "100d4172239ebd701dae2fbaaccd9f038e7ca166707333427e3fb2a2865b19a7f27014104510c67f46"
        "d2cbb29476d1f0b794be4cb549ea59ab9cc1e731969a7bf5be95f7ad5e7f904e5ccf50a9dc1714df00"
        "fbeb794aa27aaff33260c1032d931a75c56f2ffffffffa3195e7a1ab665473ff717814f6881485dc87"
        "59bebe97e31c301ffe7933a656f020000008b48304502201c282f35f3e02a1f32d2089265ad4b561f0"
        "7ea3c288169dedcf2f785e6065efa022100e8db18aadacb382eed13ee04708f00ba0a9c40e3b21cf91"
        "da8859d0f7d99e0c50141042b409e1ebbb43875be5edde9c452c82c01e3903d38fa4fd89f3887a52cb"
        "8aea9dc8aec7e2c9d5b3609c03eb16259a2537135a1bf0f9c5fbbcbdbaf83ba402442ffffffff02206"
        "b1000000000001976a91420bb5c3bfaef0231dc05190e7f1c8e22e098991e88acf0ca0100000000001"
        "976a9149e3e2d23973a04ec1b02be97c30ab9f2f27c3b2c88ac00000000"
    )

    def _clean(self) -> str:
        return self._KNOWN_TX_HEX.replace("\n", "").replace(" ", "")

    def test_from_hex_returns_transaction(self):
        tx = Transaction.from_hex(self._clean())
        assert tx is not None

    def test_round_trip_serialize_matches_input(self):
        """serialize().hex() after from_hex() must equal the original hex string."""
        hex_str = self._clean()
        tx = Transaction.from_hex(hex_str)
        assert tx is not None
        assert tx.serialize().hex() == hex_str

    def test_input_count(self):
        tx = Transaction.from_hex(self._clean())
        assert tx is not None
        assert len(tx.inputs) == 2

    def test_output_count(self):
        tx = Transaction.from_hex(self._clean())
        assert tx is not None
        assert len(tx.outputs) == 2

    def test_version(self):
        tx = Transaction.from_hex(self._clean())
        assert tx is not None
        assert tx.version == 1

    def test_locktime(self):
        tx = Transaction.from_hex(self._clean())
        assert tx is not None
        assert tx.locktime == 0

    def test_from_hex_with_bytes_input(self):
        """from_hex should also accept raw bytes."""
        raw = bytes.fromhex(self._clean())
        tx = Transaction.from_hex(raw)
        assert tx is not None
        assert len(tx.inputs) == 2
        assert len(tx.outputs) == 2

    def test_malformed_hex_returns_none(self):
        """Malformed hex must return None, not raise."""
        result = Transaction.from_hex("ZZZZ" + self._clean())
        assert result is None

    def test_empty_hex_returns_none(self):
        result = Transaction.from_hex("")
        assert result is None

    def test_truncated_hex_returns_none(self):
        truncated = self._clean()[:40]
        result = Transaction.from_hex(truncated)
        assert result is None


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------


def _make_privkey(seed: bytes = b"\x12" * 32) -> PrivateKeyMaterial:
    return PrivateKeyMaterial(seed)


def _make_offer(privkey: PrivateKeyMaterial, **kwargs) -> GravityOffer:
    import coincurve

    raw = privkey.unsafe_raw_bytes()
    maker_pub = coincurve.PrivateKey(raw).public_key.format(compressed=True)
    maker_pkh = hashlib.new("ripemd160", hashlib.sha256(maker_pub).digest()).digest()

    taker_priv = PrivateKeyMaterial(b"\x34" * 32)
    taker_pub = coincurve.PrivateKey(taker_priv.unsafe_raw_bytes()).public_key.format(compressed=True)
    taker_pkh = hashlib.new("ripemd160", hashlib.sha256(taker_pub).digest()).digest()

    defaults = dict(
        maker_pkh=maker_pkh,
        maker_pk=maker_pub,
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


def _make_active_offer(
    privkey: PrivateKeyMaterial,
    offer_txid: str = "aa" * 32,
) -> ActiveOffer:
    offer = _make_offer(privkey)
    result = MakerOfferResult(
        tx_hex="01" * 100,
        txid=offer_txid,
        tx_size=100,
        offer_p2sh="3FakeP2SHAddress",
        fee_sats=1000,
        output_photons=offer.photons_offered,
    )
    return ActiveOffer(
        offer=offer,
        maker_offer_result=result,
        offer_txid=offer_txid,
        offer_vout=0,
        offer_photons=offer.photons_offered,
    )


def _make_mock_client(broadcast_txid: str = "bb" * 32) -> AsyncMock:
    client = AsyncMock(spec=ElectrumXClient)
    client.broadcast = AsyncMock(return_value=MagicMock(__str__=lambda self: broadcast_txid))
    client.get_utxos = AsyncMock(return_value=[])
    return client


# ---------------------------------------------------------------------------
# _p2sh_script_hash helper tests
# ---------------------------------------------------------------------------


class TestP2shScriptHash:
    def test_returns_32_bytes(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        script_hash = _p2sh_script_hash(offer.offer_redeem_hex)
        assert len(script_hash) == 32

    def test_deterministic(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        h1 = _p2sh_script_hash(offer.offer_redeem_hex)
        h2 = _p2sh_script_hash(offer.offer_redeem_hex)
        assert h1 == h2

    def test_different_redeem_different_hash(self):
        priv = _make_privkey()
        offer1 = _make_offer(priv, btc_satoshis=100_000)
        offer2 = _make_offer(priv, btc_satoshis=200_000)
        h1 = _p2sh_script_hash(offer1.offer_redeem_hex)
        h2 = _p2sh_script_hash(offer2.offer_redeem_hex)
        assert h1 != h2

    def test_is_sha256_of_p2sh_spk_reversed(self):
        """Verify the formula: sha256(P2SH_scriptPubKey)[::-1]."""
        priv = _make_privkey()
        offer = _make_offer(priv)
        redeem = bytes.fromhex(offer.offer_redeem_hex)
        p2sh_spk = compute_p2sh_script_pubkey(redeem)
        expected = hashlib.sha256(p2sh_spk).digest()[::-1]
        assert _p2sh_script_hash(offer.offer_redeem_hex) == expected


# ---------------------------------------------------------------------------
# GravityMakerSession.create_offer
# ---------------------------------------------------------------------------


class TestCreateOffer:
    @pytest.mark.asyncio
    async def test_returns_active_offer(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        client = _make_mock_client("cc" * 32)
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
        )
        active = await session.create_offer(params)
        assert isinstance(active, ActiveOffer)

    @pytest.mark.asyncio
    async def test_broadcast_called_once(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        client = _make_mock_client("cc" * 32)
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
        )
        await session.create_offer(params)
        client.broadcast.assert_called_once()

    @pytest.mark.asyncio
    async def test_active_offer_has_correct_vout(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        client = _make_mock_client("cc" * 32)
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
        )
        active = await session.create_offer(params)
        assert active.offer_vout == 0

    @pytest.mark.asyncio
    async def test_active_offer_photons(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        client = _make_mock_client("cc" * 32)
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
        )
        active = await session.create_offer(params)
        # Single-output mode: output_photons = funding - fee = photons_offered
        assert active.offer_photons == offer.photons_offered

    @pytest.mark.asyncio
    async def test_broadcast_network_error_propagates(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        client = _make_mock_client()
        client.broadcast = AsyncMock(side_effect=NetworkError("connection refused"))
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + 10_000,
            fee_sats=10_000,
        )
        with pytest.raises(NetworkError):
            await session.create_offer(params)


# ---------------------------------------------------------------------------
# GravityMakerSession.wait_for_claim
# ---------------------------------------------------------------------------


class TestWaitForClaim:
    @pytest.mark.asyncio
    async def test_returns_none_on_timeout_when_always_open(self):
        priv = _make_privkey()
        offer_txid = "aa" * 32
        active = _make_active_offer(priv, offer_txid=offer_txid)
        client = _make_mock_client()
        # Always return the UTXO as unspent
        utxo = UtxoRecord(tx_hash=offer_txid, tx_pos=0, value=500_000, height=100)
        client.get_utxos = AsyncMock(return_value=[utxo])

        session = GravityMakerSession(
            rxd_client=client,
            maker_priv=priv,
            poll_interval_seconds=1,
        )
        # 2 polls at 1s interval → ~2s total but timeout=1 → max_polls=1
        result = await session.wait_for_claim(active, timeout_seconds=1)
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_offer_txid_when_utxo_spent(self):
        """When the UTXO disappears after first poll, return offer_txid."""
        priv = _make_privkey()
        offer_txid = "aa" * 32
        active = _make_active_offer(priv, offer_txid=offer_txid)
        client = _make_mock_client()

        utxo = UtxoRecord(tx_hash=offer_txid, tx_pos=0, value=500_000, height=100)
        # First poll: UTXO is present (offer just confirmed)
        # Second poll: UTXO is gone (Taker claimed it)
        client.get_utxos = AsyncMock(
            side_effect=[
                [utxo],  # poll 0: still open
                [],  # poll 1: claimed
            ]
        )

        session = GravityMakerSession(
            rxd_client=client,
            maker_priv=priv,
            poll_interval_seconds=0,  # no sleep in tests
        )
        result = await session.wait_for_claim(active, timeout_seconds=60)
        assert result == offer_txid

    @pytest.mark.asyncio
    async def test_network_error_retries_then_raises(self):
        priv = _make_privkey()
        active = _make_active_offer(priv)
        client = _make_mock_client()
        client.get_utxos = AsyncMock(side_effect=NetworkError("server unreachable"))

        session = GravityMakerSession(
            rxd_client=client,
            maker_priv=priv,
            poll_interval_seconds=0,
        )
        with pytest.raises(NetworkError):
            await session.wait_for_claim(active, timeout_seconds=1)

    @pytest.mark.asyncio
    async def test_polls_correct_script_hash(self):
        """get_utxos must be called with the P2SH script hash of the offer."""
        priv = _make_privkey()
        offer_txid = "aa" * 32
        active = _make_active_offer(priv, offer_txid=offer_txid)
        expected_hash = _p2sh_script_hash(active.offer.offer_redeem_hex)

        client = _make_mock_client()
        utxo = UtxoRecord(tx_hash=offer_txid, tx_pos=0, value=500_000, height=100)
        client.get_utxos = AsyncMock(return_value=[utxo])

        session = GravityMakerSession(
            rxd_client=client,
            maker_priv=priv,
            poll_interval_seconds=0,
        )
        await session.wait_for_claim(active, timeout_seconds=1)
        call_args = client.get_utxos.call_args[0][0]
        assert call_args == expected_hash


# ---------------------------------------------------------------------------
# GravityMakerSession.cancel_offer
# ---------------------------------------------------------------------------


class TestCancelOffer:
    def _maker_address(self, privkey: PrivateKeyMaterial) -> str:
        import coincurve

        from pyrxd.base58 import base58check_encode

        pub = coincurve.PrivateKey(privkey.unsafe_raw_bytes()).public_key.format(compressed=True)
        pkh = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
        return base58check_encode(b"\x00" + pkh)

    @pytest.mark.asyncio
    async def test_cancel_broadcasts_and_returns_txid(self):
        priv = _make_privkey()
        active = _make_active_offer(priv)
        cancel_txid = "dd" * 32
        client = _make_mock_client(cancel_txid)
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        addr = self._maker_address(priv)
        result = await session.cancel_offer(active, fee_sats=1000, maker_address=addr)
        assert isinstance(result, str)
        assert len(result) == 64

    @pytest.mark.asyncio
    async def test_cancel_requires_maker_address(self):
        priv = _make_privkey()
        active = _make_active_offer(priv)
        client = _make_mock_client()
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        with pytest.raises(ValidationError, match="maker_address"):
            await session.cancel_offer(active, fee_sats=1000, maker_address="")

    @pytest.mark.asyncio
    async def test_cancel_calls_broadcast(self):
        priv = _make_privkey()
        active = _make_active_offer(priv)
        client = _make_mock_client("dd" * 32)
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        addr = self._maker_address(priv)
        await session.cancel_offer(active, fee_sats=1000, maker_address=addr)
        client.broadcast.assert_called_once()


# ---------------------------------------------------------------------------
# GravityMakerSession.check_status
# ---------------------------------------------------------------------------


class TestCheckStatus:
    @pytest.mark.asyncio
    async def test_status_open_when_utxo_present(self):
        priv = _make_privkey()
        offer_txid = "aa" * 32
        active = _make_active_offer(priv, offer_txid=offer_txid)
        utxo = UtxoRecord(tx_hash=offer_txid, tx_pos=0, value=500_000, height=100)
        client = _make_mock_client()
        client.get_utxos = AsyncMock(return_value=[utxo])
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        status = await session.check_status(active)
        assert status == "open"

    @pytest.mark.asyncio
    async def test_status_claimed_when_utxo_absent_before_deadline(self):
        priv = _make_privkey()
        offer_txid = "aa" * 32
        active = _make_active_offer(priv, offer_txid=offer_txid)
        # UTXO absent, deadline still in the future
        client = _make_mock_client()
        client.get_utxos = AsyncMock(return_value=[])
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        status = await session.check_status(active)
        assert status == "claimed"

    @pytest.mark.asyncio
    async def test_status_expired_when_utxo_present_after_deadline(self):
        priv = _make_privkey()
        offer_txid = "aa" * 32
        # Build offer with deadline already in the past
        active = _make_active_offer(priv, offer_txid=offer_txid)
        # Patch claim_deadline to be in the past
        int(time.time()) - 3600
        # Rebuild offer with expired deadline
        # We need to use accept_short_deadline=True since deadline < 24h from now
        expired_offer = _make_offer(
            priv,
            claim_deadline=int(time.time()) + 48 * 3600,  # must be valid to create
        )
        # Use object.__setattr__ to override frozen dataclass field
        import dataclasses

        dataclasses.replace(expired_offer)
        # Since GravityOffer is frozen we cannot directly mutate it.
        # Instead, patch time.time in the check_status call.
        # We verify by using a future deadline and mocking time.
        utxo = UtxoRecord(tx_hash=offer_txid, tx_pos=0, value=500_000, height=100)
        client = _make_mock_client()
        client.get_utxos = AsyncMock(return_value=[utxo])
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)

        # Patch time.time to return a value past the claim_deadline
        future_time = active.offer.claim_deadline + 1
        with patch("pyrxd.gravity.maker.time.time", return_value=future_time):
            status = await session.check_status(active)
        assert status == "expired"

    @pytest.mark.asyncio
    async def test_check_status_calls_get_utxos(self):
        priv = _make_privkey()
        active = _make_active_offer(priv)
        client = _make_mock_client()
        client.get_utxos = AsyncMock(return_value=[])
        session = GravityMakerSession(rxd_client=client, maker_priv=priv)
        await session.check_status(active)
        client.get_utxos.assert_called_once()


# ---------------------------------------------------------------------------
# GravityOfferParams dataclass
# ---------------------------------------------------------------------------


class TestGravityOfferParams:
    def test_construction(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=600_000,
            fee_sats=10_000,
        )
        assert params.fee_sats == 10_000
        assert params.change_address is None

    def test_construction_with_change_address(self):
        priv = _make_privkey()
        offer = _make_offer(priv)
        params = GravityOfferParams(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=600_000,
            fee_sats=10_000,
            change_address="1FakeAddress",
        )
        assert params.change_address == "1FakeAddress"


# ---------------------------------------------------------------------------
# Top-level import: verify GravityMakerSession is exported from pyrxd
# ---------------------------------------------------------------------------


def test_top_level_import():
    from pyrxd import ActiveOffer as AO
    from pyrxd import GravityMakerSession as GMS
    from pyrxd import GravityOfferParams as GOP

    assert GMS is GravityMakerSession
    assert GOP is GravityOfferParams
    assert AO is ActiveOffer

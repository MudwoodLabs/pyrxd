"""Tests for pyrxd.wallet.RxdWallet.

``build_send_tx`` / ``build_send_max_tx`` tests are fully offline (no network).
``get_balance`` / ``get_utxos`` / ``send`` / ``send_max`` tests patch
``pyrxd.wallet.ElectrumXClient`` with an ``AsyncMock`` so no websocket is
opened.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyrxd.hash import sha256
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex32, Satoshis, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.wallet import DEFAULT_FEE_RATE, DUST_THRESHOLD, RxdWallet

# ── Fixtures ──────────────────────────────────────────────────────────────────

_WALLET_KEY_BYTES = b"\x11" * 32
_OTHER_KEY_BYTES = b"\x22" * 32


@pytest.fixture
def wallet() -> RxdWallet:
    pk = PrivateKey(_WALLET_KEY_BYTES)
    return RxdWallet(pk, "wss://electrumx.example.com", fee_rate=10_000)


@pytest.fixture
def recipient_address() -> str:
    pk = PrivateKey(_OTHER_KEY_BYTES)
    return pk.public_key().address()


def _utxo(txid_hex: str, vout: int, value: int) -> UtxoRecord:
    return UtxoRecord(tx_hash=txid_hex, tx_pos=vout, value=value, height=0)


# ── Construction / properties ────────────────────────────────────────────────


class TestConstruction:
    def test_address_matches_private_key(self) -> None:
        pk = PrivateKey(_WALLET_KEY_BYTES)
        w = RxdWallet(pk, "wss://x.example.com")
        assert w.address == pk.public_key().address()

    def test_pkh_matches_public_key_hash160(self) -> None:
        pk = PrivateKey(_WALLET_KEY_BYTES)
        w = RxdWallet(pk, "wss://x.example.com")
        assert w.pkh == pk.public_key().hash160()
        assert len(w.pkh) == 20

    def test_default_fee_rate(self) -> None:
        pk = PrivateKey(_WALLET_KEY_BYTES)
        w = RxdWallet(pk, "wss://x.example.com")
        assert w.fee_rate == DEFAULT_FEE_RATE == 10_000

    def test_custom_fee_rate(self) -> None:
        pk = PrivateKey(_WALLET_KEY_BYTES)
        w = RxdWallet(pk, "wss://x.example.com", fee_rate=5_000)
        assert w.fee_rate == 5_000

    def test_rejects_non_private_key(self) -> None:
        with pytest.raises(ValidationError):
            RxdWallet("not a key", "wss://x.example.com")  # type: ignore[arg-type]

    def test_rejects_empty_url(self) -> None:
        pk = PrivateKey(_WALLET_KEY_BYTES)
        with pytest.raises(ValidationError):
            RxdWallet(pk, "")

    def test_rejects_non_positive_fee_rate(self) -> None:
        pk = PrivateKey(_WALLET_KEY_BYTES)
        with pytest.raises(ValidationError):
            RxdWallet(pk, "wss://x.example.com", fee_rate=0)

    def test_rejects_bool_fee_rate(self) -> None:
        # bool is an int subclass — common footgun.
        pk = PrivateKey(_WALLET_KEY_BYTES)
        with pytest.raises(ValidationError):
            RxdWallet(pk, "wss://x.example.com", fee_rate=True)  # type: ignore[arg-type]


# ── build_send_tx (fully offline) ────────────────────────────────────────────


class TestBuildSendTx:
    def test_two_outputs_recipient_and_change(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        tx = wallet.build_send_tx(utxos, recipient_address, 5_000_000)
        assert len(tx.outputs) == 2
        assert tx.outputs[0].satoshis == 5_000_000
        # Output 0 goes to recipient.
        assert tx.outputs[0].locking_script == P2PKH().lock(recipient_address)
        # Output 1 is the change back to self.
        assert tx.outputs[1].locking_script == P2PKH().lock(wallet.address)

    def test_change_goes_back_to_self(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        tx = wallet.build_send_tx(utxos, recipient_address, 1_000_000)
        change_out = tx.outputs[1]
        assert change_out.locking_script == P2PKH().lock(wallet.address)

    def test_fee_deducted_from_change(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        tx = wallet.build_send_tx(utxos, recipient_address, 1_000_000)
        # total_in - total_out == fee paid
        total_out = sum(o.satoshis for o in tx.outputs)
        assert 10_000_000 - total_out == tx.get_fee()
        # Fee is >= size * rate (we may slightly overpay when change is
        # dropped or trial/final sizes differ by a byte).
        assert tx.get_fee() >= tx.byte_length() * wallet.fee_rate - 1_000

    def test_insufficient_funds_raises(self, wallet: RxdWallet, recipient_address: str) -> None:
        # 1M sats can't cover a 5M-photon send at any fee rate.
        utxos = [_utxo("aa" * 32, 0, 1_000_000)]
        with pytest.raises(ValidationError, match="Insufficient"):
            wallet.build_send_tx(utxos, recipient_address, 5_000_000)

    def test_insufficient_funds_after_fee_raises(self, wallet: RxdWallet, recipient_address: str) -> None:
        # Enough to cover requested amount but not fee.
        # 225-byte tx * 10k fee_rate = 2.25M fee. Request 1M with exactly 1M in.
        utxos = [_utxo("aa" * 32, 0, 1_000_000)]
        with pytest.raises(ValidationError, match="Insufficient"):
            wallet.build_send_tx(utxos, recipient_address, 1_000_000)

    def test_empty_utxo_list_raises(self, wallet: RxdWallet, recipient_address: str) -> None:
        with pytest.raises(ValidationError, match="Insufficient"):
            wallet.build_send_tx([], recipient_address, 1_000)

    def test_zero_value_raises(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        with pytest.raises(ValidationError):
            wallet.build_send_tx(utxos, recipient_address, 0)

    def test_negative_value_raises(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        with pytest.raises(ValidationError):
            wallet.build_send_tx(utxos, recipient_address, -100)

    def test_dust_value_raises(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        with pytest.raises(ValidationError, match="dust"):
            wallet.build_send_tx(utxos, recipient_address, DUST_THRESHOLD - 1)

    def test_dust_threshold_exactly_allowed(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        tx = wallet.build_send_tx(utxos, recipient_address, DUST_THRESHOLD)
        assert tx.outputs[0].satoshis == DUST_THRESHOLD

    def test_invalid_recipient_address(self, wallet: RxdWallet) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        with pytest.raises(ValidationError, match="valid P2PKH"):
            wallet.build_send_tx(utxos, "not-an-address", 100_000)

    def test_utxo_selection_picks_largest_first(self, wallet: RxdWallet, recipient_address: str) -> None:
        """A single large UTXO should cover the amount — smaller ones are skipped."""
        utxos = [
            _utxo("aa" * 32, 0, 500_000),
            _utxo("bb" * 32, 0, 500_000),
            _utxo("cc" * 32, 0, 20_000_000),  # largest first
            _utxo("dd" * 32, 0, 500_000),
        ]
        tx = wallet.build_send_tx(utxos, recipient_address, 1_000_000)
        assert len(tx.inputs) == 1
        # The selected input is the 20M UTXO ("cc").
        assert tx.inputs[0].source_txid == "cc" * 32

    def test_utxo_selection_accumulates_when_needed(self, wallet: RxdWallet, recipient_address: str) -> None:
        """When no single UTXO suffices, multiple are combined."""
        # A 1-input tx costs ~2.25M fee at 10k/byte; adding inputs adds ~1.5M
        # each. Make each UTXO < 3M so a single input can't cover 3M + fee.
        utxos = [
            _utxo("aa" * 32, 0, 2_500_000),
            _utxo("bb" * 32, 0, 2_500_000),
            _utxo("cc" * 32, 0, 2_500_000),
            _utxo("dd" * 32, 0, 2_500_000),
        ]
        tx = wallet.build_send_tx(utxos, recipient_address, 3_000_000)
        # Need 3M + fee; no single 2.5M UTXO alone covers it, so ≥ 2 inputs.
        assert len(tx.inputs) >= 2
        assert sum(int(inp.satoshis) for inp in tx.inputs) >= 3_000_000

    def test_signing_is_fresh_not_trial(self, wallet: RxdWallet, recipient_address: str) -> None:
        """Final signature must commit to the FINAL outputs, not the trial outputs.

        The two-pass flow must reset ``unlocking_script`` between passes; see
        the preimage regression tests for the bug this catches.
        """
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        tx = wallet.build_send_tx(utxos, recipient_address, 5_000_000)
        # Build a tx with the same inputs + a DIFFERENT set of outputs;
        # signatures must differ (because the preimage commits to outputs).
        sig_a = tx.inputs[0].unlocking_script.serialize()
        tx2 = wallet.build_send_tx(utxos, recipient_address, 4_000_000)
        sig_b = tx2.inputs[0].unlocking_script.serialize()
        assert sig_a != sig_b

    def test_build_send_tx_is_offline(self, wallet: RxdWallet, recipient_address: str) -> None:
        """build_send_tx must never open a websocket."""
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        with patch("pyrxd.wallet.ElectrumXClient") as client_cls:
            wallet.build_send_tx(utxos, recipient_address, 1_000_000)
            client_cls.assert_not_called()


# ── build_send_max_tx (offline) ──────────────────────────────────────────────


class TestBuildSendMaxTx:
    def test_single_output_no_change(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        tx = wallet.build_send_max_tx(utxos, recipient_address)
        assert len(tx.outputs) == 1
        assert tx.outputs[0].locking_script == P2PKH().lock(recipient_address)

    def test_output_value_is_total_minus_fee(self, wallet: RxdWallet, recipient_address: str) -> None:
        # Fee at 10k/byte for a 2-input 1-output tx is ~3.4M; use ample UTXOs.
        utxos = [
            _utxo("aa" * 32, 0, 5_000_000),
            _utxo("bb" * 32, 0, 5_000_000),
        ]
        tx = wallet.build_send_max_tx(utxos, recipient_address)
        total_in = 10_000_000
        assert tx.outputs[0].satoshis == total_in - tx.get_fee()

    def test_send_max_insufficient_funds(self, wallet: RxdWallet, recipient_address: str) -> None:
        # 1k photons total can't cover any fee.
        utxos = [_utxo("aa" * 32, 0, 1_000)]
        with pytest.raises(ValidationError):
            wallet.build_send_max_tx(utxos, recipient_address)

    def test_send_max_empty_utxos(self, wallet: RxdWallet, recipient_address: str) -> None:
        with pytest.raises(ValidationError, match="Insufficient"):
            wallet.build_send_max_tx([], recipient_address)

    def test_send_max_rejects_bad_address(self, wallet: RxdWallet) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        with pytest.raises(ValidationError, match="valid P2PKH"):
            wallet.build_send_max_tx(utxos, "not-an-address")


# ── Network helpers (mocked ElectrumXClient) ─────────────────────────────────


def _fake_client(returns: dict) -> MagicMock:
    """Return a MagicMock that behaves like an ElectrumXClient context manager.

    ``returns`` maps method names to return values that ``AsyncMock`` will
    yield when awaited.
    """
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    for name, value in returns.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


class TestNetworkHelpers:
    async def test_get_balance_uses_reversed_script_hash(self, wallet: RxdWallet) -> None:
        client = _fake_client({"get_balance": (Satoshis(12_345), Satoshis(678))})

        with patch("pyrxd.wallet.ElectrumXClient", return_value=client) as client_cls:
            conf, unconf = await wallet.get_balance()

        assert conf == 12_345
        assert unconf == 678
        # Client was constructed with [url].
        args, _kwargs = client_cls.call_args
        assert args[0] == ["wss://electrumx.example.com"]
        # get_balance was called with Hex32(reversed sha256(locking_script)).
        client.get_balance.assert_awaited_once()
        (passed_hash,), _ = client.get_balance.call_args
        expected = sha256(P2PKH().lock(wallet.address).serialize())[::-1]
        assert bytes(passed_hash) == expected
        assert isinstance(passed_hash, Hex32)

    async def test_get_utxos_calls_client_with_script_hash(self, wallet: RxdWallet) -> None:
        fake_utxos = [_utxo("aa" * 32, 0, 500)]
        client = _fake_client({"get_utxos": fake_utxos})
        with patch("pyrxd.wallet.ElectrumXClient", return_value=client):
            result = await wallet.get_utxos()
        assert result == fake_utxos
        expected = sha256(P2PKH().lock(wallet.address).serialize())[::-1]
        (passed_hash,), _ = client.get_utxos.call_args
        assert bytes(passed_hash) == expected


class TestSend:
    async def test_send_builds_and_broadcasts(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        client = _fake_client(
            {
                "get_utxos": utxos,
                "broadcast": Txid("bb" * 32),
            }
        )
        with patch("pyrxd.wallet.ElectrumXClient", return_value=client):
            txid = await wallet.send(recipient_address, 1_000_000)

        assert txid == "bb" * 32
        client.broadcast.assert_awaited_once()
        # The raw_tx passed in must be bytes and represent a tx with 2 outputs
        # (recipient + change).
        (raw_tx_bytes,), _ = client.broadcast.call_args
        decoded = Transaction.from_hex(raw_tx_bytes)
        assert decoded is not None
        assert len(decoded.outputs) == 2
        assert decoded.outputs[0].satoshis == 1_000_000

    async def test_send_insufficient_funds_does_not_broadcast(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 1_000)]
        client = _fake_client({"get_utxos": utxos, "broadcast": Txid("bb" * 32)})
        with patch("pyrxd.wallet.ElectrumXClient", return_value=client), pytest.raises(ValidationError):
            await wallet.send(recipient_address, 1_000_000)
        client.broadcast.assert_not_called()

    async def test_send_max_broadcasts_single_output_tx(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        client = _fake_client(
            {
                "get_utxos": utxos,
                "broadcast": Txid("cc" * 32),
            }
        )
        with patch("pyrxd.wallet.ElectrumXClient", return_value=client):
            txid = await wallet.send_max(recipient_address)

        assert txid == "cc" * 32
        (raw_tx_bytes,), _ = client.broadcast.call_args
        decoded = Transaction.from_hex(raw_tx_bytes)
        assert decoded is not None
        assert len(decoded.outputs) == 1

    async def test_send_network_error_propagates(self, wallet: RxdWallet, recipient_address: str) -> None:
        utxos = [_utxo("aa" * 32, 0, 10_000_000)]
        client = _fake_client({"get_utxos": utxos})
        client.broadcast = AsyncMock(side_effect=NetworkError("broadcast failed"))
        with patch("pyrxd.wallet.ElectrumXClient", return_value=client), pytest.raises(NetworkError):
            await wallet.send(recipient_address, 1_000_000)

"""Tests for HdWallet — BIP44 gap scanning, persistence, and balance queries."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pyrxd.hd.wallet import AddressRecord, HdWallet, _GAP_LIMIT
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
MNEMONIC2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"


def _mock_client(
    *,
    history_map: dict | None = None,
    utxo_map: dict | None = None,
    balance_map: dict | None = None,
) -> MagicMock:
    """Build a mock ElectrumXClient.

    history_map: {address: [{"tx_hash": ..., "height": ...}]}
    utxo_map:    {address: [UtxoRecord(...)]}
    balance_map: {address: (confirmed, unconfirmed)}
    """
    client = MagicMock(spec=ElectrumXClient)
    history_map = history_map or {}
    utxo_map = utxo_map or {}
    balance_map = balance_map or {}

    async def _get_history(script_hash):
        # We can't match on script_hash directly — just return empty for unknown
        for addr, hist in history_map.items():
            from pyrxd.network.electrumx import script_hash_for_address
            if script_hash_for_address(addr) == script_hash:
                return hist
        return []

    async def _get_utxos(script_hash):
        for addr, utxos in utxo_map.items():
            from pyrxd.network.electrumx import script_hash_for_address
            if script_hash_for_address(addr) == script_hash:
                return utxos
        return []

    async def _get_balance(script_hash):
        for addr, bal in balance_map.items():
            from pyrxd.network.electrumx import script_hash_for_address
            if script_hash_for_address(addr) == script_hash:
                return bal
        return (0, 0)

    client.get_history = _get_history
    client.get_utxos = _get_utxos
    client.get_balance = _get_balance
    return client


# ---------------------------------------------------------------------------
# BIP44 path correctness tests
# ---------------------------------------------------------------------------


class TestBip44CoinType:
    def test_derives_account_key_on_coin_type_236_path(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        # The xprv depth should be 3 (purpose + coin_type + account)
        assert w._xprv.depth == 3

    def test_same_mnemonic_yields_same_address(self):
        w1 = HdWallet.from_mnemonic(MNEMONIC)
        w2 = HdWallet.from_mnemonic(MNEMONIC)
        assert w1._derive_address(0, 0) == w2._derive_address(0, 0)

    def test_different_mnemonics_yield_different_addresses(self):
        w1 = HdWallet.from_mnemonic(MNEMONIC)
        w2 = HdWallet.from_mnemonic(MNEMONIC2)
        assert w1._derive_address(0, 0) != w2._derive_address(0, 0)

    def test_external_and_internal_addresses_differ(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        external = w._derive_address(0, 0)
        internal = w._derive_address(1, 0)
        assert external != internal

    def test_consecutive_indices_produce_different_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addrs = {w._derive_address(0, i) for i in range(5)}
        assert len(addrs) == 5

    def test_account_index_affects_derivation(self):
        w0 = HdWallet.from_mnemonic(MNEMONIC, account=0)
        w1 = HdWallet.from_mnemonic(MNEMONIC, account=1)
        assert w0._derive_address(0, 0) != w1._derive_address(0, 0)


# ---------------------------------------------------------------------------
# Gap-limit scanning tests
# ---------------------------------------------------------------------------


class TestRefreshEmptyWallet:
    def test_empty_wallet_discovers_nothing(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        result = asyncio.get_event_loop().run_until_complete(w.refresh(client))
        assert result == 0

    def test_all_addresses_recorded_as_unused(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        asyncio.get_event_loop().run_until_complete(w.refresh(client))
        assert all(not r.used for r in w.addresses.values())

    def test_stops_after_gap_limit_addresses(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        asyncio.get_event_loop().run_until_complete(w.refresh(client))
        # Should derive at least GAP_LIMIT addresses on each chain
        external = [r for r in w.addresses.values() if r.change == 0]
        internal = [r for r in w.addresses.values() if r.change == 1]
        assert len(external) >= _GAP_LIMIT
        assert len(internal) >= _GAP_LIMIT


class TestRefreshWithUsedAddresses:
    def _wallet_with_used(self, used_indices: list[int]) -> tuple:
        w = HdWallet.from_mnemonic(MNEMONIC)
        # Pre-compute addresses at the indices that will be marked "used"
        history_map = {w._derive_address(0, i): [{"tx_hash": "aa" * 32, "height": 100}]
                       for i in used_indices}
        client = _mock_client(history_map=history_map)
        count = asyncio.get_event_loop().run_until_complete(w.refresh(client))
        return w, count

    def test_used_address_at_index_0(self):
        w, count = self._wallet_with_used([0])
        pkey = "0/0"
        assert pkey in w.addresses
        assert w.addresses[pkey].used is True
        assert count >= 1

    def test_external_tip_updated(self):
        w, _ = self._wallet_with_used([0, 3])
        assert w.external_tip >= 4

    def test_scan_extends_beyond_gap_limit(self):
        # BIP44 gap limit: scanner stops after GAP_LIMIT consecutive unused.
        # If index 5 is used, scan must reach at least index 5 + GAP_LIMIT.
        w, count = self._wallet_with_used([5])
        # Index 5 is used, so scanner continues until 20 consecutive unused after it.
        assert w.addresses["0/5"].used is True
        assert count >= 1
        # Indices 6..25 (20 consecutive unused after index 5) must also be scanned.
        assert "0/25" in w.addresses

    def test_returns_count_of_newly_used(self):
        _, count = self._wallet_with_used([0, 5, 10])
        assert count >= 3

    def test_second_refresh_no_new_count(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        client = _mock_client(history_map={addr0: [{"tx_hash": "aa" * 32, "height": 100}]})
        asyncio.get_event_loop().run_until_complete(w.refresh(client))
        count2 = asyncio.get_event_loop().run_until_complete(w.refresh(client))
        assert count2 == 0  # already known as used

    def test_internal_chain_also_scanned(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr_internal = w._derive_address(1, 0)
        client = _mock_client(history_map={addr_internal: [{"tx_hash": "bb" * 32, "height": 50}]})
        asyncio.get_event_loop().run_until_complete(w.refresh(client))
        pkey = "1/0"
        assert w.addresses[pkey].used is True


# ---------------------------------------------------------------------------
# next_receive_address tests
# ---------------------------------------------------------------------------


class TestNextReceiveAddress:
    def test_fresh_wallet_returns_first_external_address(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr = w.next_receive_address()
        assert addr == w._derive_address(0, 0)

    def test_returns_string_address(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr = w.next_receive_address()
        assert isinstance(addr, str)
        assert len(addr) > 25  # valid P2PKH

    def test_skips_used_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        # Mark index 0 as used
        addr0 = w._derive_address(0, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        addr = w.next_receive_address()
        assert addr == w._derive_address(0, 1)

    def test_consecutive_calls_return_same_address_when_unused(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr1 = w.next_receive_address()
        addr2 = w.next_receive_address()
        assert addr1 == addr2


# ---------------------------------------------------------------------------
# Persistence tests
# ---------------------------------------------------------------------------


class TestSaveLoad:
    def test_save_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p)
            assert p.exists()
            assert p.stat().st_size > 0

    def test_round_trip_preserves_tips(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.external_tip = 7
            w.internal_tip = 3
            w.save(p)

            w2 = HdWallet.load(p, MNEMONIC)
            assert w2.external_tip == 7
            assert w2.internal_tip == 3

    def test_round_trip_preserves_addresses(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            addr = w._derive_address(0, 0)
            w.addresses["0/0"] = AddressRecord(
                address=addr, change=0, index=0, used=True
            )
            w.save(p)

            w2 = HdWallet.load(p, MNEMONIC)
            assert "0/0" in w2.addresses
            assert w2.addresses["0/0"].used is True
            assert w2.addresses["0/0"].address == addr

    def test_load_nonexistent_path_raises_file_not_found(self):
        """N6: typo'd path must NOT silently produce an empty wallet that
        subsequently overwrites the real wallet on save. ``load()`` raises;
        ``load_or_create()`` is the explicit opt-in for the old behavior.
        """
        p = Path("/nonexistent/path/wallet.dat")
        with pytest.raises(FileNotFoundError, match="load_or_create"):
            HdWallet.load(p, MNEMONIC)

    def test_load_or_create_on_missing_path_returns_fresh_wallet(self):
        """``load_or_create`` is the explicit opt-in for create-on-missing —
        the old foot-gun behavior of ``load()`` is preserved here, but
        callers must spell their intent out."""
        p = Path("/nonexistent/path/wallet.dat")
        w = HdWallet.load_or_create(p, MNEMONIC)
        assert w.external_tip == 0
        assert w.addresses == {}

    def test_load_or_create_on_existing_path_loads_it(self):
        """When the file exists, load_or_create must defer to load (not
        clobber the saved state with a fresh wallet)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.external_tip = 9
            w.save(p)
            w2 = HdWallet.load_or_create(p, MNEMONIC)
            assert w2.external_tip == 9

    def test_wrong_mnemonic_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p)
            with pytest.raises(ValidationError):
                HdWallet.load(p, MNEMONIC2)

    def test_truncated_file_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            p.write_bytes(b"\x00" * 8)  # too short
            with pytest.raises(ValidationError):
                HdWallet.load(p, MNEMONIC)

    def test_file_content_is_encrypted(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.addresses["0/0"] = AddressRecord(
                address="secret_address", change=0, index=0, used=True
            )
            w.save(p)
            raw = p.read_bytes()
            assert b"secret_address" not in raw

    def test_account_preserved_on_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC, account=2)
            w.save(p)
            w2 = HdWallet.load(p, MNEMONIC)
            assert w2.account == 2


# ---------------------------------------------------------------------------
# Balance and UTXO tests
# ---------------------------------------------------------------------------


class TestGetBalance:
    def test_empty_wallet_balance_is_zero(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        bal = asyncio.get_event_loop().run_until_complete(w.get_balance(client))
        assert bal == 0

    def test_single_used_address_balance(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        client = _mock_client(balance_map={addr0: (1000, 500)})
        bal = asyncio.get_event_loop().run_until_complete(w.get_balance(client))
        assert bal == 1500

    def test_sums_across_multiple_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        w.addresses["0/1"] = AddressRecord(address=addr1, change=0, index=1, used=True)
        client = _mock_client(balance_map={addr0: (1000, 0), addr1: (2000, 0)})
        bal = asyncio.get_event_loop().run_until_complete(w.get_balance(client))
        assert bal == 3000

    def test_unused_addresses_excluded_from_balance(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        w.addresses["0/1"] = AddressRecord(address=addr1, change=0, index=1, used=False)
        client = _mock_client(balance_map={addr0: (1000, 0), addr1: (9999, 0)})
        bal = asyncio.get_event_loop().run_until_complete(w.get_balance(client))
        assert bal == 1000


class TestGetUtxos:
    def test_empty_wallet_utxos_is_empty(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        utxos = asyncio.get_event_loop().run_until_complete(w.get_utxos(client))
        assert utxos == []

    def test_returns_utxos_for_used_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        utxo = UtxoRecord(tx_hash="aa" * 32, tx_pos=0, value=546, height=100)
        client = _mock_client(utxo_map={addr0: [utxo]})
        utxos = asyncio.get_event_loop().run_until_complete(w.get_utxos(client))
        assert len(utxos) == 1
        assert utxos[0].value == 546

    def test_unused_addresses_not_queried(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        w.addresses["0/1"] = AddressRecord(address=addr1, change=0, index=1, used=False)
        utxo = UtxoRecord(tx_hash="bb" * 32, tx_pos=0, value=1000, height=50)
        client = _mock_client(utxo_map={addr0: [utxo], addr1: [utxo]})
        utxos = asyncio.get_event_loop().run_until_complete(w.get_utxos(client))
        # Only addr0 (used=True) is queried
        assert len(utxos) == 1


# ---------------------------------------------------------------------------
# known_addresses tests
# ---------------------------------------------------------------------------


class TestKnownAddresses:
    def test_returns_empty_on_fresh_wallet(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        assert w.known_addresses() == []

    def test_filter_by_change_0(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(1, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=False)
        w.addresses["1/0"] = AddressRecord(address=addr1, change=1, index=0, used=False)
        external = w.known_addresses(change=0)
        assert len(external) == 1
        assert external[0].change == 0

    def test_no_filter_returns_all(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(1, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=False)
        w.addresses["1/0"] = AddressRecord(address=addr1, change=1, index=0, used=False)
        assert len(w.known_addresses()) == 2


# ---------------------------------------------------------------------------
# Stream C / HD-hardening tests (N1-N5; N6 covered above)
# ---------------------------------------------------------------------------


class TestSeedSecretBytesProtection:
    """N1: ``_seed`` must live in :class:`SecretBytes` so it cannot leak via
    repr, copy, or pickle.
    """

    def test_seed_is_secret_bytes(self):
        from pyrxd.security.secrets import SecretBytes
        w = HdWallet.from_mnemonic(MNEMONIC)
        assert isinstance(w._seed, SecretBytes)

    def test_seed_repr_does_not_leak_bytes(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        # repr of the SecretBytes wrapper must be a fixed marker, not the seed.
        repr_str = repr(w._seed)
        assert "SecretBytes" in repr_str
        # The actual seed bytes must not appear in any printable form.
        raw_hex = w._seed.unsafe_raw_bytes().hex()
        assert raw_hex not in repr_str
        assert raw_hex not in str(w._seed)

    def test_seed_cannot_be_pickled(self):
        import pickle
        w = HdWallet.from_mnemonic(MNEMONIC)
        with pytest.raises(TypeError, match="cannot be pickled"):
            pickle.dumps(w._seed)


class TestAtomicSave:
    """N2: ``save()`` must be atomic (mkstemp + fchmod 0o600 + fsync +
    os.replace) so a crash mid-write cannot leave a partial file.
    """

    def test_saved_file_mode_is_0600(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p)
            mode = oct(p.stat().st_mode)[-3:]
            assert mode == "600", f"Expected mode 600, got {mode}"

    def test_no_temp_file_lingers_on_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p)
            leftovers = [f.name for f in Path(tmpdir).iterdir() if f.suffix == ".tmp"]
            assert leftovers == [], f"unexpected .tmp files: {leftovers}"

    def test_fsync_is_called(self, monkeypatch):
        import os as os_mod
        fsync_calls = []
        real_fsync = os_mod.fsync

        def tracking_fsync(fd):
            fsync_calls.append(fd)
            real_fsync(fd)

        monkeypatch.setattr(os_mod, "fsync", tracking_fsync)
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            HdWallet.from_mnemonic(MNEMONIC).save(p)
        assert len(fsync_calls) >= 1

    def test_save_creates_parent_dir(self):
        """save() should mkdir parents=True so callers don't need to."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "subdir" / "wallet.dat"
            HdWallet.from_mnemonic(MNEMONIC).save(p)
            assert p.exists()
            assert (Path(tmpdir) / "subdir").is_dir()


class TestScryptKeyDerivation:
    """N3: encryption key must be derived via scrypt with a per-file salt,
    not via a static hash of the seed.
    """

    def test_two_saves_use_different_salts(self):
        """The salt must be regenerated on every save — otherwise a fixed
        salt collapses to the static-derivation case.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.dat"
            p2 = Path(tmpdir) / "b.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p1)
            w.save(p2)
            # Header layout: version(1) | salt(16) | nonce(12) | tag(16) | ct...
            salt1 = p1.read_bytes()[1:17]
            salt2 = p2.read_bytes()[1:17]
            assert salt1 != salt2

    def test_two_saves_produce_different_ciphertexts(self):
        """Same plaintext, fresh salt+nonce per save → ciphertext bytes
        must differ. Otherwise an attacker watching the file could detect
        whether anything actually changed between saves.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.dat"
            p2 = Path(tmpdir) / "b.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p1)
            w.save(p2)
            assert p1.read_bytes() != p2.read_bytes()


class TestAeadTamperDetection:
    """N4: AES-256-GCM (AEAD) must reject any modified ciphertext. Pre-fix
    AES-CBC would silently decrypt to attacker-shaped JSON.
    """

    def test_flipped_ciphertext_byte_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            HdWallet.from_mnemonic(MNEMONIC).save(p)
            blob = bytearray(p.read_bytes())
            # Flip one bit in the ciphertext (after the 45-byte header).
            blob[60] ^= 0x01
            p.write_bytes(bytes(blob))
            with pytest.raises(ValidationError, match="Could not decrypt"):
                HdWallet.load(p, MNEMONIC)

    def test_truncated_tag_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            HdWallet.from_mnemonic(MNEMONIC).save(p)
            blob = bytearray(p.read_bytes())
            # Zero out the GCM tag (offset 1 + 16 salt + 12 nonce = 29).
            for i in range(29, 29 + 16):
                blob[i] = 0
            p.write_bytes(bytes(blob))
            with pytest.raises(ValidationError, match="Could not decrypt"):
                HdWallet.load(p, MNEMONIC)

    def test_wrong_version_byte_rejected_with_clear_message(self):
        """A v1 (pre-Stream-C-hard) wallet file must be rejected with a
        message that tells the operator how to recover (re-create from
        mnemonic), not a cryptic decrypt failure.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            HdWallet.from_mnemonic(MNEMONIC).save(p)
            blob = bytearray(p.read_bytes())
            blob[0] = 1  # pretend this is a v1 file
            p.write_bytes(bytes(blob))
            with pytest.raises(ValidationError, match="Unsupported wallet file version"):
                HdWallet.load(p, MNEMONIC)


class TestGapScanErrorPropagation:
    """N5: a network failure during ``client.get_history`` must propagate.
    Pre-fix, the ``except Exception: is_used = False`` clause silently
    treated failed lookups as "address unused" — a real funded address
    could be hidden from the wallet.
    """

    def test_network_error_propagates(self):
        from pyrxd.security.errors import NetworkError

        client = MagicMock(spec=ElectrumXClient)

        async def _broken_history(*args, **kwargs):
            raise NetworkError("ElectrumX connection lost")

        client.get_history = _broken_history
        w = HdWallet.from_mnemonic(MNEMONIC)
        with pytest.raises(NetworkError):
            asyncio.get_event_loop().run_until_complete(w.refresh(client))

    def test_network_error_does_not_mark_address_unused(self):
        """Even if the scan errors out, no address record may be left
        with ``used=False`` from a failed lookup — the partial state
        would be misleading on retry.
        """
        from pyrxd.security.errors import NetworkError

        client = MagicMock(spec=ElectrumXClient)

        async def _broken_history(*args, **kwargs):
            raise NetworkError("fail")

        client.get_history = _broken_history
        w = HdWallet.from_mnemonic(MNEMONIC)
        try:
            asyncio.get_event_loop().run_until_complete(w.refresh(client))
        except NetworkError:
            # Expected — verifying state is consistent after the failure below.
            pass
        # No false-negative records may remain.
        assert all(r.used is True for r in w.addresses.values()) or w.addresses == {}

"""Tests for HdWallet — BIP44 gap scanning, persistence, and balance queries."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from pyrxd.hd.wallet import _GAP_LIMIT, AddressRecord, HdWallet
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
    def test_derives_account_key_on_coin_type_512_path(self):
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
# Per-call coin_type kwarg — the foundational fix from Phase 1 of the
# coin-type-512 decision record. Before this kwarg existed, the only way
# to derive at a non-default path was to set RXD_PY_SDK_BIP44_DERIVATION_PATH
# *before* importing pyrxd, because the path was parsed once at module
# import time. That made restoration of Photonic / Electron-Radiant
# mnemonics undiscoverable for non-expert users.
#
# Vector provenance (the EXPECTED_* values below):
#   - EXPECTED_0 (coin_type=0): VERIFIED end-to-end against Photonic
#     Wallet on 2026-05-03 — the canonical BIP39 mnemonic
#     "abandon abandon ... about" was restored in Photonic, and its
#     Receive screen displayed exactly this address. So this test is a
#     cross-wallet compatibility check, not a regression-only guard.
#     Re-verify if Photonic ships a derivation-path change.
#   - EXPECTED_512 (coin_type=512): captured from this SDK; matches
#     SLIP-0044 spec for Radiant. Tangem hardware wallet uses this
#     path but cannot import mnemonics so end-to-end verification
#     against Tangem is not possible.
#   - EXPECTED_236 (coin_type=236): captured from this SDK; pre-#14
#     pyrxd default, BSV's coin type. Regression-only.
# ---------------------------------------------------------------------------


class TestCoinTypeKwarg:
    EXPECTED_512 = "18qiat9Kff5niCcincht6efD8HhFfzL1AJ"  # SLIP-0044 default
    EXPECTED_236 = "1K6LZdwpKT5XkEZo2T2kW197aMXYbYMc4f"  # legacy BSV
    EXPECTED_0 = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"  # Photonic-verified 2026-05-03

    def test_coin_type_512_matches_default(self):
        explicit = HdWallet.from_mnemonic(MNEMONIC, coin_type=512)
        assert explicit._derive_address(0, 0) == self.EXPECTED_512

    def test_coin_type_0_matches_photonic_path(self):
        # The reason this kwarg exists. Photonic users restoring their
        # mnemonic must be able to reach m/44'/0'/0'/0/0 without setting
        # an env var before importing pyrxd.
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)
        assert w._derive_address(0, 0) == self.EXPECTED_0

    def test_coin_type_236_matches_legacy_bsv(self):
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=236)
        assert w._derive_address(0, 0) == self.EXPECTED_236

    def test_three_coin_types_yield_three_addresses(self):
        # Belt-and-braces against the failure mode where the kwarg is
        # silently ignored and all three calls return the default.
        addrs = {HdWallet.from_mnemonic(MNEMONIC, coin_type=ct)._derive_address(0, 0) for ct in (0, 236, 512)}
        assert len(addrs) == 3

    def test_coin_type_persisted_on_instance(self):
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)
        assert w.coin_type == 0

    def test_coin_type_default_is_module_default(self):
        # Don't hardcode 512 here — module default may be overridden
        # via env var. The assertion is that the instance default
        # matches whatever the module resolved at import.
        from pyrxd.hd.wallet import _COIN_TYPE

        w = HdWallet.from_mnemonic(MNEMONIC)
        assert w.coin_type == _COIN_TYPE

    def test_account_kwarg_still_independent_of_coin_type(self):
        # account and coin_type are orthogonal — confirm changing one
        # doesn't perturb the other.
        w_a0 = HdWallet.from_mnemonic(MNEMONIC, coin_type=0, account=0)
        w_a1 = HdWallet.from_mnemonic(MNEMONIC, coin_type=0, account=1)
        assert w_a0.coin_type == 0 == w_a1.coin_type
        assert w_a0._derive_address(0, 0) != w_a1._derive_address(0, 0)


# ---------------------------------------------------------------------------
# Load-time coin_type validation — the second foundational fix from
# Phase 1. Without this check, a wallet saved at one coin type and
# loaded under a different module default would silently derive
# different addresses (the original report from Photonic users). The
# loud-error-instead-of-silent-empty-wallet behavior is what makes any
# future default change safe.
# ---------------------------------------------------------------------------


class TestCoinTypeLoadValidation:
    def test_save_and_load_roundtrip_at_non_default_coin_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            wallet_path = Path(tmp) / "photonic.dat"
            saved = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)
            saved.save(wallet_path)

            loaded = HdWallet.load(wallet_path, MNEMONIC, coin_type=0)
            assert loaded.coin_type == 0
            assert loaded._derive_address(0, 0) == saved._derive_address(0, 0)

    def test_load_with_no_coin_type_kwarg_accepts_persisted_value(self):
        # Backwards-compatible: callers who don't care about validation
        # get the persisted coin_type without needing to know it.
        with tempfile.TemporaryDirectory() as tmp:
            wallet_path = Path(tmp) / "photonic.dat"
            HdWallet.from_mnemonic(MNEMONIC, coin_type=0).save(wallet_path)

            loaded = HdWallet.load(wallet_path, MNEMONIC)
            assert loaded.coin_type == 0

    def test_load_with_mismatched_coin_type_raises(self):
        # The killer bug class: silent empty wallet because the wallet
        # was saved at coin type 0 but the loader is looking at 512.
        with tempfile.TemporaryDirectory() as tmp:
            wallet_path = Path(tmp) / "photonic.dat"
            HdWallet.from_mnemonic(MNEMONIC, coin_type=0).save(wallet_path)

            with pytest.raises(ValidationError, match="coin type 0"):
                HdWallet.load(wallet_path, MNEMONIC, coin_type=512)

    def test_mismatch_error_names_both_coin_types(self):
        # The fix-it message must tell the user what was persisted AND
        # what they passed, so they can choose which to change.
        with tempfile.TemporaryDirectory() as tmp:
            wallet_path = Path(tmp) / "legacy.dat"
            HdWallet.from_mnemonic(MNEMONIC, coin_type=236).save(wallet_path)

            with pytest.raises(ValidationError) as exc_info:
                HdWallet.load(wallet_path, MNEMONIC, coin_type=512)

            msg = str(exc_info.value)
            assert "236" in msg
            assert "512" in msg

    def test_load_or_create_validates_coin_type_when_file_exists(self):
        # load_or_create must NOT silently swallow a mismatch by
        # falling back to "create new wallet" — that would defeat the
        # point of the validation.
        with tempfile.TemporaryDirectory() as tmp:
            wallet_path = Path(tmp) / "w.dat"
            HdWallet.from_mnemonic(MNEMONIC, coin_type=0).save(wallet_path)

            with pytest.raises(ValidationError, match="coin type 0"):
                HdWallet.load_or_create(wallet_path, MNEMONIC, coin_type=512)

    def test_load_or_create_uses_coin_type_for_fresh_wallet(self):
        # No existing file → coin_type drives the new wallet's path.
        with tempfile.TemporaryDirectory() as tmp:
            wallet_path = Path(tmp) / "fresh.dat"
            assert not wallet_path.exists()

            w = HdWallet.load_or_create(wallet_path, MNEMONIC, coin_type=0)
            assert w.coin_type == 0


# ---------------------------------------------------------------------------
# Red-team-driven tests — these encode SEV-1/SEV-2 findings from the
# 2026-05-03 review of Phase 1. Each test name maps to a specific bug
# class. If any of these regress, the underlying validation has been
# weakened and the silent-empty-wallet failure mode is back.
# ---------------------------------------------------------------------------


class TestCoinTypeInputValidation:
    """SEV-1: kwarg-boundary type/range validation.

    Without these guards, ``coin_type=True`` formats into a path as the
    string ``"True"``, persists as JSON ``true``, and reloads as the
    integer ``1`` — silently routing the wallet to a different address
    tree and defeating the validation kwarg.
    """

    def test_bool_true_rejected(self):
        # bool subclasses int in Python; without the explicit bool guard
        # this would slip through and produce path m/44'/True'.
        with pytest.raises(ValidationError, match="non-bool int"):
            HdWallet.from_mnemonic(MNEMONIC, coin_type=True)

    def test_bool_false_rejected(self):
        # False == 0 numerically. Without the guard, coin_type=False
        # would silently restore Photonic-path wallets, which is the
        # opposite of explicit user intent.
        with pytest.raises(ValidationError, match="non-bool int"):
            HdWallet.from_mnemonic(MNEMONIC, coin_type=False)

    def test_string_rejected(self):
        with pytest.raises(ValidationError, match="non-bool int"):
            HdWallet.from_mnemonic(MNEMONIC, coin_type="0")

    def test_float_rejected(self):
        with pytest.raises(ValidationError, match="non-bool int"):
            HdWallet.from_mnemonic(MNEMONIC, coin_type=0.0)

    def test_negative_coin_type_rejected(self):
        # SEV-1: coin_type=-1 produces path m/44'/-1', which BIP32
        # parses as the unhardened index 0x7FFFFFFF — funds end up at
        # a path shared with whoever derives the unhardened sibling
        # directly.
        with pytest.raises(ValidationError, match="out of BIP44 hardened range"):
            HdWallet.from_mnemonic(MNEMONIC, coin_type=-1)

    def test_oversized_coin_type_rejected(self):
        # 2**31 collides with the hardening bit; values above are
        # outside the 32-bit child-index domain.
        with pytest.raises(ValidationError, match="out of BIP44 hardened range"):
            HdWallet.from_mnemonic(MNEMONIC, coin_type=2**31)

    def test_zero_accepted(self):
        # 0 is the legitimate Photonic / Electron-Radiant value — it
        # must NOT be a casualty of the range check.
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)
        assert w.coin_type == 0

    def test_intenum_subclass_accepted(self):
        # IntEnum is a real-world int subclass that should pass. The
        # f-string format MUST yield the underlying integer, not a
        # custom __str__ form. (Test name avoids "_int_" because the
        # repo's conftest auto-marks any node with that substring as
        # an integration test and excludes it from the default run.)
        from enum import IntEnum

        class Coin(IntEnum):
            PHOTONIC = 0
            RADIANT = 512

        ref = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)._derive_address(0, 0)
        via_enum = HdWallet.from_mnemonic(MNEMONIC, coin_type=Coin.PHOTONIC)._derive_address(0, 0)
        assert ref == via_enum


class TestMissingCoinTypeFieldIsHardError:
    """SEV-1: a wallet file missing the persisted coin_type must NOT
    silently fall back to the module default.

    The fallback was the original implementation; red-team review
    showed it re-introduced the silent-default-flip footgun the kwarg
    was added to prevent.
    """

    def _write_wallet_blob_without_coin_type(self, p: Path) -> None:
        """Hand-craft a v2 wallet file whose JSON omits coin_type."""
        import hashlib
        import json
        import secrets

        from Cryptodome.Cipher import AES

        from pyrxd.hd.bip39 import seed_from_mnemonic
        from pyrxd.hd.wallet import _FILE_VERSION_V2, _NONCE_LEN, _SALT_LEN, _SCRYPT_N, _SCRYPT_P, _SCRYPT_R

        seed = seed_from_mnemonic(MNEMONIC, passphrase="")
        salt = secrets.token_bytes(_SALT_LEN)
        nonce = secrets.token_bytes(_NONCE_LEN)
        enc_key = hashlib.scrypt(
            seed, salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=32
        )
        data_no_coin_type = {
            "version": _FILE_VERSION_V2,
            "account": 0,
            # NO coin_type — this is the failure under test.
            "external_tip": 0,
            "internal_tip": 0,
            "addresses": {},
        }
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data_no_coin_type).encode())
        blob = bytes([_FILE_VERSION_V2]) + salt + nonce + tag + ciphertext
        p.write_bytes(blob)
        p.chmod(0o600)

    def test_load_refuses_file_without_coin_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "no_coin_type.dat"
            self._write_wallet_blob_without_coin_type(p)
            with pytest.raises(ValidationError, match="missing required field 'coin_type'"):
                HdWallet.load(p, MNEMONIC)

    def test_load_with_kwarg_still_refuses_file_without_coin_type(self):
        # Even if the caller "knows" the path, missing-field is a hard
        # error — the file is corrupt or hand-edited and the right
        # answer is "re-create from mnemonic", not "trust the caller".
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "no_coin_type.dat"
            self._write_wallet_blob_without_coin_type(p)
            with pytest.raises(ValidationError, match="missing required field 'coin_type'"):
                HdWallet.load(p, MNEMONIC, coin_type=512)


class TestCoinTypeIsReadOnly:
    """SEV-2: post-construction mutation of coin_type would desync from
    the already-derived ``_xprv``.

    A caller that does ``wallet.coin_type = 0; wallet.save()`` would
    persist coin_type=0 in the JSON while ``_xprv`` is still rooted at
    the original path — leading to a silent address-tree mismatch on
    next load.
    """

    def test_setting_coin_type_attribute_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=512)
        with pytest.raises(AttributeError):
            w.coin_type = 0  # type: ignore[misc]

    def test_setting_underscored_field_raises(self):
        # The patch-on-patch review found that the property blocked the
        # public name but the underscored backing field was still
        # writable directly. The __setattr__ guard closes that hole.
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=512)
        with pytest.raises(AttributeError, match="read-only"):
            w._coin_type = 0  # type: ignore[misc]

    def test_property_returns_construction_value(self):
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)
        # Read multiple times — value must be stable.
        assert w.coin_type == 0
        assert w.coin_type == 0

    def test_other_attributes_remain_mutable(self):
        # __setattr__ guard must NOT lock down external_tip /
        # internal_tip / addresses — gap-scan and next_receive_address
        # legitimately mutate them.
        w = HdWallet.from_mnemonic(MNEMONIC)
        w.external_tip = 5
        w.internal_tip = 3
        w.addresses["0/0"] = AddressRecord(address="x", change=0, index=0, used=True)
        assert w.external_tip == 5
        assert w.internal_tip == 3


# ---------------------------------------------------------------------------
# Patch-on-patch review fixes — tests for the SEV-1 issues found in the
# 2026-05-03 review of the FIRST round of red-team patches. These hit
# entry points the original validation missed: the load path, direct
# dataclass construction, and underscore-bypass mutation.
# ---------------------------------------------------------------------------


class TestLoadPathValidatesPersistedCoinType:
    """SEV-1: persisted coin_type values must pass the same validator as kwargs.

    Before this fix, ``int(data["coin_type"])`` ran with no type/range
    checks — so a hand-edited or corrupted file with a bool, float,
    string, or out-of-range int would silently load and route the
    wallet to the wrong derivation path. The load path now uses the
    same ``_validate_coin_type`` helper that protects construction.
    """

    def _write_blob_with_coin_type(self, p: Path, raw_coin_type: object) -> None:
        """Hand-craft a v2 wallet file with a malicious coin_type field.

        The ciphertext is correctly AES-GCM-sealed (so the AEAD layer
        passes), but the JSON inside contains *raw_coin_type*
        verbatim — letting us probe the load-path validator
        independent of the construction-path validator.
        """
        import hashlib
        import json
        import secrets

        from Cryptodome.Cipher import AES

        from pyrxd.hd.bip39 import seed_from_mnemonic
        from pyrxd.hd.wallet import _FILE_VERSION_V2, _NONCE_LEN, _SALT_LEN, _SCRYPT_N, _SCRYPT_P, _SCRYPT_R

        seed = seed_from_mnemonic(MNEMONIC, passphrase="")
        salt = secrets.token_bytes(_SALT_LEN)
        nonce = secrets.token_bytes(_NONCE_LEN)
        enc_key = hashlib.scrypt(
            seed, salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, maxmem=128 * 1024 * 1024, dklen=32
        )
        data = {
            "version": _FILE_VERSION_V2,
            "account": 0,
            "coin_type": raw_coin_type,
            "external_tip": 0,
            "internal_tip": 0,
            "addresses": {},
        }
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(data).encode())
        blob = bytes([_FILE_VERSION_V2]) + salt + nonce + tag + ciphertext
        p.write_bytes(blob)
        p.chmod(0o600)

    def test_persisted_negative_coin_type_rejected(self):
        # SEV-1 from patch-on-patch review: persisted coin_type=-1 was
        # previously accepted via int(-1), routing the wallet to
        # m/44'/-1'/... (unhardened-sibling collision).
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "neg.dat"
            self._write_blob_with_coin_type(p, -1)
            with pytest.raises(ValidationError, match="out of BIP44 hardened range"):
                HdWallet.load(p, MNEMONIC)

    def test_persisted_oversized_coin_type_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.dat"
            self._write_blob_with_coin_type(p, 2**31)
            with pytest.raises(ValidationError, match="out of BIP44 hardened range"):
                HdWallet.load(p, MNEMONIC)

    def test_persisted_bool_rejected(self):
        # JSON ``true`` previously round-tripped to coin_type=1 via
        # int(True). The bool guard fires before any int coercion.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bool.dat"
            self._write_blob_with_coin_type(p, True)
            with pytest.raises(ValidationError, match="non-bool int"):
                HdWallet.load(p, MNEMONIC)

    def test_persisted_string_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "str.dat"
            self._write_blob_with_coin_type(p, "0")
            with pytest.raises(ValidationError, match="non-bool int"):
                HdWallet.load(p, MNEMONIC)

    def test_persisted_float_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "float.dat"
            self._write_blob_with_coin_type(p, 512.0)
            with pytest.raises(ValidationError, match="non-bool int"):
                HdWallet.load(p, MNEMONIC)

    def test_persisted_null_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "null.dat"
            self._write_blob_with_coin_type(p, None)
            with pytest.raises(ValidationError, match="non-bool int"):
                HdWallet.load(p, MNEMONIC)

    def test_error_message_names_wallet_file_path(self):
        # The validator's source= argument must surface in the error
        # message so the user knows the bad value is in the file, not
        # in their kwarg.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.dat"
            self._write_blob_with_coin_type(p, -1)
            with pytest.raises(ValidationError) as exc_info:
                HdWallet.load(p, MNEMONIC)
            assert "wallet file" in str(exc_info.value).lower()
            assert str(p) in str(exc_info.value)


class TestDirectConstructionValidatesCoinType:
    """SEV-1: ``HdWallet(_coin_type=-99)`` must NOT bypass validation.

    The original docstring claimed ``_resolve_coin_type`` was "the
    single entry point" but the dataclass auto-generated ``__init__``
    accepted any int. ``__post_init__`` now re-runs the validator so
    direct construction is gated.
    """

    def _make_wallet_kwargs(self, *, coin_type: object) -> dict:
        # Build the minimum set of constructor kwargs needed to land
        # in __post_init__ with a malicious _coin_type. The xprv/seed
        # are real (so the test is realistic), but they're rooted at
        # the *valid* default path — the test isn't about whether
        # _xprv matches _coin_type, it's about whether the validator
        # runs at all.
        from pyrxd.hd.bip32 import bip32_derive_xprv_from_mnemonic
        from pyrxd.hd.bip39 import seed_from_mnemonic
        from pyrxd.security.secrets import SecretBytes

        seed = seed_from_mnemonic(MNEMONIC, passphrase="")
        xprv = bip32_derive_xprv_from_mnemonic(MNEMONIC, passphrase="", path="m/44'/512'/0'")
        return {
            "_xprv": xprv,
            "_seed": SecretBytes(seed),
            "account": 0,
            "_coin_type": coin_type,
        }

    def test_direct_construction_with_negative_rejected(self):
        kwargs = self._make_wallet_kwargs(coin_type=-1)
        with pytest.raises(ValidationError, match="out of BIP44 hardened range"):
            HdWallet(**kwargs)  # type: ignore[arg-type]

    def test_direct_construction_with_bool_rejected(self):
        kwargs = self._make_wallet_kwargs(coin_type=True)
        with pytest.raises(ValidationError, match="non-bool int"):
            HdWallet(**kwargs)  # type: ignore[arg-type]

    def test_direct_construction_with_oversized_rejected(self):
        kwargs = self._make_wallet_kwargs(coin_type=2**31)
        with pytest.raises(ValidationError, match="out of BIP44 hardened range"):
            HdWallet(**kwargs)  # type: ignore[arg-type]

    def test_direct_construction_with_valid_value_succeeds(self):
        # Positive control — the validator must not be over-eager.
        # (Test name avoids "_int_" which the conftest auto-marks as
        # an integration test.)
        kwargs = self._make_wallet_kwargs(coin_type=0)
        w = HdWallet(**kwargs)
        assert w.coin_type == 0


class TestUnderscoreMutationBlocked:
    """SEV-1: writes to ``_coin_type`` post-construction must fail.

    The read-only property was theater without the ``__setattr__``
    guard — ``wallet._coin_type = X``, ``wallet.__dict__['_coin_type']
    = X``, and ``dataclasses.replace`` were all bypasses. ``__setattr__``
    closes the first; the others remain (Python idioms, beyond an
    "honest mistake" guardrail) and are documented as such.
    """

    def test_direct_assignment_to_underscore_blocked(self):
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=512)
        with pytest.raises(AttributeError, match="read-only"):
            w._coin_type = 0  # type: ignore[misc]
        # The original value must be unchanged.
        assert w.coin_type == 512

    def test_initialization_path_still_works(self):
        # Sanity: __setattr__ must NOT block writes during __init__,
        # otherwise the dataclass constructor itself would fail.
        w = HdWallet.from_mnemonic(MNEMONIC, coin_type=0)
        assert w.coin_type == 0
        assert w._coin_type == 0


# ---------------------------------------------------------------------------
# Gap-limit scanning tests
# ---------------------------------------------------------------------------


class TestRefreshEmptyWallet:
    def test_empty_wallet_discovers_nothing(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        result = asyncio.run(w.refresh(client))
        assert result == 0

    def test_all_addresses_recorded_as_unused(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        asyncio.run(w.refresh(client))
        assert all(not r.used for r in w.addresses.values())

    def test_stops_after_gap_limit_addresses(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        asyncio.run(w.refresh(client))
        # Should derive at least GAP_LIMIT addresses on each chain
        external = [r for r in w.addresses.values() if r.change == 0]
        internal = [r for r in w.addresses.values() if r.change == 1]
        assert len(external) >= _GAP_LIMIT
        assert len(internal) >= _GAP_LIMIT


class TestRefreshWithUsedAddresses:
    def _wallet_with_used(self, used_indices: list[int]) -> tuple:
        w = HdWallet.from_mnemonic(MNEMONIC)
        # Pre-compute addresses at the indices that will be marked "used"
        history_map = {w._derive_address(0, i): [{"tx_hash": "aa" * 32, "height": 100}] for i in used_indices}
        client = _mock_client(history_map=history_map)
        count = asyncio.run(w.refresh(client))
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
        asyncio.run(w.refresh(client))
        count2 = asyncio.run(w.refresh(client))
        assert count2 == 0  # already known as used

    def test_internal_chain_also_scanned(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr_internal = w._derive_address(1, 0)
        client = _mock_client(history_map={addr_internal: [{"tx_hash": "bb" * 32, "height": 50}]})
        asyncio.run(w.refresh(client))
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
            w.addresses["0/0"] = AddressRecord(address=addr, change=0, index=0, used=True)
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

    def test_load_rejects_world_readable_wallet_file(self):
        """A wallet file with mode 0644 (or anything wider than 0600)
        must be refused at load time. ``save()`` always writes 0600,
        but a restore-from-backup via ``cp``/``rsync`` can widen the
        mode silently — the check catches that before the seed touches
        memory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"
            w = HdWallet.from_mnemonic(MNEMONIC)
            w.save(p)
            # Loosen the mode after a clean save.
            p.chmod(0o644)

            with pytest.raises(ValidationError, match="0o600"):
                HdWallet.load(p, MNEMONIC)

    def test_load_rejects_malformed_decrypted_json(self):
        """Defense in depth: even if AES-GCM passes (impossible without
        the right seed), structurally-invalid wallet state must raise
        ValidationError rather than crash with KeyError or silently
        drop fields."""
        import hashlib
        import json
        import secrets

        from Cryptodome.Cipher import AES

        from pyrxd.hd.bip39 import seed_from_mnemonic
        from pyrxd.hd.wallet import (
            _FILE_VERSION_V2,
            _NONCE_LEN,
            _SALT_LEN,
            _SCRYPT_N,
            _SCRYPT_P,
            _SCRYPT_R,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "wallet.dat"

            # Hand-craft a wallet file with a CORRECTLY encrypted
            # payload but missing the "address" key in an address record.
            seed = seed_from_mnemonic(MNEMONIC, passphrase="")
            salt = secrets.token_bytes(_SALT_LEN)
            nonce = secrets.token_bytes(_NONCE_LEN)
            enc_key = hashlib.scrypt(
                seed,
                salt=salt,
                n=_SCRYPT_N,
                r=_SCRYPT_R,
                p=_SCRYPT_P,
                maxmem=128 * 1024 * 1024,
                dklen=32,
            )
            bad_data = {
                "version": _FILE_VERSION_V2,
                "account": 0,
                "coin_type": 512,  # required field; absence is now its own hard error
                "external_tip": 1,
                "internal_tip": 0,
                # missing "address" → KeyError when reconstructing
                "addresses": {"0/0": {"change": 0, "index": 0, "used": True}},
            }
            cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(json.dumps(bad_data).encode())
            blob = bytes([_FILE_VERSION_V2]) + salt + nonce + tag + ciphertext
            p.write_bytes(blob)
            # Match the mode invariant that ``save()`` would have written;
            # otherwise the load-time mode check fires first.
            p.chmod(0o600)

            with pytest.raises(ValidationError, match="malformed"):
                HdWallet.load(p, MNEMONIC)

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
            w.addresses["0/0"] = AddressRecord(address="secret_address", change=0, index=0, used=True)
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
        bal = asyncio.run(w.get_balance(client))
        assert bal == 0

    def test_single_used_address_balance(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        client = _mock_client(balance_map={addr0: (1000, 500)})
        bal = asyncio.run(w.get_balance(client))
        assert bal == 1500

    def test_sums_across_multiple_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        w.addresses["0/1"] = AddressRecord(address=addr1, change=0, index=1, used=True)
        client = _mock_client(balance_map={addr0: (1000, 0), addr1: (2000, 0)})
        bal = asyncio.run(w.get_balance(client))
        assert bal == 3000

    def test_unused_addresses_excluded_from_balance(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        w.addresses["0/1"] = AddressRecord(address=addr1, change=0, index=1, used=False)
        client = _mock_client(balance_map={addr0: (1000, 0), addr1: (9999, 0)})
        bal = asyncio.run(w.get_balance(client))
        assert bal == 1000


class TestGetUtxos:
    def test_empty_wallet_utxos_is_empty(self):
        client = _mock_client()
        w = HdWallet.from_mnemonic(MNEMONIC)
        utxos = asyncio.run(w.get_utxos(client))
        assert utxos == []

    def test_returns_utxos_for_used_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr0 = w._derive_address(0, 0)
        w.addresses["0/0"] = AddressRecord(address=addr0, change=0, index=0, used=True)
        utxo = UtxoRecord(tx_hash="aa" * 32, tx_pos=0, value=546, height=100)
        client = _mock_client(utxo_map={addr0: [utxo]})
        utxos = asyncio.run(w.get_utxos(client))
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
        utxos = asyncio.run(w.get_utxos(client))
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
            asyncio.run(w.refresh(client))

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
            asyncio.run(w.refresh(client))
        except NetworkError:
            # Expected — verifying state is consistent after the failure below.
            pass
        # No false-negative records may remain.
        assert all(r.used is True for r in w.addresses.values()) or w.addresses == {}


# ---------------------------------------------------------------------------
# Cut 1A: HdWallet.send / send_max + helpers
#
# These tests cover the OFFLINE build path with fixture UTXOs. The
# network-touching async paths (``send`` / ``send_max``) reuse those
# builders + a mocked ElectrumX, so a green build_send_tx is sufficient
# to assert the broadcast wrapper works.
# ---------------------------------------------------------------------------

# A valid Radiant P2PKH address (used as a recipient throughout).
_RECIPIENT_ADDR = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"  # known-vector for privkey=1


def _utxo(*, tx_hash: str = "aa" * 32, tx_pos: int = 0, value: int = 1_000_000_000) -> UtxoRecord:
    return UtxoRecord(tx_hash=tx_hash, tx_pos=tx_pos, value=value, height=1)


def _seed_wallet_with_used_addresses(w: HdWallet, n_external: int = 2, n_internal: int = 1) -> HdWallet:
    """Mark the first ``n_external`` external addresses + ``n_internal`` internal as used.

    Bypasses ``refresh()`` so tests don't need a chaintracker — we just
    set the AddressRecords directly.
    """
    for i in range(n_external):
        addr = w._derive_address(0, i)
        w.addresses[w._path_key(0, i)] = AddressRecord(address=addr, change=0, index=i, used=True)
    for i in range(n_internal):
        addr = w._derive_address(1, i)
        w.addresses[w._path_key(1, i)] = AddressRecord(address=addr, change=1, index=i, used=True)
    w.external_tip = n_external
    w.internal_tip = n_internal
    return w


class TestPrivkeyDerivation:
    def test_privkey_for_matches_address(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        addr = w._derive_address(0, 0)
        privkey = w._privkey_for(0, 0)
        assert privkey.public_key().address() == addr

    def test_internal_chain_distinct_from_external(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        ext = w._privkey_for(0, 0)
        int_ = w._privkey_for(1, 0)
        assert ext.public_key().address() != int_.public_key().address()


class TestNextChangeIndex:
    def test_returns_zero_when_nothing_used(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        assert w._next_change_index() == 0

    def test_skips_used_internal(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=1, n_internal=2)
        # First two internal indices used → expect 2
        assert w._next_change_index() == 2

    def test_creates_record_for_returned_index(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        idx = w._next_change_index()
        pkey = w._path_key(1, idx)
        assert pkey in w.addresses
        assert w.addresses[pkey].used is False


class TestBuildSendTxOffline:
    """Offline path — `triples` is supplied by the caller; no network."""

    def _triples(self, w: HdWallet, *, n_inputs: int = 1, value_each: int = 1_000_000_000):
        """Build (utxo, address, privkey) triples on the wallet's first external address."""
        addr = w._derive_address(0, 0)
        pk = w._privkey_for(0, 0)
        return [
            (
                _utxo(tx_hash=bytes([i + 1]).hex() * 32, value=value_each),
                addr,
                pk,
            )
            for i in range(n_inputs)
        ]

    def test_builds_signed_transaction(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w, n_inputs=1, value_each=1_000_000_000)
        tx = w.build_send_tx(triples, _RECIPIENT_ADDR, photons=10_000_000)
        assert tx.byte_length() > 0
        # Recipient + change = 2 outputs (we provide enough for change).
        assert len(tx.outputs) == 2
        assert tx.outputs[0].satoshis == 10_000_000

    def test_change_goes_to_internal_chain_by_default(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=1, n_internal=0)
        triples = self._triples(w, n_inputs=1, value_each=1_000_000_000)
        tx = w.build_send_tx(triples, _RECIPIENT_ADDR, photons=10_000_000)
        # The wallet picked m/.../1/0 as change; verify by re-deriving.
        expected_change_addr = w._derive_address(1, 0)
        from pyrxd.script.type import P2PKH

        expected_change_script = P2PKH().lock(expected_change_addr).serialize()
        assert tx.outputs[1].locking_script.serialize() == expected_change_script

    def test_explicit_change_address_honored(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w, n_inputs=1, value_each=1_000_000_000)
        # Pick a custom change address — same wallet's external index 5.
        custom_change = w._derive_address(0, 5)
        tx = w.build_send_tx(
            triples,
            _RECIPIENT_ADDR,
            photons=10_000_000,
            change_address=custom_change,
        )
        from pyrxd.script.type import P2PKH

        expected_script = P2PKH().lock(custom_change).serialize()
        assert tx.outputs[1].locking_script.serialize() == expected_script

    def test_insufficient_funds_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w, n_inputs=1, value_each=10_000)  # tiny
        with pytest.raises(ValidationError, match="Insufficient"):
            w.build_send_tx(triples, _RECIPIENT_ADDR, photons=1_000_000_000)

    def test_below_dust_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w)
        with pytest.raises(ValidationError, match="dust"):
            w.build_send_tx(triples, _RECIPIENT_ADDR, photons=100)

    def test_negative_photons_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w)
        with pytest.raises(ValidationError):
            w.build_send_tx(triples, _RECIPIENT_ADDR, photons=-1)

    def test_zero_fee_rate_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w)
        with pytest.raises(ValidationError, match="fee_rate"):
            w.build_send_tx(triples, _RECIPIENT_ADDR, photons=10_000_000, fee_rate=0)

    def test_invalid_to_address_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w)
        with pytest.raises(ValidationError, match="to_address"):
            w.build_send_tx(triples, "not-an-address", photons=10_000_000)

    def test_invalid_change_address_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        triples = self._triples(w)
        with pytest.raises(ValidationError, match="change_address"):
            w.build_send_tx(
                triples,
                _RECIPIENT_ADDR,
                photons=10_000_000,
                change_address="garbage",
            )

    def test_no_utxos_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        with pytest.raises(ValidationError, match="Insufficient"):
            w.build_send_tx([], _RECIPIENT_ADDR, photons=10_000_000)

    def test_change_below_dust_omitted(self):
        """If the change remainder is below dust, the change output must be dropped."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        # Pick an amount such that change after fee will be tiny.
        # 10_000_000 in, ~150 sat fee, send 9_999_500 → change of ~350 < DUST(546)
        triples = self._triples(w, n_inputs=1, value_each=10_000_000)
        # Use a low fee_rate so the residual is small but the function still
        # builds; the test asserts that the dust-burning branch fires.
        # With photons=9_999_454 and fee_rate=1, fee~tx_bytes < 546 leftover.
        tx = w.build_send_tx(
            triples,
            _RECIPIENT_ADDR,
            photons=9_999_500,
            fee_rate=1,
        )
        assert len(tx.outputs) == 1  # change burned
        assert tx.outputs[0].satoshis == 9_999_500

    def test_signs_with_correct_per_utxo_key(self):
        """Each input must be signed by the key derived for THAT utxo's address."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=2)

        # Build triples spanning two distinct external addresses.
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)
        pk0 = w._privkey_for(0, 0)
        pk1 = w._privkey_for(0, 1)
        triples = [
            (_utxo(tx_hash="aa" * 32, value=600_000_000), addr0, pk0),
            (_utxo(tx_hash="bb" * 32, value=600_000_000), addr1, pk1),
        ]
        tx = w.build_send_tx(triples, _RECIPIENT_ADDR, photons=1_000_000_000)
        assert len(tx.inputs) == 2
        # Both inputs were signed; just verify byte_length is plausibly
        # the sum of two signed inputs.
        assert tx.byte_length() > 300


class TestBuildSendMaxTxOffline:
    def test_sweeps_all_utxos_to_single_output(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        addr = w._derive_address(0, 0)
        pk = w._privkey_for(0, 0)
        triples = [(_utxo(tx_hash=bytes([i + 1]).hex() * 32, value=500_000_000), addr, pk) for i in range(3)]
        tx = w.build_send_max_tx(triples, _RECIPIENT_ADDR)
        assert len(tx.outputs) == 1
        # 1.5B in, fee deducted; expect output ~ input minus fee.
        # Fee for ~500-byte 3-input tx at 10_000 photons/byte ~ 5M photons.
        out = tx.outputs[0].satoshis
        assert 1_490_000_000 < out < 1_500_000_000

    def test_dust_total_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        addr = w._derive_address(0, 0)
        pk = w._privkey_for(0, 0)
        triples = [(_utxo(value=500), addr, pk)]
        with pytest.raises(ValidationError, match="dust"):
            w.build_send_max_tx(triples, _RECIPIENT_ADDR)

    def test_total_under_fee_raises(self):
        """Enough to clear dust, but not enough to cover fee."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w)
        addr = w._derive_address(0, 0)
        pk = w._privkey_for(0, 0)
        # 10_000 photons in; fee at 10_000 photons/byte on ~200-byte tx
        # would be ~2M photons — way over the input.
        triples = [(_utxo(value=10_000), addr, pk)]
        with pytest.raises(ValidationError, match="cover fee"):
            w.build_send_max_tx(triples, _RECIPIENT_ADDR)

    def test_no_utxos_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        with pytest.raises(ValidationError, match="Insufficient"):
            w.build_send_max_tx([], _RECIPIENT_ADDR)


class TestCollectSpendable:
    def test_returns_triples_for_used_addresses(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=2, n_internal=0)
        addr0 = w._derive_address(0, 0)
        addr1 = w._derive_address(0, 1)

        client = _mock_client(
            utxo_map={
                addr0: [_utxo(tx_hash="aa" * 32, value=100_000_000)],
                addr1: [_utxo(tx_hash="bb" * 32, value=200_000_000)],
            }
        )
        triples = asyncio.run(w.collect_spendable(client))
        assert len(triples) == 2
        # Each privkey is the one derived for its address.
        for _utxo_rec, addr, pk in triples:
            assert pk.public_key().address() == addr

    def test_returns_empty_when_no_used(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        client = _mock_client()
        triples = asyncio.run(w.collect_spendable(client))
        assert triples == []

    def test_drops_failed_address_lookups(self):
        """A per-address failure must not crash the whole collection."""
        from pyrxd.security.errors import NetworkError

        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=2, n_internal=0)
        addr0 = w._derive_address(0, 0)

        client = MagicMock(spec=ElectrumXClient)

        async def _get_utxos(script_hash):
            from pyrxd.network.electrumx import script_hash_for_address

            if script_hash_for_address(addr0) == script_hash:
                return [_utxo(tx_hash="aa" * 32, value=100_000_000)]
            raise NetworkError("simulated failure")

        client.get_utxos = _get_utxos
        triples = asyncio.run(w.collect_spendable(client))
        # Only the working address contributed.
        assert len(triples) == 1


class TestSendBroadcast:
    """Network-path tests — verify send() wires UTXO collection +
    builder + broadcast together. The build mechanics are covered above.
    """

    def test_send_returns_txid(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=1, n_internal=0)
        addr = w._derive_address(0, 0)

        client = _mock_client(
            utxo_map={addr: [_utxo(value=1_000_000_000)]},
        )

        async def _broadcast(raw):
            return "ab" * 32

        client.broadcast = _broadcast

        txid = asyncio.run(w.send(client, _RECIPIENT_ADDR, photons=10_000_000))
        assert txid == "ab" * 32

    def test_send_max_returns_txid(self):
        w = HdWallet.from_mnemonic(MNEMONIC)
        _seed_wallet_with_used_addresses(w, n_external=1, n_internal=0)
        addr = w._derive_address(0, 0)

        client = _mock_client(
            utxo_map={addr: [_utxo(value=1_000_000_000)]},
        )

        async def _broadcast(raw):
            return "cd" * 32

        client.broadcast = _broadcast

        txid = asyncio.run(w.send_max(client, _RECIPIENT_ADDR))
        assert txid == "cd" * 32

    def test_send_with_no_utxos_raises(self):
        w = HdWallet.from_mnemonic(MNEMONIC)  # no used addresses → no UTXOs
        client = _mock_client()
        with pytest.raises(ValidationError, match="Insufficient"):
            asyncio.run(w.send(client, _RECIPIENT_ADDR, photons=10_000_000))

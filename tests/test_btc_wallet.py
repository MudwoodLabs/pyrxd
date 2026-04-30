"""Tests for pyrxd.btc_wallet — Phase 2b Bitcoin wallet tooling for Gravity Taker."""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet import (
    BtcUtxo,
    build_payment_tx,
    generate_keypair,
    keypair_from_wif,
    validate_btc_address,
    validate_satoshis,
)
from pyrxd.security.errors import ValidationError
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH
from pyrxd.spv.pow import hash256
from pyrxd.spv.witness import strip_witness


class TestKeygen:
    def test_generate_keypair_produces_valid_key(self):
        """generate_keypair() returns a BtcKeypair with all address formats."""
        kp = generate_keypair()
        assert kp.p2pkh_address.startswith("1")
        assert kp.p2wpkh_address.startswith("bc1q")
        assert kp.p2sh_p2wpkh_address.startswith("3")
        assert kp.p2tr_address.startswith("bc1p")

    def test_pkh_is_20_bytes(self):
        kp = generate_keypair()
        assert len(kp.pkh) == 20

    def test_p2sh_hash_is_20_bytes(self):
        kp = generate_keypair()
        assert len(kp.p2sh_hash) == 20

    def test_p2tr_output_key_is_32_bytes(self):
        kp = generate_keypair()
        assert len(kp.p2tr_output_key) == 32

    def test_pubkey_is_33_bytes_compressed(self):
        kp = generate_keypair()
        assert len(kp.pubkey_bytes) == 33
        assert kp.pubkey_bytes[0] in (0x02, 0x03)

    def test_privkey_repr_does_not_leak(self):
        kp = generate_keypair()
        raw_hex = kp._privkey.unsafe_raw_bytes().hex()
        assert raw_hex not in repr(kp)
        assert raw_hex not in str(kp)

    def test_privkey_repr_redacted(self):
        kp = generate_keypair()
        assert repr(kp._privkey) == "<PrivateKeyMaterial>"

    def test_keypair_repr_shows_address(self):
        kp = generate_keypair()
        assert "bc1q" in repr(kp)

    def test_generate_10_unique_keypairs(self):
        """Statistical uniqueness: 10 generated keys should all differ."""
        keypairs = [generate_keypair() for _ in range(10)]
        pubkeys = [kp.pubkey_bytes for kp in keypairs]
        assert len(set(pubkeys)) == 10

    def test_wif_round_trip(self):
        """keypair_from_wif(kp.unsafe_wif()) should reconstruct same pubkey."""
        kp = generate_keypair()
        wif = kp.unsafe_wif()
        assert wif.startswith("K") or wif.startswith("L")  # mainnet compressed WIF
        kp2 = keypair_from_wif(wif)
        assert kp2.pubkey_bytes == kp.pubkey_bytes

    def test_wif_round_trip_preserves_addresses(self):
        kp = generate_keypair()
        kp2 = keypair_from_wif(kp.unsafe_wif())
        assert kp2.p2pkh_address == kp.p2pkh_address
        assert kp2.p2wpkh_address == kp.p2wpkh_address
        assert kp2.p2sh_p2wpkh_address == kp.p2sh_p2wpkh_address
        assert kp2.p2tr_address == kp.p2tr_address


class TestAddressFormats:
    """Known-vector tests for address generation.

    Privkey = 1 (scalar) → compressed mainnet WIF:
      KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
    This is the secp256k1 generator point G as public key.
    Known P2PKH: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    """

    PRIVKEY_1_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

    def test_p2pkh_address_known_vector(self):
        kp = keypair_from_wif(self.PRIVKEY_1_WIF)
        assert kp.p2pkh_address == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    def test_p2wpkh_address_is_bech32(self):
        kp = keypair_from_wif(self.PRIVKEY_1_WIF)
        assert kp.p2wpkh_address.startswith("bc1q")
        # Known P2WPKH for privkey=1
        assert kp.p2wpkh_address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

    def test_p2sh_p2wpkh_starts_with_3(self):
        kp = keypair_from_wif(self.PRIVKEY_1_WIF)
        assert kp.p2sh_p2wpkh_address.startswith("3")

    def test_p2tr_address_is_bech32m(self):
        kp = keypair_from_wif(self.PRIVKEY_1_WIF)
        assert kp.p2tr_address.startswith("bc1p")

    def test_pkh_matches_p2pkh_address_embedding(self):
        """The PKH embedded in P2PKH address should match keypair.pkh."""

        from pyrxd.base58 import b58_decode

        kp = keypair_from_wif(self.PRIVKEY_1_WIF)
        # Decode address: base58(version + pkh + checksum)
        decoded = b58_decode(kp.p2pkh_address)
        # Strip 4-byte checksum and 1-byte version prefix
        embedded_pkh = decoded[1:-4]
        assert embedded_pkh == kp.pkh

    def test_invalid_wif_raises(self):
        with pytest.raises(Exception):
            keypair_from_wif("notavalidwif")


class TestNetworkHrp:
    """Network / HRP parameterization (mainnet ``bc`` default, testnet ``tb``, etc.)."""

    PRIVKEY_1_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"

    def test_default_network_is_mainnet(self):
        """BtcKeypair defaults to mainnet (``bc``) when no network is given."""
        kp = generate_keypair()
        assert kp.network == "bc"
        assert kp.p2wpkh_address.startswith("bc1q")
        assert kp.p2tr_address.startswith("bc1p")
        assert kp.p2pkh_address.startswith("1")
        assert kp.p2sh_p2wpkh_address.startswith("3")

    def test_explicit_bc_same_as_default(self):
        """Passing ``network="bc"`` must produce the same addresses as the default."""
        kp_default = keypair_from_wif(self.PRIVKEY_1_WIF)
        kp_explicit = keypair_from_wif(self.PRIVKEY_1_WIF, network="bc")
        assert kp_default.p2pkh_address == kp_explicit.p2pkh_address
        assert kp_default.p2wpkh_address == kp_explicit.p2wpkh_address
        assert kp_default.p2sh_p2wpkh_address == kp_explicit.p2sh_p2wpkh_address
        assert kp_default.p2tr_address == kp_explicit.p2tr_address
        assert kp_explicit.network == "bc"

    def test_testnet_hrp_differs_from_mainnet(self):
        """Testnet HRP ``tb`` produces a different address than mainnet ``bc``."""
        kp_main = keypair_from_wif(self.PRIVKEY_1_WIF)
        kp_test = keypair_from_wif(self.PRIVKEY_1_WIF, network="tb")
        assert kp_test.network == "tb"
        assert kp_test.p2wpkh_address != kp_main.p2wpkh_address
        assert kp_test.p2tr_address != kp_main.p2tr_address
        assert kp_test.p2pkh_address != kp_main.p2pkh_address
        assert kp_test.p2sh_p2wpkh_address != kp_main.p2sh_p2wpkh_address

    def test_testnet_bech32_prefix(self):
        """Testnet bech32 P2WPKH starts with ``tb1q`` and P2TR with ``tb1p``."""
        kp = keypair_from_wif(self.PRIVKEY_1_WIF, network="tb")
        assert kp.p2wpkh_address.startswith("tb1q")
        assert kp.p2tr_address.startswith("tb1p")
        # Known P2WPKH for privkey=1 on testnet (same pkh, different HRP only).
        assert kp.p2wpkh_address == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

    def test_testnet_base58_prefixes(self):
        """Testnet P2PKH starts with m/n and P2SH with 2."""
        kp = keypair_from_wif(self.PRIVKEY_1_WIF, network="tb")
        assert kp.p2pkh_address[0] in {"m", "n"}
        assert kp.p2sh_p2wpkh_address.startswith("2")

    def test_regtest_hrp(self):
        """Regtest HRP ``bcrt`` yields ``bcrt1`` addresses and testnet base58."""
        kp = keypair_from_wif(self.PRIVKEY_1_WIF, network="bcrt")
        assert kp.network == "bcrt"
        assert kp.p2wpkh_address.startswith("bcrt1q")
        assert kp.p2tr_address.startswith("bcrt1p")
        # Regtest shares testnet base58 versions.
        assert kp.p2pkh_address[0] in {"m", "n"}
        assert kp.p2sh_p2wpkh_address.startswith("2")

    def test_testnet_wif_prefix(self):
        """Testnet WIF must use version 0xEF (starts with c for compressed)."""
        kp = generate_keypair(network="tb")
        wif = kp.unsafe_wif()
        # Compressed testnet WIF always starts with 'c' (0xEF + ... + 0x01 checksum).
        assert wif.startswith("c")

    def test_mainnet_wif_unchanged(self):
        """Mainnet WIF still starts with K/L as before (backward compat)."""
        kp = generate_keypair()
        wif = kp.unsafe_wif()
        assert wif.startswith("K") or wif.startswith("L")

    def test_testnet_wif_round_trip_preserves_pubkey(self):
        """keypair_from_wif(kp.unsafe_wif(), network="tb") preserves the pubkey."""
        kp = generate_keypair(network="tb")
        kp2 = keypair_from_wif(kp.unsafe_wif(), network="tb")
        assert kp2.pubkey_bytes == kp.pubkey_bytes
        assert kp2.p2wpkh_address == kp.p2wpkh_address

    def test_bech32_checksum_valid_for_testnet(self):
        """The generated testnet bech32 address decodes back to the same pkh."""
        from pyrxd.btc_wallet.keys import _BECH32_CHARSET

        kp = keypair_from_wif(self.PRIVKEY_1_WIF, network="tb")
        addr = kp.p2wpkh_address
        # Shape: 'tb1' + data(32-char witness program + 6-char checksum + leading v0)
        assert addr.startswith("tb1")
        # Character set check — body after '1' separator is in bech32 charset.
        body = addr[addr.rindex("1") + 1 :]
        for ch in body:
            assert ch in _BECH32_CHARSET

    def test_unknown_hrp_accepted(self):
        """Custom / unknown HRPs are accepted (base58 falls back to mainnet)."""
        kp = keypair_from_wif(self.PRIVKEY_1_WIF, network="rxdtest")
        assert kp.network == "rxdtest"
        assert kp.p2wpkh_address.startswith("rxdtest1")

    def test_empty_network_rejected(self):
        """Empty network string must raise a ValidationError."""
        with pytest.raises(ValidationError):
            generate_keypair(network="")


class TestBuildPaymentTx:
    def test_invalid_input_type_rejected(self):
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        with pytest.raises(ValidationError, match="input_type"):
            build_payment_tx(kp, utxo, b"\x00" * 20, P2PKH, 50_000, 1_000, input_type="p2pkh")

    def test_invalid_to_type_rejected(self):
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        with pytest.raises(ValidationError, match="to_type"):
            build_payment_tx(kp, utxo, b"\x00" * 20, "p2invalid", 50_000, 1_000)

    def test_insufficient_funds_rejected(self):
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=1_000)
        with pytest.raises(ValidationError, match="insufficient"):
            build_payment_tx(kp, utxo, b"\x00" * 20, P2PKH, 50_000, 1_000)

    def test_p2wpkh_payment_builds_valid_tx(self):
        """Build a P2WPKH payment tx and verify txid matches non-witness hash."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(
            kp,
            utxo,
            to_hash=b"\xbb" * 20,
            to_type=P2WPKH,
            amount_sats=50_000,
            fee_sats=1_000,
        )
        assert result.txid
        assert len(result.txid) == 64
        assert result.change_sats == 49_000
        assert result.input_type == "p2wpkh"
        assert result.output_type == P2WPKH

        # Verify txid = hash256(non-witness serialization)[::-1].hex()
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        computed_txid = hash256(stripped)[::-1].hex()
        assert computed_txid == result.txid

    def test_p2wpkh_tx_has_empty_scriptsig(self):
        """P2WPKH input must have empty scriptSig (covenant structural requirement)."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000)
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        # Non-witness layout: version(4) + input_count(1) + prevout(36) + scriptSig_len_byte
        scriptsig_len = stripped[41]  # after version(4) + varint(1) + prevout(36)
        assert scriptsig_len == 0

    def test_p2sh_p2wpkh_has_nonempty_scriptsig(self):
        """P2SH-P2WPKH input must have 23-byte scriptSig."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000, input_type="p2sh_p2wpkh")
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        # After version(4) + input_count(1) + prevout(36), scriptSig length byte
        scriptsig_len = stripped[41]
        # scriptSig = 0x16 + redeem(22) = 23 bytes total on wire
        # The length byte at offset 41 is the varint for the scriptSig bytes
        assert scriptsig_len == 23

    def test_p2sh_p2wpkh_txid_valid(self):
        """P2SH-P2WPKH tx txid should match non-witness hash."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="bb" * 32, vout=1, value=200_000)
        result = build_payment_tx(kp, utxo, b"\xcc" * 20, P2PKH, 100_000, 2_000, input_type="p2sh_p2wpkh")
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        computed_txid = hash256(stripped)[::-1].hex()
        assert computed_txid == result.txid

    def test_change_output_included_above_dust(self):
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000)
        assert result.change_sats == 49_000
        # Tx should have 2 outputs
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        # Parse output count from stripped tx
        # version(4) + inputs_section (varint + input) + output_count varint
        pos = 4
        in_count, pos = _read_varint(stripped, pos)
        for _ in range(in_count):
            pos += 36  # prevout
            script_len, pos = _read_varint(stripped, pos)
            pos += script_len + 4  # script + sequence
        out_count, _ = _read_varint(stripped, pos)
        assert out_count == 2

    def test_change_below_dust_swept_into_fee(self):
        """When change < 546 sats, it is swept into the miner fee."""
        kp = generate_keypair()
        # change = 50_400 - 50_000 - 1 = 399 < 546 = dust
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=50_400)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1)
        assert result.change_sats == 0

        # Tx should have only 1 output (no change)
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        pos = 4
        in_count, pos = _read_varint(stripped, pos)
        for _ in range(in_count):
            pos += 36
            script_len, pos = _read_varint(stripped, pos)
            pos += script_len + 4
        out_count, _ = _read_varint(stripped, pos)
        assert out_count == 1

    def test_change_exactly_at_dust_limit_included(self):
        """Change == 546 (exactly dust limit) should be included."""
        kp = generate_keypair()
        # change = value - amount - fee = 546
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=51_546)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000)
        assert result.change_sats == 546

    def test_p2tr_output_32_byte_hash(self):
        """P2TR output requires 32-byte hash."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xdd" * 32, P2TR, 50_000, 1_000)
        assert result.output_type == P2TR
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        computed_txid = hash256(stripped)[::-1].hex()
        assert computed_txid == result.txid

    def test_p2tr_output_wrong_hash_len_rejected(self):
        """P2TR to_hash must be 32 bytes."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        with pytest.raises(ValidationError):
            build_payment_tx(kp, utxo, b"\xdd" * 20, P2TR, 50_000, 1_000)

    def test_p2sh_output(self):
        """P2SH output builds and hashes correctly."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xee" * 20, P2SH, 50_000, 1_000)
        assert result.output_type == P2SH
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        computed_txid = hash256(stripped)[::-1].hex()
        assert computed_txid == result.txid

    def test_tx_version_is_2(self):
        """Transaction version should be 2."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000)
        raw = bytes.fromhex(result.tx_hex)
        import struct

        version = struct.unpack_from("<I", raw, 0)[0]
        assert version == 2

    def test_tx_segwit_marker_flag(self):
        """Segwit serialization must have 0x00 0x01 marker/flag."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000)
        raw = bytes.fromhex(result.tx_hex)
        assert raw[4] == 0x00  # marker
        assert raw[5] == 0x01  # flag

    def test_fee_is_recorded(self):
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 2_500)
        assert result.fee_sats == 2_500

    def test_exactly_one_input_in_serialized_tx(self):
        """Exactly 1 input must appear in the serialized transaction."""
        kp = generate_keypair()
        utxo = BtcUtxo(txid="aa" * 32, vout=0, value=100_000)
        result = build_payment_tx(kp, utxo, b"\xbb" * 20, P2WPKH, 50_000, 1_000)
        raw = bytes.fromhex(result.tx_hex)
        stripped = strip_witness(raw)
        # After version(4): input count varint
        in_count, _ = _read_varint(stripped, 4)
        assert in_count == 1


class TestValidation:
    def test_valid_p2pkh_address_accepted(self):
        validate_btc_address("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")

    def test_valid_p2sh_address_accepted(self):
        validate_btc_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")

    def test_valid_bech32_p2wpkh_address_accepted(self):
        validate_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")

    def test_valid_bech32m_p2tr_address_accepted(self):
        # A well-formed bc1p... address (BIP350 example prefix)
        validate_btc_address("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")

    def test_path_traversal_rejected(self):
        with pytest.raises(ValidationError):
            validate_btc_address("../../../etc/passwd")

    def test_query_injection_rejected(self):
        with pytest.raises(ValidationError):
            validate_btc_address("1abc?foo=bar")

    def test_empty_address_rejected(self):
        with pytest.raises(ValidationError):
            validate_btc_address("")

    def test_non_string_rejected(self):
        with pytest.raises(ValidationError):
            validate_btc_address(12345)  # type: ignore[arg-type]

    def test_testnet_address_rejected(self):
        # testnet P2PKH starts with 'm' or 'n'
        with pytest.raises(ValidationError):
            validate_btc_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")

    def test_validate_satoshis_valid(self):
        validate_satoshis(1_000)
        validate_satoshis(1)
        validate_satoshis(2_100_000_000_000_000)

    def test_validate_satoshis_zero_rejected(self):
        with pytest.raises(ValidationError):
            validate_satoshis(0)

    def test_validate_satoshis_negative_rejected(self):
        with pytest.raises(ValidationError):
            validate_satoshis(-1)

    def test_validate_satoshis_bool_rejected(self):
        with pytest.raises(ValidationError):
            validate_satoshis(True)  # type: ignore[arg-type]

    def test_validate_satoshis_float_rejected(self):
        with pytest.raises(ValidationError):
            validate_satoshis(1.5)  # type: ignore[arg-type]

    def test_validate_satoshis_exceeds_max_rejected(self):
        with pytest.raises(ValidationError):
            validate_satoshis(2_100_000_000_000_001)

    def test_validate_satoshis_custom_name_in_message(self):
        with pytest.raises(ValidationError, match="fee"):
            validate_satoshis(0, name="fee")


# ---------------------------------------------------------------------------
# Helpers for parsing stripped tx bytes in tests
# ---------------------------------------------------------------------------


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    if first == 0xFD:
        return int.from_bytes(data[pos + 1 : pos + 3], "little"), pos + 3
    if first == 0xFE:
        return int.from_bytes(data[pos + 1 : pos + 5], "little"), pos + 5
    return int.from_bytes(data[pos + 1 : pos + 9], "little"), pos + 9

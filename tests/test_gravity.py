"""Tests for pyrxd.gravity — Phase 3a covenant transaction builders.

These are structural / unit tests.  We cannot test actual covenant *execution*
without a Radiant node; instead we verify:
  * Correct wire-format structure (lengths, opcodes, locktime, sequence)
  * Determinism and uniqueness of hash functions
  * Validation guards (deadline, fee checks, bad inputs)
  * ScriptSig contains the correct proof components in the correct positions
"""

from __future__ import annotations

import time

import pytest

from pyrxd.gravity import (
    ClaimResult,
    FinalizeResult,
    ForfeitResult,
    GravityOffer,
    build_finalize_tx,
    build_forfeit_tx,
    compute_p2sh_code_hash,
)
from pyrxd.gravity.codehash import (
    compute_p2sh_address_from_redeem,
    compute_p2sh_script_pubkey,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial
from pyrxd.spv.proof import _BUILDER_TOKEN, CovenantParams, SpvProof

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_gravity_offer(**kwargs) -> GravityOffer:
    """Return a valid GravityOffer, with field overrides from *kwargs*.

    expected_code_hash_hex is computed from claimed_redeem_hex so that
    build_claim_tx's H-1 enforcement check passes.
    """
    defaults: dict = dict(
        btc_receive_hash=b"\x00" * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=50_000,
        chain_anchor=b"\x00" * 32,
        anchor_height=840_000,
        merkle_depth=12,
        taker_radiant_pkh=b"\x00" * 20,
        claim_deadline=int(time.time()) + 48 * 3600,  # 48 h from now
        photons_offered=1_000_000,
        offer_redeem_hex="aa" * 100,
        claimed_redeem_hex="bb" * 100,
    )
    defaults.update(kwargs)
    # Derive the correct expected_code_hash_hex unless caller overrides it
    if "expected_code_hash_hex" not in defaults:
        claimed_redeem = bytes.fromhex(defaults["claimed_redeem_hex"])
        defaults["expected_code_hash_hex"] = compute_p2sh_code_hash(claimed_redeem).hex()
    return GravityOffer(**defaults)


def _make_spv_proof(headers: list[bytes] | None = None) -> SpvProof:
    """Build a minimal fake SpvProof for structure testing."""
    params = CovenantParams(
        btc_receive_hash=b"\xaa" * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=50_000,
        chain_anchor=b"\x00" * 32,
        anchor_height=840_000,
        merkle_depth=1,
    )
    return SpvProof(
        txid="aa" * 32,
        raw_tx=b"\x01" * 100,
        headers=headers if headers is not None else [b"\x00" * 80],
        branch=b"\x00" * 33,
        pos=1,
        output_offset=0,
        covenant_params=params,
        _token=_BUILDER_TOKEN,
    )


# ---------------------------------------------------------------------------
# codehash tests
# ---------------------------------------------------------------------------


class TestCodeHash:
    def test_p2sh_script_pubkey_is_23_bytes(self):
        redeem = b"\x00" * 100
        spk = compute_p2sh_script_pubkey(redeem)
        assert len(spk) == 23

    def test_p2sh_script_pubkey_opcodes(self):
        redeem = b"\xab" * 50
        spk = compute_p2sh_script_pubkey(redeem)
        assert spk[0] == 0xA9  # OP_HASH160
        assert spk[1] == 0x14  # PUSH 20
        assert spk[-1] == 0x87  # OP_EQUAL

    def test_p2sh_code_hash_is_32_bytes(self):
        redeem = b"\xab" * 50
        ch = compute_p2sh_code_hash(redeem)
        assert len(ch) == 32

    def test_p2sh_code_hash_deterministic(self):
        redeem = b"\xcd" * 50
        assert compute_p2sh_code_hash(redeem) == compute_p2sh_code_hash(redeem)

    def test_different_redeems_produce_different_hashes(self):
        assert compute_p2sh_code_hash(b"\x01" * 50) != compute_p2sh_code_hash(b"\x02" * 50)

    def test_empty_redeem_rejected(self):
        with pytest.raises(ValidationError):
            compute_p2sh_code_hash(b"")

    def test_p2sh_address_is_string(self):
        addr = compute_p2sh_address_from_redeem(b"\xaa" * 50)
        assert isinstance(addr, str)
        assert len(addr) > 0

    def test_p2sh_address_deterministic(self):
        redeem = b"\xde" * 30
        assert compute_p2sh_address_from_redeem(redeem) == compute_p2sh_address_from_redeem(redeem)


# ---------------------------------------------------------------------------
# GravityOffer validation tests
# ---------------------------------------------------------------------------


class TestGravityOffer:
    def test_valid_offer_constructs(self):
        offer = _make_gravity_offer()
        assert offer.btc_satoshis == 50_000

    def test_offer_is_frozen(self):
        offer = _make_gravity_offer()
        # frozen=True dataclasses raise FrozenInstanceError (subclass of AttributeError)
        # when you try to set an attribute via normal attribute assignment.
        with pytest.raises(AttributeError):
            offer.btc_satoshis = 1  # type: ignore[misc]

    def test_unknown_btc_receive_type_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(btc_receive_type="p2xxx")

    def test_zero_btc_satoshis_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(btc_satoshis=0)

    def test_negative_btc_satoshis_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(btc_satoshis=-1)

    def test_short_chain_anchor_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(chain_anchor=b"\x00" * 31)

    def test_long_chain_anchor_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(chain_anchor=b"\x00" * 33)

    def test_short_taker_pkh_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(taker_radiant_pkh=b"\x00" * 19)

    def test_zero_photons_rejected(self):
        with pytest.raises(ValidationError):
            _make_gravity_offer(photons_offered=0)

    def test_old_claim_deadline_rejected(self):
        """Any deadline before 2025-01-01 must be rejected."""
        with pytest.raises(ValidationError):
            _make_gravity_offer(claim_deadline=1_000_000_000)  # year 2001

    def test_exact_min_deadline_accepted(self):
        """The boundary value MIN_CLAIM_DEADLINE itself must be accepted."""
        from pyrxd.gravity.types import MIN_CLAIM_DEADLINE

        offer = _make_gravity_offer(claim_deadline=MIN_CLAIM_DEADLINE)
        assert offer.claim_deadline == MIN_CLAIM_DEADLINE

    def test_all_btc_receive_types_accepted(self):
        for rt in ("p2pkh", "p2wpkh", "p2sh", "p2tr"):
            hash_len = 32 if rt == "p2tr" else 20
            offer = _make_gravity_offer(
                btc_receive_type=rt,
                btc_receive_hash=b"\x00" * hash_len,
            )
            assert offer.btc_receive_type == rt

    # --- validate_deadline_from_now ---

    def test_deadline_too_soon_raises_without_override(self):
        offer = _make_gravity_offer(claim_deadline=int(time.time()) + 3600)  # 1 h
        with pytest.raises(ValidationError, match="24h"):
            offer.validate_deadline_from_now(accept_short_deadline=False)

    def test_deadline_too_soon_accepted_with_override(self):
        offer = _make_gravity_offer(claim_deadline=int(time.time()) + 3600)
        # Must not raise
        offer.validate_deadline_from_now(accept_short_deadline=True)

    def test_far_future_deadline_passes(self):
        offer = _make_gravity_offer(claim_deadline=int(time.time()) + 7 * 24 * 3600)
        offer.validate_deadline_from_now()  # no raise


# ---------------------------------------------------------------------------
# build_finalize_tx tests
# ---------------------------------------------------------------------------


class TestBuildFinalizeTx:
    def test_finalize_tx_produces_valid_hex(self):
        proof = _make_spv_proof()
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        assert isinstance(result, FinalizeResult)
        assert result.tx_hex
        # Valid hex
        bytes.fromhex(result.tx_hex)

    def test_finalize_txid_is_64_hex_chars(self):
        proof = _make_spv_proof()
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        assert len(result.txid) == 64

    def test_finalize_output_photons_correct(self):
        proof = _make_spv_proof()
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        assert result.output_photons == 999_000
        assert result.fee_sats == 1_000

    def test_finalize_fee_exceeds_photons_rejected(self):
        proof = _make_spv_proof()
        with pytest.raises(ValidationError, match="fee"):
            build_finalize_tx(
                spv_proof=proof,
                claimed_redeem_hex="ab" * 50,
                funding_txid="cd" * 32,
                funding_vout=0,
                funding_photons=500,
                to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                fee_sats=1_000,
            )

    def test_finalize_scriptsig_contains_header_bytes(self):
        """The header bytes must appear verbatim in the serialized tx."""
        proof = _make_spv_proof(headers=[b"\xde\xad\xbe\xef" + b"\x00" * 76])
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        assert b"\xde\xad\xbe\xef" in raw

    def test_finalize_scriptsig_contains_raw_tx_bytes(self):
        proof = _make_spv_proof()
        # raw_tx is b'\x01' * 100 from _make_spv_proof
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        assert b"\x01" * 100 in raw

    def test_finalize_multiple_headers(self):
        headers = [b"\x11" * 80, b"\x22" * 80, b"\x33" * 80]
        proof = _make_spv_proof(headers=headers)
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        for h in headers:
            assert h in raw

    def test_finalize_tx_version_is_2(self):
        proof = _make_spv_proof()
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        version = int.from_bytes(raw[:4], "little")
        assert version == 2

    def test_finalize_invalid_address_rejected(self):
        proof = _make_spv_proof()
        with pytest.raises(ValidationError):
            build_finalize_tx(
                spv_proof=proof,
                claimed_redeem_hex="ab" * 50,
                funding_txid="cd" * 32,
                funding_vout=0,
                funding_photons=1_000_000,
                to_address="notanaddress!!!",
                fee_sats=1_000,
            )

    def test_finalize_txid_is_hash256_of_raw(self):
        """txid must be hash256(raw_tx) reversed, as hex."""
        import hashlib

        proof = _make_spv_proof()
        result = build_finalize_tx(
            spv_proof=proof,
            claimed_redeem_hex="ab" * 50,
            funding_txid="cd" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            to_address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        h1 = hashlib.sha256(raw).digest()
        h2 = hashlib.sha256(h1).digest()
        expected_txid = h2[::-1].hex()
        assert result.txid == expected_txid


# ---------------------------------------------------------------------------
# build_forfeit_tx tests
# ---------------------------------------------------------------------------


class TestBuildForfeitTx:
    PAST_DEADLINE = 1_735_686_400  # exactly MIN_CLAIM_DEADLINE = 2025-01-01

    def _past_offer(self) -> GravityOffer:
        claimed_redeem = bytes.fromhex("bb" * 100)
        return GravityOffer(
            btc_receive_hash=b"\x00" * 20,
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=b"\x00" * 20,
            claim_deadline=self.PAST_DEADLINE,
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
            expected_code_hash_hex=compute_p2sh_code_hash(claimed_redeem).hex(),
        )

    def test_forfeit_future_deadline_rejected(self):
        claimed_redeem = bytes.fromhex("bb" * 100)
        offer = GravityOffer(
            btc_receive_hash=b"\x00" * 20,
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=b"\x00" * 20,
            claim_deadline=int(time.time()) + 3600,
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
            expected_code_hash_hex=compute_p2sh_code_hash(claimed_redeem).hex(),
        )
        with pytest.raises(ValidationError, match="future"):
            build_forfeit_tx(
                offer,
                "aa" * 32,
                0,
                1_000_000,
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                1_000,
            )

    def test_forfeit_past_deadline_builds_tx(self):
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        assert isinstance(result, ForfeitResult)
        assert result.tx_hex
        bytes.fromhex(result.tx_hex)  # valid hex

    def test_forfeit_txid_is_64_hex_chars(self):
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        assert len(result.txid) == 64

    def test_forfeit_output_photons_correct(self):
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        assert result.output_photons == 999_000
        assert result.fee_sats == 1_000

    def test_forfeit_fee_exceeds_photons_rejected(self):
        offer = self._past_offer()
        with pytest.raises(ValidationError, match="fee"):
            build_forfeit_tx(
                offer,
                "aa" * 32,
                0,
                500,
                "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
                1_000,
            )

    def test_forfeit_locktime_equals_claim_deadline(self):
        """Last 4 bytes of the raw tx = nLockTime = claim_deadline."""
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        locktime = int.from_bytes(raw[-4:], "little")
        assert locktime == offer.claim_deadline

    def test_forfeit_input_sequence_is_cltv_compatible(self):
        """Input sequence must be 0xFFFFFFFE (< 0xFFFFFFFF) for CLTV."""
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        # 0xFFFFFFFE as little-endian 4 bytes
        assert b"\xfe\xff\xff\xff" in raw

    def test_forfeit_tx_version_is_2(self):
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        version = int.from_bytes(raw[:4], "little")
        assert version == 2

    def test_forfeit_scriptsig_starts_with_op1(self):
        """scriptSig must start with OP_1 (0x51)."""
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        # version(4) + varint(1 input)(1) + prevhash(32) + vout(4) + scriptsig_len(varint)
        # scriptsig_len is 1 byte for small scripts
        pos = 4 + 1 + 32 + 4  # version + input_count + prevhash + vout
        # read varint for scriptsig length
        script_sig_start = pos + 1  # 1-byte varint for scripts < 253 bytes
        # OP_1 should be the first byte of the scriptSig
        assert raw[script_sig_start] == 0x51

    def test_forfeit_invalid_address_rejected(self):
        offer = self._past_offer()
        with pytest.raises(ValidationError):
            build_forfeit_tx(
                offer,
                "aa" * 32,
                0,
                1_000_000,
                "not-valid!!!",
                1_000,
            )

    def test_forfeit_txid_is_hash256_of_raw(self):
        import hashlib

        offer = self._past_offer()
        result = build_forfeit_tx(
            offer,
            "aa" * 32,
            0,
            1_000_000,
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        h1 = hashlib.sha256(raw).digest()
        h2 = hashlib.sha256(h1).digest()
        expected_txid = h2[::-1].hex()
        assert result.txid == expected_txid


# ---------------------------------------------------------------------------
# build_claim_tx tests (structural only — signing requires coincurve)
# ---------------------------------------------------------------------------


class TestBuildClaimTx:
    """
    Structural tests for build_claim_tx.

    Full signing is tested at the integration level when a Radiant node is
    available.  Here we verify input validation guards.
    """

    def _make_privkey(self) -> PrivateKeyMaterial:
        # secp256k1 scalar = 1 (minimal valid key)
        return PrivateKeyMaterial(b"\x00" * 31 + b"\x01")

    def test_claim_fee_exceeds_photons_rejected(self):
        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer()
        with pytest.raises(ValidationError, match="fee"):
            build_claim_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=500,
                fee_sats=1_000,
                taker_privkey=self._make_privkey(),
                accept_short_deadline=True,
            )

    def test_claim_deadline_guard_triggered(self):
        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer(claim_deadline=int(time.time()) + 3600)
        with pytest.raises(ValidationError, match="24h"):
            build_claim_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=1_000_000,
                fee_sats=1_000,
                taker_privkey=self._make_privkey(),
                accept_short_deadline=False,  # guard active
            )

    def test_claim_builds_with_valid_key(self):
        """Full sign+serialize with a real secp256k1 private key."""
        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer()
        result = build_claim_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            fee_sats=1_000,
            taker_privkey=self._make_privkey(),
            accept_short_deadline=True,
        )
        assert isinstance(result, ClaimResult)
        assert result.tx_hex
        bytes.fromhex(result.tx_hex)
        assert len(result.txid) == 64
        assert result.output_photons == 999_000
        assert result.fee_sats == 1_000
        assert result.offer_p2sh
        assert result.claimed_p2sh

    def test_claim_tx_version_is_2(self):
        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer()
        result = build_claim_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            fee_sats=1_000,
            taker_privkey=self._make_privkey(),
            accept_short_deadline=True,
        )
        raw = bytes.fromhex(result.tx_hex)
        version = int.from_bytes(raw[:4], "little")
        assert version == 2

    def test_claim_scriptsig_contains_op1_selector(self):
        """scriptSig must contain OP_1 (0x51) as the selector byte."""
        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer()
        result = build_claim_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            fee_sats=1_000,
            taker_privkey=self._make_privkey(),
            accept_short_deadline=True,
        )
        raw = bytes.fromhex(result.tx_hex)
        assert b"\x51" in raw  # OP_1 selector

    def test_claim_txid_is_hash256_of_raw(self):
        import hashlib

        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer()
        result = build_claim_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            fee_sats=1_000,
            taker_privkey=self._make_privkey(),
            accept_short_deadline=True,
        )
        raw = bytes.fromhex(result.tx_hex)
        h1 = hashlib.sha256(raw).digest()
        h2 = hashlib.sha256(h1).digest()
        expected_txid = h2[::-1].hex()
        assert result.txid == expected_txid

    def test_claim_offer_p2sh_differs_from_claimed_p2sh(self):
        """Different redeem scripts must yield different P2SH addresses."""
        from pyrxd.gravity import build_claim_tx

        offer = _make_gravity_offer(
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )
        result = build_claim_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            fee_sats=1_000,
            taker_privkey=self._make_privkey(),
            accept_short_deadline=True,
        )
        assert result.offer_p2sh != result.claimed_p2sh

    def test_claim_rejects_mismatched_code_hash(self):
        """H-1: build_claim_tx must raise if claimed_redeem_hex doesn't match
        offer.expected_code_hash_hex (audit 05-F-13 enforcement)."""
        from pyrxd.gravity import build_claim_tx

        # Build an offer where expected_code_hash_hex is correct for "bb"*100
        offer = _make_gravity_offer(
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )
        # Now tamper with claimed_redeem_hex via dataclass replace
        from dataclasses import replace as dc_replace

        tampered = dc_replace(offer, claimed_redeem_hex="cc" * 100)

        with pytest.raises(ValidationError, match="expected_code_hash_hex"):
            build_claim_tx(
                offer=tampered,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=1_000_000,
                fee_sats=1_000,
                taker_privkey=self._make_privkey(),
                accept_short_deadline=True,
            )


# ---------------------------------------------------------------------------
# Module import test
# ---------------------------------------------------------------------------


class TestGravityModuleImports:
    def test_all_public_symbols_importable(self):
        from pyrxd.gravity import (  # noqa: F401
            ClaimResult,
            FinalizeResult,
            ForfeitResult,
            GravityOffer,
            build_claim_tx,
            build_finalize_tx,
            build_forfeit_tx,
            compute_p2sh_code_hash,
        )


def _ser_output(value: int, script: bytes) -> bytes:
    """Wire-serialize one output: value(8 LE) + 1-byte len + script."""
    return value.to_bytes(8, "little") + bytes([len(script)]) + script


_P2PKH_AA = bytes.fromhex("76a914" + "aa" * 20 + "88ac")
_P2PKH_BB = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
# FT locking script shape: P2PKH + OP_STATESEPARATOR OP_PUSHINPUTREF <36B ref> <12B FT fingerprint>
_FT_OUTPUT = (
    bytes.fromhex("76a914" + "cc" * 20 + "88ac") + b"\xbd\xd0" + bytes(36) + bytes.fromhex("dec0e9aa76e378e4a269e69d")
)


class TestSighashBackcompat:
    """Regression guard for the Phase-1 de-duplication of
    ``_compute_hash_output_hashes``.

    The Gravity-specific copy (which hard-coded ``totalRefs = 0``) was deleted
    in favor of the canonical ref-aware implementation in
    ``pyrxd.transaction.transaction_preimage``. These golden vectors were
    captured from the OLD implementation *before* the refactor; the de-dup must
    reproduce them byte-for-byte for the ``totalRefs = 0`` path that plain-RXD
    Gravity uses today. See
    docs/plans/2026-05-19-feat-gravity-ref-bearing-covenant-plan.md (Phase 1).
    """

    # Golden vectors captured from the pre-refactor _compute_hash_output_hashes.
    GOLDEN = {
        "single_p2pkh": (
            _ser_output(546, _P2PKH_AA),
            "42053adc8c31d4299864f45101c180c7397471cd13b2ac0451217754649b33cf",
        ),
        "two_p2pkh": (
            _ser_output(1000, _P2PKH_AA) + _ser_output(2000, _P2PKH_BB),
            "0aec905422816fe9325e8fa82f37f2ef0a8dd78fde9a9f5518ba34c315dbe0d8",
        ),
    }

    @pytest.mark.parametrize("scenario", list(GOLDEN.keys()))
    def test_totalrefs0_byte_identical_to_pre_refactor(self, scenario):
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        outputs_serialized, expected = self.GOLDEN[scenario]
        assert _compute_hash_output_hashes(outputs_serialized).hex() == expected

    def test_ft_output_computes_real_refshash_golden(self):
        """The point of the de-dup: a ref-bearing output must hash with the REAL
        refsHash, not the old hard-coded zeros. Pin the FT result to a golden
        value captured from the canonical (ref-aware) impl. A bare ``ft != plain``
        check is too weak — two different scripts differ in the script-hash term
        regardless of refsHash, so it could pass even if refsHash were still
        zeroed. This golden pins the ref accounting itself."""
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        result = _compute_hash_output_hashes(_ser_output(546, _FT_OUTPUT)).hex()
        assert result == "c1e66ffcb9c4ced99641614ff23ccb185cbe1c721ebded2eeb9cc2b622609605"

    def test_large_script_0xfd_varint_boundary(self):
        """A script >= 0xFD bytes uses a 2-byte varint length prefix. Golden
        captured from the canonical impl — locks the varint-boundary path the
        old hand-rolled parser handled explicitly."""
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        big_script = b"\x6a" + b"\x4c\xfa" + bytes(250)  # OP_RETURN OP_PUSHDATA1 250 <250> = 253 bytes
        blob = (546).to_bytes(8, "little") + b"\xfd" + len(big_script).to_bytes(2, "little") + big_script
        assert (
            _compute_hash_output_hashes(blob).hex()
            == "98ba70b21fcac18a6e6ef8c7232b945856455b028e6e62b8ad845f8f7dd86600"
        )

    def test_empty_outputs_blob(self):
        """Empty input must not crash (no IndexError on the empty-list path)."""
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        # hash256(b"") — the well-defined hash of zero outputs.
        assert _compute_hash_output_hashes(b"").hex() == (
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        )

    def test_trailing_garbage_rejected(self):
        """A trailing fragment that can't form a full output record must raise,
        not be silently ignored."""
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        blob = _ser_output(546, _P2PKH_AA) + b"\xff\xff"  # 2 trailing bytes
        with pytest.raises(ValidationError):
            _compute_hash_output_hashes(blob)

    def test_overlong_script_length_rejected(self):
        """An output whose script-length varint OVER-CLAIMS must raise — not
        produce a hash over a silently truncated script. This is the signing-path
        regression guard: the old hand-rolled parser caught it explicitly and the
        from_hex-based adapter must too."""
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        # Claims a 25-byte script but provides only 13 bytes.
        blob = (546).to_bytes(8, "little") + bytes([25]) + bytes.fromhex("76a914" + "aa" * 10)
        with pytest.raises(ValidationError):
            _compute_hash_output_hashes(blob)

    def test_midstream_truncation_rejected(self):
        """A valid first output followed by a truncated second output must raise,
        not hash only the first and silently drop the corrupt tail."""
        from pyrxd.gravity.transactions import _compute_hash_output_hashes

        truncated_second = (1000).to_bytes(8, "little") + bytes([25]) + bytes.fromhex("76a914aa")
        blob = _ser_output(546, _P2PKH_AA) + truncated_second
        with pytest.raises(ValidationError):
            _compute_hash_output_hashes(blob)

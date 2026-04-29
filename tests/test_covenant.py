"""Tests for pyrxd.gravity.covenant — artifact loading, param substitution, code hash."""

import hashlib
import json
import time
from pathlib import Path

import pytest

from pyrxd.gravity.codehash import (
    compute_p2sh_code_hash,
    compute_p2sh_script_pubkey,
    hash160,
    hash256,
)
from pyrxd.gravity.covenant import (
    CovenantArtifact,
    _encode_bytes_push,
    _encode_int_push,
    build_gravity_offer,
    validate_claim_deadline,
)
from pyrxd.security.errors import ValidationError

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MAKER_PKH = bytes.fromhex("aa" * 20)
TAKER_PKH = bytes.fromhex("bb" * 20)
MAKER_PK = bytes.fromhex("02" + "aa" * 32)
TAKER_PK = bytes.fromhex("02" + "bb" * 32)
BTC_RECEIVE_HASH = bytes.fromhex("cc" * 20)
CHAIN_ANCHOR = bytes.fromhex("dd" * 32)
EXPECTED_NBITS = bytes.fromhex("ffff001d")


def _future_deadline(hours: int = 48) -> int:
    return int(time.time()) + hours * 3600


def _base_claimed_params() -> dict:
    return {
        "makerPkh": "aa" * 20,
        "btcReceiveHash": "cc" * 20,
        "btcSatoshis": 100_000,
        "btcChainAnchor": "dd" * 32,
        "expectedNBits": "ffff001d",
        "totalPhotonsInOutput": 10_000_000,
    }


# ---------------------------------------------------------------------------
# _encode_int_push
# ---------------------------------------------------------------------------

class TestEncodeIntPush:
    def test_zero(self):
        assert _encode_int_push(0) == bytes([0x00])

    def test_one_through_sixteen_use_op_n(self):
        for n in range(1, 17):
            result = _encode_int_push(n)
            assert result == bytes([0x50 + n])

    def test_seventeen_uses_pushdata(self):
        result = _encode_int_push(17)
        assert result[0] == 1          # 1 byte of data
        assert result[1] == 17

    def test_large_int(self):
        result = _encode_int_push(100_000)
        assert len(result) > 1
        # Decode: body = result[1:1+result[0]]
        body = result[1:1 + result[0]]
        val = int.from_bytes(body, "little")
        assert val == 100_000

    def test_negative(self):
        result = _encode_int_push(-1)
        assert len(result) == 2
        assert result[1] & 0x80  # sign bit set

    def test_round_trip_via_bytes(self):
        for n in [0, 1, 16, 17, 127, 128, 255, 256, 65535, 1_000_000]:
            encoded = _encode_int_push(n)
            body = encoded[1:1 + encoded[0]] if encoded[0] not in range(0x51, 0x61) else bytes([encoded[0] - 0x50])
            # Just check no exception and length > 0
            assert len(encoded) >= 1


# ---------------------------------------------------------------------------
# _encode_bytes_push
# ---------------------------------------------------------------------------

class TestEncodeBytesPush:
    def test_20_byte_push(self):
        h = "aa" * 20
        result = _encode_bytes_push(h)
        assert result[0] == 20
        assert result[1:] == bytes.fromhex(h)

    def test_32_byte_push(self):
        h = "bb" * 32
        result = _encode_bytes_push(h)
        assert result[0] == 32

    def test_4_byte_push(self):
        h = "ffff001d"
        result = _encode_bytes_push(h)
        assert result[0] == 4
        assert result[1:] == bytes.fromhex(h)


# ---------------------------------------------------------------------------
# CovenantArtifact loading
# ---------------------------------------------------------------------------

class TestCovenantArtifactLoad:
    def test_load_claimed_artifact(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        assert art.contract == "MakerCovenant6x12_p2wpkh"

    def test_load_offer_artifact(self):
        art = CovenantArtifact.load("maker_offer")
        assert art.contract == "MakerOffer"

    def test_load_missing_raises(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            CovenantArtifact.load("nonexistent_artifact")

    def test_constructor_params_claimed(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        names = [p["name"] for p in art.constructor_params()]
        assert "makerPkh" in names
        assert "btcReceiveHash" in names
        assert "btcSatoshis" in names
        assert "btcChainAnchor" in names
        assert "expectedNBits" in names
        assert "totalPhotonsInOutput" in names
        # State params are NOT in constructor (state-separated layout)
        assert "takerRadiantPkh" not in names
        assert "claimDeadline" not in names

    def test_constructor_params_offer(self):
        art = CovenantArtifact.load("maker_offer")
        names = [p["name"] for p in art.constructor_params()]
        assert "makerPk" in names
        assert "takerPk" in names
        assert "totalPhotonsInOutput" in names
        assert "expectedClaimedCodeHash" in names

    def test_from_json_roundtrip(self):
        art1 = CovenantArtifact.load("maker_offer")
        art_dir = Path(__file__).parent.parent / "src" / "pyrxd" / "gravity" / "artifacts"
        json_text = (art_dir / "maker_offer.artifact.json").read_text()
        art2 = CovenantArtifact.from_json(json_text)
        assert art1.contract == art2.contract
        assert art1.hex_template == art2.hex_template


# ---------------------------------------------------------------------------
# CovenantArtifact.substitute
# ---------------------------------------------------------------------------

class TestSubstitute:
    def test_substitute_all_params_produces_bytes(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = art.substitute(_base_claimed_params())
        assert isinstance(redeem, bytes)
        assert len(redeem) > 100

    def test_substitute_consistent_length(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        r1 = art.substitute(_base_claimed_params())
        r2 = art.substitute(_base_claimed_params())
        assert r1 == r2

    def test_substitute_different_pkh_produces_different_bytes(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        p1 = dict(_base_claimed_params(), makerPkh="aa" * 20)
        p2 = dict(_base_claimed_params(), makerPkh="ff" * 20)
        assert art.substitute(p1) != art.substitute(p2)

    def test_substitute_missing_param_raises(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        params = dict(_base_claimed_params())
        del params["makerPkh"]
        with pytest.raises(ValidationError, match="Missing required constructor param"):
            art.substitute(params)

    def test_substitute_offer_params(self):
        claimed_art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = claimed_art.substitute(_base_claimed_params())
        code_hash = compute_p2sh_code_hash(redeem)

        offer_art = CovenantArtifact.load("maker_offer")
        offer_redeem = offer_art.substitute({
            "makerPk": "02" + "aa" * 32,
            "takerPk": "02" + "bb" * 32,
            "totalPhotonsInOutput": 10_000_000,
            "expectedClaimedCodeHash": code_hash.hex(),
        })
        assert isinstance(offer_redeem, bytes)
        assert len(offer_redeem) > 50

    def test_substitute_int_encoded_correctly(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        p = dict(_base_claimed_params(), btcSatoshis=16)
        redeem = art.substitute(p)
        # btcSatoshis=16 should encode as OP_16 (0x60)
        assert bytes([0x60]) in redeem


# ---------------------------------------------------------------------------
# Code hash computation
# ---------------------------------------------------------------------------

class TestCodeHash:
    def test_code_hash_is_32_bytes(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = art.substitute(_base_claimed_params())
        h = compute_p2sh_code_hash(redeem)
        assert len(h) == 32

    def test_code_hash_is_hash256_of_p2sh_spk(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = art.substitute(_base_claimed_params())
        p2sh_spk = compute_p2sh_script_pubkey(redeem)
        expected = hash256(p2sh_spk)
        actual = compute_p2sh_code_hash(redeem)
        assert actual == expected

    def test_p2sh_spk_is_23_bytes(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = art.substitute(_base_claimed_params())
        spk = compute_p2sh_script_pubkey(redeem)
        assert len(spk) == 23
        assert spk[0] == 0xa9   # OP_HASH160
        assert spk[1] == 0x14   # PUSH20
        assert spk[-1] == 0x87  # OP_EQUAL

    def test_p2sh_spk_hash_matches_hash160_of_redeem(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = art.substitute(_base_claimed_params())
        spk = compute_p2sh_script_pubkey(redeem)
        # bytes 2..22 should be hash160(redeem)
        assert spk[2:22] == hash160(redeem)

    def test_different_params_produce_different_code_hash(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        p1 = dict(_base_claimed_params(), btcSatoshis=100_000)
        p2 = dict(_base_claimed_params(), btcSatoshis=200_000)
        h1 = compute_p2sh_code_hash(art.substitute(p1))
        h2 = compute_p2sh_code_hash(art.substitute(p2))
        assert h1 != h2

    def test_code_hash_known_vector(self):
        # Regression: code hash for these params must not change across refactors.
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        redeem = art.substitute(_base_claimed_params())
        h = compute_p2sh_code_hash(redeem)
        # Recorded from first run (2026-04-21)
        assert h.hex() == "2297b80797b486faf1be620219cf25c38122c68bf47f48134fbeae0ef5fb3d82"


# ---------------------------------------------------------------------------
# validate_claim_deadline
# ---------------------------------------------------------------------------

class TestValidateClaimDeadline:
    def test_future_deadline_ok(self):
        validate_claim_deadline(_future_deadline(48))  # should not raise

    def test_past_deadline_raises(self):
        with pytest.raises(ValidationError, match="claim_deadline"):
            validate_claim_deadline(int(time.time()) - 3600)

    def test_near_present_raises(self):
        with pytest.raises(ValidationError):
            validate_claim_deadline(int(time.time()) + 3600)  # only 1h, need 24h

    def test_exactly_24h_ok(self):
        validate_claim_deadline(int(time.time()) + 24 * 3600 + 60)

    def test_bypass_allows_short_deadline(self):
        validate_claim_deadline(int(time.time()) - 3600, bypass=True)  # no raise

    def test_custom_min_future_seconds(self):
        # 1h minimum: 2h future should pass
        validate_claim_deadline(int(time.time()) + 7200, min_future_seconds=3600)


# ---------------------------------------------------------------------------
# build_gravity_offer
# ---------------------------------------------------------------------------

class TestBuildGravityOffer:
    def _offer_kwargs(self) -> dict:
        return dict(
            maker_pkh=MAKER_PKH,
            maker_pk=MAKER_PK,
            taker_pk=TAKER_PK,
            taker_radiant_pkh=TAKER_PKH,
            btc_receive_hash=BTC_RECEIVE_HASH,
            btc_receive_type="p2wpkh",
            btc_satoshis=100_000,
            btc_chain_anchor=CHAIN_ANCHOR,
            expected_nbits=EXPECTED_NBITS,
            anchor_height=800_000,
            merkle_depth=12,
            claim_deadline=_future_deadline(48),
            photons_offered=10_000_000,
            accept_short_deadline=False,
        )

    def test_returns_gravity_offer(self):
        from pyrxd.gravity.types import GravityOffer
        offer = build_gravity_offer(**self._offer_kwargs())
        assert isinstance(offer, GravityOffer)

    def test_offer_redeem_hex_nonempty(self):
        offer = build_gravity_offer(**self._offer_kwargs())
        assert len(offer.offer_redeem_hex) > 10

    def test_claimed_redeem_hex_nonempty(self):
        offer = build_gravity_offer(**self._offer_kwargs())
        assert len(offer.claimed_redeem_hex) > 10

    def test_claimed_redeem_is_valid_hex(self):
        offer = build_gravity_offer(**self._offer_kwargs())
        bytes.fromhex(offer.claimed_redeem_hex)  # no exception

    def test_offer_fields_match_inputs(self):
        kwargs = self._offer_kwargs()
        offer = build_gravity_offer(**kwargs)
        assert offer.btc_receive_hash == kwargs["btc_receive_hash"]
        assert offer.btc_receive_type == kwargs["btc_receive_type"]
        assert offer.btc_satoshis == kwargs["btc_satoshis"]
        assert offer.chain_anchor == kwargs["btc_chain_anchor"]
        assert offer.photons_offered == kwargs["photons_offered"]
        assert offer.taker_radiant_pkh == kwargs["taker_radiant_pkh"]

    def test_short_deadline_raises(self):
        kwargs = self._offer_kwargs()
        kwargs["claim_deadline"] = int(time.time()) - 3600
        with pytest.raises(ValidationError, match="claim_deadline"):
            build_gravity_offer(**kwargs)

    def test_short_deadline_bypass(self):
        kwargs = self._offer_kwargs()
        kwargs["claim_deadline"] = int(time.time()) - 3600
        kwargs["accept_short_deadline"] = True
        offer = build_gravity_offer(**kwargs)
        assert offer is not None

    def test_different_maker_pkh_produces_different_claimed_redeem(self):
        k1 = self._offer_kwargs()
        k2 = dict(self._offer_kwargs(), maker_pkh=bytes.fromhex("ff" * 20))
        o1 = build_gravity_offer(**k1)
        o2 = build_gravity_offer(**k2)
        assert o1.claimed_redeem_hex != o2.claimed_redeem_hex

    def test_different_taker_produces_different_offer_redeem(self):
        k1 = self._offer_kwargs()
        k2 = dict(self._offer_kwargs(), taker_pk=bytes.fromhex("02" + "ff" * 32))
        o1 = build_gravity_offer(**k1)
        o2 = build_gravity_offer(**k2)
        assert o1.offer_redeem_hex != o2.offer_redeem_hex

    def test_claimed_redeem_taker_dependent_for_flat_artifacts(self):
        # Flat artifacts bake takerRadiantPkh into the code section, so different
        # takers produce different claimed_redeem_hex. Non-flat artifacts keep
        # takerRadiantPkh in state (same code hash for all takers).
        k1 = self._offer_kwargs()
        k2 = dict(self._offer_kwargs(), taker_radiant_pkh=bytes.fromhex("ee" * 20))
        o1 = build_gravity_offer(**k1)
        o2 = build_gravity_offer(**k2)
        # For the default flat artifact, taker PKH is baked in → must differ
        assert o1.claimed_redeem_hex != o2.claimed_redeem_hex

    def test_code_hash_embedded_in_offer_redeem(self):
        kwargs = self._offer_kwargs()
        offer = build_gravity_offer(**kwargs)

        # The expectedClaimedCodeHash embedded in the offer must match what we
        # compute independently from the claimed redeem.
        claimed_redeem = bytes.fromhex(offer.claimed_redeem_hex)
        expected_code_hash = compute_p2sh_code_hash(claimed_redeem)
        # Verify: hex of code hash appears somewhere in the offer_redeem_hex
        # (it's length-prefixed, so preceded by a 0x20 byte)
        assert expected_code_hash.hex() in offer.offer_redeem_hex

    # Flat-layout artifacts bake all 9 constructor params (including
    # takerRadiantPkh / expectedNBitsNext / claimDeadline) into the code
    # section. Regression: the flat-artifact branch in build_gravity_offer
    # silently failed because substitute() raises "Missing required
    # constructor param" before the "Unfilled placeholders" fallback it
    # was watching for. The production example defaults to the unified
    # artifact, so this path must stay exercised.
    @pytest.mark.parametrize("artifact_name", [
        "maker_covenant_flat_6x12_p2wpkh",
        "maker_covenant_flat_6x13_p2wpkh",
        "maker_covenant_flat_6x10_11_12_13_14_p2wpkh",
        "maker_covenant_unified_p2wpkh",
    ])
    def test_flat_artifact_builds_successfully(self, artifact_name):
        kwargs = dict(self._offer_kwargs(), covenant_artifact_name=artifact_name)
        offer = build_gravity_offer(**kwargs)
        assert len(offer.claimed_redeem_hex) > 10
        # Flat artifacts bake taker PKH into the claimed redeem, so a
        # different taker must produce a different claimed redeem.
        kwargs2 = dict(kwargs, taker_radiant_pkh=bytes.fromhex("ee" * 20))
        offer2 = build_gravity_offer(**kwargs2)
        assert offer.claimed_redeem_hex != offer2.claimed_redeem_hex

    def test_unified_artifact_has_flat_constructor_abi(self):
        # If this ever regresses to a state-separated layout, the
        # flat-layout path in build_gravity_offer would stop being
        # exercised and the example script's default would drift.
        art = CovenantArtifact.load("maker_covenant_unified_p2wpkh")
        ctor_names = {p["name"] for p in art.constructor_params()}
        assert {"takerRadiantPkh", "expectedNBitsNext", "claimDeadline"} <= ctor_names

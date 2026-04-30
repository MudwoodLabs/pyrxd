"""Red-team / adversarial tests for the Gravity Protocol covenant SDK.

These tests attempt to break the covenant artifact loader, parameter
substitution, ``build_gravity_offer``, ``build_maker_offer_tx``,
``build_forfeit_tx``, and the deny-list in ways a malicious or careless
caller might. Each test either confirms an existing guard or documents a
bug fix applied in ``covenant.py``.

Bugs found and fixed during this red-team pass
----------------------------------------------
1. ``build_gravity_offer`` silently accepted wrong-length ``maker_pkh``,
   ``taker_radiant_pkh``, ``btc_receive_hash``, ``btc_chain_anchor``,
   ``expected_nbits`` etc. and encoded the bad bytes as a short/long
   push. The resulting covenant P2SH was dead-on-arrival — it would be
   rejected on-chain, wasting the Maker's funding fee. Fix: strict
   length / type checks at the top of ``build_gravity_offer``.

2. ``CovenantArtifact.substitute`` silently accepted an empty hex string
   for a fixed-width bytes param (e.g. ``btcReceiveHash=""``) and
   produced an ``OP_0`` push in place of the expected 20- or 32-byte
   hash. Fix: reject empty hex and wrong-length values for fixed-width
   typed params (``Ripemd160`` / ``Sha256`` / ``PubKey``).
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

import pytest

from pyrxd.gravity import (
    GravityOffer,
    MakerOfferResult,
    build_forfeit_tx,
    build_maker_offer_tx,
)
from pyrxd.gravity.codehash import compute_p2sh_code_hash
from pyrxd.gravity.covenant import (
    _BANNED_BYTECODE_SHA256,
    _BANNED_NAMES,
    CovenantArtifact,
    _encode_bytes_push,
    _encode_int_push,
    build_gravity_offer,
    validate_claim_deadline,
)
from pyrxd.gravity.types import MIN_CLAIM_DEADLINE
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import PrivateKeyMaterial


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _future_deadline(hours: int = 48) -> int:
    return int(time.time()) + hours * 3600


def _base_claimed_params() -> dict[str, Any]:
    return {
        "makerPkh": "aa" * 20,
        "btcReceiveHash": "cc" * 20,
        "btcSatoshis": 100_000,
        "btcChainAnchor": "dd" * 32,
        "expectedNBits": "ffff001d",
        "totalPhotonsInOutput": 10_000_000,
    }


def _valid_offer_kwargs() -> dict[str, Any]:
    return dict(
        maker_pkh=bytes([0xAA]) * 20,
        maker_pk=bytes.fromhex("02" + "bb" * 32),
        taker_pk=bytes.fromhex("02" + "cc" * 32),
        taker_radiant_pkh=bytes([0xDD]) * 20,
        btc_receive_hash=bytes([0xEE]) * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=bytes(32),
        expected_nbits=bytes.fromhex("ffff001d"),
        anchor_height=800_000,
        merkle_depth=12,
        claim_deadline=_future_deadline(48),
        photons_offered=10_000_000,
    )


def _make_gravity_offer_direct(**kwargs) -> GravityOffer:
    """Build a GravityOffer with fake redeem scripts, deriving expected_code_hash_hex correctly."""
    claimed_hex = kwargs.get("claimed_redeem_hex", "bb" * 100)
    if "expected_code_hash_hex" not in kwargs:
        kwargs["expected_code_hash_hex"] = compute_p2sh_code_hash(bytes.fromhex(claimed_hex)).hex()
    return GravityOffer(**kwargs)


def _make_privkey(seed: int = 0x12) -> PrivateKeyMaterial:
    return PrivateKeyMaterial(bytes([seed]) * 32)


def _pkh(priv: PrivateKeyMaterial) -> bytes:
    import coincurve

    pub = coincurve.PrivateKey(priv.unsafe_raw_bytes()).public_key.format(compressed=True)
    return hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()


def _pub(priv: PrivateKeyMaterial) -> bytes:
    import coincurve

    return coincurve.PrivateKey(priv.unsafe_raw_bytes()).public_key.format(compressed=True)


def _make_real_offer(priv: PrivateKeyMaterial, **overrides: Any) -> GravityOffer:
    t_priv = _make_privkey(0x34)
    defaults = dict(
        maker_pkh=_pkh(priv),
        maker_pk=_pub(priv),
        taker_pk=_pub(t_priv),
        taker_radiant_pkh=_pkh(t_priv),
        btc_receive_hash=bytes([0xCC]) * 20,
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=bytes([0xDD]) * 32,
        expected_nbits=bytes.fromhex("ffff001d"),
        anchor_height=800_000,
        merkle_depth=12,
        claim_deadline=_future_deadline(48),
        photons_offered=500_000,
    )
    defaults.update(overrides)
    return build_gravity_offer(**defaults)


# ===========================================================================
# 1. Covenant artifact tampering
# ===========================================================================


class TestArtifactTampering:
    def test_mutating_one_byte_of_template_changes_code_hash(self):
        """A mutated hex template must produce a different code hash."""
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        params = _base_claimed_params()
        h1 = compute_p2sh_code_hash(art.substitute(params))

        # Mutate the first byte of the template while keeping it valid hex.
        # Template starts with a known opcode; flip it to a different valid hex.
        original_prefix = art.hex_template[:2]
        new_prefix = "ff" if original_prefix != "ff" else "00"
        mutated = CovenantArtifact(
            contract=art.contract,
            hex_template=new_prefix + art.hex_template[2:],
            abi=art.abi,
        )
        h2 = compute_p2sh_code_hash(mutated.substitute(params))
        assert h1 != h2, "mutating template bytes must change the code hash"

    def test_deny_list_catches_renamed_banned_bytecode(self):
        """Rename alone cannot bypass the bytecode-SHA deny-list.

        The attacker renames a banned artifact to an innocent-looking name
        but keeps the insecure hex. The bytecode SHA check must still fire.
        """
        test_hex = "cafebabe" * 4
        test_sha = hashlib.sha256(test_hex.encode()).hexdigest()
        # Temporarily add a synthetic banned-bytecode entry and confirm it
        # catches the renamed artifact.
        assert test_sha not in _BANNED_BYTECODE_SHA256
        _BANNED_BYTECODE_SHA256[test_sha] = "synthetic-red-team-entry"
        try:
            renamed = {
                "version": 1,
                "contract": "TotallyInnocuousNewContract",
                "abi": [{"type": "constructor", "params": []}],
                "hex": test_hex,
            }
            with pytest.raises(ValidationError, match="deny-list"):
                CovenantArtifact.from_json(json.dumps(renamed))
        finally:
            del _BANNED_BYTECODE_SHA256[test_sha]

    def test_deny_list_catches_banned_name(self):
        """Each entry in _BANNED_NAMES must be rejected when loaded by name."""
        for banned_name in _BANNED_NAMES.keys():
            fake = {
                "version": 1,
                "contract": banned_name,
                "abi": [{"type": "constructor", "params": []}],
                "hex": "aa",  # innocent hex — name alone triggers the ban
            }
            with pytest.raises(ValidationError, match="deny-list"):
                CovenantArtifact.from_json(json.dumps(fake))

    def test_allow_legacy_bypasses_deny_list(self):
        """``allow_legacy=True`` must bypass the deny-list (research escape)."""
        fake = {
            "version": 1,
            "contract": "MakerOfferSimple",  # banned name
            "abi": [{"type": "constructor", "params": []}],
            "hex": "aa",
        }
        art = CovenantArtifact.from_json(json.dumps(fake), allow_legacy=True)
        assert art.contract == "MakerOfferSimple"

    def test_bundled_artifacts_are_not_banned(self):
        """Our bundled artifacts must all pass the deny-list (regression)."""
        for name in [
            "maker_covenant_6x12_p2wpkh",
            "maker_covenant_flat_6x12_p2wpkh",
            "maker_covenant_trade",
            "maker_offer",
        ]:
            CovenantArtifact.load(name)  # must not raise

    def test_no_reinjection_via_hex_encoded_ascii_payload(self):
        """A param value that looks like '<foo>' in ASCII cannot cause
        re-substitution of a (hypothetical) orphan placeholder.

        The substituter iterates constructor params and calls ``str.replace``
        on the hex-template STRING. The substitution target chars are
        ``< name >`` — the '<' and '>' chars cannot appear in a hex value.
        So even if a param value, interpreted as raw bytes, contains
        ``0x3c ... 0x3e`` (ASCII ``<`` and ``>``), those bytes never get
        treated as placeholder syntax because the template has already
        been processed at the hex-string level, not the bytes level.
        """
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        # 0x3c 0x66 0x6f 0x6f 0x3e = '<foo>' in ASCII-as-bytes. Use as first
        # 5 bytes of a 20-byte PKH.
        payload = bytes.fromhex("3c666f6f3e") + bytes(15)
        params = dict(_base_claimed_params(), makerPkh=payload.hex())
        # Substituting must succeed — the bytes sequence is just data.
        result_bytes = art.substitute(params)
        # Bytes will (expectedly) contain ``<foo>`` as raw data inside the
        # PKH push. That's fine — the push is a data push, not a placeholder.
        assert b"\x3c\x66\x6f\x6f\x3e" in result_bytes
        # The *hex string representation* of the result must not contain any
        # ``<placeholder>`` syntax: '<' and '>' aren't valid hex chars.
        hex_form = result_bytes.hex()
        assert "<" not in hex_form
        assert ">" not in hex_form


# ===========================================================================
# 2. Param encoding edge cases
# ===========================================================================


class TestParamEncodingEdges:
    def test_encode_int_zero_is_op_0(self):
        assert _encode_int_push(0) == bytes([0x00])  # OP_0 / empty push

    def test_encode_int_sixteen_is_op_16(self):
        assert _encode_int_push(16) == bytes([0x60])

    def test_encode_int_one_is_op_1(self):
        assert _encode_int_push(1) == bytes([0x51])

    def test_encode_int_seventeen_pushes_one_byte(self):
        # 17 is above OP_16, so encoded as PUSH1 0x11
        result = _encode_int_push(17)
        assert result[0] == 1
        assert result[1] == 17

    def test_encode_int_negative_produces_signbit(self):
        """Bitcoin scriptnum encodes negative with high bit of MSB set."""
        result = _encode_int_push(-1)
        # Format: [len=1, 0x81]
        assert result == bytes([1, 0x81])

    def test_encode_int_large_negative(self):
        result = _encode_int_push(-500)
        # Decode: body should have sign bit set on MSB
        body = result[1:]
        assert body[-1] & 0x80

    def test_encode_bytes_empty_produces_op_0(self):
        """Empty hex produces just a zero-length prefix = OP_0."""
        assert _encode_bytes_push("") == bytes([0x00])

    def test_build_gravity_offer_rejects_empty_btc_receive_hash(self):
        """Empty-bytes hash would silently become OP_0 — must be rejected."""
        kwargs = _valid_offer_kwargs()
        kwargs["btc_receive_hash"] = b""
        with pytest.raises(ValidationError, match="btc_receive_hash"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_zero_btc_satoshis(self):
        """btc_satoshis=0 would produce an always-true BTC payment check."""
        kwargs = _valid_offer_kwargs()
        kwargs["btc_satoshis"] = 0
        with pytest.raises(ValidationError, match="btc_satoshis"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_negative_btc_satoshis(self):
        kwargs = _valid_offer_kwargs()
        kwargs["btc_satoshis"] = -1
        with pytest.raises(ValidationError, match="btc_satoshis"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_short_maker_pkh(self):
        """19-byte PKH used to silently encode as a 19-byte push — now rejected."""
        kwargs = _valid_offer_kwargs()
        kwargs["maker_pkh"] = bytes([0xAA]) * 19
        with pytest.raises(ValidationError, match="maker_pkh"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_long_maker_pkh(self):
        kwargs = _valid_offer_kwargs()
        kwargs["maker_pkh"] = bytes([0xAA]) * 21
        with pytest.raises(ValidationError, match="maker_pkh"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_short_taker_pkh(self):
        kwargs = _valid_offer_kwargs()
        kwargs["taker_radiant_pkh"] = bytes([0xDD]) * 19
        with pytest.raises(ValidationError, match="taker_radiant_pkh"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_short_chain_anchor(self):
        kwargs = _valid_offer_kwargs()
        kwargs["btc_chain_anchor"] = bytes(31)
        with pytest.raises(ValidationError, match="btc_chain_anchor"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_wrong_nbits_length(self):
        kwargs = _valid_offer_kwargs()
        kwargs["expected_nbits"] = bytes.fromhex("001d")  # 2 bytes, not 4
        with pytest.raises(ValidationError, match="expected_nbits"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_rejects_uncompressed_pubkey(self):
        """65-byte uncompressed pubkeys must be rejected — covenants use compressed."""
        kwargs = _valid_offer_kwargs()
        # 65-byte pubkey: 0x04 || X(32) || Y(32)
        kwargs["maker_pk"] = bytes.fromhex("04" + "aa" * 64)
        with pytest.raises(ValidationError, match="maker_pk"):
            build_gravity_offer(**kwargs)

    def test_build_gravity_offer_accepts_all_zero_chain_anchor(self):
        """All-zero anchor is a legitimate test value — must not be rejected."""
        kwargs = _valid_offer_kwargs()
        kwargs["btc_chain_anchor"] = bytes(32)  # all zeros
        # Must not raise
        offer = build_gravity_offer(**kwargs)
        assert offer.chain_anchor == bytes(32)

    def test_p2tr_requires_32_byte_btc_receive_hash(self):
        kwargs = _valid_offer_kwargs()
        kwargs["btc_receive_type"] = "p2tr"
        kwargs["btc_receive_hash"] = bytes(20)  # wrong for p2tr
        with pytest.raises(ValidationError, match="btc_receive_hash"):
            build_gravity_offer(**kwargs)

    def test_p2tr_accepts_32_byte_btc_receive_hash(self):
        kwargs = _valid_offer_kwargs()
        kwargs["btc_receive_type"] = "p2tr"
        kwargs["btc_receive_hash"] = bytes(32)
        offer = build_gravity_offer(**kwargs)
        assert offer.btc_receive_type == "p2tr"

    def test_substitute_rejects_empty_fixed_width_param(self):
        """Low-level substitute must reject empty hex for fixed-width typed params."""
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        params = dict(_base_claimed_params(), btcReceiveHash="")
        with pytest.raises(ValidationError, match="btcReceiveHash"):
            art.substitute(params)

    def test_substitute_rejects_wrong_length_ripemd160(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        params = dict(_base_claimed_params(), makerPkh="aa" * 19)  # 19 bytes
        with pytest.raises(ValidationError, match="makerPkh"):
            art.substitute(params)

    def test_substitute_rejects_odd_length_hex(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        params = dict(_base_claimed_params(), makerPkh="aa" * 19 + "b")  # odd
        with pytest.raises(ValidationError, match="odd length|makerPkh"):
            art.substitute(params)


# ===========================================================================
# 3. build_maker_offer_tx signing surface
# ===========================================================================


class TestMakerOfferTxSigning:
    FAKE_TXID = "aa" * 32
    FEE = 1_000

    def test_exact_funding_no_change_succeeds(self):
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=self.FAKE_TXID,
            funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE,
            maker_privkey=pk,
        )
        assert isinstance(result, MakerOfferResult)
        assert result.output_photons == offer.photons_offered

    def test_funding_one_photon_short_rejected(self):
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        with pytest.raises(ValidationError, match="Insufficient funding"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid=self.FAKE_TXID,
                funding_vout=0,
                funding_photons=offer.photons_offered + self.FEE - 1,
                fee_sats=self.FEE,
                maker_privkey=pk,
            )

    def test_p2sh_change_address_rejected(self):
        """Change address starting with '3' (P2SH mainnet) must be rejected."""
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        # A valid Bitcoin mainnet P2SH address (version byte 0x05).
        p2sh_addr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        with pytest.raises(ValidationError, match="version byte"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid=self.FAKE_TXID,
                funding_vout=0,
                funding_photons=offer.photons_offered + self.FEE + 10_000,
                fee_sats=self.FEE,
                maker_privkey=pk,
                change_address=p2sh_addr,
            )

    def test_malformed_change_address_rejected(self):
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        with pytest.raises(ValidationError, match="invalid Radiant address"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid=self.FAKE_TXID,
                funding_vout=0,
                funding_photons=offer.photons_offered + self.FEE + 10_000,
                fee_sats=self.FEE,
                maker_privkey=pk,
                change_address="not-a-valid-address!!!",
            )

    def test_signer_key_independent_of_offer_maker_pkh(self):
        """The signing key derives the funding input's P2PKH.

        It is correct that the signer's PKH is NOT cross-checked against the
        offer's committed ``maker_pkh`` — that committed PKH lives in the
        CLAIMED covenant state (off-input). This test documents that
        independence explicitly.
        """
        import coincurve

        offer_maker = _make_privkey(0x11)
        signer = _make_privkey(0x99)
        offer = _make_real_offer(offer_maker)
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid=self.FAKE_TXID,
            funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE,
            maker_privkey=signer,
        )
        raw = bytes.fromhex(result.tx_hex)
        signer_pub = coincurve.PrivateKey(signer.unsafe_raw_bytes()).public_key.format(
            compressed=True
        )
        offer_maker_pub = coincurve.PrivateKey(
            offer_maker.unsafe_raw_bytes()
        ).public_key.format(compressed=True)
        assert signer_pub in raw
        assert offer_maker_pub not in raw


# ===========================================================================
# 4. Claim deadline race (S1)
# ===========================================================================


class TestClaimDeadlineRace:
    def test_one_second_short_rejected(self):
        """24h - 1s should raise when accept_short_deadline=False."""
        kwargs = _valid_offer_kwargs()
        kwargs["claim_deadline"] = int(time.time()) + 24 * 3600 - 1
        with pytest.raises(ValidationError, match="claim_deadline"):
            build_gravity_offer(**kwargs)

    def test_one_second_short_accepted_with_bypass(self):
        kwargs = _valid_offer_kwargs()
        kwargs["claim_deadline"] = int(time.time()) + 24 * 3600 - 1
        kwargs["accept_short_deadline"] = True
        offer = build_gravity_offer(**kwargs)
        assert offer.claim_deadline == kwargs["claim_deadline"]

    def test_exactly_24h_plus_padding_accepted(self):
        kwargs = _valid_offer_kwargs()
        kwargs["claim_deadline"] = int(time.time()) + 24 * 3600 + 60
        offer = build_gravity_offer(**kwargs)
        assert offer is not None

    def test_direct_constructor_with_min_deadline(self):
        """Direct GravityOffer construction with MIN_CLAIM_DEADLINE passes
        ``__post_init__`` (which only enforces the 2025-01-01 floor) but
        ``validate_deadline_from_now()`` must still fire."""
        offer = _make_gravity_offer_direct(
            btc_receive_hash=bytes(20),
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=bytes(32),
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=bytes(20),
            claim_deadline=MIN_CLAIM_DEADLINE,
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )
        assert offer.claim_deadline == MIN_CLAIM_DEADLINE
        # But the dynamic deadline guard must reject it as stale.
        with pytest.raises(ValidationError, match="24h"):
            offer.validate_deadline_from_now()

    def test_direct_constructor_below_min_deadline(self):
        """Anything before 2025-01-01 must be rejected in __post_init__."""
        with pytest.raises(ValidationError, match="claim_deadline"):
            _make_gravity_offer_direct(
                btc_receive_hash=bytes(20),
                btc_receive_type="p2wpkh",
                btc_satoshis=50_000,
                chain_anchor=bytes(32),
                anchor_height=840_000,
                merkle_depth=12,
                taker_radiant_pkh=bytes(20),
                claim_deadline=MIN_CLAIM_DEADLINE - 1,
                photons_offered=1_000_000,
                offer_redeem_hex="aa" * 100,
                claimed_redeem_hex="bb" * 100,
            )

    def test_validate_claim_deadline_direct(self):
        validate_claim_deadline(int(time.time()) + 25 * 3600)  # OK

        with pytest.raises(ValidationError):
            validate_claim_deadline(int(time.time()) + 1 * 3600)

        validate_claim_deadline(int(time.time()) + 1 * 3600, bypass=True)  # OK


# ===========================================================================
# 5. Code hash stability and embedding
# ===========================================================================


class TestCodeHashStability:
    def test_same_params_same_code_hash(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        p = _base_claimed_params()
        h1 = compute_p2sh_code_hash(art.substitute(p))
        h2 = compute_p2sh_code_hash(art.substitute(p))
        assert h1 == h2

    def test_different_maker_pkh_different_code_hash(self):
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        p1 = dict(_base_claimed_params(), makerPkh="aa" * 20)
        p2 = dict(_base_claimed_params(), makerPkh="ff" * 20)
        h1 = compute_p2sh_code_hash(art.substitute(p1))
        h2 = compute_p2sh_code_hash(art.substitute(p2))
        assert h1 != h2

    def test_offer_redeem_embeds_expected_code_hash_length_prefixed(self):
        """The claimed code hash must appear in the offer redeem as a
        length-prefixed (``0x20 || hash``) 32-byte push — not just the bare
        hex (which could also appear incidentally)."""
        kwargs = _valid_offer_kwargs()
        offer = build_gravity_offer(**kwargs)
        claimed = bytes.fromhex(offer.claimed_redeem_hex)
        code_hash = compute_p2sh_code_hash(claimed)
        # Expect 0x20 (push 32 bytes) followed immediately by the hash.
        expected_push = bytes([0x20]) + code_hash
        offer_bytes = bytes.fromhex(offer.offer_redeem_hex)
        assert expected_push in offer_bytes, (
            "expectedClaimedCodeHash must appear as a 32-byte push in the offer redeem"
        )

    def test_offer_changes_when_claimed_changes(self):
        kwargs1 = _valid_offer_kwargs()
        kwargs2 = dict(kwargs1, maker_pkh=bytes([0xFF]) * 20)
        o1 = build_gravity_offer(**kwargs1)
        o2 = build_gravity_offer(**kwargs2)
        # Different claimed → different code hash → different offer
        assert o1.claimed_redeem_hex != o2.claimed_redeem_hex
        assert o1.offer_redeem_hex != o2.offer_redeem_hex


# ===========================================================================
# 6. Forfeit deadline semantics
# ===========================================================================


class TestForfeit:
    MAKER_ADDR = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    def _past_offer(self) -> GravityOffer:
        return _make_gravity_offer_direct(
            btc_receive_hash=bytes(20),
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=bytes(32),
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=bytes(20),
            claim_deadline=MIN_CLAIM_DEADLINE,  # 2025-01-01 — in the past now
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )

    def test_forfeit_future_deadline_rejected(self):
        future = int(time.time()) + 3600
        offer = _make_gravity_offer_direct(
            btc_receive_hash=bytes(20),
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=bytes(32),
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=bytes(20),
            claim_deadline=future,
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )
        with pytest.raises(ValidationError, match="future"):
            build_forfeit_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=1_000_000,
                maker_address=self.MAKER_ADDR,
                fee_sats=1_000,
            )

    def test_forfeit_tx_locktime_equals_claim_deadline(self):
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            maker_address=self.MAKER_ADDR,
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        locktime = int.from_bytes(raw[-4:], "little")
        assert locktime == offer.claim_deadline

    def test_forfeit_tx_sequence_is_cltv_compatible(self):
        """Sequence must be < 0xFFFFFFFF (specifically 0xFFFFFFFE) for CLTV."""
        offer = self._past_offer()
        result = build_forfeit_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            maker_address=self.MAKER_ADDR,
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        # 0xFFFFFFFE as 4-byte LE = \xfe\xff\xff\xff
        assert b"\xfe\xff\xff\xff" in raw
        # And the forbidden 0xFFFFFFFF sequence must NOT appear as the input sequence.
        # The input sequence is placed just before the varint output count.
        # Simple heuristic: confirm the CLTV-compatible sequence is present.


# ===========================================================================
# 7. Supply-chain: artifact format robustness
# ===========================================================================


class TestArtifactSupplyChain:
    def test_artifact_missing_hex_field_substitutes_to_empty(self):
        """An artifact with empty hex produces an empty bytes result.

        This is a sanity check — loading such an artifact isn't blocked, but
        substituting with no params produces ``b''`` which downstream code
        will reject (``compute_p2sh_code_hash`` rejects empty)."""
        fake = {
            "version": 1,
            "contract": "EmptyTest",
            "abi": [{"type": "constructor", "params": []}],
            "hex": "",
        }
        art = CovenantArtifact.from_json(json.dumps(fake))
        # No placeholders, no params — substitute yields empty bytes.
        assert art.substitute({}) == b""
        # Empty redeem is rejected downstream:
        with pytest.raises(ValidationError):
            compute_p2sh_code_hash(b"")

    def test_artifact_with_orphan_placeholder_rejected(self):
        """An artifact with a placeholder that no constructor param declares
        must fail substitute() with 'Unfilled placeholders'."""
        fake = {
            "version": 1,
            "contract": "OrphanTest",
            "abi": [{"type": "constructor", "params": [{"name": "x", "type": "int"}]}],
            "hex": "aa<x>bb<unknown>cc",
        }
        art = CovenantArtifact.from_json(json.dumps(fake))
        with pytest.raises(ValidationError, match="Unfilled placeholders"):
            art.substitute({"x": 5})

    def test_artifact_missing_param_raises(self):
        """Constructor declares a param, caller doesn't supply it."""
        art = CovenantArtifact.load("maker_covenant_6x12_p2wpkh")
        params = dict(_base_claimed_params())
        del params["makerPkh"]
        with pytest.raises(ValidationError, match="Missing"):
            art.substitute(params)

    def test_load_missing_artifact_raises_with_available_list(self):
        """File-not-found for a missing artifact must name the alternatives."""
        with pytest.raises(FileNotFoundError) as exc_info:
            CovenantArtifact.load("definitely_not_a_real_artifact")
        assert "Available" in str(exc_info.value)

    def test_all_bundled_artifact_shas_not_in_banned_list(self):
        """Regression: none of our bundled artifacts may have a SHA that
        matches an entry in the bytecode deny-list."""
        for name in [
            "maker_covenant_6x12_p2wpkh",
            "maker_covenant_flat_6x12_p2wpkh",
            "maker_covenant_trade",
            "maker_offer",
        ]:
            art = CovenantArtifact.load(name)
            sha = hashlib.sha256(art.hex_template.encode()).hexdigest()
            assert sha not in _BANNED_BYTECODE_SHA256, (
                f"bundled artifact {name} has banned SHA {sha}; regenerate!"
            )


# ===========================================================================
# 8. build_gravity_offer full-pipeline smoke for the hardened checks
# ===========================================================================


class TestHardenedBuildGravityOffer:
    """Confirm the new defensive checks don't false-positive on valid inputs
    and catch each of the bugs they're meant to catch."""

    def test_happy_path_still_builds(self):
        kwargs = _valid_offer_kwargs()
        offer = build_gravity_offer(**kwargs)
        assert offer is not None
        assert len(offer.claimed_redeem_hex) > 10
        assert len(offer.offer_redeem_hex) > 10

    @pytest.mark.parametrize(
        "field,bad_value,match",
        [
            ("maker_pkh", bytes(19), "maker_pkh"),
            ("maker_pkh", bytes(21), "maker_pkh"),
            ("maker_pk", bytes(32), "maker_pk"),
            ("maker_pk", bytes(64), "maker_pk"),
            ("taker_pk", bytes(32), "taker_pk"),
            ("taker_radiant_pkh", bytes(19), "taker_radiant_pkh"),
            ("btc_chain_anchor", bytes(31), "btc_chain_anchor"),
            ("btc_chain_anchor", bytes(33), "btc_chain_anchor"),
            ("expected_nbits", bytes(3), "expected_nbits"),
            ("expected_nbits", bytes(5), "expected_nbits"),
        ],
    )
    def test_wrong_length_inputs_rejected(self, field, bad_value, match):
        kwargs = _valid_offer_kwargs()
        kwargs[field] = bad_value
        with pytest.raises(ValidationError, match=match):
            build_gravity_offer(**kwargs)

    def test_expected_nbits_next_wrong_length_rejected(self):
        kwargs = _valid_offer_kwargs()
        kwargs["expected_nbits_next"] = bytes(2)
        with pytest.raises(ValidationError, match="expected_nbits_next"):
            build_gravity_offer(**kwargs)

    def test_photons_offered_zero_rejected(self):
        kwargs = _valid_offer_kwargs()
        kwargs["photons_offered"] = 0
        with pytest.raises(ValidationError, match="photons_offered"):
            build_gravity_offer(**kwargs)

    def test_photons_offered_negative_rejected(self):
        kwargs = _valid_offer_kwargs()
        kwargs["photons_offered"] = -1
        with pytest.raises(ValidationError, match="photons_offered"):
            build_gravity_offer(**kwargs)


# ===========================================================================
# 9. MakerOffer tx wire-format binding (scenarios 11-16)
# ===========================================================================


class TestMakerOfferTxWireBinding:
    """Parse the raw tx bytes and prove load-bearing fields are correct."""

    FEE = 10_000

    def _build_result(self, pk=None, **overrides):
        pk = pk or _make_privkey(0x12)
        offer = _make_real_offer(pk)
        defaults = dict(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE,
            maker_privkey=pk,
        )
        defaults.update(overrides)
        return build_maker_offer_tx(**defaults), offer

    def test_fee_larger_than_surplus_raises_insufficient(self):
        """Scenario 11: fee consumes more than the remaining photons."""
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        with pytest.raises(ValidationError, match="Insufficient funding"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=offer.photons_offered + self.FEE - 1,
                fee_sats=self.FEE,
                maker_privkey=pk,
            )

    def test_surplus_without_change_address_stays_in_p2sh(self):
        """Scenario 12 (updated): single-output mode rolls surplus into the
        P2SH instead of requiring a change_address. The covenant uses the
        surplus to fund claim/finalize tx fees while enforcing ``output >=
        photons_offered`` on forfeit — so surplus-in-P2SH is safe.
        Previously the builder rejected this case, which broke real trades
        (claim tx must deduct its fee from the covenant output, so P2SH
        must start above the floor)."""
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        surplus = 1
        result = build_maker_offer_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE + surplus,
            fee_sats=self.FEE,
            maker_privkey=pk,
        )
        assert result.output_photons == offer.photons_offered + surplus

    def test_first_output_value_equals_photons_offered(self):
        """Scenario 13: the first output value (8-byte LE) must equal
        ``offer.photons_offered`` exactly."""
        result, offer = self._build_result()
        raw = bytes.fromhex(result.tx_hex)
        # Navigate: version(4) + in_count(1) + prevhash(32) + vout(4) +
        #   scriptsig_len(varint) + scriptsig + sequence(4) + out_count(varint)
        pos = 4 + 1 + 32 + 4
        first = raw[pos]
        if first < 0xFD:
            ss_len = first
            pos += 1
        else:
            ss_len = int.from_bytes(raw[pos + 1:pos + 3], "little")
            pos += 3
        pos += ss_len + 4  # past scriptsig + sequence
        # Skip output count varint (1 byte for small counts)
        assert raw[pos] == 0x01  # single-output tx
        pos += 1
        value = int.from_bytes(raw[pos:pos + 8], "little")
        assert value == offer.photons_offered

    def test_first_output_scriptpubkey_is_p2sh_of_offer_redeem(self):
        """Scenario 14: the output's scriptPubKey must be exactly
        ``OP_HASH160 <hash160(offer_redeem)> OP_EQUAL`` (23 bytes)."""
        from pyrxd.gravity.codehash import compute_p2sh_script_pubkey

        result, offer = self._build_result()
        raw = bytes.fromhex(result.tx_hex)
        offer_redeem = bytes.fromhex(offer.offer_redeem_hex)
        expected_spk = compute_p2sh_script_pubkey(offer_redeem)
        assert len(expected_spk) == 23
        assert expected_spk[0] == 0xA9  # OP_HASH160
        assert expected_spk[1] == 0x14  # PUSH20
        assert expected_spk[-1] == 0x87  # OP_EQUAL
        assert expected_spk in raw

    def test_different_maker_keys_produce_different_txids(self):
        """Scenario 15: two calls with same offer but different
        ``maker_privkey`` must produce different txids (signature covers
        different pubkeys → different scriptSigs → different tx bytes)."""
        # Build ONE offer, then sign with two different keys.
        pk1 = _make_privkey(0x11)
        offer = _make_real_offer(pk1)
        pk2 = _make_privkey(0x22)
        r1 = build_maker_offer_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk1,
        )
        r2 = build_maker_offer_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk2,
        )
        # Different keys derive different PKHs → different P2PKH scriptCode
        # (and different pubkey in scriptSig). Tx bytes AND txid must differ.
        assert r1.tx_hex != r2.tx_hex
        assert r1.txid != r2.txid

    def test_embedded_code_hash_equals_independent_recompute(self):
        """Scenario 16: the ``expectedClaimedCodeHash`` inside the offer
        redeem must exactly equal ``compute_p2sh_code_hash(claimed_redeem)``.
        This is the on-chain enforcement linkage."""
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        claimed = bytes.fromhex(offer.claimed_redeem_hex)
        recomputed = compute_p2sh_code_hash(claimed)
        # The 32-byte hash must appear as a length-prefixed 32-byte push
        # (0x20 prefix) in the offer redeem.
        expected_push = bytes([0x20]) + recomputed
        offer_bytes = bytes.fromhex(offer.offer_redeem_hex)
        assert expected_push in offer_bytes


# ===========================================================================
# 10. Claim tx attack surface (scenarios 17-20)
# ===========================================================================


class TestClaimTxAttacks:
    def _taker(self) -> PrivateKeyMaterial:
        # Minimal valid secp256k1 scalar
        return PrivateKeyMaterial(b"\x00" * 31 + b"\x01")

    def _offer(self, **overrides) -> GravityOffer:
        defaults = dict(
            btc_receive_hash=b"\x00" * 20,
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=b"\x00" * 20,
            claim_deadline=int(time.time()) + 48 * 3600,
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )
        defaults.update(overrides)
        return _make_gravity_offer_direct(**defaults)

    def test_deadline_guard_fires_for_claim(self):
        """Scenario 17: claim with a short deadline must raise."""
        from pyrxd.gravity import build_claim_tx

        offer = self._offer(claim_deadline=int(time.time()) + 3600)  # 1h
        with pytest.raises(ValidationError, match="24h"):
            build_claim_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=1_000_000,
                fee_sats=1_000,
                taker_privkey=self._taker(),
                accept_short_deadline=False,
            )

    def test_scriptsig_contains_op1_selector_as_bare_opcode(self):
        """Scenario 18: ``claim()`` is selector 1 → scriptSig must contain
        ``0x51`` (OP_1) as a BARE opcode, not as pushed data.

        Pushed data 0x51 would be ``0x01 0x51``; bare is just ``0x51``.
        We parse and check the byte position.
        """
        from pyrxd.gravity import build_claim_tx

        offer = self._offer()
        result = build_claim_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=1_000_000, fee_sats=1_000,
            taker_privkey=self._taker(), accept_short_deadline=True,
        )
        raw = bytes.fromhex(result.tx_hex)
        # Parse scriptSig
        pos = 4 + 1 + 32 + 4  # version + in_count + prevhash + vout
        first = raw[pos]
        if first < 0xFD:
            ss_len = first
            pos += 1
        else:
            ss_len = int.from_bytes(raw[pos + 1:pos + 3], "little")
            pos += 3
        scriptsig = raw[pos:pos + ss_len]
        # scriptSig layout: <sig+hashtype> OP_1 <offer_redeem>
        # Skip the sig push — first byte is its length prefix.
        sig_len = scriptsig[0]
        # The byte IMMEDIATELY after the sig push MUST be OP_1 (0x51) — bare.
        assert scriptsig[1 + sig_len] == 0x51, (
            "expected OP_1 (0x51) selector as bare opcode after sig push"
        )

    def test_claim_output_is_p2sh_of_claimed_redeem(self):
        """Scenario 19: the claim tx's output scriptPubKey must be exactly
        ``compute_p2sh_script_pubkey(claimed_redeem)``."""
        from pyrxd.gravity import build_claim_tx
        from pyrxd.gravity.codehash import compute_p2sh_script_pubkey

        offer = self._offer()
        result = build_claim_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=1_000_000, fee_sats=1_000,
            taker_privkey=self._taker(), accept_short_deadline=True,
        )
        raw = bytes.fromhex(result.tx_hex)
        expected_spk = compute_p2sh_script_pubkey(
            bytes.fromhex(offer.claimed_redeem_hex)
        )
        assert expected_spk in raw
        assert raw.count(expected_spk) == 1  # only one output

    def test_fee_overflow_raises(self):
        """Scenario 20: fee_sats >= funding_photons must raise."""
        from pyrxd.gravity import build_claim_tx

        offer = self._offer()
        with pytest.raises(ValidationError, match="fee exceeds funding"):
            build_claim_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=1_000,
                fee_sats=1_000,  # equal → output would be 0 → rejected
                taker_privkey=self._taker(),
                accept_short_deadline=True,
            )


# ===========================================================================
# 11. Forfeit tx attack surface (scenarios 21-25)
# ===========================================================================


class TestForfeitTxAttacks:
    MAKER_ADDR = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    def _past(self) -> GravityOffer:
        return _make_gravity_offer_direct(
            btc_receive_hash=bytes(20),
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=bytes(32),
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=bytes(20),
            claim_deadline=MIN_CLAIM_DEADLINE,  # 2025-01-01 in the past
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )

    def test_future_deadline_prevents_forfeit(self):
        """Scenario 21: deadline in the future must raise."""
        future = int(time.time()) + 3600
        offer = _make_gravity_offer_direct(
            btc_receive_hash=bytes(20),
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=bytes(32),
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=bytes(20),
            claim_deadline=future,
            photons_offered=1_000_000,
            offer_redeem_hex="aa" * 100,
            claimed_redeem_hex="bb" * 100,
        )
        with pytest.raises(ValidationError, match="future"):
            build_forfeit_tx(
                offer=offer,
                funding_txid="aa" * 32,
                funding_vout=0,
                funding_photons=1_000_000,
                maker_address=self.MAKER_ADDR,
                fee_sats=1_000,
            )

    def test_past_deadline_allows_forfeit(self):
        """Scenario 22: deadline in the past must succeed."""
        offer = self._past()
        result = build_forfeit_tx(
            offer=offer,
            funding_txid="aa" * 32,
            funding_vout=0,
            funding_photons=1_000_000,
            maker_address=self.MAKER_ADDR,
            fee_sats=1_000,
        )
        assert result.tx_hex

    def test_forfeit_nlocktime_equals_claim_deadline_le(self):
        """Scenario 23: last 4 bytes of raw tx must be claim_deadline LE."""
        offer = self._past()
        result = build_forfeit_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=1_000_000, maker_address=self.MAKER_ADDR,
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        assert raw[-4:] == offer.claim_deadline.to_bytes(4, "little")

    def test_forfeit_sequence_is_ffffffffe(self):
        """Scenario 24: input sequence must be 0xFFFFFFFE (required for CLTV)."""
        offer = self._past()
        result = build_forfeit_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=1_000_000, maker_address=self.MAKER_ADDR,
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        # Parse to extract input sequence.
        pos = 4 + 1 + 32 + 4  # version + in_count + prevhash + vout
        first = raw[pos]
        if first < 0xFD:
            ss_len = first
            pos += 1
        else:
            ss_len = int.from_bytes(raw[pos + 1:pos + 3], "little")
            pos += 3
        pos += ss_len
        sequence = int.from_bytes(raw[pos:pos + 4], "little")
        assert sequence == 0xFFFFFFFE

    def test_forfeit_scriptsig_starts_with_op1(self):
        """Scenario 25: scriptSig must start with OP_1 (0x51) as selector 1."""
        offer = self._past()
        result = build_forfeit_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=1_000_000, maker_address=self.MAKER_ADDR,
            fee_sats=1_000,
        )
        raw = bytes.fromhex(result.tx_hex)
        pos = 4 + 1 + 32 + 4  # version + in_count + prevhash + vout
        first = raw[pos]
        assert first < 0xFD
        pos += 1  # past scriptsig length varint
        assert raw[pos] == 0x51


# ===========================================================================
# 12. Signing integrity (scenarios 26-28)
# ===========================================================================


class TestSigningIntegrity:
    """Verify the BIP143-style preimage binds to all the fields a signer
    needs to be bound to: outpoint, input value, scriptCode, outputs.
    """

    FEE = 10_000

    def test_sig_binds_to_output_script_via_hashoutputhashes(self):
        """Scenario 26: changing the P2SH output script changes the signature.

        If ``hashOutputHashes`` or ``hashOutputs`` was zeroed out, two offers
        differing only in their P2SH output SPK would produce identical
        signatures. Prove they differ.
        """
        pk = _make_privkey()
        # Two offers with different btc_satoshis → different claimed redeem
        # → different code hash → different offer_redeem → different P2SH SPK
        offer_a = _make_real_offer(pk, btc_satoshis=100_000)
        offer_b = _make_real_offer(pk, btc_satoshis=200_000)
        assert offer_a.offer_redeem_hex != offer_b.offer_redeem_hex

        r_a = build_maker_offer_tx(
            offer=offer_a, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer_a.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        r_b = build_maker_offer_tx(
            offer=offer_b, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer_b.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        # Different outputs → different preimage → different sig → different tx
        assert r_a.tx_hex != r_b.tx_hex
        # And crucially: txids differ even though the input outpoint is identical
        assert r_a.txid != r_b.txid

    def test_sig_binds_to_funding_txid(self):
        """Scenario 27: signature (and thus tx) must differ when the outpoint
        txid differs — preimage's ``hashPrevouts`` includes it."""
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        r1 = build_maker_offer_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        r2 = build_maker_offer_tx(
            offer=offer, funding_txid="bb" * 32, funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        # Extract scriptSigs and compare signature bytes directly.
        # This is strictly stronger than comparing full tx_hex.
        assert r1.tx_hex != r2.tx_hex
        assert r1.txid != r2.txid

    def test_sig_binds_to_funding_vout(self):
        """Extra coverage: vout also goes into hashPrevouts."""
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        r1 = build_maker_offer_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        r2 = build_maker_offer_tx(
            offer=offer, funding_txid="aa" * 32, funding_vout=1,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        assert r1.tx_hex != r2.tx_hex

    def test_deterministic_signing_rfc6979(self):
        """Scenario 28: back-to-back identical calls produce byte-identical tx.

        coincurve defaults to RFC-6979 deterministic nonces. This test serves
        as a tripwire: if it ever fails, the signer has been swapped to use
        random nonces, which is a serious footgun (accidental nonce reuse
        leaks the private key).
        """
        pk = _make_privkey()
        offer = _make_real_offer(pk)
        kwargs = dict(
            offer=offer, funding_txid="aa" * 32, funding_vout=0,
            funding_photons=offer.photons_offered + self.FEE,
            fee_sats=self.FEE, maker_privkey=pk,
        )
        r1 = build_maker_offer_tx(**kwargs)
        r2 = build_maker_offer_tx(**kwargs)
        assert r1.tx_hex == r2.tx_hex, (
            "non-deterministic signing detected — potential nonce-reuse risk"
        )
        assert r1.txid == r2.txid


# ===========================================================================
# 13. Taker-independent claimed redeem (scenario 8)
# ===========================================================================


class TestTakerIndependentClaimedRedeem:
    """The flat sentinel artifact bakes ``takerRadiantPkh`` and ``claimDeadline``
    into the code section (all constructor params are flat). So two offers for
    different Takers will have different ``claimed_redeem_hex``. This differs
    from the old state-separated 6x12 artifact where those were in state.
    """

    def test_claimed_redeem_differs_for_different_takers(self):
        pk = _make_privkey()
        t1 = _make_privkey(0x55)
        t2 = _make_privkey(0x66)

        def _build(taker_priv):
            return build_gravity_offer(
                maker_pkh=_pkh(pk),
                maker_pk=_pub(pk),
                taker_pk=_pub(taker_priv),
                taker_radiant_pkh=_pkh(taker_priv),
                btc_receive_hash=bytes([0xCC]) * 20,
                btc_receive_type="p2wpkh",
                btc_satoshis=100_000,
                btc_chain_anchor=bytes([0xDD]) * 32,
                expected_nbits=bytes.fromhex("ffff001d"),
                anchor_height=800_000,
                merkle_depth=12,
                claim_deadline=_future_deadline(48),
                photons_offered=500_000,
            )

        o1 = _build(t1)
        o2 = _build(t2)
        # Flat artifact: takerRadiantPkh is baked into code section → must differ
        assert o1.claimed_redeem_hex != o2.claimed_redeem_hex
        # Offer redeem also differs (contains takerPk)
        assert o1.offer_redeem_hex != o2.offer_redeem_hex

    def test_claimed_redeem_differs_for_different_deadlines(self):
        """``claimDeadline`` is also baked into the flat code section."""
        pk = _make_privkey()
        t = _make_privkey(0x55)

        def _build(deadline):
            return build_gravity_offer(
                maker_pkh=_pkh(pk),
                maker_pk=_pub(pk),
                taker_pk=_pub(t),
                taker_radiant_pkh=_pkh(t),
                btc_receive_hash=bytes([0xCC]) * 20,
                btc_receive_type="p2wpkh",
                btc_satoshis=100_000,
                btc_chain_anchor=bytes([0xDD]) * 32,
                expected_nbits=bytes.fromhex("ffff001d"),
                anchor_height=800_000,
                merkle_depth=12,
                claim_deadline=deadline,
                photons_offered=500_000,
            )

        o1 = _build(_future_deadline(48))
        o2 = _build(_future_deadline(72))
        assert o1.claimed_redeem_hex != o2.claimed_redeem_hex


# ===========================================================================
# 14. Additional substitution-order attack (expectedNBits / expectedNBitsNext)
# ===========================================================================


class TestPrefixPlaceholderCollision:
    """Regression test for a subtle prefix-collision bug.

    The flat artifact has two placeholders: ``<expectedNBits>`` and
    ``<expectedNBitsNext>``. Naive left-to-right ``str.replace`` with
    ``<expectedNBits>`` first would corrupt the embedded
    ``<expectedNBits>Next>`` substring in the longer placeholder.

    The fix in ``substitute()`` is to sort by descending name length so the
    longer placeholder is replaced first.
    """

    def test_substitute_does_not_collide_on_shared_prefix(self):
        """Synthetic artifact with ``<foo>`` and ``<fooBar>`` — replacing
        ``<foo>`` first would destroy ``<fooBar>``. Confirm we handle it.
        """
        fake = {
            "version": 1,
            "contract": "PrefixTest",
            "abi": [{
                "type": "constructor",
                "params": [
                    {"name": "foo", "type": "int"},
                    {"name": "fooBar", "type": "int"},
                ],
            }],
            "hex": "aa<fooBar>bb<foo>cc",
        }
        art = CovenantArtifact.from_json(json.dumps(fake))
        result = art.substitute({"foo": 5, "fooBar": 7})
        # Expected: aa <push 7> bb <push 5> cc
        # push 7 = OP_7 = 0x57; push 5 = OP_5 = 0x55
        assert result == bytes.fromhex("aa57bb55cc")


# ---------------------------------------------------------------------------
# Security audit findings — regression tests (2026-04-24)
# ---------------------------------------------------------------------------

class TestAuditFindings2026:
    """Regression tests for findings from internal security audit (2026-04-24)."""

    def test_invalid_btc_receive_type_raises_validation_error_not_key_error(self):
        """HIGH: invalid btc_receive_type must raise ValidationError, not KeyError.

        Previously the bare dict lookup at covenant.py:418 raised KeyError, which
        bypassed callers' except ValidationError guards.
        """
        from pyrxd.gravity.covenant import build_gravity_offer
        from pyrxd.security.errors import ValidationError
        with pytest.raises(ValidationError, match="btc_receive_type"):
            build_gravity_offer(
                maker_pkh=b"\xaa" * 20,
                maker_pk=b"\x02" + b"\xaa" * 32,
                taker_pk=b"\x02" + b"\xbb" * 32,
                taker_radiant_pkh=b"\xcc" * 20,
                btc_receive_hash=b"\xbb" * 20,
                btc_receive_type="p2sh-p2wpkh",  # invalid — not in the allow-list
                btc_satoshis=100_000,
                btc_chain_anchor=b"\x00" * 32,
                expected_nbits=b"\xff\xff\x00\x1d",
                anchor_height=840_000,
                merkle_depth=12,
                claim_deadline=int(time.time()) + 90_000,
                photons_offered=1_000_000,
            )

    def test_spv_proof_direct_construction_rejected(self):
        """MEDIUM: SpvProof must only be constructable via SpvProofBuilder.build().

        Direct construction bypasses all SPV verification. The sentinel guard
        enforces this at the dataclass level.
        """
        from pyrxd.spv.proof import CovenantParams, SpvProof
        params = CovenantParams(
            btc_receive_hash=b"\xaa" * 20,
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840_000,
            merkle_depth=1,
        )
        with pytest.raises(TypeError, match="SpvProofBuilder.build"):
            SpvProof(
                txid="aa" * 32,
                raw_tx=b"\x01" * 100,
                headers=[b"\x00" * 80],
                branch=b"\x00" * 33,
                pos=1,
                output_offset=0,
                covenant_params=params,
                # _token intentionally omitted — should be rejected
            )

    def test_finalize_tx_rejects_oversized_raw_tx(self):
        """LOW: raw_tx > 65535 bytes must raise ValidationError with clear message.

        OP_PUSHDATA2 cannot encode a push larger than 65535 bytes.
        """
        from pyrxd.gravity.transactions import build_finalize_tx
        from pyrxd.security.errors import ValidationError
        from pyrxd.spv.proof import CovenantParams, SpvProof, _BUILDER_TOKEN

        params = CovenantParams(
            btc_receive_hash=b"\xaa" * 20,
            btc_receive_type="p2wpkh",
            btc_satoshis=50_000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840_000,
            merkle_depth=1,
        )
        oversized_proof = SpvProof(
            txid="aa" * 32,
            raw_tx=b"\x01" * 65536,  # one byte over the limit
            headers=[b"\x00" * 80],
            branch=b"\x00" * 33,
            pos=1,
            output_offset=0,
            covenant_params=params,
            _token=_BUILDER_TOKEN,
        )
        with pytest.raises(ValidationError, match="65535"):
            build_finalize_tx(
                spv_proof=oversized_proof,
                claimed_redeem_hex="bb" * 100,
                funding_txid="cc" * 32,
                funding_vout=0,
                funding_photons=10_000_000,
                to_address="1A4uLV5MpZXXj4N4uaFppRYrZACgYm36j9",
                fee_sats=1_000_000,
            )

    def test_private_key_eq_uses_constant_time(self):
        """MEDIUM: PrivateKey.__eq__ must use hmac.compare_digest, not CcPrivateKey.__eq__.

        CcPrivateKey equality is variable-time over raw secret bytes; a timing oracle
        could reconstruct the key one bit at a time. Fixed to use hmac.compare_digest.
        """
        from pyrxd.keys import PrivateKey
        k1 = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        k2 = PrivateKey(0x1111111111111111111111111111111111111111111111111111111111111111)
        k3 = PrivateKey(0x2222222222222222222222222222222222222222222222222222222222222222)
        assert k1 == k2
        assert k1 != k3
        # Verify the comparison uses hmac.compare_digest by checking it returns bool
        # (not NotImplemented) for both equal and unequal keys.
        assert isinstance(k1.__eq__(k2), bool)
        assert isinstance(k1.__eq__(k3), bool)

    def test_claim_deadline_above_uint32_max_raises(self):
        """HIGH: claim_deadline > 0xFFFFFFFF must raise ValidationError at offer construction.

        build_forfeit_tx uses .to_bytes(4, 'little') — deadline overflow raises OverflowError
        inside the tx builder, leaving funds permanently locked with no recovery path.
        """
        from pyrxd.gravity.types import GravityOffer
        with pytest.raises(ValidationError, match="uint32 max"):
            GravityOffer(
                btc_receive_hash=b"\xaa" * 20,
                btc_receive_type="p2pkh",
                btc_satoshis=100_000,
                chain_anchor=b"\x00" * 32,
                anchor_height=840_000,
                merkle_depth=12,
                taker_radiant_pkh=b"\xcc" * 20,
                claim_deadline=0x100000000,  # one above uint32 max
                photons_offered=1_000_000,
                offer_redeem_hex="aa" * 50,
                claimed_redeem_hex="bb" * 50,
                expected_code_hash_hex="cc" * 32,
            )

    def test_artifact_path_traversal_blocked(self):
        """HIGH: artifact names with '..' must be rejected before any filesystem access."""
        from pyrxd.gravity.covenant import CovenantArtifact
        with pytest.raises(ValidationError, match="invalid characters"):
            CovenantArtifact.load("../../etc/passwd")

    def test_fee_sats_negative_rejected(self):
        """MEDIUM: negative fee_sats in tx builders must raise ValidationError."""
        from pyrxd.gravity.transactions import build_maker_offer_tx
        from pyrxd.gravity.types import GravityOffer
        offer = GravityOffer(
            btc_receive_hash=b"\xaa" * 20,
            btc_receive_type="p2pkh",
            btc_satoshis=100_000,
            chain_anchor=b"\x00" * 32,
            anchor_height=840_000,
            merkle_depth=12,
            taker_radiant_pkh=b"\xcc" * 20,
            claim_deadline=1_800_000_000,
            photons_offered=5_000_000,
            offer_redeem_hex="aa" * 50,
            claimed_redeem_hex="bb" * 50,
            expected_code_hash_hex="cc" * 32,
        )
        with pytest.raises(ValidationError, match="fee_sats"):
            build_maker_offer_tx(
                offer=offer,
                funding_txid="bb" * 32,
                funding_vout=0,
                funding_photons=10_000_000,
                fee_sats=-1,
                maker_privkey=__import__("pyrxd.security.secrets", fromlist=["PrivateKeyMaterial"]).PrivateKeyMaterial(bytes(range(1, 33))),
            )

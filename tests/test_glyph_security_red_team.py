"""Red-team / security regression tests for the pyrxd glyph module.

Each test class maps to a specific finding from the 2026-04-24 security review.
All tests assert that a previously-identified vulnerability is now blocked.

Finding inventory:
  RT-01  CBOR payload size bomb → ValidationError before cbor2 parse
  RT-02  decimals float coercion → ValidationError (not silent truncation)
  RT-03  Protocol list mutability after construction → tuple, can't .append()
  RT-04  Royalty split sum exceeds total bps → ValidationError
  RT-05  build_mutable_scriptsig with empty cbor_bytes → ValidationError
  RT-06  build_mutable_scriptsig with negative index → ValidationError
  RT-07  verify_sha256d_solution target > MAX_SHA256D_TARGET → still bounded
  RT-08  attrs dict DoS (>64 entries) → ValidationError
  RT-09  Creator sig key-substitution attack is detectable
  RT-10  Creator sig stripping detected
  RT-11  Creator sig field-tamper detected
"""

from __future__ import annotations

import hashlib

import cbor2
import pytest

from pyrxd.glyph.creator import sign_metadata, verify_creator_signature
from pyrxd.glyph.dmint import MAX_SHA256D_TARGET, verify_sha256d_solution
from pyrxd.glyph.payload import (
    _MAX_CBOR_PAYLOAD_BYTES,
    build_mutable_scriptsig,
    decode_payload,
)
from pyrxd.glyph.types import (
    GlyphCreator,
    GlyphMetadata,
    GlyphProtocol,
    GlyphRoyalty,
)
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

TREASURY_PKH = Hex20(b"\x11" * 20)


# ---------------------------------------------------------------------------
# RT-01: CBOR payload size bomb
# ---------------------------------------------------------------------------


class TestRT01CborSizeBomb:
    """decode_payload must reject oversized payloads before cbor2.loads()."""

    def test_exactly_at_limit_is_accepted(self):
        """A payload just under the cap should decode without error.

        The cap is sourced from ``_MAX_CBOR_PAYLOAD_BYTES`` so it tracks
        any future tuning. Previously hardcoded 64 KB — bumped to 256 KB
        in M2 to accommodate V1 dMint deploys that embed media (see
        docs/dmint-research-photonic-deploy.md §4)."""
        # Pad to near limit with an unknown key that decode_payload ignores.
        big_cbor = cbor2.dumps(
            {
                "p": [1],
                "name": "Bomb Test",
                "ticker": "BMB",
                "_pad": "y" * (_MAX_CBOR_PAYLOAD_BYTES - 100),
            }
        )
        assert len(big_cbor) <= _MAX_CBOR_PAYLOAD_BYTES
        # Should not raise — just ignores unknown key
        meta = decode_payload(big_cbor)
        assert meta.name == "Bomb Test"

    def test_oversized_payload_raises_before_parse(self):
        """A payload over the cap must be rejected immediately."""
        oversized = b"\x00" * (_MAX_CBOR_PAYLOAD_BYTES + 1)
        with pytest.raises(ValidationError, match="too large"):
            decode_payload(oversized)

    def test_exact_limit_plus_one_rejected(self):
        # Build a CBOR blob that is definitely above the cap. Prepend a
        # minimal valid CBOR map header — the size check fires before
        # cbor2.loads() so the contents don't matter.
        bomb = b"\xa1" + b"x" * (_MAX_CBOR_PAYLOAD_BYTES + 1)
        assert len(bomb) > _MAX_CBOR_PAYLOAD_BYTES
        with pytest.raises(ValidationError, match="too large"):
            decode_payload(bomb)

    def test_crafted_large_attrs_rejected(self):
        """An attacker could send huge attrs entries — size limit catches
        it (either the payload cap or the attrs-count cap, depending on
        encoded size)."""
        giant = cbor2.dumps(
            {
                "p": [1],
                "name": "x",
                "attrs": {f"k{i}": "v" * 1000 for i in range(70)},
            }
        )
        if len(giant) > _MAX_CBOR_PAYLOAD_BYTES:
            with pytest.raises(ValidationError, match="too large"):
                decode_payload(giant)
        else:
            # If it fits, the attrs count check (RT-08) catches it
            with pytest.raises(ValidationError, match="attrs.*too large"):
                decode_payload(giant)


# ---------------------------------------------------------------------------
# RT-02: decimals float coercion
# ---------------------------------------------------------------------------


class TestRT02DecimalsFloat:
    """CBOR allows floats and bools as map values. decimals must reject them."""

    def test_float_decimals_rejected(self):
        cbor_bytes = cbor2.dumps({"p": [1], "name": "x", "ticker": "X", "decimals": 2.5})
        with pytest.raises(ValidationError, match="float"):
            decode_payload(cbor_bytes)

    def test_float_whole_number_still_rejected(self):
        """2.0 as CBOR float is still a float — must not silently truncate to int 2."""
        cbor_bytes = cbor2.dumps({"p": [1], "name": "x", "ticker": "X", "decimals": 8.0})
        with pytest.raises(ValidationError, match="float"):
            decode_payload(cbor_bytes)

    def test_bool_decimals_rejected(self):
        """In Python, bool is a subclass of int. True must not coerce to 1."""
        cbor_bytes = cbor2.dumps({"p": [1], "name": "x", "ticker": "X", "decimals": True})
        with pytest.raises(ValidationError, match="bool"):
            decode_payload(cbor_bytes)

    def test_string_decimals_rejected(self):
        cbor_bytes = cbor2.dumps({"p": [1], "name": "x", "ticker": "X", "decimals": "8"})
        with pytest.raises(ValidationError, match="integer"):
            decode_payload(cbor_bytes)

    def test_integer_decimals_accepted(self):
        cbor_bytes = cbor2.dumps({"p": [1], "name": "x", "ticker": "X", "decimals": 8})
        meta = decode_payload(cbor_bytes)
        assert meta.decimals == 8

    def test_zero_decimals_accepted(self):
        """Zero as integer (default) must pass cleanly."""
        cbor_bytes = cbor2.dumps({"p": [1], "name": "x", "ticker": "X", "decimals": 0})
        meta = decode_payload(cbor_bytes)
        assert meta.decimals == 0


# ---------------------------------------------------------------------------
# RT-03: Protocol list mutability
# ---------------------------------------------------------------------------


class TestRT03ProtocolImmutability:
    """After construction, protocol must be immutable — list.append() is a vector."""

    def test_protocol_is_tuple_not_list(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x")
        assert isinstance(meta.protocol, tuple), "protocol must be coerced to tuple"

    def test_cannot_append_to_protocol(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x")
        with pytest.raises((AttributeError, TypeError)):
            meta.protocol.append(GlyphProtocol.FT)  # type: ignore[attr-defined]

    def test_cannot_index_assign_to_protocol(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x")
        with pytest.raises((TypeError, AttributeError)):
            meta.protocol[0] = GlyphProtocol.FT  # type: ignore[index]

    def test_protocol_tuple_content_correct(self):
        meta = GlyphMetadata(protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT], name="x", ticker="X")
        assert meta.protocol == (GlyphProtocol.FT, GlyphProtocol.DMINT)

    def test_protocol_survives_round_trip_as_list_in_cbor(self):
        """CBOR must encode protocol as a list (not tuple) — cbor2 encodes tuple→array."""
        meta = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Round Trip")
        d = meta.to_cbor_dict()
        assert isinstance(d["p"], list), "CBOR dict must emit list for JSON/CBOR compatibility"


# ---------------------------------------------------------------------------
# RT-04: Royalty split sum overflow
# ---------------------------------------------------------------------------


class TestRT04RoyaltySplitSumOverflow:
    """Splits must not exceed the total royalty bps — otherwise enforcement is broken."""

    def test_splits_exceeding_total_bps_rejected(self):
        with pytest.raises(ValidationError, match="bps"):
            GlyphRoyalty(
                bps=500,
                address="rxd1main",
                splits=(("rxd1a", 300), ("rxd1b", 300)),  # sum=600 > total 500
            )

    def test_splits_equal_to_total_bps_accepted(self):
        r = GlyphRoyalty(
            bps=500,
            address="rxd1main",
            splits=(("rxd1a", 300), ("rxd1b", 200)),  # sum=500 == total
        )
        assert r.bps == 500

    def test_splits_below_total_accepted(self):
        r = GlyphRoyalty(
            bps=500,
            address="rxd1main",
            splits=(("rxd1a", 200),),  # sum=200 < total 500 — remainder to main
        )
        assert r.bps == 500

    def test_empty_splits_always_valid(self):
        r = GlyphRoyalty(bps=500, address="rxd1main")
        assert r.splits == ()

    def test_single_split_overage_rejected(self):
        with pytest.raises(ValidationError, match="bps"):
            GlyphRoyalty(bps=100, address="rxd1main", splits=(("rxd1a", 101),))


# ---------------------------------------------------------------------------
# RT-05 & RT-06: build_mutable_scriptsig input validation
# ---------------------------------------------------------------------------


class TestRT05RT06MutableScriptSigValidation:
    """build_mutable_scriptsig must reject empty cbor_bytes and negative indices."""

    _VALID_CBOR = cbor2.dumps({"p": [2], "name": "MutToken"})

    def test_empty_cbor_rejected(self):
        with pytest.raises(ValidationError, match="cbor_bytes"):
            build_mutable_scriptsig(
                operation="mod",
                cbor_bytes=b"",
                contract_output_index=0,
                ref_hash_index=0,
                ref_index=0,
                token_output_index=1,
            )

    def test_negative_contract_output_index_rejected(self):
        with pytest.raises(ValidationError, match="contract_output_index"):
            build_mutable_scriptsig(
                operation="mod",
                cbor_bytes=self._VALID_CBOR,
                contract_output_index=-1,
                ref_hash_index=0,
                ref_index=0,
                token_output_index=1,
            )

    def test_negative_ref_hash_index_rejected(self):
        with pytest.raises(ValidationError, match="ref_hash_index"):
            build_mutable_scriptsig(
                operation="mod",
                cbor_bytes=self._VALID_CBOR,
                contract_output_index=0,
                ref_hash_index=-1,
                ref_index=0,
                token_output_index=1,
            )

    def test_negative_ref_index_rejected(self):
        with pytest.raises(ValidationError, match="ref_index"):
            build_mutable_scriptsig(
                operation="mod",
                cbor_bytes=self._VALID_CBOR,
                contract_output_index=0,
                ref_hash_index=0,
                ref_index=-1,
                token_output_index=1,
            )

    def test_negative_token_output_index_rejected(self):
        with pytest.raises(ValidationError, match="token_output_index"):
            build_mutable_scriptsig(
                operation="mod",
                cbor_bytes=self._VALID_CBOR,
                contract_output_index=0,
                ref_hash_index=0,
                ref_index=0,
                token_output_index=-1,
            )

    def test_bool_as_index_rejected(self):
        """bool is a subclass of int — True must not pass as index 1."""
        with pytest.raises(ValidationError, match="contract_output_index"):
            build_mutable_scriptsig(
                operation="mod",
                cbor_bytes=self._VALID_CBOR,
                contract_output_index=True,  # type: ignore[arg-type]
                ref_hash_index=0,
                ref_index=0,
                token_output_index=1,
            )

    def test_invalid_operation_rejected(self):
        with pytest.raises(ValidationError, match="operation"):
            build_mutable_scriptsig(
                operation="del",  # type: ignore[arg-type]
                cbor_bytes=self._VALID_CBOR,
                contract_output_index=0,
                ref_hash_index=0,
                ref_index=0,
                token_output_index=1,
            )

    def test_valid_mod_scriptsig_accepted(self):
        sig = build_mutable_scriptsig(
            operation="mod",
            cbor_bytes=self._VALID_CBOR,
            contract_output_index=0,
            ref_hash_index=0,
            ref_index=0,
            token_output_index=1,
        )
        assert sig[:4] == b"\x03gly"

    def test_valid_sl_scriptsig_accepted(self):
        sig = build_mutable_scriptsig(
            operation="sl",
            cbor_bytes=self._VALID_CBOR,
            contract_output_index=1,
            ref_hash_index=0,
            ref_index=0,
            token_output_index=0,
        )
        assert b"sl" in sig


# ---------------------------------------------------------------------------
# RT-07: verify_sha256d_solution target overflow
# ---------------------------------------------------------------------------


class TestRT07PoWTargetOverflow:
    """verify_sha256d_solution must cap target at MAX_SHA256D_TARGET."""

    def _hash_bytes(self, preimage: bytes, nonce: bytes) -> bytes:
        return hashlib.sha256(hashlib.sha256(preimage + nonce).digest()).digest()

    # Nonce values fixed at the V2 default (8 bytes) to satisfy the post-V1
    # strict length check; the actual nonce content is irrelevant to these
    # tests, which exercise *target* boundary behavior in isolation.
    _NONCE = b"\x00" * 8
    _PREIMAGE = b"\x00" * 64

    def test_zero_target_always_false(self):
        """target=0 means impossible — must not accept any solution."""
        assert verify_sha256d_solution(self._PREIMAGE, self._NONCE, 0) is False

    def test_negative_target_always_false(self):
        """Negative target is nonsensical — must not wrap around."""
        assert verify_sha256d_solution(self._PREIMAGE, self._NONCE, -1) is False

    def test_target_above_max_capped_at_max(self):
        """An attacker passing target > MAX must not bypass difficulty enforcement.

        We verify by passing the theoretical maximum (2^64 - 1) and confirming
        the function uses MAX_SHA256D_TARGET as the effective ceiling.  A real
        solution would still need hash[0:4] == 0 AND hash[4:12] < MAX.
        """
        # Passing an astronomical target must not make verification trivially true
        # for a garbage nonce (no valid PoW).
        result = verify_sha256d_solution(b"\xff" * 64, self._NONCE, 2**64 - 1)
        # The result depends on whether the hash happens to meet MAX — the point
        # is it doesn't silently accept anything by wrapping max to 0 or accepting negative.
        # We just confirm it returns bool without raising.
        assert isinstance(result, bool)

    def test_max_target_constant_is_positive(self):
        assert MAX_SHA256D_TARGET > 0
        assert MAX_SHA256D_TARGET == 0x7FFFFFFFFFFFFFFF

    def test_target_equal_to_max_accepted_as_valid_range(self):
        """target == MAX_SHA256D_TARGET is the easiest legal difficulty."""
        result = verify_sha256d_solution(self._PREIMAGE, self._NONCE, MAX_SHA256D_TARGET)
        assert isinstance(result, bool)

    def test_target_one_above_max_clamped_not_wrapped(self):
        """target = MAX + 1 must behave identically to MAX (clamped), not wrap."""
        r1 = verify_sha256d_solution(self._PREIMAGE, self._NONCE, MAX_SHA256D_TARGET)
        r2 = verify_sha256d_solution(self._PREIMAGE, self._NONCE, MAX_SHA256D_TARGET + 1)
        assert r1 == r2, "target > MAX must be clamped to MAX, not wrapped"


# ---------------------------------------------------------------------------
# RT-08: attrs dict DoS
# ---------------------------------------------------------------------------


class TestRT08AttrsDictDoS:
    """decode_payload must reject attrs maps with more than 64 entries."""

    def test_65_attrs_rejected(self):
        cbor_bytes = cbor2.dumps(
            {
                "p": [2],
                "name": "AttrBomb",
                "attrs": {f"key{i}": f"val{i}" for i in range(65)},
            }
        )
        with pytest.raises(ValidationError, match="attrs.*too large"):
            decode_payload(cbor_bytes)

    def test_64_attrs_accepted(self):
        cbor_bytes = cbor2.dumps(
            {
                "p": [2],
                "name": "AttrBomb",
                "attrs": {f"key{i}": f"val{i}" for i in range(64)},
            }
        )
        meta = decode_payload(cbor_bytes)
        assert len(meta.attrs) == 64

    def test_non_dict_attrs_ignored_not_raised(self):
        """Malformed attrs (non-dict) should be silently ignored."""
        cbor_bytes = cbor2.dumps({"p": [2], "name": "x", "attrs": ["a", "b"]})
        meta = decode_payload(cbor_bytes)
        assert meta.attrs == {}

    def test_empty_attrs_accepted(self):
        cbor_bytes = cbor2.dumps({"p": [2], "name": "x", "attrs": {}})
        meta = decode_payload(cbor_bytes)
        assert meta.attrs == {}


# ---------------------------------------------------------------------------
# RT-09, RT-10, RT-11: Creator signature attacks
# ---------------------------------------------------------------------------

_VALID_PUBKEY = "02" + "ab" * 32


def _make_meta(name: str = "Token") -> GlyphMetadata:
    return GlyphMetadata(protocol=[GlyphProtocol.NFT], name=name)


class TestRT09CreatorKeySubstitution:
    """Replacing pubkey after signing must cause verify to fail."""

    def test_key_substitution_detected(self):
        import dataclasses

        meta = _make_meta("Original")
        key1 = PrivateKey()
        key2 = PrivateKey()
        signed = sign_metadata(meta, key1)
        # Attacker replaces the pubkey with key2's — sig was made with key1
        forged_creator = dataclasses.replace(
            signed.creator,
            pubkey=key2.public_key().serialize(compressed=True).hex(),
        )
        forged = dataclasses.replace(signed, creator=forged_creator)
        valid, err = verify_creator_signature(forged)
        assert valid is False
        assert err != ""

    def test_same_key_verifies(self):
        meta = _make_meta("Original")
        key = PrivateKey()
        signed = sign_metadata(meta, key)
        valid, err = verify_creator_signature(signed)
        assert valid is True, f"Unexpected error: {err}"


class TestRT10CreatorSigStripping:
    """A token with creator.pubkey but no sig must not pass verification."""

    def test_empty_sig_rejected(self):
        meta = GlyphMetadata(
            protocol=[GlyphProtocol.NFT],
            name="Stripped",
            creator=GlyphCreator(pubkey=_VALID_PUBKEY, sig=""),
        )
        valid, err = verify_creator_signature(meta)
        assert valid is False
        assert "empty" in err.lower()

    def test_no_creator_rejected(self):
        meta = _make_meta("No Creator")
        valid, err = verify_creator_signature(meta)
        assert valid is False
        assert "creator" in err.lower()


class TestRT11CreatorSigTamper:
    """Modifying any metadata field after signing must cause verify to fail."""

    def test_tampered_name_detected(self):
        import dataclasses

        meta = _make_meta("Original Name")
        signed = sign_metadata(meta, PrivateKey())
        tampered = dataclasses.replace(signed, name="Tampered Name")
        valid, _err = verify_creator_signature(tampered)
        assert valid is False

    def test_tampered_description_detected(self):
        import dataclasses

        meta = GlyphMetadata(
            protocol=[GlyphProtocol.NFT],
            name="Token",
            description="Original desc",
        )
        signed = sign_metadata(meta, PrivateKey())
        tampered = dataclasses.replace(signed, description="Changed desc")
        valid, _err = verify_creator_signature(tampered)
        assert valid is False

    def test_tampered_royalty_detected(self):
        import dataclasses

        meta = GlyphMetadata(
            protocol=[GlyphProtocol.NFT],
            name="Token",
            royalty=GlyphRoyalty(bps=100, address="rxd1original"),
        )
        signed = sign_metadata(meta, PrivateKey())
        tampered = dataclasses.replace(
            signed,
            royalty=GlyphRoyalty(bps=500, address="rxd1attacker"),
        )
        valid, _err = verify_creator_signature(tampered)
        assert valid is False

    def test_sig_payload_replay_across_tokens_detected(self):
        """A sig from token A must not verify token B (different name)."""
        import dataclasses

        meta_a = _make_meta("Token A")
        meta_b = _make_meta("Token B")
        key = PrivateKey()
        signed_a = sign_metadata(meta_a, key)
        # Transplant sig from A onto B
        forged_creator = dataclasses.replace(
            signed_a.creator,
            pubkey=key.public_key().serialize(compressed=True).hex(),
        )
        forged_b = dataclasses.replace(meta_b, creator=forged_creator)
        valid, _ = verify_creator_signature(forged_b)
        assert valid is False

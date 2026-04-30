"""Tests for Glyph V2 metadata sub-objects: GlyphCreator, GlyphRoyalty, GlyphPolicy,
GlyphRights, and sign_metadata / verify_creator_signature."""
from __future__ import annotations

import pytest

from pyrxd.glyph.creator import sign_metadata, verify_creator_signature
from pyrxd.glyph.payload import decode_payload, encode_payload
from pyrxd.glyph.types import (
    GlyphCreator,
    GlyphMetadata,
    GlyphPolicy,
    GlyphProtocol,
    GlyphRights,
    GlyphRoyalty,
)
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError


# ---------------------------------------------------------------------------
# GlyphCreator
# ---------------------------------------------------------------------------

_VALID_PUBKEY = "02" + "ab" * 32  # compressed pubkey (02 prefix + 32 bytes)


def test_creator_valid():
    c = GlyphCreator(pubkey=_VALID_PUBKEY)
    assert c.sig == ""
    assert c.algo == "ecdsa-secp256k1"


def test_creator_invalid_pubkey_wrong_prefix():
    with pytest.raises(ValidationError, match="pubkey"):
        GlyphCreator(pubkey="04" + "ab" * 32)  # uncompressed prefix


def test_creator_invalid_pubkey_wrong_length():
    with pytest.raises(ValidationError, match="pubkey"):
        GlyphCreator(pubkey="02" + "ab" * 31)  # 65 hex chars, not 66


def test_creator_invalid_sig_not_hex():
    with pytest.raises(ValidationError, match="sig"):
        GlyphCreator(pubkey=_VALID_PUBKEY, sig="not-hex!")


def test_creator_to_cbor_dict_no_sig():
    d = GlyphCreator(pubkey=_VALID_PUBKEY).to_cbor_dict()
    assert d == {"pubkey": _VALID_PUBKEY}  # sig and default algo omitted


def test_creator_to_cbor_dict_with_sig():
    d = GlyphCreator(pubkey=_VALID_PUBKEY, sig="deadbeef").to_cbor_dict()
    assert d["sig"] == "deadbeef"
    assert "algo" not in d  # default algo omitted


def test_creator_to_cbor_dict_non_default_algo():
    d = GlyphCreator(pubkey=_VALID_PUBKEY, algo="schnorr-secp256k1").to_cbor_dict()
    assert d["algo"] == "schnorr-secp256k1"


def test_creator_round_trip():
    c = GlyphCreator(pubkey=_VALID_PUBKEY, sig="aabbccdd", algo="ecdsa-secp256k1")
    back = GlyphCreator.from_cbor_dict(c.to_cbor_dict())
    assert back == c


def test_creator_from_cbor_dict_string_form():
    # Some on-chain tokens may have creator as a bare pubkey string
    c = GlyphCreator.from_cbor_dict(_VALID_PUBKEY)
    assert c.pubkey == _VALID_PUBKEY
    assert c.sig == ""


# ---------------------------------------------------------------------------
# GlyphRoyalty
# ---------------------------------------------------------------------------

def test_royalty_valid():
    r = GlyphRoyalty(bps=500, address="1someaddress", enforced=True)
    assert r.bps == 500


def test_royalty_bps_out_of_range():
    with pytest.raises(ValidationError, match="bps"):
        GlyphRoyalty(bps=10001, address="addr")
    with pytest.raises(ValidationError, match="bps"):
        GlyphRoyalty(bps=-1, address="addr")


def test_royalty_empty_address():
    with pytest.raises(ValidationError, match="address"):
        GlyphRoyalty(bps=100, address="")


def test_royalty_to_cbor_dict_minimal():
    d = GlyphRoyalty(bps=250, address="rxd1abc").to_cbor_dict()
    assert d["bps"] == 250
    assert d["address"] == "rxd1abc"
    assert d["enforced"] is False
    assert "minimum" not in d
    assert "splits" not in d


def test_royalty_to_cbor_dict_with_splits():
    r = GlyphRoyalty(
        bps=500,
        address="rxd1main",
        enforced=True,
        minimum=1000,
        splits=(("rxd1a", 300), ("rxd1b", 200)),
    )
    d = r.to_cbor_dict()
    assert d["minimum"] == 1000
    assert len(d["splits"]) == 2
    assert d["splits"][0] == {"address": "rxd1a", "bps": 300}


def test_royalty_round_trip():
    r = GlyphRoyalty(
        bps=500, address="rxd1abc", enforced=True, minimum=100,
        splits=(("rxd1x", 300), ("rxd1y", 200)),
    )
    back = GlyphRoyalty.from_cbor_dict(r.to_cbor_dict())
    assert back == r


# ---------------------------------------------------------------------------
# GlyphPolicy
# ---------------------------------------------------------------------------

def test_policy_all_none_emits_empty_dict():
    d = GlyphPolicy().to_cbor_dict()
    assert d == {}


def test_policy_fields_encoded():
    p = GlyphPolicy(renderable=True, nsfw=False, transferable=False)
    d = p.to_cbor_dict()
    assert d["renderable"] is True
    assert d["nsfw"] is False
    assert d["transferable"] is False
    assert "executable" not in d


def test_policy_round_trip():
    p = GlyphPolicy(renderable=True, executable=False, nsfw=True, transferable=False)
    back = GlyphPolicy.from_cbor_dict(p.to_cbor_dict())
    assert back == p


def test_policy_partial_round_trip():
    p = GlyphPolicy(nsfw=True)
    back = GlyphPolicy.from_cbor_dict(p.to_cbor_dict())
    assert back.nsfw is True
    assert back.renderable is None


# ---------------------------------------------------------------------------
# GlyphRights
# ---------------------------------------------------------------------------

def test_rights_empty_emits_empty_dict():
    assert GlyphRights().to_cbor_dict() == {}


def test_rights_fields():
    r = GlyphRights(license="CC-BY-4.0", attribution="Alice")
    d = r.to_cbor_dict()
    assert d["license"] == "CC-BY-4.0"
    assert "terms" not in d
    assert d["attribution"] == "Alice"


def test_rights_round_trip():
    r = GlyphRights(license="MIT", terms="See mit.org", attribution="Bob")
    back = GlyphRights.from_cbor_dict(r.to_cbor_dict())
    assert back == r


# ---------------------------------------------------------------------------
# GlyphMetadata — new fields in CBOR and round-trip
# ---------------------------------------------------------------------------

def _meta(**kw) -> GlyphMetadata:
    kw.setdefault("name", "Test NFT")
    return GlyphMetadata(protocol=[GlyphProtocol.NFT], **kw)


def test_metadata_creator_in_cbor():
    c = GlyphCreator(pubkey=_VALID_PUBKEY)
    meta = _meta(v=2, creator=c)
    d = meta.to_cbor_dict()
    assert "creator" in d
    assert d["creator"]["pubkey"] == _VALID_PUBKEY


def test_metadata_royalty_in_cbor():
    r = GlyphRoyalty(bps=250, address="rxd1abc")
    meta = _meta(v=2, royalty=r)
    d = meta.to_cbor_dict()
    assert d["royalty"]["bps"] == 250


def test_metadata_policy_omitted_when_all_none():
    meta = _meta(v=2, policy=GlyphPolicy())
    d = meta.to_cbor_dict()
    assert "policy" not in d


def test_metadata_policy_in_cbor():
    meta = _meta(v=2, policy=GlyphPolicy(nsfw=True))
    d = meta.to_cbor_dict()
    assert d["policy"]["nsfw"] is True


def test_metadata_rights_omitted_when_empty():
    meta = _meta(v=2, rights=GlyphRights())
    d = meta.to_cbor_dict()
    assert "rights" not in d


def test_metadata_rights_in_cbor():
    meta = _meta(v=2, rights=GlyphRights(license="MIT"))
    d = meta.to_cbor_dict()
    assert d["rights"]["license"] == "MIT"


def test_metadata_created_and_commit_outpoint():
    meta = _meta(v=2, created="2026-04-24T12:00:00Z", commit_outpoint="aa" * 32 + ":0")
    d = meta.to_cbor_dict()
    assert d["created"] == "2026-04-24T12:00:00Z"
    assert d["commit_outpoint"] == "aa" * 32 + ":0"


def test_metadata_full_v2_encode_decode_round_trip():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="Signed NFT",
        v=2,
        creator=GlyphCreator(pubkey=_VALID_PUBKEY, sig="aabb"),
        royalty=GlyphRoyalty(bps=500, address="rxd1xyz", enforced=True),
        policy=GlyphPolicy(renderable=True, transferable=True),
        rights=GlyphRights(license="CC-BY-4.0"),
        created="2026-04-24T00:00:00Z",
        commit_outpoint="bb" * 32 + ":1",
    )
    cbor_bytes, _ = encode_payload(meta)
    decoded = decode_payload(cbor_bytes)

    assert decoded.v == 2
    assert decoded.creator is not None
    assert decoded.creator.pubkey == _VALID_PUBKEY
    assert decoded.creator.sig == "aabb"
    assert decoded.royalty is not None
    assert decoded.royalty.bps == 500
    assert decoded.policy is not None
    assert decoded.policy.renderable is True
    assert decoded.rights is not None
    assert decoded.rights.license == "CC-BY-4.0"
    assert decoded.created == "2026-04-24T00:00:00Z"
    assert decoded.commit_outpoint == "bb" * 32 + ":1"


# ---------------------------------------------------------------------------
# sign_metadata / verify_creator_signature
# ---------------------------------------------------------------------------

def _fresh_key() -> PrivateKey:
    return PrivateKey()


def test_sign_metadata_produces_creator_with_sig():
    meta = _meta(v=2, name="Signed Token")
    key = _fresh_key()
    signed = sign_metadata(meta, key)
    assert signed.creator is not None
    assert signed.creator.sig != ""
    assert len(signed.creator.pubkey) == 66  # 33 bytes hex


def test_sign_metadata_preserves_other_fields():
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="Preserved",
        description="Check fields pass through",
        v=2,
        royalty=GlyphRoyalty(bps=100, address="rxd1q"),
    )
    key = _fresh_key()
    signed = sign_metadata(meta, key)
    assert signed.name == "Preserved"
    assert signed.description == "Check fields pass through"
    assert signed.royalty is not None
    assert signed.royalty.bps == 100


def test_verify_creator_signature_valid():
    meta = _meta(v=2, name="Verify Me")
    key = _fresh_key()
    signed = sign_metadata(meta, key)
    valid, err = verify_creator_signature(signed)
    assert valid is True, f"Expected valid, got error: {err}"
    assert err == ""


def test_verify_creator_signature_tampered_name():
    meta = _meta(v=2, name="Original")
    key = _fresh_key()
    signed = sign_metadata(meta, key)
    # Tamper: change the name after signing
    import dataclasses
    tampered = dataclasses.replace(signed, name="Tampered")
    valid, err = verify_creator_signature(tampered)
    assert valid is False
    assert err != ""


def test_verify_creator_signature_no_creator():
    meta = _meta(v=2)
    valid, err = verify_creator_signature(meta)
    assert valid is False
    assert "no creator" in err


def test_verify_creator_signature_empty_sig():
    meta = _meta(v=2, creator=GlyphCreator(pubkey=_VALID_PUBKEY))
    valid, err = verify_creator_signature(meta)
    assert valid is False
    assert "empty" in err


def test_verify_creator_signature_wrong_key():
    meta = _meta(v=2, name="Token")
    key1 = _fresh_key()
    key2 = _fresh_key()
    signed_with_key1 = sign_metadata(meta, key1)
    # Replace pubkey with key2's pubkey — mismatch
    import dataclasses
    wrong_creator = dataclasses.replace(
        signed_with_key1.creator,
        pubkey=key2.public_key().serialize(compressed=True).hex(),
    )
    forged = dataclasses.replace(signed_with_key1, creator=wrong_creator)
    valid, _ = verify_creator_signature(forged)
    assert valid is False


def test_sign_verify_round_trip_with_dmint():
    """Signing works with complex V2 metadata including dmint_params."""
    from pyrxd.glyph.dmint import DmintAlgo, DmintCborPayload
    dmint = DmintCborPayload(
        algo=DmintAlgo.SHA256D, num_contracts=1, max_height=10_000,
        reward=100, premine=0, diff=1000,
    )
    meta = GlyphMetadata(
        protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
        ticker="TST", name="Test Token",
        v=2, dmint_params=dmint,
    )
    key = _fresh_key()
    signed = sign_metadata(meta, key)
    valid, err = verify_creator_signature(signed)
    assert valid is True, f"dMint round-trip sig failed: {err}"

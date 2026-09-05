"""AUTHORITY (protocol 10): the write side, and what a verdict is allowed to say.

Before this, ``GlyphProtocol.AUTHORITY`` had exactly two references outside the
enum — both ``if AUTHORITY in p: return "authority"`` classifier labels. pyrxd
could name an authority token and do nothing with one.

The consensus behaviour of the gate is proven separately, on a node, in
``tests/test_authority_regtest_e2e.py``. This file covers the parts that do not
need one — and, most importantly, that a verdict never claims more than its
evidence supports.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pyrxd.glyph.authority import (
    AuthorityAttrs,
    AuthorityBasis,
    build_authority_metadata,
    has_permission,
    is_authority,
    is_authority_expired,
    read_authority_attrs,
    validate_authority,
    verify_authority_claim,
    verify_authority_gate,
)
from pyrxd.glyph.builder import GlyphBuilder
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.relationships import (
    RelationshipBacking,
    RelationshipKind,
    RelationshipOutcome,
    RelationshipVerdict,
)
from pyrxd.glyph.script import (
    AUTHORITY_GATED_SCRIPT_SIZE,
    build_authority_gated_nft_script,
    build_nft_locking_script,
    is_authority_gated_script,
    is_nft_script,
    parse_authority_gated_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

PKH = Hex20(bytes.fromhex("7d6c507735322c6bac9398317a65b4597072f0a6"))
ISSUER_PKH = Hex20(bytes.fromhex("2307b8956bc0c9923e66b3b4eea282f70fabb04a"))
AUTHORITY = GlyphRef(txid="aa" * 32, vout=1)
ITEM = GlyphRef(txid="11" * 32, vout=0)


# ---------------------------------------------------------------------------
# The gated script
# ---------------------------------------------------------------------------


def test_gated_script_is_101_bytes_in_photonics_layout():
    script = build_authority_gated_nft_script(PKH, ITEM, AUTHORITY)
    assert len(script) == AUTHORITY_GATED_SCRIPT_SIZE == 101
    assert script[0] == 0xD1 and script[1:37] == AUTHORITY.to_bytes()  # OP_REQUIREINPUTREF <auth>
    assert script[37] == 0x75  # OP_DROP
    assert script[38] == 0xD8 and script[39:75] == ITEM.to_bytes()  # OP_PUSHINPUTREFSINGLETON <item>
    assert script[75] == 0x75  # OP_DROP
    assert script[76:] == bytes.fromhex("76a914") + bytes(PKH) + bytes.fromhex("88ac")


def test_gated_script_round_trips():
    parsed = parse_authority_gated_script(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY))
    assert parsed == (AUTHORITY, ITEM, PKH)


def test_a_token_gated_on_itself_is_refused():
    """Its own creation satisfies the requirement, so it gates nothing."""
    with pytest.raises(ValidationError, match="gated on itself"):
        build_authority_gated_nft_script(PKH, ITEM, ITEM)


def test_gated_and_plain_nft_are_never_confused():
    gated = build_authority_gated_nft_script(PKH, ITEM, AUTHORITY)
    plain = build_nft_locking_script(PKH, ITEM)
    assert is_authority_gated_script(gated.hex()) and not is_nft_script(gated.hex())
    assert is_nft_script(plain.hex()) and not is_authority_gated_script(plain.hex())
    assert parse_authority_gated_script(plain) is None


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_build_authority_metadata_is_an_nft_carrying_the_marker():
    md = build_authority_metadata("rxd1qissuer", name="FlipperHub Issuer", scope="tournaments")
    assert GlyphProtocol.AUTHORITY in md.protocol and GlyphProtocol.NFT in md.protocol
    assert is_authority(md) and validate_authority(md) == []
    assert md.attrs["issuer"] == "rxd1qissuer" and md.attrs["scope"] == "tournaments"


def test_absent_optionals_are_omitted_not_nulled():
    """A null key and an absent key are different bytes and hash differently."""
    md = build_authority_metadata("rxd1qissuer")
    assert "scope" not in md.attrs and "expires" not in md.attrs and "permissions" not in md.attrs
    assert md.attrs["revocable"] is True
    # And the envelope encodes without the caller doing anything special.
    cbor_bytes, _hash = encode_payload(md)
    assert cbor_bytes


def test_an_authority_naming_no_issuer_is_refused_at_build_time():
    """A mint is irreversible; catching this on read would be too late."""
    with pytest.raises(ValidationError, match="issuer is required"):
        build_authority_metadata("   ")


def test_an_unparseable_expiry_is_refused_at_build_time():
    """Because on READ it silently means 'never expires' — the unsafe direction."""
    with pytest.raises(ValidationError, match="ISO-8601"):
        build_authority_metadata("issuer", expires="soon")


def test_validate_reports_problems_on_third_party_tokens_rather_than_raising():
    """This reads tokens other people minted; one bad field must not blind the rest."""
    broken = GlyphMetadata(
        protocol=[GlyphProtocol.NFT, GlyphProtocol.AUTHORITY],
        name="dodgy",
        attrs={"issuer": "", "expires": "not-a-date"},
    )
    problems = validate_authority(broken)
    assert any("issuer is required" in p for p in problems)
    assert any("ISO-8601" in p for p in problems)
    # Still readable despite the problems.
    assert read_authority_attrs(broken) is not None


def test_a_non_authority_is_reported_as_such():
    plain = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="ordinary")
    assert not is_authority(plain)
    assert any("AUTHORITY" in p for p in validate_authority(plain))


@pytest.mark.parametrize(
    ("expires", "now", "expected"),
    [
        ("2030-01-01T00:00:00Z", datetime(2029, 1, 1, tzinfo=UTC), False),
        ("2030-01-01T00:00:00Z", datetime(2031, 1, 1, tzinfo=UTC), True),
        # Naive timestamps are read as UTC rather than crashing on the compare.
        ("2030-01-01T00:00:00", datetime(2031, 1, 1, tzinfo=UTC), True),
        ("2030-01-01T00:00:00+05:00", datetime(2029, 1, 1, tzinfo=UTC), False),
    ],
)
def test_expiry_handles_the_timestamp_shapes_that_occur(expires, now, expected):
    md = build_authority_metadata("issuer", expires=expires)
    assert is_authority_expired(md, now=now) is expected


def test_no_expiry_never_expires():
    assert is_authority_expired(build_authority_metadata("issuer")) is False


def test_permissions_are_read_exactly():
    md = build_authority_metadata("issuer", permissions=["mint", "revoke"])
    assert has_permission(md, "mint") and has_permission(md, "revoke")
    assert not has_permission(md, "burn")
    assert not has_permission(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x"), "mint")


def test_revocable_defaults_true_and_only_explicit_false_is_false():
    """Photonic's default. Reading a missing key as 'not revocable' would strand issuers."""
    assert read_authority_attrs(build_authority_metadata("i")).revocable is True
    explicit = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x", attrs={"issuer": "i", "revocable": False})
    assert read_authority_attrs(explicit).revocable is False
    missing = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x", attrs={"issuer": "i"})
    assert read_authority_attrs(missing).revocable is True


def test_wrong_typed_attrs_degrade_to_defaults_rather_than_raising():
    junk = GlyphMetadata(
        protocol=[GlyphProtocol.NFT], name="x", attrs={"issuer": 7, "permissions": "mint", "scope": []}
    )
    attrs = read_authority_attrs(junk)
    assert attrs == AuthorityAttrs(issuer="", scope=None, permissions=(), expires=None, revocable=True)


# ---------------------------------------------------------------------------
# The two verdicts, and the line between them
# ---------------------------------------------------------------------------


def test_the_gate_verdict_reads_the_genesis_output():
    verdict = verify_authority_gate(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY), AUTHORITY)
    assert verdict.valid and verdict.basis is AuthorityBasis.GATE
    assert verdict.authority_ref == AUTHORITY


def test_the_gate_verdict_refuses_a_different_authority():
    """Gated, but by someone else. Reporting 'valid' here would be the whole bug."""
    other = GlyphRef(txid="bb" * 32, vout=3)
    verdict = verify_authority_gate(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY), other)
    assert not verdict.valid and verdict.authority_ref == AUTHORITY
    assert "not on" in verdict.reason


def test_the_gate_verdict_refuses_an_ungated_output():
    verdict = verify_authority_gate(build_nft_locking_script(PKH, ITEM), AUTHORITY)
    assert not verdict.valid and verdict.basis is AuthorityBasis.NONE


def _author_verdict(outcome, backing):
    return [RelationshipVerdict(kind=RelationshipKind.AUTHOR, ref=AUTHORITY, outcome=outcome, backing=backing)]


def test_an_unbacked_by_claim_is_NOT_reported_as_an_issuer():
    """The divergence from Photonic, and the reason this function takes verdicts.

    ``verifyAuthorityChain`` matches the ``by`` field against a candidate
    authority's ref and reports success on a string match. ``by`` is operator
    CBOR: a forger writes a real issuer's ref into their own token and passes.
    Only the relationship verdict can say whether anything authorised it.
    """
    verdict = verify_authority_claim(AUTHORITY, _author_verdict(RelationshipOutcome.UNBACKED, RelationshipBacking.NONE))
    assert not verdict.valid
    assert verdict.basis is AuthorityBasis.NONE
    assert "nothing authorised the claim" in verdict.reason


@pytest.mark.parametrize(
    ("backing", "evidence"),
    [
        (RelationshipBacking.DIRECT, "spent the authority itself"),
        (RelationshipBacking.DELEGATED, "delegate"),
    ],
)
def test_a_backed_by_claim_is_accepted_and_says_HOW(backing, evidence):
    verdict = verify_authority_claim(AUTHORITY, _author_verdict(RelationshipOutcome.BACKED, backing))
    assert verdict.valid and verdict.basis is AuthorityBasis.BACKED_CLAIM
    assert evidence in verdict.reason


def test_a_claim_on_a_different_authority_is_not_borrowed():
    """A backed claim on X must not validate a question about Y."""
    other = GlyphRef(txid="bb" * 32, vout=3)
    verdict = verify_authority_claim(other, _author_verdict(RelationshipOutcome.BACKED, RelationshipBacking.DIRECT))
    assert not verdict.valid and "makes no `by` claim" in verdict.reason


def test_no_verdicts_at_all_is_not_an_issuer():
    assert not verify_authority_claim(AUTHORITY, []).valid


# ---------------------------------------------------------------------------
# The mint path
# ---------------------------------------------------------------------------


def test_the_gated_reveal_re_creates_the_authority_rather_than_burning_it():
    """Spending a singleton without re-creating it destroys it irrecoverably.

    Same lesson as the delegate base: the caller is handed the output rather
    than told about it.
    """
    builder = GlyphBuilder()
    cbor_bytes, _hash = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Gated item"))

    scripts = builder.prepare_authority_gated_reveal("11" * 32, 0, cbor_bytes, PKH, AUTHORITY, ISSUER_PKH)

    assert is_authority_gated_script(scripts.item_script.hex())
    assert parse_authority_gated_script(scripts.item_script) == (AUTHORITY, scripts.ref, PKH)
    # Byte-identical to the authority output being spent — it neither moves nor
    # changes hands.
    assert scripts.authority_script == build_nft_locking_script(ISSUER_PKH, AUTHORITY)
    assert scripts.authority_ref == AUTHORITY


def test_the_gated_reveal_refuses_a_non_nft_envelope():
    builder = GlyphBuilder()
    cbor_bytes, _hash = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.FT], name="not an nft"))
    with pytest.raises(ValidationError, match="NFT"):
        builder.prepare_authority_gated_reveal("11" * 32, 0, cbor_bytes, PKH, AUTHORITY, ISSUER_PKH)


# ---------------------------------------------------------------------------
# What reaches a human
# ---------------------------------------------------------------------------


def test_the_inspector_names_a_gated_output_and_says_what_it_does_not_prove():
    from pyrxd.glyph._inspect_core import _inspect_script

    row = _inspect_script(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY).hex())
    assert row["type"] == "authority-gated-nft"
    assert row["authority_ref"] == f"{AUTHORITY.txid}:{AUTHORITY.vout}"
    assert row["ref_outpoint"] == f"{ITEM.txid}:{ITEM.vout}"
    # The note is the load-bearing part: gated NOW is not minted-under-authority.
    assert "not proof it was MINTED" in row["note"]

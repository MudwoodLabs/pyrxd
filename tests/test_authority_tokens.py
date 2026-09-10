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

from datetime import datetime, timezone

import pytest

from pyrxd.glyph.authority import (
    AuthorityAttrs,
    AuthorityBasis,
    build_authority_metadata,
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
    RelationshipBasis,
    RelationshipKind,
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
        ("2030-01-01T00:00:00Z", datetime(2029, 1, 1, tzinfo=timezone.utc), False),
        ("2030-01-01T00:00:00Z", datetime(2031, 1, 1, tzinfo=timezone.utc), True),
        # Naive timestamps are read as UTC rather than crashing on the compare.
        ("2030-01-01T00:00:00", datetime(2031, 1, 1, tzinfo=timezone.utc), True),
        ("2030-01-01T00:00:00+05:00", datetime(2029, 1, 1, tzinfo=timezone.utc), False),
    ],
)
def test_expiry_handles_the_timestamp_shapes_that_occur(expires, now, expected):
    md = build_authority_metadata("issuer", expires=expires)
    assert is_authority_expired(md, now=now) is expected


def test_no_expiry_never_expires():
    assert is_authority_expired(build_authority_metadata("issuer")) is False


def test_permissions_are_read_exactly():
    md = build_authority_metadata("issuer", permissions=["mint", "revoke"])
    perms = read_authority_attrs(md).permissions
    assert "mint" in perms and "revoke" in perms
    assert "burn" not in perms
    assert read_authority_attrs(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="x")).permissions == ()


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
    verdict = verify_authority_gate(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY), AUTHORITY, item_ref=ITEM)
    assert verdict.ok and verdict.basis is AuthorityBasis.GATE
    assert verdict.authority_ref == AUTHORITY


def test_the_gate_verdict_refuses_a_different_authority():
    """Gated, but by someone else. Reporting 'valid' here would be the whole bug."""
    other = GlyphRef(txid="bb" * 32, vout=3)
    verdict = verify_authority_gate(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY), other, item_ref=ITEM)
    assert not verdict.ok and verdict.authority_ref == AUTHORITY
    assert "not on" in verdict.reason


def test_the_gate_verdict_refuses_an_ungated_output():
    verdict = verify_authority_gate(build_nft_locking_script(PKH, ITEM), AUTHORITY, item_ref=ITEM)
    assert not verdict.ok and verdict.basis is AuthorityBasis.NONE


def _author_verdict(ok, basis):
    return [RelationshipVerdict(kind=RelationshipKind.AUTHOR, ref=AUTHORITY, ok=ok, basis=basis, reason="fixture")]


def test_an_unbacked_by_claim_is_NOT_reported_as_an_issuer():
    """The divergence from Photonic, and the reason this function takes verdicts.

    ``verifyAuthorityChain`` matches the ``by`` field against a candidate
    authority's ref and reports success on a string match. ``by`` is operator
    CBOR: a forger writes a real issuer's ref into their own token and passes.
    Only the relationship verdict can say whether anything authorised it.
    """
    verdict = verify_authority_claim(AUTHORITY, _author_verdict(False, RelationshipBasis.NONE))
    assert not verdict.ok
    assert verdict.basis is AuthorityBasis.NONE
    assert "nothing authorised the claim" in verdict.reason


@pytest.mark.parametrize(
    ("backing", "evidence"),
    [
        (RelationshipBasis.DIRECT, "spent the authority itself"),
        (RelationshipBasis.DELEGATED, "delegate"),
    ],
)
def test_a_backed_by_claim_is_accepted_and_says_HOW(backing, evidence):
    verdict = verify_authority_claim(AUTHORITY, _author_verdict(True, backing))
    assert verdict.ok and verdict.basis is AuthorityBasis.BACKED_CLAIM
    assert evidence in verdict.reason


def test_a_claim_on_a_different_authority_is_not_borrowed():
    """A backed claim on X must not validate a question about Y."""
    other = GlyphRef(txid="bb" * 32, vout=3)
    verdict = verify_authority_claim(other, _author_verdict(True, RelationshipBasis.DIRECT))
    assert not verdict.ok and "makes no `by` claim" in verdict.reason


def test_no_verdicts_at_all_is_not_an_issuer():
    assert not verify_authority_claim(AUTHORITY, []).ok


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

    authority_utxo_script = build_nft_locking_script(ISSUER_PKH, AUTHORITY)
    scripts = builder.prepare_authority_gated_reveal("11" * 32, 0, cbor_bytes, PKH, AUTHORITY, authority_utxo_script)

    assert is_authority_gated_script(scripts.item_script.hex())
    assert parse_authority_gated_script(scripts.item_script) == (AUTHORITY, scripts.ref, PKH)
    # Byte-identical to the authority output being spent — it neither moves nor
    # changes hands.
    # Re-emitted VERBATIM — not rebuilt from a pkh, which would strip anything
    # the authority itself carried.
    assert scripts.authority_script == authority_utxo_script
    assert scripts.authority_ref == AUTHORITY


def test_the_gated_reveal_refuses_a_non_nft_envelope():
    builder = GlyphBuilder()
    cbor_bytes, _hash = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.FT], name="not an nft"))
    with pytest.raises(ValidationError, match="NFT"):
        builder.prepare_authority_gated_reveal(
            "11" * 32, 0, cbor_bytes, PKH, AUTHORITY, build_nft_locking_script(ISSUER_PKH, AUTHORITY)
        )


def test_the_gated_reveal_refuses_a_script_that_is_not_the_named_authority():
    """A wrong script here re-creates some other token and BURNS the authority.

    The parameter used to be a `Hex20` sitting next to `owner_pkh`; transposing
    the two irreversibly gifted the issuer's authority to the mint recipient in
    a transaction consensus accepts. It is now the authority's own script, and
    cross-checked against the ref it is supposed to be.
    """
    from pyrxd.glyph.payload import encode_payload

    builder = GlyphBuilder()
    cbor_bytes, _hash = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Gated item"))
    someone_else = build_nft_locking_script(PKH, GlyphRef(txid="ee" * 32, vout=7))
    with pytest.raises(ValidationError, match="does not carry"):
        builder.prepare_authority_gated_reveal("11" * 32, 0, cbor_bytes, PKH, AUTHORITY, someone_else)


def test_a_gated_authority_is_re_emitted_with_its_own_gate_intact():
    """An authority may itself be gated. Rebuilding from a pkh silently un-gated it."""
    from pyrxd.glyph.payload import encode_payload

    builder = GlyphBuilder()
    cbor_bytes, _hash = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Gated item"))
    parent_authority = GlyphRef(txid="dd" * 32, vout=3)
    gated_authority = build_authority_gated_nft_script(ISSUER_PKH, AUTHORITY, parent_authority)

    scripts = builder.prepare_authority_gated_reveal("11" * 32, 0, cbor_bytes, PKH, AUTHORITY, gated_authority)
    assert scripts.authority_script == gated_authority
    assert is_authority_gated_script(scripts.authority_script.hex())


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


# ---------------------------------------------------------------------------
# Through the transport that actually carries it
# ---------------------------------------------------------------------------


def test_authority_attrs_survive_a_real_cbor_round_trip():
    """The test that was missing, and the defect it would have caught.

    Every other test in this file builds metadata in memory. `attrs` was typed
    `dict[str, str]` and the decoder coerced every value with `str()`, so a
    token read back OFF THE CHAIN came out wrong in two ways at once:

    * ``revocable=False`` decoded as the string ``"False"``, which is truthy —
      a NON-revocable authority read back as revocable;
    * ``permissions=["mint"]`` decoded as ``"['mint']"``, parsed as ``()`` —
      every permission silently lost, so a permission check was False for all.

    Both are what a reader gets for a Photonic-minted authority too, since
    `authority.ts` writes exactly those types.
    """
    from pyrxd.glyph.payload import decode_payload

    minted = build_authority_metadata(
        "rxd1qissuer",
        scope="tournaments",
        permissions=["mint", "revoke"],
        expires="2030-01-01T00:00:00Z",
        revocable=False,
    )
    cbor_bytes, _hash = encode_payload(minted)
    recovered = read_authority_attrs(decode_payload(cbor_bytes))

    assert recovered is not None
    assert recovered.revocable is False, "a non-revocable authority must not read back as revocable"
    assert recovered.permissions == ("mint", "revoke")
    assert recovered.issuer == "rxd1qissuer" and recovered.scope == "tournaments"
    assert "mint" in read_authority_attrs(decode_payload(cbor_bytes)).permissions


def test_a_photonic_shaped_authority_decodes_with_its_types_intact():
    """Read side, from raw CBOR nobody in this repo produced."""
    import cbor2

    from pyrxd.glyph.payload import decode_payload

    raw = cbor2.dumps(
        {
            "p": [2, 10],
            "name": "Issuer",
            "attrs": {"issuer": "them", "revocable": False, "permissions": ["mint"]},
        }
    )
    attrs = read_authority_attrs(decode_payload(raw))
    assert attrs is not None and attrs.revocable is False and attrs.permissions == ("mint",)


def test_wave_attrs_are_unaffected_by_the_wider_attrs_type():
    """Honest-path check: widening the value type must not disturb string attrs."""
    import cbor2

    from pyrxd.glyph.payload import decode_payload
    from pyrxd.glyph.wave import WaveAttrs

    raw = cbor2.dumps(
        {
            "p": [2, 5, 11],
            "name": "w",
            "attrs": {"name": "alice.rxd", "domain": "rxd", "target": "1abc", "target_type": "address"},
        }
    )
    attrs = WaveAttrs.from_dict(decode_payload(raw).attrs)
    assert attrs.name == "alice.rxd" and attrs.domain == "rxd"


def test_a_nested_attr_value_is_still_flattened():
    """Nothing in the protocol needs nesting, and untrusted CBOR should not carry it."""
    import cbor2

    from pyrxd.glyph.payload import decode_payload

    raw = cbor2.dumps({"p": [2], "name": "x", "attrs": {"deep": {"a": {"b": 1}}}})
    assert isinstance(decode_payload(raw).attrs["deep"], str)


def test_an_authority_gated_item_does_NOT_parse_as_a_delegate_base():
    """Regression for a confirmed forgery of an authority claim.

    A gated item is `OP_REQUIREINPUTREF <authority> OP_DROP
    OP_PUSHINPUTREFSINGLETON <item> OP_DROP` + P2PKH — it OPENS with exactly the
    pair `parse_delegate_base_script` collects. While that parser ignored its
    tail, a gated item parsed as a base authorising the issuer, byte-for-byte
    indistinguishable from a real one.

    The attack: the holder of ONE gated item, who never held the authority,
    spends its outpoint and emits a burn naming it — permitted, because
    consensus puts every spent outpoint into the require set. Every token in
    that transaction claiming `by:[authority]` then resolved to
    BACKED/DELEGATED, and `verify_authority_claim` returned valid=True.
    """
    from pyrxd.glyph.script import build_delegate_base_script, parse_delegate_base_script

    gated = build_authority_gated_nft_script(PKH, ITEM, AUTHORITY)
    assert parse_delegate_base_script(gated) == (), "a gated item must not read as a delegate base"

    # A genuine base still parses, including one with an unrecognised tail —
    # the fix must not refuse honest bases built by another wallet.
    real = build_delegate_base_script(PKH, [AUTHORITY, ITEM])
    assert parse_delegate_base_script(real) == (AUTHORITY.to_bytes(), ITEM.to_bytes())
    assert parse_delegate_base_script(real + bytes.fromhex("6a02ffff")) == (
        AUTHORITY.to_bytes(),
        ITEM.to_bytes(),
    )


def test_find_glyphs_recognises_a_gated_item_and_a_delegate_token():
    """The wallet-holdings classifier, which knew neither shape.

    `GlyphInspector.find_glyphs` is what `GlyphScanner` runs to enumerate what an
    address holds (`scanner.py:160`). It is a hand-typed if/elif chain that falls
    through to a SILENT skip, and both new spendable shapes fell through it — so
    an authority-gated NFT or an unspent delegate token in a wallet was not
    reported as unknown, it simply was not reported. `_inspect_script` knew both
    shapes; this classifier did not.
    """
    from pyrxd.glyph.inspector import GlyphInspector
    from pyrxd.glyph.script import build_delegate_token_script

    gated = build_authority_gated_nft_script(PKH, ITEM, AUTHORITY)
    delegate = build_delegate_token_script(PKH, AUTHORITY)
    plain = build_nft_locking_script(PKH, ITEM)

    found = {g.glyph_type: g for g in GlyphInspector().find_glyphs([(546, gated), (546, delegate), (546, plain)])}
    assert set(found) == {"authority-gated-nft", "delegate-token", "nft"}

    item = found["authority-gated-nft"]
    assert item.ref == ITEM and item.owner_pkh == PKH
    assert item.authority_ref == AUTHORITY
    # The gated item's pkh sits at a different offset than a plain NFT's, so the
    # plain extractor must not be used on it.
    assert found["delegate-token"].ref == AUTHORITY and found["delegate-token"].owner_pkh == PKH


def test_the_scanner_returns_a_gated_item_as_an_nft_it_holds():
    """Recognising the shape is not enough — the scanner dispatched on two types.

    `find_glyphs` returning `authority-gated-nft` still produced nothing, because
    the scanner's dispatch built items only for "nft" and "ft" and dropped
    everything else without a word.
    """
    import inspect as _inspect

    from pyrxd.glyph import scanner as _scanner

    src = _inspect.getsource(_scanner)
    assert '"authority-gated-nft"' in src, "the scanner must build an item for a gated NFT"
    assert '"delegate-token"' in src, "a held delegate token must at least be reported, not dropped silently"


def test_more_permissions_than_the_decoder_keeps_are_refused_at_build_time():
    """The decoder truncates a list attr; minting past it loses entries forever.

    a permission check would answer False for the lost ones for the life of the
    token, and a mint cannot be undone — so the refusal belongs on the encode
    path, where the caller can still change their mind.
    """
    from pyrxd.glyph.payload import _MAX_ATTRS_LIST_LEN

    ok = [f"perm{i}" for i in range(_MAX_ATTRS_LIST_LEN)]
    assert len(read_authority_attrs(build_authority_metadata("i", permissions=ok)).permissions) == len(ok)

    with pytest.raises(ValidationError, match="exceeds"):
        build_authority_metadata("i", permissions=[*ok, "one-too-many"])


@pytest.mark.parametrize(
    ("opcode", "name"),
    [(0xD1, "OP_REQUIREINPUTREF"), (0xD2, "OP_DISALLOWPUSHINPUTREF"), (0xD3, "OP_DISALLOWPUSHINPUTREFSIBLING")],
)
def test_a_script_that_only_NAMES_the_authority_is_refused(opcode, name):
    """Found by re-attacking the fix that added this cross-check.

    The check accepted any of the five ref opcodes, so a script that merely
    NAMED the authority — 0xd2 is a local assertion consensus never
    subset-checks, writable by anyone — passed as "the authority's script". The
    reveal then re-creates that instead of the authority, and the real
    authority, spent as an input, is BURNED.

    Third occurrence of this exact opcode-set mistake on one branch, which is
    why `script_carries_ref` now exists and every call site goes through it.
    """
    from pyrxd.glyph.payload import encode_payload

    builder = GlyphBuilder()
    cbor_bytes, _hash = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.NFT], name="Gated item"))
    impostor = bytes([opcode]) + AUTHORITY.to_bytes() + b"\x75" + b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"

    with pytest.raises(ValidationError, match="does not carry"):
        builder.prepare_authority_gated_reveal("11" * 32, 0, cbor_bytes, PKH, AUTHORITY, impostor)


def test_script_carries_ref_counts_only_the_two_opcodes_that_mean_possession():
    """The primitive itself — one definition, so a fourth call site cannot get it wrong."""
    from pyrxd.glyph.script import build_delegate_token_script, script_carries_ref

    wire = AUTHORITY.to_bytes()
    # 0xd0 (FT / delegate token) and 0xd8 (NFT singleton) hold a token.
    assert script_carries_ref(build_nft_locking_script(PKH, AUTHORITY), wire)
    assert script_carries_ref(build_delegate_token_script(PKH, AUTHORITY), wire)
    # The other three do not.
    for opcode in (0xD1, 0xD2, 0xD3):
        assert not script_carries_ref(bytes([opcode]) + wire + b"\x75", wire)
    # A different ref, and an undecodable script, are both False rather than raising.
    assert not script_carries_ref(build_nft_locking_script(PKH, ITEM), wire)
    assert not script_carries_ref(b"\xd8" + b"\x00" * 10, wire)


def test_a_gated_genesis_for_ANOTHER_item_does_not_answer_about_this_one() -> None:
    """The substitution the old signature made undetectable.

    `verify_authority_gate` took only (script, authority) and returned ok=True with basis GATE for
    a genuine gated output under the right authority — whichever ITEM that output was the genesis
    of. No forgery needed: handing it item B's genesis while asking about item A was enough, and
    the function could not notice although B's ref is in the bytes it was handed.

    `item_ref` is keyword-only and REQUIRED, so the unbound call is not expressible. An optional
    parameter would have left the old behaviour reachable by omission, which for a security
    verdict is the same defect with a longer fuse.
    """
    item_a = GlyphRef(txid="11" * 32, vout=0)
    item_b = GlyphRef(txid="22" * 32, vout=0)
    genesis_of_b = build_authority_gated_nft_script(PKH, item_b, AUTHORITY)

    honest = verify_authority_gate(genesis_of_b, AUTHORITY, item_ref=item_b)
    assert honest.ok, "the honest case must still pass — a guard that refuses valid work is a bug"

    substituted = verify_authority_gate(genesis_of_b, AUTHORITY, item_ref=item_a)
    assert not substituted.ok
    assert "a different item" in substituted.reason


def test_the_unbound_call_is_not_expressible() -> None:
    """Structural: omitting `item_ref` must be a TypeError, not a permissive default."""
    with pytest.raises(TypeError):
        verify_authority_gate(build_authority_gated_nft_script(PKH, ITEM, AUTHORITY), AUTHORITY)  # type: ignore[call-arg]


def _authority_reveal_payload(**attrs_overrides):
    """A classified payload for a real AUTHORITY reveal, through the production classifier.

    Built as a transaction and run through `_classify_raw_tx` rather than hand-shaping a dict, so
    the fixture is a shape the producer actually emits. `_classify_raw_tx` binds the echoed txid,
    so the real one is computed rather than invented.
    """
    import cbor2

    from pyrxd.glyph._inspect_core import _classify_raw_tx
    from pyrxd.glyph.payload import GLY_MARKER
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    attrs = {
        "issuer": "mudwood-issuer",
        "scope": "collection:x",
        "permissions": ["mint", "revoke"],
        "expires": "2020-01-01T00:00:00Z",
        "revocable": True,
    }
    attrs.update(attrs_overrides)
    blob = cbor2.dumps({"p": [2, 10], "v": 2, "name": "Issuer Authority", "type": "authority", "attrs": attrs})
    scriptsig = bytes([len(GLY_MARKER)]) + GLY_MARKER + b"\x4c" + bytes([len(blob)]) + blob
    tx = Transaction()
    tx.inputs.append(
        TransactionInput(
            source_txid="ab" * 32,
            source_output_index=0,
            unlocking_script=Script(scriptsig, allow_malformed=True),
        )
    )
    tx.outputs.append(TransactionOutput(satoshis=546, locking_script=Script(b"\x6a", allow_malformed=True)))
    return _classify_raw_tx(tx.txid(), bytes(tx.serialize()))


def test_an_expired_authority_says_so_on_the_terminal() -> None:
    """`metadata.authority` was computed and rendered by NOTHING — not the CLI, not the browser.

    So an authority that expired years ago printed identically to a live one, and `problems` (the
    one signal that `validate_authority` could not read the expiry at all) was invisible too. The
    classifier had the answer; nobody could see it.
    """
    from pyrxd.cli.glyph_inspect import _render_txid_human

    payload = _authority_reveal_payload()
    auth = (payload.get("metadata") or {}).get("authority")
    assert auth is not None, "the classifier stopped emitting metadata.authority"
    assert auth["expired"] is True, "the fixture is meant to be an EXPIRED authority"

    text = _render_txid_human(payload)
    assert "EXPIRED" in text, "an expired authority renders the same as a live one"
    assert "mudwood-issuer" in text
    assert "collection:x" in text
    assert "mint, revoke" in text
    # And what it does NOT establish, which is the whole reason to print the block.
    assert "NOT proof any item was minted" in text


def test_a_live_authority_does_not_say_expired() -> None:
    """The other branch. A guard that refuses valid work is a bug, and so is a banner that fires
    on everything — an EXPIRED label on live authorities would train readers to ignore it."""
    from pyrxd.cli.glyph_inspect import _render_txid_human

    payload = _authority_reveal_payload(expires="2999-01-01T00:00:00Z")
    assert (payload["metadata"]["authority"])["expired"] is False
    assert "EXPIRED" not in _render_txid_human(payload)

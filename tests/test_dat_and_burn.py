"""DAT (protocol 3) and BURN (protocol 6): the write sides, and honest verdicts.

Both markers had label-only support: `DAT` had two `if DAT in p: return "dat"`
classifier branches and nothing else; `BURN` had **zero** references in `src/`
outside the enum, and one test asserting its value was 6.

Consensus behaviour is proven separately on a node in
``tests/test_dat_and_burn_regtest_e2e.py``. This file covers what does not need
one.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder
from pyrxd.glyph.burn import (
    BURN_MARKER_BYTE,
    BURN_PROOF_VERSION,
    BurnBasis,
    build_burn_proof_script,
    parse_burn_proof,
    verify_burn,
)
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import (
    DAT_MARKER,
    GLY_MARKER,
    build_dat_reveal_scriptsig_suffix,
    build_reveal_scriptsig_suffix,
    encode_payload,
)
from pyrxd.glyph.script import (
    DAT_COMMIT_SCRIPT_SIZE,
    build_commit_locking_script,
    build_dat_commit_locking_script,
    build_nft_locking_script,
    extract_delegate_ref_from_commit_script,
    is_commit_script,
    parse_dat_commit_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

PKH = Hex20(bytes.fromhex("7d6c507735322c6bac9398317a65b4597072f0a6"))
HASH = bytes(range(32))
TOKEN = GlyphRef(txid="11" * 32, vout=0)
OTHER = GlyphRef(txid="22" * 32, vout=1)
BASE = GlyphRef(txid="b2" * 32, vout=2)


# ---------------------------------------------------------------------------
# DAT
# ---------------------------------------------------------------------------


def test_dat_commit_is_70_bytes_and_has_no_reftype_block():
    """The missing OP_REFTYPE_OUTPUT block is what makes the reveal mint nothing."""
    dat = build_dat_commit_locking_script(HASH, PKH)
    assert len(dat) == DAT_COMMIT_SCRIPT_SIZE == 70
    # The NFT/FT commits carry `da <OP_N> 9d` (OP_REFTYPE_OUTPUT ... VERIFY).
    assert b"\xda" not in dat
    assert b"\x03dat" in dat and b"\x03gly" in dat


def test_dat_commit_round_trips_and_is_not_an_nft_or_ft_commit():
    assert parse_dat_commit_script(build_dat_commit_locking_script(HASH, PKH)) == (HASH, PKH)
    assert not is_commit_script(build_dat_commit_locking_script(HASH, PKH).hex())
    assert parse_dat_commit_script(build_commit_locking_script(HASH, PKH, is_nft=True)) is None
    assert parse_dat_commit_script(build_nft_locking_script(PKH, TOKEN)) is None


def test_dat_commit_supports_the_delegate_prefix():
    delegated = build_dat_commit_locking_script(HASH, PKH, delegate_ref=BASE)
    assert len(delegated) == 70 + 56
    assert parse_dat_commit_script(delegated) == (HASH, PKH)
    assert extract_delegate_ref_from_commit_script(delegated) == BASE


def test_the_dat_reveal_suffix_pushes_the_markers_in_the_order_the_commit_pops_them():
    """`gly`, `dat`, payload. The commit pops payload, then "dat", then "gly"."""
    cbor_bytes, _h = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.DAT], name="blob"))
    suffix = build_dat_reveal_scriptsig_suffix(cbor_bytes)
    assert suffix.startswith(b"\x03" + GLY_MARKER + b"\x03" + DAT_MARKER)
    # The ordinary suffix has no `dat` push — that difference is load-bearing,
    # and the regtest suite proves a DAT commit refuses it.
    assert build_reveal_scriptsig_suffix(cbor_bytes).startswith(b"\x03" + GLY_MARKER)
    assert DAT_MARKER not in build_reveal_scriptsig_suffix(cbor_bytes)[:8]


def test_both_suffixes_share_one_push_ladder():
    """A large payload must reach PUSHDATA4 on BOTH, or the DAT variant caps early."""
    big = b"y" * 70_000
    assert build_reveal_scriptsig_suffix(big)[4] == 0x4E
    assert build_dat_reveal_scriptsig_suffix(big)[8] == 0x4E


def test_the_reveal_parser_reads_a_dat_payload():
    """Regression: `items[i + 1]` after `gly` is the DAT MARKER, not the payload.

    A DAT reveal has no token output, so the payload is the entire content. The
    parser returning None meant a DAT glyph pyrxd minted was unreadable by
    pyrxd, and the regtest suite is what surfaced it.
    """
    metadata = GlyphMetadata(protocol=[GlyphProtocol.DAT], name="stored", description="content")
    cbor_bytes, _h = encode_payload(metadata)
    # A realistic scriptSig: <sig> <pubkey> <suffix>.
    scriptsig = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + build_dat_reveal_scriptsig_suffix(cbor_bytes)

    found = GlyphInspector().extract_reveal_metadata(scriptsig)
    assert found is not None, "a DAT payload must be recoverable"
    assert found.name == "stored" and found.description == "content"


def test_the_reveal_parser_still_reads_an_ordinary_payload():
    """Honest-path check: the DAT branch must not disturb every other glyph."""
    metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="ordinary")
    cbor_bytes, _h = encode_payload(metadata)
    scriptsig = b"\x47" + b"\x00" * 71 + b"\x21" + b"\x02" * 33 + build_reveal_scriptsig_suffix(cbor_bytes)
    found = GlyphInspector().extract_reveal_metadata(scriptsig)
    assert found is not None and found.name == "ordinary"


def test_the_builder_refuses_a_dat_commit_for_non_dat_metadata():
    builder = GlyphBuilder()
    params = CommitParams(
        metadata=GlyphMetadata(protocol=[GlyphProtocol.NFT], name="not dat"),
        owner_pkh=PKH,
        change_pkh=PKH,
        funding_satoshis=100_000,
    )
    with pytest.raises(ValidationError, match="GlyphProtocol.DAT"):
        builder.prepare_dat_commit(params)


def test_a_dat_reveal_returns_no_locking_script():
    """It mints nothing; handing back a token script would be a lie about that."""
    builder = GlyphBuilder()
    cbor_bytes, _h = encode_payload(GlyphMetadata(protocol=[GlyphProtocol.DAT], name="blob"))
    # None, not b"": an empty scriptPubKey is a VALID anyone-can-spend script,
    # so returning it would let a caller reusing the ordinary reveal loop put
    # the commit value up for grabs. None makes that construction fail.
    assert builder.prepare_dat_reveal(cbor_bytes).locking_script is None


# ---------------------------------------------------------------------------
# BURN
# ---------------------------------------------------------------------------


def test_burn_proof_layout_matches_photonic():
    """OP_RETURN <"gly"> <0x02> <0x06> <CBOR>, with ONE-BYTE PUSHES for the flags.

    A minimal push would encode 0x02 as OP_2 and 0x06 as OP_6, which carry no
    `buf` — Photonic's parser reads `chunks[n].buf` and would see undefined.
    """
    script = build_burn_proof_script(TOKEN)
    assert script[0] == 0x6A
    assert script[1:5] == b"\x03" + GLY_MARKER
    assert script[5:7] == bytes([1, BURN_PROOF_VERSION])
    assert script[7:9] == bytes([1, BURN_MARKER_BYTE])
    assert BURN_MARKER_BYTE == int(GlyphProtocol.BURN) == 6


def test_burn_proof_round_trips_with_every_optional():
    proof = parse_burn_proof(build_burn_proof_script(TOKEN, amount=250, burn_reason="redeemed"))
    assert proof is not None
    assert proof.token_ref == f"{TOKEN.txid}:{TOKEN.vout}"
    assert proof.action == "burn" and proof.amount == 250 and proof.reason == "redeemed"
    assert proof.protocol == (6,)


def test_optionals_are_omitted_when_not_given():
    proof = parse_burn_proof(build_burn_proof_script(TOKEN))
    assert proof is not None and proof.amount is None and proof.reason is None


def test_a_negative_burn_amount_is_refused():
    with pytest.raises(ValidationError, match="must be >= 0"):
        build_burn_proof_script(TOKEN, amount=-1)


def test_an_oversized_reason_is_refused():
    with pytest.raises(ValidationError, match="over the"):
        build_burn_proof_script(TOKEN, burn_reason="x" * 9000)


def test_non_burn_scripts_parse_as_none_rather_than_raising():
    assert parse_burn_proof(build_nft_locking_script(PKH, TOKEN)) is None
    assert parse_burn_proof(b"") is None
    assert parse_burn_proof(b"\x6a") is None
    assert parse_burn_proof(b"\x6a\x03" + GLY_MARKER) is None  # truncated
    # Right shape, wrong markers.
    assert parse_burn_proof(b"\x6a\x03" + GLY_MARKER + b"\x01\x09\x01\x06\x01\x00") is None


# ---------------------------------------------------------------------------
# The verdict, and the line Photonic does not draw
# ---------------------------------------------------------------------------


def _proof_and_token():
    return build_burn_proof_script(TOKEN), build_nft_locking_script(PKH, TOKEN)


def test_the_spent_outputs_cannot_be_omitted():
    """The weak verdict is gone: you either have the evidence or cannot ask.

    `spent_output_scripts` was optional, and omitting it returned ok=False for a
    GENUINE burn — a function called `verify_burn` answering False about a real
    burn is the most surprising thing an API can do. Absence from the outputs
    alone is satisfied by every unrelated transaction on the chain, so there was
    no useful verdict to give without it.
    """
    proof, _tok = _proof_and_token()
    with pytest.raises(TypeError):
        verify_burn([proof], TOKEN)  # type: ignore[call-arg]


def test_with_the_spent_outputs_it_is_the_strong_one():
    proof, tok = _proof_and_token()
    verdict = verify_burn([proof], TOKEN, [tok])
    assert verdict.ok and verdict.basis is BurnBasis.SPENT_AND_ABSENT


def test_a_proof_about_a_token_the_tx_never_held_is_REFUSED():
    """The divergence from Photonic's `validateBurn`, which checks only absence.

    Absence from the outputs is a condition every unrelated transaction in the
    world satisfies, so on its own it cannot distinguish a burn from an
    assertion about someone else's property.
    """
    proof = build_burn_proof_script(TOKEN)
    verdict = verify_burn([proof], TOKEN, [build_nft_locking_script(PKH, OTHER)])
    assert not verdict.ok and verdict.basis is BurnBasis.NONE
    assert "spent nothing carrying the token ref" in verdict.reason


def test_a_token_that_survives_in_an_output_is_not_burned():
    proof, tok = _proof_and_token()
    verdict = verify_burn([proof, tok], TOKEN, [tok])
    assert not verdict.ok and "forwarded, not burned" in verdict.reason


def test_a_proof_naming_a_different_token_does_not_burn_this_one():
    verdict = verify_burn([build_burn_proof_script(OTHER)], TOKEN, [build_nft_locking_script(PKH, TOKEN)])
    assert not verdict.ok and "names" in verdict.reason


def test_no_proof_at_all_is_not_a_burn():
    """A token can vanish by accident; the proof is what records it was meant."""
    _proof, tok = _proof_and_token()
    verdict = verify_burn([build_nft_locking_script(PKH, OTHER)], TOKEN, [tok])
    assert not verdict.ok and "no burn proof" in verdict.reason


def test_an_unwalkable_output_does_not_turn_a_survival_into_a_burn():
    """Fail-closed on garbage: it must not be evidence the ref is gone.

    A truncated ref operand makes the script's length ambiguous. Treating that
    as "does not carry the ref" would let a crafted output hide a survival.
    """
    proof, tok = _proof_and_token()
    truncated = b"\xd8" + b"\x00" * 10
    verdict = verify_burn([proof, truncated], TOKEN, [tok])
    # The real token is genuinely absent here, so this is still a burn — the
    # point is that the unwalkable output neither crashed it nor was counted.
    assert verdict.ok and verdict.basis is BurnBasis.SPENT_AND_ABSENT


# ---------------------------------------------------------------------------
# What reaches a human
# ---------------------------------------------------------------------------


def test_the_inspector_names_both_shapes_and_qualifies_the_burn_claim():
    from pyrxd.glyph._inspect_core import _inspect_script

    dat = _inspect_script(build_dat_commit_locking_script(HASH, PKH).hex())
    assert dat["type"] == "commit-dat"
    assert dat["payload_hash"] == HASH.hex() and dat["owner_pkh"] == bytes(PKH).hex()
    assert "creates no token" in dat["note"]

    burn = _inspect_script(build_burn_proof_script(TOKEN, amount=7).hex())
    assert burn["type"] == "op_return-burn"
    assert burn["burn"]["claims"]["token_ref"] == f"{TOKEN.txid}:{TOKEN.vout}"
    assert burn["burn"]["claims"]["amount"] == 7
    # The caveat must travel with the claim.
    assert "anyone can write one" in burn["burn"]["note"]


# ---------------------------------------------------------------------------
# Forged burns (found by the security panel, 2026-09-05)
# ---------------------------------------------------------------------------


def test_a_disallow_ref_opcode_does_not_count_as_having_held_the_token():
    """`_carries` must count only PUSHED refs. Regression for a real forgery.

    `OP_DISALLOWPUSHINPUTREF` (0xd2) and `...SIBLING` (0xd3) are LOCAL
    assertions — consensus never asks whether an input carried them, so anyone
    can name any ref with one for the price of an output. Walking the wide
    opcode set let an attacker create `0xd2 <victim_ref> OP_DROP <P2PKH>`, spend
    it beside a burn proof naming the victim's live NFT, and receive
    SPENT_AND_ABSENT / valid=True for a token they never held.

    This is the identical defect `relationships.py` records having had — "the
    verifier ... originally used the widest one and reported forged collection
    membership as VERIFIED" — committed a second time in a second module.
    """
    victim = GlyphRef(txid="ab" * 32, vout=0)
    proof = build_burn_proof_script(victim)
    p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"

    for opcode, name in ((0xD2, "OP_DISALLOWPUSHINPUTREF"), (0xD3, "OP_DISALLOWPUSHINPUTREFSIBLING")):
        forged = bytes([opcode]) + victim.to_bytes() + b"\x75" + p2pkh
        verdict = verify_burn([proof], victim, [forged])
        assert not verdict.ok, f"{name} forged a burn of someone else's token"
        assert verdict.basis is BurnBasis.NONE

    # OP_REQUIREINPUTREF is a requirement, not possession — also not enough.
    required = bytes([0xD1]) + victim.to_bytes() + b"\x75" + p2pkh
    assert not verify_burn([proof], victim, [required]).ok

    # And the honest path still works: a real singleton the tx spent.
    honest = build_nft_locking_script(PKH, victim)
    assert verify_burn([proof], victim, [honest]).ok


def test_a_stray_disallow_mention_does_not_make_an_honest_burn_read_as_survival():
    """The same over-wide set, in the other direction — refusing valid work.

    On the OUTPUT side, counting 0xd2 as "the token is still here" would report
    a genuine burn as `forwarded, not burned`.
    """
    victim = GlyphRef(txid="ab" * 32, vout=0)
    proof = build_burn_proof_script(victim)
    p2pkh = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    noise = bytes([0xD2]) + victim.to_bytes() + b"\x75" + p2pkh

    verdict = verify_burn([proof, noise], victim, [build_nft_locking_script(PKH, victim)])
    assert verdict.ok and verdict.basis is BurnBasis.SPENT_AND_ABSENT


def test_a_transaction_burning_two_tokens_answers_for_both():
    """Selecting the FIRST parseable proof refused an honest batch burn.

    A transaction burning A and B carries two proofs. Taking proofs[0] reported
    B as "the proof names A, not B" — a guard refusing valid work.
    """
    a, b = TOKEN, OTHER
    outputs = [build_burn_proof_script(a), build_burn_proof_script(b)]
    spent = [build_nft_locking_script(PKH, a), build_nft_locking_script(PKH, b)]

    for ref in (a, b):
        verdict = verify_burn(outputs, ref, spent)
        assert verdict.ok, f"honest batch burn refused for {ref.txid[:8]}"
        assert verdict.proof is not None
        assert verdict.proof.token_ref == f"{ref.txid}:{ref.vout}"

    # A token neither proof names is still refused.
    third = GlyphRef(txid="33" * 32, vout=2)
    assert not verify_burn(outputs, third, spent).ok


def _proof_script_naming(token_ref_text: str) -> bytes:
    """A real burn-proof script whose `token_ref` is spelled *token_ref_text*.

    Built by taking `build_burn_proof_script`'s own output and substituting the one field, so the
    version, protocol and push layout are whatever production actually emits. Hand-rolling the
    script got `v` and `p` wrong and produced a proof `parse_burn_proof` refused, which would have
    made this test pass for the wrong reason.
    """
    import cbor2

    from pyrxd.glyph.burn import build_burn_proof_script

    template = build_burn_proof_script(GlyphRef(txid="ab" * 32, vout=7))
    marker = template.index(b"\x4c")
    decoded = cbor2.loads(template[marker + 2 :])
    decoded["token_ref"] = token_ref_text
    blob = cbor2.dumps(decoded)
    return template[:marker] + b"\x4c" + bytes([len(blob)]) + blob


def test_a_burn_proof_in_photonics_spelling_is_accepted() -> None:
    """pyrxd refused every burn proof Photonic has ever written, with a false reason.

    pyrxd writes `"<txid>:<vout>"`. Photonic writes `Outpoint.toString()` — txid hex then the vout
    as 8 big-endian hex digits, no separator — on BOTH sides: `createBurnProof` builds it that way
    and `validateBurn` normalises through `Outpoint.fromString(...).toString()` before comparing
    (`packages/lib/src/burn.ts`). Neither project emits the other's form, so matching only the
    colon form rejected all of them — and said "the burn proof names X, not Y" about a proof that
    named the same token in the other implementation's spelling.
    """
    from pyrxd.glyph.burn import verify_burn

    ref = GlyphRef(txid="ab" * 32, vout=7)
    photonic = f"{ref.txid}{(7).to_bytes(4, 'big').hex()}"
    assert ":" not in photonic and len(photonic) == 72

    held = [build_nft_locking_script(Hex20(b"\x11" * 20), ref)]
    verdict = verify_burn([_proof_script_naming(photonic)], ref, held)
    assert verdict.ok, f"a Photonic-spelled burn proof was refused: {verdict.reason}"

    # pyrxd's own spelling must still work — this must not trade one implementation for the other.
    assert verify_burn([_proof_script_naming(f"{ref.txid}:{ref.vout}")], ref, held).ok


def test_a_proof_naming_a_DIFFERENT_token_is_still_refused_in_both_spellings() -> None:
    """Widening the match must not widen it to everything."""
    from pyrxd.glyph.burn import verify_burn

    ref = GlyphRef(txid="ab" * 32, vout=7)
    other = GlyphRef(txid="cd" * 32, vout=1)
    held = [build_nft_locking_script(Hex20(b"\x11" * 20), ref)]

    for spelling in (f"{other.txid}:{other.vout}", f"{other.txid}{(1).to_bytes(4, 'big').hex()}"):
        verdict = verify_burn([_proof_script_naming(spelling)], ref, held)
        assert not verdict.ok, f"a proof naming another token was accepted ({spelling})"

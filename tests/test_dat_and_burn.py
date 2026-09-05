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
    assert builder.prepare_dat_reveal(cbor_bytes).locking_script == b""


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


def test_without_the_spent_outputs_the_verdict_is_explicitly_the_weaker_one():
    proof, _tok = _proof_and_token()
    verdict = verify_burn([proof], TOKEN)
    assert verdict.valid and verdict.basis is BurnBasis.ABSENT_ONLY
    assert "does not rule out" in verdict.reason


def test_with_the_spent_outputs_it_is_the_strong_one():
    proof, tok = _proof_and_token()
    verdict = verify_burn([proof], TOKEN, spent_output_scripts=[tok])
    assert verdict.valid and verdict.basis is BurnBasis.SPENT_AND_ABSENT


def test_a_proof_about_a_token_the_tx_never_held_is_REFUSED():
    """The divergence from Photonic's `validateBurn`, which checks only absence.

    Absence from the outputs is a condition every unrelated transaction in the
    world satisfies, so on its own it cannot distinguish a burn from an
    assertion about someone else's property.
    """
    proof = build_burn_proof_script(TOKEN)
    verdict = verify_burn([proof], TOKEN, spent_output_scripts=[build_nft_locking_script(PKH, OTHER)])
    assert not verdict.valid and verdict.basis is BurnBasis.NONE
    assert "spent nothing carrying the token ref" in verdict.reason


def test_a_token_that_survives_in_an_output_is_not_burned():
    proof, tok = _proof_and_token()
    verdict = verify_burn([proof, tok], TOKEN, spent_output_scripts=[tok])
    assert not verdict.valid and "forwarded, not burned" in verdict.reason


def test_a_proof_naming_a_different_token_does_not_burn_this_one():
    verdict = verify_burn([build_burn_proof_script(OTHER)], TOKEN)
    assert not verdict.valid and "names" in verdict.reason


def test_no_proof_at_all_is_not_a_burn():
    """A token can vanish by accident; the proof is what records it was meant."""
    _proof, tok = _proof_and_token()
    verdict = verify_burn([build_nft_locking_script(PKH, OTHER)], TOKEN, spent_output_scripts=[tok])
    assert not verdict.valid and "no burn proof" in verdict.reason


def test_an_unwalkable_output_does_not_turn_a_survival_into_a_burn():
    """Fail-closed on garbage: it must not be evidence the ref is gone.

    A truncated ref operand makes the script's length ambiguous. Treating that
    as "does not carry the ref" would let a crafted output hide a survival.
    """
    proof, tok = _proof_and_token()
    truncated = b"\xd8" + b"\x00" * 10
    verdict = verify_burn([proof, truncated], TOKEN, spent_output_scripts=[tok])
    # The real token is genuinely absent here, so this is still a burn — the
    # point is that the unwalkable output neither crashed it nor was counted.
    assert verdict.valid and verdict.basis is BurnBasis.SPENT_AND_ABSENT


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

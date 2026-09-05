"""Delegate refs: the write side for ``in``/``by`` that pyrxd never had.

Before this, ``GlyphMetadata.author_refs`` had exactly one producer — the CBOR
emit — so a ``by`` claim could be *declared* and never *authorised*, and
:mod:`pyrxd.glyph.relationships` (which checks CONTAINER and AUTHOR by the same
rule) reported every one of them UNBACKED. ``prepare_container_child_reveal``
covered ``in`` only, by spending and re-creating the container.

A delegate authorises both without the minter holding either singleton: the
parents are spent ONCE into a base output under ``OP_REQUIREINPUTREF``, cheap
delegate tokens point at that base, and each mint burns one.

Every byte layout here is cross-checked against Photonic Wallet
(``packages/lib/src/script.ts``), which is the implementation whose indexer
decides whether a claim is honoured (``packages/app/src/electrum/worker/NFT.ts``
lines 869-871 apply the same filter to containers and authors).
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.builder import CommitParams, GlyphBuilder, RevealParams
from pyrxd.glyph.relationships import (
    RelationshipBacking,
    RelationshipKind,
    RelationshipOutcome,
    delegate_burn_refs,
    verify_relationship_claims,
)
from pyrxd.glyph.script import (
    DELEGATE_BURN_SCRIPT_SIZE,
    DELEGATE_COMMIT_PREFIX_SIZE,
    DELEGATE_TOKEN_SCRIPT_SIZE,
    build_commit_locking_script,
    build_delegate_base_script,
    build_delegate_burn_script,
    build_delegate_commit_prefix,
    build_delegate_token_script,
    build_nft_locking_script,
    extract_delegate_ref_from_commit_script,
    extract_owner_pkh_from_commit_script,
    extract_payload_hash_from_commit_script,
    is_commit_nft_script,
    is_commit_script,
    is_delegate_token_script,
    is_nft_script,
    parse_delegate_base_script,
    parse_delegate_burn_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

PKH = Hex20(bytes.fromhex("7d6c507735322c6bac9398317a65b4597072f0a6"))
CONTAINER = GlyphRef(txid="c0" * 32, vout=0)
AUTHOR = GlyphRef(txid="a1" * 32, vout=1)
BASE = GlyphRef(txid="b2" * 32, vout=2)
MINTED = GlyphRef(txid="11" * 32, vout=0)


def _metadata() -> GlyphMetadata:
    return GlyphMetadata(
        protocol=[GlyphProtocol.NFT],
        name="Tournament NFT",
        container_refs=(CONTAINER,),
        author_refs=(AUTHOR,),
    )


# ---------------------------------------------------------------------------
# Byte layout, against Photonic's independently-declared sizes
# ---------------------------------------------------------------------------


def test_script_sizes_match_photonic_constants():
    """script.ts declares 63 / 42 and a +56 commit delta. Ours must be those.

    These three numbers are the cross-check that the operands are encoded as
    BARE 36-byte ref operands rather than pushdata-wrapped: a pushdata encoding
    is one byte longer in each script and none of the three would land.
    """
    assert len(build_delegate_token_script(PKH, BASE)) == DELEGATE_TOKEN_SCRIPT_SIZE == 63
    assert len(build_delegate_burn_script(BASE)) == DELEGATE_BURN_SCRIPT_SIZE == 42
    assert len(build_delegate_commit_prefix(BASE)) == DELEGATE_COMMIT_PREFIX_SIZE == 56


def test_base_script_length_is_38_per_ref_plus_p2pkh():
    for n in (1, 2, 5):
        refs = [GlyphRef(txid=f"{i:02x}" * 32, vout=i) for i in range(n)]
        assert len(build_delegate_base_script(PKH, refs)) == 38 * n + 25


def test_burn_script_is_exactly_photonics_bytes():
    """``OP_REQUIREINPUTREF <ref> OP_RETURN "del"`` — matches script.ts:471."""
    script = build_delegate_burn_script(BASE)
    assert script[0] == 0xD1
    assert script[1:37] == BASE.to_bytes()
    assert script[37:] == bytes.fromhex("6a") + bytes.fromhex("03") + b"del"
    # Photonic's parseDelegateBurnScript regex, applied to our bytes.
    assert __import__("re").fullmatch(r"d1[0-9a-f]{72}6a0364656c", script.hex())


def test_token_script_has_the_op_drop_that_the_removed_child_ref_prefix_lacked():
    """The ``0x75`` is what made pyrxd's 0.9.0-0.14.0 container prefix unspendable."""
    script = build_delegate_token_script(PKH, BASE)
    assert script[0] == 0xD0  # OP_PUSHINPUTREF
    assert script[37] == 0x75  # OP_DROP — leaves the stack clean for the P2PKH tail
    assert script[38:] == bytes.fromhex("76a914") + bytes(PKH) + bytes.fromhex("88ac")


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------


def test_base_script_round_trips_in_order():
    script = build_delegate_base_script(PKH, [CONTAINER, AUTHOR])
    assert parse_delegate_base_script(script) == (CONTAINER.to_bytes(), AUTHOR.to_bytes())


def test_burn_script_round_trips():
    assert parse_delegate_burn_script(build_delegate_burn_script(BASE)) == BASE.to_bytes()


def test_base_parser_ignores_an_unrecognised_tail_like_photonics_regex():
    """Photonic's regex ends in ``.*``. Being stricter would refuse honest bases.

    A base built by another wallet may end in something other than our P2PKH
    tail; the leading authorisation run is what carries meaning.
    """
    script = build_delegate_base_script(PKH, [CONTAINER]) + bytes.fromhex("6a02ffff")
    assert parse_delegate_base_script(script) == (CONTAINER.to_bytes(),)


def test_parsers_reject_non_delegate_scripts_rather_than_guessing():
    assert parse_delegate_base_script(build_nft_locking_script(PKH, MINTED)) == ()
    assert parse_delegate_burn_script(build_nft_locking_script(PKH, MINTED)) is None
    assert parse_delegate_burn_script(b"") is None
    # Truncated mid-operand: ambiguous length, must not parse as anything.
    assert parse_delegate_base_script(b"\xd1" + b"\x00" * 10) == ()


def test_empty_base_is_refused():
    """A base authorising nothing parses back as a plain P2PKH and delegates nothing."""
    with pytest.raises(ValidationError, match="at least one ref"):
        build_delegate_base_script(PKH, [])


# ---------------------------------------------------------------------------
# The 63-byte shape collision
# ---------------------------------------------------------------------------


def test_delegate_token_and_nft_singleton_are_both_63_bytes_and_must_not_be_confused():
    """Same length, same layout, different opcode (0xd0 vs 0xd8).

    Anything classifying chain outputs by length alone would call a delegate
    token an NFT. It is token-bearing either way, so spending one as ordinary
    funding destroys it.
    """
    token = build_delegate_token_script(PKH, BASE)
    nft = build_nft_locking_script(PKH, BASE)
    assert len(token) == len(nft) == 63
    assert token != nft
    assert is_delegate_token_script(token.hex()) and not is_nft_script(token.hex())
    assert is_nft_script(nft.hex()) and not is_delegate_token_script(nft.hex())


# ---------------------------------------------------------------------------
# The commit script's other branch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("is_nft", [True, False])
def test_delegate_commit_is_the_plain_commit_behind_a_56_byte_prefix(is_nft):
    payload_hash = bytes(range(32))
    plain = build_commit_locking_script(payload_hash, PKH, is_nft=is_nft)
    delegated = build_commit_locking_script(payload_hash, PKH, is_nft=is_nft, delegate_ref=BASE)
    assert len(delegated) - len(plain) == DELEGATE_COMMIT_PREFIX_SIZE
    assert delegated.endswith(plain)


@pytest.mark.parametrize("is_nft", [True, False])
def test_classifiers_and_extractors_handle_the_delegate_form(is_nft):
    """The branch that ships broken is the one you did not build for.

    Every commit classifier and extractor indexed a fixed 75-byte layout. A
    delegate commit is 131 bytes with each offset shifted by 56 — so a mint made
    through this very feature would have read as "not a commit script".
    """
    payload_hash = bytes(range(32))
    delegated = build_commit_locking_script(payload_hash, PKH, is_nft=is_nft, delegate_ref=BASE)
    assert is_commit_script(delegated.hex())
    assert extract_payload_hash_from_commit_script(delegated) == payload_hash
    assert extract_owner_pkh_from_commit_script(delegated) == PKH
    assert extract_delegate_ref_from_commit_script(delegated) == BASE
    if is_nft:
        assert is_commit_nft_script(delegated.hex())


def test_plain_commit_still_reports_no_delegate():
    plain = build_commit_locking_script(bytes(range(32)), PKH, is_nft=True)
    assert extract_delegate_ref_from_commit_script(plain) is None
    assert is_commit_script(plain.hex())


def test_other_token_shapes_are_not_mistaken_for_delegate_commits():
    assert not is_commit_script(build_nft_locking_script(PKH, BASE).hex())
    assert not is_commit_script(build_delegate_token_script(PKH, BASE).hex())


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------


def test_by_is_backable_by_delegate_which_is_the_whole_point():
    """The gap this closes: an AUTHOR claim that no pyrxd write path could back."""
    reveal_outputs = [build_nft_locking_script(PKH, MINTED), build_delegate_burn_script(BASE)]
    authorised = parse_delegate_base_script(build_delegate_base_script(PKH, [CONTAINER, AUTHOR]))

    verdicts = verify_relationship_claims(_metadata(), reveal_outputs, delegated_refs=authorised)

    by_kind = {v.kind: v for v in verdicts}
    assert by_kind[RelationshipKind.AUTHOR].outcome is RelationshipOutcome.BACKED
    assert by_kind[RelationshipKind.AUTHOR].backing is RelationshipBacking.DELEGATED
    assert by_kind[RelationshipKind.CONTAINER].outcome is RelationshipOutcome.BACKED


def test_direct_backing_still_wins_and_is_reported_as_direct():
    """A spend-and-recreate reveal is the stronger statement; don't understate it."""
    reveal_outputs = [build_nft_locking_script(PKH, MINTED), build_nft_locking_script(PKH, CONTAINER)]
    verdicts = {v.kind: v for v in verify_relationship_claims(_metadata(), reveal_outputs)}
    assert verdicts[RelationshipKind.CONTAINER].backing is RelationshipBacking.DIRECT
    # The author was never spent and no delegate was burned.
    assert verdicts[RelationshipKind.AUTHOR].outcome is RelationshipOutcome.UNBACKED


def test_a_delegate_does_not_back_a_ref_its_base_never_authorised():
    """Non-vacuity: the delegated set is a filter, not a blanket approval."""
    reveal_outputs = [build_nft_locking_script(PKH, MINTED), build_delegate_burn_script(BASE)]
    # Base authorises the CONTAINER only. The AUTHOR claim must not ride along.
    authorised = parse_delegate_base_script(build_delegate_base_script(PKH, [CONTAINER]))

    verdicts = {v.kind: v for v in verify_relationship_claims(_metadata(), reveal_outputs, delegated_refs=authorised)}

    assert verdicts[RelationshipKind.CONTAINER].outcome is RelationshipOutcome.BACKED
    assert verdicts[RelationshipKind.AUTHOR].outcome is RelationshipOutcome.UNBACKED
    assert verdicts[RelationshipKind.AUTHOR].backing is RelationshipBacking.NONE


def test_without_the_base_lookup_a_delegated_claim_reads_unbacked():
    """Default is 'no evidence gathered', never 'assume authorised'."""
    reveal_outputs = [build_nft_locking_script(PKH, MINTED), build_delegate_burn_script(BASE)]
    verdicts = verify_relationship_claims(_metadata(), reveal_outputs)
    assert all(v.outcome is RelationshipOutcome.UNBACKED for v in verdicts)


def test_delegate_burn_refs_finds_the_base_ref_to_resolve():
    reveal_outputs = [build_nft_locking_script(PKH, MINTED), build_delegate_burn_script(BASE)]
    assert delegate_burn_refs(reveal_outputs) == {BASE.to_bytes()}
    # A reveal with no burn output offers no delegate evidence at all.
    assert delegate_burn_refs([build_nft_locking_script(PKH, MINTED)]) == set()


def test_declaring_nothing_is_not_a_failure():
    plain = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="no relationships")
    assert verify_relationship_claims(plain, [build_nft_locking_script(PKH, MINTED)]) == []


# ---------------------------------------------------------------------------
# Builder wiring
# ---------------------------------------------------------------------------


def test_reveal_derives_the_burn_output_from_the_commit_script():
    """A caller holding the commit script cannot forget the burn output.

    Omitting it does not mint an unauthorised token — the commit covenant
    requires exactly one — but it does strand the commit value until a correct
    reveal is built, so the failure is worth designing out.
    """
    builder = GlyphBuilder()
    commit = builder.prepare_commit(
        CommitParams(
            metadata=_metadata(),
            owner_pkh=PKH,
            change_pkh=PKH,
            funding_satoshis=1_000_000,
            delegate_ref=BASE,
        )
    )
    assert commit.delegate_ref == BASE

    reveal = builder.prepare_reveal(
        RevealParams(
            commit_txid="11" * 32,
            commit_vout=0,
            commit_value=1000,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=PKH,
            is_nft=True,
            commit_script=commit.commit_script,
        )
    )
    assert reveal.delegate_burn_script is not None
    assert parse_delegate_burn_script(reveal.delegate_burn_script) == BASE.to_bytes()


def test_a_non_delegate_commit_produces_no_burn_output():
    builder = GlyphBuilder()
    commit = builder.prepare_commit(
        CommitParams(metadata=_metadata(), owner_pkh=PKH, change_pkh=PKH, funding_satoshis=1_000_000)
    )
    reveal = builder.prepare_reveal(
        RevealParams(
            commit_txid="11" * 32,
            commit_vout=0,
            commit_value=1000,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=PKH,
            is_nft=True,
            commit_script=commit.commit_script,
        )
    )
    assert reveal.delegate_burn_script is None


def test_a_delegate_ref_contradicting_the_commit_script_raises():
    """The commit script is the covenant that will actually be evaluated."""
    builder = GlyphBuilder()
    commit = builder.prepare_commit(
        CommitParams(
            metadata=_metadata(),
            owner_pkh=PKH,
            change_pkh=PKH,
            funding_satoshis=1_000_000,
            delegate_ref=BASE,
        )
    )
    with pytest.raises(ValidationError, match="does not match"):
        builder.prepare_reveal(
            RevealParams(
                commit_txid="11" * 32,
                commit_vout=0,
                commit_value=1000,
                cbor_bytes=commit.cbor_bytes,
                owner_pkh=PKH,
                is_nft=True,
                commit_script=commit.commit_script,
                delegate_ref=GlyphRef(txid="ff" * 32, vout=9),
            )
        )


def test_the_honest_non_delegate_path_still_works_unchanged():
    """A guard that refuses valid work is a bug: plain mints must be untouched."""
    builder = GlyphBuilder()
    metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="plain mint")
    commit = builder.prepare_commit(
        CommitParams(metadata=metadata, owner_pkh=PKH, change_pkh=PKH, funding_satoshis=1_000_000)
    )
    assert len(commit.commit_script) == 75
    assert commit.delegate_ref is None
    reveal = builder.prepare_reveal(
        RevealParams(
            commit_txid="11" * 32,
            commit_vout=0,
            commit_value=1000,
            cbor_bytes=commit.cbor_bytes,
            owner_pkh=PKH,
            is_nft=True,
        )
    )
    assert reveal.locking_script and reveal.delegate_burn_script is None


# ---------------------------------------------------------------------------
# The setup entry point and the resolver
# ---------------------------------------------------------------------------


def test_delegate_setup_is_two_steps_because_tokens_need_the_bases_outpoint():
    builder = GlyphBuilder()

    step1 = builder.prepare_delegate_setup(PKH, [CONTAINER, AUTHOR])
    assert parse_delegate_base_script(step1.base_script) == (CONTAINER.to_bytes(), AUTHOR.to_bytes())
    assert step1.authorised_refs == (CONTAINER, AUTHOR)
    assert step1.token_scripts == ()  # no base ref yet, so no tokens

    step2 = builder.prepare_delegate_setup(PKH, [CONTAINER, AUTHOR], base_ref=BASE, token_count=3)
    assert len(step2.token_scripts) == 3
    # Every token carries the SAME base ref — they are distinguished by being
    # separate UTXOs, not by their scripts (Photonic createDelegateTokens).
    assert len(set(step2.token_scripts)) == 1
    assert all(is_delegate_token_script(s.hex()) for s in step2.token_scripts)


def test_the_base_transaction_must_re_create_the_parents_or_it_burns_them():
    """OP_REQUIREINPUTREF requires a ref as an INPUT — it does not carry it forward.

    A base transaction whose only output is the base SPENDS the container and
    author singletons and re-creates neither. That burns them permanently: a
    consumed singleton can never be re-minted (spec §7.5.1). Photonic builds
    ``outputs = [base, ...tokens]`` for this reason (mint.ts:634), so the setup
    hands the caller those outputs rather than describing them in prose.
    """
    builder = GlyphBuilder()
    setup = builder.prepare_delegate_setup(PKH, [CONTAINER, AUTHOR])

    assert setup.parent_scripts == (
        build_nft_locking_script(PKH, CONTAINER),
        build_nft_locking_script(PKH, AUTHOR),
    ), "the parent outputs must be byte-identical to the ones being spent, in the same order"
    # Same guarantee the container-child reveal gives: nothing moves or re-owns.
    assert all(is_nft_script(s.hex()) and len(s) == 63 for s in setup.parent_scripts)


def test_a_parent_can_be_re_created_to_a_different_holder():
    """The spender is normally the owner, but the two need not be the same key."""
    builder = GlyphBuilder()
    cold = Hex20(bytes.fromhex("00" * 19 + "ff"))
    setup = builder.prepare_delegate_setup(PKH, [CONTAINER], parent_owner_pkh=cold)
    assert setup.parent_scripts == (build_nft_locking_script(cold, CONTAINER),)


def test_delegate_setup_refuses_the_two_ways_to_build_a_useless_one():
    builder = GlyphBuilder()
    with pytest.raises(ValidationError, match="at least one ref"):
        builder.prepare_delegate_setup(PKH, [])
    with pytest.raises(ValidationError, match="token_count requires base_ref"):
        builder.prepare_delegate_setup(PKH, [CONTAINER], token_count=2)


def test_resolver_uses_the_vout_in_the_ref_not_the_first_output_that_parses():
    """A tx may hold two bases. The burn points at ONE of them.

    Scanning for "the first output that parses as a base" would honour refs the
    burn never pointed at — a real authorisation for the wrong collection.
    """
    from pyrxd.glyph.relationships import resolve_delegated_refs

    other = GlyphRef(txid="ee" * 32, vout=7)
    base_tx_outputs = [
        build_delegate_base_script(PKH, [other]),  # vout 0 — a DIFFERENT base
        build_delegate_base_script(PKH, [CONTAINER, AUTHOR]),  # vout 1 — the one named
    ]
    named = GlyphRef(txid="b2" * 32, vout=1).to_bytes()
    assert resolve_delegated_refs(named, base_tx_outputs) == (CONTAINER.to_bytes(), AUTHOR.to_bytes())
    # And the other one resolves to its own refs, not to a merged set.
    assert resolve_delegated_refs(GlyphRef(txid="b2" * 32, vout=0).to_bytes(), base_tx_outputs) == (other.to_bytes(),)


def test_resolver_returns_nothing_rather_than_raising_on_bad_input():
    from pyrxd.glyph.relationships import resolve_delegated_refs

    outputs = [build_delegate_base_script(PKH, [CONTAINER])]
    assert resolve_delegated_refs(GlyphRef(txid="b2" * 32, vout=9).to_bytes(), outputs) == ()  # out of range
    assert resolve_delegated_refs(b"\x00" * 10, outputs) == ()  # not a wire ref
    assert resolve_delegated_refs(GlyphRef(txid="b2" * 32, vout=0).to_bytes(), [b"\x51"]) == ()  # not a base


# ---------------------------------------------------------------------------
# What reaches a human
# ---------------------------------------------------------------------------


def test_the_inspector_names_both_delegate_shapes():
    """Otherwise a holder inspecting their wallet sees an unrecognised output."""
    from pyrxd.glyph._inspect_core import _inspect_script

    token = _inspect_script(build_delegate_token_script(PKH, BASE).hex())
    assert token["type"] == "delegate-token"
    assert token["owner_pkh"] == bytes(PKH).hex()
    assert token["delegate_base_ref"] == f"{BASE.txid}:{BASE.vout}"

    burn = _inspect_script(build_delegate_burn_script(BASE).hex())
    assert burn["type"] == "delegate-burn"
    assert burn["spendable"] is False


def test_the_inspector_still_calls_an_nft_an_nft():
    """The two shapes are the same 63 bytes; the classifier must not confuse them."""
    from pyrxd.glyph._inspect_core import _inspect_script

    assert _inspect_script(build_nft_locking_script(PKH, BASE).hex())["type"] == "nft"


def test_a_delegate_commit_is_still_classified_as_a_commit_by_the_inspector():
    """131 bytes, every field shifted by 56 — the branch that reads as 'unknown'."""
    from pyrxd.glyph._inspect_core import _inspect_script

    payload_hash = bytes(range(32))
    row = _inspect_script(build_commit_locking_script(payload_hash, PKH, is_nft=True, delegate_ref=BASE).hex())
    assert row["type"] == "commit-nft"
    assert row["payload_hash"] == payload_hash.hex()


# ---------------------------------------------------------------------------
# The sentence a human reads
# ---------------------------------------------------------------------------
#
# Prose is a CLAIM and no test evaluates claims unless one is written to. Every
# string below was WRONG for a delegated token before this change: the tool said
# either "spent in this tx" (it was not) or "nothing authorised it" (something
# did). Both are the confident kind of wrong.


def _render(relationships, burns=()):
    from pyrxd.cli.glyph_inspect import _render_txid_human

    return _render_txid_human(
        {
            "txid": "11" * 32,
            "byte_length": 250,
            "input_count": 2,
            "output_count": 2,
            "outputs": [],
            # Keys the renderer requires, spelled the way `_classify_raw_tx`
            # emits them — a fixture the production path would never produce
            # tests nothing about the production path.
            "metadata": {
                "input_index": 0,
                "protocol": [2],
                "relationships": relationships,
                "delegate_burns": list(burns),
            },
        }
    )


def test_a_directly_backed_claim_says_spent_in_this_tx():
    out = _render([{"kind": "container", "ref": "c0:0", "outcome": "backed", "backing": "direct"}])
    assert "[VERIFIED — spent in this tx]" in out


def test_a_delegated_claim_does_not_claim_it_was_spent_here():
    """It was not. The parent was spent when the BASE was created."""
    out = _render(
        [{"kind": "author", "ref": "a1:1", "outcome": "backed", "backing": "delegated"}],
        burns=["b2:2"],
    )
    assert "spent in this tx" not in out
    assert "VERIFIED via delegate b2:2" in out
    assert "not spent here" in out


def test_an_unresolved_claim_is_not_called_forged():
    """A burn we could not resolve is 'we did not look', not 'nobody authorised it'."""
    out = _render(
        [{"kind": "container", "ref": "c0:0", "outcome": "unbacked", "backing": "none"}],
        burns=["b2:2"],
    )
    assert "nothing authorised it" not in out
    assert "UNRESOLVED" in out and "b2:2" in out


def test_a_claim_with_no_delegate_at_all_is_still_called_out():
    """The honest-path check: the original warning must survive."""
    out = _render([{"kind": "container", "ref": "c0:0", "outcome": "unbacked", "backing": "none"}])
    assert "[CLAIMED ONLY — nothing authorised it]" in out

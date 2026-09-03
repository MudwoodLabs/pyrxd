"""A container/creator claim must be checked, not repeated.

`in` and `by` are operator-supplied CBOR: anyone can write any collection's ref
into their own token. pyrxd decoded them and handed them on, so a marketplace or
wallet reading `metadata.container_refs` would render "part of collection X" —
an unverified assertion, presented as a fact.

WHY THE CHECK IS LOCAL. Radiant's induction rules
(`ReferenceParser::validateTransactionReferenceOperations`, called from
`validation.cpp:742`) enforce a SUBSET RULE: every ref in an output must be backed
by an input ref, where the input set includes the spent outpoints themselves.

THAT RULE COVERS THREE OF THE FIVE operand-carrying opcodes, not all five, and this
docstring originally said "every ref" and claimed the claim was verified against
upstream — while `validation.h`, the file the rule lives in, was not among the
vendored sources and could not have been checked. `OP_DISALLOWPUSHINPUTREF` reaches
no out-parameter at all and `OP_DISALLOWPUSHINPUTREFSIBLING` is compared only
against other OUTPUTS, so either can name any ref without holding it. It is now
vendored, and `tests/test_ref_backing_matches_consensus.py` derives the covered set
from it. So a claimed parent appearing among a transaction's output refs under one
of the three PROVES the transaction spent it — no parent fetch required.

Reasoning from the opcode handler alone gives the opposite answer:
`interpreter.cpp:1957` says outright that it performs NO membership check.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.relationships import (
    RelationshipKind,
    RelationshipOutcome,
    output_ref_operands,
    verify_relationship_claims,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef

_PARENT = GlyphRef(txid="ab" * 32, vout=7)
_OTHER = GlyphRef(txid="cd" * 32, vout=1)
_P2PKH = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"


def _singleton_carrying(ref: GlyphRef) -> bytes:
    """An output whose script carries `ref` via OP_PUSHINPUTREFSINGLETON (0xd8)."""
    return b"\xd8" + ref.to_bytes() + b"\x75" + _P2PKH


def _meta(**kw) -> GlyphMetadata:
    return GlyphMetadata(protocol=(GlyphProtocol.NFT.value,), **kw)


class TestAClaimBackedByTheTransaction:
    def test_a_container_ref_carried_in_an_output_is_verified(self) -> None:
        v = verify_relationship_claims(_meta(container_refs=(_PARENT,)), [_singleton_carrying(_PARENT), _P2PKH])
        assert [x.outcome for x in v] == [RelationshipOutcome.BACKED]
        assert v[0].kind is RelationshipKind.CONTAINER

    def test_an_author_ref_is_verified_the_same_way(self) -> None:
        v = verify_relationship_claims(_meta(author_refs=(_PARENT,)), [_singleton_carrying(_PARENT)])
        assert v[0].kind is RelationshipKind.AUTHOR and v[0].backed

    def test_both_kinds_are_reported_separately(self) -> None:
        v = verify_relationship_claims(
            _meta(container_refs=(_PARENT,), author_refs=(_OTHER,)),
            [_singleton_carrying(_PARENT), _singleton_carrying(_OTHER)],
        )
        assert {x.kind for x in v} == {RelationshipKind.CONTAINER, RelationshipKind.AUTHOR}
        assert all(x.backed for x in v)


class TestAnUnbackedClaim:
    def test_naming_a_collection_the_tx_never_touched_is_UNBACKED(self) -> None:
        """The whole point. Writing someone else's collection ref into your own
        token must not read as membership."""
        v = verify_relationship_claims(_meta(container_refs=(_PARENT,)), [_P2PKH])
        assert v[0].outcome is RelationshipOutcome.UNBACKED

    def test_carrying_a_DIFFERENT_ref_does_not_back_the_claim(self) -> None:
        """A transaction that legitimately carries some other token's ref must not
        launder an unrelated claim."""
        v = verify_relationship_claims(_meta(container_refs=(_PARENT,)), [_singleton_carrying(_OTHER)])
        assert v[0].outcome is RelationshipOutcome.UNBACKED

    def test_one_backed_and_one_not_are_reported_independently(self) -> None:
        v = verify_relationship_claims(_meta(container_refs=(_PARENT, _OTHER)), [_singleton_carrying(_PARENT)])
        assert [x.outcome for x in v] == [RelationshipOutcome.BACKED, RelationshipOutcome.UNBACKED]


class TestNoClaimIsNotAFailure:
    @pytest.mark.parametrize("meta", [_meta(), None])
    def test_a_glyph_declaring_nothing_yields_no_verdicts(self, meta) -> None:
        """Most glyphs claim nothing — measured, zero relationship claims in 600
        sampled mainnet glyphs. An empty list must never render as a failure."""
        assert verify_relationship_claims(meta, [_singleton_carrying(_PARENT)]) == []


class TestTheRefWalkIsOpcodeAware:
    def test_a_ref_pattern_inside_PUSH_DATA_does_not_count(self) -> None:
        """The 36 bytes of a ref sitting inside push data are data, not an operand.
        A naive `in` scan over the raw script would call this backed and let anyone
        forge membership by embedding the bytes."""
        payload = b"\xd8" + _PARENT.to_bytes()
        script = b"\x6a" + bytes([len(payload)]) + payload  # OP_RETURN <push of those bytes>
        assert _PARENT.to_bytes() in script, "the bytes ARE present, which is the trap"
        assert output_ref_operands([script]) == set(), "but not as a ref operand"

    def test_an_unwalkable_output_does_not_fail_the_whole_check(self) -> None:
        """A transaction may carry other protocols' outputs. One unparseable script
        must not make an honest claim read as unbacked."""
        truncated = b"\xd8" + b"\x00" * 10  # ref opcode with a short operand
        v = verify_relationship_claims(_meta(container_refs=(_PARENT,)), [truncated, _singleton_carrying(_PARENT)])
        assert v[0].backed

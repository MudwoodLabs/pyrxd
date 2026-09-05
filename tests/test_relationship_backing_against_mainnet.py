"""The DIRECT backing path, checked against real mainnet bytes.

Every other relationship test in this repo builds its outputs with pyrxd's own
script builders. That proves the verifier agrees with the builder, which is a
weaker statement than it looks: if both shared a wrong assumption about what the
chain carries, the pair would still be self-consistent and green.

The fixtures here are the GLYPH Protocol deploy — the reference mainnet token,
reveal ``b965b32dba8628c339bc39a3369d0c46d645a77828aeb941904c77323bb99dd6`` at
height 228,604, 36 inputs and 35 outputs:

* ``glyph_reveal_cbor.bin`` — its envelope, already in this repo and already
  used as the CBOR golden. Its ``by`` refs are CBOR **tag-64 wrapped**, a
  producer shape pyrxd does not itself emit.
* ``glyph_reveal_output_scripts.json`` — the 35 output scripts of that same
  transaction, read off the chain 2026-09-05.

Between them they exercise the read path end to end on bytes nobody in this
repo wrote: decode a third-party envelope, walk third-party output scripts, and
reach a verdict.
"""

from __future__ import annotations

import json
from pathlib import Path

import cbor2

from pyrxd.glyph.payload import decode_payload
from pyrxd.glyph.relationships import (
    RelationshipBacking,
    RelationshipKind,
    RelationshipOutcome,
    delegate_burn_refs,
    output_ref_operands,
    verify_relationship_claims,
)

_FIXTURES = Path(__file__).parent / "fixtures"
#: The author ref the GLYPH token claims in `by`.
_AUTHOR_REF = "874c3cce53856be763f525b67e833053f6a44b21cf84d6a1e34805298cced56a"


def _envelope():
    return decode_payload((_FIXTURES / "glyph_reveal_cbor.bin").read_bytes())


def _output_scripts() -> list[bytes]:
    return [bytes.fromhex(h) for h in json.loads((_FIXTURES / "glyph_reveal_output_scripts.json").read_text())]


def test_the_fixtures_are_the_transaction_we_think_they_are():
    """Non-vacuity. A fixture that decoded to nothing would pass every test below."""
    raw = (_FIXTURES / "glyph_reveal_cbor.bin").read_bytes()
    assert list(cbor2.loads(raw)) == ["p", "ticker", "name", "desc", "by", "main"]
    scripts = _output_scripts()
    assert len(scripts) == 35, "the GLYPH deploy reveal has 35 outputs"
    assert sum(len(s) for s in scripts) == 7863


def test_a_third_party_by_claim_decodes_from_tag_64_wrapped_refs():
    """pyrxd emits untagged byte strings; this producer wrapped them in tag 64.

    Read back wrong, the ref would not match anything in the outputs and an
    honest token would report UNBACKED.
    """
    metadata = _envelope()
    assert metadata.name == "Glyph Protocol" and metadata.ticker == "GLYPH"
    assert [r.txid for r in metadata.author_refs] == [_AUTHOR_REF]
    assert metadata.container_refs == ()


def test_the_mainnet_author_claim_verifies_as_BACKED_DIRECT():
    """The verdict, from a third-party envelope against third-party scripts."""
    verdicts = verify_relationship_claims(_envelope(), _output_scripts())

    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert verdict.kind is RelationshipKind.AUTHOR
    assert verdict.ref.txid == _AUTHOR_REF
    assert verdict.outcome is RelationshipOutcome.BACKED
    assert verdict.backing is RelationshipBacking.DIRECT


def test_this_transaction_used_no_delegate():
    """So the verdict above rests on the direct path, not on a delegate.

    Pinning it makes the test above unambiguous: if a future change made
    everything read DELEGATED, this would fail rather than the assertion above
    quietly passing for the wrong reason.
    """
    assert delegate_burn_refs(_output_scripts()) == set()


def test_the_author_ref_really_is_among_the_subset_checked_operands():
    """The mechanism, not just the verdict.

    `output_ref_operands` collects only the three opcodes consensus subset-checks.
    The claim being in that set is what makes it authorised rather than asserted.
    """
    from pyrxd.glyph.types import GlyphRef

    wire = GlyphRef(txid=_AUTHOR_REF, vout=0).to_bytes()
    assert wire in output_ref_operands(_output_scripts())


def test_removing_the_backing_output_flips_the_verdict():
    """Make it fail: with the one output that carries the ref gone, it is a claim."""
    from pyrxd.glyph.types import GlyphRef

    wire = GlyphRef(txid=_AUTHOR_REF, vout=0).to_bytes()
    kept = [s for s in _output_scripts() if wire not in s]
    assert len(kept) == 34, "exactly one output should carry the author ref"

    verdicts = verify_relationship_claims(_envelope(), kept)
    assert verdicts[0].outcome is RelationshipOutcome.UNBACKED
    assert verdicts[0].backing is RelationshipBacking.NONE

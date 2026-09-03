"""Verify a glyph's CONTAINER and CREATOR claims instead of repeating them.

A glyph declares its collection and creator in CBOR — ``in`` (containers) and
``by`` (authors). Those are **operator-supplied assertions**: anyone can write any
collection's ref into their own token. Reading them out and displaying them, which
is all pyrxd did, presents an unverified claim as a fact.

The authorization is observable, and — importantly — observable from the reveal
transaction ALONE, with no extra fetching.

Radiant's consensus "induction rules"
(``ReferenceParser::validateTransactionReferenceOperations``, called from
``validation.cpp:742`` and ``:2044``) enforce a SUBSET RULE: every ref appearing in
an output must be backed by some input ref, where the input ref set is the refs
carried by the spent inputs' scripts PLUS the spent outpoints themselves. Verified
against upstream Radiant-Core at the commit this repo vendors (v3.1.2,
``45e0aa4``); the normative note there reads "every output ref is backed by some
input ref (subset rule)".

So if a claimed parent ref appears among a transaction's OUTPUT refs, consensus
already guaranteed that transaction spent the parent (or its outpoint). That is
the authorization, and checking it needs only the reveal transaction.

Note the interpreter does NOT do this: ``interpreter.cpp:1957`` says so in as many
words — "there is NO per-input membership check here ... the real enforcement
lives solely in ReferenceParser". A verifier reasoning from the opcode handler
alone would conclude the opposite.

WHAT THIS DOES NOT PROVE. That the parent's owner *approved* the membership in any
social sense, only that the transaction was authorised to carry the parent's ref —
which requires having spent it. Delegated authorization (a delegate token consumed
by the commit and burned by the reveal) is a separate mechanism pyrxd does not
implement at all, so a legitimately delegated claim will read UNBACKED here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from ..security.errors import ValidationError
from .script import iter_input_refs
from .types import GlyphRef

_log = logging.getLogger(__name__)

__all__ = [
    "RelationshipKind",
    "RelationshipOutcome",
    "RelationshipVerdict",
    "output_ref_operands",
    "verify_relationship_claims",
]


class RelationshipKind(Enum):
    CONTAINER = "container"
    AUTHOR = "author"


class RelationshipOutcome(Enum):
    #: The claimed ref appears among the transaction's output refs, so consensus
    #: required the transaction to have spent it. The claim is authorised.
    BACKED = "backed"
    #: The glyph claims a parent that appears nowhere in the transaction's outputs.
    #: Nothing authorised it — display it as a claim, never as a fact.
    UNBACKED = "unbacked"


@dataclass(frozen=True)
class RelationshipVerdict:
    kind: RelationshipKind
    ref: GlyphRef
    outcome: RelationshipOutcome

    @property
    def backed(self) -> bool:
        return self.outcome is RelationshipOutcome.BACKED


def output_ref_operands(output_scripts: list[bytes]) -> set[bytes]:
    """Every 36-byte ref operand carried by these output scripts.

    Uses :func:`iter_input_refs`, which walks the script as an opcode stream the way
    consensus does — so a ref-range byte sitting inside push data is not mistaken for
    an opcode, and the operand-less REFHASH opcodes (``0xd4``-``0xd7``) advance by one
    byte instead of swallowing 36.

    A script that cannot be walked is SKIPPED rather than failing the whole check: a
    transaction may carry outputs from other protocols, and one unparseable output
    must not make an honest claim read as unbacked.
    """
    operands: set[bytes] = set()
    for script in output_scripts:
        try:
            for _op, operand in iter_input_refs(script):
                operands.add(bytes(operand))
        except Exception as exc:
            # Logged, not swallowed: if a claim reads UNBACKED because an output could
            # not be walked, whoever is debugging that needs to know it happened.
            _log.debug("output_ref_operands: skipping unwalkable output script: %s", exc)
            continue
    return operands


def verify_relationship_claims(metadata, output_scripts: list[bytes]) -> list[RelationshipVerdict]:
    """Check each declared container/author ref against what the transaction carries.

    Returns one verdict per CLAIM. An empty list means the glyph declared nothing —
    which is not a failure and must not be rendered as one.
    """
    if metadata is None:
        return []
    backing = output_ref_operands(output_scripts)
    verdicts: list[RelationshipVerdict] = []
    for kind, refs in (
        (RelationshipKind.CONTAINER, getattr(metadata, "container_refs", ()) or ()),
        (RelationshipKind.AUTHOR, getattr(metadata, "author_refs", ()) or ()),
    ):
        for ref in refs:
            try:
                wire = ref.to_bytes()
            except (ValidationError, AttributeError):  # pragma: no cover - malformed ref
                continue
            outcome = RelationshipOutcome.BACKED if wire in backing else RelationshipOutcome.UNBACKED
            verdicts.append(RelationshipVerdict(kind=kind, ref=ref, outcome=outcome))
    return verdicts

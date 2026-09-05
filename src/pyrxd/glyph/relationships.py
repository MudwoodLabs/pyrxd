"""Verify a glyph's CONTAINER and CREATOR claims instead of repeating them.

A glyph declares its collection and creator in CBOR — ``in`` (containers) and
``by`` (authors). Those are **operator-supplied assertions**: anyone can write any
collection's ref into their own token. Reading them out and displaying them, which
is all pyrxd did, presents an unverified claim as a fact.

The authorization is observable. For a claim backed DIRECTLY it is observable
from the reveal transaction alone, with no extra fetching. For a claim backed by
a DELEGATE it is not: the reveal names a delegate base ref, and learning which
parent refs that base authorises means fetching the base transaction. See
:func:`delegate_burn_refs` for that second path and how to feed it back in.

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
which requires having spent it. And it proves that only for refs carried by the
three opcodes consensus subset-checks: ``OP_DISALLOWPUSHINPUTREF`` and
``OP_DISALLOWPUSHINPUTREFSIBLING`` operands are local assertions anyone may write
about any ref, and reading them as backing forges the verdict outright.

DELEGATED AUTHORIZATION. A claim may instead be backed by a delegate: a delegate
token consumed by the commit and burned by the reveal, whose base output named
the parent refs under ``OP_REQUIREINPUTREF``. That is consensus-backed by the
same subset rule, one step removed — the base transaction provably spent the
parents, and the burn provably spent a token carrying the base ref. It is what
lets a minting service authorise claims without custody of the parent
singletons. pyrxd honours it, but only when the caller supplies the resolved
refs: extract the burned base refs with :func:`delegate_burn_refs`, resolve each
to the refs its base authorises with
:func:`~pyrxd.glyph.script.parse_delegate_base_script`, and pass the result as
``delegated_refs``. Omit that step and a legitimately delegated claim reads
UNBACKED, which is why the verdict records HOW it was backed.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from ..constants import INPUT_BACKED_REF_OPCODES
from ..security.errors import ValidationError
from .script import iter_input_refs, parse_delegate_base_script, parse_delegate_burn_script
from .types import GlyphRef

_log = logging.getLogger(__name__)

__all__ = [
    "RelationshipBacking",
    "RelationshipKind",
    "RelationshipOutcome",
    "RelationshipVerdict",
    "delegate_burn_refs",
    "output_ref_operands",
    "resolve_delegated_refs",
    "verify_relationship_claims",
]


class RelationshipKind(Enum):
    CONTAINER = "container"
    AUTHOR = "author"


class RelationshipOutcome(Enum):
    #: The claimed ref appears in an output under an opcode consensus subset-checks
    #: against the inputs, so the transaction provably spent it. The claim is
    #: authorised. A ref named only by ``OP_DISALLOWPUSHINPUTREF``/``...SIBLING`` does
    #: NOT qualify — see :func:`output_ref_operands`.
    BACKED = "backed"
    #: The glyph claims a parent that appears nowhere in the transaction's outputs.
    #: Nothing authorised it — display it as a claim, never as a fact.
    UNBACKED = "unbacked"


class RelationshipBacking(Enum):
    """HOW a BACKED claim was authorised. Meaningless when UNBACKED."""

    #: The reveal's own outputs carry the parent ref under a subset-checked
    #: opcode — the transaction spent the parent itself.
    DIRECT = "direct"
    #: The reveal burned a delegate token whose base authorised the parent ref.
    #: One step removed: the parent was spent when the BASE was created, not by
    #: this transaction. Anyone holding a delegate token could have made this
    #: claim, which is the mechanism working as intended — but it is a weaker
    #: statement than DIRECT and must not be displayed as the same thing.
    DELEGATED = "delegated"
    #: Nothing authorised the claim.
    NONE = "none"


@dataclass(frozen=True)
class RelationshipVerdict:
    kind: RelationshipKind
    ref: GlyphRef
    outcome: RelationshipOutcome
    backing: RelationshipBacking = RelationshipBacking.NONE

    @property
    def backed(self) -> bool:
        return self.outcome is RelationshipOutcome.BACKED


def output_ref_operands(output_scripts: list[bytes]) -> set[bytes]:
    """The ref operands in these outputs that consensus REQUIRED an input to back.

    Not every ref operand qualifies, and the difference is the whole point of this
    function. ``ReferenceParser::validateTransactionReferenceOperations`` subset-checks
    only three of the five operand-carrying opcodes against the transaction's inputs
    (:data:`~pyrxd.constants.INPUT_BACKED_REF_OPCODES`). The other two —
    ``OP_DISALLOWPUSHINPUTREF`` and ``OP_DISALLOWPUSHINPUTREFSIBLING`` — are local
    assertions about this transaction's own outputs; consensus never asks whether an
    input carried them. Anyone can name any ref with them, for the price of one
    output, without ever holding it. Collecting those as backing is a complete
    forgery of the authorisation verdict, so they are walked and discarded.

    Walking still uses :func:`iter_input_refs`, which consumes the operand of ALL five
    the way consensus does — so a ref-range byte sitting inside push data is not
    mistaken for an opcode, and the operand-less REFHASH opcodes (``0xd4``-``0xd7``)
    advance by one byte instead of swallowing 36. Filtering happens after the walk,
    never by narrowing the walk: skipping an opcode's 36 bytes would desynchronise the
    parse and hand back refs that are not there.

    A script that cannot be walked is SKIPPED rather than failing the whole check: a
    transaction may carry outputs from other protocols, and one unparseable output
    must not make an honest claim read as unbacked.
    """
    operands: set[bytes] = set()
    for script in output_scripts:
        try:
            for op, operand in iter_input_refs(script):
                if op not in INPUT_BACKED_REF_OPCODES:
                    continue
                operands.add(bytes(operand))
        except Exception as exc:
            # Logged, not swallowed: if a claim reads UNBACKED because an output could
            # not be walked, whoever is debugging that needs to know it happened.
            _log.debug("output_ref_operands: skipping unwalkable output script: %s", exc)
            continue
    return operands


def delegate_burn_refs(output_scripts: list[bytes]) -> set[bytes]:
    """The delegate BASE refs burned by these outputs.

    Each is the ref of a delegate base output. To turn one into the parent refs
    it authorises, fetch the transaction that created it and run
    :func:`~pyrxd.glyph.script.parse_delegate_base_script` over that
    transaction's outputs. That fetch is why this is a separate function rather
    than folded into :func:`verify_relationship_claims`: the verifier stays
    network-free, and the caller decides whether the extra round trip is worth
    it.

    An empty set means no delegate was burned — so any claim this transaction
    makes has to stand on the DIRECT path or not at all.
    """
    burned: set[bytes] = set()
    for script in output_scripts:
        ref = parse_delegate_burn_script(script)
        if ref is not None:
            burned.add(ref)
    return burned


def resolve_delegated_refs(base_ref: bytes, base_tx_output_scripts: list[bytes]) -> tuple[bytes, ...]:
    """The parent refs a delegate base authorises — step 2 of the delegate lookup.

    *base_ref* is a wire ref from :func:`delegate_burn_refs`. *base_tx_output_scripts*
    are the output scripts of the transaction that CREATED it, which the caller
    fetches by the txid inside that ref.

    This exists so the caller does not have to pick the right output by hand.
    The base ref names an outpoint, so the vout encoded in it — not "the first
    output that parses" — identifies the base. Scanning for any parsable base
    would honour a *different* base output in the same transaction, which is a
    ref the burn never pointed at.

    Returns ``()`` when the named output does not exist or is not a delegate
    base, so a caller feeding this straight into
    :func:`verify_relationship_claims` gets "no evidence" rather than an
    exception or a wrong answer.
    """
    if len(base_ref) != 36:
        return ()
    vout = int.from_bytes(base_ref[32:36], "little")
    if vout >= len(base_tx_output_scripts):
        return ()
    return parse_delegate_base_script(base_tx_output_scripts[vout])


def verify_relationship_claims(
    metadata,
    output_scripts: list[bytes],
    *,
    delegated_refs: Iterable[bytes] = (),
) -> list[RelationshipVerdict]:
    """Check each declared container/author ref against what the transaction carries.

    Returns one verdict per CLAIM. An empty list means the glyph declared nothing —
    which is not a failure and must not be rendered as one.

    :param delegated_refs: wire refs authorised by a delegate base whose token
        this transaction burned — see :func:`delegate_burn_refs` for how to
        obtain them. Defaults to empty, which is the correct answer for a caller
        that has not done the lookup: it means "no delegate evidence", and a
        delegated claim then reads UNBACKED rather than being asserted on
        evidence nobody gathered. Passing refs here is a statement that they
        were resolved from a base transaction, NOT that the caller trusts them.
    """
    if metadata is None:
        return []
    direct = output_ref_operands(output_scripts)
    delegated = {bytes(r) for r in delegated_refs}
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
            # DIRECT wins when both apply: it is the stronger statement, and
            # reporting the weaker one for a claim that stands on its own would
            # understate a verdict a UI shows to a user.
            if wire in direct:
                outcome, backing = RelationshipOutcome.BACKED, RelationshipBacking.DIRECT
            elif wire in delegated:
                outcome, backing = RelationshipOutcome.BACKED, RelationshipBacking.DELEGATED
            else:
                outcome, backing = RelationshipOutcome.UNBACKED, RelationshipBacking.NONE
            verdicts.append(RelationshipVerdict(kind=kind, ref=ref, outcome=outcome, backing=backing))
    return verdicts

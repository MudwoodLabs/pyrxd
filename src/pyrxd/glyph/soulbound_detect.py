"""Detect whether a Glyph UTXO scriptPubKey is *genuinely* soulbound on-chain.

The hard lesson from inspecting real Radiant tokens: "soulbound" can mean two
completely different things, and the explorer's ``NFT`` badge does not tell them
apart:

* **Metadata-only** — an ordinary transferable NFT singleton
  (``OP_PUSHINPUTREFSINGLETON <ref> OP_DROP <P2PKH>``) whose "soulbound" status is
  just a ``policy.transferable:false`` flag in the off-chain payload. Consensus
  imposes NO transfer restriction; any wallet running its own code can move it.
* **Covenant-enforced** — the singleton is locked into a self-replicating covenant
  that, at consensus, only permits the token to recur into a byte-identical clone
  of itself (same ref + logic + owner) OR be burned. A live example is deployed on
  mainnet ("TheArtofSatoshi", UTXO ``4b25…:0``).

A swap / credential gate that trusts a "soulbound credential" MUST distinguish
these — trusting a metadata-only token is trusting nothing. This module is the
detector: give it the UTXO's scriptPubKey, it tells you which kind it is.

It classifies by *semantic markers*, not a byte-match of one template, so it
recognises both known covenant shapes (and reasonable variants):

* the deployed shape — ``OP_CODESCRIPTBYTECODE_OUTPUT … OP_CODESCRIPTBYTECODE_UTXO
  OP_EQUAL`` (code-script self-equality), and
* the pyrxd prototype shape — ``OP_OUTPUTBYTECODE … OP_UTXOBYTECODE OP_EQUALVERIFY``
  (full-bytecode self-equality).

The rule: a SPK gets ``SOULBOUND_COVENANT`` when it (1) binds a singleton ref
(``d8``), (2) contains a *self-replication equality* — an output-bytecode opcode
AND an own/input-bytecode opcode joined by ``OP_EQUAL``/``OP_EQUALVERIFY`` — and
optionally (3) has a *burn branch* (``OP_REFOUTPUTCOUNT_OUTPUTS`` compared
against 0). A ``d8 … OP_DROP P2PKH`` with none of these is a plain transferable
NFT.

This is a heuristic over consensus-visible structure; it cannot prove the
covenant is *correct* (that needs the regtest differential test), only that the
locking script imposes a self-replication-or-burn constraint rather than none.

**Those markers are necessary, not sufficient — read this before using the
verdict as a label.** Measured against every locking-script builder in ``src``:
a **dMint V1 contract**, a **dMint V2 contract**, and a **mutable-NFT script**
all return ``SOULBOUND_COVENANT``. They are not soulbound NFTs; they bind a
singleton ref and self-replicate because that is how a Radiant covenant carries
state forward, which is every marker this module looks for. Container and vault
covenants have the same shape. That looseness is correct for the question this
module answers — *"does this lock restrict transfer at all, or is 'soulbound'
just a metadata flag?"* — and wrong for the question *"is this a soulbound
token?"*.

For the second question use
:func:`pyrxd.glyph.soulbound_covenant.parse_soulbound_nft_covenant`, an exact
builder round-trip, and rule out the specific token shapes first.
``pyrxd.glyph._inspect_core`` does both: it runs the dMint and mutable-NFT
parsers before either of these, reports ``soulbound-covenant`` only on the
exact match, and reports a marker-only hit as ``self-replicating-covenant``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pyrxd.glyph.script import TruncatedScriptError, count_input_refs, iter_script_ops_strict

__all__ = [
    "SoulboundClassification",
    "Transferability",
    "classify_soulbound",
]

# Opcodes (kept local to avoid importing the whole OpCode table for four bytes).
_OP_PUSHINPUTREFSINGLETON = 0xD8
_OP_DROP = 0x75
_OP_EQUAL = 0x87
_OP_EQUALVERIFY = 0x88
_OP_REFOUTPUTCOUNT_OUTPUTS = 0xDE
_OP_0 = 0x00
_OP_NUMEQUAL = 0x9C

# "What does this output look like?" introspection opcodes (compared via OP_EQUAL).
_OUTPUT_BYTECODE_OPS = frozenset({0xCD, 0xEA})  # OP_OUTPUTBYTECODE, OP_CODESCRIPTBYTECODE_OUTPUT
# "What do I (this input/utxo) look like?" introspection opcodes.
_SELF_BYTECODE_OPS = frozenset({0xC7, 0xE9, 0xC1})  # OP_UTXOBYTECODE, OP_CODESCRIPTBYTECODE_UTXO, OP_ACTIVEBYTECODE
# "How many outputs replicate my code script?" — the index-independent self-
# replication form (own code hash via _SELF_BYTECODE_OPS + OP_HASH256, then count).
_CODESCRIPTHASH_COUNT_OPS = frozenset({0xE5, 0xE6})  # OP_CODESCRIPTHASHOUTPUTCOUNT_{UTXOS,OUTPUTS}

# The split that decides whether a self-equality covers the OWNER.
# Full-bytecode opcodes compare the entire script; code-script opcodes compare only
# the part after OP_STATESEPARATOR, leaving any state prefix free to change.
_FULL_BYTECODE_OPS = frozenset({0xCD, 0xC7, 0xC1})  # OP_OUTPUTBYTECODE, OP_UTXOBYTECODE, OP_ACTIVEBYTECODE
_CODESCRIPT_BYTECODE_OPS = frozenset({0xEA, 0xE9})  # OP_CODESCRIPTBYTECODE_{OUTPUT,UTXO}
_OP_STATESEPARATOR = 0xBD


class Transferability(Enum):
    """How a Glyph singleton UTXO restricts transfer at the consensus layer."""

    TRANSFERABLE_NFT = "transferable_nft"
    """Plain singleton NFT — no on-chain transfer restriction (may still carry a
    metadata ``transferable:false`` flag, which is advisory only)."""

    SOULBOUND_COVENANT = "soulbound_covenant"
    """Self-replication-or-burn covenant pinning the WHOLE script, owner included —
    the only spends are a clone with the same owner, or a burn."""

    MUTABLE_STATE_COVENANT = "mutable_state_covenant"
    """Self-replication of the CODE script only, with a mutable state prefix — so
    the covenant survives a spend that changes the owner. That is a TRANSFER, and
    this is therefore NOT soulbound.

    ``OP_CODESCRIPTBYTECODE_*`` compares only the bytes after ``OP_STATESEPARATOR``.
    With no separator the code script IS the whole script, so the same opcodes DO
    pin the owner — which is why the deployed mainnet token and both pyrxd builders
    remain ``SOULBOUND_COVENANT``. It is only the combination of code-script-only
    equality WITH a state prefix that leaves the owner free."""

    NOT_A_SINGLETON = "not_a_singleton"
    """No ``OP_PUSHINPUTREFSINGLETON`` — not a singleton NFT at all."""

    UNKNOWN = "unknown"
    """A singleton with introspection opcodes we can't classify (or malformed)."""


@dataclass(frozen=True)
class SoulboundClassification:
    """Result of :func:`classify_soulbound`."""

    transferability: Transferability
    bound_ref: bytes | None
    """The 36-byte singleton ref the script binds, if any."""
    has_self_replication: bool
    """A self-clone equality (output-bytecode == own-bytecode) is present."""
    has_burn_branch: bool
    """An ``OP_REFOUTPUTCOUNT_OUTPUTS … 0 … OP_NUMEQUAL`` burn check is present."""

    @property
    def is_consensus_soulbound(self) -> bool:
        return self.transferability is Transferability.SOULBOUND_COVENANT


def _opcodes(script: bytes) -> list[int]:
    """Return the script's opcodes (at opcode positions only), skipping the
    operands of pushes and 36-byte ref opcodes.

    A thin projection of the shared walk
    (:func:`pyrxd.glyph.script.iter_script_ops_strict`, which is itself
    Radiant's ``GetScriptOp`` via :mod:`pyrxd.script.consensus`). This module
    used to carry its own transcription of that loop — a fifth copy of the
    rules that decide how many bytes an opcode consumes, and exactly the drift
    that produced this repo's ref-walker bugs. The shared walk raises
    :class:`~pyrxd.glyph.script.TruncatedScriptError` where the old local copy
    silently ``break``-ed; :func:`classify_soulbound` already returned
    ``UNKNOWN`` for those scripts via its ``count_input_refs`` pre-check, so
    the visible behaviour is unchanged and now fails closed in both paths.
    """
    return [op.opcode for op in iter_script_ops_strict(script)]


def classify_soulbound(script: bytes) -> SoulboundClassification:
    """Classify a Glyph singleton UTXO scriptPubKey's consensus transferability.

    Returns a :class:`SoulboundClassification`; check ``.is_consensus_soulbound``
    to decide whether the lock genuinely forbids transfer (vs a metadata flag).

    ``SOULBOUND_COVENANT`` means *this lock imposes a self-replication-or-burn
    constraint*, NOT *this is a soulbound NFT*. dMint contracts and mutable-NFT
    scripts return it too — see the module docstring for why, and for what to
    use instead when a wrong yes is expensive.
    """
    # Both calls consume the same shared walk, so either both succeed or the
    # first one raises; keeping them under one guard makes that explicit
    # rather than relying on the coupling.
    try:
        ref_counts = count_input_refs(script)
        ops = _opcodes(script)
    except TruncatedScriptError:
        return SoulboundClassification(Transferability.UNKNOWN, None, False, False)

    op_set = set(ops)

    is_singleton = _OP_PUSHINPUTREFSINGLETON in op_set
    bound_ref = None
    if is_singleton:
        # The singleton ref is the one pushed by a d8 opcode; in practice these
        # covenants bind exactly one. Pick it deterministically.
        singleton_refs = [r for r in ref_counts]
        if len(singleton_refs) == 1:
            bound_ref = singleton_refs[0]

    if not is_singleton:
        return SoulboundClassification(Transferability.NOT_A_SINGLETON, bound_ref, False, False)

    # (2) self-replication constraint — the output(s) must replicate THIS script.
    # Two known forms:
    #   (a) direct equality: output-bytecode == own-bytecode (OP_EQUAL/OP_EQUALVERIFY)
    #       e.g. OP_0 OP_OUTPUTBYTECODE … OP_INPUTINDEX OP_UTXOBYTECODE OP_EQUAL.
    #   (b) index-independent count: count outputs whose code-script-hash == mine
    #       (own hash via own-bytecode + OP_HASH256, then OP_CODESCRIPTHASHOUTPUTCOUNT_*).
    has_self_bc = bool(op_set & _SELF_BYTECODE_OPS)
    has_equality = _OP_EQUAL in op_set or _OP_EQUALVERIFY in op_set
    form_a = bool(op_set & _OUTPUT_BYTECODE_OPS) and has_self_bc and has_equality
    form_b = has_self_bc and bool(op_set & _CODESCRIPTHASH_COUNT_OPS)
    has_self_replication = form_a or form_b

    # (3) burn branch: OP_REFOUTPUTCOUNT_OUTPUTS compared against zero.
    has_burn_branch = _OP_REFOUTPUTCOUNT_OUTPUTS in op_set and _OP_NUMEQUAL in op_set

    if has_self_replication:
        # A self-clone-or-burn lock. The burn branch is expected but not required
        # for the *transfer is restricted* conclusion (the self-equality alone
        # forbids moving to a different script).
        #
        # ...BUT ONLY IF THE EQUALITY COVERS THE OWNER. `OP_CODESCRIPTBYTECODE_*`
        # compares the bytes AFTER `OP_STATESEPARATOR`, so a script that carries a
        # mutable state prefix and pins only its code script can recur with a
        # different owner in that prefix — a transfer, under a lock this function
        # used to call "transfer is impossible at consensus".
        #
        # This module knew it and did not act on it: `soulbound_covenant.py` says
        # outright that "code-script-only equality would let the state (owner)
        # change between hops — i.e. a transfer — so it is the wrong primitive for
        # soulbinding", which is why the pyrxd builders emit NO state separator.
        #
        # The distinction is exactly the pair, never either half alone. With no
        # separator the code script IS the whole script, so code-script equality
        # pins everything — the deployed mainnet token uses those very opcodes and
        # must keep its classification. Verified against all three real shapes.
        codescript_only = not (op_set & _FULL_BYTECODE_OPS) and bool(op_set & _CODESCRIPT_BYTECODE_OPS)
        if codescript_only and _OP_STATESEPARATOR in op_set:
            transferability = Transferability.MUTABLE_STATE_COVENANT
        else:
            transferability = Transferability.SOULBOUND_COVENANT
    else:
        # A singleton whose only other structure is OP_DROP + P2PKH (or anything
        # without a self-replication constraint) is freely transferable.
        # If it has stray introspection opcodes we can't reason about, say UNKNOWN.
        introspection = op_set & (_OUTPUT_BYTECODE_OPS | _SELF_BYTECODE_OPS | _CODESCRIPTHASH_COUNT_OPS)
        transferability = Transferability.UNKNOWN if introspection else Transferability.TRANSFERABLE_NFT

    return SoulboundClassification(
        transferability=transferability,
        bound_ref=bound_ref,
        has_self_replication=has_self_replication,
        has_burn_branch=has_burn_branch,
    )

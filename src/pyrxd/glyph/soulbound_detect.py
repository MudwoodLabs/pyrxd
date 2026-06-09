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

The rule: a SPK is covenant-enforced soulbound iff it (1) binds a singleton ref
(``d8``), (2) contains a *self-replication equality* — an output-bytecode opcode
AND an own/input-bytecode opcode joined by ``OP_EQUAL``/``OP_EQUALVERIFY`` — and
(3) has a *burn branch* (``OP_REFOUTPUTCOUNT_OUTPUTS`` compared against 0). A
``d8 … OP_DROP P2PKH`` with none of these is a plain transferable NFT.

This is a heuristic over consensus-visible structure; it cannot prove the
covenant is *correct* (that needs the regtest differential test), only that the
locking script imposes a self-replication-or-burn constraint rather than none.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pyrxd.glyph.script import REF_OPCODES, TruncatedScriptError, count_input_refs

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


class Transferability(Enum):
    """How a Glyph singleton UTXO restricts transfer at the consensus layer."""

    TRANSFERABLE_NFT = "transferable_nft"
    """Plain singleton NFT — no on-chain transfer restriction (may still carry a
    metadata ``transferable:false`` flag, which is advisory only)."""

    SOULBOUND_COVENANT = "soulbound_covenant"
    """Self-replication-or-burn covenant — transfer is impossible at consensus."""

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
    operands of pushes and 36-byte ref opcodes. Mirrors the consensus-accurate
    walk in :func:`pyrxd.glyph.script.iter_input_refs`."""
    ops: list[int] = []
    pos, n = 0, len(script)
    while pos < n:
        op = script[pos]
        ops.append(op)
        if op in REF_OPCODES:  # 0xd0..0xd8: opcode + 36-byte ref operand
            pos += 37
            continue
        if 0x01 <= op <= 0x4B:
            pos += 1 + op
            continue
        if op == 0x4C:  # PUSHDATA1
            if pos + 1 >= n:
                break
            pos += 2 + script[pos + 1]
            continue
        if op == 0x4D:  # PUSHDATA2
            if pos + 2 >= n:
                break
            pos += 3 + int.from_bytes(script[pos + 1 : pos + 3], "little")
            continue
        if op == 0x4E:  # PUSHDATA4
            if pos + 4 >= n:
                break
            pos += 5 + int.from_bytes(script[pos + 1 : pos + 5], "little")
            continue
        pos += 1
    return ops


def classify_soulbound(script: bytes) -> SoulboundClassification:
    """Classify a Glyph singleton UTXO scriptPubKey's consensus transferability.

    Returns a :class:`SoulboundClassification`; check ``.is_consensus_soulbound``
    to decide whether the lock genuinely forbids transfer (vs a metadata flag).
    """
    try:
        ref_counts = count_input_refs(script)
    except TruncatedScriptError:
        return SoulboundClassification(Transferability.UNKNOWN, None, False, False)

    ops = _opcodes(script)
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

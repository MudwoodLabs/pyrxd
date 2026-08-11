"""A faithful Python mirror of Radiant's script walker and validity check.

Two functions, both transcribed from vendored Radiant Core v3.1.2:

* :func:`get_script_op` — ``GetScriptOp`` (``src/script/script.cpp:662-731``),
  the single routine every consensus-side script walk goes through. It is the
  authority on the one structural question a walker can get wrong: *how many
  bytes does this opcode consume?*
* :func:`has_valid_ops` — ``CScript::HasValidOps``
  (``src/script/script.cpp:733-744``), which is nine lines long and is what
  decides whether a script is structurally acceptable at all.

Why this module exists
----------------------
``pyrxd.constants`` pinned ``MAX_OPCODE``, ``MAX_SCRIPT_ELEMENT_SIZE`` and
``REF_OPERAND_WIDTH`` from that source, and then nothing in the SDK read them:
six ref walkers hand-spelled ``36``/``37`` and no code path enforced
``HasValidOps`` at all. A pinned constant with no consumer pins nothing — it
reads like coverage while providing none. These functions are the consumers.

They are a *structural* check, not an evaluator. pyrxd does not execute scripts,
so ``MAX_OPS_PER_SCRIPT`` and ``MAX_STACK_SIZE`` are pinned in
:mod:`pyrxd.constants` with no consumer, and say so.

Faithfulness matters more than ergonomics here, so ``get_script_op`` keeps
Radiant's exact push-size dispatch — including that ``OP_PUSHDATA4`` reads a
32-bit length that a truncated script cannot satisfy — rather than a tidier
equivalent. ``tests/test_consensus_opcode_parity.py`` checks the constants it
reads against the vendored C++; ``tests/test_script_consensus.py`` checks the
behaviour.
"""

from __future__ import annotations

from ..constants import MAX_OPCODE, MAX_SCRIPT_ELEMENT_SIZE, MAX_SCRIPT_SIZE, REF_OPERAND_OPCODES, REF_OPERAND_WIDTH

__all__ = ["ScriptOp", "get_script_op", "has_valid_ops", "is_valid_script_size", "iter_script_ops"]

# Push opcodes, from Radiant's ``enum opcodetype``. Named here rather than
# imported from the ``OpCode`` enum because that enum stores ``bytes`` and every
# comparison in this module is against an ``int`` read out of a script.
_OP_PUSHDATA1 = 0x4C
_OP_PUSHDATA2 = 0x4D
_OP_PUSHDATA4 = 0x4E

#: How many bytes of length prefix each PUSHDATA form carries.
_PUSHDATA_LENGTH_WIDTH = {_OP_PUSHDATA1: 1, _OP_PUSHDATA2: 2, _OP_PUSHDATA4: 4}


class ScriptOp(tuple):
    """One decoded instruction: ``(opcode, operand, next_pos)``.

    A tuple subclass so it destructures like the C++ out-params it mirrors while
    still having readable attribute names at call sites that want them.
    """

    __slots__ = ()

    def __new__(cls, opcode: int, operand: bytes, next_pos: int) -> ScriptOp:
        return super().__new__(cls, (opcode, operand, next_pos))

    @property
    def opcode(self) -> int:
        return self[0]

    @property
    def operand(self) -> bytes:
        """The pushed data, or the 36-byte ref for a ref opcode. ``b""`` otherwise."""
        return self[1]

    @property
    def next_pos(self) -> int:
        return self[2]


def get_script_op(script: bytes, pos: int) -> ScriptOp | None:
    """Decode the instruction at ``script[pos]``, or ``None`` if it is malformed.

    Mirrors ``GetScriptOp``. ``None`` corresponds to its ``return false``, which
    covers a read past the end, a truncated length prefix, a push whose data
    runs off the end, and a ref opcode with fewer than
    :data:`~pyrxd.constants.REF_OPERAND_WIDTH` bytes behind it.

    Returning ``None`` rather than raising is deliberate: this is the primitive
    the tolerant walkers are built on, and a walker that must not raise should
    not have to wrap every step in a ``try``.
    """
    end = len(script)
    if pos < 0 or pos >= end:
        return None

    opcode = script[pos]
    pos += 1

    if opcode <= _OP_PUSHDATA4:
        if opcode < _OP_PUSHDATA1:
            size = opcode
        else:
            width = _PUSHDATA_LENGTH_WIDTH[opcode]
            if end - pos < width:
                return None
            size = int.from_bytes(script[pos : pos + width], "little")
            pos += width
        if end - pos < size:
            return None
        return ScriptOp(opcode, script[pos : pos + size], pos + size)

    if opcode in REF_OPERAND_OPCODES:
        # The five ref opcodes are followed by a fixed-width immediate operand
        # with no length prefix. A walker that does not consume it starts reading
        # ref bytes as opcodes — the desync behind three fund-affecting bugs.
        if end - pos < REF_OPERAND_WIDTH:
            return None
        return ScriptOp(opcode, script[pos : pos + REF_OPERAND_WIDTH], pos + REF_OPERAND_WIDTH)

    return ScriptOp(opcode, b"", pos)


def iter_script_ops(script: bytes):
    """Yield every :class:`ScriptOp` in ``script``, stopping at the first malformed one.

    Stopping silently matches ``GetScriptOp``'s contract — the caller decides
    whether a short walk is an error. :func:`has_valid_ops` is the caller that
    treats it as one.
    """
    pos = 0
    while pos < len(script):
        op = get_script_op(script, pos)
        if op is None:
            return
        yield op
        pos = op.next_pos


def has_valid_ops(script: bytes) -> bool:
    """``CScript::HasValidOps`` — is ``script`` structurally acceptable to Radiant?

    Three ways to fail, exactly as the C++ has them:

    * an instruction that will not decode (``GetScriptOp`` returned false);
    * an opcode byte above :data:`~pyrxd.constants.MAX_OPCODE`;
    * a push larger than :data:`~pyrxd.constants.MAX_SCRIPT_ELEMENT_SIZE`.

    The size cap is included even though a 32,000,000-byte push is not something
    a caller reaches by accident — the point is that it is Radiant's number,
    recovered from Radiant's source, and not Bitcoin's 520. Enforcing 520 here
    would reject scripts the chain accepts.

    Note this does NOT check the script's total length; that is
    :func:`is_valid_script_size`, which the C++ enforces elsewhere.
    """
    pos = 0
    end = len(script)
    while pos < end:
        op = get_script_op(script, pos)
        if op is None or op.opcode > MAX_OPCODE or len(op.operand) > MAX_SCRIPT_ELEMENT_SIZE:
            return False
        pos = op.next_pos
    return True


def is_valid_script_size(script: bytes) -> bool:
    """Is ``script`` within :data:`~pyrxd.constants.MAX_SCRIPT_SIZE`?

    Separate from :func:`has_valid_ops` because Radiant enforces the two in
    different places, and conflating them would make a caller that wants only
    the structural check pay for a rule it did not ask about.
    """
    return len(script) <= MAX_SCRIPT_SIZE

from __future__ import annotations

from ..constants import OPCODE_VALUE_NAME_DICT, REF_OPERAND_OPCODES, REF_OPERAND_WIDTH, OpCode
from ..utils import Reader, encode_pushdata, unsigned_to_varint

#: Size operand width, in bytes, for each of the three OP_PUSHDATA opcodes.
#: ``GetScriptOp`` reads exactly this many bytes and returns false if fewer
#: remain (``script.cpp:685-702``). Keyed off the ``OpCode`` table rather than
#: hex literals, for the same reason the ref-operand set is: an opcode byte
#: written down twice is an opcode byte that can disagree with itself.
_PUSHDATA_SIZE_WIDTH: dict[int, int] = {
    OpCode.OP_PUSHDATA1.value[0]: 1,
    OpCode.OP_PUSHDATA2.value[0]: 2,
    OpCode.OP_PUSHDATA4.value[0]: 4,
}

#: Largest opcode byte that is a direct "push this many bytes" instruction —
#: one below OP_PUSHDATA1, exactly as ``GetScriptOp``'s ``opcode < OP_PUSHDATA1``
#: branch decides it.
_MAX_DIRECT_PUSH: int = OpCode.OP_PUSHDATA1.value[0] - 1


class ScriptMalformedError(ValueError):
    """A script that Radiant's ``GetOp`` cannot walk.

    ``ValueError`` so that callers already catching ``ValueError`` around
    script parsing keep working, and so ``Transaction.from_hex``'s
    ``suppress(Exception)`` still turns it into ``None``.
    """


class ScriptChunk:
    """
    A representation of a chunk of a script, which includes an opcode.
    For push operations, the associated data to push onto the stack is also included.
    ``data`` also carries the fixed 36-byte immediate of a ref opcode, which is
    an operand rather than a stack push — :meth:`is_ref_operand` tells the two
    apart, because they re-serialize differently.
    """

    def __init__(self, op: bytes, data: bytes | None = None):
        self.op = op
        self.data = data

    def is_ref_operand(self) -> bool:
        """True when ``op`` is one of the five opcodes ``GetScriptOp`` follows
        with a bare 36-byte operand (no length prefix)."""
        return len(self.op) == 1 and self.op[0] in REF_OPERAND_OPCODES

    def serialize(self) -> bytes:
        """The exact bytes this chunk was parsed from.

        Re-emits the *declared* push encoding rather than the minimal one. The
        previous implementation ran every chunk through ``encode_pushdata``,
        which normalises, so a script using a non-minimal push came back as
        different bytes — and anything hashing the result (a txid, a covenant's
        codeScriptHash) was hashing a script the caller never had.
        """
        if self.data is None:
            return self.op
        if self.is_ref_operand():
            return self.op + self.data
        op = self.op[0]
        width = _PUSHDATA_SIZE_WIDTH.get(op)
        if width is None:
            return self.op + self.data
        return self.op + len(self.data).to_bytes(width, "little") + self.data

    def __str__(self):
        if self.is_ref_operand():
            return f"{OPCODE_VALUE_NAME_DICT[self.op]} {self.data.hex()}"
        if self.data is not None:
            return self.data.hex()
        return OPCODE_VALUE_NAME_DICT[self.op]

    def __repr__(self):
        return self.__str__()


class Script:
    def __init__(self, script: str | bytes | None = None, *, allow_malformed: bool = False):
        """
        Create script from hex string or bytes.

        The chunk walk mirrors Radiant's ``GetScriptOp``
        (``src/script/script.cpp:662-731``) exactly, including its refusal to
        clamp a push whose declared size runs past the end of the script.

        ``allow_malformed`` is the deliberate, opt-in escape hatch and has
        exactly one legitimate user: transaction deserialization. A scriptPubKey
        is only executed when it is *spent*, so a transaction carrying an
        unwalkable output script is perfectly valid in a block, and a
        deserializer that refused it could not read real chain history. In that
        mode the walk stops where ``GetOp`` returns false and records the offset
        in :attr:`truncated_at`; it never invents a chunk. Raw bytes are
        preserved verbatim either way, matching ``CScript``, which stores bytes
        and only fails when something walks them.
        """
        if script is None:
            self.script: bytes = b""
        elif isinstance(script, str):
            # script in hex string
            self.script: bytes = bytes.fromhex(script)
        elif isinstance(script, bytes):
            # script in bytes
            self.script: bytes = script
        else:
            raise TypeError("unsupported script type")
        # An array of script chunks that make up the script.
        self.chunks: list[ScriptChunk] = []
        #: Byte offset of the opcode where the walk stopped, or ``None`` when the
        #: whole script parsed. Only ever set under ``allow_malformed``.
        self.truncated_at: int | None = None
        self._build_chunks(allow_malformed)

    def _build_chunks(self, allow_malformed: bool = False):
        """Walk the script the way ``GetScriptOp`` does.

        Two rules, both of which pyrxd previously got wrong:

        * A push whose declared size exceeds what remains makes ``GetScriptOp``
          return **false**. Reading "as many bytes as are left" instead produced
          a chunk list for a script the node treats as malformed — and
          :meth:`is_push_only` then called such a scriptSig push-only, which
          ``SCRIPT_VERIFY_SIGPUSHONLY`` (set for every connected block) says it
          is not.
        * The five opcodes in :data:`~pyrxd.constants.REF_OPERAND_OPCODES` are
          each followed by a bare :data:`~pyrxd.constants.REF_OPERAND_WIDTH`
          -byte operand. A ref-blind walk reads those 36 bytes as opcodes and
          desynchronises from consensus for the rest of the script.
        """
        self.chunks = []
        self.truncated_at = None
        reader = Reader(self.script)
        total = len(self.script)

        def _fail(offset: int, detail: str):
            if not allow_malformed:
                raise ScriptMalformedError(
                    f"malformed script at byte {offset}: {detail}. Radiant's GetScriptOp "
                    f"refuses this script; pass allow_malformed=True only if you are "
                    f"deserializing chain bytes that may legitimately contain one."
                )
            self.truncated_at = offset

        while not reader.eof():
            offset = reader.tell()
            op = reader.read_bytes(1)
            op_int = op[0]

            if 0x01 <= op_int <= _MAX_DIRECT_PUSH:
                size = op_int
            elif op_int in _PUSHDATA_SIZE_WIDTH:
                width = _PUSHDATA_SIZE_WIDTH[op_int]
                if total - reader.tell() < width:
                    _fail(offset, f"{OPCODE_VALUE_NAME_DICT[op]} needs a {width}-byte size operand")
                    return
                size = int.from_bytes(reader.read_bytes(width), "little")
            elif op_int in REF_OPERAND_OPCODES:
                size = REF_OPERAND_WIDTH
            else:
                # OP_0 and every non-push opcode: no operand. OP_0 is left with
                # data=None (rather than an empty push) so that disassembly and
                # ASM round-tripping keep naming it as an opcode.
                self.chunks.append(ScriptChunk(op))
                continue

            if total - reader.tell() < size:
                _fail(offset, f"push declares {size} bytes, only {total - reader.tell()} remain")
                return
            self.chunks.append(ScriptChunk(op, reader.read_bytes(size)))

    def serialize(self) -> bytes:
        return self.script

    def hex(self) -> str:
        return self.script.hex()

    def byte_length(self) -> int:
        return len(self.script)

    size = byte_length

    def byte_length_varint(self) -> bytes:
        return unsigned_to_varint(self.byte_length())

    size_varint = byte_length_varint

    def is_push_only(self) -> bool:
        """
        Checks if the script contains only push data operations.
        :return: True if the script is push-only, otherwise false.

        Mirrors ``CScript::IsPushOnly`` (``script.cpp:537-553``), which returns
        false the moment ``GetOp`` fails — before it ever looks at the opcode.
        A script that stopped short is therefore NOT push-only, however
        push-like the chunks it did manage to yield look. This matters:
        ``SCRIPT_VERIFY_SIGPUSHONLY`` is applied to every connected block, so
        answering "yes" here for a truncated scriptSig calls valid an input no
        block can contain.
        """
        if self.truncated_at is not None:
            return False
        return all(chunk.op <= OpCode.OP_16 for chunk in self.chunks)

    def __eq__(self, o: object) -> bool:
        if isinstance(o, Script):
            return self.script == o.script
        return super().__eq__(o)

    def __str__(self) -> str:
        return self.script.hex()

    def __repr__(self) -> str:
        return self.__str__()

    @classmethod
    def from_chunks(cls, chunks: list[ScriptChunk]) -> Script:
        """Reassemble a script from chunks, byte-for-byte.

        Each chunk re-emits its own declared encoding
        (:meth:`ScriptChunk.serialize`). It used to route everything through
        ``encode_pushdata``, which rewrites a non-minimal push into the minimal
        one — so ``from_chunks(Script(x).chunks)`` was not the identity, and
        ``find_and_delete`` could change a script it deleted nothing from.
        """
        script = b"".join(chunk.serialize() for chunk in chunks)
        s = Script(script)
        s.chunks = chunks
        return s

    @classmethod
    def from_asm(cls, asm: str) -> Script:
        chunks: [ScriptChunk] = []
        tokens = asm.split(" ")
        i = 0
        while i < len(tokens):
            token = tokens[i]
            token = "OP_0" if token == "OP_FALSE" else token  # nosec B105 -- comparing opcode names, not passwords
            opcode: str | None = None
            opcode_value: bytes | None = None
            if token.startswith("OP_") and token in OPCODE_VALUE_NAME_DICT.values():
                opcode = token
                opcode_value = OpCode[opcode].value

            if token == "0":  # nosec B105 -- comparing script ASM token, not a password
                opcode_value = b"\x00"
                chunks.append(ScriptChunk(opcode_value))
                i += 1
            elif token == "-1":  # nosec B105 -- comparing script ASM token, not a password
                opcode_value = OpCode.OP_1NEGATE
                chunks.append(ScriptChunk(opcode_value))
                i += 1
            elif opcode is None:
                hex_string = tokens[i]
                if len(hex_string) % 2 != 0:
                    hex_string = "0" + hex_string
                hex_bytes = bytes.fromhex(hex_string)
                if hex_bytes.hex() != hex_string:
                    raise ValueError("invalid hex string in script")
                hex_len = len(hex_bytes)
                if 0 <= hex_len < int.from_bytes(OpCode.OP_PUSHDATA1, "big"):
                    opcode_value = int.to_bytes(hex_len, 1, "big")
                elif hex_len < pow(2, 8):
                    opcode_value = OpCode.OP_PUSHDATA1
                elif hex_len < pow(2, 16):
                    opcode_value = OpCode.OP_PUSHDATA2
                elif hex_len < pow(2, 32):
                    opcode_value = OpCode.OP_PUSHDATA4
                chunks.append(ScriptChunk(opcode_value, hex_bytes))
                i = i + 1
            elif (
                opcode_value == OpCode.OP_PUSHDATA1
                or opcode_value == OpCode.OP_PUSHDATA2
                or opcode_value == OpCode.OP_PUSHDATA4
            ):
                chunks.append(ScriptChunk(opcode_value, bytes.fromhex(tokens[i + 2])))
                i += 3
            else:
                chunks.append(ScriptChunk(opcode_value))
                i += 1
        return Script.from_chunks(chunks)

    def to_asm(self) -> str:
        """Disassemble to ASM, marking an unwalkable tail rather than hiding it.

        Radiant's ``ScriptToAsmStr`` (``src/core_write.cpp:117-120``) emits
        ``[error]`` and stops as soon as ``GetOp`` fails. Rendering clean ASM
        for a script the node cannot read is how a malformed script gets
        eyeballed as fine.
        """
        tokens = [str(chunk) for chunk in self.chunks]
        if self.truncated_at is not None:
            tokens.append("[error]")
        return " ".join(tokens)

    @classmethod
    def find_and_delete(cls, source: Script, pattern: Script) -> Script:
        chunks = []
        for chunk in source.chunks:
            if Script.from_chunks([chunk]).hex() != pattern.hex():
                chunks.append(chunk)
        return Script.from_chunks(chunks)

    @classmethod
    def write_bin(cls, octets: bytes) -> Script:
        return Script(encode_pushdata(octets))


#: The three opcodes that carry an arbitrary-length data payload. Direct pushes
#: (``0x01``-``0x4B``) encode the length in the opcode itself; ``OP_PUSHDATA1``
#: takes one length byte and ``OP_PUSHDATA2`` two. ``OP_PUSHDATA4`` is excluded:
#: nothing that fits in an ``OP_RETURN`` data carrier needs a 4-byte length, and
#: HashMark §4.1 requires verifiers to reject it outright.
_OP_PUSHDATA1, _OP_PUSHDATA2 = 0x4C, 0x4D

#: Smallest payload each opcode is the MINIMAL encoding for. A push shorter than
#: its opcode's threshold has a shorter spelling and is therefore non-canonical.
_MINIMAL_FLOOR = {_OP_PUSHDATA1: 76, _OP_PUSHDATA2: 256}


def data_pushes_after_op_return(script: bytes, *, require_minimal: bool = False) -> list[bytes] | None:
    """Every data push following a leading ``OP_RETURN``, or None if not push-only.

    Shared by the ``OP_RETURN`` payload decoders (HashMark, the Photonic ``msg``
    convention) so the walk exists once. Returns None rather than raising: at the
    point a caller uses this, no protocol marker has been seen yet, so a parse
    failure means "some other protocol", not "a broken record". Radiant Core
    classifies a data carrier as ``TX_NULL_DATA`` only when the remainder after
    ``OP_RETURN`` is push-only, so a non-push chunk means this is not one.

    ``OP_PUSHDATA1``/``OP_PUSHDATA2`` ARE data pushes. This originally refused
    every opcode above ``0x4B`` under a comment claiming they were not, which put
    a cliff at exactly 76 bytes — the length at which every encoder in this repo
    switches to ``OP_PUSHDATA1``. pyrxd therefore WROTE ``msg`` outputs that
    pyrxd could not READ, and skipped spec-legal signed HashMark records as
    though they were some other protocol.

    ``OP_1NEGATE`` and ``OP_1``-``OP_16`` are never data pushes here — they are
    push operations in Bitcoin's ``IsPushOnly`` sense, but reading them as data
    would give a one-byte field a second spelling. The opcode bound covers them.

    :param require_minimal: reject any push that is not the SHORTEST spelling of
        itself — ``OP_PUSHDATA1`` carrying ≤75 bytes, ``OP_PUSHDATA2`` carrying
        ≤255, and ``OP_0`` for the empty push. HashMark §4.1 mandates this:
        every record must have exactly one valid serialization, or two
        implementations cannot compare records as bytes.

        Left OFF by default for the ``msg`` convention, which has no canonical
        form to protect. Refusing a third-party writer's honest text over its
        choice of length prefix would be a guard refusing valid work — and
        turning it on unconditionally measurably was one: it downgraded a
        ``msg`` whose payload is ``OP_0`` from "malformed message, empty push"
        to "not a message at all", losing the diagnostic for a record that
        plainly IS one.
    """
    if not script or script[0] != 0x6A:
        return None
    parsed = Script(script[1:], allow_malformed=True)
    if parsed.truncated_at is not None:
        return None
    out: list[bytes] = []
    for chunk in parsed.chunks:
        op = chunk.op[0] if isinstance(chunk.op, bytes) else chunk.op
        if op > _OP_PUSHDATA2:  # OP_PUSHDATA4, OP_1NEGATE, OP_1-OP_16, or a non-push opcode
            return None
        data = chunk.data or b""
        # OP_0 counts as a zero-length push here; under `require_minimal` it does not
        # (see below). Both are floor-1 cases, so one comparison covers them.
        if require_minimal and len(data) < _MINIMAL_FLOOR.get(op, 1):
            return None
        out.append(data)
    return out

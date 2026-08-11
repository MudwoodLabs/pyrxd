"""Differential over every pyrxd script walker, against a consensus-derived reference.

pyrxd walks raw script bytes in several independent places. Each walk must
advance the program counter exactly as Radiant's ``GetScriptOp`` does, because a
walker that desynchronises by even one byte starts reading operand data as
opcodes — and then reports refs that are not there while missing the ones that
are. That is not a cosmetic bug: the ref set feeds ``hashOutputHashes`` in the
sighash preimage, and it decides which key owns a soulbound token.

Three shipped bugs came from four walkers each spelling the rule by hand. This
file replaces "they all agree with each other" (which was true of the two wrong
ones) with "they all agree with the C++", by generating scripts and comparing
every walker to a reference whose rules are **parsed out of Radiant Core** —
see ``tests/consensus_oracle.py``.

Coverage is deliberately adversarial:

* every opcode value ``0x00``-``0xff`` in varied positions,
* all five ref-operand opcodes, including the three (``0xd1``/``0xd2``/``0xd3``)
  that carry an operand but contribute no ref — the pair of facts whose
  conflation caused the sighash bug,
* the four ``REFHASH*`` stack ops ``0xd4``-``0xd7`` that sit *inside* the
  ``0xd0``-``0xd8`` range but carry no operand — the phantom-ref trap,
* push payloads and ref operands whose bytes are themselves ref opcodes, so a
  desynchronised walker produces a confidently wrong answer rather than an error.
"""

from __future__ import annotations

import os

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pyrxd.constants import REF_OPERAND_OPCODES
from pyrxd.glyph.script import TruncatedScriptError, count_input_refs, iter_input_refs
from pyrxd.glyph.soulbound_covenant import _assert_no_nonminimal_push
from pyrxd.glyph.soulbound_detect import _opcodes as soulbound_opcodes
from pyrxd.gravity.htlc_covenant import _assert_minimal_pushes, _opcode_bd_positions
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction_preimage import _get_push_refs
from tests.consensus_oracle import (
    opcode_table,
    push_ref_opcodes,
    ref_operand_opcodes,
    ref_operand_width,
)

pytestmark = pytest.mark.unit

_BUDGET = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))

# Every rule below comes from the vendored C++, never from a literal here.
_OPERAND_OPS = ref_operand_opcodes()
_PUSH_REF_OPS = push_ref_opcodes()
_OPERAND_WIDTH = ref_operand_width()
_OP_STATESEPARATOR = opcode_table()["OP_STATESEPARATOR"]

# The operand-less stack ops interleaved through the ref range. Deriving them
# (rather than typing 0xd4..0xd7) means a future upstream reshuffle is picked up.
_REFHASH_TRAP_OPS = sorted(set(range(min(_OPERAND_OPS), max(_OPERAND_OPS) + 1)) - _OPERAND_OPS)


class RefWalkTruncated(Exception):
    """The reference walker's equivalent of ``GetScriptOp`` returning false."""


def _reference_walk(script: bytes) -> list[tuple[int, int, bytes]]:
    """Transcription of Radiant's ``GetScriptOp``, driven by the parsed oracle.

    Returns ``(position, opcode, operand)`` per opcode. ``operand`` is the push
    payload for a data push, the 36-byte ref for a ref opcode, and empty
    otherwise. Raises :class:`RefWalkTruncated` wherever ``GetScriptOp`` would
    return false, which is what makes the whole script invalid to a node.
    """
    out: list[tuple[int, int, bytes]] = []
    pos, n = 0, len(script)
    while pos < n:
        start = pos
        op = script[pos]
        pos += 1
        operand = b""

        if op <= 0x4B:  # OP_0 and the direct-push range
            size = op
            if n - pos < size:
                raise RefWalkTruncated(f"direct push at {start} wants {size} bytes")
            operand = script[pos : pos + size]
            pos += size
        elif op in (0x4C, 0x4D, 0x4E):  # PUSHDATA1/2/4
            width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
            if n - pos < width:
                raise RefWalkTruncated(f"PUSHDATA length prefix at {start} truncated")
            size = int.from_bytes(script[pos : pos + width], "little")
            pos += width
            if n - pos < size:
                raise RefWalkTruncated(f"PUSHDATA at {start} wants {size} bytes")
            operand = script[pos : pos + size]
            pos += size
        elif op in _OPERAND_OPS:  # the 36-byte immediate — the rule that broke
            if n - pos < _OPERAND_WIDTH:
                raise RefWalkTruncated(f"ref operand at {start} truncated")
            operand = script[pos : pos + _OPERAND_WIDTH]
            pos += _OPERAND_WIDTH
        # else: a bare opcode, already advanced by one.

        out.append((start, op, operand))
    return out


def _reference_push_refs(script: bytes) -> list[bytes]:
    """``GetPushRefs``' ``foundPushRefs``, in ``std::set<uint288>`` order.

    Deliberately derived differently from the production code: production sorts
    on the reversed byte string, this sorts the decoded little-endian integer.
    Two derivations of "uint288 ascending" that must agree.
    """
    refs = {op_ref for _, op, op_ref in _reference_walk(script) if op in _PUSH_REF_OPS}
    return [v.to_bytes(_OPERAND_WIDTH, "little") for v in sorted(int.from_bytes(r, "little") for r in refs)]


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

# Refs whose bytes are themselves ref opcodes: if a walker fails to consume the
# operand, it reads these as a run of pushref opcodes and reports phantom refs.
_ADVERSARIAL_REFS = [
    bytes([0xD0]) * _OPERAND_WIDTH,
    bytes([0xD8]) * _OPERAND_WIDTH,
    bytes([0xD4]) * _OPERAND_WIDTH,
    bytes(_OPERAND_WIDTH),
    bytes([0xFF]) * _OPERAND_WIDTH,
    bytes(range(_OPERAND_WIDTH)),
]

_ref_bytes = st.one_of(
    st.sampled_from(_ADVERSARIAL_REFS),
    st.binary(min_size=_OPERAND_WIDTH, max_size=_OPERAND_WIDTH),
)

# A ref-operand opcode plus a well-formed operand.
_ref_element = st.tuples(st.sampled_from(sorted(_OPERAND_OPS)), _ref_bytes).map(lambda t: bytes([t[0]]) + t[1])

# Bare opcodes: EVERY byte that is not a push and not a ref-operand opcode.
# Includes 0xd4-0xd7, the ops that made a range-based walker fabricate refs.
_BARE_OPS = [b for b in range(0x4F, 0x100) if b not in _OPERAND_OPS]
_bare_element = st.sampled_from(_BARE_OPS).map(lambda b: bytes([b]))

# Push payloads may contain ref opcode bytes on purpose — a correct walker
# never interprets payload bytes as opcodes.
_payload = st.one_of(
    st.binary(min_size=0, max_size=40),
    st.sampled_from([bytes([o]) * 40 for o in sorted(_OPERAND_OPS)] + [bytes([0xD4]) * 40]),
)
_direct_push = _payload.map(lambda d: bytes([len(d)]) + d if len(d) <= 0x4B else bytes([0x4B]) + d[:0x4B])
_pushdata1 = _payload.map(lambda d: b"\x4c" + bytes([len(d)]) + d)
_pushdata2 = _payload.map(lambda d: b"\x4d" + len(d).to_bytes(2, "little") + d)
_pushdata4 = _payload.map(lambda d: b"\x4e" + len(d).to_bytes(4, "little") + d)

_element = st.one_of(_ref_element, _bare_element, _direct_push, _pushdata1, _pushdata2, _pushdata4)
_script = st.lists(_element, min_size=0, max_size=12).map(b"".join)

# Biased toward scripts that actually carry refs.
_ref_heavy_script = st.lists(
    st.one_of(_ref_element, _ref_element, _bare_element, _direct_push), min_size=1, max_size=10
).map(b"".join)


# ---------------------------------------------------------------------------
# Every opcode, in varied positions
# ---------------------------------------------------------------------------

_REAL_REF = bytes.fromhex("b73ea8b33a8d8f15b25d25b9e6892926f893a7fdb6a97695d029732aa4ae01cd00000000")
_P2PKH = bytes.fromhex("76a914" + "cc" * 20 + "88ac")


def _well_formed_with(op: int) -> bytes | None:
    """A minimal well-formed script exercising ``op`` mid-script, or None if
    the opcode cannot appear without extra framing we would have to invent."""
    if op <= 0x4B:
        return _P2PKH + bytes([op]) + b"\xab" * op + b"\x75"
    if op in (0x4C, 0x4D, 0x4E):
        width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
        return _P2PKH + bytes([op]) + (3).to_bytes(width, "little") + b"\xab\xcd\xef" + b"\x75"
    if op in _OPERAND_OPS:
        return _P2PKH + bytes([op]) + _REAL_REF + b"\x75"
    return _P2PKH + bytes([op]) + b"\x75"


class TestEveryOpcodeInVariedPositions:
    """Systematic sweep: each of the 256 byte values placed after a P2PKH
    prologue and before a trailing opcode, so a mis-advance is visible as a
    changed tail rather than a truncation."""

    @pytest.mark.parametrize("op", range(0x100))
    def test_walkers_agree_with_reference(self, op):
        script = _well_formed_with(op)
        assert script is not None
        expected = _reference_walk(script)
        assert soulbound_opcodes(script) == [o for _, o, _ in expected]
        assert [(o, r) for _, o, r in expected if o in _OPERAND_OPS] == list(iter_input_refs(script))
        assert _get_push_refs(script) == _reference_push_refs(script)
        assert _opcode_bd_positions(script) == [p for p, o, _ in expected if o == _OP_STATESEPARATOR]

    @pytest.mark.parametrize("op", _REFHASH_TRAP_OPS)
    def test_refhash_stack_ops_carry_no_operand(self, op):
        """The exact defect in ``glyph/script.py``: 0xd4-0xd7 sit inside the
        0xd0-0xd8 range but take no operand. A range-based walker swallows the
        next 36 bytes, invents a ref from them, and loses the real one."""
        script = bytes([op]) + bytes([0xD0]) + _REAL_REF
        refs = list(iter_input_refs(script))
        assert refs == [(0xD0, _REAL_REF)], (
            f"{hex(op)} must advance the walk by ONE byte; the real ref that follows it has to remain visible"
        )
        assert _get_push_refs(script) == [_REAL_REF]
        assert op not in REF_OPERAND_OPCODES


# ---------------------------------------------------------------------------
# Property differentials
# ---------------------------------------------------------------------------


class TestWalkerDifferential:
    @settings(max_examples=300 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_script)
    def test_opcode_stream_matches_reference(self, script):
        assert soulbound_opcodes(script) == [op for _, op, _ in _reference_walk(script)]

    @settings(max_examples=300 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_ref_heavy_script)
    def test_iter_input_refs_matches_reference(self, script):
        expected = [(op, operand) for _, op, operand in _reference_walk(script) if op in _OPERAND_OPS]
        assert list(iter_input_refs(script)) == expected

    @settings(max_examples=300 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_ref_heavy_script)
    def test_preimage_push_refs_match_reference(self, script):
        assert _get_push_refs(script) == _reference_push_refs(script)

    @settings(max_examples=300 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_script)
    def test_stateseparator_positions_match_reference(self, script):
        expected = [pos for pos, op, _ in _reference_walk(script) if op == _OP_STATESEPARATOR]
        assert _opcode_bd_positions(script) == expected

    @settings(max_examples=200 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_ref_heavy_script)
    def test_count_input_refs_matches_reference(self, script):
        expected: dict[bytes, int] = {}
        for _, op, operand in _reference_walk(script):
            if op in _OPERAND_OPS:
                expected[operand] = expected.get(operand, 0) + 1
        assert count_input_refs(script) == expected


# ---------------------------------------------------------------------------
# Regression cases for the three shipped bugs
# ---------------------------------------------------------------------------


class TestShippedBugRegressions:
    def test_phantom_refs_from_refhash_operand_range(self):
        """``REF_OPCODES`` spanning 0xd0-0xd8 made this script report a ref
        that is not in it and hid the one that is."""
        script = bytes([0xD4]) + bytes([0xD0]) + _REAL_REF
        assert _get_push_refs(script) == _reference_push_refs(script) == [_REAL_REF]
        assert list(iter_input_refs(script)) == [(0xD0, _REAL_REF)]

    def test_the_differential_actually_catches_the_range_bug(self):
        """Negative control.

        A differential is only worth its runtime if it fails on the bug it
        claims to cover. This re-creates the exact defective walker —
        ``0xd0 <= op <= 0xd8`` — and asserts the reference disagrees with it.
        Without this, a future refactor that quietly narrowed the generators
        would leave the tests above passing while checking nothing.
        """

        def buggy_range_walk(script: bytes) -> list[bytes]:
            refs, pos, n = [], 0, len(script)
            while pos < n:
                op = script[pos]
                pos += 1
                if 0xD0 <= op <= 0xD8:  # the shipped bug
                    if pos + _OPERAND_WIDTH > n:
                        break
                    if op in _PUSH_REF_OPS:
                        refs.append(script[pos : pos + _OPERAND_WIDTH])
                    pos += _OPERAND_WIDTH
                elif 0x01 <= op <= 0x4B:
                    pos += op
            return refs

        script = bytes([0xD4]) + bytes([0xD0]) + _REAL_REF
        phantom = buggy_range_walk(script)
        assert phantom != [_REAL_REF], "the buggy walker was supposed to get this wrong"
        assert _REAL_REF not in phantom, "the buggy walker loses the real ref entirely"
        assert _reference_push_refs(script) == [_REAL_REF]
        assert _get_push_refs(script) == [_REAL_REF]

    def test_requireinputref_operand_is_walked_not_collected(self):
        """The sighash bug: 0xd1 carries an operand (so it must be WALKED) but
        contributes no ref (so it must not be COLLECTED). Walking only
        0xd0/0xd8 resumed the scan inside the ref bytes."""
        script = bytes([0xD1]) + _REAL_REF + bytes([0xD8]) + _REAL_REF
        assert _get_push_refs(script) == [_REAL_REF]
        assert list(iter_input_refs(script)) == [(0xD1, _REAL_REF), (0xD8, _REAL_REF)]
        assert _reference_push_refs(script) == [_REAL_REF]

    @pytest.mark.parametrize("op", [0xD1, 0xD2, 0xD3])
    def test_walked_but_not_collected_ops(self, op):
        script = bytes([op]) + bytes([0xD0]) * _OPERAND_WIDTH
        assert _get_push_refs(script) == []
        assert _get_push_refs(script) == _reference_push_refs(script)

    def test_photonic_nft_auth_script_shape(self):
        """OP_REQUIREINPUTREF <ref> <sha256> OP_2DROP … OP_PUSHINPUTREFSINGLETON <ref>
        — the real script shape that exposed the sighash bug in the wild."""
        other = bytes(range(_OPERAND_WIDTH))
        script = bytes([0xD1]) + other + b"\x20" + bytes(32) + b"\x6d" + _P2PKH + bytes([0xD8]) + _REAL_REF
        assert _get_push_refs(script) == _reference_push_refs(script) == [_REAL_REF]

    def test_ref_opcode_bytes_inside_a_push_payload_are_data(self):
        script = b"\x26" + bytes([0xD0]) * 0x26 + bytes([0xD0]) + _REAL_REF
        assert _get_push_refs(script) == [_REAL_REF]
        assert _get_push_refs(script) == _reference_push_refs(script)


# ---------------------------------------------------------------------------
# The MINIMALDATA guards — the two walkers that assert rather than return
# ---------------------------------------------------------------------------
#
# ``soulbound_covenant._assert_no_nonminimal_push`` and
# ``htlc_covenant._assert_minimal_pushes`` walk a script the same way as everything
# above, but their output is an exception rather than a list, so the differentials in
# this file did not reach them. Both were listed in the ``_REF_WALKERS`` registry, which
# gave them a green tick from ``test_walker_references_the_shared_constant`` they had not
# earned: mutating the soulbound walker's ``i += 37`` to ``i += 1`` left the whole suite
# green (7596 passed, 44 skipped, measured).
#
# A stride bug here is not silent. The 36 operand bytes get read as opcodes, and any
# ``0x01`` inside a ref followed by a byte in 1..16 becomes a "non-minimal push" — so the
# guard REFUSES TO BUILD a perfectly valid covenant, for one ref in roughly every eight.


def _pushdata_floor(op: int) -> int:
    """Smallest payload size for which ``op`` is the minimal PUSHDATA encoding."""
    return {0x4C: 76, 0x4D: 256, 0x4E: 0x10000}[op]


def _reference_rejects(script: bytes, *, any_pushdata_is_a_violation: bool) -> bool:
    """Does the CONSENSUS tokenisation contain a push these guards must reject?

    Derived from ``_reference_walk``, so the ref operand is skipped as one unit by
    construction rather than by the rule under test.
    """
    for _pos, op, operand in _reference_walk(script):
        if op == 0x01 and (1 <= operand[0] <= 16 or operand[0] == 0x81):
            return True  # a 1-byte push of a value OP_1..OP_16/OP_1NEGATE encodes
        if op in (0x4C, 0x4D, 0x4E) and (any_pushdata_is_a_violation or len(operand) < _pushdata_floor(op)):
            return True
    return False


def _refuses(guard) -> bool:
    try:
        guard()
    except ValidationError:
        return True
    return False


#: Ref operands whose bytes, if read as opcodes, look like a MINIMALDATA violation.
#: These are what a stride bug turns into a spurious build-time refusal — the plain
#: ``_ADVERSARIAL_REFS`` above cannot see it, because 36 bytes of ``0xd0`` (or ``0x00``,
#: or ``0xff``) each advance a broken walk by one and land on the very same offset.
_MINIMALDATA_TRAP_REFS = [
    b"\x01\x05" * 18,  # 1-byte push of 5 -> "must be OP_5"
    b"\x01\x81" * 18,  # 1-byte push of OP_1NEGATE's encoding
    bytes(range(_OPERAND_WIDTH)),  # 0x01 followed by 0x02
    b"\x4c" + bytes(_OPERAND_WIDTH - 1),  # PUSHDATA1 inside the operand
    b"\x4d" + bytes(_OPERAND_WIDTH - 1),  # PUSHDATA2 inside the operand
    b"\x4b" + bytes(_OPERAND_WIDTH - 1),  # a 75-byte direct push claiming past the end
]

_trap_ref_element = st.tuples(
    st.sampled_from(sorted(_OPERAND_OPS)),
    st.one_of(st.sampled_from(_MINIMALDATA_TRAP_REFS), _ref_bytes),
).map(lambda t: bytes([t[0]]) + t[1])

_minimaldata_script = st.lists(
    st.one_of(_trap_ref_element, _trap_ref_element, _bare_element, _direct_push, _pushdata1),
    min_size=1,
    max_size=8,
).map(b"".join)


class TestMinimalDataGuardsWalkLikeConsensus:
    @pytest.mark.parametrize("ref", _MINIMALDATA_TRAP_REFS, ids=range(len(_MINIMALDATA_TRAP_REFS)))
    @pytest.mark.parametrize("op", sorted(_OPERAND_OPS))
    def test_a_ref_operand_is_never_read_as_a_push(self, op, ref):
        """The regression, stated directly: operand bytes are DATA, whatever they spell.

        Every script here is valid — one ref opcode with a well-formed 36-byte operand,
        after a P2PKH prologue — so both guards must accept it. Under ``i += 1`` the
        walk resumes inside the ref and reports a non-minimal push that is not there.
        """
        script = _P2PKH + bytes([op]) + ref
        assert not _reference_rejects(script, any_pushdata_is_a_violation=True), "fixture must be clean"

        _assert_no_nonminimal_push(script)  # must not raise
        _assert_minimal_pushes(script, variant="test")  # must not raise

    @settings(max_examples=300 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_minimaldata_script)
    def test_soulbound_guard_matches_the_reference_verdict(self, script):
        assert _refuses(lambda: _assert_no_nonminimal_push(script)) == _reference_rejects(
            script, any_pushdata_is_a_violation=True
        )

    @settings(max_examples=300 * _BUDGET, suppress_health_check=[HealthCheck.too_slow], deadline=None)
    @given(script=_minimaldata_script)
    def test_htlc_guard_matches_the_reference_verdict(self, script):
        assert _refuses(lambda: _assert_minimal_pushes(script, variant="test")) == _reference_rejects(
            script, any_pushdata_is_a_violation=False
        )

    def test_the_guards_still_catch_a_real_non_minimal_push(self):
        """Negative control: the agreement above must not be "both accept everything"."""
        assert _refuses(lambda: _assert_no_nonminimal_push(_P2PKH + b"\x01\x05"))
        assert _refuses(lambda: _assert_minimal_pushes(_P2PKH + b"\x01\x05", variant="test"))
        # ...and the F-001 shape that motivated the HTLC guard: PUSHDATA1 under 76 bytes.
        assert _refuses(lambda: _assert_minimal_pushes(_P2PKH + b"\x4c\x02\xaa\xbb", variant="test"))

    def test_a_real_ref_bearing_covenant_prefix_is_accepted(self):
        """The shape both guards actually run on in production."""
        script = bytes([0xD1]) + _REAL_REF + _P2PKH + bytes([0xD8]) + _REAL_REF
        _assert_no_nonminimal_push(script)
        _assert_minimal_pushes(script, variant="test")


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


class TestTruncation:
    """A script whose last opcode's operand runs off the end makes
    ``GetScriptOp`` return false, which makes the whole script invalid.

    pyrxd has two behaviours here and the split is intentional: walkers whose
    output is consensus-visible (the sighash ref set; ref extraction used to
    gate spends) refuse the script, while the two structural classifiers stop
    early. These tests pin both, so a change to either is a decision rather
    than a drift.
    """

    @pytest.mark.parametrize("op", sorted(_OPERAND_OPS))
    @pytest.mark.parametrize("short_by", [1, 12, 36])
    def test_reference_rejects_truncated_ref_operand(self, op, short_by):
        script = bytes([op]) + _REAL_REF[: _OPERAND_WIDTH - short_by]
        with pytest.raises(RefWalkTruncated):
            _reference_walk(script)

    @pytest.mark.parametrize("op", sorted(_OPERAND_OPS))
    def test_consensus_visible_walkers_refuse_truncated_refs(self, op):
        from pyrxd.security.errors import ValidationError

        script = bytes([op]) + _REAL_REF[:20]
        with pytest.raises(ValidationError):
            _get_push_refs(script)
        with pytest.raises(TruncatedScriptError):
            list(iter_input_refs(script))

    @pytest.mark.parametrize("op", sorted(_OPERAND_OPS))
    def test_structural_classifiers_stop_at_a_truncated_ref(self, op):
        """Documented leniency, not agreement with consensus.

        ``_opcodes`` and ``_opcode_bd_positions`` record the opcode then run off
        the end, so they yield a prefix rather than raising. Both feed
        fail-closed comparisons (an exact position list, an exact
        classification), so a truncated script fails those checks anyway — but
        the divergence from ``GetScriptOp`` is real and is pinned here rather
        than assumed away.
        """
        script = bytes([op]) + _REAL_REF[:20]
        assert soulbound_opcodes(script) == [op]
        assert _opcode_bd_positions(script) == []
        with pytest.raises(RefWalkTruncated):
            _reference_walk(script)

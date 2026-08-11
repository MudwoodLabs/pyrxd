"""``get_script_op`` / ``has_valid_ops`` against the vendored Radiant Core source.

The value of these tests is that the *inputs* are built from the oracle's view
of the C++, so a constant that drifts from Radiant fails here rather than in a
covenant three months later.
"""

from __future__ import annotations

import pytest

from pyrxd.constants import (
    MAX_OPCODE,
    MAX_SCRIPT_ELEMENT_SIZE,
    MAX_SCRIPT_ELEMENT_SIZE_LEGACY,
    REF_OPERAND_OPCODES,
    REF_OPERAND_WIDTH,
)
from pyrxd.script.consensus import get_script_op, has_valid_ops, is_valid_script_size, iter_script_ops
from tests.consensus_oracle import script_limit

pytestmark = pytest.mark.unit

_REF_OP = min(REF_OPERAND_OPCODES)  # 0xd0, OP_PUSHINPUTREF
_P2PKH = bytes.fromhex("76a914" + "11" * 20 + "88ac")


class TestGetScriptOp:
    def test_a_direct_push_yields_its_data(self):
        op = get_script_op(b"\x03abc", 0)
        assert (op.opcode, op.operand, op.next_pos) == (0x03, b"abc", 4)

    @pytest.mark.parametrize(
        ("label", "script", "expected"),
        [
            ("OP_PUSHDATA1", b"\x4c\x02ab", b"ab"),
            ("OP_PUSHDATA2", b"\x4d\x02\x00ab", b"ab"),
            ("OP_PUSHDATA4", b"\x4e\x02\x00\x00\x00ab", b"ab"),
        ],
    )
    def test_every_pushdata_width_is_dispatched(self, label, script, expected):
        assert get_script_op(script, 0).operand == expected

    def test_a_non_push_opcode_consumes_one_byte(self):
        op = get_script_op(b"\xac", 0)
        assert (op.opcode, op.operand, op.next_pos) == (0xAC, b"", 1)

    def test_a_ref_opcode_consumes_its_fixed_width_operand(self):
        """The rule three walkers got wrong: no length prefix, fixed width."""
        ref = bytes(range(REF_OPERAND_WIDTH))
        op = get_script_op(bytes([_REF_OP]) + ref, 0)
        assert op.operand == ref
        assert op.next_pos == 1 + REF_OPERAND_WIDTH

    def test_a_ref_operand_one_byte_short_is_malformed(self):
        short = bytes([_REF_OP]) + bytes(REF_OPERAND_WIDTH - 1)
        assert get_script_op(short, 0) is None

    @pytest.mark.parametrize(
        ("label", "script"),
        [
            ("empty", b""),
            ("push runs off the end", b"\x05ab"),
            ("PUSHDATA1 length prefix missing", b"\x4c"),
            ("PUSHDATA2 length prefix truncated", b"\x4d\x02"),
            ("PUSHDATA4 length prefix truncated", b"\x4e\x02\x00\x00"),
            ("PUSHDATA4 claims more data than exists", b"\x4e\xff\xff\xff\xffab"),
        ],
    )
    def test_malformed_instructions_decode_to_none(self, label, script):
        assert get_script_op(script, 0) is None

    def test_reading_past_the_end_is_none_not_an_index_error(self):
        assert get_script_op(_P2PKH, len(_P2PKH)) is None
        assert get_script_op(_P2PKH, -1) is None


class TestIterScriptOps:
    def test_a_p2pkh_decodes_to_its_five_instructions(self):
        assert [op.opcode for op in iter_script_ops(_P2PKH)] == [0x76, 0xA9, 0x14, 0x88, 0xAC]

    def test_the_walk_stops_at_the_first_malformed_instruction(self):
        assert [op.opcode for op in iter_script_ops(b"\xac\xac\x05ab")] == [0xAC, 0xAC]

    def test_ref_bytes_are_never_walked_as_opcodes(self):
        """A ref operand containing ``76a914…`` must not decode as a P2PKH prefix.

        This is the concrete shape of the desync bug: the ref payload is
        attacker-chosen, so a walker that does not skip it can be steered into
        reading any opcode sequence the attacker likes.
        """
        hostile_ref = _P2PKH + bytes(REF_OPERAND_WIDTH - len(_P2PKH))
        assert len(hostile_ref) == REF_OPERAND_WIDTH
        script = bytes([_REF_OP]) + hostile_ref + b"\xac"
        assert [op.opcode for op in iter_script_ops(script)] == [_REF_OP, 0xAC]


class TestHasValidOps:
    def test_a_p2pkh_is_valid(self):
        assert has_valid_ops(_P2PKH)

    def test_an_empty_script_is_valid(self):
        """``HasValidOps`` on an empty script never enters its loop."""
        assert has_valid_ops(b"")

    def test_a_truncated_push_is_invalid(self):
        assert not has_valid_ops(b"\x05ab")

    def test_a_truncated_ref_operand_is_invalid(self):
        assert not has_valid_ops(bytes([_REF_OP]) + bytes(REF_OPERAND_WIDTH - 1))

    @pytest.mark.parametrize("opcode", [MAX_OPCODE + 1, 0xFB, 0xFF])
    def test_a_byte_above_max_opcode_is_invalid(self, opcode):
        """The consumer ``MAX_OPCODE`` did not have. ``OP_INVALIDOPCODE`` (0xff)
        and the four other pseudo-words in ``pyrxd.constants.OpCode`` all land
        here, which is exactly why they must never be emitted."""
        assert not has_valid_ops(bytes([opcode]))

    def test_max_opcode_itself_is_valid(self):
        """The boundary is inclusive — off-by-one in the other direction would
        reject ``OP_K12``, a real Glyph v2 dMint opcode."""
        assert has_valid_ops(bytes([MAX_OPCODE]))

    def test_a_high_byte_inside_a_push_payload_is_still_valid(self):
        """``MAX_OPCODE`` applies to opcode positions, not to pushed data."""
        assert has_valid_ops(b"\x01\xff")

    def test_a_high_byte_inside_a_ref_operand_is_still_valid(self):
        assert has_valid_ops(bytes([_REF_OP]) + b"\xff" * REF_OPERAND_WIDTH)


class TestTheLimitsAreRadiantsNotBitcoins:
    """The correction this work turned up.

    Radiant raised ``MAX_SCRIPT_ELEMENT_SIZE`` to 32,000,000 and kept Bitcoin's
    520 under ``MAX_SCRIPT_ELEMENT_SIZE_LEGACY``. Wiring the pinned constant into
    a builder while "knowing" it means 520 would have rejected valid scripts.
    """

    def test_the_radiant_push_limit_is_not_the_bitcoin_one(self):
        assert script_limit("MAX_SCRIPT_ELEMENT_SIZE") == MAX_SCRIPT_ELEMENT_SIZE
        assert script_limit("MAX_SCRIPT_ELEMENT_SIZE_LEGACY") == MAX_SCRIPT_ELEMENT_SIZE_LEGACY
        assert MAX_SCRIPT_ELEMENT_SIZE != MAX_SCRIPT_ELEMENT_SIZE_LEGACY

    def test_a_push_far_above_bitcoins_limit_is_valid_on_radiant(self):
        """A 1,000-byte push: invalid under Bitcoin's 520, fine under Radiant's."""
        payload = b"\x5a" * 1000
        assert len(payload) > MAX_SCRIPT_ELEMENT_SIZE_LEGACY
        script = b"\x4d" + len(payload).to_bytes(2, "little") + payload
        assert has_valid_ops(script)

    def test_script_size_uses_the_pinned_limit(self):
        assert is_valid_script_size(b"\x00" * 1_000_000)
        assert not is_valid_script_size(b"\x00" * (script_limit("MAX_SCRIPT_SIZE") + 1))


# ---------------------------------------------------------------------------
# Differential: the production walker vs. the transcribed consensus walker
# ---------------------------------------------------------------------------


def _ref_corpus() -> list[tuple[str, bytes]]:
    """Scripts whose ref content the two walkers must agree on.

    Includes the shapes that have actually broken walkers here: a ref operand
    carrying opcode-looking bytes, an operand-less ``0xd4``-family opcode
    adjacent to a real ref, and back-to-back refs.
    """
    ref_a = bytes([0xAA]) * REF_OPERAND_WIDTH
    ref_b = _P2PKH + bytes(REF_OPERAND_WIDTH - len(_P2PKH))  # opcode-looking payload
    d0, d8 = 0xD0, 0xD8
    return [
        ("bare P2PKH, no refs", _P2PKH),
        ("one ref then P2PKH", bytes([d0]) + ref_a + _P2PKH),
        ("ref carrying a P2PKH-shaped payload", bytes([d0]) + ref_b + _P2PKH),
        ("two refs back to back", bytes([d8]) + ref_a + bytes([d0]) + ref_b),
        # 0xd4 is OP_REFHASHDATASUMMARY_UTXO: inside the 0xd0-0xd8 band but
        # carrying NO operand. Consuming bytes after it is the original bug.
        ("an operand-less 0xd4 next to a real ref", bytes([0xD4, d0]) + ref_a + _P2PKH),
        ("ref preceded by a push of ref-looking bytes", b"\x04" + bytes([d0, d0, d0, d0]) + bytes([d0]) + ref_a),
    ]


class TestWalkerDifferential:
    """``glyph.script.iter_input_refs`` must see what ``GetScriptOp`` sees.

    Two independent walks over the same bytes: one the production Glyph
    classifier, one a direct transcription of the C++. Agreement on a corpus is
    a far stronger statement than either walk's own unit tests, because the two
    would have to be wrong in the same way to both pass.
    """

    @pytest.mark.parametrize(("label", "script"), _ref_corpus(), ids=[c[0] for c in _ref_corpus()])
    def test_both_walkers_find_the_same_ref_operands(self, label, script):
        from pyrxd.glyph.script import iter_input_refs

        production = [(op, operand) for op, operand in iter_input_refs(script)]
        mirrored = [(op.opcode, op.operand) for op in iter_script_ops(script) if op.opcode in REF_OPERAND_OPCODES]
        assert production == mirrored

    @pytest.mark.parametrize(("label", "script"), _ref_corpus(), ids=[c[0] for c in _ref_corpus()])
    def test_every_corpus_script_is_structurally_valid(self, label, script):
        """Guards the corpus itself: a fixture the mirror rejects would make the
        agreement above vacuous."""
        assert has_valid_ops(script)


# ---------------------------------------------------------------------------
# The real consumers
# ---------------------------------------------------------------------------


class TestTheCovenantBuildersRunHasValidOps:
    """``has_valid_ops`` is wired into the two build-time covenant guards.

    A function whose only callers are its own tests is the same problem as a
    constant with no consumer, one level up. These two guards are where it
    belongs: both already re-check the fully assembled scriptPubKey fail-closed
    before an asset is locked into it, and "would Radiant even decode this?" is
    the question that has to be answered before "is every push minimal?" —
    because on a script that does not decode, the minimality walk's offsets are
    reading arbitrary bytes.
    """

    @pytest.mark.parametrize(
        ("label", "spk"),
        [
            ("a byte above MAX_OPCODE", b"\x76\xa9" + bytes([MAX_OPCODE + 1])),
            ("a push whose data runs off the end", b"\x76\xa9\x20\x11\x22"),
            ("a truncated ref operand", bytes([_REF_OP]) + bytes(REF_OPERAND_WIDTH - 1)),
        ],
    )
    def test_the_htlc_guard_refuses_a_structurally_invalid_spk(self, label, spk):
        from pyrxd.gravity.htlc_covenant import _assert_minimal_pushes
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="HasValidOps"):
            _assert_minimal_pushes(spk, variant="rxd")

    @pytest.mark.parametrize(
        ("label", "spk"),
        [
            ("a byte above MAX_OPCODE", b"\x76\xa9" + bytes([MAX_OPCODE + 1])),
            ("a truncated ref operand", bytes([_REF_OP]) + bytes(REF_OPERAND_WIDTH - 1)),
        ],
    )
    def test_the_soulbound_guard_refuses_a_structurally_invalid_spk(self, label, spk):
        from pyrxd.glyph.soulbound_covenant import _assert_no_nonminimal_push
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="HasValidOps"):
            _assert_no_nonminimal_push(spk)

    def test_a_valid_spk_still_passes_both_guards(self):
        """The other half — the new precondition must not reject real covenants.

        (The full builders are covered by ``test_htlc_covenant.py``; this is the
        direct check that a well-formed P2PKH-shaped script reaches the
        minimality walk rather than being stopped by the new gate.)
        """
        from pyrxd.glyph.soulbound_covenant import _assert_no_nonminimal_push
        from pyrxd.gravity.htlc_covenant import _assert_minimal_pushes

        _assert_minimal_pushes(_P2PKH, variant="rxd")
        _assert_no_nonminimal_push(_P2PKH)

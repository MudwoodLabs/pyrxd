"""The set of ref opcodes pyrxd reads as authorisation must be consensus's set.

pyrxd shipped a relationship verifier that treated all five operand-carrying ref
opcodes as proof the transaction had spent the ref, and rendered the result
``[VERIFIED — spent in this tx]``. Two of the five are never checked against the
inputs, so anyone could mint a token naming a valuable collection they had never
touched and pyrxd would call the forgery authentic.

Nothing could have caught it. The rule lives in ``validation.h``, which was not
among the vendored consensus sources, so the differential oracle had no opinion and
every test that existed could only confirm pyrxd agreed with pyrxd. Vendoring that
file is the fix; this module is the assertion it makes possible.

Three overlapping opcode sets exist and are easy to conflate — walk-me
(:data:`REF_OPERAND_OPCODES`), summarise-me (:data:`PUSH_REF_OPCODES`), and
trust-me (:data:`INPUT_BACKED_REF_OPCODES`). They are pinned together here so the
next person to reach for one is shown the other two.
"""

from __future__ import annotations

import pytest

from pyrxd.constants import INPUT_BACKED_REF_OPCODES, PUSH_REF_OPCODES, REF_OPERAND_OPCODES
from pyrxd.glyph.relationships import output_ref_operands
from tests import consensus_oracle as oracle

REF = bytes(range(36))


def _output(opcode: int, ref: bytes = REF) -> bytes:
    """One output script naming *ref* under *opcode*, then paying to a key."""
    return bytes([opcode]) + ref + b"\x75" + bytes.fromhex("76a914") + bytes(20) + bytes.fromhex("88ac")


class TestTheConstantIsDerivedFromConsensus:
    def test_it_equals_what_the_C_source_actually_subset_checks(self) -> None:
        assert oracle.input_backed_ref_opcodes() == INPUT_BACKED_REF_OPCODES

    def test_the_oracle_names_them_rather_than_agreeing_by_accident(self) -> None:
        """A set comparison can pass on two empty sets. Pin the names too."""
        assert oracle.input_backed_ref_opcode_names() == {
            "OP_PUSHINPUTREF",
            "OP_REQUIREINPUTREF",
            "OP_PUSHINPUTREFSINGLETON",
        }

    def test_the_unbacked_two_are_exactly_the_disallow_opcodes(self) -> None:
        table = oracle.opcode_table()
        assert {
            table["OP_DISALLOWPUSHINPUTREF"],
            table["OP_DISALLOWPUSHINPUTREFSIBLING"],
        } == REF_OPERAND_OPCODES - INPUT_BACKED_REF_OPCODES

    def test_the_three_sets_are_kept_distinct(self) -> None:
        """Each is a strict answer to a different question. Any two becoming equal
        means someone unified them, which is the conflation this file exists for."""
        assert PUSH_REF_OPCODES < INPUT_BACKED_REF_OPCODES < REF_OPERAND_OPCODES


class TestForgedAuthorisationIsNotBacking:
    """The exploit: name a ref you never held, at the cost of one output."""

    @pytest.mark.parametrize("opcode", [0xD2, 0xD3], ids=["OP_DISALLOWPUSHINPUTREF", "OP_DISALLOWPUSHINPUTREFSIBLING"])
    def test_a_ref_named_by_a_disallow_opcode_is_not_backing(self, opcode: int) -> None:
        assert output_ref_operands([_output(opcode)]) == set()

    def test_a_forgery_beside_an_honest_ref_does_not_borrow_its_backing(self) -> None:
        """Two outputs, one real. Only the real ref may come back."""
        other = bytes(range(100, 136))
        backing = output_ref_operands([_output(0xD0, REF), _output(0xD3, other)])
        assert backing == {REF}

    def test_both_opcodes_in_one_script_still_yield_nothing(self) -> None:
        assert output_ref_operands([bytes([0xD2]) + REF + bytes([0xD3]) + REF + b"\x75"]) == set()


class TestHonestBackingIsStillRecognised:
    """The other half. A verifier that refuses real authorisation is also broken —
    it would report every genuine collection member as an unverified claim."""

    @pytest.mark.parametrize("opcode", sorted(INPUT_BACKED_REF_OPCODES), ids=lambda o: f"0x{o:02x}")
    def test_every_subset_checked_opcode_counts_as_backing(self, opcode: int) -> None:
        assert output_ref_operands([_output(opcode)]) == {REF}

    def test_OP_REQUIREINPUTREF_specifically(self) -> None:
        """Called out because the obvious narrowing — "only the push opcodes count" —
        drops it, and 0xd1 IS passed to validatePushRefRule against the input set.
        A require-ref in an output does prove an input carried it."""
        assert 0xD1 in INPUT_BACKED_REF_OPCODES
        assert output_ref_operands([_output(0xD1)]) == {REF}


class TestFilteringDoesNotDesynchroniseTheWalk:
    def test_a_discarded_opcodes_36_bytes_are_still_consumed(self) -> None:
        """The tempting implementation — drop 0xd2/0xd3 from the walker's opcode set —
        is wrong in a way that produces MORE backing, not less: the 36 operand bytes
        would then be read as opcodes, and a 0xd0 byte inside a ref would fabricate a
        ref that is not in the script. Here a real push FOLLOWS a discarded one, so a
        desynchronised parse cannot land on the right answer by luck."""
        script = bytes([0xD2]) + bytes([0xD0] * 36) + bytes([0xD0]) + REF + b"\x75"
        assert output_ref_operands([script]) == {REF}

    def test_a_ref_byte_inside_push_data_is_not_a_ref(self) -> None:
        script = b"\x25" + bytes([0xD0]) + bytes(36) + b"\x75"
        assert output_ref_operands([script]) == set()

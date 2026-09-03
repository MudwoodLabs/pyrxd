"""``OP_RETURN`` payload decoding must accept every push encoding a writer emits.

The walker refused every opcode above ``0x4B`` under a comment asserting those were
"not a direct or OP_PUSHDATA data push". ``0x4C`` and ``0x4D`` ARE
``OP_PUSHDATA1``/``OP_PUSHDATA2``, so the code contradicted its own comment and put
a cliff at exactly 76 bytes — the length at which every encoder in this repo, and
the HashMark spec's own §4.1 table, switches to ``OP_PUSHDATA1``.

Two consequences, both of which a hand-built fixture hides:

* **pyrxd wrote records pyrxd could not read.** ``OpReturn.lock`` emits
  ``OP_PUSHDATA1`` above 75 bytes and the ``msg`` convention is documented up to
  255, so pyrxd's own writer produced outputs its own decoder classified as
  "not a message". Only a round trip through the real writer shows this; a test
  that assembles the script by hand picks lengths under 76 without meaning to.
* **Spec-legal signed HashMark records were skipped silently** — outcome
  ``NOT_HASHMARK``, which §6 defines as "skip, not an error" — so a valid
  signature disappeared rather than being reported.

This is the guard-refuses-valid-work shape, so every case below is paired: what
must be accepted as well as what must be refused.
"""

from __future__ import annotations

import pytest

from pyrxd.script.hashmark import HashMarkOutcome, _max_label_bytes, decode_hashmark
from pyrxd.script.message import MessageOutcome, decode_message
from pyrxd.script.script import data_pushes_after_op_return
from pyrxd.script.type import OpReturn

DIGEST = bytes(range(32))


def _push(data: bytes) -> bytes:
    """Minimal push encoding, per HashMark §4.1."""
    n = len(data)
    if n <= 75:
        return bytes([n]) + data
    if n <= 255:
        return b"\x4c" + bytes([n]) + data
    return b"\x4d" + n.to_bytes(2, "little") + data


class TestPyrxdCanReadWhatPyrxdWrites:
    """Round-tripped through the production writer, NOT a hand-built script.

    The defect lives at 76 bytes. Hand-built fixtures cluster below that by
    accident, which is how this shipped."""

    @pytest.mark.parametrize("size", [1, 74, 75, 76, 77, 100, 254, 255])
    def test_a_msg_output_survives_its_own_encoder(self, size: int) -> None:
        script = bytes(OpReturn().lock([b"msg", b"H" * size]).serialize())
        record = decode_message(script)
        assert record.outcome is MessageOutcome.OK, f"{size}B written, then unreadable"
        assert record.text == "H" * size

    def test_the_cliff_was_exactly_at_the_pushdata_switch(self) -> None:
        """Pins the mechanism, not just the symptom: 75 direct, 76 OP_PUSHDATA1."""
        at75 = bytes(OpReturn().lock([b"msg", b"H" * 75]).serialize())
        at76 = bytes(OpReturn().lock([b"msg", b"H" * 76]).serialize())
        assert at75[5] == 75 and at76[5] == 0x4C
        assert decode_message(at75).outcome is decode_message(at76).outcome is MessageOutcome.OK


class TestPushEncodingsAcceptedAndRefused:
    _ACCEPT = {
        "direct 1": b"\x01A",
        "direct 75": b"\x4b" + b"A" * 75,
        "OP_PUSHDATA1 at its floor": b"\x4c\x4c" + b"A" * 76,
        "OP_PUSHDATA2 at its floor": b"\x4d\x00\x01" + b"A" * 256,
    }
    _REFUSE = {
        "OP_1NEGATE": b"\x4f",
        "OP_1": b"\x51",
        "OP_16": b"\x60",
        "OP_PUSHDATA4": b"\x4e\x08\x00\x00\x00" + b"A" * 8,
        "a non-push opcode": b"\x76",
        "a push past the end": b"\x20\x01\x02",
    }

    @pytest.mark.parametrize("body", _ACCEPT.values(), ids=list(_ACCEPT))
    def test_accepted(self, body: bytes) -> None:
        assert data_pushes_after_op_return(b"\x6a" + body) is not None

    @pytest.mark.parametrize("body", _REFUSE.values(), ids=list(_REFUSE))
    def test_refused(self, body: bytes) -> None:
        assert data_pushes_after_op_return(b"\x6a" + body) is None

    def test_OP_0_is_a_push_for_msg_and_not_for_hashmark(self) -> None:
        """``OP_0`` is a second spelling of the empty push, so §4.1 refuses it — but
        only under strict mode. Refusing it everywhere downgraded a ``msg`` whose
        payload is ``OP_0`` from "malformed, empty push" to "not a message", which
        is a guard refusing valid work: the record plainly IS a message."""
        assert data_pushes_after_op_return(b"\x6a\x00") == [b""]
        assert data_pushes_after_op_return(b"\x6a\x00", require_minimal=True) is None

    def test_a_script_that_is_not_an_op_return_is_refused(self) -> None:
        assert data_pushes_after_op_return(bytes.fromhex("76a914") + bytes(20) + bytes.fromhex("88ac")) is None


class TestMinimalityIsStrictForHashMarkAndLenientForMsg:
    """§4.1 exists so every HashMark record has ONE serialization — two verifiers
    that disagree about the same bytes is the failure this project cares about.
    ``msg`` has no canonical form to protect, so refusing a third-party writer's
    honest text over its choice of length prefix would be a guard refusing valid
    work."""

    NON_MINIMAL = b"\x6a\x4c\x08" + b"HASHMARK"

    def test_msg_walker_accepts_a_non_minimal_push(self) -> None:
        assert data_pushes_after_op_return(self.NON_MINIMAL) == [b"HASHMARK"]

    def test_hashmark_walker_refuses_it(self) -> None:
        assert data_pushes_after_op_return(self.NON_MINIMAL, require_minimal=True) is None

    @pytest.mark.parametrize(
        "raw,label",
        [(b"\x4c\x08" + b"A" * 8, "OP_PUSHDATA1 under 76"), (b"\x4d\x08\x00" + b"A" * 8, "OP_PUSHDATA2 under 256")],
    )
    def test_each_non_minimal_opcode_is_caught(self, raw: bytes, label: str) -> None:
        assert data_pushes_after_op_return(b"\x6a" + raw, require_minimal=True) is None, label

    def test_a_non_minimally_encoded_hashmark_is_NOT_A_HASHMARK(self) -> None:
        """Not INVALID. The bytes are not a record of this format at all, and §6
        says to skip what is not a HashMark rather than report it as broken."""
        raw = b"\x6a" + b"\x4c\x08" + b"HASHMARK" + _push(bytes([1, 1])) + _push(DIGEST)
        assert decode_hashmark(raw).outcome is HashMarkOutcome.NOT_HASHMARK


class TestSpecLegalRecordsAreNoLongerSkipped:
    @pytest.mark.parametrize("size", [76, 88, 100, 128])
    def test_a_v1_label_needing_OP_PUSHDATA1_decodes(self, size: int) -> None:
        raw = b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(DIGEST) + _push(b"x" * size)
        record = decode_hashmark(raw)
        assert record.ok and record.label == "x" * size

    def test_a_v2_label_at_the_derived_cap_decodes(self) -> None:
        cap = _max_label_bytes(32)
        raw = (
            b"\x6a"
            + _push(b"HASHMARK")
            + _push(bytes([2, 1]))
            + _push(DIGEST)
            + _push(bytes(20))
            + _push(bytes(65))
            + _push(b"x" * cap)
        )
        assert decode_hashmark(raw).label == "x" * cap


class TestTheLabelCapIsDerivedNotGuessed:
    """It was hardcoded to 223 — the whole-RECORD ceiling mistaken for the label's
    share of it — and was unreachable only because the walker refused every
    OP_PUSHDATA1. Fixing the walker is what made this load-bearing."""

    def test_sha256_gives_the_spec_number(self) -> None:
        assert _max_label_bytes(32) == 88

    @pytest.mark.parametrize("digest_len", [20, 32, 48, 64])
    def test_a_record_at_the_cap_exactly_fills_the_ceiling(self, digest_len: int) -> None:
        """Derivation check with teeth: one byte more must not fit."""
        from pyrxd.script.hashmark import _MAX_RECORD_BYTES, _encoded_push_size

        fixed = 1 + sum(_encoded_push_size(n) for n in (8, 2, digest_len, 20, 65))
        cap = _max_label_bytes(digest_len)
        assert fixed + _encoded_push_size(cap) <= _MAX_RECORD_BYTES
        assert fixed + _encoded_push_size(cap + 1) > _MAX_RECORD_BYTES

    def test_a_longer_digest_shrinks_the_label(self) -> None:
        assert _max_label_bytes(64) < _max_label_bytes(32) < _max_label_bytes(20)

    def test_an_over_cap_v2_label_is_INVALID(self) -> None:
        cap = _max_label_bytes(32)
        raw = (
            b"\x6a"
            + _push(b"HASHMARK")
            + _push(bytes([2, 1]))
            + _push(DIGEST)
            + _push(bytes(20))
            + _push(bytes(65))
            + _push(b"x" * (cap + 1))
        )
        record = decode_hashmark(raw)
        assert record.outcome is HashMarkOutcome.INVALID and "label" in (record.detail or "")

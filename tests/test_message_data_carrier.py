"""The Photonic ``msg`` convention — the only OP_RETURN format with real volume.

``OP_RETURN PUSH3 "msg" <push> <message>``. pyrxd already WROTE these (the dMint
miner's ``op_return_msg``, bounded by ``MAX_OP_RETURN_MSG_BYTES``) and could not
read one back, so the commonest data output on the chain rendered as opaque hex.

Measured on 20 consecutive mainnet blocks: **73 of 73** ``OP_RETURN`` outputs
carried this marker, and nothing else did.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph._inspect_core import _inspect_script
from pyrxd.script.message import MSG_MARKER, MessageOutcome, decode_message


def _push(b: bytes) -> bytes:
    return (bytes([len(b)]) + b) if len(b) <= 0x4B else (b"\x4c" + bytes([len(b)]) + b)


def _msg(body: bytes) -> bytes:
    return b"\x6a" + _push(MSG_MARKER) + _push(body)


#: A REAL output, copied byte-for-byte off Radiant mainnet. Chosen because it is
#: not the clean case anyone would invent: "Radiate " + U+1F31E + a NUL + "33".
#: Real data carries control characters, and a fixture that only ever holds tidy
#: ASCII cannot show whether the display path handles what the chain contains.
_REAL_MAINNET = bytes.fromhex("6a036d73670f5261646961746520f09f8c9e003333")


class TestRealMainnetOutput:
    def test_it_decodes(self) -> None:
        r = decode_message(_REAL_MAINNET)
        assert r.ok and r.is_utf8
        assert r.raw == b"Radiate \xf0\x9f\x8c\x9e\x0033"
        assert r.text is not None and r.text.startswith("Radiate \U0001f31e")

    def test_the_classifier_sanitises_the_control_byte_for_display(self) -> None:
        """The decoder returns the bytes unmangled — a caller verifying a
        commitment needs them — and the DISPLAY boundary sanitises. The NUL in
        this real message is what proves the two are separate."""
        row = _inspect_script(_REAL_MAINNET.hex())
        assert row["type"] == "op_return-msg"
        assert "\x00" not in row["message"]["text"]
        assert row["message"]["byte_length"] == 15


class TestDecoding:
    def test_utf8_text(self) -> None:
        r = decode_message(_msg(b"gm radiant"))
        assert r.ok and r.text == "gm radiant" and r.is_utf8

    def test_non_utf8_is_REPORTED_not_refused(self) -> None:
        """The bytes are already on chain and nothing constrains them to text.
        Refusing would lose a record we can otherwise describe exactly."""
        r = decode_message(_msg(b"\xff\xfe\x00"))
        assert r.ok and r.is_utf8 is False and r.text is None
        assert r.raw == b"\xff\xfe\x00"

    @pytest.mark.parametrize(
        ("script", "why"),
        [
            (b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac", "a P2PKH"),
            (b"\x6a" + _push(b"OTHER") + _push(b"x"), "another protocol's marker"),
            (b"\x6a", "a bare OP_RETURN"),
            (b"", "empty"),
        ],
    )
    def test_anything_else_is_skipped_silently(self, script: bytes, why: str) -> None:
        assert decode_message(script).outcome is MessageOutcome.NOT_MESSAGE, why

    @pytest.mark.parametrize(
        ("script", "why"),
        [
            (b"\x6a" + _push(MSG_MARKER), "marker with no message"),
            (b"\x6a" + _push(MSG_MARKER) + _push(b"a") + _push(b"b"), "a third push"),
            (b"\x6a" + _push(MSG_MARKER) + b"\x00", "empty message push"),
        ],
    )
    def test_a_claimed_message_that_is_malformed_is_reported(self, script: bytes, why: str) -> None:
        """Past the marker the output claims to be a message, so a bad shape is a
        defect rather than another protocol."""
        assert decode_message(script).outcome is MessageOutcome.INVALID, why


class TestItStaysAdditive:
    def test_a_non_message_data_output_is_unchanged(self) -> None:
        row = _inspect_script((b"\x6a" + _push(b"OTHERPROTO") + _push(b"payload here, long enough")).hex())
        assert row["type"] == "op_return"
        assert "message" not in row

    def test_a_hashmark_is_not_claimed_as_a_message(self) -> None:
        """Two decoders on the same branch must not fight over one script."""
        hm = b"\x6a" + _push(b"HASHMARK") + _push(bytes([1, 1])) + _push(bytes(32))
        row = _inspect_script(hm.hex())
        assert row["type"] == "op_return-hashmark-v1"
        assert "message" not in row

"""Tests for the pyrxd.contrib.miner JSON-over-stdio wire protocol.

Pure data-shape tests; no subprocess spawn, no mining. These pin the
contract that the miner (``pyrxd.contrib.miner.cli.main``) and the
verifier (``pyrxd.glyph.dmint.mine_solution_external``) agree on.

If either side serializes/parses a shape this test doesn't accept,
they have drifted and need updating together.
"""

from __future__ import annotations

import json

import pytest

from pyrxd.contrib.miner.protocol import (
    MAX_PROGRESS_LINE_BYTES,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    MineExhausted,
    MineProgress,
    MineRequest,
    MineSuccess,
    ProtocolError,
    parse_progress_line,
    parse_response,
)

# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


class TestMineRequestFromJson:
    """``MineRequest.from_json`` accepts well-formed wire requests and
    rejects everything else loudly."""

    def _valid_payload(self, **overrides: object) -> dict[str, object]:
        payload: dict[str, object] = {
            "preimage_hex": "ab" * 64,
            "target_hex": "7fffffffffffffff",
            "nonce_width": 4,
        }
        payload.update(overrides)
        return payload

    def test_minimal_v1_request(self):
        req = MineRequest.from_json(json.dumps(self._valid_payload()))
        assert req.preimage == bytes.fromhex("ab" * 64)
        assert req.target == 0x7FFFFFFFFFFFFFFF
        assert req.nonce_width == 4
        assert req.protocol == PROTOCOL_VERSION

    def test_v2_request_with_8_byte_nonce(self):
        req = MineRequest.from_json(json.dumps(self._valid_payload(nonce_width=8)))
        assert req.nonce_width == 8

    def test_bytes_input_accepted(self):
        """The CLI reads stdin.buffer (bytes), so from_json must accept bytes."""
        req = MineRequest.from_json(json.dumps(self._valid_payload()).encode())
        assert req.nonce_width == 4

    def test_explicit_protocol_v1_accepted(self):
        req = MineRequest.from_json(json.dumps(self._valid_payload(protocol=1)))
        assert req.protocol == 1

    def test_unknown_protocol_version_rejected(self):
        with pytest.raises(ProtocolError, match="unsupported protocol version"):
            MineRequest.from_json(json.dumps(self._valid_payload(protocol=99)))

    def test_non_json_rejected(self):
        with pytest.raises(ProtocolError, match="not valid JSON"):
            MineRequest.from_json("not json {")

    def test_non_object_rejected(self):
        with pytest.raises(ProtocolError, match="must be a JSON object"):
            MineRequest.from_json("[1, 2, 3]")

    def test_missing_preimage_hex_rejected(self):
        payload = self._valid_payload()
        del payload["preimage_hex"]
        with pytest.raises(ProtocolError, match="preimage_hex"):
            MineRequest.from_json(json.dumps(payload))

    def test_missing_target_hex_rejected(self):
        payload = self._valid_payload()
        del payload["target_hex"]
        with pytest.raises(ProtocolError, match="target_hex"):
            MineRequest.from_json(json.dumps(payload))

    def test_missing_nonce_width_rejected(self):
        payload = self._valid_payload()
        del payload["nonce_width"]
        with pytest.raises(ProtocolError, match="nonce_width"):
            MineRequest.from_json(json.dumps(payload))

    def test_non_hex_preimage_rejected(self):
        with pytest.raises(ProtocolError, match="preimage_hex.*hex"):
            MineRequest.from_json(json.dumps(self._valid_payload(preimage_hex="xyz")))

    def test_wrong_length_preimage_rejected(self):
        with pytest.raises(ProtocolError, match="preimage must be 64 bytes"):
            MineRequest.from_json(json.dumps(self._valid_payload(preimage_hex="ab" * 32)))

    def test_negative_target_rejected(self):
        with pytest.raises(ProtocolError, match="target must be positive"):
            MineRequest.from_json(json.dumps(self._valid_payload(target_hex="0")))

    def test_invalid_nonce_width_rejected(self):
        with pytest.raises(ProtocolError, match="nonce_width.*4 or 8"):
            MineRequest.from_json(json.dumps(self._valid_payload(nonce_width=6)))

    def test_nonce_width_bool_rejected(self):
        """Booleans are int subclasses in Python; reject them explicitly."""
        with pytest.raises(ProtocolError, match="nonce_width"):
            MineRequest.from_json(json.dumps(self._valid_payload(nonce_width=True)))

    def test_oversize_payload_rejected_bytes(self):
        oversize = b"x" * (MAX_REQUEST_BYTES + 1)
        with pytest.raises(ProtocolError, match="too large"):
            MineRequest.from_json(oversize)

    def test_oversize_payload_rejected_str(self):
        oversize = "x" * (MAX_REQUEST_BYTES + 1)
        with pytest.raises(ProtocolError, match="too large"):
            MineRequest.from_json(oversize)


# ---------------------------------------------------------------------------
# Response serialization
# ---------------------------------------------------------------------------


class TestMineSuccessToJson:
    def test_success_round_trip_through_parse_response(self):
        succ = MineSuccess(nonce=b"\x01\x02\x03\x04", attempts=12345, elapsed_s=1.5)
        parsed = parse_response(succ.to_json())
        assert isinstance(parsed, MineSuccess)
        assert parsed.nonce == succ.nonce
        assert parsed.attempts == succ.attempts
        assert parsed.elapsed_s == succ.elapsed_s

    def test_nan_elapsed_s_rejected_at_serialize_time(self):
        """A buggy miner producing NaN should fail loudly at our boundary,
        not be silently rejected later by pyrxd's verifier."""
        succ = MineSuccess(nonce=b"\x01\x02\x03\x04", attempts=1, elapsed_s=float("nan"))
        with pytest.raises(ProtocolError, match="finite"):
            succ.to_json()


class TestMineExhaustedToJson:
    def test_exhausted_serialized_shape(self):
        assert json.loads(MineExhausted().to_json()) == {"exhausted": True}

    def test_exhausted_round_trip_through_parse_response(self):
        parsed = parse_response(MineExhausted().to_json())
        assert isinstance(parsed, MineExhausted)


# ---------------------------------------------------------------------------
# Response parsing (verifier side)
# ---------------------------------------------------------------------------


class TestParseResponse:
    def test_success_shape(self):
        raw = json.dumps({"nonce_hex": "deadbeef", "attempts": 100, "elapsed_s": 0.5})
        result = parse_response(raw)
        assert isinstance(result, MineSuccess)
        assert result.nonce == bytes.fromhex("deadbeef")

    def test_exhausted_shape(self):
        result = parse_response('{"exhausted": true}')
        assert isinstance(result, MineExhausted)

    def test_bytes_input_accepted(self):
        result = parse_response(b'{"exhausted": true}')
        assert isinstance(result, MineExhausted)

    def test_oversize_rejected_bytes(self):
        with pytest.raises(ProtocolError, match="too large"):
            parse_response(b"x" * (MAX_RESPONSE_BYTES + 1))

    def test_non_finite_elapsed_s_rejected(self):
        """parse_response rejects NaN/Inf even though json.loads accepts them.

        Mirrors pyrxd's defense in mine_solution_external: a malicious or
        buggy miner that writes ``NaN`` could otherwise poison downstream
        metrics aggregators.
        """
        raw = '{"nonce_hex": "01", "attempts": 1, "elapsed_s": NaN}'
        with pytest.raises(ProtocolError, match="finite"):
            parse_response(raw)

    def test_negative_attempts_rejected(self):
        raw = json.dumps({"nonce_hex": "01", "attempts": -1, "elapsed_s": 0.0})
        with pytest.raises(ProtocolError, match="non-negative"):
            parse_response(raw)

    def test_attempts_bool_rejected(self):
        """Booleans pass int isinstance checks; reject explicitly so a
        miner returning ``true`` for attempts fails loudly."""
        raw = json.dumps({"nonce_hex": "01", "attempts": True, "elapsed_s": 0.0})
        with pytest.raises(ProtocolError, match="attempts.*integer"):
            parse_response(raw)

    def test_non_hex_nonce_rejected(self):
        raw = json.dumps({"nonce_hex": "xyz", "attempts": 1, "elapsed_s": 0.0})
        with pytest.raises(ProtocolError, match="nonce_hex.*hex"):
            parse_response(raw)

    def test_malformed_json_rejected(self):
        with pytest.raises(ProtocolError, match="not valid JSON"):
            parse_response("not json")

    def test_non_object_rejected(self):
        with pytest.raises(ProtocolError, match="must be a JSON object"):
            parse_response("[]")


# ---------------------------------------------------------------------------
# Progress frames (stderr, optional, added after 0.13.0)
# ---------------------------------------------------------------------------


class TestMineProgressToJson:
    def test_round_trip_through_parse_progress_line(self):
        prog = MineProgress(attempts=12345, elapsed_s=1.5)
        parsed = parse_progress_line(prog.to_json())
        assert isinstance(parsed, MineProgress)
        assert parsed.attempts == 12345
        assert parsed.elapsed_s == 1.5

    def test_serialized_shape_is_wrapped_under_progress_key(self):
        """Progress frames nest under a "progress" key -- structurally
        distinct from MineSuccess's flat {"nonce_hex", ...} shape, so a
        line can never be ambiguous between the two."""
        assert json.loads(MineProgress(attempts=1, elapsed_s=0.5).to_json()) == {
            "progress": {"attempts": 1, "elapsed_s": 0.5}
        }

    def test_nan_elapsed_s_rejected_at_serialize_time(self):
        prog = MineProgress(attempts=1, elapsed_s=float("nan"))
        with pytest.raises(ProtocolError, match="finite"):
            prog.to_json()


class TestParseProgressLine:
    """parse_progress_line fails SOFT (returns None), never raises --
    progress is a display hint, not a trust boundary."""

    def test_valid_frame(self):
        raw = json.dumps({"progress": {"attempts": 42, "elapsed_s": 0.25}})
        parsed = parse_progress_line(raw)
        assert isinstance(parsed, MineProgress)
        assert parsed.attempts == 42
        assert parsed.elapsed_s == 0.25

    def test_bytes_input_accepted(self):
        raw = json.dumps({"progress": {"attempts": 1, "elapsed_s": 0.0}}).encode()
        parsed = parse_progress_line(raw)
        assert isinstance(parsed, MineProgress)

    def test_blank_line_returns_none(self):
        assert parse_progress_line("") is None
        assert parse_progress_line("   \n") is None

    def test_non_json_returns_none_not_raise(self):
        assert parse_progress_line("this is a debug log line, not JSON") is None

    def test_non_object_json_returns_none(self):
        assert parse_progress_line("[1, 2, 3]") is None

    def test_missing_progress_key_returns_none(self):
        """A MineSuccess-shaped line (what a confused/hostile miner might
        write to stderr) has no "progress" key -- never parses as one."""
        raw = json.dumps({"nonce_hex": "deadbeef", "attempts": 1, "elapsed_s": 0.1})
        assert parse_progress_line(raw) is None

    def test_progress_value_not_object_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": "not an object"})) is None

    def test_missing_attempts_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": {"elapsed_s": 0.1}})) is None

    def test_missing_elapsed_s_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": {"attempts": 1}})) is None

    def test_negative_attempts_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": {"attempts": -1, "elapsed_s": 0.0}})) is None

    def test_attempts_over_cap_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": {"attempts": 1 << 41, "elapsed_s": 0.0}})) is None

    def test_bool_attempts_returns_none(self):
        """Booleans are int subclasses in Python; reject explicitly."""
        assert parse_progress_line(json.dumps({"progress": {"attempts": True, "elapsed_s": 0.0}})) is None

    def test_bool_elapsed_s_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": {"attempts": 1, "elapsed_s": True}})) is None

    def test_non_finite_elapsed_s_returns_none(self):
        raw = '{"progress": {"attempts": 1, "elapsed_s": NaN}}'
        assert parse_progress_line(raw) is None

    def test_negative_elapsed_s_returns_none(self):
        assert parse_progress_line(json.dumps({"progress": {"attempts": 1, "elapsed_s": -1.0}})) is None

    def test_oversize_line_returns_none_bytes(self):
        oversize = b'{"progress": {"attempts": ' + b"1" * MAX_PROGRESS_LINE_BYTES + b"}}"
        assert len(oversize) > MAX_PROGRESS_LINE_BYTES
        assert parse_progress_line(oversize) is None

    def test_oversize_line_returns_none_str(self):
        oversize = "x" * (MAX_PROGRESS_LINE_BYTES + 1)
        assert parse_progress_line(oversize) is None

    def test_non_utf8_bytes_returns_none(self):
        assert parse_progress_line(b"\xff\xfe\x00\x01") is None

    def test_smuggled_nonce_field_is_ignored(self):
        """A well-formed progress frame that ALSO carries a sibling
        nonce_hex key still parses -- but only ever yields the
        (attempts, elapsed_s) MineProgress shape. There is no code path
        by which a nonce could ride along on this object."""
        raw = json.dumps(
            {
                "progress": {"attempts": 7, "elapsed_s": 0.2},
                "nonce_hex": "deadbeef",
            }
        )
        parsed = parse_progress_line(raw)
        assert isinstance(parsed, MineProgress)
        assert parsed.attempts == 7
        assert parsed.elapsed_s == 0.2
        assert not hasattr(parsed, "nonce_hex")

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
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    MineExhausted,
    MineRequest,
    MineSuccess,
    ProtocolError,
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

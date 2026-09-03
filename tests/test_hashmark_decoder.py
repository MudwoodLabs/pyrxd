"""HashMark decoding — a THIRD-PARTY OP_RETURN format we read but never write.

Spec: HASHMARK_PROTOCOL.md in github.com/cdonnachie/hashmark.rxd (MIT). It is
written to be implementable without access to its codebase, and this suite is
the check on whether we managed that: the cases below are the spec's own rules,
not our implementation's shape.
"""

from __future__ import annotations

import pytest

from pyrxd.script.hashmark import HASHMARK_MAGIC, HashMarkOutcome, decode_hashmark


def _push(b: bytes) -> bytes:
    assert len(b) <= 0x4B, "these fixtures stay inside the direct-push range"
    return bytes([len(b)]) + b


def _record(*pushes: bytes) -> bytes:
    return b"\x6a" + b"".join(_push(p) for p in pushes)


_HDR_V1 = bytes([1, 1])
_HDR_V2 = bytes([2, 1])
_DIGEST = bytes(range(32))


class TestNotAHashMarkIsNotAnError:
    """A block scanner meets thousands of other protocols' OP_RETURN outputs.
    Reporting them as errors buries the real ones, which is why the spec keeps
    NOT_HASHMARK distinct from INVALID."""

    @pytest.mark.parametrize(
        ("script", "why"),
        [
            (b"", "empty script"),
            (b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac", "an ordinary P2PKH"),
            (_record(b"OTHER", b"payload"), "another protocol's data output"),
            (b"\x6a", "a bare OP_RETURN carrying nothing"),
            (b"\x00\x6a" + _push(HASHMARK_MAGIC), "OP_FALSE-prefixed: script[0] is not OP_RETURN"),
        ],
    )
    def test_skipped_silently(self, script: bytes, why: str) -> None:
        assert decode_hashmark(script).outcome is HashMarkOutcome.NOT_HASHMARK, why


class TestWellFormedRecords:
    def test_v1_without_a_label(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST))
        assert r.ok and r.version == 1 and r.algorithm == "sha256"
        assert r.digest_hex == _DIGEST.hex()
        assert r.label is None and r.signature_hex is None

    def test_v1_with_a_label(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST, b"invoice.pdf"))
        assert r.ok and r.label == "invoice.pdf"

    def test_v2_carries_a_signer_and_an_UNVERIFIED_signature(self) -> None:
        """Decoding is not attestation. Verifying the signature needs secp256k1
        and the chain the tx was found on, so this module returns it unchecked —
        and the field name has to say so, or a caller will read a decoded record
        as a believed one."""
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V2, _DIGEST, b"\xaa" * 20, b"\xbb" * 65))
        assert r.ok and r.version == 2
        assert r.signer_hash160_hex == "aa" * 20
        assert r.signature_hex == "bb" * 65

    def test_the_digest_is_rendered_lowercase(self) -> None:
        """The spec requires uppercase hex be REJECTED rather than normalised, so
        a digest has exactly one accepted spelling. We only render, so the
        obligation here is to never emit the other one."""
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V1, b"\xab" * 32))
        assert r.digest_hex == "ab" * 32


class TestAClaimedHashMarkThatIsMalformed:
    """Past the magic the output CLAIMS to be a HashMark, so every remaining
    failure is a genuine defect rather than another protocol."""

    def test_header_of_the_wrong_width(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, bytes([1]), _DIGEST))
        assert r.outcome is HashMarkOutcome.INVALID

    def test_a_short_digest_is_refused_at_the_REGISTRY_length(self) -> None:
        """The length comes from the algorithm registry, never from the push.
        Trusting the push is what would let a truncated digest be accepted at the
        wrong width — the whole reason the spec states it that way."""
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST[:16]))
        assert r.outcome is HashMarkOutcome.INVALID
        assert "16 bytes" in (r.detail or "")

    @pytest.mark.parametrize("n_extra", [1, 2])
    def test_wrong_push_count_for_the_version(self, n_extra: int) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST, *([b"x"] * (n_extra + 1))))
        assert r.outcome is HashMarkOutcome.INVALID

    def test_v2_signer_of_the_wrong_width(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V2, _DIGEST, b"\xaa" * 19, b"\xbb" * 65))
        assert r.outcome is HashMarkOutcome.INVALID

    def test_a_label_that_is_not_utf8(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST, b"\xff\xfe"))
        assert r.outcome is HashMarkOutcome.INVALID


class TestUnimplementedIsNotBroken:
    """A record from the future is not corrupt. Reporting it as malformed would
    make every later version look like damage and discourage anyone shipping
    one — the spec's words, and the reason these are separate outcomes."""

    def test_a_newer_version_reports_its_version(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, bytes([3, 1]), _DIGEST))
        assert r.outcome is HashMarkOutcome.UNKNOWN_VERSION
        assert r.version == 3

    def test_an_unassigned_algorithm_reports_its_id(self) -> None:
        r = decode_hashmark(_record(HASHMARK_MAGIC, bytes([1, 0x02]), _DIGEST))
        assert r.outcome is HashMarkOutcome.UNKNOWN_ALGORITHM
        assert r.algorithm_id == 0x02


class TestTheInspectorSurfacesIt:
    """Reachability: a decoder nothing calls is not finished. These go through
    the production classifier, not the decoder directly."""

    @staticmethod
    def _classify(script: bytes) -> dict:
        from pyrxd.glyph._inspect_core import _inspect_script

        return _inspect_script(script.hex())

    def test_a_hashmark_output_classifies_as_one(self) -> None:
        row = self._classify(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST, b"invoice.pdf"))
        assert row["type"] == "op_return-hashmark-v1"
        assert row["hashmark"]["digest"] == _DIGEST.hex()
        assert row["hashmark"]["label"] == "invoice.pdf"
        assert row["data_hex"], "the raw data is still surfaced — the decode is additive"

    def test_a_malformed_hashmark_is_reported_not_hidden(self) -> None:
        row = self._classify(_record(HASHMARK_MAGIC, _HDR_V1, _DIGEST[:16]))
        assert row["type"] == "op_return", "a malformed record must not be claimed as a valid mark"
        assert row["hashmark"]["outcome"] == "invalid"

    def test_a_plain_data_output_stays_EXACTLY_as_it_was(self) -> None:
        """Additive, not disruptive. Another protocol's data output keeps
        classifying as it did before, with no hashmark key at all."""
        row = self._classify(_record(b"OTHER", b"data"))
        assert row["type"] == "op_return"
        assert "hashmark" not in row

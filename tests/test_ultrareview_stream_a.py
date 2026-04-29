"""Regression tests for Wave 1 Stream A — cryptographic correctness fixes.

Each test corresponds to a finding from the eight-reviewer ultrareview at
docs/ultrareview-2026-04-25.md. These pin the fixes so future refactors
cannot reintroduce the bug class.
"""
from __future__ import annotations

import pytest

from pyrxd.glyph.dmint import DaaMode, _build_part_b
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction_preimage import _get_push_refs
from pyrxd.utils import deserialize_ecdsa_der, serialize_ecdsa_der


# ---------------------------------------------------------------------------
# DER signature parser strictness (code-quality finding #1, critical)
# ---------------------------------------------------------------------------


class TestDerStrict:
    def test_round_trip_canonical_signatures(self):
        """Strict DER round-trips known canonical (r, s) pairs unchanged."""
        for r, s in [
            (1, 1),
            (0xFFFF, 0x7FFF),
            (0x80000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001,
             0x40000000_00000000_00000000_00000000_00000000_00000000_00000000_00000001),
        ]:
            sig = serialize_ecdsa_der((r, s))
            assert deserialize_ecdsa_der(sig) == (r, s)

    def test_total_length_mismatch_rejected(self):
        """Earlier versions sliced ``s`` from the end of buffer; tampered
        total-length now fails strict r_len + s_len + 6 == len() check."""
        sig = serialize_ecdsa_der((0xAA, 0xBB))
        # Append junk bytes — total_len byte still says original length
        tampered = sig + b'\xCC\xDD'
        with pytest.raises(ValueError, match="DER length mismatch"):
            deserialize_ecdsa_der(tampered)

    def test_r_len_overruns_buffer_rejected(self):
        """A declared r_len that runs past the buffer must raise."""
        # 30 06 02 09 ... (r_len=9 but only 4 r bytes follow)
        bad = bytes.fromhex("3006020901020304020100")
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(bad)

    def test_zero_r_len_rejected(self):
        """r_len = 0 is not a valid DER signature."""
        bad = bytes.fromhex("3006020002020100")
        with pytest.raises(ValueError, match="r length is zero"):
            deserialize_ecdsa_der(bad)

    def test_zero_s_len_rejected(self):
        bad = bytes.fromhex("3006020100020000")
        with pytest.raises(ValueError, match="s length is zero"):
            deserialize_ecdsa_der(bad)

    def test_too_short_rejected(self):
        with pytest.raises(ValueError, match="too short"):
            deserialize_ecdsa_der(b"\x30\x04\x02\x01\x01")

    def test_attacker_chosen_s_via_negative_index_no_longer_works(self):
        """The original bug: ``signature[-s_len:]`` slices from the end
        regardless of declared offsets. Construct a signature where the
        declared structure points one place but the negative slice points
        elsewhere — strict parsing must reject."""
        # Declare total_len = 0x0a (10), r_len = 2, s_len = 2.
        # Then add 4 trailing bytes that the negative slice would have grabbed.
        # Total declared layout: 30 0a 02 02 r1 r2 02 02 s1 s2  (12 bytes total)
        # Tampered: total_len byte still says 0x0a but real length is 14.
        tampered = bytes.fromhex("300a02020a0b02020c0dDEADBEEF")
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(tampered)


# ---------------------------------------------------------------------------
# _get_push_refs truncation guard (code-quality finding #2, critical)
# ---------------------------------------------------------------------------


class TestGetPushRefsTruncation:
    def test_truncated_pushref_raises(self):
        """A pushref opcode followed by fewer than 36 bytes is malformed
        and must raise rather than silently produce a short ref entry."""
        # OP_PUSHINPUTREFSINGLETON (0xd8) with only 10 bytes of "ref" data
        truncated = bytes([0xd8]) + bytes(10)
        with pytest.raises(ValidationError, match="truncated pushref"):
            _get_push_refs(truncated)

    def test_truncated_pushref_normal_raises(self):
        truncated = bytes([0xd0]) + bytes(35)  # one byte short
        with pytest.raises(ValidationError, match="truncated pushref"):
            _get_push_refs(truncated)

    def test_consensus_dedup_preserved(self):
        """Sort + dedup is consensus-required (matches radiantjs and the
        mainnet-verified vector at tests/test_preimage.py). Pin it here."""
        ref = bytes(range(36))
        script = bytes([0xd8]) + ref + bytes([0xd8]) + ref
        assert len(_get_push_refs(script)) == 1

    def test_count_invariant_matches_unique_pushref_count(self):
        """Per Kieran's tech-review request: pin the count invariant
        explicitly so the dedup behavior cannot be silently changed.

        For N pushref opcodes with K distinct refs, _get_push_refs returns
        exactly K entries, sorted. Test 5 distinct refs duplicated 3x each
        → 15 opcodes → 5 returned entries (sorted).
        """
        refs = [bytes([i]) + bytes(35) for i in (0x05, 0x01, 0x04, 0x02, 0x03)]
        # Build script with 3 copies of each ref, in shuffled order
        script = b""
        for r in refs * 3:
            script += bytes([0xd0]) + r
        result = _get_push_refs(script)
        assert len(result) == 5  # 5 distinct refs, dedup applied
        # Sort order is by hex(); 0x01... sorts before 0x02... etc.
        assert result[0][0] == 0x01
        assert result[1][0] == 0x02
        assert result[2][0] == 0x03
        assert result[3][0] == 0x04
        assert result[4][0] == 0x05


# ---------------------------------------------------------------------------
# DaaMode unsupported variants raise (code-quality finding #3, critical)
# ---------------------------------------------------------------------------


class TestDaaModeNotImplemented:
    def test_epoch_raises(self):
        with pytest.raises(NotImplementedError, match="EPOCH"):
            _build_part_b(DaaMode.EPOCH, half_life=600)

    def test_schedule_raises(self):
        with pytest.raises(NotImplementedError, match="SCHEDULE"):
            _build_part_b(DaaMode.SCHEDULE, half_life=600)

    def test_fixed_returns_no_daa_bytes(self):
        """FIXED is the documented "no DAA" mode and must succeed."""
        result = _build_part_b(DaaMode.FIXED, half_life=0)
        assert isinstance(result, bytes)

    def test_asert_emits_daa_bytes(self):
        result_fixed = _build_part_b(DaaMode.FIXED, half_life=0)
        result_asert = _build_part_b(DaaMode.ASERT, half_life=600)
        # ASERT must add bytecode that FIXED does not
        assert len(result_asert) > len(result_fixed)

    def test_lwma_emits_daa_bytes(self):
        result_fixed = _build_part_b(DaaMode.FIXED, half_life=0)
        result_lwma = _build_part_b(DaaMode.LWMA, half_life=0)
        assert len(result_lwma) > len(result_fixed)


# ---------------------------------------------------------------------------
# CBOR canonical encoding (data-integrity finding #5, high)
# ---------------------------------------------------------------------------


class TestCborCanonical:
    def test_encode_payload_is_canonical_across_field_orderings(self):
        """Two GlyphMetadata that differ only in optional-field-set order
        must produce byte-identical CBOR."""
        meta_a = GlyphMetadata.for_dmint_ft(
            ticker="TST",
            name="Test Token",
            image_url="https://example.org/test-logo.png",
            image_ipfs="ipfs://bafy...",
            image_sha256="0" * 64,
        )
        # Construct a second instance with the same data but via the
        # explicit GlyphMetadata constructor — the input dict order to
        # cbor2 may be different.
        meta_b = GlyphMetadata(
            protocol=[GlyphProtocol.FT, GlyphProtocol.DMINT],
            name="Test Token",
            ticker="TST",
            decimals=0,
            image_sha256="0" * 64,
            image_ipfs="ipfs://bafy...",
            image_url="https://example.org/test-logo.png",
        )
        cbor_a, _ = encode_payload(meta_a)
        cbor_b, _ = encode_payload(meta_b)
        assert cbor_a == cbor_b, (
            "CBOR encoding must be byte-identical for the same logical "
            "metadata regardless of optional-field source-code ordering. "
            "If this fails, canonical=True is not being applied."
        )

    def test_encoded_keys_appear_in_canonical_order(self):
        """Canonical CBOR sorts map keys by length-then-lex per RFC 8949
        §4.2.1. Spot-check on a small payload."""
        meta = GlyphMetadata.for_dmint_ft(
            ticker="TST",
            name="Test Token",
        )
        cbor_bytes, _ = encode_payload(meta)
        # Decode and re-encode via cbor2 with canonical=True; should be
        # identical (idempotent canonical encoding).
        import cbor2
        d = cbor2.loads(cbor_bytes)
        re_encoded = cbor2.dumps(d, canonical=True)
        assert cbor_bytes == re_encoded


# ---------------------------------------------------------------------------
# Transaction.fee remainder routing (code-quality finding #5, high)
# ---------------------------------------------------------------------------


class TestTransactionFeeRemainder:
    """The change distribution must not leak the integer-division remainder
    to miners. Verified via direct property: sum(change_outputs) == change."""

    def _build_tx_with_change(self, total_in: int, fee: int, n_change: int):
        """Construct a minimal Transaction with n_change change outputs and
        no non-change outputs; total inputs = total_in."""
        from pyrxd.script.script import Script
        from pyrxd.transaction.transaction import Transaction
        from pyrxd.transaction.transaction_input import TransactionInput
        from pyrxd.transaction.transaction_output import TransactionOutput

        # Build a one-input source tx providing total_in satoshis at vout 0
        source = Transaction(
            tx_inputs=[],
            tx_outputs=[TransactionOutput(Script(b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"), total_in)],
        )
        tx_input = TransactionInput(
            source_transaction=source,
            source_output_index=0,
            unlocking_script=Script(b""),
        )
        change_outputs = [
            TransactionOutput(
                Script(b"\x76\xa9\x14" + b"\xaa" * 20 + b"\x88\xac"), 0, change=True,
            )
            for _ in range(n_change)
        ]
        return Transaction(tx_inputs=[tx_input], tx_outputs=change_outputs)

    def test_remainder_routed_to_first_change_output(self):
        """change=10, change_count=3 → outputs [4, 3, 3], not [3, 3, 3]."""
        tx = self._build_tx_with_change(total_in=110, fee=100, n_change=3)
        tx.fee(100)  # fee=100; change=10
        change_outs = [out for out in tx.outputs if out.change]
        amounts = [out.satoshis for out in change_outs]
        assert sum(amounts) == 10
        assert amounts == [4, 3, 3]   # first gets the remainder

    def test_exact_division_unchanged(self):
        """change=9, change_count=3 → outputs [3, 3, 3] — no remainder."""
        tx = self._build_tx_with_change(total_in=109, fee=100, n_change=3)
        tx.fee(100)
        change_outs = [out for out in tx.outputs if out.change]
        amounts = [out.satoshis for out in change_outs]
        assert amounts == [3, 3, 3]

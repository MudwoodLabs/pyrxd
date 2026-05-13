"""Tests for pyrxd.script.timelock — CLTV / CSV locking-script primitives."""

from __future__ import annotations

import pytest

from pyrxd.script.timelock import (
    LOCKTIME_THRESHOLD,
    CsvKind,
    build_csv_sequence,
    build_p2pkh_with_cltv_script,
    build_p2pkh_with_csv_script,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20

_PKH = Hex20(bytes(range(20)))  # 20 distinct bytes 0x00..0x13
_P2PKH_TAIL = bytes.fromhex("76a914") + bytes(_PKH) + bytes.fromhex("88ac")


class TestBuildP2pkhWithCltvScript:
    """Build_p2pkh_with_cltv_script — absolute time-lock + P2PKH."""

    def test_block_height_lock_uses_minimal_int_push(self):
        """A small block-height locktime encodes as a minimal int push.
        ``OP_3`` (= 0x53) is the canonical minimal encoding for the
        integer 3."""
        script = build_p2pkh_with_cltv_script(_PKH, locktime=3)
        # script = OP_3 OP_CHECKLOCKTIMEVERIFY OP_DROP <P2PKH tail>
        assert script[0] == 0x53  # OP_3 = OP_1(0x51) + 2
        assert script[1] == 0xB1  # OP_CHECKLOCKTIMEVERIFY
        assert script[2] == 0x75  # OP_DROP
        assert script[3:] == _P2PKH_TAIL

    def test_height_lock_above_op_n_uses_pushdata(self):
        """A locktime above 16 encodes as a length-prefixed push, since
        ``OP_1..OP_16`` only cover 1..16."""
        script = build_p2pkh_with_cltv_script(_PKH, locktime=100)
        # 100 fits in 1 byte → push opcode 0x01 then 0x64
        assert script[0] == 0x01
        assert script[1] == 0x64
        assert script[2] == 0xB1  # OP_CHECKLOCKTIMEVERIFY
        assert script[3] == 0x75  # OP_DROP
        assert script[4:] == _P2PKH_TAIL

    def test_unix_time_lock_above_threshold_round_trips(self):
        """A locktime ≥500_000_000 selects the Unix-time interpretation at
        consensus. At the script level the encoding is just a minimal int
        push — the threshold is only meaningful when the spending tx's
        nLockTime is checked."""
        ts = 1_700_000_000  # 2023-11-14 — well past LOCKTIME_THRESHOLD
        assert ts > LOCKTIME_THRESHOLD
        script = build_p2pkh_with_cltv_script(_PKH, locktime=ts)
        # 1_700_000_000 = 0x65540008 ... but encode_int is little-endian
        # signed. ts fits in 4 bytes with high bit clear → push opcode 0x04.
        assert script[0] == 0x04  # PUSH 4
        # Recover the LE-encoded integer from the script bytes
        recovered = int.from_bytes(script[1:5], "little", signed=True)
        assert recovered == ts
        assert script[5] == 0xB1
        assert script[6] == 0x75
        assert script[7:] == _P2PKH_TAIL

    def test_zero_locktime_uses_op_0(self):
        """A locktime of 0 (lock-disabled) encodes as ``OP_0``."""
        script = build_p2pkh_with_cltv_script(_PKH, locktime=0)
        assert script[0] == 0x00  # OP_0
        assert script[1] == 0xB1
        assert script[2] == 0x75
        assert script[3:] == _P2PKH_TAIL

    def test_max_locktime_round_trips(self):
        """A 32-bit max locktime encodes with the high-bit zero-padding
        rule — encode_int adds a 0x00 byte to keep the value positive
        when the most-significant byte has the sign bit set."""
        script = build_p2pkh_with_cltv_script(_PKH, locktime=0xFFFF_FFFF)
        # 0xFFFF_FFFF has high bit set → encode_int pads with 0x00 → 5 bytes
        assert script[0] == 0x05  # PUSH 5
        assert script[1:6] == bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x00])
        assert script[6] == 0xB1
        assert script[7] == 0x75

    def test_negative_locktime_rejected(self):
        with pytest.raises(ValidationError, match="locktime out of range"):
            build_p2pkh_with_cltv_script(_PKH, locktime=-1)

    def test_locktime_overflow_rejected(self):
        with pytest.raises(ValidationError, match="locktime out of range"):
            build_p2pkh_with_cltv_script(_PKH, locktime=0x1_0000_0000)

    def test_wrong_pkh_length_rejected(self):
        with pytest.raises(ValidationError, match="pkh must be 20 bytes"):
            build_p2pkh_with_cltv_script(b"\x00" * 19, locktime=1)  # type: ignore[arg-type]


class TestBuildP2pkhWithCsvScript:
    """build_p2pkh_with_csv_script — relative time-lock + P2PKH."""

    def test_block_count_round_trips(self):
        """A small block-count sequence encodes as a minimal int push.
        144 = 0x90 has the sign bit set, so ``encode_int`` pads with
        ``0x00`` to keep it positive — yielding a 2-byte push."""
        sequence = build_csv_sequence(units=144, kind=CsvKind.BLOCKS)
        # 144 fits in 1 byte; no type bit set for BLOCKS
        assert sequence == 144
        script = build_p2pkh_with_csv_script(_PKH, sequence=sequence)
        assert script[0] == 0x02  # PUSH 2
        assert script[1:3] == bytes([0x90, 0x00])  # 144 LE with sign-pad
        # Recover the LE-encoded integer from the script bytes
        recovered = int.from_bytes(script[1:3], "little", signed=True)
        assert recovered == 144
        assert script[3] == 0xB2  # OP_CHECKSEQUENCEVERIFY
        assert script[4] == 0x75  # OP_DROP
        assert script[5:] == _P2PKH_TAIL

    def test_time_kind_sets_bit_22(self):
        """``CsvKind.TIME_512_SECONDS`` flips bit 22 of the encoded value
        per BIP-112. 1 hour ≈ 7 units of 512 seconds."""
        sequence = build_csv_sequence(units=7, kind=CsvKind.TIME_512_SECONDS)
        assert sequence == (1 << 22) | 7

    def test_block_count_clears_bit_22(self):
        sequence = build_csv_sequence(units=100, kind=CsvKind.BLOCKS)
        assert sequence & (1 << 22) == 0
        assert sequence == 100

    def test_max_unit_count(self):
        """16-bit max unit count (65 535) is the BIP-112 limit."""
        sequence = build_csv_sequence(units=65_535, kind=CsvKind.BLOCKS)
        assert sequence == 65_535

    def test_unit_count_overflow_rejected(self):
        with pytest.raises(ValidationError, match="CSV unit count out of range"):
            build_csv_sequence(units=65_536, kind=CsvKind.BLOCKS)

    def test_negative_unit_count_rejected(self):
        with pytest.raises(ValidationError, match="CSV unit count out of range"):
            build_csv_sequence(units=-1, kind=CsvKind.BLOCKS)

    def test_disable_bit_rejected(self):
        """A caller who manually constructs a sequence with bit 31 set
        gets rejected — that bit means 'no relative lock' and would make
        the script a no-op."""
        with pytest.raises(ValidationError, match="disable bit"):
            build_p2pkh_with_csv_script(_PKH, sequence=1 << 31)

    def test_sequence_overflow_rejected(self):
        with pytest.raises(ValidationError, match="sequence out of range"):
            build_p2pkh_with_csv_script(_PKH, sequence=0x1_0000_0000)

    def test_negative_sequence_rejected(self):
        with pytest.raises(ValidationError, match="sequence out of range"):
            build_p2pkh_with_csv_script(_PKH, sequence=-1)

    def test_zero_sequence_op_0(self):
        """A sequence of 0 (relative lock of 0 — i.e. spendable in the
        next block) encodes as OP_0."""
        script = build_p2pkh_with_csv_script(_PKH, sequence=0)
        assert script[0] == 0x00  # OP_0
        assert script[1] == 0xB2
        assert script[2] == 0x75
        assert script[3:] == _P2PKH_TAIL

    def test_wrong_pkh_length_rejected(self):
        with pytest.raises(ValidationError, match="pkh must be 20 bytes"):
            build_p2pkh_with_csv_script(b"\x00" * 19, sequence=1)  # type: ignore[arg-type]


class TestCltvAndCsvScriptInvariants:
    """Cross-invariants between the two builders."""

    def test_scripts_have_no_overlap_in_opcode(self):
        """CLTV uses 0xb1, CSV uses 0xb2 — the byte after the locktime
        push is the only structural difference between the two shapes."""
        cltv = build_p2pkh_with_cltv_script(_PKH, locktime=1)
        csv = build_p2pkh_with_csv_script(_PKH, sequence=1)
        # Both: <OP_1> <OP_CLTV|CSV> <OP_DROP> <P2PKH tail>
        assert cltv[0] == csv[0]  # same locktime push
        assert cltv[1] == 0xB1  # OP_CHECKLOCKTIMEVERIFY
        assert csv[1] == 0xB2  # OP_CHECKSEQUENCEVERIFY
        assert cltv[2] == csv[2] == 0x75  # OP_DROP
        assert cltv[3:] == csv[3:]  # same P2PKH tail


class TestPublicReexports:
    """Names are reachable via ``pyrxd.script.<name>`` (the PEP 562 lazy
    re-exports), so downstream consumers don't have to know about the
    internal module path."""

    def test_top_level_imports(self):
        import pyrxd.script as ps

        assert ps.LOCKTIME_THRESHOLD == 500_000_000
        assert ps.CsvKind.BLOCKS.value == "blocks"
        assert ps.CsvKind.TIME_512_SECONDS.value == "time"
        assert callable(ps.build_csv_sequence)
        assert callable(ps.build_p2pkh_with_cltv_script)
        assert callable(ps.build_p2pkh_with_csv_script)

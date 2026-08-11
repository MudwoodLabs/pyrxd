"""Parsers that must agree with Radiant consensus about *malformed* input.

Every path here takes attacker-controlled bytes — an advert's source
transaction, an ElectrumX response, a watchtower blob, a presigned recovery
file — and every one of them used to accept something the node rejects. A
parser that is more permissive than consensus is not a convenience: it reports
"valid" for bytes that can never confirm, and (worse) re-serializes them to
*different* bytes, so any txid or hash derived from the parse describes a
transaction the input bytes do not encode.

Ground truth is derived from the vendored Radiant Core sources
(``tests/vendor/radiant_core/``) via :mod:`tests.consensus_oracle`, never from
a value typed into this file. That rule exists because the ref-operand bug was
spelled by hand in four walkers, two of them wrong, and a fifth time in the
test meant to catch it — so the test agreed with the bug.

The inverse error is guarded too: each section carries at least one test
asserting the tightened parser still accepts what consensus accepts.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import re
from pathlib import Path

import pytest

from pyrxd import curve
from pyrxd.constants import (
    REF_OPERAND_OPCODES,
    REF_OPERAND_WIDTH,
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_GRANULARITY,
    SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import Reader, deserialize_ecdsa_der, serialize_ecdsa_der
from tests.consensus_oracle import (
    block_script_flag_names,
    check_sequence_disable_flag_name,
    check_sequence_mask_flag_names,
    check_sequence_min_tx_version,
    der_encoding_gate_flag_names,
    der_signature_size_bounds,
    low_s_gate_flag_name,
    mandatory_script_verify_flag_names,
    ref_operand_opcodes,
    ref_operand_width,
    requires_standard_default,
    script_verify_flags,
    sequence_locktime_constants,
    standard_script_verify_flag_names,
    verify_script_implied_flag_names,
)

pytestmark = pytest.mark.unit

_SRC = Path(__file__).resolve().parent.parent / "src" / "pyrxd"


# ===========================================================================
# 1. Script._build_chunks — clamping a truncated push, and ref-blindness
# ===========================================================================
#
# Radiant's GetScriptOp (script.cpp) returns FALSE — it does not clamp — when
# a push's declared size runs past the end of the script, and it consumes a
# fixed 36-byte immediate after each of the five ref opcodes. A walker that
# clamps reports a chunk list for a script the node cannot read; a walker that
# is ref-blind starts reading ref bytes as opcodes the moment one appears.


def _truncated_scripts() -> list[tuple[str, bytes]]:
    """Scripts whose final push declares more bytes than remain."""
    return [
        ("direct push 0x05 with 2 bytes", bytes([0x05, 0xAA, 0xBB])),
        ("direct push 0x4b with 0 bytes", bytes([0x4B])),
        ("OP_PUSHDATA1 claims 0x50, 4 present", bytes([0x4C, 0x50]) + b"\xaa" * 4),
        ("OP_PUSHDATA1 with no size byte", bytes([0x4C])),
        ("OP_PUSHDATA2 claims 0x1000, 4 present", bytes([0x4D, 0x00, 0x10]) + b"\xaa" * 4),
        ("OP_PUSHDATA2 with a 1-byte size", bytes([0x4D, 0x00])),
        ("OP_PUSHDATA4 claims 2^24, 4 present", bytes([0x4E, 0x00, 0x00, 0x00, 0x01]) + b"\xaa" * 4),
        ("OP_PUSHDATA4 with a 3-byte size", bytes([0x4E, 0x00, 0x00, 0x00])),
    ]


class TestScriptWalkMatchesGetScriptOp:
    @pytest.mark.parametrize("label,raw", _truncated_scripts(), ids=[label for label, _ in _truncated_scripts()])
    def test_truncated_push_is_refused_by_default(self, label, raw):
        """GetScriptOp returns false here; clamping invented a chunk instead."""
        with pytest.raises(ValueError, match="truncated|malformed"):
            Script(raw)

    @pytest.mark.parametrize("label,raw", _truncated_scripts(), ids=[label for label, _ in _truncated_scripts()])
    def test_lenient_parse_stops_where_consensus_stops(self, label, raw):
        """Opt-in leniency must REPORT the failure, not paper over it.

        ``allow_malformed`` exists for one caller — transaction
        deserialization, where consensus does permit an unparseable script to
        sit inside a perfectly valid transaction. It stops the walk at the
        offending opcode exactly as ``GetOp`` does, and records where.
        """
        prefix = b"\x51"  # OP_1, a complete op the walk must keep
        script = Script(prefix + raw, allow_malformed=True)
        assert script.truncated_at == len(prefix)
        assert [c.op for c in script.chunks] == [b"\x51"]
        assert script.serialize() == prefix + raw, "raw bytes must be preserved verbatim"

    def test_truncated_script_is_not_push_only(self):
        """``CScript::IsPushOnly`` returns false as soon as ``GetOp`` fails
        (script.cpp:537-553). ``SCRIPT_VERIFY_SIGPUSHONLY`` is set for every
        connected block, so getting this backwards calls a scriptSig valid
        that no block can contain."""
        script = Script(bytes([0x05, 0xAA, 0xBB]), allow_malformed=True)
        assert script.is_push_only() is False

    def test_well_formed_push_only_script_is_still_push_only(self):
        """Inverse-error guard: the tightening must not reclassify valid input."""
        assert Script(bytes([0x02, 0xAA, 0xBB]) + b"\x51").is_push_only() is True

    @pytest.mark.parametrize("opcode", sorted(REF_OPERAND_OPCODES))
    def test_ref_opcode_consumes_its_36_byte_immediate(self, opcode):
        """One chunk for the ref opcode, one for what follows — not 30-odd
        chunks fabricated out of the ref's own bytes."""
        ref = bytes(range(REF_OPERAND_WIDTH))
        script = Script(bytes([opcode]) + ref + b"\xac")
        assert [c.op for c in script.chunks] == [bytes([opcode]), b"\xac"]
        assert script.chunks[0].data == ref
        assert script.chunks[1].data is None

    @pytest.mark.parametrize("opcode", sorted(REF_OPERAND_OPCODES))
    def test_truncated_ref_operand_is_refused(self, opcode):
        with pytest.raises(ValueError, match="truncated|malformed"):
            Script(bytes([opcode]) + bytes(REF_OPERAND_WIDTH - 1))

    @pytest.mark.parametrize("opcode", [0xD4, 0xD5, 0xD6, 0xD7])
    def test_refhash_stack_ops_take_no_operand(self, opcode):
        """The four opcodes sitting *inside* 0xd0-0xd8 that carry nothing.

        ``frozenset(range(0xD0, 0xD9))`` — the original bug's exact spelling —
        would eat 36 bytes here and desynchronise.
        """
        assert opcode not in ref_operand_opcodes()
        script = Script(bytes([opcode, 0xAC]))
        assert [c.op for c in script.chunks] == [bytes([opcode]), b"\xac"]
        assert script.chunks[0].data is None

    def test_ref_bearing_script_disassembles_to_one_token_per_opcode(self):
        ref = bytes(range(REF_OPERAND_WIDTH))
        asm = Script(bytes([0xD0]) + ref + b"\xac").to_asm()
        assert asm == f"OP_PUSHINPUTREF {ref.hex()} OP_CHECKSIG"

    def test_lenient_disassembly_marks_the_error(self):
        """Radiant's ``ScriptToAsmStr`` emits ``[error]`` and stops
        (core_write.cpp:117-120). Emitting clean-looking ASM for a script the
        node cannot read is how a malformed script gets eyeballed as fine."""
        asm = Script(b"\x51" + bytes([0x05, 0xAA, 0xBB]), allow_malformed=True).to_asm()
        assert asm == "OP_1 [error]"


class TestScriptChunkRoundTrip:
    """``from_chunks`` must re-emit the bytes it was given.

    It used to run every chunk back through ``encode_pushdata``, which
    normalises the push encoding. That silently rewrote any script using a
    non-minimal push — and ``find_and_delete`` is built on it, so a
    "delete nothing" call could still change the script's bytes and therefore
    its hash.
    """

    @pytest.mark.parametrize(
        "label,raw",
        [
            ("minimal direct push", bytes.fromhex("76a914" + "ab" * 20 + "88ac")),
            ("non-minimal OP_PUSHDATA1", bytes([0x4C, 0x02, 0xAA, 0xBB])),
            ("non-minimal OP_PUSHDATA2", bytes([0x4D, 0x02, 0x00, 0xAA, 0xBB])),
            ("non-minimal OP_PUSHDATA4", bytes([0x4E, 0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB])),
            ("ref opcode + immediate", bytes([0xD0]) + bytes(range(REF_OPERAND_WIDTH)) + b"\xac"),
            ("OP_0 then a push", bytes([0x00, 0x02, 0xAA, 0xBB])),
        ],
    )
    def test_from_chunks_is_byte_exact(self, label, raw):
        assert Script.from_chunks(Script(raw).chunks).serialize() == raw

    def test_find_and_delete_of_an_absent_pattern_changes_nothing(self):
        raw = bytes([0x4C, 0x02, 0xAA, 0xBB])
        assert Script.find_and_delete(Script(raw), Script(b"\x76")).serialize() == raw


class TestScriptOracleParity:
    def test_ref_operand_width_matches_consensus(self):
        assert ref_operand_width() == REF_OPERAND_WIDTH

    def test_walker_uses_the_shared_constant(self):
        """No fifth hand-spelling. ``_build_chunks`` must reference the shared
        name; a literal ``0xd0``/range would not be caught by the parity test."""
        source = inspect.getsource(Script._build_chunks)
        assert "REF_OPERAND_OPCODES" in source
        assert "REF_OPERAND_WIDTH" in source
        assert not re.search(r"0[xX][dD][0-8]\b", source), "ref opcodes must not be re-spelled as literals"


# ===========================================================================
# 2. TransactionInput.from_hex vs TransactionOutput.from_hex
# ===========================================================================
#
# Same file, same job, opposite behaviour on a truncated script. The output
# parser refuses; the input parser used to keep going, absorbing the following
# fields into the script and then reading past the end for the ones it had
# eaten. The transaction it produced re-serialized to different bytes.

_TXID = b"\x11" * 32


def _input_bytes(script: bytes, *, declared_len: int | None = None) -> bytes:
    length = len(script) if declared_len is None else declared_len
    return _TXID + b"\x00\x00\x00\x00" + bytes([length]) + script + b"\xff\xff\xff\xff"


def _output_bytes(script: bytes, *, declared_len: int | None = None) -> bytes:
    length = len(script) if declared_len is None else declared_len
    return b"\x00" * 8 + bytes([length]) + script


class TestInputOutputParserParity:
    def test_input_refuses_a_script_length_that_overruns(self):
        assert TransactionInput.from_hex(_input_bytes(b"\xaa\xbb", declared_len=5)) is None

    def test_output_refuses_a_script_length_that_overruns(self):
        assert TransactionOutput.from_hex(_output_bytes(b"\xaa\xbb", declared_len=5)) is None

    def test_input_refuses_a_truncated_sequence(self):
        """``Reader.read_int`` zero-extended a short read, so two bytes of
        sequence decoded as a four-byte value."""
        assert TransactionInput.from_hex(_TXID + b"\x00\x00\x00\x00" + b"\x00" + b"\xff\xff") is None

    def test_input_refuses_a_truncated_vout(self):
        assert TransactionInput.from_hex(_TXID + b"\x00\x00") is None

    def test_input_accepts_a_well_formed_input(self):
        """Inverse-error guard, plus the property that actually matters:
        parse(serialize(x)) must give back the same bytes."""
        raw = _input_bytes(bytes.fromhex("76a914" + "ab" * 20 + "88ac"))
        parsed = TransactionInput.from_hex(raw)
        assert parsed is not None
        assert parsed.serialize() == raw

    def test_input_accepts_an_empty_unlocking_script(self):
        raw = _input_bytes(b"")
        parsed = TransactionInput.from_hex(raw)
        assert parsed is not None
        assert parsed.unlocking_script.serialize() == b""
        assert parsed.serialize() == raw


def _tx_bytes(input_script: bytes, *, declared_len: int | None = None, locktime: bytes = b"\x00\x00\x00\x00") -> bytes:
    return (
        b"\x01\x00\x00\x00"
        + b"\x01"
        + _input_bytes(input_script, declared_len=declared_len)
        + b"\x01"
        + b"\x00" * 8
        + b"\x01\x51"
        + locktime
    )


class TestTransactionRoundTrip:
    def test_transaction_with_an_overrunning_input_script_does_not_parse(self):
        """The concrete cost of the fail-open.

        Inside a transaction an over-claiming script length does not run off
        the end — it eats the fields that follow, and every later boundary
        slides. This 63-byte blob parsed "successfully" into a Transaction with
        one input, ZERO outputs and 8 bytes left unread, which re-serialized to
        56 different bytes; ``txid()`` then returned the id of a transaction
        these bytes do not encode. Same shape as the CompactSize defect, and
        the same fix: the parse has to account for every byte.
        """
        blob = _tx_bytes(b"\xaa\xbb", declared_len=5)
        assert len(blob) == 63
        assert Transaction.from_hex(blob) is None

    def test_trailing_bytes_after_a_transaction_are_refused(self):
        """The general form of the above: parse(bytes).serialize() == bytes,
        or the parse is wrong about what it was given."""
        assert Transaction.from_hex(_tx_bytes(b"") + b"\x00") is None

    def test_transaction_truncated_in_its_locktime_does_not_parse(self):
        assert Transaction.from_hex(_tx_bytes(b"", locktime=b"\x00\x00")) is None

    def test_well_formed_transaction_round_trips_byte_exactly(self):
        blob = _tx_bytes(bytes.fromhex("76a914" + "ab" * 20 + "88ac"))
        parsed = Transaction.from_hex(blob)
        assert parsed is not None
        assert parsed.serialize() == blob

    def test_transaction_may_still_carry_an_unparseable_output_script(self):
        """The one legitimate lenient caller, and why ``allow_malformed`` exists.

        An output script is never executed when it is created — only when it is
        spent — so a transaction whose scriptPubKey is not walkable by
        ``GetOp`` is perfectly valid in a block. Refusing to deserialize it
        would make pyrxd unable to read real chain history: a strictly worse
        bug than the one being fixed.
        """
        garbage = bytes([0x05, 0xAA, 0xBB])  # a push claiming more than it has
        blob = (
            b"\x01\x00\x00\x00"
            + b"\x01"
            + _input_bytes(b"")
            + b"\x01"
            + b"\x00" * 8
            + bytes([len(garbage)])
            + garbage
            + b"\x00\x00\x00\x00"
        )
        parsed = Transaction.from_hex(blob)
        assert parsed is not None
        assert parsed.serialize() == blob
        assert parsed.outputs[0].locking_script.truncated_at == 0


class TestReaderFixedWidthReads:
    """A short read must be an error, not a zero-extension.

    ``int.from_bytes(b"\\xff\\xff", "little")`` is 65535 whether it was meant
    to be two bytes or the first two of four. Every fixed-width field in the
    transaction wire format is exposed to this.
    """

    def test_read_int_refuses_a_short_read(self):
        assert Reader(b"\xff\xff").read_int(4) is None

    def test_read_uint32_le_refuses_a_short_read(self):
        assert Reader(b"\xff\xff").read_uint32_le() is None

    def test_read_uint16_le_refuses_a_short_read(self):
        assert Reader(b"\xff").read_uint16_le() is None

    def test_full_width_reads_still_work(self):
        assert Reader(b"\x01\x00\x00\x00").read_uint32_le() == 1
        assert Reader(b"\x01\x00\x00\x00\x00\x00\x00\x00").read_int(8) == 1


# ===========================================================================
# 3. DER strictness and low-S on the DECODE path
# ===========================================================================
#
# `serialize_ecdsa_der` normalises S and emits minimal integers.
# `deserialize_ecdsa_der` used to check only the length arithmetic, so it
# accepted encodings no Radiant block can contain and handed back an (r, s)
# that re-encodes to different bytes than it was given.

_N = curve.curve.n


def _der(r: int, s: int, *, pad_r: bytes = b"", pad_s: bytes = b"") -> bytes:
    def enc(value: int, pad: bytes) -> bytes:
        raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if not pad and raw[0] & 0x80:
            raw = b"\x00" + raw
        raw = pad + raw
        return bytes([0x02, len(raw)]) + raw

    body = enc(r, pad_r) + enc(s, pad_s)
    return bytes([0x30, len(body)]) + body


class TestDerDecodeMatchesConsensus:
    def test_high_s_is_refused(self):
        """``SCRIPT_VERIFY_LOW_S`` is set unconditionally for every connected
        block (validation.cpp ``GetNextBlockScriptFlags``), so a high-S
        signature is consensus-invalid, not merely non-standard."""
        with pytest.raises(ValueError, match="[Hh]igh"):
            deserialize_ecdsa_der(_der(1, _N - 1))

    def test_low_s_boundary_is_accepted(self):
        """Inverse-error guard: ``CheckLowS`` rejects ``s > n/2``, so exactly
        ``n/2`` is still valid and must decode."""
        assert deserialize_ecdsa_der(_der(1, _N // 2)) == (1, _N // 2)

    def test_negative_r_is_refused(self):
        with pytest.raises(ValueError, match="negative"):
            deserialize_ecdsa_der(bytes.fromhex("3006020180020101"))

    def test_negative_s_is_refused(self):
        with pytest.raises(ValueError, match="negative"):
            deserialize_ecdsa_der(bytes.fromhex("3006020101020180"))

    def test_non_minimal_r_is_refused(self):
        with pytest.raises(ValueError, match="minimal|padding"):
            deserialize_ecdsa_der(_der(1, 1, pad_r=b"\x00"))

    def test_non_minimal_s_is_refused(self):
        with pytest.raises(ValueError, match="minimal|padding"):
            deserialize_ecdsa_der(_der(1, 1, pad_s=b"\x00"))

    def test_required_leading_zero_is_accepted(self):
        """The one case where a leading 0x00 is mandatory rather than
        forbidden: the next byte has its high bit set, so without the pad the
        integer would read as negative."""
        value = 0x80
        assert deserialize_ecdsa_der(_der(value, value)) == (value, value)

    def test_oversize_signature_is_refused(self):
        body = bytes([0x02, 0x40]) + b"\x01" * 64 + bytes([0x02, 0x40]) + b"\x01" * 64
        oversize = bytes([0x30, len(body)]) + body
        assert len(oversize) > der_signature_size_bounds()[1]
        with pytest.raises(ValueError, match="too long|size"):
            deserialize_ecdsa_der(oversize)

    def test_real_signatures_still_decode(self):
        """Inverse-error guard on the path that actually matters."""
        for _ in range(8):
            key = PrivateKey()
            sig = key.sign(b"parser strictness")
            r, s = deserialize_ecdsa_der(sig)
            assert serialize_ecdsa_der((r, s)) == sig
            assert key.public_key().verify(sig, b"parser strictness")

    def test_size_bounds_match_the_vendored_check(self):
        low, high = der_signature_size_bounds()
        assert (low, high) == (8, 72)
        assert deserialize_ecdsa_der.__doc__ is not None
        with pytest.raises(ValueError):
            deserialize_ecdsa_der(bytes([0x30, low - 3]) + b"\x02\x01\x01\x02\x01\x01"[: low - 3])


class TestSignatureFlagProvenance:
    """Which signature-encoding rules are consensus on THIS chain."""

    def test_low_s_is_a_block_connection_flag(self):
        assert low_s_gate_flag_name() in block_script_flag_names()
        assert low_s_gate_flag_name() in mandatory_script_verify_flag_names()

    def test_strict_der_is_reachable_from_a_block_connection_flag(self):
        """Any of DERSIG / LOW_S / STRICTENC turns on ``IsValidDERSignatureEncoding``."""
        assert der_encoding_gate_flag_names() & block_script_flag_names()

    def test_strictenc_is_implied_by_forkid(self):
        """``VerifyScript`` ORs STRICTENC in whenever SIGHASH_FORKID is set,
        and FORKID is mandatory here — so strict encoding is not optional."""
        implied = verify_script_implied_flag_names()
        assert implied.get("SCRIPT_VERIFY_STRICTENC") == "SCRIPT_ENABLE_SIGHASH_FORKID"
        assert "SCRIPT_ENABLE_SIGHASH_FORKID" in mandatory_script_verify_flag_names()

    def test_policy_only_flags_are_named_as_such(self):
        """``fRequireStandard`` is hardcoded false (validation.cpp:271), so a
        flag that is standard but NOT applied at block connection buys pyrxd
        nothing: no node on this chain is required to apply it. Pinning the
        split keeps a policy rule from being sold as a consensus one — and
        makes it a reviewable event if one moves.
        """
        assert requires_standard_default() is False
        policy_only = standard_script_verify_flag_names() - block_script_flag_names()
        assert policy_only == {
            # Never mandatory by construction — it exists so a node can decline
            # to relay a NOP whose meaning a future fork may change.
            "SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS",
            # Relay-side sigcheck budget keyed on scriptSig length.
            "SCRIPT_VERIFY_INPUT_SIGCHECKS",
            # Segwit-recovery carve-out; relay-side only.
            "SCRIPT_DISALLOW_SEGWIT_RECOVERY",
        }, (
            "the consensus/policy split moved. Re-read GetNextBlockScriptFlags before "
            f"treating any of these as enforced: {sorted(policy_only)}"
        )

    def test_the_rules_pyrxd_tightened_are_all_block_connection_rules(self):
        """Every rule this branch started enforcing must be one a *block* is
        verified under, not merely one a relay policy prefers."""
        for flag in ("SCRIPT_VERIFY_LOW_S", "SCRIPT_VERIFY_STRICTENC", "SCRIPT_VERIFY_SIGPUSHONLY"):
            assert flag in block_script_flag_names(), f"{flag} is not applied at block connection"

    def test_every_named_flag_exists_upstream(self):
        table = script_verify_flags()
        for name in mandatory_script_verify_flag_names() | block_script_flag_names():
            assert name in table, f"{name} is referenced but not defined in script_flags.h"


# ===========================================================================
# 4. BIP68 / sequence-lock constants — one definition, pinned to the C++
# ===========================================================================
#
# CSV maturity governs HTLC refunds. Radiant has neither RBF nor CPFP, so a
# refund that misjudges maturity by one block cannot be repaired: the only
# remedy is to wait and rebuild, and by then the counterparty's claim window
# may have opened.


class TestSequenceLocktimeConstants:
    def test_values_match_the_vendored_ctxin(self):
        upstream = sequence_locktime_constants()
        assert upstream["SEQUENCE_FINAL"] == SEQUENCE_FINAL
        assert upstream["SEQUENCE_LOCKTIME_DISABLE_FLAG"] == SEQUENCE_LOCKTIME_DISABLE_FLAG
        assert upstream["SEQUENCE_LOCKTIME_TYPE_FLAG"] == SEQUENCE_LOCKTIME_TYPE_FLAG
        assert upstream["SEQUENCE_LOCKTIME_MASK"] == SEQUENCE_LOCKTIME_MASK
        assert upstream["SEQUENCE_LOCKTIME_GRANULARITY"] == SEQUENCE_LOCKTIME_GRANULARITY

    def test_check_sequence_uses_the_constants_we_pinned(self):
        assert check_sequence_disable_flag_name() == "SEQUENCE_LOCKTIME_DISABLE_FLAG"
        assert check_sequence_mask_flag_names() == {"SEQUENCE_LOCKTIME_TYPE_FLAG", "SEQUENCE_LOCKTIME_MASK"}
        assert check_sequence_min_tx_version() == 2

    def test_granularity_is_the_shift_not_the_seconds(self):
        """``SEQUENCE_LOCKTIME_GRANULARITY`` is 9 — a shift — and the derived
        seconds-per-unit is 512. Storing 512 under the upstream name is how a
        conversion ends up 2**9 times off."""
        assert SEQUENCE_LOCKTIME_GRANULARITY == 9
        assert 1 << SEQUENCE_LOCKTIME_GRANULARITY == 512


def _module_constant_offenders(names: set[str]) -> dict[str, list[str]]:
    """Modules that assign a BIP68 constant's VALUE to their own name."""
    wanted = {
        SEQUENCE_LOCKTIME_DISABLE_FLAG,
        SEQUENCE_LOCKTIME_TYPE_FLAG,
        SEQUENCE_LOCKTIME_MASK,
        SEQUENCE_FINAL,
    }
    offenders: dict[str, list[str]] = {}
    for path in sorted(_SRC.rglob("*.py")):
        if path.name == "constants.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError, SyntaxError):
                continue
            if not isinstance(value, int) or isinstance(value, bool) or value not in wanted:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and any(tok in target.id.upper() for tok in names):
                    offenders.setdefault(str(path.relative_to(_SRC)), []).append(target.id)
    return offenders


class TestSingleDefinitionOfBip68:
    def test_no_module_re_spells_a_sequence_constant(self):
        """``script/timelock.py`` and ``btc_wallet/taproot.py`` each carried a
        private copy of the same three numbers. Two transcriptions of one
        consensus rule is the exact condition PR #408 removed for the
        ref opcodes."""
        offenders = _module_constant_offenders({"SEQUENCE", "CSV", "BIP68", "LOCKTIME"})
        assert not offenders, (
            "these modules re-spell a BIP68 sequence constant instead of importing it "
            "from pyrxd.constants: "
            + "; ".join(f"{mod}: {', '.join(names)}" for mod, names in sorted(offenders.items()))
        )

    @pytest.mark.parametrize("module", ["script/timelock.py", "btc_wallet/taproot.py"])
    def test_timelock_modules_import_the_shared_constants(self, module):
        source = (_SRC / module).read_text(encoding="utf-8")
        assert "SEQUENCE_LOCKTIME_TYPE_FLAG" in source
        assert re.search(r"from .*constants import|from \.\.constants import", source)

    def test_no_test_hand_types_the_type_flag(self):
        """The anti-pattern this file exists to end: a test citing
        ``interpreter.cpp`` in a comment while asserting a hand-typed
        ``1 << 22``. A hand-typed constant cannot detect a constant that
        moved."""
        offenders = []
        for path in sorted((Path(__file__).resolve().parent).rglob("test_*.py")):
            if path.name == Path(__file__).name:
                continue
            source = path.read_text(encoding="utf-8")
            for lineno, line in enumerate(source.splitlines(), start=1):
                code = line.split("#", 1)[0]
                if re.search(r"1\s*<<\s*(22|31)\b", code):
                    offenders.append(f"{path.name}:{lineno}")
        assert not offenders, (
            "hand-typed BIP68 bit positions in tests — import SEQUENCE_LOCKTIME_TYPE_FLAG / "
            "SEQUENCE_LOCKTIME_DISABLE_FLAG from pyrxd.constants instead: " + ", ".join(offenders)
        )


class TestCsvEncodingUsesTheSharedConstants:
    def test_block_and_time_encodings_round_trip(self):
        from pyrxd.script.timelock import CsvKind, build_csv_sequence

        assert build_csv_sequence(6, CsvKind.BLOCKS) == 6
        assert build_csv_sequence(6, CsvKind.TIME_512_SECONDS) == SEQUENCE_LOCKTIME_TYPE_FLAG | 6
        assert build_csv_sequence(SEQUENCE_LOCKTIME_MASK, CsvKind.BLOCKS) == SEQUENCE_LOCKTIME_MASK

    def test_btc_timelock_encoding_agrees_with_the_rxd_one(self):
        from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
        from pyrxd.script.timelock import CsvKind, build_csv_sequence

        assert Timelock(6, TimeUnit.BLOCKS).to_nsequence() == build_csv_sequence(6, CsvKind.BLOCKS)
        assert Timelock(6 * 512, TimeUnit.SECONDS).to_nsequence() == build_csv_sequence(6, CsvKind.TIME_512_SECONDS)


# ===========================================================================
# 5. hash160 must not depend on OpenSSL exposing RIPEMD160
# ===========================================================================
#
# Not reproducible on a host whose OpenSSL still carries the legacy provider;
# it is a portability defect, and the only honest way to test it is to make the
# fast path unavailable on purpose.


def _hash160_call_sites() -> list[str]:
    """Real ``<module>.new("ripemd160", ...)`` CALLS, found by AST.

    Deliberately not a text grep: this module and the ones it fixes both
    mention the offending expression in prose, and a scanner that cannot tell
    a call from a comment is a scanner that gets silenced.
    """
    root = _SRC.parent.parent.parent
    hits = []
    for scanned in (_SRC, root / "examples"):
        for path in sorted(scanned.rglob("*.py")):
            if path.name == "hash.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "new" or not node.args:
                    continue
                first = node.args[0]
                if isinstance(first, ast.Constant) and str(first.value).lower().replace("-", "") == "ripemd160":
                    hits.append(f"{path.relative_to(root)}:{node.lineno}")
    return hits


class TestRipemd160Portability:
    def test_no_module_calls_hashlib_ripemd160_directly(self):
        """``pyrxd.hash`` exists to provide the OpenSSL-3 fallback. Reaching
        past it re-imports the portability bug it was written to remove."""
        assert not _hash160_call_sites(), (
            "these call hashlib.new('ripemd160') directly instead of pyrxd.hash.hash160, "
            "so they raise on any OpenSSL-3 host with the legacy provider unloaded "
            "(Ubuntu 24.04, Debian 12, python.org macOS builds, Pyodide/WASM): " + ", ".join(_hash160_call_sites())
        )

    @pytest.mark.parametrize(
        "module,func",
        [
            ("pyrxd.gravity.codehash", "hash160"),
            ("pyrxd.btc_wallet.keys", "_hash160"),
        ],
    )
    def test_hash160_survives_an_openssl_without_ripemd160(self, monkeypatch, module, func):
        """Simulate the distro this breaks on and assert the digest is still
        correct — an import-time fallback is only useful if callers route
        through it.

        The simulation is faithful to how the failure actually occurs:
        ``pyrxd.hash`` picks its implementation once, at import. So we make
        ``hashlib`` refuse and then re-run that selection, which is what would
        have happened at import on such a host. A caller that reaches past
        ``pyrxd.hash`` raises regardless of what the fallback selected.
        """
        import importlib

        import pyrxd.hash as pyrxd_hash

        target = getattr(importlib.import_module(module), func)
        payload = b"portability probe"
        expected = target(payload)

        real_new = hashlib.new

        def refuse_ripemd160(name, *args, **kwargs):
            if str(name).lower().replace("-", "") == "ripemd160":
                raise ValueError("unsupported hash type ripemd160")
            return real_new(name, *args, **kwargs)

        monkeypatch.setattr(hashlib, "new", refuse_ripemd160)
        selected = pyrxd_hash._select_ripemd160()
        assert selected is pyrxd_hash._ripemd160_pure_python, (
            "the OpenSSL-3 fallback did not engage — if pyrxd.hash's own fallback is broken, "
            "routing callers through it fixes nothing"
        )
        monkeypatch.setattr(pyrxd_hash, "_ripemd160_impl", selected)

        assert target(payload) == expected
        assert len(expected) == 20

    def test_the_fallback_itself_is_correct(self, monkeypatch):
        """Guard the guard: routing through ``pyrxd.hash`` is only an
        improvement if its pure-Python path produces the same digest as
        OpenSSL. Skips where OpenSSL cannot answer — i.e. exactly the hosts
        where only the fallback exists and the published vectors in
        ``tests/test_ripemd160_fallback.py`` are the evidence instead.
        """
        import pyrxd.hash as pyrxd_hash

        try:
            reference = hashlib.new("ripemd160", b"portability probe").digest()
        except ValueError:  # pragma: no cover - host-dependent
            pytest.skip("OpenSSL on this host has RIPEMD160 disabled; see test_ripemd160_fallback.py")
        assert pyrxd_hash._ripemd160_pure_python(b"portability probe") == reference

    def test_gravity_p2sh_code_hash_is_unchanged_by_the_reroute(self):
        """Pin the actual on-chain-visible value: MakerOffer verifies this
        against ``hash256(tx.outputs[0].codeScript)``. If routing through
        ``pyrxd.hash`` changed it by a byte, every deployed covenant would
        stop matching."""
        from pyrxd.gravity.codehash import compute_p2sh_code_hash, compute_p2sh_script_pubkey

        redeem = bytes.fromhex("51")  # OP_1
        assert compute_p2sh_script_pubkey(redeem).hex() == (
            "a914" + hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).hexdigest() + "87"
        )
        assert len(compute_p2sh_code_hash(redeem)) == 32

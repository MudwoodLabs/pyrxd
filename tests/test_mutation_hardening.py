"""Targeted assertions that kill surviving cosmic-ray mutants.

Each test names the mutant class it kills (module + line refers to the
2026-07 baseline run; see docs/how-to/mutation-testing.md). These are
behavior pins, not implementation mirrors: every expected value is derived
in-test from the spec (stdlib hashing, documented formulas, docstring
examples), never from the code under test.

Grouped by mutation scope so the per-scope cosmic-ray test commands stay
fast: `task mutate transaction|script|dmint` all include this file.
"""

from __future__ import annotations

import hashlib

import pytest

from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

_P2PKH_AA = bytes.fromhex("76a914" + "aa" * 20 + "88ac")
_P2PKH_BB = bytes.fromhex("76a914" + "bb" * 20 + "88ac")


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _out(script: bytes, sats: int, change: bool = False) -> TransactionOutput:
    return TransactionOutput(Script(script), sats, change=change)


def _in(txid: str = "ab" * 32, vout: int = 0, sequence: int = 0xFFFFFFFF) -> TransactionInput:
    tx_in = TransactionInput(source_txid=txid, source_output_index=vout, sequence=sequence)
    tx_in.satoshis = 10_000
    tx_in.locking_script = Script(_P2PKH_AA)
    return tx_in


class TestTransactionIdentity:
    """transaction.py — txid/hash/serialize mutants."""

    def test_txid_is_reversed_double_sha256_of_serialization(self):
        """Kills the L91 `hash()[::-1]` → `hash()[::1]` survivors: txid MUST
        be the byte-reversed double-SHA256, re-derived here with hashlib
        alone. An unreversed txid would silently break every outpoint
        reference this SDK ever signs."""
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, 5_000)])
        raw = tx.serialize()
        assert tx.txid() == _sha256d(raw)[::-1].hex()
        assert tx.hash() == _sha256d(raw)

    def test_is_coinbase_requires_exactly_one_all_zero_input(self):
        """Kills the L83 `== 1` → `>= 1` and txid-comparison survivors."""
        coinbase = Transaction(tx_inputs=[_in(txid="00" * 32)])
        assert coinbase.is_coinbase()
        normal = Transaction(tx_inputs=[_in(txid="ab" * 32)])
        assert not normal.is_coinbase()
        two_inputs = Transaction(tx_inputs=[_in(txid="00" * 32), _in(txid="ab" * 32)])
        assert not two_inputs.is_coinbase()

    def test_preimage_index_bounds(self):
        """Kills the L97 guard survivors (`0 <=` → `-1 <=`, `<` → `<=`):
        out-of-range indexes must raise, never wrap to inputs[-1]."""
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, 5_000)])
        with pytest.raises(ValueError):
            tx.preimage(-1)
        with pytest.raises(ValueError):
            tx.preimage(1)

    def test_constructor_preserves_extra_kwargs(self):
        """Kills the L45 `dict(**kwargs) or {}` → `and {}` survivor, which
        would silently drop caller metadata."""
        tx = Transaction(note="keepme")
        assert tx.kwargs == {"note": "keepme"}


class TestTransactionAccounting:
    """transaction.py — fee/value arithmetic mutants."""

    def test_get_fee_is_subtraction(self):
        """Kills the L133 `-` → `%` survivor: 10_000 in − 3_000 out = 7_000
        (the `%` mutant would report 1_000)."""
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, 3_000)])
        assert tx.total_value_in() == 10_000
        assert tx.total_value_out() == 3_000
        assert tx.get_fee() == 7_000

    def test_estimated_byte_length_formula(self):
        """Kills the L156 `41` NumberReplacer survivors by pinning the
        documented per-input formula: 4 (version) + varint(#in) +
        varint(#out) + 4 (locktime) + per-input (40 outpoint/sequence + 1
        script-len varint = 41, + template estimate) + per-output (8 +
        script varint + script)."""
        from pyrxd.keys import PrivateKey

        pk_template = P2PKH().unlock(PrivateKey())  # fresh throwaway key
        tx_in = _in()
        tx_in.unlocking_script_template = pk_template
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[_out(_P2PKH_AA, 5_000)])
        expected = 4 + 1 + 1 + 4 + (41 + 107) + (8 + 1 + len(_P2PKH_AA))
        assert tx.estimated_byte_length() == expected

    def test_fee_change_distribution_docstring_example(self):
        """Kills the L181–L217 change-distribution survivors with the
        docstring's own worked example: change=10 over 3 change outputs
        must yield [4, 3, 3] (sum preserved, remainder to the first)."""
        src = Transaction(tx_outputs=[_out(_P2PKH_AA, 1_010)])
        tx_in = TransactionInput(source_transaction=src, source_output_index=0)
        tx = Transaction(
            tx_inputs=[tx_in],
            tx_outputs=[
                _out(_P2PKH_BB, 1_000),
                _out(_P2PKH_AA, None, change=True),
                _out(_P2PKH_AA, None, change=True),
                _out(_P2PKH_AA, None, change=True),
            ],
        )
        tx.fee(0)  # explicit zero fee → change pool is exactly 10
        assert [o.satoshis for o in tx.outputs if o.change] == [4, 3, 3]

    def test_fee_drops_change_outputs_when_dust(self):
        """Kills the `change <= change_count` branch survivors: when the
        pool can't give each change output more than 1 photon, ALL change
        outputs are removed and the surplus goes to miners."""
        src = Transaction(tx_outputs=[_out(_P2PKH_AA, 1_002)])
        tx_in = TransactionInput(source_transaction=src, source_output_index=0)
        tx = Transaction(
            tx_inputs=[tx_in],
            tx_outputs=[
                _out(_P2PKH_BB, 1_000),
                _out(_P2PKH_AA, None, change=True),
                _out(_P2PKH_AA, None, change=True),
            ],
        )
        tx.fee(0)  # change pool = 2 == change_count → drop them
        assert [o for o in tx.outputs if o.change] == []
        assert len(tx.outputs) == 1

    def test_fee_random_distribution_not_implemented(self):
        """Pins the L203 'random' branch: it must raise NotImplementedError,
        not fall through to equal distribution."""
        src = Transaction(tx_outputs=[_out(_P2PKH_AA, 2_000)])
        tx_in = TransactionInput(source_transaction=src, source_output_index=0)
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[_out(_P2PKH_AA, None, change=True)])
        with pytest.raises(NotImplementedError):
            tx.fee(0, change_distribution="random")


class TestWireFormats:
    """transaction.py — from_beef guard and parse_script_offsets mutants."""

    def test_from_beef_rejects_wrong_version_below_magic(self):
        """Kills the L244 `!=` → `>` survivor: a version BELOW the BEEF magic
        (4022206465) must raise, not fall through to parsing garbage."""
        tx = Transaction(tx_outputs=[_out(_P2PKH_AA, 1_000)])
        good = (4022206465).to_bytes(4, "little") + b"\x00" + b"\x01" + tx.serialize() + b"\x00"
        assert Transaction.from_beef(good).txid() == tx.txid()
        bad = (1).to_bytes(4, "little") + good[4:]
        with pytest.raises(ValueError, match="BEEF version"):
            Transaction.from_beef(bad)

    def test_parse_script_offsets_exact_slices(self):
        """Kills the parse_script_offsets skip-arithmetic survivors
        (L416–L429): every reported (offset, length) must slice the raw tx
        back to the exact script bytes, across multiple inputs/outputs with
        distinct script lengths."""
        in_a, in_b = _in(txid="11" * 32), _in(txid="22" * 32)
        in_a.unlocking_script = Script(b"\x51" * 7)
        in_b.unlocking_script = Script(b"\x52" * 19)
        tx = Transaction(
            tx_inputs=[in_a, in_b],
            tx_outputs=[_out(_P2PKH_AA, 1_000), _out(_P2PKH_BB, 2_000)],
        )
        raw = tx.serialize()
        offsets = Transaction.parse_script_offsets(raw)
        assert [i["vin"] for i in offsets["inputs"]] == [0, 1]
        assert [o["vout"] for o in offsets["outputs"]] == [0, 1]
        for rec, script in zip(offsets["inputs"], [b"\x51" * 7, b"\x52" * 19]):
            assert raw[rec["offset"] : rec["offset"] + rec["length"]] == script
        for rec, script in zip(offsets["outputs"], [_P2PKH_AA, _P2PKH_BB]):
            assert raw[rec["offset"] : rec["offset"] + rec["length"]] == script


class TestScriptChunkParsing:
    """script/script.py — _build_chunks parser mutants (L45–L67). The chunk
    view feeds to_asm/find_and_delete; no prior test asserted parsed chunk
    DATA, so every push-dispatch comparison survived."""

    def test_p2pkh_chunks_carry_exact_push_data(self):
        s = Script(_P2PKH_AA)
        ops = [c.op for c in s.chunks]
        assert ops == [b"\x76", b"\xa9", b"\x14", b"\x88", b"\xac"]
        assert s.chunks[2].data == b"\xaa" * 20
        assert s.chunks[0].data is None

    def test_direct_push_boundary_75_bytes(self):
        """op == 0x4b is the LAST direct-push opcode; `<= 0x4b` → `< 0x4b`
        must not drop its payload."""
        payload = bytes(range(75))
        s = Script(bytes([0x4B]) + payload)
        assert len(s.chunks) == 1
        assert s.chunks[0].data == payload

    def test_pushdata_1_2_4_dispatch(self):
        payload = b"\xcd" * 80
        for opcode, len_bytes in (
            (b"\x4c", (80).to_bytes(1, "little")),
            (b"\x4d", (80).to_bytes(2, "little")),
            (b"\x4e", (80).to_bytes(4, "little")),
        ):
            s = Script(opcode + len_bytes + payload)
            assert len(s.chunks) == 1, f"opcode {opcode.hex()}"
            assert s.chunks[0].data == payload, f"opcode {opcode.hex()}"

    def test_script_equality_is_not_ordering(self):
        """__eq__ `==` → `>=` survivor: equality must be symmetric-false for
        two different scripts regardless of byte order."""
        lo, hi = Script(b"\x51"), Script(b"\x52")
        assert lo == Script(b"\x51")
        # NB: `!=` falls back to object identity (no __ne__), so the kill
        # must go through __eq__ from both sides explicitly.
        assert (lo == hi) is False
        assert (hi == lo) is False

    def test_find_and_delete_keeps_nonmatching_chunks(self):
        source = Script.from_chunks(Script(_P2PKH_AA).chunks)
        pattern = Script(b"\x76")  # OP_DUP
        remaining = Script.find_and_delete(source, pattern)
        assert remaining.serialize() == _P2PKH_AA[1:]


class TestFromAsm:
    """script/script.py — from_asm token handling mutants (L113–L162)."""

    def test_op_false_normalizes_to_op_0(self):
        assert Script.from_asm("OP_FALSE").hex() == "00"
        assert Script.from_asm("0").hex() == "00"

    def test_minus_one_is_op_1negate_not_zero(self):
        """Kills the L126 `== "0"` → `<= "0"` survivor ("-1" sorts before
        "0" lexicographically and would be swallowed by the zero branch)."""
        assert Script.from_asm("-1").hex() == "4f"

    def test_hex_push_encodings_by_length(self):
        """Kills the L142–L148 push-size boundary survivors: 75 bytes stays
        a direct push, 76..255 → PUSHDATA1, 256..65535 → PUSHDATA2."""
        for n, prefix in ((75, "4b"), (76, "4c4c"), (255, "4cff"), (256, "4d0001")):
            asm = "ab" * n
            assert Script.from_asm(asm).hex() == prefix + "ab" * n, f"len {n}"

    def test_pushdata_token_form_roundtrip(self):
        """OP_PUSHDATAx SIZE DATA consumes exactly three tokens (L151–L158
        index arithmetic)."""
        s = Script.from_asm("OP_PUSHDATA1 4c " + "ef" * 76 + " OP_CHECKSIG")
        assert s.hex() == "4c4c" + "ef" * 76 + "ac"

    def test_unknown_op_token_is_value_error(self):
        """Kills the L122 `and` → `or` survivor: an OP_-prefixed token that
        is NOT a known opcode must fail hex validation (ValueError), not
        KeyError into the opcode table."""
        with pytest.raises(ValueError):
            Script.from_asm("OP_NOT_A_REAL_OPCODE")

    def test_invalid_hex_token_rejected(self):
        with pytest.raises(ValueError):
            Script.from_asm("zz")


class TestDmintParamsValidation:
    """glyph/dmint/types.py — __post_init__ boundary mutants. Each guard
    gets its exact boundary: the smallest VALID value must construct and the
    first INVALID value must raise, so `<` → `<=` (and friends) all die."""

    @staticmethod
    def _params(**overrides):
        from pyrxd.glyph.dmint import DaaMode, DmintAlgo, DmintDeployParams
        from pyrxd.glyph.types import GlyphRef

        base = dict(
            contract_ref=GlyphRef(txid="11" * 32, vout=1),
            token_ref=GlyphRef(txid="11" * 32, vout=0),
            max_height=10,
            reward=1000,
            difficulty=1,
            algo=DmintAlgo.SHA256D,
            daa_mode=DaaMode.FIXED,
        )
        base.update(overrides)
        return DmintDeployParams(**base)

    def test_boundary_minimums(self):
        from pyrxd.security.errors import ValidationError

        p = self._params(max_height=1, reward=1, difficulty=1, target_time=1, half_life=1)
        assert (p.max_height, p.reward, p.difficulty, p.target_time, p.half_life) == (1, 1, 1, 1, 1)
        for field, bad in (
            ("max_height", 0),
            ("reward", 0),
            ("difficulty", 0),
            ("target_time", 0),
            ("half_life", 0),
            ("height", -1),
            ("last_time", -1),
        ):
            with pytest.raises(ValidationError):
                self._params(**{field: bad})

    def test_documented_defaults(self):
        p = self._params()
        assert p.target_time == 60
        assert p.half_life == 3600
        assert p.height == 0
        assert p.last_time == 0
        assert p.epoch_length == 2016
        assert p.max_adjustment_log2 == 2

    def test_params_are_frozen(self):
        import dataclasses

        with pytest.raises(dataclasses.FrozenInstanceError):
            self._params().max_height = 99

    def test_max_v2_target_is_2_256_minus_1(self):
        from pyrxd.glyph.dmint import DmintAlgo

        p = self._params(algo=DmintAlgo.BLAKE3, difficulty=1)
        assert p.initial_target == (1 << 256) - 1

    def test_schedule_boundaries(self):
        from pyrxd.glyph.dmint import DaaMode
        from pyrxd.security.errors import ValidationError

        # height 0 in the first entry is VALID (prev_h starts at -1, not -0)
        p = self._params(daa_mode=DaaMode.SCHEDULE, schedule=((0, 1000),))
        assert p.schedule == ((0, 1000),)
        # exactly 10 entries allowed, 11 rejected
        ok = tuple((h, 1000) for h in range(10))
        assert self._params(daa_mode=DaaMode.SCHEDULE, schedule=ok).schedule == ok
        with pytest.raises(ValidationError, match="at most"):
            self._params(daa_mode=DaaMode.SCHEDULE, schedule=tuple((h, 1000) for h in range(11)))
        with pytest.raises(ValidationError, match="height must be >= 0"):
            self._params(daa_mode=DaaMode.SCHEDULE, schedule=((-1, 1000),))
        with pytest.raises(ValidationError, match="ascending"):
            self._params(daa_mode=DaaMode.SCHEDULE, schedule=((5, 1000), (5, 2000)))
        with pytest.raises(ValidationError, match="non-empty"):
            self._params(daa_mode=DaaMode.SCHEDULE, schedule=())

    def test_epoch_guards(self):
        from pyrxd.glyph.dmint import DaaMode
        from pyrxd.security.errors import ValidationError

        min_diff = 0x7FFFFFFFFFFFFFFF // (1 << 48) + 1
        p = self._params(daa_mode=DaaMode.EPOCH, difficulty=min_diff, epoch_length=1)
        assert p.epoch_length == 1
        with pytest.raises(ValidationError):
            self._params(daa_mode=DaaMode.EPOCH, difficulty=min_diff, epoch_length=0)
        with pytest.raises(ValidationError, match="2\\^48"):
            self._params(daa_mode=DaaMode.EPOCH, difficulty=1)
        with pytest.raises(ValidationError, match="max_adjustment_log2"):
            self._params(daa_mode=DaaMode.EPOCH, difficulty=min_diff, max_adjustment_log2=5)

    def test_cbor_payload_guards(self):
        from pyrxd.glyph.dmint import DmintAlgo
        from pyrxd.glyph.dmint.types import DmintCborPayload
        from pyrxd.security.errors import ValidationError

        ok = DmintCborPayload(algo=DmintAlgo.SHA256D, num_contracts=1, max_height=1, reward=0, premine=0, diff=1)
        assert (ok.num_contracts, ok.max_height, ok.reward, ok.premine, ok.diff) == (1, 1, 0, 0, 1)
        for field, bad in (
            ("num_contracts", 0),
            ("max_height", 0),
            ("reward", -1),
            ("premine", -1),
            ("diff", 0),
        ):
            kwargs = dict(algo=DmintAlgo.SHA256D, num_contracts=1, max_height=1, reward=0, premine=0, diff=1)
            kwargs[field] = bad
            with pytest.raises(ValidationError):
                DmintCborPayload(**kwargs)


class TestTransactionInputConstruction:
    """transaction_input.py — constructor mutants."""

    def test_default_output_index_is_zero(self):
        assert TransactionInput(source_txid="ab" * 32).source_output_index == 0

    def test_no_source_at_all_leaves_txid_none(self):
        """Kills the L28 `and not` → `or not` survivor, which would call
        .txid() on a None source_transaction."""
        tx_in = TransactionInput()
        assert tx_in.source_txid is None


class TestTransactionOutputWire:
    """transaction_output.py — constructor default + from_hex guard mutants."""

    def test_default_is_not_change(self):
        assert TransactionOutput(Script(_P2PKH_AA), 1_000).change is False

    def test_from_hex_accepts_large_script_exactly(self):
        """Kills the L54 `!=` → `is not` survivor: for a >256-byte script the
        two equal lengths are distinct int objects, so `is not` would reject
        a VALID output. 300 bytes also exercises the 0xfd varint form."""
        script = bytes([0x4C, 0x2C]) + b"\xee" * 44 + b"\x51" * 254  # 300 bytes total
        raw = (5_000).to_bytes(8, "little") + b"\xfd\x2c\x01" + script
        out = TransactionOutput.from_hex(raw)
        assert out is not None
        assert out.locking_script.serialize() == script
        assert out.satoshis == 5_000

    def test_from_hex_rejects_truncated_script(self):
        """The varint over-claim guard (hashOutputHashes corruption class):
        claiming 300 bytes with fewer available must yield None, not a
        silently truncated output."""
        script = b"\x51" * 100
        raw = (5_000).to_bytes(8, "little") + b"\xfd\x2c\x01" + script
        assert TransactionOutput.from_hex(raw) is None


class TestDmintScriptIntParser:
    """glyph/dmint/chain.py — _parse_script_int/_decode_script_le_int
    mutants. Expected values re-derived from the Bitcoin script-number
    encoding rules (little-endian, sign bit = MSB of last byte)."""

    def test_opcode_forms(self):
        from pyrxd.glyph.dmint.chain import _parse_script_int

        assert _parse_script_int(b"\x00", 0) == (0, 1)
        assert _parse_script_int(b"\x4f", 0) == (-1, 1)
        assert _parse_script_int(b"\x51", 0) == (1, 1)  # OP_1 boundary
        assert _parse_script_int(b"\x60", 0) == (16, 1)  # OP_16 boundary

    def test_direct_push_forms_and_positions(self):
        from pyrxd.glyph.dmint.chain import _parse_script_int

        assert _parse_script_int(b"\x01\x11", 0) == (0x11, 2)
        # little-endian multi-byte with position advance
        assert _parse_script_int(b"\xff\x02\x34\x12\xff", 1) == (0x1234, 4)
        # sign bit: 0x81 encodes -1, 0xff,0x80 encodes -255
        assert _parse_script_int(b"\x01\x81", 0) == (-1, 2)
        assert _parse_script_int(b"\x02\xff\x80", 0) == (-255, 3)

    def test_pushdata1_form(self):
        from pyrxd.glyph.dmint.chain import _parse_script_int

        payload = (123456789).to_bytes(4, "little")
        assert _parse_script_int(b"\x4c\x04" + payload, 0) == (123456789, 6)

    def test_truncated_pushes_raise(self):
        from pyrxd.glyph.dmint.chain import _parse_script_int

        for bad in (b"\x02\x01", b"\x4c", b"\x4c\x04\x01"):
            with pytest.raises(Exception):
                _parse_script_int(bad, 0)


class TestDmintStateParserRejectsCorruption:
    """glyph/dmint/chain.py — _from_v2_script guard mutants: a valid built
    contract corrupted at documented layout offsets must be REJECTED, and
    the offsets are computed from the layout, not the parser."""

    @staticmethod
    def _contract() -> bytes:
        from pyrxd.glyph.dmint import DaaMode, DmintAlgo, DmintDeployParams, build_dmint_contract_script
        from pyrxd.glyph.types import GlyphRef

        return build_dmint_contract_script(
            DmintDeployParams(
                contract_ref=GlyphRef(txid="11" * 32, vout=1),
                token_ref=GlyphRef(txid="11" * 32, vout=0),
                max_height=10,
                reward=1000,
                difficulty=1,
                algo=DmintAlgo.SHA256D,
                daa_mode=DaaMode.FIXED,
            )
        )

    def test_valid_contract_parses(self):
        from pyrxd.glyph.dmint.chain import DmintState

        assert DmintState.from_script(self._contract()).max_height == 10

    def test_wrong_tokenref_opcode_rejected(self):
        from pyrxd.glyph.dmint.chain import DmintState
        from pyrxd.security.errors import ValidationError

        script = bytearray(self._contract())
        # layout: height push (1B for height 0) + d8+36 → tokenRef d0 at 38
        assert script[38] == 0xD0
        script[38] = 0xD1
        with pytest.raises(ValidationError):
            DmintState.from_script(bytes(script))

    def test_truncated_contract_ref_rejected(self):
        from pyrxd.glyph.dmint.chain import DmintState
        from pyrxd.security.errors import ValidationError

        script = self._contract()
        # cut inside the 36-byte contractRef payload (offset 2..37)
        with pytest.raises(ValidationError):
            DmintState.from_script(script[:20])

    def test_wrong_lasttime_push_width_rejected(self):
        from pyrxd.glyph.dmint.chain import DmintState
        from pyrxd.security.errors import ValidationError

        script = bytearray(self._contract())
        # lastTime is the fixed 4-byte push after the five numeric slots;
        # locate it from the layout: 1 (height) + 37 + 37 + 5 pushes for
        # maxHeight(1B opcode-form? no: 10 → 0x01 0x0a = 2B) …
        # Simpler and layout-true: find the documented 04-push preceding the
        # target slot by scanning for the exact 0x04 || last_time(=0) window.
        idx = bytes(script).index(b"\x04\x00\x00\x00\x00")
        script[idx] = 0x05
        with pytest.raises(ValidationError):
            DmintState.from_script(bytes(script))

    def test_missing_state_separator_rejected(self):
        from pyrxd.glyph.dmint.chain import DmintState
        from pyrxd.security.errors import ValidationError

        script = bytearray(self._contract())
        sep = bytes(script).index(b"\xbd")
        script[sep] = 0xBE
        with pytest.raises(ValidationError):
            DmintState.from_script(bytes(script))


class TestTimelockScriptBytes:
    """script/timelock.py — CSV/CLTV builder mutants. Expected bytes are
    hand-assembled from the BIP-65/BIP-112 reference shapes in the module
    docstring, never from the builders."""

    def test_cltv_script_exact_bytes(self):
        """Byte-for-byte against the BIP-65 reference shape:
        <locktime> OP_CHECKLOCKTIMEVERIFY(0xb1) OP_DROP(0x75)
        OP_DUP(0x76) OP_HASH160(0xa9) 0x14 <pkh> OP_EQUALVERIFY(0x88)
        OP_CHECKSIG(0xac), locktime as a minimal script number (LE,
        sign-bit padding)."""
        from pyrxd.script.timelock import build_p2pkh_with_cltv_script

        pkh = b"\xaa" * 20
        tail = b"\x76\xa9\x14" + pkh + b"\x88\xac"
        # 100 = 0x64, no sign bit → single-byte push
        assert build_p2pkh_with_cltv_script(pkh, 100) == b"\x01\x64\xb1\x75" + tail
        # 500_000_000 = 0x1DCD6500 → LE 00 65 cd 1d, 4-byte push (the
        # BIP-65 height/time threshold value itself)
        assert build_p2pkh_with_cltv_script(pkh, 500_000_000) == b"\x04\x00\x65\xcd\x1d\xb1\x75" + tail

    def test_csv_script_exact_bytes_with_sign_padding(self):
        """144 = 0x90 has the sign bit set, so the minimal script number is
        90 00 (two bytes) — a padding rule a wrong encoder silently breaks.
        OP_CHECKSEQUENCEVERIFY is 0xb2."""
        from pyrxd.script.timelock import build_p2pkh_with_csv_script

        pkh = b"\xaa" * 20
        tail = b"\x76\xa9\x14" + pkh + b"\x88\xac"
        assert build_p2pkh_with_csv_script(pkh, 144) == b"\x02\x90\x00\xb2\x75" + tail

    def test_cltv_locktime_bounds(self):
        from pyrxd.script.timelock import build_p2pkh_with_cltv_script
        from pyrxd.security.errors import ValidationError

        pkh = b"\xaa" * 20
        assert build_p2pkh_with_cltv_script(pkh, 0)  # boundary: 0 valid
        assert build_p2pkh_with_cltv_script(pkh, 0xFFFFFFFF)  # max valid
        for bad in (-1, 0x1_0000_0000):
            with pytest.raises(ValidationError):
                build_p2pkh_with_cltv_script(pkh, bad)

    def test_csv_sequence_encoding_per_bip112(self):
        from pyrxd.script.timelock import CsvKind, build_csv_sequence

        # blocks: the value IS the unit count; time: bit 22 set, per BIP-112.
        assert build_csv_sequence(144, CsvKind.BLOCKS) == 144
        assert build_csv_sequence(144, CsvKind.TIME_512_SECONDS) == 144 | (1 << 22)
        assert build_csv_sequence(0xFFFF, CsvKind.BLOCKS) == 0xFFFF  # max units

    def test_csv_sequence_bounds(self):
        from pyrxd.script.timelock import CsvKind, build_csv_sequence
        from pyrxd.security.errors import ValidationError

        assert build_csv_sequence(0, CsvKind.BLOCKS) == 0  # zero units valid
        for bad in (-1, 0x1_0000):
            with pytest.raises(ValidationError):
                build_csv_sequence(bad, CsvKind.BLOCKS)

    def test_csv_max_sequence_fails_on_disable_bit_not_range(self):
        """sequence 0xFFFFFFFF is INSIDE the 32-bit range; it must be
        rejected by the disable-bit guard specifically (kills the range
        `<=` → `<` mutant, which would fire the wrong error first)."""
        from pyrxd.script.timelock import build_p2pkh_with_csv_script
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="disable"):
            build_p2pkh_with_csv_script(b"\xaa" * 20, 0xFFFFFFFF)

    def test_csv_script_rejects_disable_bit(self):
        from pyrxd.script.timelock import build_p2pkh_with_csv_script
        from pyrxd.security.errors import ValidationError

        pkh = b"\xaa" * 20
        assert build_p2pkh_with_csv_script(pkh, 144)  # valid sequence
        with pytest.raises(ValidationError, match="disable"):
            build_p2pkh_with_csv_script(pkh, 144 | (1 << 31))

    def test_pkh_length_guard(self):
        from pyrxd.script.timelock import build_p2pkh_with_cltv_script
        from pyrxd.security.errors import ValidationError

        for bad in (b"\xaa" * 19, b"\xaa" * 21):
            with pytest.raises(ValidationError):
                build_p2pkh_with_cltv_script(bad, 100)


class TestDmintPushEncoders:
    """glyph/dmint/builders.py — _push_minimal/_encode_data_push mutants.
    The negative-number and PUSHDATA branches never execute for valid dMint
    params, so they only die to direct unit pins against the script
    minimal-encoding rules (same rules as TestDmintScriptIntParser, from
    the encode side)."""

    def test_push_minimal_opcode_forms(self):
        from pyrxd.glyph.dmint.builders import _push_minimal

        assert _push_minimal(0) == b"\x00"
        assert _push_minimal(-1) == b"\x4f"
        assert _push_minimal(1) == b"\x51"
        assert _push_minimal(16) == b"\x60"
        assert _push_minimal(17) == b"\x01\x11"  # first non-opcode value

    def test_push_minimal_sign_bit_rules(self):
        from pyrxd.glyph.dmint.builders import _push_minimal

        # 0x90 needs a 00 pad; negative counterpart pads with 0x80
        assert _push_minimal(0x90) == b"\x02\x90\x00"
        assert _push_minimal(-0x90) == b"\x02\x90\x80"
        # small negatives set the sign bit in the last byte
        assert _push_minimal(-2) == b"\x01\x82"
        assert _push_minimal(-255) == b"\x02\xff\x80"
        # positive multi-byte little-endian
        assert _push_minimal(0x1234) == b"\x02\x34\x12"

    def test_push_minimal_length_cliffs(self):
        from pyrxd.glyph.dmint.builders import _push_minimal
        from pyrxd.security.errors import ValidationError

        # 75-byte payload → direct push; 76 → PUSHDATA1; >255 → error
        n75 = int.from_bytes(b"\x7f" * 75, "little")
        assert _push_minimal(n75) == bytes([75]) + b"\x7f" * 75
        n76 = int.from_bytes(b"\x7f" * 76, "little")
        assert _push_minimal(n76) == b"\x4c\x4c" + b"\x7f" * 76
        n255 = int.from_bytes(b"\x7f" * 255, "little")
        assert _push_minimal(n255) == b"\x4c\xff" + b"\x7f" * 255
        with pytest.raises(ValidationError):
            _push_minimal(int.from_bytes(b"\x7f" * 256, "little"))

    def test_push_4bytes_le(self):
        from pyrxd.glyph.dmint.builders import _push_4bytes_le

        assert _push_4bytes_le(0) == b"\x04\x00\x00\x00\x00"
        assert _push_4bytes_le(0x01020304) == b"\x04\x04\x03\x02\x01"

    def test_encode_data_push_cliffs(self):
        from pyrxd.glyph.dmint.builders import _encode_data_push

        assert _encode_data_push(b"\xee" * 75) == bytes([75]) + b"\xee" * 75
        assert _encode_data_push(b"\xee" * 76) == b"\x4c\x4c" + b"\xee" * 76
        assert _encode_data_push(b"\xee" * 255) == b"\x4c\xff" + b"\xee" * 255
        assert _encode_data_push(b"\xee" * 256) == b"\x4d\x00\x01" + b"\xee" * 256
        assert _encode_data_push(b"\xee" * 65535) == b"\x4d\xff\xff" + b"\xee" * 65535
        assert _encode_data_push(b"\xee" * 65536) == b"\x4e\x00\x00\x01\x00" + b"\xee" * 65536


class TestPushRefScannerGuards:
    """transaction_preimage.py — _get_push_refs truncation guards. The
    differential suite only generates WELL-FORMED scripts, so the malformed
    branch needs direct pins (consensus context: a silently short ref would
    corrupt hashOutputHashes)."""

    def test_ref_ending_exactly_at_script_end_is_valid(self):
        from pyrxd.transaction.transaction_preimage import _get_push_refs

        ref = bytes(range(36))
        assert _get_push_refs(b"\xd0" + ref) == [ref]
        assert _get_push_refs(b"\xd8" + ref) == [ref]

    def test_truncated_ref_raises(self):
        from pyrxd.security.errors import ValidationError
        from pyrxd.transaction.transaction_preimage import _get_push_refs

        for short in (0, 1, 35):
            with pytest.raises(ValidationError, match="truncated pushref"):
                _get_push_refs(b"\xd0" + bytes(range(short)))

    def test_single_byte_push_is_not_an_opcode(self):
        """A 1-byte direct push must consume its payload: [0x01, 0xd0]
        contains NO pushref (the 0xd0 is data, not an opcode)."""
        from pyrxd.transaction.transaction_preimage import _get_push_refs

        assert _get_push_refs(b"\x01\xd0") == []


class TestDmintCborPayloadDecode:
    """glyph/dmint/types.py — from_cbor_dict default/except mutants."""

    def test_minimal_dict_defaults(self):
        """Absent optional keys must take the DOCUMENTED defaults (Photonic
        DmintPayload semantics): numContracts 1, premine 0, FIXED DAA at
        60s target."""
        from pyrxd.glyph.dmint import DaaMode, DmintAlgo
        from pyrxd.glyph.dmint.types import DmintCborPayload

        p = DmintCborPayload.from_cbor_dict({"algo": 0, "maxHeight": 5, "reward": 10, "diff": 1})
        assert p.algo == DmintAlgo.SHA256D
        assert p.num_contracts == 1
        assert p.premine == 0
        assert p.daa_mode == DaaMode.FIXED
        assert p.target_block_time == 60
        assert p.half_life == 0
        assert p.window_size == 0

    def test_daa_subdict_defaults(self):
        from pyrxd.glyph.dmint import DaaMode
        from pyrxd.glyph.dmint.types import DmintCborPayload

        p = DmintCborPayload.from_cbor_dict({"algo": 0, "maxHeight": 5, "reward": 10, "diff": 1, "daa": {"mode": 2}})
        assert p.daa_mode == DaaMode.ASERT
        assert p.target_block_time == 60  # daa present, targetBlockTime absent

    def test_missing_and_invalid_algo_are_validation_errors(self):
        """Kills the ExceptionReplacer mutants on the (KeyError, ValueError)
        handler: BOTH failure shapes must surface as ValidationError, never
        a raw KeyError/ValueError."""
        from pyrxd.glyph.dmint.types import DmintCborPayload
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError, match="algo"):
            DmintCborPayload.from_cbor_dict({"maxHeight": 5, "reward": 10, "diff": 1})
        with pytest.raises(ValidationError, match="algo"):
            DmintCborPayload.from_cbor_dict({"algo": 99, "maxHeight": 5, "reward": 10, "diff": 1})

    def test_missing_required_field_is_validation_error(self):
        from pyrxd.glyph.dmint.types import DmintCborPayload
        from pyrxd.security.errors import ValidationError

        with pytest.raises(ValidationError):
            DmintCborPayload.from_cbor_dict({"algo": 0, "reward": 10, "diff": 1})  # no maxHeight

    def test_payload_dataclasses_frozen(self):
        import dataclasses

        from pyrxd.glyph.dmint import DmintAlgo
        from pyrxd.glyph.dmint.types import DmintCborPayload, DmintV1ContractInitialState

        p = DmintCborPayload(algo=DmintAlgo.SHA256D, num_contracts=1, max_height=1, reward=0, premine=0, diff=1)
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.reward = 5
        assert dataclasses.fields(DmintV1ContractInitialState)  # class exists, frozen checked below
        assert DmintV1ContractInitialState.__dataclass_params__.frozen is True


class TestScriptTemplates:
    """script/type.py — template lock/unlock mutants. Locking bytes are
    hand-assembled from the canonical script shapes; sighash suffixes are
    pinned to exactly ONE byte (the `to_bytes(1)` → `to_bytes(2)` class
    would produce node-invalid signatures)."""

    def test_abstract_template_rejects_incomplete_subclass(self):
        from pyrxd.script.type import ScriptTemplate

        class Incomplete(ScriptTemplate):
            pass

        with pytest.raises(TypeError):
            Incomplete()

    def test_op_return_lock_uses_non_minimal_push(self):
        """0x01 as OP_RETURN data must stay a literal `01 01` push — the
        minimal-push form (OP_1) would CHANGE the pushed byte semantics for
        data carriers that read raw pushdata."""
        from pyrxd.script.type import OpReturn

        assert OpReturn().lock([b"\x01"]).serialize() == b"\x00\x6a\x01\x01"
        assert OpReturn().lock(["hi"]).serialize() == b"\x00\x6a\x02hi"

    def test_p2pk_lock_bytes_and_length_guard(self):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PK
        from pyrxd.security.errors import ValidationError

        pub = PrivateKey().public_key().serialize()  # 33-byte compressed
        assert P2PK().lock(pub).serialize() == b"\x21" + pub + b"\xac"
        with pytest.raises(ValidationError):
            P2PK().lock(b"\x02" * 32)

    def test_bare_multisig_lock_bytes_and_threshold_guards(self):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import BareMultisig
        from pyrxd.security.errors import ValidationError

        keys = [PrivateKey().public_key().serialize() for _ in range(3)]
        script = BareMultisig().lock(keys, 2).serialize()
        expected = b"\x52" + b"".join(b"\x21" + k for k in keys) + b"\x53\xae"
        assert script == expected
        for bad in (0, 4):
            with pytest.raises(ValidationError):
                BareMultisig().lock(keys, bad)

    def test_rpuzzle_lock_hash_op_dispatch(self):
        from pyrxd.script.type import RPuzzle

        value = b"\x99" * 32
        base_prefix = bytes.fromhex("78537f7751 7f7c7f75".replace(" ", ""))
        raw = RPuzzle("raw").lock(value).serialize()
        sha = RPuzzle("SHA256").lock(value).serialize()
        assert raw == base_prefix + b"\x20" + value + b"\x88\xac"
        assert sha == base_prefix + b"\xa8" + b"\x20" + value + b"\x88\xac"

    def test_estimated_unlocking_lengths(self):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PK, BareMultisig, RPuzzle

        pk = PrivateKey()
        assert P2PKH().unlock(pk).estimated_unlocking_byte_length() == 107
        pk_uncompressed = PrivateKey()
        pk_uncompressed.compressed = False
        assert P2PKH().unlock(pk_uncompressed).estimated_unlocking_byte_length() == 139
        assert P2PK().unlock(pk).estimated_unlocking_byte_length() == 73
        assert BareMultisig().unlock([pk, pk]).estimated_unlocking_byte_length() == 1 + 73 * 2 + 1
        assert RPuzzle().unlock(k=12345).estimated_unlocking_byte_length() == 108

    @staticmethod
    def _signed_input(template):
        tx_in = _in()
        tx_in.unlocking_script_template = template
        tx = Transaction(tx_inputs=[tx_in], tx_outputs=[_out(_P2PKH_AA, 1_000)])
        tx.sign()
        return tx_in

    def test_p2pkh_sign_appends_exactly_one_sighash_byte(self):
        from pyrxd.keys import PrivateKey

        pk = PrivateKey()
        tx_in = self._signed_input(P2PKH().unlock(pk))
        sig_push, pub_push = tx_in.unlocking_script.chunks
        assert pub_push.data == pk.public_key().serialize()
        assert sig_push.data[0] == 0x30  # DER sequence tag
        assert sig_push.data[-1] == int(tx_in.sighash)  # single 0x41 byte
        assert len(sig_push.data) <= 73  # DER sig (<=72) + 1 sighash byte

    def test_p2pk_and_multisig_sign_sighash_suffix(self):
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import P2PK, BareMultisig

        tx_in = self._signed_input(P2PK().unlock(PrivateKey()))
        (sig_push,) = tx_in.unlocking_script.chunks
        assert sig_push.data[-1] == int(tx_in.sighash)

        tx_in = self._signed_input(BareMultisig().unlock([PrivateKey(), PrivateKey()]))
        chunks = tx_in.unlocking_script.chunks
        assert len(chunks) == 3  # OP_0 + two signatures (NULLDUMMY + loop ran)
        assert chunks[0].op == b"\x00"
        for sig in chunks[1:]:
            assert sig.data[-1] == int(tx_in.sighash)

    def test_rpuzzle_sign_sighash_flag_branches(self):
        """sign_outputs/anyone_can_pay must map to the exact FORKID sighash
        bytes (ALL 0x41, NONE 0x42, SINGLE 0x43, |0x80 for ACP) — and the
        flags are WRITTEN BACK to the input before preimaging."""
        from pyrxd.script.type import RPuzzle

        cases = [
            (dict(sign_outputs="all"), 0x41),
            (dict(sign_outputs="none"), 0x42),
            (dict(sign_outputs="single"), 0x43),
            (dict(sign_outputs="single", anyone_can_pay=True), 0xC3),
        ]
        for kwargs, expected in cases:
            tx_in = self._signed_input(RPuzzle().unlock(k=12345, **kwargs))
            sig_push = tx_in.unlocking_script.chunks[0]
            assert int(tx_in.sighash) == expected, kwargs
            assert sig_push.data[-1] == expected, kwargs

    def test_rpuzzle_honors_provided_private_key(self):
        """Kills the L259 `if private_key is None` negation: a caller's key
        must be used, not silently replaced with a fresh one (nonce-reuse
        safety depends on the caller controlling which key signs)."""
        from pyrxd.keys import PrivateKey
        from pyrxd.script.type import RPuzzle

        pk = PrivateKey()
        tx_in = self._signed_input(RPuzzle().unlock(k=999, private_key=pk))
        pub_push = tx_in.unlocking_script.chunks[-1]
        assert pub_push.data == pk.public_key().serialize()


class TestSignValidation:
    """transaction.py — sign()'s missing-amount validation mutants (L106–108)."""

    def test_sign_rejects_uncomputed_change_output(self):
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, None, change=True)])
        with pytest.raises(ValueError, match="fee\\(\\)"):
            tx.sign()

    def test_sign_rejects_missing_amount_on_regular_output(self):
        tx = Transaction(tx_inputs=[_in()], tx_outputs=[_out(_P2PKH_AA, None)])
        with pytest.raises(ValueError, match="missing an amount"):
            tx.sign()

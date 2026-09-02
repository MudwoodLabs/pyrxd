"""Locking-script classification in ``pyrxd glyph inspect``.

Every shape here is built by **its own production builder** and then fed to
``_inspect_script``. No hand-typed hex blobs for the positive cases: a golden
string can only prove the classifier still agrees with whatever was pasted the
day the test was written, whereas a builder round-trip breaks the moment the
two disagree — which is the failure this file exists to catch.

Each newly-classified shape gets a matched pair:

* a positive test, built from the builder;
* a **near-miss** test, which mutates one byte / one field of that same script
  and asserts the classifier does NOT claim it. A classifier that says yes too
  easily is worse than one that says unknown, and the near-misses are the only
  thing standing between "recognises the shape" and "recognises anything
  vaguely shaped like it".

The one exception to the no-hex rule is ``_DEPLOYED_SOULBOUND_SPK``, a real
mainnet UTXO's scriptPubKey. It is not a shape any pyrxd builder emits, so
there is nothing to build it from; it is here to pin the tier boundary between
``soulbound-covenant`` (exact builder match) and
``self-replicating-covenant`` (structural markers only).
"""

from __future__ import annotations

import os

import pytest

from pyrxd.constants import SEQUENCE_LOCKTIME_DISABLE_FLAG
from pyrxd.glyph._inspect_core import _classify_input, _inspect_script
from pyrxd.glyph.dmint.builders import build_dmint_contract_script, build_dmint_v1_contract_script
from pyrxd.glyph.dmint.types import DmintDeployParams
from pyrxd.glyph.script import build_ft_locking_script, build_mutable_nft_script, build_nft_locking_script
from pyrxd.glyph.soulbound_covenant import (
    build_composable_soulbound_nft_covenant,
    build_soulbound_nft_covenant,
    parse_soulbound_nft_covenant,
)
from pyrxd.glyph.soulbound_detect import Transferability, classify_soulbound
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.timelock import (
    LOCKTIME_THRESHOLD,
    CsvKind,
    build_csv_sequence,
    build_p2pkh_with_cltv_script,
    build_p2pkh_with_csv_script,
    parse_p2pkh_timelock_script,
)
from pyrxd.utils import encode_int

# Keys are generated, never written down: a hand-typed test key with a weak
# private half was swept by a live bot once. ``PrivateKey()`` seeds from the
# CSPRNG.
_PKH = PrivateKey().public_key().hash160()
_OTHER_PKH = PrivateKey().public_key().hash160()
_REF = GlyphRef(txid=os.urandom(32).hex(), vout=3)
_REF2 = GlyphRef(txid=os.urandom(32).hex(), vout=1)

_OP_CLTV = 0xB1
_OP_CSV = 0xB2
_OP_DROP = 0x75

# Live mainnet "TheArtofSatoshi" soulbound authority token, UTXO
# 4b25a66668c41536a654151fc92e4f115b4c36d7ca2db08d2e121b36e0243f5b:0. Uses the
# code-script-equality idiom rather than pyrxd's full-bytecode one.
_DEPLOYED_SOULBOUND_SPK = bytes.fromhex(
    "d8020eab29108de31237293118da44eb870882889ab8c7713a2c5302d73f6b0d7e00000000"
    "7c637576a914716477de74200c2e2416177c53aea716f5035ac288ad00eac0e98767de009c69"
    "76a914716477de74200c2e2416177c53aea716f5035ac288ad5168"
)


def _classify(script: bytes) -> dict:
    return _inspect_script(bytes(script).hex())


# ─────────────────────────────────────────────────── soulbound covenants ──


class TestSoulboundCovenant:
    """Both variants classify; both report the covenant's own facts."""

    @pytest.mark.parametrize(
        ("builder", "variant"),
        [
            (build_soulbound_nft_covenant, "fixed-index"),
            (build_composable_soulbound_nft_covenant, "composable"),
        ],
    )
    def test_builder_output_classifies_as_soulbound(self, builder, variant):
        spk = builder(_REF, _PKH).funded_spk
        row = _classify(spk)
        assert row["type"] == "soulbound-covenant"
        assert row["variant"] == variant
        assert row["transferability"] == "soulbound_covenant"
        assert row["bound_ref_txid"] == _REF.txid
        assert row["bound_ref_vout"] == _REF.vout
        assert row["bound_ref_outpoint"] == f"{_REF.txid}:{_REF.vout}"
        assert row["owner_pkh"] == _PKH.hex()
        assert row["has_self_replication"] is True
        assert row["has_burn_branch"] is True

    @pytest.mark.parametrize(
        "builder",
        [build_soulbound_nft_covenant, build_composable_soulbound_nft_covenant],
    )
    def test_note_does_not_overclaim(self, builder):
        """The label is about the LOCK, not about the token behind the ref."""
        note = _classify(builder(_REF, _PKH).funded_spk)["note"]
        assert "does NOT verify" in note
        assert "pre-external-audit" in note

    # ── near misses ──────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        "builder",
        [build_soulbound_nft_covenant, build_composable_soulbound_nft_covenant],
    )
    @pytest.mark.parametrize("index", [0, 37, 38, -25, -24, -2, -1])
    def test_single_byte_mutation_is_not_soulbound(self, builder, index):
        """Flip one STRUCTURAL byte and the exact match must fail.

        The offsets are the singleton opcode (0), the first bytes of the
        covenant body (37, 38, just past the 36-byte ref operand), and the
        P2PKH tail's fixed bytes (-25 OP_DUP, -24 OP_HASH160, -2
        OP_EQUALVERIFY, -1 OP_CHECKSIG). The ref operand and the pkh are
        deliberately excluded: those are the *parameters* the parser recovers,
        so changing them yields a different-but-still-valid covenant, which
        :meth:`test_different_parameters_still_classify` pins separately.
        """
        spk = bytearray(builder(_REF, _PKH).funded_spk)
        spk[index] ^= 0xFF
        assert _classify(bytes(spk))["type"] != "soulbound-covenant"

    @pytest.mark.parametrize(
        "builder",
        [build_soulbound_nft_covenant, build_composable_soulbound_nft_covenant],
    )
    def test_different_parameters_still_classify(self, builder):
        """Changing the ref or the owner is a different covenant, not a
        broken one — and the parser must report the NEW values, not the old."""
        spk = builder(_REF2, _OTHER_PKH).funded_spk
        row = _classify(spk)
        assert row["type"] == "soulbound-covenant"
        assert row["bound_ref_outpoint"] == f"{_REF2.txid}:{_REF2.vout}"
        assert row["owner_pkh"] == _OTHER_PKH.hex()

    @pytest.mark.parametrize(
        "builder",
        [build_soulbound_nft_covenant, build_composable_soulbound_nft_covenant],
    )
    def test_truncated_covenant_is_not_soulbound(self, builder):
        spk = builder(_REF, _PKH).funded_spk
        assert _classify(spk[:-1])["type"] != "soulbound-covenant"
        assert _classify(spk[:40])["type"] != "soulbound-covenant"

    def test_body_swapped_between_variants_is_not_soulbound(self):
        """A chimera of the two variants matches neither builder.

        Both start with the same 37-byte ``d8 <ref>`` prologue and end with the
        same 25-byte P2PKH tail, so the splice has to land inside the body for
        the graft to be a real one — hence the mid-body offset and the
        assertion that the result differs from both parents.
        """
        fixed = build_soulbound_nft_covenant(_REF, _PKH).funded_spk
        composable = build_composable_soulbound_nft_covenant(_REF, _PKH).funded_spk
        chimera = fixed[:45] + composable[45:]
        assert chimera != fixed
        assert chimera != composable
        assert _classify(chimera)["type"] != "soulbound-covenant"

    def test_plain_nft_singleton_is_not_soulbound(self):
        """``d8 <ref> OP_DROP <P2PKH>`` — a Photonic 'soulbound' NFT, which is
        soulbound in metadata only and freely transferable at consensus."""
        assert _classify(build_nft_locking_script(_PKH, _REF))["type"] == "nft"

    def test_parse_helper_recovers_the_builder_parameters(self):
        for builder, variant in (
            (build_soulbound_nft_covenant, "fixed-index"),
            (build_composable_soulbound_nft_covenant, "composable"),
        ):
            spk = builder(_REF, _PKH).funded_spk
            parsed = parse_soulbound_nft_covenant(spk)
            assert parsed is not None
            ref, pkh, got_variant = parsed
            assert (ref.txid, ref.vout, pkh, got_variant) == (_REF.txid, _REF.vout, _PKH, variant)

    def test_parse_helper_returns_none_on_junk_and_never_raises(self):
        """Runs over arbitrary chain bytes, so a raise would be a crash in the
        inspector rather than a classification."""
        junk = [
            b"",
            b"\xd8",
            b"\xd8" * 80,  # ref opcodes all the way down: the walk must not run off
            b"\x00" * 73,
            b"\xd8" + b"\x00" * 36 + b"\x00" * 36,  # right length, wrong body
            os.urandom(73),
            os.urandom(78),
        ]
        for script in junk:
            assert parse_soulbound_nft_covenant(script) is None


class TestSelfReplicatingTier:
    """The weaker tier exists so a marker match is never sold as a soulbound
    token — and so the shapes that trip those markers are named correctly."""

    def test_deployed_mainnet_shape_is_markers_only(self):
        row = _classify(_DEPLOYED_SOULBOUND_SPK)
        assert row["type"] == "self-replicating-covenant"
        assert row["has_self_replication"] is True
        assert "NOT proof" in row["note"]

    def test_weak_tier_withholds_the_transferability_verdict(self):
        """The caveat lives in ``note``; a machine consumer reads
        ``transferability``. Emitting ``soulbound_covenant`` there handed the
        exact claim this tier exists to withhold to the only reader that cannot
        see the caveat, so the key is absent instead."""
        row = _classify(_DEPLOYED_SOULBOUND_SPK)
        assert "transferability" not in row
        # The exact tier still states its verdict — that one is earned.
        exact = _classify(build_soulbound_nft_covenant(_REF, _PKH).funded_spk)
        assert exact["transferability"] == "soulbound_covenant"

    @pytest.mark.parametrize(
        ("label", "script"),
        [
            (
                "dmint-v2",
                build_dmint_contract_script(
                    DmintDeployParams(contract_ref=_REF, token_ref=_REF2, max_height=1000, reward=100_000, difficulty=1)
                ),
            ),
            (
                "dmint-v1",
                build_dmint_v1_contract_script(
                    height=0,
                    contract_ref=_REF,
                    token_ref=_REF2,
                    max_height=1000,
                    reward=100_000,
                    target=0x7FFFFFFFFFFFFF,
                ),
            ),
            ("mut", build_mutable_nft_script(_REF, os.urandom(32))),
        ],
    )
    def test_self_replicating_token_shapes_keep_their_own_label(self, label, script):
        """dMint contracts and mutable NFTs bind a singleton AND self-replicate,
        so they trip every marker ``classify_soulbound`` looks for.

        They must still be reported as what they are. This is the regression
        guard on classifier ORDERING: move the soulbound fallback above the
        dMint / mut parsers and a token contract starts reading as a credential.

        The premise is asserted first, deliberately. Without it this test would
        keep passing if ``classify_soulbound`` stopped matching these shapes —
        still green, but no longer guarding anything, and the docstring above
        would quietly become false.
        """
        assert classify_soulbound(bytes(script)).transferability is Transferability.SOULBOUND_COVENANT, (
            "premise broken: this shape no longer trips the soulbound markers, so this test "
            "is not exercising the ordering it claims to guard"
        )
        row = _classify(script)
        assert row["type"] == ("mut" if label == "mut" else "dmint")
        assert row["type"] not in ("soulbound-covenant", "self-replicating-covenant")


# ────────────────────────────────────────────────────── time-lock scripts ──


class TestTimelockScripts:
    """CLTV / CSV P2PKH locks — in practice these are HTLC refund outputs."""

    @pytest.mark.parametrize("locktime", [0, 1, 16, 17, 144, 800_000, LOCKTIME_THRESHOLD - 1])
    def test_cltv_height(self, locktime):
        row = _classify(build_p2pkh_with_cltv_script(_PKH, locktime))
        assert row["type"] == "p2pkh-cltv"
        assert row["owner_pkh"] == _PKH.hex()
        assert row["locktime_value"] == locktime
        assert row["locktime_basis"] == "height"
        assert row["locktime_units"] == locktime

    @pytest.mark.parametrize("locktime", [LOCKTIME_THRESHOLD, 1_800_000_000, 0xFFFFFFFF])
    def test_cltv_unix_time(self, locktime):
        row = _classify(build_p2pkh_with_cltv_script(_PKH, locktime))
        assert row["type"] == "p2pkh-cltv"
        assert row["locktime_basis"] == "unix_time"
        assert row["locktime_units"] == locktime

    @pytest.mark.parametrize("locktime", [0, 144, 800_000, LOCKTIME_THRESHOLD, 1_800_000_000])
    def test_cltv_reports_the_earliest_block_not_the_encoded_value(self, locktime):
        """The encoded value is a floor on the SPENDING TX's nLockTime, and
        ``IsFinalTx`` (Radiant-Core src/consensus/tx_verify.cpp at the vendored
        pin 45e0aa4 / v3.1.2) is ``lockTime < lockTimeLimit`` — strictly less
        than the CONTAINING block's height/time. So the first block that can
        carry the spend is one past the encoded value, and reporting the
        encoded value as "spendable at" was off by one block in the direction
        that makes a refund leg look available before it is.

        Derived on the Python side on purpose: the CLI, ``--json`` and the
        browser renderer all print this number and must not each compute it."""
        row = _classify(build_p2pkh_with_cltv_script(_PKH, locktime))
        assert row["locktime_earliest"] == locktime + 1

    def test_csv_has_no_absolute_earliest(self):
        """A relative lock has no absolute answer — it is measured from a
        confirmation height the locking script does not carry."""
        row = _classify(build_p2pkh_with_csv_script(_PKH, build_csv_sequence(144, CsvKind.BLOCKS)))
        assert "locktime_earliest" not in row


class TestWallClockCltvIsReachable:
    """A 32-byte script is 64 hex, and so is a txid.

    Every CLTV deadline in ``[LOCKTIME_THRESHOLD, 2**31)`` — every Unix deadline
    from 1985 to 2038 — encodes as a minimal 4-byte push, so the script is
    exactly 32 bytes. ``_classify_input`` claimed all 64-hex input as a txid, so
    the CLI answered "this looks like a txid (64 hex chars)" and the browser did
    the same, for precisely the shape the time-lock classifier exists to
    explain: the wall-clock HTLC refund leg. ``--fetch`` would have sent the
    script bytes to an ElectrumX server as a transaction id.
    """

    @pytest.mark.parametrize("locktime", [LOCKTIME_THRESHOLD, 1_767_225_600, 2**31 - 1])
    def test_a_wall_clock_cltv_script_is_read_as_a_script(self, locktime):
        script = build_p2pkh_with_cltv_script(_PKH, locktime)
        assert len(script.hex()) == 64, "premise: this shape is exactly txid-length"
        form, value = _classify_input(script.hex())
        assert form == "script"
        assert _inspect_script(value)["type"] == "p2pkh-cltv"

    def test_a_height_based_cltv_that_happens_to_be_64_hex_also_works(self):
        """Not only the unix-time basis: any 4-byte minimal push lands here.
        ``0x01000000`` is 16,777,216 — below LOCKTIME_THRESHOLD, so a height."""
        script = build_p2pkh_with_cltv_script(_PKH, 0x01000000)
        assert len(script.hex()) == 64
        assert _classify_input(script.hex())[0] == "script"
        assert _inspect_script(script.hex())["locktime_basis"] == "height"

    def test_random_txids_are_still_txids(self):
        """The preference must be narrow enough that it cannot swallow the form
        it shares a length with. 20,000 draws, zero misroutes; the template
        parse pins 7 bytes at fixed offsets plus push minimality, so a real
        collision is a ~2**-56 event."""
        assert all(_classify_input(os.urandom(32).hex())[0] == "txid" for _ in range(20_000))

    def test_an_op_return_shaped_txid_is_still_a_txid(self):
        """The counter-example that rules out a wider rule: ``op_return``
        classifies on the FIRST BYTE alone, so preferring "any 64 hex that
        classifies" would misroute 1 txid in 256."""
        assert _classify_input("6a" + os.urandom(31).hex())[0] == "txid"

    def test_a_near_miss_timelock_of_txid_length_is_still_a_txid(self):
        """One byte off the template and the preference must not fire."""
        broken = bytearray(build_p2pkh_with_cltv_script(_PKH, 1_767_225_600))
        broken[-1] ^= 0xFF  # OP_CHECKSIG -> something else
        assert len(bytes(broken).hex()) == 64
        assert _classify_input(bytes(broken).hex())[0] == "txid"

    @pytest.mark.parametrize("blocks", [1, 16, 144, 65535])
    def test_csv_blocks(self, blocks):
        seq = build_csv_sequence(blocks, CsvKind.BLOCKS)
        row = _classify(build_p2pkh_with_csv_script(_PKH, seq))
        assert row["type"] == "p2pkh-csv"
        assert row["owner_pkh"] == _PKH.hex()
        assert row["locktime_value"] == seq
        assert row["locktime_basis"] == "blocks"
        assert row["locktime_units"] == blocks
        assert row["relative_lock_disabled"] is False

    @pytest.mark.parametrize("units", [1, 100, 65535])
    def test_csv_512_second_units(self, units):
        seq = build_csv_sequence(units, CsvKind.TIME_512_SECONDS)
        row = _classify(build_p2pkh_with_csv_script(_PKH, seq))
        assert row["type"] == "p2pkh-csv"
        assert row["locktime_basis"] == "time_512s"
        assert row["locktime_units"] == units
        # The raw value keeps the type flag; the decoded count does not.
        assert row["locktime_value"] != units

    def test_csv_with_zero_units_is_still_classified(self):
        """``build_p2pkh_with_csv_script`` refuses to emit a zero-unit lock, but
        one can exist on-chain — anyone can write the bytes — and the inspector's
        job is to READ what is there, not only what this library will build.

        So the builder's floor must not become a blind spot in the reader. Hand-
        constructed for exactly that reason, following the disable-bit case below.
        """
        script = bytes([0x00, _OP_CSV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        row = _classify(script)
        assert row["type"] == "p2pkh-csv"
        assert row["locktime_units"] == 0
        assert row["relative_lock_disabled"] is False

    def test_csv_with_disable_bit_is_reported_as_a_no_op(self):
        """``build_p2pkh_with_csv_script`` refuses to emit this, but it can
        exist on-chain — and there it means the relative lock does nothing.
        Reporting the delay without the flag would be actively misleading."""
        sequence = SEQUENCE_LOCKTIME_DISABLE_FLAG | 144
        script = encode_int(sequence) + bytes([_OP_CSV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        row = _classify(script)
        assert row["type"] == "p2pkh-csv"
        assert row["relative_lock_disabled"] is True
        assert row["locktime_units"] == 144

    # ── near misses ──────────────────────────────────────────────────────

    def test_missing_op_drop_is_not_a_timelock(self):
        script = encode_int(144) + bytes([_OP_CLTV]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        assert _classify(script)["type"] != "p2pkh-cltv"

    def test_wrong_verify_opcode_is_not_a_timelock(self):
        # OP_NOP (0x61) in the CLTV/CSV slot: same length, no time-lock.
        script = encode_int(144) + bytes([0x61, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        row = _classify(script)
        assert row["type"] not in ("p2pkh-cltv", "p2pkh-csv")

    def test_non_minimal_value_push_is_not_a_timelock(self):
        """``02 05 00`` pushes 5 the long way. MINIMALDATA rejects it on-chain,
        so the bytes are not the script they appear to be — and two encodings
        must never both be reported as the same lock."""
        script = b"\x02\x05\x00" + bytes([_OP_CLTV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        assert _classify(script)["type"] != "p2pkh-cltv"
        assert parse_p2pkh_timelock_script(script) is None
        # ...while the minimal encoding of the same value does classify.
        minimal = encode_int(5) + bytes([_OP_CLTV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        assert _classify(minimal)["type"] == "p2pkh-cltv"

    def test_negative_value_is_not_a_timelock(self):
        """OP_1NEGATE. Consensus fails CLTV/CSV outright on a negative stack
        value, so this is not a lock — it is an unspendable output."""
        script = b"\x4f" + bytes([_OP_CLTV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        assert _classify(script)["type"] != "p2pkh-cltv"

    def test_trailing_bytes_after_the_p2pkh_tail_is_not_a_timelock(self):
        script = build_p2pkh_with_cltv_script(_PKH, 144) + b"\x51"
        assert _classify(script)["type"] != "p2pkh-cltv"

    def test_broken_p2pkh_tail_is_not_a_timelock(self):
        spk = bytearray(build_p2pkh_with_cltv_script(_PKH, 144))
        spk[-1] ^= 0xFF  # OP_CHECKSIG -> something else
        assert _classify(bytes(spk))["type"] != "p2pkh-cltv"

    def test_plain_p2pkh_is_not_a_timelock(self):
        assert _classify(b"\x76\xa9\x14" + _PKH + b"\x88\xac")["type"] == "p2pkh"

    @pytest.mark.parametrize(
        ("label", "script"),
        [
            ("empty", b""),
            ("a direct push whose data is entirely missing", b"\x4b"),
            ("all 0xff", b"\xff" * 28),
            ("plain p2pkh", b"\x76\xa9\x14" + _PKH + b"\x88\xac"),
            ("a cltv script one byte short", build_p2pkh_with_cltv_script(_PKH, 144)[:-1]),
            ("no value push at all", bytes([_OP_CLTV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"),
        ],
    )
    def test_parser_returns_none_on_junk(self, label, script):
        assert parse_p2pkh_timelock_script(script) is None, label

    def test_parser_never_raises_and_can_only_claim_what_the_bytes_say(self):
        """Runs over arbitrary chain bytes, so a raise would be a crash in the
        inspector rather than a classification.

        The second half used to read ``result is None or result.kind in
        ("cltv", "csv")`` — which cannot fail: ``kind`` is only ever assigned
        those two strings, so a parser that fabricated a time-lock for **every**
        input, ``b""`` included, still passed. What is checked instead is that
        anything the parser DOES claim is readable back out of the bytes at the
        fixed offsets the template pins. A fabricating parser fails on the first
        short input."""
        for size in (0, 1, 26, 27, 28, 31, 32, 64, 200):
            for _ in range(200):
                script = os.urandom(size)
                parsed = parse_p2pkh_timelock_script(script)
                if parsed is None:
                    continue
                assert script[-25:-22] == b"\x76\xa9\x14"  # OP_DUP OP_HASH160 PUSH20
                assert script[-2:] == b"\x88\xac"  # OP_EQUALVERIFY OP_CHECKSIG
                assert script[-26] == _OP_DROP
                assert script[-27] == (_OP_CLTV if parsed.kind == "cltv" else _OP_CSV)
                assert parsed.owner_pkh == script[-22:-2]

    def test_two_value_pushes_is_not_a_timelock(self):
        """The prologue must be exactly ONE push — a script with junk in front
        of the value is a different script."""
        script = encode_int(7) + encode_int(144) + bytes([_OP_CLTV, _OP_DROP]) + b"\x76\xa9\x14" + _PKH + b"\x88\xac"
        assert _classify(script)["type"] != "p2pkh-cltv"


# ──────────────────────────────────────────────────────────────── P2SH ──


class TestP2sh:
    def test_p2sh_classifies(self):
        row = _classify(b"\xa9\x14" + _PKH + b"\x87")
        assert row["type"] == "p2sh"
        assert row["script_hash"] == _PKH.hex()

    def test_bare_p2sh_reaches_the_classifier_from_the_input_dispatcher(self):
        """23 bytes / 46 hex is below the old 50-hex floor, so a pasted P2SH
        used to be rejected as "could not classify input" before any classifier
        ran. The floor moved; this is the regression guard on that path."""
        spk_hex = (b"\xa9\x14" + _PKH + b"\x87").hex()
        assert len(spk_hex) == 46
        assert _classify_input(spk_hex) == ("script", spk_hex)

    @pytest.mark.parametrize(
        "script",
        [
            b"\xa9\x14" + _PKH + b"\x88",  # OP_EQUALVERIFY, not OP_EQUAL
            b"\xa9\x13" + _PKH[:19] + b"\x87",  # 19-byte hash
            b"\xa8\x14" + _PKH + b"\x87",  # OP_SHA256, not OP_HASH160
            b"\xa9\x14" + _PKH + b"\x87\x51",  # trailing byte
        ],
    )
    def test_near_miss_is_not_p2sh(self, script):
        assert _classify(script)["type"] != "p2sh"


# ───────────────────────────────────────── unknown scripts report refs ──


class TestUnknownReportsRefs:
    """An unnamed script is still worth one fact: is it token-bearing?

    Spending a ref-carrying UTXO as plain funding burns the token it carries,
    so ``unknown`` reporting nothing at all was the least useful honest answer
    available.
    """

    def test_unknown_ref_free_script_says_so(self):
        row = _classify(b"\x51" * 60)  # 60x OP_1: decodes, carries no refs
        assert row["type"] == "unknown"
        assert row["token_bearing"] is False
        assert row["input_refs"] == []

    def test_unknown_ref_bearing_script_lists_the_refs(self):
        # OP_PUSHINPUTREF <ref> then filler — not a shape any classifier claims.
        script = b"\xd0" + _REF.to_bytes() + b"\x51" * 30
        row = _classify(script)
        assert row["type"] == "unknown"
        assert row["token_bearing"] is True
        assert row["input_refs"] == [{"opcode": "0xd0", "ref_outpoint": f"{_REF.txid}:{_REF.vout}"}]

    def test_ref_byte_inside_pushdata_is_not_counted(self):
        """The whole reason the walk is opcode-aware. A 0xd0 byte inside pushed
        data is data, and counting it would fabricate a ref."""
        payload = b"\xd0" * 40
        script = bytes([len(payload)]) + payload + b"\x51" * 10
        row = _classify(script)
        assert row["type"] == "unknown"
        assert row["token_bearing"] is False

    def test_undecodable_script_reports_unknown_not_false(self):
        """A walk that cannot finish has not proven the absence of a ref.
        ``null`` says that; ``false`` would be a claim the walk did not earn."""
        script = b"\x51" * 30 + b"\xd0" + b"\x00" * 10  # ref operand truncated
        row = _classify(script)
        assert row["type"] == "unknown"
        assert row["token_bearing"] is None
        assert row["input_refs"] == []
        assert row["referenced_refs"] == []


class TestWalkSetIsNotTheCollectSet:
    """Carrying a ref and naming one are different facts, and only the first
    burns.

    ``CScript::GetPushRefs`` (tests/vendor/radiant_core/script.cpp:586-607)
    files 0xd0 ``OP_PUSHINPUTREF`` and 0xd8 ``OP_PUSHINPUTREFSINGLETON`` into
    ``foundPushRefs``; 0xd1 ``OP_REQUIREINPUTREF`` goes to ``foundRequiredRefs``
    and 0xd2 / 0xd3 to the disallow sets. All five must be **walked** (skip one
    and the program counter desynchronises — the 2026 sighash bug), but only
    the first two are **collected** as evidence the output holds a token.

    The inspector used to collect the whole walk set, so every credential-gate
    covenant (``OP_REQUIREINPUTREF <ref>``, the idiom in
    ``glyph/soulbound_covenant.py``) came back "token-bearing: YES — Do NOT
    spend this as plain funding". It carries nothing. These four cases pin the
    boundary in both directions.
    """

    @pytest.mark.parametrize("opcode", [0xD0, 0xD8])
    def test_push_ref_opcodes_are_token_bearing(self, opcode):
        row = _classify(bytes([opcode]) + _REF.to_bytes() + b"\x51" * 25)
        assert row["type"] == "unknown"
        assert row["token_bearing"] is True
        assert row["input_refs"] == [{"opcode": f"0x{opcode:02x}", "ref_outpoint": f"{_REF.txid}:{_REF.vout}"}]
        assert row["referenced_refs"] == []

    @pytest.mark.parametrize("opcode", [0xD1, 0xD2, 0xD3])
    def test_require_and_disallow_opcodes_are_not_token_bearing(self, opcode):
        """The regression. A script whose only ref opcode is a gate holds no
        token, and saying it does is a burn warning that cannot come true."""
        row = _classify(bytes([opcode]) + _REF.to_bytes() + b"\x51" * 25)
        assert row["type"] == "unknown"
        assert row["token_bearing"] is False
        assert row["input_refs"] == []
        assert row["referenced_refs"] == [{"opcode": f"0x{opcode:02x}", "ref_outpoint": f"{_REF.txid}:{_REF.vout}"}]

    def test_gate_plus_carrier_reports_both_separately(self):
        """The realistic shape: a covenant that requires one credential ref and
        carries its own singleton. Both are reported; only one is the token."""
        script = b"\xd1" + _REF2.to_bytes() + b"\xd8" + _REF.to_bytes() + b"\x51" * 20
        row = _classify(script)
        assert row["token_bearing"] is True
        assert row["input_refs"] == [{"opcode": "0xd8", "ref_outpoint": f"{_REF.txid}:{_REF.vout}"}]
        assert row["referenced_refs"] == [{"opcode": "0xd1", "ref_outpoint": f"{_REF2.txid}:{_REF2.vout}"}]

    def test_the_walk_still_advances_past_a_gate_opcode(self):
        """Not collecting 0xd1 must not mean not walking it. If the walk
        skipped its 36-byte operand it would resynchronise inside the operand
        and report a phantom ref — the failure mode that is worse than either
        of the above."""
        script = b"\xd1" + _REF2.to_bytes() + b"\xd0" + _REF.to_bytes()
        row = _classify(script)
        assert [r["ref_outpoint"] for r in row["input_refs"]] == [f"{_REF.txid}:{_REF.vout}"]
        assert [r["ref_outpoint"] for r in row["referenced_refs"]] == [f"{_REF2.txid}:{_REF2.vout}"]


# ──────────────────────────────────────── existing shapes are unchanged ──


class TestExistingShapesUnchanged:
    """The additions are additive; the shapes that already classified still do,
    and still from their own builders."""

    @pytest.mark.parametrize(
        ("expected", "script"),
        [
            ("nft", build_nft_locking_script(_PKH, _REF)),
            ("ft", build_ft_locking_script(_PKH, _REF)),
            ("mut", build_mutable_nft_script(_REF, os.urandom(32))),
            ("p2pkh", b"\x76\xa9\x14" + _PKH + b"\x88\xac"),
        ],
    )
    def test_shape_still_classifies(self, expected, script):
        assert _classify(script)["type"] == expected

    def test_json_keys_are_additive_for_existing_types(self):
        """``--json`` is machine-consumed: the keys an ``nft`` row carried
        before must still be there, with the same names."""
        row = _classify(build_nft_locking_script(_OTHER_PKH, _REF))
        for key in ("form", "length", "hex", "type", "ref_txid", "ref_vout", "ref_outpoint", "owner_pkh"):
            assert key in row

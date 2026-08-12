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
        """
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

    @pytest.mark.parametrize("blocks", [0, 1, 16, 144, 65535])
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

    def test_parser_returns_none_on_junk_and_never_raises(self):
        junk = [
            b"",
            b"\x4b",  # a direct push whose data is entirely missing
            b"\xff" * 28,
            b"\x76\xa9\x14" + _PKH + b"\x88\xac",
            os.urandom(28),
            os.urandom(31),
        ]
        for script in junk:
            result = parse_p2pkh_timelock_script(script)
            assert result is None or result.kind in ("cltv", "csv")

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

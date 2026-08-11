"""Tests for MUT, CONTAINER, and WAVE GlyphBuilder methods, and updated GlyphInspector."""

from __future__ import annotations

import hashlib

import cbor2
import pytest

from pyrxd.glyph._inspect_core import _inspect_script
from pyrxd.glyph.builder import (
    ContainerChildRevealScripts,
    ContainerRevealScripts,
    GlyphBuilder,
    MutableRevealScripts,
    TransferParams,
)
from pyrxd.glyph.inspector import GlyphInspector
from pyrxd.glyph.payload import encode_payload
from pyrxd.glyph.script import (
    MUTABLE_NFT_SCRIPT_RE,
    build_mutable_nft_script,
    build_nft_locking_script,
    is_legacy_container_script,
    parse_legacy_container_script,
    parse_mutable_nft_script,
)
from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol, GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

TXID = "aa" * 32
TXID2 = "cc" * 32
PKH = Hex20(bytes.fromhex("bb" * 20))
REF = GlyphRef(txid=Txid(TXID), vout=0)
CHILD_REF = GlyphRef(txid=Txid(TXID2), vout=1)


def _cbor(protocol: list[int], name: str = "test") -> bytes:
    cbor_bytes, _ = encode_payload(GlyphMetadata(name=name, protocol=protocol))
    return cbor_bytes


def _cbor_child(protocol: list[int], name: str, *, container_refs: list[GlyphRef]) -> bytes:
    cbor_bytes, _ = encode_payload(GlyphMetadata(name=name, protocol=protocol, container_refs=tuple(container_refs)))
    return cbor_bytes


MUT_CBOR = _cbor([GlyphProtocol.NFT, GlyphProtocol.MUT], "mut-test")
CONTAINER_CBOR = _cbor([GlyphProtocol.NFT, GlyphProtocol.CONTAINER], "container-test")
WAVE_CBOR = _cbor([GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE], "myname.rxd")

BUILDER = GlyphBuilder()
INSPECTOR = GlyphInspector()


# ---------------------------------------------------------------------------
# MUT builder tests
# ---------------------------------------------------------------------------


class TestPrepareMutableReveal:
    def test_returns_mutable_reveal_scripts(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert isinstance(result, MutableRevealScripts)

    def test_nft_script_is_63_bytes(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.nft_script) == 63

    def test_contract_script_is_174_bytes(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.contract_script) == 174

    def test_contract_script_matches_mutable_re(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert MUTABLE_NFT_SCRIPT_RE.fullmatch(result.contract_script.hex())

    def test_payload_hash_is_32_bytes(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.payload_hash) == 32

    def test_ref_matches_commit_txid_and_vout(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 3, MUT_CBOR, PKH)
        assert result.ref.txid == TXID
        assert result.ref.vout == 3

    def test_payload_hash_embedded_in_contract_script(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        parsed = parse_mutable_nft_script(result.contract_script)
        assert parsed is not None
        _, embedded_hash = parsed
        assert embedded_hash == result.payload_hash

    def test_contract_ref_is_the_next_outpoint_after_the_nft_ref(self):
        """The two singletons must be DIFFERENT outpoints, one vout apart.

        Through 0.15.0 this asserted ``contract_ref == result.ref``, and that is
        precisely the bug: two outputs leading with ``0xd8 <same ref>`` are
        rejected by consensus, and the contract's body recomputes the token ref
        as ``mutable_ref.vout - 1`` so an equal pair matches nothing either.
        Proven on a node in ``tests/test_mut_wave_regtest_e2e.py``.
        """
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        parsed = parse_mutable_nft_script(result.contract_script)
        assert parsed is not None
        contract_ref, _ = parsed
        assert contract_ref != result.ref
        assert contract_ref == result.mutable_ref
        assert contract_ref.txid == result.ref.txid
        assert contract_ref.vout == result.ref.vout + 1

    def test_the_two_output_scripts_never_share_a_ref(self):
        """The consensus invariant, asserted directly on the emitted bytes.

        ``build_nft_locking_script`` and ``build_mutable_nft_script`` both lead
        their ref with ``OP_PUSHINPUTREFSINGLETON``, and a transaction may not
        have two outputs claiming the same singleton ref.
        """
        for vout in (0, 1, 7):
            result = BUILDER.prepare_mutable_reveal(TXID, vout, MUT_CBOR, PKH)
            assert result.nft_script[0] == 0xD8
            assert result.contract_script[35] == 0xD8
            assert result.nft_script[1:37] != result.contract_script[36:72]

    def test_scriptsig_suffix_not_empty(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert len(result.scriptsig_suffix) > 0

    def test_scriptsig_suffix_starts_with_gly_marker(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert b"gly" in result.scriptsig_suffix

    def test_raises_when_protocol_missing_mut(self):
        nft_only_cbor = _cbor([GlyphProtocol.NFT], "bad")
        with pytest.raises(ValidationError, match="MUT"):
            BUILDER.prepare_mutable_reveal(TXID, 0, nft_only_cbor, PKH)

    def test_raises_on_invalid_cbor(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_mutable_reveal(TXID, 0, b"\xff\xfe\xfd", PKH)

    def test_different_vouts_produce_different_refs(self):
        r0 = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        r1 = BUILDER.prepare_mutable_reveal(TXID, 1, MUT_CBOR, PKH)
        assert r0.ref != r1.ref
        assert r0.nft_script != r1.nft_script

    def test_nft_script_starts_with_singleton_opcode(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        assert result.nft_script[0] == 0xD8  # OP_PUSHINPUTREFSINGLETON


# ---------------------------------------------------------------------------
# CONTAINER builder tests
# ---------------------------------------------------------------------------


class TestPrepareContainerReveal:
    def test_returns_container_reveal_scripts(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert isinstance(result, ContainerRevealScripts)

    def test_no_child_ref_yields_63_byte_script(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert len(result.locking_script) == 63
        assert result.child_ref is None

    def test_child_ref_is_refused(self):
        """The 100-byte child-ref shape is gone, and asking for it must say why.

        It was never a token: the output could not be spent by anyone (the
        OP_PUSHINPUTREF push is never dropped, so the P2PKH tail hashes the ref),
        and building one consumed the child NFT's singleton ref irrecoverably.
        Both proven on a regtest node in ``tests/test_container_regtest_e2e.py``.
        """
        with pytest.raises(ValidationError, match="unspendable"):
            BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH, child_ref=CHILD_REF)

    def test_child_ref_refusal_names_the_replacement(self):
        with pytest.raises(ValidationError, match="prepare_container_child_reveal"):
            BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH, child_ref=CHILD_REF)

    def test_container_script_is_byte_identical_to_a_plain_nft(self):
        """A container has NO distinct script shape — that is the whole design.

        It is why every NFT classifier, ``GlyphScanner`` and
        ``build_nft_transfer_tx`` handle a collection with no special case, and it
        matches Photonic Wallet, which has one ``nftScript`` and no container
        variant.
        """
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert result.locking_script == build_nft_locking_script(PKH, REF)

    def test_raises_when_protocol_missing_container(self):
        nft_only_cbor = _cbor([GlyphProtocol.NFT], "bad")
        with pytest.raises(ValidationError, match="CONTAINER"):
            BUILDER.prepare_container_reveal(TXID, 0, nft_only_cbor, PKH)

    def test_scriptsig_suffix_contains_gly(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert b"gly" in result.scriptsig_suffix

    def test_ref_matches_commit_params(self):
        result = BUILDER.prepare_container_reveal(TXID, 2, CONTAINER_CBOR, PKH)
        assert result.ref.txid == TXID
        assert result.ref.vout == 2

    def test_empty_container_child_ref_is_none(self):
        result = BUILDER.prepare_container_reveal(TXID, 0, CONTAINER_CBOR, PKH)
        assert result.child_ref is None


# ---------------------------------------------------------------------------
# Container membership (child -> parent, in the envelope)
# ---------------------------------------------------------------------------


CHILD_CBOR = _cbor_child([GlyphProtocol.NFT], "child", container_refs=[REF])


class TestPrepareContainerChildReveal:
    """Minting a token INTO a container.

    The child is an ordinary NFT; what makes the claim checkable is the reveal
    shape — the container's own UTXO is spent and re-created, so its ref appears
    among the reveal's output refs, which is the condition Photonic's indexer
    applies before honouring an ``in`` entry (``filterRels``).
    """

    def test_returns_container_child_reveal_scripts(self):
        result = BUILDER.prepare_container_child_reveal(TXID2, 1, CHILD_CBOR, PKH, REF, PKH)
        assert isinstance(result, ContainerChildRevealScripts)

    def test_child_script_is_a_plain_63_byte_nft_on_its_own_ref(self):
        result = BUILDER.prepare_container_child_reveal(TXID2, 1, CHILD_CBOR, PKH, REF, PKH)
        assert result.nft_script == build_nft_locking_script(PKH, GlyphRef(txid=Txid(TXID2), vout=1))

    def test_container_output_recreates_the_container_unchanged(self):
        """Output 1 must be byte-identical to the container UTXO being spent.

        If it were not, the reveal would move or re-own the collection as a side
        effect of minting a member.
        """
        result = BUILDER.prepare_container_child_reveal(TXID2, 1, CHILD_CBOR, PKH, REF, PKH)
        assert result.container_script == build_nft_locking_script(PKH, REF)

    def test_container_output_can_be_re_owned_deliberately(self):
        other = Hex20(bytes.fromhex("dd" * 20))
        result = BUILDER.prepare_container_child_reveal(TXID2, 1, CHILD_CBOR, PKH, REF, other)
        assert result.container_script == build_nft_locking_script(other, REF)

    def test_refuses_an_envelope_that_does_not_declare_the_container(self):
        """A silent mismatch would mint a token an indexer will not show in the
        collection — the failure would only appear days later, on someone else's
        screen."""
        plain = _cbor([GlyphProtocol.NFT], "no-membership")
        with pytest.raises(ValidationError, match="does not contain the container ref"):
            BUILDER.prepare_container_child_reveal(TXID2, 1, plain, PKH, REF, PKH)

    def test_refuses_an_envelope_declaring_a_different_container(self):
        elsewhere = _cbor_child([GlyphProtocol.NFT], "other", container_refs=[CHILD_REF])
        with pytest.raises(ValidationError, match="does not contain the container ref"):
            BUILDER.prepare_container_child_reveal(TXID2, 1, elsewhere, PKH, REF, PKH)

    def test_refuses_a_non_nft_envelope(self):
        ft = _cbor([GlyphProtocol.FT], "ft")
        with pytest.raises(ValidationError, match="NFT"):
            BUILDER.prepare_container_child_reveal(TXID2, 1, ft, PKH, REF, PKH)

    def test_accepts_a_tag64_wrapped_membership_entry(self):
        """Some cbor-x producers tag byte strings; the cross-check must see
        through that rather than reject a valid envelope."""
        payload = cbor2.dumps({"p": [int(GlyphProtocol.NFT)], "in": [cbor2.CBORTag(64, REF.to_bytes())]})
        result = BUILDER.prepare_container_child_reveal(TXID2, 1, payload, PKH, REF, PKH)
        assert result.container_ref == REF

    @pytest.mark.parametrize(
        "bad_in",
        [
            [None],
            [42],
            [cbor2.CBORTag(64, None)],
            [cbor2.CBORTag(64, 42)],
            "not-a-list",
            {"in": "map"},
        ],
    )
    def test_malformed_membership_entries_raise_validation_error_not_typeerror(self, bad_in):
        """The cross-check must not coerce junk. ``bytes(42)`` silently makes 42
        zero bytes and ``bytes(None)`` raises TypeError out of a builder whose
        contract is ValidationError — either way the caller learns nothing."""
        payload = cbor2.dumps({"p": [int(GlyphProtocol.NFT)], "in": bad_in})
        with pytest.raises(ValidationError, match="does not contain the container ref"):
            BUILDER.prepare_container_child_reveal(TXID2, 1, payload, PKH, REF, PKH)

    def test_scriptsig_suffix_contains_gly(self):
        result = BUILDER.prepare_container_child_reveal(TXID2, 1, CHILD_CBOR, PKH, REF, PKH)
        assert b"gly" in result.scriptsig_suffix


class TestLegacyContainerScript:
    """The dead 100-byte shape pyrxd built from 0.9.0 to 0.14.0.

    Recognising it is not support — it is so a holder of one is told the output
    cannot be spent, instead of seeing ``unknown``.
    """

    LEGACY = bytes([0xD0]) + CHILD_REF.to_bytes() + build_nft_locking_script(PKH, REF)

    def test_is_100_bytes(self):
        assert len(self.LEGACY) == 100

    def test_classifier_recognises_it(self):
        assert is_legacy_container_script(self.LEGACY.hex())

    def test_a_plain_nft_is_not_mistaken_for_one(self):
        assert not is_legacy_container_script(build_nft_locking_script(PKH, REF).hex())

    def test_parses_both_refs_and_the_owner(self):
        parsed = parse_legacy_container_script(self.LEGACY)
        assert parsed is not None
        container_ref, child_ref, owner = parsed
        assert container_ref == REF
        assert child_ref == CHILD_REF
        assert bytes(owner) == bytes(PKH)

    def test_parse_returns_none_for_a_plain_nft(self):
        assert parse_legacy_container_script(build_nft_locking_script(PKH, REF)) is None

    def test_find_glyphs_reports_it_as_unspendable(self):
        glyphs = INSPECTOR.find_glyphs([(546, self.LEGACY)])
        assert len(glyphs) == 1
        assert glyphs[0].glyph_type == "container-legacy"
        assert glyphs[0].spendable is False
        assert glyphs[0].ref == REF
        assert glyphs[0].child_ref == CHILD_REF

    def test_inspect_script_says_why_it_is_dead(self):
        result = _inspect_script(self.LEGACY.hex())
        assert result["type"] == "container-legacy"
        assert result["spendable"] is False
        assert "UNSPENDABLE" in result["note"]

    def test_transfer_refuses_it_with_the_reason(self):
        """``build_nft_transfer_tx`` used to say "not a valid NFT script", which
        sends the holder looking for a builder that would work. None does."""
        with pytest.raises(ValidationError, match="permanently unspendable"):
            BUILDER.build_nft_transfer_tx(
                TransferParams(
                    nft_script=self.LEGACY,
                    nft_utxo_txid=TXID,
                    nft_utxo_vout=0,
                    nft_utxo_value=100_000_000,
                    new_owner_pkh=PKH,
                    private_key=PrivateKey(),
                )
            )

    def test_p2pkh_tail_hashes_the_ref_not_the_pubkey(self):
        """The mechanical reason it cannot be spent, pinned as an assertion.

        ``OP_PUSHINPUTREF <child_ref>`` is never dropped, so at ``OP_DUP
        OP_HASH160`` the top of the stack is the ref, and the comparison against
        the owner PKH is between two unrelated values whatever the scriptSig
        pushed.
        """
        pkh_in_script = self.LEGACY[78:98]
        assert pkh_in_script == bytes(PKH)
        assert hashlib.new("ripemd160", hashlib.sha256(CHILD_REF.to_bytes()).digest()).digest() != pkh_in_script


# ---------------------------------------------------------------------------
# WAVE builder tests
# ---------------------------------------------------------------------------


class TestPrepareWaveReveal:
    def test_returns_mutable_reveal_scripts(self):
        result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        assert isinstance(result, MutableRevealScripts)

    def test_nft_script_is_63_bytes(self):
        result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        assert len(result.nft_script) == 63

    def test_contract_script_is_174_bytes(self):
        result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        assert len(result.contract_script) == 174

    def test_raises_when_name_empty(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "")

    def test_raises_when_name_too_long(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "a" * 256)

    def test_raises_when_name_has_control_chars(self):
        with pytest.raises(ValidationError):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "bad\x00name")

    def test_raises_when_protocol_missing_wave(self):
        mut_only_cbor = _cbor([GlyphProtocol.NFT, GlyphProtocol.MUT], "mut")
        with pytest.raises(ValidationError, match="WAVE"):
            BUILDER.prepare_wave_reveal(TXID, 0, mut_only_cbor, PKH, "name")

    def test_raises_when_protocol_missing_mut(self):
        # GlyphMetadata validates protocol combos — WAVE without MUT raises at
        # metadata construction time before we even get to the builder.
        with pytest.raises(ValidationError):
            _cbor([GlyphProtocol.NFT, GlyphProtocol.WAVE], "name")

    def test_raises_when_cbor_name_mismatch(self):
        with pytest.raises(ValidationError, match="name"):
            BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "different.rxd")

    def test_wave_uses_same_two_output_structure_as_mut(self):
        wave_result = BUILDER.prepare_wave_reveal(TXID, 0, WAVE_CBOR, PKH, "myname.rxd")
        # Both outputs present
        assert wave_result.nft_script
        assert wave_result.contract_script
        assert MUTABLE_NFT_SCRIPT_RE.fullmatch(wave_result.contract_script.hex())

    def test_255_char_name_is_valid(self):
        name = "a" * 255
        cbor_255, _ = encode_payload(
            GlyphMetadata(name=name, protocol=[GlyphProtocol.NFT, GlyphProtocol.MUT, GlyphProtocol.WAVE])
        )
        # Should not raise
        result = BUILDER.prepare_wave_reveal(TXID, 0, cbor_255, PKH, name)
        assert len(result.nft_script) == 63


# ---------------------------------------------------------------------------
# GlyphInspector MUT detection tests
# ---------------------------------------------------------------------------


class TestInspectorMutDetection:
    def test_detects_mutable_script(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert len(glyphs) == 1
        assert glyphs[0].glyph_type == "mut"

    def test_mutable_glyph_type_is_mut(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert glyphs[0].glyph_type == "mut"

    def test_mutable_ref_extracted_correctly(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert glyphs[0].ref == REF

    def test_mutable_metadata_is_none(self):
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, mutable_script)])
        assert glyphs[0].metadata is None

    def test_nft_still_detected_alongside_mut(self):
        nft_script = build_nft_locking_script(PKH, REF)
        mutable_script = build_mutable_nft_script(GlyphRef(txid=Txid(TXID2), vout=0), b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(546, nft_script), (546, mutable_script)])
        types = {g.glyph_type for g in glyphs}
        assert "nft" in types
        assert "mut" in types

    def test_plain_script_not_detected_as_mut(self):
        plain = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        glyphs = INSPECTOR.find_glyphs([(1000, plain)])
        assert glyphs == []

    def test_mut_vout_index_is_correct(self):
        plain = bytes.fromhex("76a914" + "bb" * 20 + "88ac")
        mutable_script = build_mutable_nft_script(REF, b"\x78" * 32)
        glyphs = INSPECTOR.find_glyphs([(1000, plain), (546, mutable_script)])
        assert glyphs[0].vout == 1

    def test_mut_from_prepare_mutable_reveal(self):
        result = BUILDER.prepare_mutable_reveal(TXID, 0, MUT_CBOR, PKH)
        glyphs = INSPECTOR.find_glyphs([(546, result.contract_script)])
        assert glyphs[0].glyph_type == "mut"

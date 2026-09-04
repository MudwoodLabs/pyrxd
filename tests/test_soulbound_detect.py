"""Tests for the soulbound-covenant detector.

Anchored to REAL on-chain bytes: the deployed "TheArtofSatoshi" soulbound
authority token (live UTXO ``4b25a66668…:0``, fetched 2026-06-08) must classify as
covenant-enforced; a plain transferable NFT singleton must not.
"""

from __future__ import annotations

from pyrxd.glyph.soulbound_covenant import (
    build_composable_soulbound_nft_covenant,
    build_soulbound_nft_covenant,
)
from pyrxd.glyph.soulbound_detect import Transferability, classify_soulbound
from pyrxd.glyph.types import GlyphRef

# The exact live scriptPubKey of the deployed soulbound authority token
# (radiant_get_transaction 4b25a66668c41536a654151fc92e4f115b4c36d7ca2db08d2e121b36e0243f5b, vout 0).
_DEPLOYED_SPK = bytes.fromhex(
    "d8020eab29108de31237293118da44eb870882889ab8c7713a2c5302d73f6b0d7e00000000"
    "7c637576a914716477de74200c2e2416177c53aea716f5035ac288ad00eac0e98767de009c69"
    "76a914716477de74200c2e2416177c53aea716f5035ac288ad5168"
)

_REF = GlyphRef(txid="11" * 32, vout=0)
_PKH = bytes.fromhex("aa" * 20)


def _plain_nft_singleton(ref: GlyphRef, pkh: bytes) -> bytes:
    # d8 <ref> OP_DROP  OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    return b"\xd8" + ref.to_bytes() + b"\x75" + b"\x76\xa9\x14" + pkh + b"\x88\xac"


# --------------------------------------------------------------------------- the deployed token


def test_deployed_token_is_consensus_soulbound():
    c = classify_soulbound(_DEPLOYED_SPK)
    assert c.transferability is Transferability.SOULBOUND_COVENANT
    assert c.is_consensus_soulbound
    assert c.has_self_replication
    assert c.has_burn_branch
    # binds the genesis singleton ref 7e0d…0e02:0
    assert c.bound_ref is not None
    assert GlyphRef.from_bytes(c.bound_ref).txid == ("7e0d6b3fd702532c3a71c7b89a88820887eb44da1831293712e38d1029ab0e02")


# --------------------------------------------------------------------------- my prototype


def test_pyrxd_prototype_is_consensus_soulbound():
    spk = build_soulbound_nft_covenant(_REF, _PKH).funded_spk
    c = classify_soulbound(spk)
    assert c.transferability is Transferability.SOULBOUND_COVENANT
    assert c.has_self_replication
    assert c.has_burn_branch
    assert c.bound_ref == _REF.to_bytes()


def test_composable_variant_is_consensus_soulbound():
    """The index-independent (CODESCRIPTHASHOUTPUTCOUNT) form must also classify
    as soulbound — the detector recognises both self-replication shapes."""
    spk = build_composable_soulbound_nft_covenant(_REF, _PKH).funded_spk
    c = classify_soulbound(spk)
    assert c.transferability is Transferability.SOULBOUND_COVENANT
    assert c.has_self_replication
    assert c.bound_ref == _REF.to_bytes()


# --------------------------------------------------------------------------- the negative case


def test_plain_nft_singleton_is_transferable():
    c = classify_soulbound(_plain_nft_singleton(_REF, _PKH))
    assert c.transferability is Transferability.TRANSFERABLE_NFT
    assert not c.is_consensus_soulbound
    assert not c.has_self_replication
    assert c.bound_ref == _REF.to_bytes()


def test_metadata_flag_does_not_fool_the_detector():
    """The whole point: a plain NFT is transferable regardless of any off-chain
    transferable:false flag — the detector only reads consensus structure."""
    plain = _plain_nft_singleton(_REF, _PKH)
    assert not classify_soulbound(plain).is_consensus_soulbound


def test_non_singleton_is_classified_as_such():
    # plain P2PKH, no singleton
    p2pkh = b"\x76\xa9\x14" + _PKH + b"\x88\xac"
    c = classify_soulbound(p2pkh)
    assert c.transferability is Transferability.NOT_A_SINGLETON


def test_truncated_script_is_unknown_not_crash():
    c = classify_soulbound(b"\xd8\x00\x01\x02")  # d8 then truncated ref
    assert c.transferability is Transferability.UNKNOWN


class TestCodeScriptEqualityDoesNotPinAMutableOwner:
    """Self-replication only forbids transfer when the equality covers the OWNER.

    `OP_CODESCRIPTBYTECODE_OUTPUT`/`_UTXO` compare the bytes AFTER
    `OP_STATESEPARATOR`. A covenant that pins its code script while carrying a
    mutable state prefix can therefore recur with a DIFFERENT owner in that prefix
    — which is a transfer, under a lock the classifier used to call "transfer is
    impossible at consensus".

    THE REPOSITORY ALREADY KNEW. `soulbound_covenant.py` says outright that
    "code-script-only equality would let the state (owner) change between hops —
    i.e. a transfer — so it is the wrong primitive for soulbinding", which is why
    both pyrxd builders deliberately emit NO state separator. The detector was
    written from the opcode markers and never encoded the caveat, so it accepted a
    shape the module beside it had already ruled out.

    IT IS THE PAIR, NEVER EITHER HALF. With no separator the code script IS the
    whole script, so the same opcodes DO pin the owner. The deployed mainnet token
    uses exactly those opcodes; declassifying it would be a guard refusing valid
    work on the only real instance that exists.
    """

    #: Owner in the STATE prefix, self-equality over the CODE script only.
    @staticmethod
    def _mutable_owner_spk(pkh: bytes) -> bytes:
        return (
            b"\xd8"
            + _REF.to_bytes()  # singleton ref
            + b"\x76\xa9\x14"
            + pkh
            + b"\x88\xac"  # P2PKH owner -- STATE
            + b"\xbd"  # OP_STATESEPARATOR
            + b"\x00\xea\xc0\xe9\x87"  # OP_0 CSB_OUTPUT OP_INPUTINDEX CSB_UTXO OP_EQUAL
        )

    def test_the_owner_really_can_change_under_this_lock(self) -> None:
        """The premise, established before any classification is asserted. If the
        code scripts ever differed, the rest of this class would be theatre."""
        a, b = self._mutable_owner_spk(b"\xaa" * 20), self._mutable_owner_spk(b"\xbb" * 20)
        code_a, code_b = a[a.index(b"\xbd") + 1 :], b[b.index(b"\xbd") + 1 :]
        assert code_a == code_b, "the covenant's own equality is satisfied by both owners"
        assert a != b, "yet the scripts differ — the owner moved"

    def test_it_is_NOT_reported_as_soulbound(self) -> None:
        c = classify_soulbound(self._mutable_owner_spk(b"\xaa" * 20))
        assert c.transferability is Transferability.MUTABLE_STATE_COVENANT
        assert not c.is_consensus_soulbound

    def test_the_self_replication_fact_is_still_reported(self) -> None:
        """Declassifying must not erase what IS true: the lock does self-replicate.
        Reporting `has_self_replication=False` would be a second wrong answer."""
        assert classify_soulbound(self._mutable_owner_spk(b"\xaa" * 20)).has_self_replication

    def test_the_credential_gate_now_refuses_it(self) -> None:
        """Reachability: the classifier is what `assert_soulbound_credential` gates
        on, so the fix has to be visible through the production entry point."""
        from pyrxd.glyph.credential_binding import extract_owner_pkh

        spk = self._mutable_owner_spk(b"\xaa" * 20)
        assert extract_owner_pkh(spk) == b"\xaa" * 20, "the owner is still readable"
        assert not classify_soulbound(spk).is_consensus_soulbound, "but it must not gate a swap"


class TestTheHONESTShapesAreStillSoulbound:
    """The other half. Every real soulbound covenant that exists must survive.

    All three carry NO state separator, so their code script is their whole script
    and code-script equality pins the owner. A rule keyed on the opcodes alone
    would have broken all of them."""

    def test_the_deployed_mainnet_token(self) -> None:
        c = classify_soulbound(_DEPLOYED_SPK)
        assert c.is_consensus_soulbound, "the only real instance on chain"
        assert 0xBD not in _DEPLOYED_SPK, "and it has no state prefix, which is why"

    def test_both_pyrxd_builders(self) -> None:
        from pyrxd.glyph.soulbound_covenant import (
            build_composable_soulbound_nft_covenant,
            build_soulbound_nft_covenant,
        )

        for build in (build_soulbound_nft_covenant, build_composable_soulbound_nft_covenant):
            spk = build(_REF, _PKH).funded_spk
            assert classify_soulbound(spk).is_consensus_soulbound, build.__name__

    def test_full_bytecode_equality_is_soulbound_even_WITH_a_state_prefix(self) -> None:
        """The discriminator is the PAIR, not the separator alone. Full-bytecode
        equality covers the state prefix too, so such a script stays soulbound."""
        spk = (
            b"\xd8"
            + _REF.to_bytes()
            + b"\x76\xa9\x14"
            + _PKH
            + b"\x88\xac"
            + b"\xbd"
            + b"\x00\xcd\xc0\xc7\x87"  # OP_0 OP_OUTPUTBYTECODE OP_INPUTINDEX OP_UTXOBYTECODE OP_EQUAL
        )
        assert classify_soulbound(spk).is_consensus_soulbound

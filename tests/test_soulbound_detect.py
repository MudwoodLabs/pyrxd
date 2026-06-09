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

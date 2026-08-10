"""Tests for owner==claimer credential binding (anti-rental gate).

Anchored to the real deployed soulbound token bytes where possible.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.credential_binding import (
    CredentialBindingError,
    ResolvedCredential,
    extract_owner_pkh,
    verify_credential_binding,
)
from pyrxd.glyph.soulbound_covenant import build_soulbound_nft_covenant
from pyrxd.glyph.types import GlyphRef

# Live mainnet soulbound authority token UTXO 4b25…:0 (owner 716477de…).
_DEPLOYED_SPK = bytes.fromhex(
    "d8020eab29108de31237293118da44eb870882889ab8c7713a2c5302d73f6b0d7e00000000"
    "7c637576a914716477de74200c2e2416177c53aea716f5035ac288ad00eac0e98767de009c69"
    "76a914716477de74200c2e2416177c53aea716f5035ac288ad5168"
)
_DEPLOYED_OWNER = bytes.fromhex("716477de74200c2e2416177c53aea716f5035ac2")

_REF = GlyphRef(txid="11" * 32, vout=0)
_P = bytes.fromhex("aa" * 20)
_Q = bytes.fromhex("bb" * 20)


def _soulbound_spk(owner: bytes) -> bytes:
    return build_soulbound_nft_covenant(_REF, owner).funded_spk


def _plain_nft(owner: bytes) -> bytes:
    return b"\xd8" + _REF.to_bytes() + b"\x75\x76\xa9\x14" + owner + b"\x88\xac"


# --------------------------------------------------------------------------- owner extraction


def test_extract_owner_from_deployed_token():
    assert extract_owner_pkh(_DEPLOYED_SPK) == _DEPLOYED_OWNER


def test_extract_owner_from_prototype():
    assert extract_owner_pkh(_soulbound_spk(_P)) == _P


def test_extract_owner_none_when_absent():
    assert extract_owner_pkh(b"\x00\x01\x02") is None


# --- the walk must use the consensus ref-operand set, not the 0xd0-0xd8 range ---
#
# 0xd4-0xd7 (OP_REFHASHDATASUMMARY_UTXO, OP_REFHASHVALUESUM_UTXOS,
# OP_REFHASHDATASUMMARY_OUTPUT, OP_REFHASHVALUESUM_OUTPUTS —
# Radiant-Core/src/script/script.h:281-284) take NO operand. A walk that skips
# 37 bytes for one of them steps over real script and can report an owner the
# consensus-correct walk would never see. These opcodes exist precisely for
# covenant use, so a soulbound credential covenant can legitimately contain one.

_P2PKH_FAKE = b"\x76\xa9\x14" + bytes.fromhex("cc" * 20) + b"\x88\xac"


def test_refhash_opcode_does_not_hide_the_real_owner():
    """``d4`` then P2PKH(owner): the owner is at offset 1, not offset 37."""
    spk = b"\xd4" + b"\x76\xa9\x14" + _P + b"\x88\xac"
    assert extract_owner_pkh(spk) == _P


def test_refhash_opcode_cannot_promote_a_second_pkh_to_sole_owner():
    """Two P2PKH runs => ambiguous => ``None``.

    A walk that swallowed 36 bytes after the ``d4`` would step clean over the
    first P2PKH and confidently return the second — reporting an owner the
    script does not unambiguously bind, which is what the anti-rental gate
    compares against ``taker_dest_hash``.
    """
    spk = b"\xd4" + b"\x76\xa9\x14" + _P + b"\x88\xac" + b"\x75" * 11 + _P2PKH_FAKE
    assert spk[37:].startswith(_P2PKH_FAKE)  # exactly where a 37-byte skip lands
    assert extract_owner_pkh(spk) is None


def test_operand_carrying_ref_opcodes_still_skip_36_bytes():
    """A P2PKH-shaped run inside a real 36-byte ref operand is DATA, not an owner."""
    poisoned_ref = (b"\x76\xa9\x14" + bytes.fromhex("dd" * 20) + b"\x88\xac") + bytes(11)
    assert len(poisoned_ref) == 36
    for op in (0xD0, 0xD1, 0xD2, 0xD3, 0xD8):
        spk = bytes([op]) + poisoned_ref + b"\x76\xa9\x14" + _P + b"\x88\xac"
        assert extract_owner_pkh(spk) == _P, f"ref operand walked as opcodes after {op:#x}"


# --------------------------------------------------------------------------- the gate: accept


def test_binding_accepts_genuine_soulbound_owned_by_recipient():
    cred = ResolvedCredential(current_spk=_soulbound_spk(_P), confirmations=10, bound_ref=_REF.to_bytes())
    # no raise
    verify_credential_binding(cred, recipient_pkh=_P, min_confirmations=6, expected_credential_ref=_REF.to_bytes())


def test_binding_accepts_deployed_design():
    cred = ResolvedCredential(current_spk=_DEPLOYED_SPK, confirmations=200)
    verify_credential_binding(cred, recipient_pkh=_DEPLOYED_OWNER, min_confirmations=6)


# --------------------------------------------------------------------------- the gate: reject


def test_rejects_metadata_only_credential():
    """A plain transferable NFT (any off-chain transferable:false flag is advisory)
    must be refused — it can be rented or resold."""
    cred = ResolvedCredential(current_spk=_plain_nft(_P), confirmations=10)
    with pytest.raises(CredentialBindingError, match="not a consensus-soulbound"):
        verify_credential_binding(cred, recipient_pkh=_P, min_confirmations=6)


def test_rejects_owner_not_recipient():
    """The rental scenario: credential owned by Q, but the swap pays P."""
    cred = ResolvedCredential(current_spk=_soulbound_spk(_Q), confirmations=10)
    with pytest.raises(CredentialBindingError, match="owner .* != swap recipient"):
        verify_credential_binding(cred, recipient_pkh=_P, min_confirmations=6)


def test_rejects_shallow_confirmations():
    cred = ResolvedCredential(current_spk=_soulbound_spk(_P), confirmations=2)
    with pytest.raises(CredentialBindingError, match="confirmations"):
        verify_credential_binding(cred, recipient_pkh=_P, min_confirmations=6)


def test_rejects_wrong_credential_ref():
    cred = ResolvedCredential(current_spk=_soulbound_spk(_P), confirmations=10)
    other = GlyphRef(txid="22" * 32, vout=0).to_bytes()
    with pytest.raises(CredentialBindingError, match="binds ref"):
        verify_credential_binding(cred, recipient_pkh=_P, min_confirmations=6, expected_credential_ref=other)


def test_rejects_bad_recipient_pkh_length():
    cred = ResolvedCredential(current_spk=_soulbound_spk(_P), confirmations=10)
    with pytest.raises(CredentialBindingError, match="20 bytes"):
        verify_credential_binding(cred, recipient_pkh=b"\x00" * 19, min_confirmations=6)

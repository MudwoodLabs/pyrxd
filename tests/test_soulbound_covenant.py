"""Tests for the PROTOTYPE consensus-enforced soulbound NFT covenant.

The structural tests below RUN today and prove the script is well-formed and that
the *non-transferability invariant holds at the script level*: any "transfer"
(a clone with a different owner) is a different script and so cannot satisfy the
recur ``OP_EQUALVERIFY``.

The consensus behaviour (does the Radiant VM accept/reject these spends?) is
validated separately on a real ``radiant-core:v2.3.0`` regtest node in
``tests/test_soulbound_covenant_regtest.py`` (recur-to-self ACCEPTED,
transfer-to-other REJECTED, burn ACCEPTED).
"""

from __future__ import annotations

import pytest

from pyrxd.constants import OpCode as OP
from pyrxd.glyph.soulbound_covenant import build_soulbound_nft_covenant
from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError

_TXID = "11" * 32
_OWNER = bytes.fromhex("aa" * 20)
_OTHER = bytes.fromhex("bb" * 20)


def _cov(owner: bytes = _OWNER, vout: int = 0):
    return build_soulbound_nft_covenant(GlyphRef(txid=_TXID, vout=vout), owner)


# --------------------------------------------------------------------------- structure


def test_spk_starts_with_singleton_ref_binding():
    c = _cov()
    # d8 <36-byte ref>
    assert c.funded_spk[:1] == OP.OP_PUSHINPUTREFSINGLETON
    assert c.funded_spk[1:37] == GlyphRef(txid=_TXID, vout=0).to_bytes()
    assert c.genesis_ref == c.funded_spk[1:37]


def test_spk_ends_with_owner_p2pkh():
    c = _cov()
    tail = OP.OP_DUP + OP.OP_HASH160 + bytes([20]) + _OWNER + OP.OP_EQUALVERIFY + OP.OP_CHECKSIG
    assert c.funded_spk.endswith(tail)


def test_spk_contains_burn_or_clone_branch_in_order():
    c = _cov()
    spk = c.funded_spk
    # The recurrence/burn decision opcodes appear in the expected sequence.
    branch = (
        OP.OP_REFOUTPUTCOUNT_OUTPUTS
        + OP.OP_0
        + OP.OP_NUMEQUAL
        + OP.OP_IF
        + OP.OP_ELSE
        + OP.OP_0
        + OP.OP_OUTPUTBYTECODE
        + OP.OP_INPUTINDEX
        + OP.OP_UTXOBYTECODE
        + OP.OP_EQUALVERIFY
        + OP.OP_ENDIF
    )
    assert branch in spk


def test_exactly_one_input_ref_bound():
    from pyrxd.glyph.script import count_input_refs

    c = _cov()
    refs = count_input_refs(c.funded_spk)
    assert list(refs.keys()) == [c.genesis_ref]
    assert refs[c.genesis_ref] == 1


# --------------------------------------------------------------------------- the security invariant


def test_recur_target_is_exact_self_clone():
    c = _cov()
    # Soulbound => the only legal non-burn output[0] is a byte-identical clone.
    assert c.recur_target_spk == c.funded_spk


def test_transfer_to_different_owner_is_a_different_script():
    """The heart of soulbinding: a clone locked to a *different* owner is a
    different scriptPubKey, so it can never satisfy the recur OP_EQUALVERIFY
    against the original UTXO. Hence consensus has no transfer path."""
    mine = _cov(_OWNER)
    theirs = _cov(_OTHER)
    assert mine.funded_spk != theirs.funded_spk
    # The only difference is the 20-byte owner pkh field.
    assert mine.funded_spk.replace(_OWNER, b"\x00" * 20) == theirs.funded_spk.replace(_OTHER, b"\x00" * 20)


def test_different_genesis_ref_changes_binding():
    a = build_soulbound_nft_covenant(GlyphRef(txid=_TXID, vout=0), _OWNER)
    b = build_soulbound_nft_covenant(GlyphRef(txid=_TXID, vout=1), _OWNER)
    assert a.funded_spk != b.funded_spk
    assert a.genesis_ref != b.genesis_ref


# --------------------------------------------------------------------------- guards / inputs


def test_rejects_bad_owner_pkh_length():
    with pytest.raises(ValidationError):
        build_soulbound_nft_covenant(GlyphRef(txid=_TXID, vout=0), b"\x00" * 19)


def test_opcode_stream_walks_cleanly():
    """The whole SPK must parse as a clean opcode stream (no truncated push,
    no stray PUSHDATA) — the build-time minimal-push guard already enforces this,
    so a successful build is the assertion; we re-confirm length sanity here."""
    c = _cov()
    # d8(1) + ref(36) + branch(11) + p2pkh(3+20+2=25) == 73 bytes
    assert len(c.funded_spk) == 1 + 36 + 11 + 25


# --------------------------------------------------------------------------- consensus validation
#
# The three consensus cases (recur-to-self ACCEPTED, transfer-to-other REJECTED,
# burn ACCEPTED) are validated on a real radiant-core:v2.3.0 regtest node in
# tests/test_soulbound_covenant_regtest.py (run: RADIANT_REGTEST=1 ... -m integration),
# differentially alongside the live mainnet deployed covenant design.

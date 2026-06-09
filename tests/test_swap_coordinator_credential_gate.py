"""pre_btc_lock_check credential-binding gate (step 1b) — wiring tests.

Confirms the coordinator runs the soulbound-credential binding fail-closed when a
swap sets ``terms.credential_ref``, and is a no-op otherwise. Reuses the fakes
from test_swap_coordinator.
"""

from __future__ import annotations

import hashlib
import os

from pyrxd.btc_wallet import taproot as t
from pyrxd.glyph.credential_binding import ResolvedCredential
from pyrxd.glyph.soulbound_covenant import build_soulbound_nft_covenant
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.htlc_covenant import holder_hash
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20
from tests.test_swap_coordinator import (
    FakeBtcLeg,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _xonly,
)

_P = bytes(Hex20(PrivateKey(b"\x03" * 32).public_key().hash160()))
_Q = bytes(Hex20(PrivateKey(b"\x04" * 32).public_key().hash160()))
_CRED_REF = GlyphRef(txid="cc" * 32, vout=0)


class FakeCredentialResolver:
    def __init__(self, cred):
        self.cred = cred

    async def resolve_credential(self, ref: bytes):
        return self.cred


def _rxd_terms(*, taker_pkh: bytes, credential_ref: bytes = b""):
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=holder_hash(taker_pkh, variant="rxd"),
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
        credential_ref=credential_ref,
    )


def _coord(terms, resolver):
    rec = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    return SwapCoordinator(
        record=rec,
        btc_leg=FakeBtcLeg(),
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated(), maker_stall_safety_window_blocks=6),
        credential_resolver=resolver,
    )


def _resolved(owner: bytes, *, soulbound: bool = True, confirmations: int = 10):
    if soulbound:
        spk = build_soulbound_nft_covenant(_CRED_REF, owner).funded_spk
    else:  # plain transferable NFT singleton
        spk = b"\xd8" + _CRED_REF.to_bytes() + b"\x75\x76\xa9\x14" + owner + b"\x88\xac"
    return ResolvedCredential(current_spk=spk, confirmations=confirmations, bound_ref=_CRED_REF.to_bytes())


# --------------------------------------------------------------------------- accept


async def test_accepts_genuine_bound_credential():
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord = _coord(terms, FakeCredentialResolver(_resolved(_P)))
    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok, gate.reason


async def test_no_credential_ref_skips_gate_even_without_resolver():
    """Backward compat: a non-gated swap ignores the credential machinery."""
    terms = _rxd_terms(taker_pkh=_P)  # credential_ref empty
    coord = _coord(terms, None)
    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok, gate.reason


# --------------------------------------------------------------------------- reject (fail-closed)


async def test_rejects_when_gated_but_no_resolver():
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord = _coord(terms, None)
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "no credential_resolver" in gate.reason


async def test_rejects_unresolved_credential():
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord = _coord(terms, FakeCredentialResolver(None))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "did not resolve" in gate.reason


async def test_rejects_metadata_only_credential():
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord = _coord(terms, FakeCredentialResolver(_resolved(_P, soulbound=False)))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "binding failed" in gate.reason


async def test_rejects_owner_not_payout_recipient():
    """Rental: credential owned by Q, but the swap pays P -> fail-closed."""
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())  # pays P
    coord = _coord(terms, FakeCredentialResolver(_resolved(_Q)))  # owned by Q
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "not the swap payout recipient" in gate.reason


async def test_rejects_shallow_credential_confirmations():
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord = _coord(terms, FakeCredentialResolver(_resolved(_P, confirmations=2)))
    gate = await coord.pre_btc_lock_check(terms)
    assert not gate.ok and "binding failed" in gate.reason

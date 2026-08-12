"""The soulbound-credential binding gate, on BOTH parties' paths.

Confirms the coordinator runs the credential binding fail-closed when a swap sets
``terms.credential_ref``, and is a no-op otherwise — on the TAKER's pre-fund gate
(``pre_btc_lock_check``, step 1b) and on the MAKER's transition into
``BOTH_LOCKED``, which is the precondition for the ``p`` reveal.

The second half exists because the first half was, for a while, the whole of it:
the only enforcement lived inside ``taker_funds_btc``, a method a hostile taker
simply does not call. Reuses the fakes from test_swap_coordinator.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.glyph.credential_binding import ResolvedCredential
from pyrxd.glyph.soulbound_covenant import build_soulbound_nft_covenant
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.htlc_covenant import holder_hash
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapRole, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
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


# --------------------------------------------------------------------------- the MAKER path
#
# Everything above drives ``pre_btc_lock_check``, which is called from exactly one
# place: ``taker_funds_btc``. That is the TAKER's own method.
#
# The party the gate protects is the MAKER. ``credential_binding.py`` names the
# asset-locker as the one who runs it, and "only credentialed counterparties may
# take my asset" is the maker's policy, not the taker's. But no maker-side path
# reads ``terms.credential_ref`` — so an uncredentialed taker declines to call the
# method holding the check, funds the freely-derivable HTLC address directly, and
# the honest maker walks its own coordinator to the ``p`` reveal without the
# resolver ever being asked a question.
#
# This is the third instance of one defect class in this file's neighbourhood: the
# maker-side and taker-side counter-funding checks each lived only inside the OTHER
# party's method, and both were fund-safety gaps (HZ-1, HZ-3). The fix that worked
# there is the fix here — put the check on the transition into ``BOTH_LOCKED``,
# which is the precondition for ``maker_claims_btc``, rather than on whichever
# method the honest party happens to pass through.


class _CountingResolver:
    """Records whether the maker ever ASKED, which is the whole finding."""

    def __init__(self, cred):
        self.cred = cred
        self.calls = 0

    async def resolve_credential(self, ref: bytes):
        self.calls += 1
        return self.cred


def _maker_coord_at_btc_locked(terms, resolver):
    """The honest maker's coordinator as a two-party deployment builds it.

    Not a shortcut: the maker observes the taker's funding on-chain and starts at
    ``BTC_LOCKED`` holding the advertised locator — the same construction
    ``tests/test_btc_maker_counter_funding_adversarial.py`` uses, and the same
    shape ``scripts/btc_swap_two_host.py --phase lock-claim`` builds from
    ``taker_funding.json``. The maker never calls ``taker_funds_btc``; the taker
    does, on another host, if it feels like it.
    """
    leg = FakeBtcLeg()
    locator = leg._htlc(terms).with_funding(t.BtcOutpoint("ab" * 32, 0), terms.btc_sats)
    record = (
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_counter_lock(locator).with_state(SwapState.BTC_LOCKED)
    )
    coord = SwapCoordinator(
        record=record,
        btc_leg=leg,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=MarginPolicy.estimated(),
            maker_stall_safety_window_blocks=6,
            role=SwapRole.MAKER,
        ),
        credential_resolver=resolver,
    )
    return coord, leg


async def _maker_locks_asset(coord):
    spk = await coord.radiant_leg.expected_covenant_scriptpubkey(coord.record.terms)
    return await coord.post_asset_lock_revalidate(spk)


async def test_the_maker_refuses_to_reach_both_locked_for_an_uncredentialed_payout():
    """THE bypass, as a call sequence.

    Terms are credential-gated and pay ``taker_dest_hash`` = P; the credential
    resolves to owner Q. The taker's own gate refuses this (see
    ``test_rejects_owner_not_payout_recipient`` above). The maker must too — and
    the maker is the party whose asset is on the line.

    ``BOTH_LOCKED`` is the state that enables ``maker_claims_btc``, and that claim
    is the ``p`` reveal — the maker's actual point of no return. Refusing here
    leaves the maker at ``BTC_LOCKED``, from which its CSV refund is still open.
    """
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())  # pays P
    resolver = _CountingResolver(_resolved(_Q))  # credential owned by Q
    coord, _leg = _maker_coord_at_btc_locked(terms, resolver)

    with pytest.raises(ValidationError, match="not the swap payout recipient"):
        await _maker_locks_asset(coord)

    assert resolver.calls == 1, "the maker must ASK — a resolver it never calls is decoration"
    assert coord.record.state is SwapState.BTC_LOCKED, (
        "never reached the reveal-enabling state; the maker's CSV asset refund is still available"
    )


async def test_the_maker_accepts_a_genuine_bound_credential():
    """The other half. A gate that refuses everything is not a gate."""
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    resolver = _CountingResolver(_resolved(_P))
    coord, _leg = _maker_coord_at_btc_locked(terms, resolver)

    rec = await _maker_locks_asset(coord)
    assert rec.state is SwapState.BOTH_LOCKED
    assert resolver.calls == 1


async def test_an_ungated_swap_is_untouched_by_any_of_this():
    """Zero ``credential_ref`` = zero behaviour change. No CLI command, script or
    example in this repo sets one, so this is the path every existing swap takes."""
    terms = _rxd_terms(taker_pkh=_P)  # no credential_ref
    resolver = _CountingResolver(_resolved(_Q))
    coord, _leg = _maker_coord_at_btc_locked(terms, resolver)

    rec = await _maker_locks_asset(coord)
    assert rec.state is SwapState.BOTH_LOCKED
    assert resolver.calls == 0


async def test_a_gated_swap_with_no_resolver_cannot_reach_the_reveal():
    """Fail-closed, matching the taker gate and the two counter-funding gates
    beside it: a maker that cannot check the credential must not lock past the
    point where it can still refund."""
    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord, _leg = _maker_coord_at_btc_locked(terms, None)

    with pytest.raises(ValidationError, match="no credential_resolver"):
        await _maker_locks_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_a_resolver_that_cannot_answer_refuses_the_lock():
    """An unreachable authority is not a passing check. Same shape as the
    counter-funding gates: unavailable => refuse, do not assume."""

    class _BrokenResolver:
        calls = 0

        async def resolve_credential(self, ref: bytes):
            raise RuntimeError("indexer down")

    terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
    coord, _leg = _maker_coord_at_btc_locked(terms, _BrokenResolver())

    with pytest.raises(ValidationError, match="resolver unavailable"):
        await _maker_locks_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_the_taker_gate_and_the_maker_gate_are_the_same_rule():
    """One rule, one spelling. The counter-funding checks that preceded this were
    each written twice; the second copy is how a rule starts drifting. Both entry
    points must agree on every case, so both call the same private assertion."""
    for owner, expect_ok in ((_P, True), (_Q, False)):
        terms = _rxd_terms(taker_pkh=_P, credential_ref=_CRED_REF.to_bytes())
        taker = _coord(terms, FakeCredentialResolver(_resolved(owner)))
        gate = await taker.pre_btc_lock_check(terms)
        assert gate.ok is expect_ok

        maker, _leg = _maker_coord_at_btc_locked(terms, _CountingResolver(_resolved(owner)))
        if expect_ok:
            assert (await _maker_locks_asset(maker)).state is SwapState.BOTH_LOCKED
        else:
            with pytest.raises(ValidationError):
                await _maker_locks_asset(maker)

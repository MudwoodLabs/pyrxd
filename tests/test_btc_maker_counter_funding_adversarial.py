"""TWO-PARTY ADVERSARIAL tests for the MAKER-side BTC counter-funding gate (HZ-3).

The BTC analogue of ``test_xchain_eth_adversarial_e2e.py::test_S7`` — but with no chain: the
honest MAKER drives the REAL ``SwapCoordinator`` + the REAL ``BitcoinTaprootLeg``, and the only
fake is the node the maker reads BTC through (:class:`_HostileChainView`), which reports what a
hostile taker actually put on-chain.

The gap this covers. The runbook is TAKER-funds-BTC-FIRST, MAKER-locks-the-asset-SECOND. A P2TR
scriptPubKey commits to the TAPTREE, not to the output VALUE, so every SPK-derivation check in the
handshake passes on an HTLC funded with the wrong amount. The coordinator's amount bind
(``funded != terms.value_amount``) lives inside ``taker_funds_btc`` — the TAKER's own method — so a
hostile taker simply never calls it and funds the (freely derivable) HTLC address directly. Before
this gate the maker then locked its asset, claimed the under-funded BTC (revealing ``p``), and the
taker claimed the full asset: the maker is paid less than the agreed price. One-sided maker loss,
reachable in the intended two-party flow by any caller using ``SwapCoordinator`` directly.

Every test here asserts the honest maker's OUTCOME: it never reaches ``BOTH_LOCKED`` (the state
that enables the ``p`` reveal) against a counter leg the chain does not corroborate. Keys are
generated (``generate_keypair`` / ``os.urandom``), never hand-written.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import coincurve
import pytest

# tests.* import path (mirrors test_xchain_eth_adversarial_e2e; conftest adds the repo root).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg, FundingPolicy
from pyrxd.btc_wallet.keys import BtcKeypair, generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.security.errors import NetworkError, ValidationError
from tests.test_swap_coordinator import FakeIndexer, FakeRadiantLeg, FakeSeenStore

_BTC_SATS = 100_000
_FUNDING_TXID = "ab" * 32


# --------------------------------------------------------------------------- fakes


class _HostileChainView:
    """The BTC node the MAKER reads through — i.e. what the taker really put on-chain.

    Satisfies ``BtcFundingReader`` plus the ``read_confirmed_unspent_output`` capability the
    maker-side gate needs (scriptPubKey + value of a CONFIRMED, UNSPENT output). Every knob is
    a deviation a hostile taker can actually produce: a different ``sats`` (under/over-funding),
    a different ``spk`` (a decoy output the taker owns), ``spent``/``confirmed=False`` (nothing
    claimable there), or a shallow ``confs`` (reorgable).
    """

    def __init__(self, *, spk: bytes, sats: int, confs: int = 6, spent: bool = False) -> None:
        self.spk = bytes(spk)
        self.sats = int(sats)
        self.confs = int(confs)
        self.spent = bool(spent)
        self.reads: list[tuple[str, int]] = []

    # -- the maker-side binding read (confirmed UTXO set; fail-closed) --
    async def read_confirmed_unspent_output(self, txid: str, vout: int) -> tuple[bytes, int]:
        self.reads.append((str(txid), int(vout)))
        if self.spent or self.confs < 1:
            raise NetworkError("gettxout returned null — spent, unconfirmed, or unknown; fail-closed")
        return self.spk, self.sats

    # -- BtcFundingReader Protocol --
    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        return self.sats

    async def confirmations(self, txid: str) -> int:
        return self.confs

    async def txid_of(self, raw_tx: bytes) -> str:
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


class _BlindChainView:
    """A reader with NO ``read_confirmed_unspent_output`` — the maker cannot bind the funding
    output at all. The gate must refuse to lock rather than proceed on an unverifiable leg."""

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        return _BTC_SATS

    async def confirmations(self, txid: str) -> int:
        return 100

    async def txid_of(self, raw_tx: bytes) -> str:
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


class _NullBroadcaster:
    async def broadcast(self, raw_tx: bytes) -> str:
        return hashlib.sha256(bytes(raw_tx)).hexdigest()


# --------------------------------------------------------------------------- builders


def _xonly(kp: BtcKeypair) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(kp._privkey.unsafe_raw_bytes()).format()


def _terms(*, maker_kp: BtcKeypair, taker_kp: BtcKeypair) -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=_BTC_SATS,
        radiant_amount=1_000,
        t_btc=t.Timelock(72, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(144, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(maker_kp),
        btc_refund_pubkey_xonly=_xonly(taker_kp),
    )


def _expected_htlc(terms: NegotiatedTerms) -> t.BtcHtlc:
    """The HTLC the MAKER re-derives from its own copy of terms (never taker-supplied)."""
    return t.build_htlc(
        hashlock=terms.hashlock,
        claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        refund_pubkey_xonly=terms.btc_refund_pubkey_xonly,
        timeout=terms.t_btc,
        network="bcrt",
    )


def _maker_leg(*, terms, maker_kp, taker_kp, reader, min_confirmations: int = 1) -> BitcoinTaprootLeg:
    """A MAKER-role BTC leg (holds the claim key; never funds). The taker keypair/UTXO are the
    placeholders the shipped runbook passes on the maker host."""
    return BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker_kp,
        funding_utxo=BtcUtxo(txid=_FUNDING_TXID, vout=0, value=terms.btc_sats * 3),
        maker_claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        broadcaster=_NullBroadcaster(),
        funding_reader=reader,
        refund_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        claim_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        policy=FundingPolicy(fee_sats=500, min_confirmations=min_confirmations),
        maker_claim_privkey=maker_kp._privkey.unsafe_raw_bytes(),
    )


def _advertised_locator(terms: NegotiatedTerms) -> t.BtcHtlcLocator:
    """What the hostile TAKER hands the maker in ``taker_funding.json``: a well-formed locator
    for the RIGHT HTLC that SELF-REPORTS the agreed amount. Every field is attacker-chosen, so
    the maker may trust nothing here but the outpoint it goes and reads on-chain."""
    return _expected_htlc(terms).with_funding(t.BtcOutpoint(_FUNDING_TXID, 0), terms.btc_sats)


def _maker_coord(*, terms, leg, policy=None, locator=..., state=SwapState.BTC_LOCKED) -> SwapCoordinator:
    """The maker's coordinator at BTC_LOCKED holding the taker-advertised locator — exactly what
    ``scripts/btc_swap_two_host.py --phase lock-claim`` builds from ``taker_funding.json``."""
    loc = _advertised_locator(terms) if locator is ... else locator
    record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    if loc is not None:
        record = record.with_counter_lock(loc)
    record = record.with_state(state)
    return SwapCoordinator(
        record=record,
        counter_leg=leg,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=policy or MarginPolicy.estimated()),
    )


async def _lock_asset(coord: SwapCoordinator):
    """The maker's asset-lock step: revalidate the covenant it just funded → BOTH_LOCKED."""
    spk = await coord.radiant_leg.expected_covenant_scriptpubkey(coord.record.terms)
    return await coord.post_asset_lock_revalidate(spk)


def _setup(*, chain_sats=None, chain_spk=None, confs: int = 6, spent: bool = False, min_confirmations: int = 1):
    """Honest maker + a chain that reports whatever the hostile taker funded."""
    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker_kp, taker_kp=taker_kp)
    view = _HostileChainView(
        spk=_expected_htlc(terms).scriptpubkey if chain_spk is None else chain_spk,
        sats=terms.btc_sats if chain_sats is None else chain_sats,
        confs=confs,
        spent=spent,
    )
    leg = _maker_leg(
        terms=terms, maker_kp=maker_kp, taker_kp=taker_kp, reader=view, min_confirmations=min_confirmations
    )
    return terms, view, leg


# --------------------------------------------------------------------------- the gap (HZ-3)


async def test_maker_refuses_to_lock_against_under_funded_btc_htlc():
    """THE gap. A hostile taker funds the CORRECT, freely-derivable HTLC address with LESS than
    ``value_amount``. Every SPK check in the handshake passes. The maker's asset lock MUST raise
    rather than reach BOTH_LOCKED — otherwise it claims the under-funded BTC (revealing ``p``),
    the taker claims the full asset, and the maker is paid less than the agreed price.

    Fails on the pre-fix code: ``post_asset_lock_revalidate`` skipped the counter-funding gate
    entirely for a BTC counter leg and advanced straight to BOTH_LOCKED."""
    terms, view, leg = _setup(chain_sats=_BTC_SATS - 30_000)
    coord = _maker_coord(terms=terms, leg=leg)

    with pytest.raises(ValidationError, match="70000"):
        await _lock_asset(coord)

    assert coord.record.state is SwapState.BTC_LOCKED  # never reached the reveal-enabling state
    assert view.reads == [(_FUNDING_TXID, 0)]  # the maker DID read the real output

    # The same deviation is caught by the explicit maker-side gate, before any asset is locked.
    with pytest.raises(ValidationError, match="70000"):
        await coord.maker_verify_counter_funding(t.BtcOutpoint(_FUNDING_TXID, 0))


async def test_maker_refuses_to_lock_against_over_funded_btc_htlc():
    """Over-funding is rejected too, consistent with the ``taker_funds_btc`` bind: the claim leaf
    does not cap value, so the maker would sweep the whole output — a one-sided TAKER loss."""
    terms, _view, leg = _setup(chain_sats=_BTC_SATS + 30_000)
    coord = _maker_coord(terms=terms, leg=leg)

    with pytest.raises(ValidationError, match="130000"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_maker_refuses_a_decoy_output_with_the_right_amount():
    """The taker points the maker at a DECOY output it owns, carrying exactly the agreed sats.
    Only the re-derived scriptPubKey catches this: the locator's own ``scriptpubkey()`` is
    attacker-supplied and proves nothing about what the outpoint actually pays."""
    decoy_spk = b"\x00\x14" + os.urandom(20)  # a p2wpkh the taker can spend
    terms, _view, leg = _setup(chain_spk=decoy_spk)
    coord = _maker_coord(terms=terms, leg=leg)

    with pytest.raises(ValidationError, match="scriptPubKey"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_maker_refuses_a_shallow_funding_output():
    """A correctly-funded but SHALLOW HTLC is reorgable: the funding can be replaced after the
    maker locks. The gate requires the leg's configured depth."""
    terms, _view, leg = _setup(confs=1, min_confirmations=3)
    coord = _maker_coord(terms=terms, leg=leg)

    with pytest.raises((ValidationError, NetworkError), match="confirmations"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_measured_policy_requires_the_btc_reorg_depth():
    """A real-value (``is_measured``) swap pins the funding to the policy's BTC reorg depth —
    the same ``btc_claim_reorg_depth`` the claim-finality gate uses — not the leg's shallow
    funding default. Mirrors the ETH gate's ``'finalized'``-when-measured discipline."""
    measured = MarginPolicy.measured(
        # EXPLICIT since measured() stopped substituting it silently; same value the
        # substitution used, so this test's arithmetic is unchanged.
        rxd_block_interval_fast_s=300.0,
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(6, t.TimeUnit.BLOCKS),
    )
    terms, view, leg = _setup(confs=5, min_confirmations=1)  # deep enough for the leg, not the policy
    coord = _maker_coord(terms=terms, leg=leg, policy=measured)

    with pytest.raises((ValidationError, NetworkError), match="required 6"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED

    view.confs = 6
    assert (await _lock_asset(coord)).state is SwapState.BOTH_LOCKED


async def test_maker_refuses_a_spent_or_unconfirmed_funding_output():
    """``gettxout``-style fail-closed: a spent / unconfirmed / unknown outpoint is not a funded
    HTLC. An unreachable authority must refuse the lock, never assume the leg is good."""
    terms, _view, leg = _setup(spent=True)
    coord = _maker_coord(terms=terms, leg=leg)

    with pytest.raises((ValidationError, NetworkError)):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


# --------------------------------------------------------------------------- TOCTOU / reorg


async def test_verified_then_reorged_funding_refuses_the_lock():
    """The verify→lock TOCTOU (the BTC twin of the ETH ``'finalized'`` pin). The maker verifies
    the funding, then a reorg replaces it with an under-funded output before the asset lock.
    Re-running the verification AT LOCK TIME is what catches it — a one-shot verify would not."""
    terms, view, leg = _setup()
    coord = _maker_coord(terms=terms, leg=leg)

    rec = await coord.maker_verify_counter_funding(t.BtcOutpoint(_FUNDING_TXID, 0))  # verifies clean
    assert rec.counterchain_locator is not None

    view.sats = _BTC_SATS - 1  # the reorg lands between verify and lock
    with pytest.raises(ValidationError, match="99999"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


# --------------------------------------------------------------------------- fail-closed plumbing


async def test_missing_locator_refuses_the_lock():
    """No locator on the record = the maker never learned WHERE the taker funded. Refuse."""
    terms, _view, leg = _setup()
    coord = _maker_coord(terms=terms, leg=leg, locator=None)

    with pytest.raises(ValidationError, match="never verified"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_reader_without_the_binding_capability_refuses_the_lock():
    """An unimplemented/unreachable authority fails CLOSED: a funding reader that cannot report
    a confirmed output's scriptPubKey + value cannot bind the counter leg, so the maker must
    refuse to lock rather than proceed on an unverifiable HTLC."""
    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker_kp, taker_kp=taker_kp)
    leg = _maker_leg(terms=terms, maker_kp=maker_kp, taker_kp=taker_kp, reader=_BlindChainView())
    coord = _maker_coord(terms=terms, leg=leg)

    with pytest.raises(ValidationError, match="read_confirmed_unspent_output"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_leg_without_verify_capability_refuses_the_lock():
    """A counter leg that does not implement ``verify_counterparty_funded`` cannot be verified;
    the maker refuses to lock instead of silently skipping the gate (the pre-fix behaviour)."""

    class _LegacyLeg:
        network = "bcrt"

        def derive_funding_scriptpubkey(self, terms):
            return _expected_htlc(terms).scriptpubkey

        def promised_funding_scriptpubkey(self, terms):
            return _expected_htlc(terms).scriptpubkey

        def locked_amount(self, locator):
            return locator.amount_sats

    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker_kp, taker_kp=taker_kp)
    coord = _maker_coord(terms=terms, leg=_LegacyLeg())

    with pytest.raises(ValidationError, match="verify_counterparty_funded"):
        await _lock_asset(coord)
    assert coord.record.state is SwapState.BTC_LOCKED


# --------------------------------------------------------------------------- honest path


async def test_honest_taker_funding_locks_normally():
    """The control: an HTLC funded at the agreed address for the agreed amount at sufficient
    depth still reaches BOTH_LOCKED, and the recorded locator is the one the MAKER re-derived
    (its script tree comes from the maker's own terms, never from the taker's JSON)."""
    terms, view, leg = _setup()
    coord = _maker_coord(terms=terms, leg=leg)

    rec = await _lock_asset(coord)

    assert rec.state is SwapState.BOTH_LOCKED
    assert rec.counterchain_locator.amount_sats == terms.btc_sats
    assert rec.counterchain_locator.scriptpubkey == _expected_htlc(terms).scriptpubkey
    assert rec.counterchain_locator.funding_outpoint == t.BtcOutpoint(_FUNDING_TXID, 0)
    assert view.reads  # the lock-time re-verification really read the chain

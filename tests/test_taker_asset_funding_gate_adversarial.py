"""TWO-PARTY ADVERSARIAL tests for the TAKER-side asset-funding gate (HZ-1).

The mirror of ``test_btc_maker_counter_funding_adversarial.py``. There the MAKER binds the
counterparty's BTC leg before locking its asset; here the TAKER binds the counterparty's
**Radiant covenant** before locking its BTC.

The gap this covers. ``docs/htlc-handshake-wire-format.md`` HZ-1 states it normatively: *"a taker
MUST NOT fund the counter leg until it has confirmed the maker's asset lock on chain, at the agreed
scriptPubKey, for the agreed value, at a depth the taker chose."* No library code enforced it. The
check lived only in ``scripts/btc_swap_two_host.py``, so any caller driving ``SwapCoordinator``
directly locked BTC against nothing: ``pre_btc_lock_check`` returned ``ok=True`` and
``taker_funds_btc`` reached ``BTC_LOCKED`` having invoked **zero** methods on the Radiant leg. The
maker holds both ``p`` and the BTC claim key from the moment the envelope is published, and the BTC
claim leaf is ``<H> … <makerClaimPk> OP_CHECKSIG`` with no precondition that the asset was ever
locked — so it claims immediately and the taker's loss is the full ``btc_sats``.

The honest TAKER here drives the REAL ``SwapCoordinator``, the REAL ``RadiantCovenantLeg`` and the
REAL ``BitcoinTaprootLeg``. The only fakes are the two nodes they read through. Keys are generated
(``generate_keypair`` / ``os.urandom``), never hand-written.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import coincurve
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg, FundingPolicy
from pyrxd.btc_wallet.keys import BtcKeypair, generate_keypair
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20
from tests.test_swap_coordinator import FakeIndexer, FakeSeenStore

pytestmark = pytest.mark.asyncio

_BTC_SATS = 100_000
_RXD_AMOUNT = 100_000
_BTC_FUNDING_TXID = "ab" * 32
_COV_FUNDING_TXID = "cd" * 32

_TAKER_PKH = bytes(Hex20(PrivateKey(os.urandom(32)).public_key().hash160()))
_MAKER_PKH = bytes(Hex20(PrivateKey(os.urandom(32)).public_key().hash160()))


# --------------------------------------------------------------------------- fakes


class _RxdChainView:
    """The Radiant node the TAKER reads the maker's covenant through.

    Every knob is a deviation a hostile maker can actually produce: ``funded=False`` (never
    locked anything), a wrong ``value`` (mis-funded covenant), a wrong ``spk`` (funded some
    OTHER script), or a shallow ``confs`` (a replaceable/reorgable funding it can double-spend
    away after the taker's BTC is locked).
    """

    def __init__(self, *, spk: bytes, value: int = _RXD_AMOUNT, confs: int = 6, funded: bool = True) -> None:
        self.spk = bytes(spk)
        self.value = int(value)
        self.confs = int(confs)
        self.funded = bool(funded)
        self.utxo_reads = 0
        self.conf_reads = 0
        self.raise_on_read: Exception | None = None

    async def get_utxos(self, script_hash):
        self.utxo_reads += 1
        if self.raise_on_read is not None:
            raise self.raise_on_read
        if not self.funded:
            return []
        want = hashlib.sha256(self.spk).digest()[::-1]
        if bytes(script_hash) != want:
            return []  # the taker scanned the agreed SPK; the maker funded a different one
        return [UtxoRecord(tx_hash=_COV_FUNDING_TXID, tx_pos=0, value=self.value, height=100)]

    async def get_transaction_verbose(self, txid):
        self.conf_reads += 1
        if self.raise_on_read is not None:
            raise self.raise_on_read
        return {"confirmations": self.confs}

    async def broadcast(self, raw_tx: bytes) -> str:  # pragma: no cover - the taker never spends here
        raise AssertionError("the taker must not broadcast a Radiant spend in this phase")


class _BtcChainView:
    """The BTC node the taker funds through. Records every broadcast so a test can prove that
    NOTHING was locked when the gate refused."""

    def __init__(self) -> None:
        self.broadcasts: list[bytes] = []

    async def broadcast(self, raw_tx: bytes) -> str:
        self.broadcasts.append(bytes(raw_tx))
        return t.btc_txid_from_raw(bytes(raw_tx))

    async def read_output_amount_sats(self, txid: str, vout: int, *, min_confirmations: int) -> int:
        return _BTC_SATS

    async def confirmations(self, txid: str) -> int:
        return 6

    async def txid_of(self, raw_tx: bytes) -> str:
        return t.btc_txid_from_raw(bytes(raw_tx))


class _SpyRadiantLeg:
    """The audit's instrument: a Radiant leg that records every method the coordinator calls.

    It answers everything permissively — the point is not what it returns but WHETHER it is
    consulted. On the pre-fix code the taker locked BTC with ``calls == []``.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def expected_covenant_scriptpubkey(self, terms) -> bytes:
        self.calls.append("expected_covenant_scriptpubkey")
        return b"\x76\xa9" + hashlib.sha256(terms.hashlock).digest()

    async def covenant_outpoint(self, terms) -> str:
        self.calls.append("covenant_outpoint")
        return _COV_FUNDING_TXID + ":0"

    async def claim_asset(self, record, preimage) -> None:  # pragma: no cover - unused here
        self.calls.append("claim_asset")

    async def refund_asset(self, record) -> None:  # pragma: no cover - unused here
        self.calls.append("refund_asset")


class _FeeSource:
    def next_fee_input(self) -> FeeInput:
        key = PrivateKey(os.urandom(32))
        spk = b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"
        return FeeInput(txid=os.urandom(32).hex(), vout=0, value=20_000_000, scriptpubkey=spk, wif=key.wif())


# --------------------------------------------------------------------------- builders


def _xonly(kp: BtcKeypair) -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(kp._privkey.unsafe_raw_bytes()).format()


# t_rxd 90, not 80. t_btc derives as t_rxd//2 = 45, and a MEASURED policy requires the covenant to
# be burial-deep (6) BEFORE the taker funds — so the margin is judged on the REMAINING window
# (#482 follow-up): 90 - 6 - 45 = 39 >= the 36-block margin. At 80 the remaining gap is 34 and
# the gate correctly refuses. Production must carry the same headroom; a fixture sized to the
# negotiated terms alone models a swap that cannot be funded.
def _terms(*, maker_kp: BtcKeypair, taker_kp: BtcKeypair, t_rxd_blocks: int = 90) -> NegotiatedTerms:
    """Terms whose dest hashes come from the REAL covenant, so the real leg binds to them."""
    hashlock = hashlib.sha256(os.urandom(32)).digest()
    cov = build_htlc_covenant_rxd(
        amount=_RXD_AMOUNT,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=hashlock,
        refund_csv=t_rxd_blocks,
    )
    return NegotiatedTerms(
        hashlock=hashlock,
        btc_sats=_BTC_SATS,
        radiant_amount=_RXD_AMOUNT,
        # DERIVED from the covenant's own CSV (#482): t_rxd IS `refund_csv` here, and it defaults
        # to 20, so a fixed t_btc of 72 makes the terms unconstructible under the inverted rule.
        # t_btc = t_rxd//2 is EXACTLY the zero-margin boundary in wall clock (#567): at 600 s
        # per BTC block against 300 s per Radiant block, half as many BTC blocks open at the
        # same instant. So that derivation could never satisfy any margin — subtract it.
        t_btc=t.Timelock(max(1, t_rxd_blocks // 2 - 36 - 4), t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
        asset_variant="rxd",
        genesis_ref=b"",
        taker_dest_hash=cov.expected_taker_hash,
        maker_dest_hash=cov.expected_maker_hash,
        btc_claim_pubkey_xonly=_xonly(maker_kp),
        btc_refund_pubkey_xonly=_xonly(taker_kp),
    )


def _covenant_spk(terms: NegotiatedTerms) -> bytes:
    return build_htlc_covenant_rxd(
        amount=terms.radiant_amount,
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        hashlock=terms.hashlock,
        refund_csv=terms.t_rxd.value,
    ).funded_spk


def _taker_btc_leg(*, terms, taker_kp, btc_view) -> BitcoinTaprootLeg:
    """A TAKER-role BTC leg: funds + refunds, holds NO maker claim key."""
    return BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=taker_kp,
        funding_utxo=BtcUtxo(txid=_BTC_FUNDING_TXID, vout=0, value=terms.btc_sats * 3),
        maker_claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        broadcaster=btc_view,
        funding_reader=btc_view,
        refund_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        claim_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        policy=FundingPolicy(fee_sats=500, min_confirmations=1),
        maker_claim_privkey=None,
    )


def _rxd_leg(rxd_view, *, min_confirmations: int = 1) -> RadiantCovenantLeg:
    return RadiantCovenantLeg(
        network="bcrt",
        taker_pkh=_TAKER_PKH,
        maker_pkh=_MAKER_PKH,
        chain_io=RadiantChainIO(rxd_view),
        fee_source=_FeeSource(),
        min_confirmations=min_confirmations,
    )


def _setup(*, value=None, confs: int = 6, funded: bool = True, wrong_spk: bool = False, policy=None):
    """Honest taker + a Radiant chain reporting whatever the maker really locked."""
    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker_kp, taker_kp=taker_kp)
    spk = b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac" if wrong_spk else _covenant_spk(terms)
    rxd_view = _RxdChainView(
        spk=spk, value=terms.radiant_amount if value is None else value, confs=confs, funded=funded
    )
    btc_view = _BtcChainView()
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=_taker_btc_leg(terms=terms, taker_kp=taker_kp, btc_view=btc_view),
        radiant_leg=_rxd_leg(rxd_view),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=policy or MarginPolicy.estimated()),
    )
    return terms, rxd_view, btc_view, coord


# --------------------------------------------------------------------------- the gap (HZ-1)


async def test_taker_refuses_to_lock_btc_when_the_covenant_was_never_funded():
    """THE gap, in its cheapest form: the maker publishes the envelope and locks NOTHING.

    Pre-fix, ``taker_funds_btc`` reached ``BTC_LOCKED`` and the BTC was on-chain; the maker then
    claimed it with the ``p`` it has held since the envelope. Loss = the full ``btc_sats``.
    """
    terms, rxd_view, btc_view, coord = _setup(funded=False)

    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok is False
    assert "covenant" in (gate.reason or "").lower()

    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)

    assert btc_view.broadcasts == [], "no BTC may be locked against an unfunded covenant"
    assert coord.record.state is SwapState.NEGOTIATED
    assert rxd_view.utxo_reads >= 1, "the taker must actually READ the chain, not re-derive a target"


async def test_taker_refuses_a_mis_valued_covenant():
    """The covenant SPK is a pure function of the terms, so a maker who funds it SHORT still
    matches every derivation check. Only the on-chain value binds."""
    terms, _rxd_view, btc_view, coord = _setup(value=_RXD_AMOUNT - 1)

    assert (await coord.pre_btc_lock_check(terms)).ok is False
    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)
    assert btc_view.broadcasts == []


async def test_taker_refuses_a_covenant_funded_at_a_different_script():
    """A maker that funds SOME script — just not the agreed covenant — must not pass. The taker
    scans the SPK it re-derived itself, never one the maker advertises."""
    terms, _rxd_view, btc_view, coord = _setup(wrong_spk=True)

    assert (await coord.pre_btc_lock_check(terms)).ok is False
    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)
    assert btc_view.broadcasts == []


async def test_taker_refuses_a_shallow_covenant_funding():
    """ "Funded" is not enough — ElectrumX ``listunspent`` includes MEMPOOL outputs. A maker that
    funds with a replaceable tx, waits for the BTC lock, then double-spends the funding away
    leaves the taker with nothing to claim while the maker still claims BTC with ``p``."""
    terms, _rxd_view, btc_view, coord = _setup(confs=0)

    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok is False
    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)
    assert btc_view.broadcasts == []


async def test_measured_policy_pins_the_covenant_depth_to_the_reorg_policy():
    """A real-value (``is_measured``) swap requires the policy's RXD burial depth, not the leg's
    shallow default — the same ``is_measured`` discipline as the maker-side BTC gate."""
    measured = MarginPolicy.measured(
        # EXPLICIT since measured() stopped substituting it silently; same value the
        # substitution used, so this test's arithmetic is unchanged.
        rxd_block_interval_fast_s=300.0,
        margin=t.Timelock(36, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(6, t.TimeUnit.BLOCKS),
    )
    terms, rxd_view, btc_view, coord = _setup(confs=5, policy=measured)

    assert (await coord.pre_btc_lock_check(terms)).ok is False
    assert btc_view.broadcasts == []

    rxd_view.confs = 6
    assert (await coord.pre_btc_lock_check(terms)).ok is True


async def test_taker_refuses_when_the_radiant_node_is_unreachable():
    """Fail-CLOSED, not fail-open: an unreadable authority is not a pass."""
    terms, rxd_view, btc_view, coord = _setup()
    rxd_view.raise_on_read = NetworkError("connection lost")

    assert (await coord.pre_btc_lock_check(terms)).ok is False
    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)
    assert btc_view.broadcasts == []


async def test_taker_refuses_a_radiant_leg_without_the_verification_capability():
    """A leg that cannot verify the maker's funding cannot be verified AT ALL — refuse to lock
    rather than silently skip the gate (mirrors ``_counter_verify_callable``).

    This is also the audit's instrument: the spy records every Radiant-leg call. Pre-fix it
    reached ``BTC_LOCKED`` with ``calls == []`` — the taker never read the chain at all.
    """
    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    terms = _terms(maker_kp=maker_kp, taker_kp=taker_kp)
    btc_view = _BtcChainView()
    spy = _SpyRadiantLeg()
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=_taker_btc_leg(terms=terms, taker_kp=taker_kp, btc_view=btc_view),
        radiant_leg=spy,
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated()),
    )

    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok is False
    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)

    assert btc_view.broadcasts == [], "a leg that cannot verify must not let BTC be locked"
    assert coord.record.state is SwapState.NEGOTIATED


async def test_the_verify_to_lock_toctou_is_closed():
    """The gate passes, then the maker double-spends its covenant funding away before the taker
    broadcasts. A one-shot check in ``pre_btc_lock_check`` would never see it, so the
    verification is RE-RUN immediately before the BTC lock."""
    terms, rxd_view, btc_view, coord = _setup()
    assert (await coord.pre_btc_lock_check(terms)).ok is True  # verified...

    rxd_view.funded = False  # ...then it vanishes

    with pytest.raises((ValidationError, NetworkError)):
        await coord.taker_funds_btc(terms)
    assert btc_view.broadcasts == [], "the re-run must catch the vanished covenant BEFORE the lock"
    assert coord.record.state is SwapState.NEGOTIATED


async def test_honest_control_still_locks_btc():
    """The honest path is unaffected: a funded, correctly-valued, buried covenant lets the taker
    lock — and the Radiant chain was genuinely read to decide that."""
    terms, rxd_view, btc_view, coord = _setup()

    assert (await coord.pre_btc_lock_check(terms)).ok is True
    record = await coord.taker_funds_btc(terms)

    assert record.state is SwapState.BTC_LOCKED
    assert len(btc_view.broadcasts) == 1
    assert rxd_view.utxo_reads >= 2, "verified once at the gate and again at lock time (TOCTOU)"
    assert rxd_view.conf_reads >= 2

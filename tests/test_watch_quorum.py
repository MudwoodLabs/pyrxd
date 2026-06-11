"""Tests for the watchtower observation/quorum layer (``gravity.watch.quorum``).

Fakes for the BTC claim source + RXD chain source. Covers claim detection,
depth pass-through, asset-lock-height derivation (incl. bogus-source guard),
the v1 single-source low-corroboration flag, and an observe→decide integration
check (conservative min-depth must not produce a premature PAGE_CLAIM).
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import BtcClaimStatus, ChainObserver, EthClaimStatus, Intent, decide
from pyrxd.security.errors import ValidationError

COV_OUTPOINT = "ab" * 32 + ":0"


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _terms() -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _locator() -> t.BtcHtlcLocator:
    htlc = t.build_htlc(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        claim_pubkey_xonly=_xonly(),
        refund_pubkey_xonly=_xonly(),
        timeout=t.Timelock(144, t.TimeUnit.BLOCKS),
    )
    return htlc.with_funding(t.BtcOutpoint("cd" * 32, 1), 100_000)


def _policy() -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
    )


def _record(state=SwapState.BOTH_LOCKED, *, with_locator=True, with_covenant=True) -> SwapRecord:
    return SwapRecord(
        state=state,
        terms=_terms(),
        counterchain_locator=_locator() if with_locator else None,
        radiant_covenant_outpoint=COV_OUTPOINT if with_covenant else None,
    )


class FakeBtc:
    def __init__(self, status: BtcClaimStatus, confs: int = 0):
        self._status = status
        self._confs = confs
        self.claim_status_calls: list[tuple[str, int]] = []

    async def claim_status(self, funding_txid, funding_vout):
        self.claim_status_calls.append((funding_txid, funding_vout))
        return self._status

    async def confirmations(self, claim_txid):
        return self._confs


class FakeRxd:
    def __init__(self, tip: int, cov_confs: int | None = None, *, corroborated: bool = False):
        self._tip = tip
        self._cov = cov_confs
        self.corroborated = corroborated  # mirrors MultiSourceRxdChainSource.corroborated (LOW-R2)

    async def tip_height(self):
        return self._tip

    async def covenant_confirmations(self, outpoint):
        return self._cov


# --- tests ----------------------------------------------------------------


async def test_maker_not_claimed():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _record())
    assert obs.maker_has_claimed_btc is False
    assert obs.btc_claim_confirmations is None
    assert obs.now_rxd_height == 200
    assert obs.asset_locked_at_height == 100  # 200 - 101 + 1
    assert obs.low_corroboration is True  # v1 RXD single-source
    # the funding outpoint was queried
    assert btc.claim_status_calls == [("cd" * 32, 1)]


async def test_maker_claimed_fills_depth():
    btc = FakeBtc(BtcClaimStatus(claimed=True, claim_txid="ef" * 32), confs=6)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _record())
    assert obs.maker_has_claimed_btc is True
    assert obs.btc_claim_confirmations == 6


async def test_covenant_unmined_yields_none_lock_height():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=None)).observe("s", _record())
    assert obs.asset_locked_at_height is None


async def test_no_covenant_outpoint_yields_none_lock_height():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    rec = _record(with_covenant=False)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", rec)
    assert obs.asset_locked_at_height is None


async def test_no_locator_skips_btc_query():
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    rec = _record(state=SwapState.NEGOTIATED, with_locator=False, with_covenant=False)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200)).observe("s", rec)
    assert obs.maker_has_claimed_btc is False
    assert btc.claim_status_calls == []  # no funding outpoint to watch yet


async def test_bogus_covenant_confs_guarded_to_none():
    # cov_confs > tip + 1 (impossible on an honest chain) ⇒ candidate < 0 ⇒ None, not negative.
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=500)).observe("s", _record())
    assert obs.asset_locked_at_height is None


async def test_corroboration_flag_requires_structural_quorum():
    # LOW-R2: rxd_corroborated must be backed by a real multi-source quorum, not a free bool.
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    single = FakeRxd(tip=200, cov_confs=101)  # corroborated=False (a single source)
    # default (single source) → low_corroboration flagged
    assert (
        await ChainObserver(btc=btc, rxd=single, rxd_corroborated=False).observe("s", _record())
    ).low_corroboration is True
    # asserting corroboration over a non-corroborated source is REFUSED at construction
    with pytest.raises(ValidationError, match="multi-source RXD quorum"):
        ChainObserver(btc=btc, rxd=single, rxd_corroborated=True)
    # a genuinely corroborated (quorum) source clears the flag
    quorum_rxd = FakeRxd(tip=200, cov_confs=101, corroborated=True)
    assert (
        await ChainObserver(btc=btc, rxd=quorum_rxd, rxd_corroborated=True).observe("s", _record())
    ).low_corroboration is False


async def test_observe_then_decide_min_depth_no_premature_claim():
    # Quorum returns the conservative MIN depth (3 < required 6) ⇒ gate WAIT ⇒ no PAGE_CLAIM.
    btc = FakeBtc(BtcClaimStatus(claimed=True, claim_txid="ef" * 32), confs=3)
    rec = _record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)  # locked at 100
    d = decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.WATCH  # NOT a premature PAGE_CLAIM


async def test_observe_then_decide_safe_depth_pages_claim_with_corroboration_flag():
    btc = FakeBtc(BtcClaimStatus(claimed=True, claim_txid="ef" * 32), confs=6)
    rec = _record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(btc=btc, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)  # locked at 100
    d = decide(record=rec, observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.low_corroboration is True  # propagated from the single-source RXD read


# --- ETH counter-leg routing (v3) -----------------------------------------


def _eth_terms() -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=b"\x00" * 32,
        btc_refund_pubkey_xonly=b"\x00" * 32,
        counter_chain="eth",
        value_amount=10**15,
        eth_timeout_unix_s=4_000_000_000,
    )


def _eth_locator() -> EthHtlcLocator:
    return EthHtlcLocator(
        chain_id=11155111,
        contract_address="0x" + "ab" * 20,
        deploy_tx_hash="0x" + "cd" * 32,
        hashlock="0x" + "ef" * 32,
        claimant="0x" + "11" * 20,
        refundee="0x" + "22" * 20,
        timeout=4_000_000_000,
        amount_wei=10**15,
    )


def _eth_record(state=SwapState.BOTH_LOCKED, *, with_locator=True, with_covenant=True) -> SwapRecord:
    return SwapRecord(
        state=state,
        terms=_eth_terms(),
        counterchain_locator=_eth_locator() if with_locator else None,
        radiant_covenant_outpoint=COV_OUTPOINT if with_covenant else None,
    )


def _eth_policy() -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
        eth_finalization_window_s=768,
    )


class FakeEth:
    def __init__(self, status: EthClaimStatus, finality: CounterClaimState | None = None):
        self._status = status
        self._finality = finality
        self.claim_status_calls: list[tuple[str, str]] = []
        self.verdict_calls: list[str] = []

    async def claim_status(self, contract_address, deploy_tx_hash):
        self.claim_status_calls.append((contract_address, deploy_tx_hash))
        return self._status

    async def claim_finality_verdict(self, claim_tx_hash):
        self.verdict_calls.append(claim_tx_hash)
        return CounterClaimFinality(state=self._finality)


async def test_eth_maker_not_claimed():
    eth = FakeEth(EthClaimStatus(claimed=False))
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _eth_record())
    assert obs.eth_claim_detected is False
    assert obs.eth_claim_finality is None
    assert obs.maker_has_claimed_btc is False  # BTC field unused on the ETH path
    assert obs.now_rxd_height == 200
    assert obs.asset_locked_at_height == 100  # shared RXD derivation: 200 - 101 + 1
    assert obs.low_corroboration is True
    assert eth.claim_status_calls == [("0x" + "ab" * 20, "0x" + "cd" * 32)]
    assert eth.verdict_calls == []  # not claimed → no finality read


async def test_eth_maker_claimed_final_fills_finality():
    eth = FakeEth(EthClaimStatus(claimed=True, claim_tx_hash="0x" + "12" * 32), finality=CounterClaimState.FINAL)
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _eth_record())
    assert obs.eth_claim_detected is True
    assert obs.eth_claim_finality is CounterClaimState.FINAL
    assert eth.verdict_calls == ["0x" + "12" * 32]


async def test_eth_maker_claimed_not_yet_final():
    eth = FakeEth(
        EthClaimStatus(claimed=True, claim_tx_hash="0x" + "12" * 32), finality=CounterClaimState.NOT_YET_FINAL_LIVE
    )
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _eth_record())
    assert obs.eth_claim_detected is True
    assert obs.eth_claim_finality is CounterClaimState.NOT_YET_FINAL_LIVE


async def test_eth_pre_fund_no_locator_skips_eth_query():
    eth = FakeEth(EthClaimStatus(claimed=False))
    rec = _eth_record(state=SwapState.NEGOTIATED, with_locator=False, with_covenant=False)
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=200)).observe("s", rec)
    assert obs.eth_claim_detected is False
    assert obs.eth_claim_finality is None
    assert eth.claim_status_calls == []  # no ETH contract to watch yet


async def test_eth_swap_without_eth_source_fails_closed():
    # An ETH record observed by a BTC-only observer must FAIL (reconciler turns it into a page),
    # never silently report "nothing claimed".
    btc = FakeBtc(BtcClaimStatus(claimed=False))
    with pytest.raises(ValidationError):
        await ChainObserver(btc=btc, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _eth_record())


async def test_btc_swap_without_btc_source_fails_closed():
    eth = FakeEth(EthClaimStatus(claimed=False))
    with pytest.raises(ValidationError):
        await ChainObserver(eth=eth, rxd=FakeRxd(tip=200, cov_confs=101)).observe("s", _record())


async def test_chain_observer_requires_a_counter_leg_source():
    with pytest.raises(ValidationError):
        ChainObserver(rxd=FakeRxd(tip=200))


async def test_eth_observe_then_decide_final_pages_claim():
    eth = FakeEth(EthClaimStatus(claimed=True, claim_tx_hash="0x" + "12" * 32), finality=CounterClaimState.FINAL)
    rec = _eth_record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)  # locked at 100
    d = decide(record=rec, observations=obs, policy=_eth_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_CLAIM
    assert d.recommended_action == "taker_scrape_and_claim_asset"
    assert d.low_corroboration is True


async def test_eth_observe_then_decide_not_final_waits():
    eth = FakeEth(
        EthClaimStatus(claimed=True, claim_tx_hash="0x" + "12" * 32), finality=CounterClaimState.NOT_YET_FINAL_LIVE
    )
    rec = _eth_record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)  # locked at 100
    d = decide(record=rec, observations=obs, policy=_eth_policy(), safety_window_blocks=6)
    assert d.intent is Intent.WATCH  # awaiting the finalized checkpoint, window has room


async def test_eth_observe_propagates_not_finalizing_to_squeeze():
    # The observer must propagate a COUNTER_CHAIN_NOT_FINALIZING verdict straight to decide(), which
    # SQUEEZES even with an ample window (RF-06: a non-finalizing counter chain is never WAITed out).
    eth = FakeEth(
        EthClaimStatus(claimed=True, claim_tx_hash="0x" + "12" * 32),
        finality=CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING,
    )
    rec = _eth_record(state=SwapState.SECRET_REVEALED)
    obs = await ChainObserver(eth=eth, rxd=FakeRxd(tip=150, cov_confs=51)).observe("s", rec)
    assert obs.eth_claim_finality is CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING
    d = decide(record=rec, observations=obs, policy=_eth_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_SQUEEZED


def test_eth_claim_status_claimed_requires_hash():
    # The dead-branch invariant the observer relies on: a claimed status MUST carry the tx hash.
    with pytest.raises(ValidationError):
        EthClaimStatus(claimed=True)

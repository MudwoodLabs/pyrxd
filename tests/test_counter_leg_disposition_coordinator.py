"""The coordinator acts on what the chain shows about the ETH counter leg (#850 PR 5a).

`reconcile_counter_leg` and the read-first branch of `taker_refund_btc`, driven through the real
`SwapCoordinator` and the real reader (`pyrxd.eth_wallet.disposition`) over the fake EVM chain of PR 4,
read through the production `MultiSourceEthRpc`. Only the leg's broadcast is faked.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from pyrxd.eth_wallet.disposition import read_counter_disposition
from pyrxd.eth_wallet.events import CLAIMED_TOPIC0
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.gravity.swap_coordinator import SwapCoordinator
from pyrxd.gravity.swap_state import AbortReason, RecordRole, SwapRecord, SwapRole, SwapState
from pyrxd.security.errors import NetworkError, ValidationError
from tests._fake_evm_chain import FakeEvmChain, FakeEvmEndpoint
from tests.test_swap_coordinator import (
    CoordinatorConfig,
    FakeEthLeg,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _eth_finality_policy,
    _eth_terms,
    _final,
)

TIMEOUT_BLOCK = 80
_COVENANT = "ef" * 32 + ":0"


class _ChainLeg(FakeEthLeg):
    """FakeEthLeg whose disposition is read by the REAL reader from the fake chain."""

    def __init__(self, *a, rpc, **k):
        super().__init__(*a, **k)
        self._rpc = rpc
        self.refunds = 0

    async def counter_disposition(self, locator):
        return await read_counter_disposition(self._rpc, locator)

    async def refund(self, locator, timeout=None, **_k):
        self.refunds += 1
        return "0x" + "fe" * 32


def _setup(*, state=SwapState.BTC_LOCKED, role=SwapRole.TAKER, endpoints=None, chain_kw=None, confs=None, pin=True):
    p = os.urandom(32)
    chain = FakeEvmChain(preimage=p, timeout=0, **(chain_kw or {}))
    chain.timeout = chain.ts(TIMEOUT_BLOCK)
    terms = _eth_terms(hashlock=hashlib.sha256(p).digest(), eth_timeout_unix_s=chain.timeout, now_unix_s=chain.ts(0))
    rpc = MultiSourceEthRpc(endpoints(chain) if endpoints else [FakeEvmEndpoint(chain) for _ in range(3)])
    leg = _ChainLeg(preimage=p, verdict=_final(), rpc=rpc)
    rxd = FakeRadiantLeg()
    rxd.report_confs = confs
    record = SwapRecord(state=state, terms=terms).with_counter_lock(chain.locator())
    if pin:
        record = record.with_radiant_lock(_COVENANT, "51")
    coord = SwapCoordinator(
        record=record,
        counter_leg=leg,
        radiant_leg=rxd,
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=_eth_finality_policy(window_s=768), maker_stall_safety_window_blocks=6, role=role
        ),
    )
    coord.persisted = []

    async def _persist(r):
        coord.persisted.append(r)

    coord._persist = _persist
    return coord, chain, leg


# --------------------------------------------------------------------------- reconcile


async def test_a_verified_claim_moves_a_takers_btc_locked_record_to_secret_revealed():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    tx = chain.claim(70)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.SECRET_REVEALED
    assert rec.counter_claim_tx == tx and rec.counter_disposition.kind == "claimed"
    assert rec.counter_disposition.tx_hash == tx and coord.persisted[-1] == rec
    assert leg.refunds == 0


async def test_gap_b_claimed_moves_it_too_with_no_claim_tx():
    def hide(chain):
        return [FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(3)]

    coord, chain, _leg = _setup(endpoints=hide)
    chain.claim(50)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.SECRET_REVEALED and rec.counter_disposition.tx_hash is None


async def test_an_observed_refund_aborts_a_takers_record_with_its_reason():
    coord, chain, _leg = _setup(chain_kw={"finalized": 90})
    tx = chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COUNTER_LEG_REFUNDED
    assert rec.counter_disposition.kind == "refunded" and rec.counter_disposition.tx_hash == tx


async def test_an_observed_refund_after_a_params_mismatch_aborts_too():
    coord, chain, _leg = _setup(state=SwapState.PARAMS_MISMATCH, role=None, chain_kw={"finalized": 90})
    chain.refund(85)
    assert (await coord.reconcile_counter_leg()).state is SwapState.ABORTED


async def test_a_claim_after_a_params_mismatch_has_no_edge_and_raises():
    coord, chain, _leg = _setup(state=SwapState.PARAMS_MISMATCH, role=None, chain_kw={"finalized": 90})
    chain.claim(70)
    with pytest.raises(ValidationError, match="params mismatch"):
        await coord.reconcile_counter_leg()
    assert coord.record.state is SwapState.PARAMS_MISMATCH and coord.record.counter_disposition.kind == "claimed"
    assert coord.persisted[-1].counter_disposition.kind == "claimed"  # durable before the raise


async def test_a_makers_record_records_the_evidence_and_stays():
    coord, chain, _leg = _setup(role=SwapRole.MAKER, chain_kw={"finalized": 90})
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.BTC_LOCKED and rec.counter_disposition.kind == "refunded"


async def test_a_claim_with_no_covenant_pin_records_and_raises():
    coord, chain, _leg = _setup(pin=False, chain_kw={"finalized": 90})
    chain.claim(70)
    with pytest.raises(ValidationError, match="no covenant outpoint"):
        await coord.reconcile_counter_leg()
    assert coord.record.state is SwapState.BTC_LOCKED and coord.record.counter_claim_tx is not None
    assert coord.persisted[-1].counter_claim_tx is not None  # durable before the raise


async def test_an_unknown_disposition_changes_nothing_and_raises():
    def throttled(chain):
        return [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]

    coord, chain, _leg = _setup(endpoints=throttled, chain_kw={"finalized": 90})
    chain.refund(85)
    with pytest.raises(NetworkError, match="unknown"):
        await coord.reconcile_counter_leg()
    assert coord.record.state is SwapState.BTC_LOCKED and coord.persisted == []


async def test_both_locked_claimed_goes_to_secret_revealed_but_refunded_waits_for_pr6():
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    chain.claim(70)
    assert (await coord.reconcile_counter_leg()).state is SwapState.SECRET_REVEALED
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.BOTH_LOCKED and rec.counter_disposition.kind == "refunded"


# --------------------------------------------------------------------------- D14: a seen claim holds


def _with_a_dropped_claim(chain):
    dropped = {
        "address": "0x" + "c0" * 20,
        "topics": [CLAIMED_TOPIC0],
        "data": "0x" + chain.preimage.hex(),
        "transactionHash": "0x" + "dd" * 32,
        "blockNumber": 78,
    }
    return [FakeEvmEndpoint(chain, extra_logs=(dropped,)), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain)]


async def test_a_seen_claim_holds_an_observed_refund_open_until_t_rxd():
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1)
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.BTC_LOCKED  # held: p is public, the covenant claim comes first
    assert rec.counter_claim_tx == "0x" + "dd" * 32 and rec.counter_disposition.kind == "refunded"


async def test_HONEST_once_t_rxd_has_matured_the_held_refund_aborts():
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90})
    coord.radiant_leg.report_confs = int(coord.record.terms.t_rxd.value)
    chain.refund(85)
    assert (await coord.reconcile_counter_leg()).state is SwapState.ABORTED


async def test_an_unreadable_covenant_depth_holds():
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90})
    coord.radiant_leg.asset_funded = False  # the depth read raises
    chain.refund(85)
    assert (await coord.reconcile_counter_leg()).state is SwapState.BTC_LOCKED


# --------------------------------------------------------------------------- one endpoint (D4)


async def test_one_endpoint_on_a_value_bearing_chain_changes_nothing(monkeypatch):
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    chain.refund(85)
    leg._rpc = FakeEvmEndpoint(chain)  # single source
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    with pytest.raises(NetworkError, match="from ONE endpoint, on a chain that carries value"):
        await coord.reconcile_counter_leg()
    assert coord.record.state is SwapState.BTC_LOCKED and coord.record.counter_disposition is None


async def test_HONEST_one_endpoint_on_a_testnet_decides():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})  # the fake chain is Sepolia
    chain.refund(85)
    leg._rpc = FakeEvmEndpoint(chain)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.single_source is True


@pytest.mark.parametrize(("chain_id", "decides"), [(11155111, True), (31337, True), (1, False), (999_999_999, False)])
def test_which_chains_may_decide_on_one_endpoint(chain_id, decides):
    assert SwapCoordinator._single_source_may_decide(chain_id) is decides


# --------------------------------------------------------------------------- taker_refund_btc reads first


async def test_the_taker_refund_reads_first_and_sends_nothing_on_an_observed_claim():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    chain.claim(70)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.SECRET_REVEALED and leg.refunds == 0


async def test_the_taker_refund_sends_nothing_on_a_refund_someone_else_sent():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    chain.refund(85)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COUNTER_LEG_REFUNDED
    assert leg.refunds == 0


async def test_the_taker_refund_waits_while_settled_only_at_the_tip():
    coord, chain, leg = _setup()
    chain.refund(95)  # above F=64
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and leg.refunds == 0


async def test_HONEST_an_expired_unsettled_contract_is_refunded_as_before():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 1 and rec.state is SwapState.ABORTED and rec.abort_reason is None


async def test_HONEST_an_unknown_disposition_still_sends_as_before():
    def throttled(chain):
        return [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]

    coord, _chain, leg = _setup(endpoints=throttled, chain_kw={"finalized": 90})
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 1 and rec.state is SwapState.ABORTED


async def test_a_seen_claim_records_and_still_refunds_but_holds_the_terminal():
    coord, _chain, leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1)
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 1 and rec.state is SwapState.BTC_LOCKED and rec.counter_claim_tx is not None
    assert coord.persisted[-1].counter_claim_tx == rec.counter_claim_tx


async def test_a_maker_coordinator_may_not_send_the_takers_refund():
    coord, _chain, leg = _setup(role=SwapRole.MAKER, chain_kw={"finalized": 90})
    with pytest.raises(ValidationError, match="MAKER"):
        await coord.taker_refund_btc()
    assert leg.refunds == 0


def test_the_record_role_constant_is_what_the_coordinator_stamps():
    assert RecordRole.of(SwapRole.TAKER) is RecordRole.TAKER


async def test_a_held_observed_refund_sends_nothing_either():
    """Refunded already (by anyone) and held by a seen claim: there is nothing left to send."""
    coord, chain, leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1)
    chain.refund(85)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and leg.refunds == 0


# --------------------------------------------------------------------------- mutual_refund retries complete


def _count_asset_refunds(coord):
    calls = []

    async def refund_asset(_record):
        calls.append(1)
        return "ab" * 32

    coord.radiant_leg.refund_asset = refund_asset
    return calls


async def test_a_retry_after_the_counter_leg_refunded_completes_without_resending_it():
    """Folded into 5a: a retry after one leg had refunded never completed (the re-send of that leg
    failed, and any failure kept the record at BOTH_LOCKED). The counter leg is read from the chain."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.refund(85)  # the first attempt's counter refund, now final
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and leg.refunds == 0 and asset == [1]


async def test_a_retry_after_the_covenant_refunded_completes_without_resending_it():
    coord, _chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    asset = _count_asset_refunds(coord)

    async def counter_down(*_a, **_k):
        raise NetworkError("endpoint down")

    real_refund = leg.refund
    leg.refund = counter_down
    with pytest.raises(NetworkError, match="mutual refund incomplete"):
        await coord.mutual_refund()
    assert coord.record.asset_refund_txid == "ab" * 32 and asset == [1]
    assert coord.persisted[-1].asset_refund_txid == "ab" * 32  # durable before the retry
    leg.refund = real_refund
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and asset == [1] and leg.refunds == 1


async def test_a_verified_claim_stops_mutual_refund_before_the_covenant_is_refunded():
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.claim(70)
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.SECRET_REVEALED and leg.refunds == 0 and asset == []


async def test_HONEST_a_first_mutual_refund_sends_both_as_before():
    coord, _chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and leg.refunds == 1 and asset == [1]


class _ChainIO:
    """The Radiant chain reader: the covenant's funding tx depth, readable after it is spent."""

    def __init__(self, confs):
        self.confs = confs

    async def confirmations(self, txid):
        return self.confs


async def test_the_hold_lifts_once_t_rxd_matures_even_after_the_covenant_is_spent():
    """Review of 5a (MEDIUM-LOW): the hold read the covenant as an UNSPENT output, which raises
    once the maker CSV-refunds it, and an unreadable depth holds, so the hold never lifted."""
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90})
    coord.radiant_leg.asset_funded = False  # the covenant is spent: the unspent read raises
    coord.radiant_leg.chain_io = _ChainIO(int(coord.record.terms.t_rxd.value))
    chain.refund(85)
    assert (await coord.reconcile_counter_leg()).state is SwapState.ABORTED


async def test_HONEST_the_hold_stays_before_t_rxd_by_the_funding_depth():
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90})
    coord.radiant_leg.chain_io = _ChainIO(int(coord.record.terms.t_rxd.value) - 1)
    chain.refund(85)
    assert (await coord.reconcile_counter_leg()).state is SwapState.BTC_LOCKED


async def test_a_verified_claim_replaces_an_earlier_unverified_one_on_the_record():
    """The record must name the claim that VERIFIED, not a seen-only (possibly forged) log."""
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90})
    tx = chain.claim(70)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.SECRET_REVEALED and rec.counter_claim_tx == tx


async def test_a_recorded_seen_claim_is_not_overwritten_by_a_later_seen_one():
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1)
    coord.record = __import__("dataclasses").replace(coord.record, counter_claim_tx="0x" + "aa" * 32)
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.counter_claim_tx == "0x" + "aa" * 32


async def test_one_endpoint_on_a_value_bearing_chain_falls_through_to_the_send_in_the_refund(monkeypatch):
    """D4 in taker_refund_btc: a single-source terminal answer changes no state; the refund path
    then behaves as on an unknown answer (the leg's own checks decide; a settled contract reverts)."""
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    chain.refund(85)
    leg._rpc = FakeEvmEndpoint(chain)
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    await coord.taker_refund_btc()
    assert leg.refunds == 1 and coord.record.counter_disposition is None

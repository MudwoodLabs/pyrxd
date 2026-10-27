"""The watchtower reads an ETH counter leg's disposition with the coordinator's reader (#850 PR 10,
design §5.1, §5.2).

Before PR 10 the tower knew one thing about an ETH counter-leg contract: whether its PRIMARY endpoint
served a log the scan counted as a claim. It could not tell that our refund was final, that the
contract expired empty, or that the endpoints contradict each other, and a terminal ETH record an old
pyrxd ended on its refund's broadcast was never read again. Here the tower's keyless source runs the
shared reader (``pyrxd.eth_wallet.disposition.read_counter_disposition``) over every endpoint, with the
arguments the coordinator builds for the same record.

The chain is ``tests._fake_evm_chain``: one ``EthHtlc`` contract, honest or lying endpoints behind the
production ``MultiSourceEthRpc``. Every refusal here has its honest twin.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import importlib
import json
import os

import pytest

from pyrxd.eth_wallet.disposition import DispositionKind
from pyrxd.eth_wallet.events import CLAIMED_TOPIC0, REFUNDED_TOPIC0
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.gravity.eth_counter_disposition import eth_counter_disposition_kwargs
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.swap_state import (
    AbortReason,
    CounterDispositionRecord,
    RecordRole,
    SwapRecord,
    SwapState,
)
from pyrxd.gravity.watch.adapters import JsonDirRecordStore, is_legacy_candidate
from pyrxd.gravity.watch.decide import Intent, Observations, decide
from pyrxd.gravity.watch.eth_adapters import RpcEthChainSource
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.gravity.watch.reconciler import Reconciler
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.units import ChainHeight, Confirmations
from tests._fake_evm_chain import FakeEvmChain, FakeEvmEndpoint
from tests._source_hosts import distinct_host
from tests.test_swap_coordinator import _eth_finality_policy, _eth_terms
from tests.test_watch_pages_name_state_valid_steps import _named_steps, _state_guards

#: The module, not the ``decide`` function the package re-exports under the same name.
decide_mod = importlib.import_module("pyrxd.gravity.watch.decide")

SWAP = "e1"
#: The contract times out at this block; the fake chain's head is 100 and its finalized block 64, so a
#: refund mined at 55 is past the timeout and final, and a claim at 40 is before it and final.
TIMEOUT_BLOCK = 50
REFUND_BLOCK = 55
CLAIM_BLOCK = 40
_COVENANT = "ef" * 32 + ":0"
TIP = 1_000
#: The covenant is one block deep, so t_rxd (40 blocks for these terms) is far off.
COV_CONFS = 1
SAFETY = 6


def _policy():
    return _eth_finality_policy(window_s=768)


class _Endpoint(FakeEvmEndpoint):
    """A fake endpoint that also answers ``eth_getTransactionByHash`` (the detection scan reads the
    deploy transaction's block)."""

    async def get_transaction(self, tx_hash: str) -> dict:
        r = self.chain.receipts.get(tx_hash)
        if r is None:
            raise NetworkError(f"transaction {tx_hash} not found")
        return {"blockNumber": r["blockNumber"], "nonce": 0}


class _Rxd:
    def __init__(self, *, tip: int = TIP, cov_confs: int | None = COV_CONFS) -> None:
        self.tip = tip
        self.cov_confs = cov_confs

    async def tip_height(self) -> ChainHeight:
        return ChainHeight(self.tip)

    async def covenant_confirmations(self, outpoint: str) -> Confirmations | None:
        return None if self.cov_confs is None else Confirmations(self.cov_confs)


class _Pages:
    def __init__(self, *, fail: bool = False) -> None:
        self.got: list[tuple[str, object]] = []
        self.fail = fail

    async def handle(self, swap_id, decision) -> None:
        if self.fail:
            raise RuntimeError("channel down")
        self.got.append((swap_id, decision))


class _EthTower:
    """One ETH swap on one fake chain, watched by the production source, observer, store and reconciler."""

    def __init__(
        self,
        tmp_path,
        *,
        state: SwapState = SwapState.BTC_LOCKED,
        role: RecordRole | None = RecordRole.TAKER,
        endpoints: int = 3,
        endpoint_kw: list[dict] | None = None,
    ) -> None:
        p = os.urandom(32)
        self.chain = FakeEvmChain(preimage=p, timeout=0)
        self.chain.timeout = self.chain.ts(TIMEOUT_BLOCK)
        terms = _eth_terms(
            hashlock=hashlib.sha256(p).digest(), eth_timeout_unix_s=self.chain.timeout, now_unix_s=self.chain.ts(0)
        )
        kws = endpoint_kw or [{} for _ in range(endpoints)]
        self.endpoints = [_Endpoint(self.chain, **kw) for kw in kws]
        rpc = self.endpoints[0] if len(self.endpoints) == 1 else MultiSourceEthRpc(self.endpoints)
        self.dir = tmp_path / "records"
        self.dir.mkdir(parents=True, exist_ok=True)
        record = (
            SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=role)
            .with_counter_lock(self.chain.locator())
            .with_radiant_lock(_COVENANT, "51")
        )
        self.write(record.with_state(state))
        self.rxd = _Rxd()
        self.observer = ChainObserver(
            eth=RpcEthChainSource(rpc), rxd=self.rxd, clock=lambda: float(self.chain.ts(self.chain.head))
        )
        self.store = JsonDirRecordStore(self.dir)
        self.pages = _Pages()

    def write(self, record: SwapRecord) -> None:
        (self.dir / f"{SWAP}.json").write_text(json.dumps(record.to_dict()))

    def record(self) -> SwapRecord:
        return SwapRecord.from_dict(json.loads((self.dir / f"{SWAP}.json").read_text()))

    async def observe(self) -> Observations:
        return await self.observer.observe(SWAP, self.record())

    async def decide(self):
        return decide(record=self.record(), observations=await self.observe(), policy=_policy(), safety_window_blocks=6)

    def reconciler(self, alerter=None) -> Reconciler:
        return Reconciler(
            store=self.store,
            observer=self.observer,
            alerter=self.pages if alerter is None else alerter,
            policy=_policy(),
            safety_window_blocks=SAFETY,
        )

    def marker(self) -> dict | None:
        path = self.store.legacy_marker_path(SWAP)
        return json.loads(path.read_text()) if path.exists() else None


# --------------------------------------------------------------------------- the shared reader


def test_the_tower_and_the_coordinator_ask_the_reader_one_thing():
    """One builder for both (design §5.1, "shared reader"): a record with a recorded refund, a replaced
    one, an expiry anchor and a claim is read with all four, by either caller."""
    chain = FakeEvmChain(preimage=os.urandom(32), timeout=0)
    chain.timeout = chain.ts(TIMEOUT_BLOCK)
    terms = _eth_terms(hashlock=chain.hashlock, eth_timeout_unix_s=chain.timeout, now_unix_s=chain.ts(0))
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms).with_counter_lock(chain.locator())
    assert eth_counter_disposition_kwargs(rec) == {}
    rec = dataclasses.replace(
        rec,
        counter_refund_tx_hash="0x" + "a1" * 32,
        counter_refund_nonce=3,
        counter_refund_replaced_tx_hashes=("0x" + "a2" * 32,),
        counter_expiry_anchor="64:0x" + "b0" * 32,
        counter_claim_tx="0x" + "c1" * 32,
    )
    assert eth_counter_disposition_kwargs(rec) == {
        "recorded_refund_hashes": ("0x" + "a1" * 32, "0x" + "a2" * 32),
        "expiry_anchor": (64, "0x" + "b0" * 32),
        "recorded_claim_hashes": ("0x" + "c1" * 32,),
    }


async def test_a_refund_final_at_the_finalized_block_asks_to_reconcile(tmp_path):
    w = _EthTower(tmp_path)
    refund = w.chain.refund(REFUND_BLOCK)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.REFUNDED
    assert obs.eth_disposition_tx == refund
    assert obs.eth_single_source is False
    d = await w.decide()
    assert d.intent is Intent.RECONCILE
    assert d.recommended_action == "reconcile_counter_leg"
    assert refund in d.reason


async def test_a_both_locked_record_with_a_final_refund_is_told_to_run_mutual_refund(tmp_path):
    w = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED)
    w.chain.refund(REFUND_BLOCK)
    d = await w.decide()
    assert d.intent is Intent.RECONCILE
    assert d.recommended_action == "mutual_refund"


async def test_one_endpoints_final_refund_stops_no_page(tmp_path):
    """Design §5.1: "a single endpoint's Refunded() never stops a page". One endpoint reads the same
    refund, and the refund page past the deadline stays up, marked low-corroboration."""
    w = _EthTower(tmp_path, endpoints=1)
    w.chain.refund(REFUND_BLOCK)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.REFUNDED and obs.eth_single_source is True
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert d.situation == decide_mod.SITUATION_ETH_REFUND_TIMEOUT_PASSED
    assert d.low_corroboration is True


async def test_an_unsettled_contract_past_its_timeout_still_pages_the_refund(tmp_path):
    """The honest path the reader must not change: nothing settled, the deadline passed."""
    w = _EthTower(tmp_path)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.F_EXPIRED
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert d.situation == decide_mod.SITUATION_ETH_REFUND_TIMEOUT_PASSED
    assert obs.eth_single_source is False


async def test_a_claim_the_primary_hides_is_seen_through_the_union_read(tmp_path):
    """The detection scan reads the PRIMARY endpoint only (``MultiSourceEthRpc.get_logs``). A primary
    that hides the Claimed log used to leave the tower blind; the union read nominates it from the
    others, and the claim race pages, naming the step a BTC_LOCKED record can run first."""
    w = _EthTower(tmp_path, endpoint_kw=[{"hide_claimed": True}, {}, {}])
    claim = w.chain.claim(CLAIM_BLOCK)
    status = await w.observer._eth.claim_status(w.chain.locator().contract_address, w.chain.deploy_tx)
    assert status.claimed is False  # the scan alone misses it
    obs = await w.observe()
    assert obs.eth_claim_detected is True and obs.eth_claim_seen is True
    assert obs.eth_disposition is DispositionKind.CLAIMED and obs.eth_disposition_tx == claim
    assert obs.eth_claim_finality is CounterClaimState.FINAL
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM
    assert d.situation == decide_mod.SITUATION_CLAIM_RACE
    assert d.recommended_action == "reconcile_counter_leg, then taker_scrape_and_claim_asset"


async def test_a_refund_no_endpoint_logs_is_found_by_the_hash_on_record(tmp_path):
    """The tower nominates the refund the record kept, as the coordinator does (one builder): with no
    endpoint serving its log, the hash on record is the only thing that names it."""
    w = _EthTower(tmp_path, endpoint_kw=[{"hide_all_logs": True}] * 3)
    refund = w.chain.refund(REFUND_BLOCK)
    w.write(dataclasses.replace(w.record(), counter_refund_tx_hash=refund, counter_refund_nonce=0))
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.REFUNDED and obs.eth_disposition_tx == refund
    assert (await w.decide()).intent is Intent.RECONCILE


async def test_the_verdict_is_read_for_the_verified_claim_not_the_scans_odd_log(tmp_path):
    """The primary hides the Claimed log and serves an odd one, which the scan (primary only) takes for
    the claim. A refund and the claim both verify, so the answer is UNKNOWN, not CLAIMED: the finality
    verdict must be read for the claim the reader verified, not for the odd log's transaction."""
    odd = {
        "address": "0x" + "c0" * 20,
        "topics": ["0x" + "ee" * 32],
        "data": "0x",
        "transactionHash": "0x" + "e1" * 32,
        "blockNumber": 45,
    }
    w = _EthTower(tmp_path, endpoint_kw=[{"hide_claimed": True, "extra_logs": (odd,)}, {}, {}])
    w.chain.claim(CLAIM_BLOCK)
    w.chain.force_receipt(REFUND_BLOCK, topic0=REFUNDED_TOPIC0, label="refund")
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.UNKNOWN and obs.eth_claim_seen is True
    assert obs.eth_claim_finality is CounterClaimState.FINAL
    assert (await w.decide()).situation == decide_mod.SITUATION_CLAIM_RACE


async def test_a_claim_the_scan_sees_still_pages_without_the_reader(tmp_path):
    """The honest twin, through a source with no reader: the scan's claim is still the trigger."""

    class _NoReader:
        def __init__(self, inner):
            self._inner = inner

        async def claim_status(self, *a):
            return await self._inner.claim_status(*a)

        async def claim_finality_verdict(self, tx):
            return await self._inner.claim_finality_verdict(tx)

    w = _EthTower(tmp_path)
    w.observer._eth = _NoReader(w.observer._eth)
    w.chain.claim(CLAIM_BLOCK)
    obs = await w.observe()
    assert obs.eth_disposition is None and obs.eth_claim_detected is True
    assert (await w.decide()).intent is Intent.PAGE_CLAIM


async def test_a_settled_contract_the_reader_cannot_explain_pages_investigate(tmp_path):
    """Settled at the finalized block with no refund or claim that verifies: an UNKNOWN that read the
    contract settled. Nothing proves p is not public, so it pages, never silently waits."""
    w = _EthTower(tmp_path)
    w.chain.settled_at = REFUND_BLOCK
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.UNKNOWN and obs.eth_settled_at_finalized is True
    d = await w.decide()
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.situation == decide_mod.SITUATION_ETH_DISPOSITION_CONTRADICTION
    assert d.recommended_action.startswith("investigate")


async def test_an_unreadable_chain_changes_nothing(tmp_path):
    """An UNKNOWN from a failed read is not a contradiction: the rules after it page as before."""
    w = _EthTower(tmp_path, endpoint_kw=[{}, {"tip_reads_fail": True}, {"tip_reads_fail": True}])
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.UNKNOWN and obs.eth_settled_at_finalized is False
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert d.situation == decide_mod.SITUATION_ETH_REFUND_TIMEOUT_PASSED


async def test_a_claimed_log_beside_our_final_refund_pages_the_covenant_claim(tmp_path):
    """D14: one endpoint serves a Claimed log that opens H (p is public wherever it came from), and
    our refund is final. Not a claim race (no claim can be mined), but the covenant is still ours to
    claim before t_rxd."""
    w = _EthTower(tmp_path)
    refund = w.chain.refund(REFUND_BLOCK)
    forged = {
        "address": w.chain.locator().contract_address,
        "topics": [CLAIMED_TOPIC0],
        "data": "0x" + w.chain.preimage.hex(),
        "transactionHash": "0x" + "d1" * 32,
        "blockNumber": 30,
    }
    w.endpoints[1].extra_logs = (forged,)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.REFUNDED and obs.eth_claim_seen is True
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM
    assert d.situation == decide_mod.SITUATION_CLAIM_SEEN_P_PUBLIC
    assert refund in d.reason and "build-claim" in d.recommended_action


async def test_an_odd_log_beside_our_final_refund_pages_investigate_not_a_race(tmp_path):
    """The scan counts an unrecognised event on our contract as a claim (it fails toward paging). Beside
    a final refund and no claim that opens H, the tower says it cannot tell, and names no claim step."""
    w = _EthTower(tmp_path)
    w.chain.refund(REFUND_BLOCK)
    odd = {
        "address": w.chain.locator().contract_address,
        "topics": ["0x" + "ee" * 32],
        "data": "0x",
        "transactionHash": "0x" + "e1" * 32,
        "blockNumber": 60,
    }
    w.endpoints[0].extra_logs = (odd,)
    obs = await w.observe()
    assert obs.eth_claim_detected is True and obs.eth_claim_seen is False
    d = await w.decide()
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.situation == decide_mod.SITUATION_ETH_DISCOVERY_DISAGREES
    assert d.recommended_action.startswith("investigate")


async def test_a_makers_record_with_the_takers_final_refund_pages_its_covenant(tmp_path):
    w = _EthTower(tmp_path, role=RecordRole.MAKER, state=SwapState.BOTH_LOCKED)
    w.chain.refund(REFUND_BLOCK)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert d.situation == decide_mod.SITUATION_MAKER_REFUND_AFTER_TAKER_REFUND


# --------------------------------------------------------------------------- pure decide: the rest of the table


def _record(state: SwapState, *, role: RecordRole | None = RecordRole.TAKER, **kw) -> SwapRecord:
    chain = FakeEvmChain(preimage=os.urandom(32), timeout=0)
    chain.timeout = chain.ts(TIMEOUT_BLOCK)
    terms = _eth_terms(hashlock=chain.hashlock, eth_timeout_unix_s=chain.timeout, now_unix_s=chain.ts(0))
    rec = (
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=role)
        .with_counter_lock(chain.locator())
        .with_radiant_lock(_COVENANT, "51")
        .with_state(state)
    )
    return dataclasses.replace(rec, **kw)


def _obs(**kw) -> Observations:
    base = {
        "maker_has_claimed_btc": False,
        "now_rxd_height": ChainHeight(TIP),
        "asset_locked_at_height": ChainHeight(TIP),
        "now_unix_s": 2_000_000_000,
    }
    return Observations(**{**base, **kw})


def _d(record, obs):
    return decide(record=record, observations=obs, policy=_policy(), safety_window_blocks=SAFETY)


def test_an_expired_empty_token_contract_pages_the_push_nonce_close():
    rec = _record(SwapState.BTC_LOCKED)
    d = _d(rec, _obs(eth_disposition=DispositionKind.EXPIRED_EMPTY_OPEN, eth_nonce_at_finalized=7))
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "close_push_nonce"
    assert d.situation == decide_mod.SITUATION_ETH_EXPIRED_EMPTY_OPEN
    assert "nonce 7" in d.reason


def test_a_closed_empty_contract_pages_the_step_that_ends_the_record():
    d = _d(_record(SwapState.BTC_LOCKED), _obs(eth_disposition=DispositionKind.EXPIRED_EMPTY_CLOSED))
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "taker_refund_btc"
    assert d.situation == decide_mod.SITUATION_ETH_EXPIRED_EMPTY_CLOSED


@pytest.mark.parametrize("kind", [DispositionKind.EXPIRED_EMPTY_OPEN, DispositionKind.EXPIRED_EMPTY_CLOSED])
def test_one_endpoints_empty_contract_replaces_no_refund_page(kind):
    """The empty-contract pages replace the refund page, so one endpoint's "it holds nothing" may not."""
    d = _d(_record(SwapState.BTC_LOCKED), _obs(eth_disposition=kind, eth_single_source=True))
    assert d.situation == decide_mod.SITUATION_ETH_REFUND_TIMEOUT_PASSED
    assert d.recommended_action == "taker_refund_btc" and d.low_corroboration is True


@pytest.mark.parametrize("kind", [DispositionKind.EXPIRED_EMPTY_OPEN, DispositionKind.EXPIRED_EMPTY_CLOSED])
def test_an_empty_contract_at_both_locked_pages_the_abandon(kind):
    d = _d(_record(SwapState.BOTH_LOCKED), _obs(eth_disposition=kind))
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action.startswith("abandon_counter_leg")
    assert d.situation == decide_mod.SITUATION_ETH_EXPIRED_EMPTY_BOTH_LOCKED
    # With no role the abandon leaves the covenant, and the page says so.
    d_none = _d(_record(SwapState.BOTH_LOCKED, role=RecordRole.NONE), _obs(eth_disposition=kind))
    assert "covenant" in d_none.reason


@pytest.mark.parametrize("role", [RecordRole.MAKER, RecordRole.TAKER, RecordRole.NONE])
def test_an_empty_contract_after_a_params_mismatch_pages_the_covenant_then_the_abandon(role):
    d = _d(_record(SwapState.PARAMS_MISMATCH, role=role), _obs(eth_disposition=DispositionKind.EXPIRED_EMPTY_CLOSED))
    assert d.situation == decide_mod.SITUATION_ETH_EXPIRED_EMPTY_MISMATCH
    assert "abandon_counter_leg" in d.recommended_action and "CSV" in d.recommended_action


def test_a_claim_after_a_params_mismatch_pages_the_gated_exit_not_investigate():
    """§3.2: no edge into the taker's claim flow from PARAMS_MISMATCH. Before PR 10 this paged a claim
    race whose action could only be "investigate"."""
    obs = _obs(eth_claim_detected=True, eth_claim_finality=CounterClaimState.FINAL)
    d = _d(_record(SwapState.PARAMS_MISMATCH, role=RecordRole.MAKER), obs)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.situation == decide_mod.SITUATION_ETH_CLAIMED_AFTER_MISMATCH
    assert "abandon_counter_leg" in d.recommended_action


def test_a_claim_on_a_both_locked_record_is_still_the_claim_race():
    """The honest twin of the params-mismatch page: a BOTH_LOCKED record keeps its claim race."""
    obs = _obs(eth_claim_detected=True, eth_claim_finality=CounterClaimState.FINAL)
    d = _d(_record(SwapState.BOTH_LOCKED), obs)
    assert d.situation == decide_mod.SITUATION_CLAIM_RACE


def test_a_claim_on_record_beside_our_final_refund_pages_the_covenant_claim():
    rec = _record(SwapState.BTC_LOCKED, counter_claim_tx="0x" + "c1" * 32)
    d = _d(rec, _obs(eth_disposition=DispositionKind.REFUNDED, eth_disposition_tx="0x" + "a1" * 32))
    assert d.intent is Intent.PAGE_CLAIM
    assert d.situation == decide_mod.SITUATION_CLAIM_SEEN_P_PUBLIC


def test_settled_at_the_tip_stops_no_page():
    """SETTLED_UNFINAL is read when ANY endpoint sees the contract settled at its tip: it must not
    silence the refund page."""
    d = _d(_record(SwapState.BTC_LOCKED), _obs(eth_disposition=DispositionKind.SETTLED_UNFINAL))
    assert d.intent is Intent.PAGE_REFUND


@pytest.mark.parametrize(
    "kw",
    [
        {"eth_claim_seen": True},
        {"eth_single_source": True},
        {"eth_disposition_reason": "x"},
        {"eth_nonce_at_finalized": 1},
        {"eth_disposition": DispositionKind.REFUNDED, "eth_settled_at_finalized": True},
        {"eth_disposition": DispositionKind.CLAIMED},
        {"eth_disposition": DispositionKind.REFUNDED, "eth_claim_seen": True},
        {"eth_disposition": DispositionKind.REFUNDED, "eth_disposition_tx": "ab" * 32},
        {"eth_disposition": DispositionKind.REFUNDED, "eth_nonce_at_finalized": -1},
    ],
)
def test_observations_refuse_incoherent_eth_fields(kw):
    with pytest.raises(ValidationError):
        _obs(**kw)


def test_observations_accept_a_coherent_eth_read():
    _obs(
        eth_disposition=DispositionKind.CLAIMED,
        eth_claim_detected=True,
        eth_claim_seen=True,
        eth_disposition_tx="0x" + "ab" * 32,
        eth_disposition_reason="a claim verifies",
    )


_TABLE_SHAPES = [
    {"eth_disposition": DispositionKind.REFUNDED, "eth_disposition_tx": "0x" + "a1" * 32},
    {
        "eth_disposition": DispositionKind.REFUNDED,
        "eth_claim_seen": True,
        "eth_claim_detected": True,
        "eth_claim_finality": CounterClaimState.FINAL,
    },
    {"eth_disposition": DispositionKind.REFUNDED, "eth_claim_detected": True, "eth_claim_finality": None},
    {"eth_disposition": DispositionKind.UNKNOWN, "eth_settled_at_finalized": True},
    {"eth_disposition": DispositionKind.EXPIRED_EMPTY_OPEN},
    {"eth_disposition": DispositionKind.EXPIRED_EMPTY_CLOSED},
    {
        "eth_disposition": DispositionKind.CLAIMED,
        "eth_claim_detected": True,
        "eth_claim_finality": CounterClaimState.FINAL,
    },
]


@pytest.mark.parametrize("role", [RecordRole.TAKER, RecordRole.NONE, RecordRole.MAKER, None])
@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH, SwapState.BOTH_LOCKED])
def test_every_eth_table_page_names_a_step_its_record_can_run(state, role):
    """The #580 sweep over the new pages: the first coordinator step a page names accepts the record's
    state, read from the coordinator's own guards."""
    guards = _state_guards()
    for kw in _TABLE_SHAPES:
        d = _d(_record(state, role=role), _obs(**kw))
        steps = _named_steps(d.recommended_action or "", guards)
        if steps:
            assert state in guards[steps[0]], (state, role, kw, d.recommended_action)


# --------------------------------------------------------------------------- the legacy net (D9) for ETH


def _legacy(tmp_path, *, state=SwapState.ABORTED, **kw) -> _EthTower:
    w = _EthTower(tmp_path, role=None, **kw)
    w.write(w.record().with_state(state))
    return w


async def test_a_legacy_terminal_eth_record_is_listed_for_the_net(tmp_path):
    w = _legacy(tmp_path)
    assert await w.store.list_active() == []
    assert [sid for sid, _r in w.store.legacy] == [SWAP]


@pytest.mark.parametrize("change", ["maker", "has_disposition", "abandoned", "never_funded", "completed"])
def test_eth_records_the_net_leaves_alone(tmp_path, change):
    w = _legacy(tmp_path)
    rec = w.record()
    assert is_legacy_candidate(rec)
    if change == "maker":
        rec = dataclasses.replace(rec, role=RecordRole.MAKER)
    elif change == "has_disposition":
        rec = dataclasses.replace(
            rec,
            abort_reason=AbortReason.COUNTER_LEG_REFUNDED,
            counter_disposition=CounterDispositionRecord(
                kind="refunded",
                block_number=64,
                block_hash="0x" + "ab" * 32,
                tx_hash="0x" + "cd" * 32,
                sources=("a", "b"),
                single_source=False,
            ),
        )
    elif change == "completed":
        rec = rec.with_state(SwapState.COMPLETED)
    else:
        rec = dataclasses.replace(rec)
        object.__setattr__(
            rec,
            "abort_reason",
            AbortReason.OPERATOR_ABANDONED if change == "abandoned" else AbortReason.TAKER_NEVER_FUNDS,
        )
    assert not is_legacy_candidate(rec)


async def test_a_legacy_refund_that_never_landed_pages_and_is_never_marked(tmp_path):
    w = _legacy(tmp_path)
    for _ in range(2):
        [res] = await w.reconciler().tick()
        assert res.legacy is True
        assert res.decision.intent is Intent.PAGE_REFUND
        assert res.decision.situation == decide_mod.SITUATION_LEGACY_ETH_UNSETTLED
        assert "refund()" in res.decision.recommended_action
    assert w.marker() is None


async def test_a_legacy_refund_final_on_every_endpoint_agrees_and_is_marked(tmp_path):
    w = _legacy(tmp_path)
    refund = w.chain.refund(REFUND_BLOCK)
    [res] = await w.reconciler().tick()
    assert res.decision.intent is Intent.WATCH
    marker = w.marker()
    assert marker["verdict"] == "refunded"
    assert marker["evidence"]["eth_disposition"] == "refunded"
    assert marker["evidence"]["eth_disposition_tx"] == refund
    await w.store.list_active()
    assert w.store.legacy == []  # never read again


async def test_one_endpoints_legacy_refund_is_read_again(tmp_path):
    w = _legacy(tmp_path, endpoints=1)
    w.chain.refund(REFUND_BLOCK)
    [res] = await w.reconciler().tick()
    assert res.decision.intent is Intent.WATCH
    assert w.marker() is None


async def test_a_legacy_refund_that_lost_to_a_claim_pages_the_covenant_claim(tmp_path):
    w = _legacy(tmp_path)
    w.chain.claim(CLAIM_BLOCK)
    [res] = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_CLAIM
    assert res.decision.situation == decide_mod.SITUATION_CLAIM_SEEN_P_PUBLIC
    assert "build-claim" in res.decision.recommended_action
    # t_rxd has not matured, so the page is not conclusive yet.
    assert w.marker() is None


async def test_the_legacy_claim_page_is_marked_once_delivered_after_t_rxd(tmp_path):
    w = _legacy(tmp_path)
    w.chain.claim(CLAIM_BLOCK)
    w.rxd.tip = TIP + 100  # covenant 1 deep at TIP, t_rxd 40: matured
    w.rxd.cov_confs = 101
    failing = _Pages(fail=True)
    await w.reconciler(alerter=failing).tick()
    assert w.marker() is None  # not delivered, not marked
    await w.reconciler().tick()
    assert w.marker()["verdict"] == "claimed"


async def test_a_legacy_eth_record_never_reaches_the_executor(tmp_path):
    w = _legacy(tmp_path)
    asked: list[str] = []

    class _Spy:
        async def execute(self, swap_id, record, decision):
            asked.append(swap_id)

    rec = Reconciler(
        store=w.store,
        observer=w.observer,
        alerter=w.pages,
        policy=_policy(),
        safety_window_blocks=SAFETY,
        executor=_Spy(),
    )
    await rec.tick()
    assert asked == []


# --------------------------------------------------------------------------- the shell: --eth-rpc-url repeats


class _FakeEthRpc:
    def __init__(self, url, *, expected_chain_id):
        self.url = url
        self.expected_chain_id = expected_chain_id
        self.source_key = distinct_host()
        self.closed = False

    async def assert_chain(self):
        return None

    async def close(self):
        self.closed = True


async def test_a_repeated_eth_rpc_url_builds_a_multi_source_reader(monkeypatch):
    from pyrxd.eth_wallet import rpc as rpc_mod
    from pyrxd.gravity.watch import run

    monkeypatch.setattr(rpc_mod, "EthRpc", _FakeEthRpc)
    parser = run._build_parser() if hasattr(run, "_build_parser") else None
    if parser is not None:
        ns = parser.parse_known_args(
            ["--records-dir", "x", "--eth-rpc-url", "https://a.test/", "--eth-rpc-url", "https://b.test/"]
        )[0]
        assert ns.eth_rpc_url == ["https://a.test/", "https://b.test/"]
    args = argparse.Namespace(eth_rpc_url=["https://a.test/", "https://b.test/"], eth_chain_id=11155111)
    async with contextlib.AsyncExitStack() as stack:
        source = await run._build_eth_source(args, stack)
        assert isinstance(source._rpc, MultiSourceEthRpc)
        assert [s.url for s in source._rpc.sources] == ["https://a.test/", "https://b.test/"]
    one = argparse.Namespace(eth_rpc_url=["https://a.test/"], eth_chain_id=11155111)
    async with contextlib.AsyncExitStack() as stack:
        assert isinstance((await run._build_eth_source(one, stack))._rpc, _FakeEthRpc)
    assert await run._build_eth_source(argparse.Namespace(eth_rpc_url=None, eth_chain_id=None), stack) is None

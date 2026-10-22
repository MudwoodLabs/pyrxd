"""The coordinator acts on what the chain shows about the ETH counter leg (#850 PRs 5a and 5b).

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
from tests._fake_evm_chain import _tx_hash as _fake_tx_hash
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


def refund_label(n: int) -> str:
    """The label the fake chain hashes for our n-th refund, so ``chain.refund(block, label=...)``
    mines exactly the transaction the leg signed."""
    return f"our-refund-{n}"


class _ChainLeg(FakeEthLeg):
    """FakeEthLeg whose disposition is read by the REAL reader from the fake chain. Its refund signs
    a hash the fake chain can later mine (:func:`refund_label`), reports it through ``on_signed``
    before "broadcasting", and leaves it pending; ``refund_progress`` reads the fake chain."""

    def __init__(self, *a, rpc, **k):
        super().__init__(*a, **k)
        self._rpc = rpc
        self.refunds = 0
        self.preflight_refusals = 0
        self.signed: list[tuple[str, int, object]] = []
        self.undelivered: set[str] = set()
        self.fees: dict[str, dict[str, int]] = {}
        self.fail_broadcast = False
        self.next_nonce = 7
        self.dropped: set[str] = set()
        self.nonce_taken: set[str] = set()
        self.out_of_gas: set[str] = set()
        self.reverted: set[str] = set()
        self.estimate = 60_000
        self.revert_reason = None
        self.gas_limit = 150_000

    async def counter_disposition(self, locator, **kwargs):
        return await read_counter_disposition(self._rpc, locator, **kwargs)

    async def refund(self, locator, timeout=None, *, on_signed=None, replace=None):
        # The real leg's checks before it signs (#850 PR 6): a refund before the timeout is a
        # retryable "not yet mature", and the eth_call preflight reverts AlreadySettled once the
        # contract is settled at the tip. Nothing is signed or counted either way.
        if self.chain.ts(self.chain.head) < self.chain.timeout:
            raise NetworkError("ETH HTLC refund is not yet mature")
        if self.chain.settled_at is not None and self.chain.settled_at <= self.chain.head:
            self.preflight_refusals += 1
            raise ValidationError("tx would revert (preflight eth_call): AlreadySettled()")
        self.refunds += 1
        tx = _fake_tx_hash(refund_label(self.refunds))
        nonce = replace.nonce if replace is not None else self.next_nonce
        if replace is None:
            self.next_nonce += 1
        if on_signed is not None:
            await on_signed(tx, nonce)
        self.signed.append((tx, nonce, replace))
        base = {"maxFeePerGas": 100, "maxPriorityFeePerGas": 2}
        self.fees[tx] = (
            {k: v * 113 // 100 + 1 for k, v in replace.previous_fees.items()} if replace is not None else base
        )
        if self.fail_broadcast:
            self.undelivered.add(tx)
            raise NetworkError("eth_sendRawTransaction failed: replacement transaction underpriced")
        return tx

    async def refund_progress(self, tx_hash, nonce, *, earlier=()):
        """Reads the fake chain. A refund is "held" by the node unless it is in ``undelivered`` (it
        never reached the node) or was displaced by a later one we sent at the same nonce."""
        from pyrxd.eth_wallet.htlc_leg import RefundProgress

        if tx_hash in self.out_of_gas:
            return RefundProgress("out_of_gas", gas_limit=self.gas_limit)
        if tx_hash in self.reverted:
            return RefundProgress("reverted", gas_limit=self.gas_limit)
        if tx_hash in self.nonce_taken:
            return RefundProgress("nonce_taken")
        if tx_hash in self.dropped:
            return RefundProgress("dropped")
        for h in (tx_hash, *earlier):
            receipt = self.chain.receipts.get(h)
            if receipt is not None and receipt["status"] == 1:
                return RefundProgress("mined")
        for h in (tx_hash, *earlier):
            if h not in self.undelivered and h in self.fees:
                return RefundProgress("pending", fee_fields=dict(self.fees[h]))
        return RefundProgress("pending", fee_fields=None)

    async def refund_estimate(self, locator):
        return self.estimate

    async def refund_revert_reason(self, locator):
        return self.revert_reason


def _setup(*, state=SwapState.BTC_LOCKED, role=SwapRole.TAKER, endpoints=None, chain_kw=None, confs=None, pin=True):
    p = os.urandom(32)
    chain = FakeEvmChain(preimage=p, timeout=0, **(chain_kw or {}))
    chain.timeout = chain.ts(TIMEOUT_BLOCK)
    terms = _eth_terms(hashlock=hashlib.sha256(p).digest(), eth_timeout_unix_s=chain.timeout, now_unix_s=chain.ts(0))
    rpc = MultiSourceEthRpc(endpoints(chain) if endpoints else [FakeEvmEndpoint(chain) for _ in range(3)])
    leg = _ChainLeg(preimage=p, verdict=_final(), rpc=rpc)
    leg.chain = chain
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


async def test_both_locked_claimed_goes_to_secret_revealed():
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    chain.claim(70)
    assert (await coord.reconcile_counter_leg()).state is SwapState.SECRET_REVEALED


@pytest.mark.parametrize(
    ("role", "lands_in"),
    [(SwapRole.TAKER, SwapState.MUTUAL_REFUND), (None, SwapState.BOTH_LOCKED), (SwapRole.MAKER, SwapState.BOTH_LOCKED)],
)
async def test_both_locked_refunded_is_a_takers_mutual_refund_only(role, lands_in):
    """#850 PR 6: a taker's MUTUAL_REFUND means its counter leg is refunded at F (the covenant is
    the maker's). A single operator's also needs the covenant refunded, which reconcile never sends."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=role, chain_kw={"finalized": 90})
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is lands_in and rec.counter_disposition.kind == "refunded"
    assert leg.refunds == 0 and coord.radiant_leg.refunded is False


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


async def test_HONEST_an_expired_unsettled_contract_is_refunded_and_the_record_waits_for_the_chain():
    """5b: our refund is sent and RECORDED; the record no longer advances on our broadcast."""
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 1 and rec.state is SwapState.BTC_LOCKED
    assert (rec.counter_refund_tx_hash, rec.counter_refund_nonce) == leg.signed[0][:2]


async def test_HONEST_an_unknown_disposition_still_sends_as_before():
    def throttled(chain):
        return [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]

    coord, _chain, leg = _setup(endpoints=throttled, chain_kw={"finalized": 90})
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 1 and rec.state is SwapState.BTC_LOCKED and rec.counter_refund_tx_hash is not None


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


async def test_a_retry_after_the_covenant_refund_failed_completes_without_resending_either():
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.refund(85)
    calls = []

    async def immature(_record):
        calls.append(1)
        raise NetworkError("covenant CSV refund is not yet mature")

    coord.radiant_leg.refund_asset = immature
    with pytest.raises(NetworkError, match="mutual refund incomplete"):
        await coord.mutual_refund()
    assert coord.record.state is SwapState.BOTH_LOCKED and calls == [1] and leg.refunds == 0
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and asset == [1] and leg.refunds == 0
    assert coord.persisted[-1].asset_refund_txid == "ab" * 32


async def test_a_verified_claim_stops_mutual_refund_before_the_covenant_is_refunded():
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.claim(70)
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.SECRET_REVEALED and leg.refunds == 0 and asset == []


async def test_HONEST_a_single_operator_refunds_the_counter_leg_then_the_covenant():
    """#850 PR 6 (design §3.3 step 4): the covenant refund goes out only once the counter leg is
    refunded at the finalized block. The first call sends the counter refund and waits."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.BOTH_LOCKED and leg.refunds == 1 and asset == []
    assert rec.counter_refund_tx_hash == _fake_tx_hash(refund_label(1))
    chain.refund(85, label=refund_label(1))  # our refund mines, and is final at 90
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and leg.refunds == 1 and asset == [1]
    assert rec.counter_disposition.tx_hash == rec.counter_refund_tx_hash


async def test_a_makers_mutual_refund_on_an_eth_leg_is_refused_before_it_reads_or_sends():
    """#850 PR 6: the maker's own step is maybe_refund_asset_on_maker_stall. Round 2 of the 5a
    review found the maker taking both legs after its own claim; now nothing is read or sent."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=SwapRole.MAKER, chain_kw={"finalized": 90})
    chain.claim(70)
    asset = _count_asset_refunds(coord)
    with pytest.raises(ValidationError, match="not the maker's step"):
        await coord.mutual_refund()
    assert asset == [] and leg.refunds == 0 and coord.record.state is SwapState.BOTH_LOCKED


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
    # An earlier read recorded the seen-only claim.
    coord.record = __import__("dataclasses").replace(coord.record, counter_claim_tx="0x" + "dd" * 32)
    tx = chain.claim(70)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.SECRET_REVEALED and rec.counter_claim_tx == tx


async def test_a_recorded_seen_claim_is_not_overwritten_by_a_later_seen_one():
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1)
    coord.record = __import__("dataclasses").replace(coord.record, counter_claim_tx="0x" + "aa" * 32)
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.counter_claim_tx == "0x" + "aa" * 32


async def test_one_endpoint_on_a_value_bearing_chain_raises_in_the_refund_and_sends_nothing(monkeypatch):
    """D4 in taker_refund_btc: a single-source terminal answer changes no state and sends nothing. 5a
    fell through to a send (which reverts on a settled contract); with 5b's follow path a recorded
    refund then waited for a quorum one endpoint can never give, silently (review of 5b, MEDIUM)."""
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    chain.refund(85)
    leg._rpc = FakeEvmEndpoint(chain)
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    with pytest.raises(NetworkError, match="ONE endpoint"):
        await coord.taker_refund_btc()
    assert leg.refunds == 0 and coord.record.counter_disposition is None


@pytest.mark.parametrize(("confs", "resent"), [(0, True), (1, False)])
async def test_a_recorded_covenant_refund_that_never_landed_is_sent_again(confs, resent):
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.refund(85)  # the counter leg is refunded at F, so the covenant step runs
    asset = _count_asset_refunds(coord)
    coord.record = __import__("dataclasses").replace(coord.record, asset_refund_txid="cd" * 32)
    coord.radiant_leg.chain_io = _ChainIO(confs)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and asset == ([1] if resent else [])


async def test_an_unreadable_recorded_covenant_refund_neither_skips_nor_resends():
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.refund(85)  # the counter leg is refunded at F, so the covenant step runs
    asset = _count_asset_refunds(coord)
    coord.record = __import__("dataclasses").replace(coord.record, asset_refund_txid="cd" * 32)

    class _Down:
        async def confirmations(self, txid):
            raise NetworkError("radiant server down")

    coord.radiant_leg.chain_io = _Down()
    with pytest.raises(NetworkError, match="radiant server down"):
        await coord.mutual_refund()
    assert asset == [] and coord.record.state is SwapState.BOTH_LOCKED


class _ForgetfulChainIO:
    """A Radiant node that has FORGOTTEN our covenant refund (an error, as for an outage), and a
    UTXO-set read that answers whether the covenant is still unspent."""

    def __init__(self, unspent):
        self.unspent = unspent

    async def confirmations(self, txid):
        raise NetworkError("No such mempool or blockchain transaction")

    async def covenant_outpoint_unspent(self, spk, outpoint):
        if isinstance(self.unspent, Exception):
            raise self.unspent
        return self.unspent


@pytest.mark.parametrize(("unspent", "resent"), [(True, True), (False, False)])
async def test_a_forgotten_covenant_refund_is_judged_by_the_covenant_itself(unspent, resent):
    """Mythos review of #893 (MEDIUM): a dropped refund the node no longer knows answered like an
    outage, so every retry raised and the covenant was never refunded in-band. The covenant's own
    UTXO decides: still unspent means our refund did not land."""
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.refund(85)  # the counter leg is refunded at F, so the covenant step runs
    asset = _count_asset_refunds(coord)
    coord.record = __import__("dataclasses").replace(coord.record, asset_refund_txid="cd" * 32)
    coord.radiant_leg.chain_io = _ForgetfulChainIO(unspent)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and asset == ([1] if resent else [])


async def test_a_forgotten_covenant_refund_with_an_unreadable_covenant_raises():
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"finalized": 90})
    chain.refund(85)  # the counter leg is refunded at F, so the covenant step runs
    asset = _count_asset_refunds(coord)
    coord.record = __import__("dataclasses").replace(coord.record, asset_refund_txid="cd" * 32)
    coord.radiant_leg.chain_io = _ForgetfulChainIO(NetworkError("radiant server down"))
    with pytest.raises(NetworkError, match="radiant server down"):
        await coord.mutual_refund()
    assert asset == [] and coord.record.state is SwapState.BOTH_LOCKED


@pytest.mark.parametrize("role", [None, SwapRole.TAKER])
async def test_mutual_refund_sends_nothing_while_a_claim_is_settled_at_the_tip(role):
    """Mythos review of #893 (LOW): only a claim verified at F stopped the covenant refund. With the
    claim mined above F the covenant went out while p was public. Since PR 6 the record waits."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=role, chain_kw={"head": 79, "finalized": 60})
    chain.claim(75)
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert asset == [] and leg.refunds == 0 and rec.state is SwapState.BOTH_LOCKED


@pytest.mark.parametrize("role", [None, SwapRole.TAKER])
async def test_mutual_refund_does_not_refund_the_covenant_or_end_while_a_seen_claim_holds(role):
    """D14 / N1 on BOTH_LOCKED (#850 PR 6): refunded at F, but a Claimed log opens H before t_rxd.
    Neither role's record goes terminal, and the covenant is not refunded: p may be public."""
    coord, chain, leg = _setup(
        state=SwapState.BOTH_LOCKED, role=role, endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1
    )
    chain.refund(85)
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert asset == [] and leg.refunds == 0 and rec.state is SwapState.BOTH_LOCKED
    assert rec.counter_claim_tx == "0x" + "dd" * 32 and rec.counter_disposition.kind == "refunded"


@pytest.mark.parametrize("role", [None, SwapRole.TAKER])
async def test_HONEST_once_t_rxd_has_matured_the_held_mutual_refund_completes(role):
    coord, chain, leg = _setup(
        state=SwapState.BOTH_LOCKED, role=role, endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}
    )
    coord.radiant_leg.report_confs = int(coord.record.terms.t_rxd.value)
    chain.refund(85)
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and leg.refunds == 0
    assert asset == ([1] if role is None else []), "a taker never refunds the covenant"


async def test_the_real_chain_reader_answers_whether_the_covenant_outpoint_is_unspent():
    """`RadiantChainIO.covenant_outpoint_unspent`: an empty set is an answer (False); a failed
    read raises, so "spent" and "could not ask" never look alike."""
    from types import SimpleNamespace

    from pyrxd.gravity.radiant_leg import RadiantChainIO

    class _Client:
        def __init__(self, utxos):
            self.utxos = utxos

        async def broadcast(self, raw):  # required by RadiantChainIO; unused here
            raise AssertionError("no broadcast in this test")

        async def get_transaction_verbose(self, txid):  # required by RadiantChainIO; unused here
            raise AssertionError("not read in this test")

        async def get_utxos(self, script_hash):
            if isinstance(self.utxos, Exception):
                raise self.utxos
            return self.utxos

    live = [SimpleNamespace(tx_hash="ab" * 32, tx_pos=0)]
    assert await RadiantChainIO(_Client(live)).covenant_outpoint_unspent(b"\x51", "ab" * 32 + ":0") is True
    assert await RadiantChainIO(_Client(live)).covenant_outpoint_unspent(b"\x51", "ab" * 32 + ":1") is False
    assert await RadiantChainIO(_Client([])).covenant_outpoint_unspent(b"\x51", "ab" * 32 + ":0") is False
    with pytest.raises(NetworkError):
        await RadiantChainIO(_Client(NetworkError("down"))).covenant_outpoint_unspent(b"\x51", "ab" * 32 + ":0")

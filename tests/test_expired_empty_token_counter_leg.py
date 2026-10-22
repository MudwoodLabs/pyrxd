"""An empty, expired ERC-20 counter-leg contract, and closing the token push's nonce (#850 PR 7a).

Design ``docs/plans/2026-10-09-counter-leg-disposition-from-chain-design.md`` §2.3 (``EXPIRED_EMPTY_*``),
§2.7 (closing the push nonce), §3.2 (``COUNTER_LEG_EXPIRED_EMPTY``), §3.3 (``close_push_nonce``) and
§7.2 scenarios 11 and 12. The reader is the real one over the fake EVM chain, read through the
production ``MultiSourceEthRpc``; the coordinator is the real one; only the leg's broadcasts are faked.

An expired contract that holds no tokens has nothing to refund, but a token push the funding key
signed may still land. It is closed, and the record may end, only once the funding key's nonce at
the finalized block ``F`` is past every push it signed: then no push can land.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import pytest

from pyrxd.eth_wallet.disposition import DispositionKind, read_counter_disposition
from pyrxd.eth_wallet.events import CLAIMED_TOPIC0
from pyrxd.eth_wallet.locator import Erc20HtlcLocator
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.gravity.swap_coordinator import CounterLegRefundNeedsOperator, SwapCoordinator
from pyrxd.gravity.swap_state import AbortReason, SwapRecord, SwapRole, SwapState
from pyrxd.security.errors import CounterLegSingleSourceAnswer, NetworkError, NothingToRefund, ValidationError
from tests._fake_evm_chain import FUNDER, TOKEN, FakeEvmChain, FakeEvmEndpoint
from tests._fake_evm_chain import _tx_hash as _fake_tx_hash
from tests.test_counter_leg_disposition_coordinator import _ChainLeg
from tests.test_swap_coordinator import (
    CoordinatorConfig,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _eth_finality_policy,
    _eth_terms,
    _final,
)

TIMEOUT_BLOCK = 80
FINALIZED = 90  # past the timeout: the contract is F_EXPIRED unless something settled it
PUSH_NONCE = 7
_COVENANT = "ef" * 32 + ":0"


def _chain(**kw) -> FakeEvmChain:
    chain = FakeEvmChain(preimage=os.urandom(32), timeout=0, finalized=FINALIZED, **kw)
    chain.timeout = chain.ts(TIMEOUT_BLOCK)
    return chain


def _rpc(chain: FakeEvmChain, *endpoints: FakeEvmEndpoint) -> MultiSourceEthRpc:
    return MultiSourceEthRpc(list(endpoints) or [FakeEvmEndpoint(chain) for _ in range(3)])


async def _read(chain, *endpoints, bound=PUSH_NONCE, funder=FUNDER, token=TOKEN, nonce_less=False):
    return await read_counter_disposition(
        _rpc(chain, *endpoints),
        chain.token_locator(),
        token_address=token,
        funding_account=funder,
        push_nonce_bound=bound,
        nonce_less=nonce_less,
    )


# --------------------------------------------------------------------------- the reader


async def test_empty_at_F_and_tip_with_the_nonce_past_the_push_is_closed():
    chain = _chain(nonces={20: PUSH_NONCE + 1})  # the push's nonce was consumed long before F
    d = await _read(chain)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_CLOSED
    assert d.evidence is not None and d.evidence.kind is DispositionKind.EXPIRED_EMPTY_CLOSED
    assert d.evidence.block_number == FINALIZED and d.evidence.tx_hash is None
    assert d.nonce_at_finalized == PUSH_NONCE + 1
    assert d.expiry_anchor is not None and d.expiry_anchor[0] == FINALIZED  # still an expiry proof


async def test_a_nonce_not_past_the_push_is_open_and_names_the_nonce_to_close():
    chain = _chain(nonces={20: PUSH_NONCE})  # nonce PUSH_NONCE not yet consumed at F
    d = await _read(chain)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.evidence is None
    assert d.nonce_at_finalized == PUSH_NONCE


async def test_without_a_push_nonce_bound_it_is_never_closed():
    """Design §2.7: a record that never kept its push nonce has no proof from the count alone."""
    chain = _chain(nonces={20: 50})
    d = await _read(chain, bound=None)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.nonce_at_finalized == 50
    assert "no push nonce is recorded" in d.reason


async def test_a_close_mined_above_F_is_not_yet_closed():
    """Scenario 11's race: the count is read at F, never at the tip. A transaction at the push nonce
    mined above F can still be reorged out, and a push signed at that nonce could then land."""
    chain = _chain(nonces={20: PUSH_NONCE, FINALIZED + 5: PUSH_NONCE + 1})
    d = await _read(chain)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.nonce_at_finalized == PUSH_NONCE


async def test_tokens_at_the_tip_are_not_empty():
    """A push that landed above F: there is something to refund, so the refund path must run."""
    chain = _chain(nonces={20: PUSH_NONCE + 1}, token_balances={FINALIZED + 3: 1_000_000})
    d = await _read(chain)
    assert d.kind is DispositionKind.F_EXPIRED


async def test_tokens_at_F_are_not_empty():
    chain = _chain(nonces={20: PUSH_NONCE + 1}, token_balances={30: 1_000_000})
    assert (await _read(chain)).kind is DispositionKind.F_EXPIRED


async def test_one_endpoint_that_cannot_read_the_balance_leaves_it_F_EXPIRED():
    """A missing answer may be the endpoint that sees the tokens: unknown, never empty."""
    chain = _chain(nonces={20: PUSH_NONCE + 1})
    d = await _read(
        chain, FakeEvmEndpoint(chain), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, balance_reads_fail=True)
    )
    assert d.kind is DispositionKind.F_EXPIRED and "token balance is unknown" in d.reason


async def test_one_endpoint_that_sees_tokens_at_F_leaves_it_F_EXPIRED():
    chain = _chain(nonces={20: PUSH_NONCE + 1})
    d = await _read(chain, FakeEvmEndpoint(chain), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lie_balance=5))
    assert d.kind is DispositionKind.F_EXPIRED


async def test_endpoints_that_disagree_on_the_nonce_at_F_are_not_closed():
    chain = _chain(nonces={20: PUSH_NONCE})
    d = await _read(
        chain, FakeEvmEndpoint(chain), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lie_nonce=PUSH_NONCE + 9)
    )
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.nonce_at_finalized is None


async def test_one_endpoint_that_cannot_read_the_nonce_is_not_closed():
    chain = _chain(nonces={20: PUSH_NONCE + 1})
    d = await _read(
        chain, FakeEvmEndpoint(chain), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, nonce_reads_fail=True)
    )
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.nonce_at_finalized is None


async def test_HONEST_a_native_contract_is_never_read_for_tokens():
    chain = _chain(nonces={20: PUSH_NONCE + 1})
    d = await read_counter_disposition(_rpc(chain), chain.locator())
    assert d.kind is DispositionKind.F_EXPIRED


async def test_HONEST_before_the_timeout_at_F_it_is_not_expired_empty():
    chain = FakeEvmChain(preimage=os.urandom(32), timeout=0, finalized=70, nonces={20: PUSH_NONCE + 1})
    chain.timeout = chain.ts(TIMEOUT_BLOCK)
    assert (await _read(chain)).kind is DispositionKind.TIP_EXPIRED


async def test_bad_inputs_are_refused():
    chain = _chain()
    for kw in (
        {"token_address": "0x12"},
        {"funding_account": "bb" * 20},
        {"push_nonce_bound": -1},
        {"push_nonce_bound": True},
    ):
        with pytest.raises(ValidationError):
            await read_counter_disposition(_rpc(chain), chain.token_locator(), **kw)


# --------------------------------------------------------------------------- the coordinator


class _TokenLeg(_ChainLeg):
    """The chain-reading fake leg, for a token contract: the disposition is read with the token and
    this key's account, as ``EthLeg.counter_disposition`` reads it, and the push nonce is closed by a
    transaction the test mines with :func:`_mine_close`."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.closes: list[tuple[str, int]] = []
        self.dropped_closes: set[str] = set()
        self.recorded_at_broadcast: list[SwapRecord] = []
        self.coord = None

    async def counter_disposition(self, locator, **kwargs):
        # As EthLeg reads it: the recorded push signer, else this key (the fake deployed it).
        signer = kwargs.pop("push_signer", None)
        if isinstance(locator, Erc20HtlcLocator):
            kwargs.update(token_address=locator.token_address, funding_account=signer or self.signer_address())
        return await read_counter_disposition(self._rpc, locator, **kwargs)

    def signer_address(self):
        return getattr(self, "key", FUNDER)

    async def close_push_nonce(self, nonce, *, on_signed=None):
        latest = self.chain.count_at(self.chain.head)
        if latest != nonce:  # the real leg's check (EthHtlcContractLeg.close_nonce)
            raise NetworkError(f"latest count {latest} is not nonce {nonce}; nothing was sent")
        tx = _fake_tx_hash(f"close-{len(self.closes) + 1}")
        if on_signed is not None:
            await on_signed(tx, nonce)
        self.recorded_at_broadcast.append(self.coord.persisted[-1])
        self.closes.append((tx, nonce))
        return tx

    async def close_progress(self, tx_hash, nonce):
        from pyrxd.eth_wallet.htlc_leg import RefundProgress

        if getattr(self, "progress_kind", None) is not None:
            return RefundProgress(self.progress_kind)
        if tx_hash in self.dropped_closes:
            return RefundProgress("dropped")
        if self.chain.count_at(self.chain.head) > nonce:
            return RefundProgress("mined", tx_hash=tx_hash)
        return RefundProgress("pending", fee_fields={"maxFeePerGas": 100, "maxPriorityFeePerGas": 2})


def _mine_close(chain: FakeEvmChain, nonce: int, *, block: int) -> None:
    chain.nonces[block] = nonce + 1


def _setup(
    *,
    state=SwapState.BTC_LOCKED,
    role=SwapRole.TAKER,
    push_nonce: int | None = PUSH_NONCE,
    nonces=None,
    endpoints=None,
    confs=None,
):
    chain = _chain(nonces=dict(nonces if nonces is not None else {20: PUSH_NONCE + 1}))
    terms = dataclasses.replace(
        _eth_terms(
            hashlock=hashlib.sha256(chain.preimage).digest(), eth_timeout_unix_s=chain.timeout, now_unix_s=chain.ts(0)
        ),
        token_address=TOKEN,
    )
    eps = endpoints(chain) if endpoints else [FakeEvmEndpoint(chain) for _ in range(3)]
    rpc = eps[0] if len(eps) == 1 else MultiSourceEthRpc(eps)  # one endpoint is read as single-source
    leg = _TokenLeg(preimage=chain.preimage, verdict=_final(), rpc=rpc)
    leg.chain = chain
    rxd = FakeRadiantLeg()
    rxd.report_confs = confs
    record = SwapRecord(state=state, terms=terms).with_counter_lock(chain.token_locator())
    record = record.with_radiant_lock(_COVENANT, "51")
    if push_nonce is not None:
        record = dataclasses.replace(record, pending_push_nonce=push_nonce)
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
    leg.coord = coord
    return coord, chain, leg


@pytest.mark.parametrize("role", [SwapRole.TAKER, None])
async def test_closed_empty_contract_aborts_the_record_and_sends_nothing(role):
    coord, _c, leg = _setup(role=role)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.EXPIRED_EMPTY
    assert rec.counter_disposition.kind == "expired_empty_closed"
    assert rec.counter_disposition.block_number == FINALIZED
    assert leg.refunds == 0 and leg.closes == []
    assert coord.persisted[-1] == rec


async def test_reconcile_takes_the_same_edge():
    coord, _c, _leg = _setup()
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.EXPIRED_EMPTY


def _with_a_dropped_claim(chain):
    """One endpoint returns a Claimed(p) log (a claim that reverted Underfunded carries p, N1)."""
    dropped = {
        "address": "0x" + "c0" * 20,
        "topics": [CLAIMED_TOPIC0],
        "data": "0x" + chain.preimage.hex(),
        "transactionHash": "0x" + "dd" * 32,
        "blockNumber": 78,
    }
    return [FakeEvmEndpoint(chain, extra_logs=(dropped,)), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain)]


@pytest.mark.parametrize("role", [SwapRole.TAKER, None])
async def test_a_seen_claim_holds_the_closed_empty_terminal_until_t_rxd(role):
    """D14 / N1 (scenario 6b): p is public, so the covenant claim comes first."""
    coord, _c, leg = _setup(role=role, endpoints=_with_a_dropped_claim, confs=1)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and rec.abort_reason is None
    assert rec.counter_claim_tx == "0x" + "dd" * 32 and rec.counter_disposition.kind == "expired_empty_closed"
    assert leg.refunds == 0 and leg.closes == []


async def test_HONEST_once_t_rxd_has_matured_the_held_empty_record_aborts():
    coord, _c, _leg = _setup(endpoints=_with_a_dropped_claim)
    coord.radiant_leg.report_confs = int(coord.record.terms.t_rxd.value)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.EXPIRED_EMPTY


async def test_open_empty_contract_refuses_the_refund_and_names_the_close():
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    with pytest.raises(NothingToRefund, match="close_push_nonce") as e:
        await coord.taker_refund_btc()
    assert e.value.contract_address == coord.record.counterchain_locator.contract_address
    assert coord.record.state is SwapState.BTC_LOCKED and leg.refunds == 0
    assert coord.record.counter_expiry_anchor == f"{FINALIZED}:" + coord.record.counter_expiry_anchor.split(":")[1]


async def test_scenario_11_close_the_push_nonce_then_the_record_ends():
    """Empty expired ERC-20 with a nonce: close, the close finalizes, ABORTED."""
    coord, chain, leg = _setup(nonces={20: PUSH_NONCE})
    rec = await coord.close_push_nonce()
    assert leg.closes == [(_fake_tx_hash("close-1"), PUSH_NONCE)]
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.push_close_tx_hash == _fake_tx_hash("close-1") and rec.push_close_nonce == PUSH_NONCE
    # Recorded BEFORE the broadcast (design §2.8): the write the broadcast saw already held it.
    assert leg.recorded_at_broadcast[-1].push_close_tx_hash == rec.push_close_tx_hash
    # Mined above F: not yet final, so a retry waits and sends nothing.
    _mine_close(chain, PUSH_NONCE, block=FINALIZED + 2)
    assert (await coord.close_push_nonce()).state is SwapState.BTC_LOCKED and len(leg.closes) == 1
    with pytest.raises(NothingToRefund):
        await coord.taker_refund_btc()
    # F passes it: closed, and the record ends.
    chain.finalized = FINALIZED + 5
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.EXPIRED_EMPTY
    assert leg.refunds == 0 and len(leg.closes) == 1


async def test_scenario_12_a_nonce_less_record_closes_by_its_own_close():
    """No push nonce recorded: OPEN however high the count, until a close of ours is final."""
    coord, chain, leg = _setup(push_nonce=None, nonces={20: 40})
    with pytest.raises(NothingToRefund):
        await coord.taker_refund_btc()
    await coord.close_push_nonce()
    assert leg.closes == [(_fake_tx_hash("close-1"), 40)]
    _mine_close(chain, 40, block=FINALIZED + 1)
    chain.finalized = FINALIZED + 3
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.EXPIRED_EMPTY


async def test_a_pending_close_is_followed_not_resent():
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    await coord.close_push_nonce()
    await coord.close_push_nonce()
    assert len(leg.closes) == 1


async def test_a_dropped_close_is_sent_again_at_the_same_nonce():
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    await coord.close_push_nonce()
    leg.dropped_closes.add(leg.closes[0][0])
    rec = await coord.close_push_nonce()
    assert [n for _tx, n in leg.closes] == [PUSH_NONCE, PUSH_NONCE]
    assert rec.push_close_tx_hash == _fake_tx_hash("close-2")


async def test_close_refuses_when_the_push_nonce_is_above_the_count_at_F():
    """Closing a lower nonce would not reach the push's own: wait, send nothing."""
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE - 2})
    with pytest.raises(NetworkError, match="above the funding key's nonce"):
        await coord.close_push_nonce()
    assert leg.closes == [] and coord.record.push_close_tx_hash is None


async def test_close_sends_nothing_when_the_contract_holds_tokens():
    coord, chain, leg = _setup(nonces={20: PUSH_NONCE})
    chain.token_balances[30] = 1_000_000
    with pytest.raises(ValidationError, match="sends only when the contract reads expired and empty"):
        await coord.close_push_nonce()
    assert leg.closes == []


async def test_close_sends_nothing_when_the_nonce_at_F_is_unknown():
    def disagree(chain):
        return [FakeEvmEndpoint(chain), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lie_nonce=99)]

    coord, _c, leg = _setup(nonces={20: PUSH_NONCE}, endpoints=disagree)
    with pytest.raises(NetworkError, match="could not be read at every endpoint"):
        await coord.close_push_nonce()
    assert leg.closes == []


async def test_close_on_an_already_closed_contract_ends_the_record_and_sends_nothing():
    coord, _c, leg = _setup()
    rec = await coord.close_push_nonce()
    assert rec.state is SwapState.ABORTED and leg.closes == []


@pytest.mark.parametrize(
    ("state", "role", "why"),
    [
        (SwapState.BTC_LOCKED, SwapRole.MAKER, "taker's step"),
        (SwapState.PARAMS_MISMATCH, None, "not valid from params_mismatch"),
        (SwapState.BOTH_LOCKED, SwapRole.TAKER, "not valid from both_locked"),
    ],
)
async def test_close_is_refused_where_the_design_gives_it_no_place(state, role, why):
    coord, _c, leg = _setup(state=state, role=role, nonces={20: PUSH_NONCE})
    with pytest.raises(ValidationError, match=why):
        await coord.close_push_nonce()
    assert leg.closes == []


async def test_close_is_refused_on_a_native_counter_leg():
    coord, chain, leg = _setup(nonces={20: PUSH_NONCE})
    terms = dataclasses.replace(coord.record.terms, token_address="")
    coord.record = dataclasses.replace(
        coord.record, terms=terms, counterchain_locator=chain.locator(), pending_push_nonce=None
    )
    with pytest.raises(ValidationError, match="only to a token"):
        await coord.close_push_nonce()
    assert leg.closes == []


async def test_params_mismatch_has_no_edge_on_a_closed_empty_contract():
    coord, _c, leg = _setup(state=SwapState.PARAMS_MISMATCH, role=None)
    with pytest.raises(ValidationError, match="no edge out of PARAMS_MISMATCH"):
        await coord.taker_refund_btc()
    assert coord.record.state is SwapState.PARAMS_MISMATCH
    assert coord.persisted[-1].counter_disposition.kind == "expired_empty_closed"  # durable before the raise
    assert leg.refunds == 0


async def test_a_makers_record_records_the_closed_empty_contract_and_stays():
    coord, _c, _leg = _setup(role=SwapRole.MAKER)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.BTC_LOCKED and rec.counter_disposition.kind == "expired_empty_closed"


@pytest.mark.parametrize("nonces", [{20: PUSH_NONCE}, {20: PUSH_NONCE + 1}])
async def test_both_locked_with_an_empty_contract_names_the_abandon_and_sends_nothing(nonces):
    """N2 / scenario 14b's first half: no refund is possible, and abandon_counter_leg is the exit."""
    coord, _c, leg = _setup(state=SwapState.BOTH_LOCKED, nonces=nonces)
    with pytest.raises(NothingToRefund, match="abandon_counter_leg"):
        await coord.mutual_refund()
    assert coord.record.state is SwapState.BOTH_LOCKED and leg.refunds == 0
    assert coord.record.asset_refund_txid is None  # the covenant is not touched either


async def test_HONEST_tokens_in_an_expired_contract_are_refunded_not_closed():
    coord, chain, leg = _setup(nonces={20: PUSH_NONCE})
    chain.token_balances[30] = 1_000_000
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 1 and rec.state is SwapState.BTC_LOCKED and rec.counter_refund_tx_hash is not None


# --------------------------------------------------------------------------- review of PR 7a


async def test_nonce_less_a_key_with_a_transaction_in_flight_is_not_closed():
    """Design §2.7: with no push nonce, our own close is the bound, and a push still in flight above it
    (pending at an endpoint) can land after it. Not CLOSED until the key is idle everywhere."""
    chain = _chain(nonces={20: 41})  # our close at 40 is final
    chain.pending_txs = 1
    d = await _read(chain, bound=40, nonce_less=True)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.funding_key_idle is False
    assert "in flight" in d.reason


async def test_HONEST_nonce_less_an_idle_key_past_our_close_is_closed():
    chain = _chain(nonces={20: 41})
    d = await _read(chain, bound=40, nonce_less=True)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_CLOSED and d.funding_key_idle is True


@pytest.mark.parametrize("which", [0, 1, 2])
async def test_nonce_less_one_endpoint_that_sees_a_transaction_in_flight_is_enough(which):
    """Every endpoint is asked, not the first: any one of them holding a pending transaction of the key
    keeps it OPEN."""
    chain = _chain(nonces={20: 41})
    eps = [FakeEvmEndpoint(chain, pending_extra=1 if i == which else 0) for i in range(3)]
    d = await _read(chain, *eps, bound=40, nonce_less=True)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.funding_key_idle is False


async def test_nonce_less_a_count_mined_above_F_is_not_idle():
    chain = _chain(nonces={20: 41, FINALIZED + 2: 42})
    d = await _read(chain, bound=40, nonce_less=True)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.funding_key_idle is False


async def test_nonce_less_an_endpoint_that_cannot_read_the_pending_count_is_not_closed():
    class _NoPending(FakeEvmEndpoint):
        async def get_transaction_count(self, address, block="pending"):
            if block == "pending":
                raise NetworkError("eth_getTransactionCount failed: 429 Too Many Requests")
            return await super().get_transaction_count(address, block)

    chain = _chain(nonces={20: 41})
    d = await _read(chain, FakeEvmEndpoint(chain), _NoPending(chain), bound=40, nonce_less=True)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_OPEN and d.funding_key_idle is False


async def test_with_a_push_nonce_the_pending_count_is_not_needed():
    """The recorded nonce is the bound, and every push of the key is at or below it."""
    chain = _chain(nonces={20: PUSH_NONCE + 1})
    chain.pending_txs = 3
    d = await _read(chain)
    assert d.kind is DispositionKind.EXPIRED_EMPTY_CLOSED and d.funding_key_idle is None


async def test_nonce_less_close_is_not_sent_while_the_key_has_a_transaction_in_flight():
    coord, chain, leg = _setup(push_nonce=None, nonces={20: 40})
    chain.pending_txs = 1
    with pytest.raises(NetworkError, match="not idle at every endpoint"):
        await coord.close_push_nonce()
    assert leg.closes == [] and coord.record.push_close_tx_hash is None


async def test_nonce_less_record_stays_while_a_push_is_in_flight_above_our_final_close():
    coord, chain, leg = _setup(push_nonce=None, nonces={20: 40})
    await coord.close_push_nonce()
    _mine_close(chain, 40, block=FINALIZED + 1)
    chain.finalized = FINALIZED + 3
    chain.pending_txs = 1  # a push at 41 that our close made executable
    with pytest.raises(NothingToRefund):
        await coord.taker_refund_btc()
    assert coord.record.state is SwapState.BTC_LOCKED
    chain.pending_txs = 0
    assert (await coord.taker_refund_btc()).state is SwapState.ABORTED
    assert len(leg.closes) == 1 and leg.refunds == 0


OTHER_KEY = "0x" + "ab" * 20


async def test_a_record_whose_push_key_is_not_this_legs_key_sends_no_close():
    """Review M1: the taker funded with key A, the runner restarted with key B. B's nonce does not
    stop A's push, so no close is sent; and the read is of A's count (0 here), so nothing ends."""
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    coord.record = dataclasses.replace(coord.record, push_signer=OTHER_KEY)
    with pytest.raises(ValidationError, match="only a close from the push's key"):
        await coord.close_push_nonce()
    assert leg.closes == []
    coord2, _c2, _l2 = _setup()  # FUNDER's count at F is past the push nonce...
    coord2.record = dataclasses.replace(coord2.record, push_signer=OTHER_KEY)
    with pytest.raises(NothingToRefund):  # ...but the push key is OTHER_KEY, whose count is not
        await coord2.taker_refund_btc()
    assert coord2.record.state is SwapState.BTC_LOCKED


async def test_a_leg_that_does_not_say_its_key_sends_no_close():
    """Re-review of #850 PR 7a, round 2: the record names the push key and the leg names none. A close
    from an unknown key would be recorded as this record's bound without stopping the push."""
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    coord.record = dataclasses.replace(coord.record, push_signer=leg.signer_address())
    leg.signer_address = None  # a leg written before signer_address
    with pytest.raises(ValidationError, match="only a close from the push's key"):
        await coord.close_push_nonce()
    assert leg.closes == [] and coord.record.push_close_nonce is None


async def test_HONEST_a_record_whose_push_key_is_this_legs_key_closes():
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    coord.record = dataclasses.replace(coord.record, push_signer=FUNDER)
    await coord.close_push_nonce()
    assert leg.closes == [(_fake_tx_hash("close-1"), PUSH_NONCE)]


async def test_one_endpoint_on_a_value_bearing_chain_does_not_end_a_closed_empty_record(monkeypatch):
    """D4 for EXPIRED_EMPTY_CLOSED: the fixture chain is a testnet, so force the value-bearing rule."""
    coord, _c, leg = _setup(endpoints=lambda chain: [FakeEvmEndpoint(chain)])
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    with pytest.raises(CounterLegSingleSourceAnswer):
        await coord.close_push_nonce()
    with pytest.raises(NetworkError, match="from ONE endpoint, on a chain that carries value"):
        await coord.taker_refund_btc()
    assert coord.record.state is SwapState.BTC_LOCKED and coord.record.counter_disposition is None
    assert coord.record.counter_expiry_anchor is None and leg.closes == [] and leg.refunds == 0


async def test_HONEST_one_endpoint_on_a_testnet_ends_a_closed_empty_record():
    coord, _c, _leg = _setup(endpoints=lambda chain: [FakeEvmEndpoint(chain)])
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.single_source is True


async def test_a_close_whose_earlier_nonce_is_missing_needs_the_operator():
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    await coord.close_push_nonce()
    leg.progress_kind = "nonce_gap"
    with pytest.raises(CounterLegRefundNeedsOperator, match="earlier transaction from the same ETH key is missing"):
        await coord.close_push_nonce()
    assert len(leg.closes) == 1


async def test_a_close_whose_nonce_another_transaction_took_waits_and_resends_nothing():
    coord, _c, leg = _setup(nonces={20: PUSH_NONCE})
    await coord.close_push_nonce()
    leg.progress_kind = "nonce_taken"
    rec = await coord.close_push_nonce()
    assert len(leg.closes) == 1 and rec.state is SwapState.BTC_LOCKED

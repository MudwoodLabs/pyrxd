"""The taker's NEGOTIATED exit, ``SwapCoordinator.abandon_unfunded`` (#850 PR 8, design §3.5).

A record ends ``ABORTED`` (``TAKER_NEVER_FUNDS``) only while it holds nothing that may hold value:
no BTC funding transaction, no native ETH contract, and a token contract only when no push was signed
for it and its balance is 0 at the finalized block and at the tip at every endpoint. Nothing is
broadcast, and the hashlock stays reserved. The balance is read with the real reader over the fake
EVM chain, through the production ``MultiSourceEthRpc``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import pytest

from pyrxd.eth_wallet.disposition import read_unfunded_token_balance
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.gravity.swap_coordinator import SwapCoordinator
from pyrxd.gravity.swap_state import SWAP_RECORD_SCHEMA_VERSION, AbortReason, SwapRecord, SwapRole, SwapState
from pyrxd.security.errors import NetworkError, ValidationError
from tests._fake_evm_chain import CHAIN_ID, CONTRACT, TOKEN, FakeEvmChain, FakeEvmEndpoint
from tests.test_swap_coordinator import (
    CoordinatorConfig,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _eth_finality_policy,
    _eth_terms,
    _terms,
)

FINALIZED = 90
DEPLOY_TX = "0x" + "de" * 32


class _Leg:
    """An ETH counter leg that reads a token balance as ``EthLeg.unfunded_token_balance`` does, and
    broadcasts nothing (it has no method that could)."""

    def __init__(self, rpc, chain_id=CHAIN_ID) -> None:
        self._rpc = rpc
        self.chain_id = chain_id
        self.reads: list[tuple[str, str]] = []

    async def unfunded_token_balance(self, *, token, contract):
        self.reads.append((token, contract))
        return await read_unfunded_token_balance(self._rpc, token=token, contract=contract)


def _chain(**kw) -> FakeEvmChain:
    return FakeEvmChain(preimage=os.urandom(32), timeout=0, finalized=FINALIZED, **kw)


def _setup(*, token=True, contract=True, role=SwapRole.TAKER, endpoints=None, chain_kw=None, chain_id=CHAIN_ID, **rec):
    chain = _chain(**(chain_kw or {}))
    h = hashlib.sha256(chain.preimage).digest()
    terms = _eth_terms(hashlock=h)
    if token:
        terms = dataclasses.replace(terms, token_address=TOKEN)
    if contract:
        rec = {"pending_counter_contract": CONTRACT, "pending_counter_deploy_tx": DEPLOY_TX, **rec}
    eps = endpoints(chain) if endpoints else [FakeEvmEndpoint(chain) for _ in range(3)]
    rpc = eps[0] if len(eps) == 1 else MultiSourceEthRpc(eps)
    leg = _Leg(rpc, chain_id)
    seen = FakeSeenStore()
    assert seen.reserve(h)
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms, **rec),
        counter_leg=leg,
        radiant_leg=FakeRadiantLeg(),
        indexer=FakeIndexer(),
        seen_store=seen,
        config=CoordinatorConfig(
            margin_policy=_eth_finality_policy(window_s=768), maker_stall_safety_window_blocks=6, role=role
        ),
    )
    coord.persisted = []

    async def _persist(r):
        coord.persisted.append(r)

    coord._persist = _persist
    return coord, chain, leg


def _unchanged(coord, before) -> None:
    assert coord.record == before and coord.persisted == []


# --------------------------------------------------------------------------- accepted


@pytest.mark.parametrize("role", [SwapRole.TAKER, None])
async def test_a_record_with_nothing_on_chain_is_abandoned_and_the_hashlock_stays_reserved(role):
    coord, _c, leg = _setup(contract=False, role=role)
    rec = await coord.abandon_unfunded()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.TAKER_NEVER_FUNDS
    assert coord.persisted == [rec] and leg.reads == []  # nothing to read: no contract
    assert coord.seen_store.reserve(rec.terms.hashlock) is False  # still reserved: H is never funded again


async def test_a_btc_record_with_no_funding_transaction_is_abandoned():
    coord, _c, _leg = _setup(contract=False)
    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms())
    rec = await coord.abandon_unfunded()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.TAKER_NEVER_FUNDS


async def test_an_empty_token_contract_never_pushed_into_is_abandoned():
    coord, _c, leg = _setup()
    rec = await coord.abandon_unfunded()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.TAKER_NEVER_FUNDS
    assert leg.reads == [(TOKEN, CONTRACT)]
    assert rec.pending_counter_contract == CONTRACT  # the deployed contract stays on the record
    assert coord.persisted == [rec]


async def test_one_endpoint_on_a_testnet_may_read_the_balance():
    coord, _c, _leg = _setup(endpoints=lambda c: [FakeEvmEndpoint(c)])
    assert (await coord.abandon_unfunded()).state is SwapState.ABORTED


async def test_the_abandoned_record_round_trips_at_the_current_schema_version():
    coord, _c, _leg = _setup()
    rec = await coord.abandon_unfunded()
    d = rec.to_dict()
    assert d["abort_reason"] == "taker_never_funds" and d["schema_version"] == SWAP_RECORD_SCHEMA_VERSION == 8
    assert SwapRecord.from_dict(d) == rec


# --------------------------------------------------------------------------- refused, nothing recorded


async def test_a_btc_funding_transaction_may_have_been_sent():
    coord, _c, _leg = _setup(contract=False)
    from tests.test_btc_runners_record_the_fund import _signed_funding_tx_hex

    terms = _terms()
    coord.record = SwapRecord(
        state=SwapState.NEGOTIATED, terms=terms, pending_btc_funding_tx=_signed_funding_tx_hex(terms)
    )
    before = coord.record
    with pytest.raises(ValidationError, match="BTC funding transaction"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


async def test_a_native_contract_is_refused_without_a_read():
    coord, _c, leg = _setup(token=False)
    before = coord.record
    with pytest.raises(ValidationError, match="whose deploy carries the value"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)
    assert leg.reads == []


@pytest.mark.parametrize(
    "pushed", [{"pending_push_nonce": 7}, {"pending_push_nonce": 7, "pending_push_tx_hash": "0x" + "ab" * 32}]
)
async def test_a_token_contract_a_push_was_signed_for_is_refused_without_a_read(pushed):
    coord, _c, leg = _setup(**pushed)
    before = coord.record
    with pytest.raises(ValidationError, match="token push .* was signed"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)
    assert leg.reads == []


@pytest.mark.parametrize(
    "balances",
    [{30: 1_000_000}, {FINALIZED + 3: 1_000_000}, {30: 1_000_000, FINALIZED + 2: 0}],
    ids=["at_F_and_tip", "at_tip", "at_F_only"],
)
async def test_tokens_in_the_contract_are_refused(balances):
    """Tokens at the tip, or at F and gone since (something moved them): either way it was funded."""
    coord, _c, _leg = _setup(chain_kw={"token_balances": balances})
    before = coord.record
    with pytest.raises(ValidationError, match="holds tokens"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


@pytest.mark.parametrize(
    "odd",
    [{"balance_reads_fail": True}, {"lie_balance": 5}],
    ids=["one_endpoint_cannot_read", "one_endpoint_disagrees"],
)
async def test_a_balance_that_is_not_known_at_every_endpoint_is_refused(odd):
    coord, _c, _leg = _setup(endpoints=lambda c: [FakeEvmEndpoint(c), FakeEvmEndpoint(c), FakeEvmEndpoint(c, **odd)])
    before = coord.record
    with pytest.raises(NetworkError, match="token balance .* is unknown"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


@pytest.mark.parametrize("chain_id", [1, None], ids=["mainnet", "leg_does_not_say"])
async def test_one_endpoint_on_a_chain_that_carries_value_is_refused(chain_id):
    coord, _c, _leg = _setup(endpoints=lambda c: [FakeEvmEndpoint(c)], chain_id=chain_id)
    if chain_id is None:
        del coord.counter_leg.chain_id
    before = coord.record
    with pytest.raises(NetworkError, match="one endpoint"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


async def test_a_maker_is_refused():
    coord, _c, _leg = _setup(contract=False, role=SwapRole.MAKER)
    before = coord.record
    with pytest.raises(ValidationError, match="taker's step"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


async def test_only_from_negotiated():
    coord, _c, _leg = _setup(contract=False)
    coord.record = dataclasses.replace(coord.record, state=SwapState.BTC_LOCKED)
    before = coord.record
    with pytest.raises(ValidationError, match="not valid from btc_locked"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


async def test_a_leg_that_cannot_read_a_token_balance_is_refused():
    coord, _c, leg = _setup()
    leg.unfunded_token_balance = None
    before = coord.record
    with pytest.raises(ValidationError, match="reads a token balance"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


# --------------------------------------------------------------------------- the reader and the shipped leg


async def test_the_reader_names_the_finalized_block_and_its_endpoints():
    chain = _chain()
    eps = [FakeEvmEndpoint(chain) for _ in range(2)]
    read = await read_unfunded_token_balance(
        MultiSourceEthRpc(eps), token=TOKEN.upper().replace("0X", "0x"), contract=CONTRACT
    )
    assert read.empty and read.finalized_block == FINALIZED and not read.single_source
    assert len(read.sources) == 2


async def test_the_shipped_eth_leg_reads_through_its_own_rpc():
    from tests.test_record_names_its_role_and_keeps_the_push import _shipped_token_eth_leg

    chain = _chain(token_balances={30: 7})
    leg, _seen = _shipped_token_eth_leg([])
    leg._leg._rpc = MultiSourceEthRpc([FakeEvmEndpoint(chain) for _ in range(2)])
    read = await leg.unfunded_token_balance(token=TOKEN, contract=CONTRACT)
    assert read.empty is False and read.finalized_block == FINALIZED

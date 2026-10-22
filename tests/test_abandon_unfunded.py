"""The taker's NEGOTIATED exit, ``SwapCoordinator.abandon_unfunded`` (#850 PR 8, design §3.5).

A record ends ``ABORTED`` (``TAKER_NEVER_FUNDS``) only while it holds nothing that may hold value:
no BTC funding transaction, no native ETH contract, and a token contract only when no push was signed
for it and its balance is 0 at the finalized block and at the tip at every endpoint. Nothing is
broadcast, and the hashlock stays reserved. The balance is read with the real reader over the fake
EVM chain, through the production ``MultiSourceEthRpc``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os

import pytest

from pyrxd.eth_wallet.disposition import read_unfunded_token_balance
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import SwapCoordinator
from pyrxd.gravity.swap_state import (
    SWAP_RECORD_SCHEMA_VERSION,
    AbortReason,
    RecordRole,
    SwapRecord,
    SwapRole,
    SwapState,
)
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
    return FakeEvmChain(preimage=os.urandom(32), **{"timeout": 0, "finalized": FINALIZED, **kw})


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


async def test_a_btc_record_written_with_a_role_is_abandoned(tmp_path):
    """0.27 writes ``role`` on every record a coordinator persists, and records the BTC funding
    transaction before its broadcast, so a record on disk that names a role and holds no funding
    transaction was never funded."""
    coord, _c, _leg = _setup(contract=False)
    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(coord.record)
    coord._persist = sink
    rec = await coord.abandon_unfunded()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.TAKER_NEVER_FUNDS
    assert sink.load_record() == rec


async def test_a_btc_record_never_persisted_is_abandoned(tmp_path):
    coord, _c, _leg = _setup(contract=False)
    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER)
    coord._persist = JsonFileRecordSink(tmp_path / "swap.json")
    assert (await coord.abandon_unfunded()).state is SwapState.ABORTED


@pytest.mark.parametrize("where", ["on_disk_without_a_role", "sink_cannot_read_back"])
async def test_a_btc_record_that_may_predate_its_funding_record_needs_the_htlc_checked(tmp_path, where):
    """Before #841 a BTC fund whose readback failed left a NEGOTIATED record with no trace of the BTC
    in the HTLC. A record on disk with no role (pre-0.27), or one that cannot be read back, may be
    that record: refused until the caller confirms the HTLC address never received an output."""
    coord, _c, _leg = _setup(contract=False)
    terms = _terms()
    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=RecordRole.TAKER)
    if where == "on_disk_without_a_role":
        sink = JsonFileRecordSink(tmp_path / "swap.json")
        await sink(SwapRecord(state=SwapState.NEGOTIATED, terms=terms))  # as 0.26.x wrote it
        assert "role" not in json.loads(sink.path.read_text())
        coord._persist = sink
        written = lambda: sink.load_record()  # noqa: E731
    else:
        written = lambda: list(coord.persisted)  # noqa: E731
    before, before_written = coord.record, written()
    with pytest.raises(ValidationError, match="0.26.x or earlier.*confirm_btc_htlc_empty=True"):
        await coord.abandon_unfunded()
    assert coord.record == before and written() == before_written
    rec = await coord.abandon_unfunded(confirm_btc_htlc_empty=True)
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.TAKER_NEVER_FUNDS


@pytest.mark.parametrize("writer", ["the_record_read_from_disk", "a_record_built_in_memory"])
async def test_a_role_written_later_does_not_hide_a_record_read_without_one(tmp_path, writer):
    """A 0.27 coordinator that takes in a 0.26.x record stamps its role, and any write it makes (the
    intent persist of a fund that is then refused) puts that role on disk. The record keeps
    ``read_without_role``, written by the record itself or added by the sink over a record on disk
    without a role, so a later abandon is still refused."""
    terms = _terms()
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(SwapRecord(state=SwapState.NEGOTIATED, terms=terms))  # as 0.26.x wrote it
    first, _c, _leg = _setup(contract=False)
    first._persist = sink
    if writer == "the_record_read_from_disk":
        first.record = first._adopted(sink.load_record())  # as the constructor takes it in
    else:
        first.record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=RecordRole.TAKER)
    await first._persist_record(first.record)
    on_disk = json.loads(sink.path.read_text())
    assert on_disk["role"] == "taker" and on_disk["read_without_role"] is True
    assert on_disk["schema_version"] == SWAP_RECORD_SCHEMA_VERSION == 9
    fresh, _c, _leg = _setup(contract=False)
    fresh.record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=RecordRole.TAKER)
    fresh._persist = sink
    with pytest.raises(ValidationError, match=r"0\.26\.x or earlier \(the record on disk was written without a role\)"):
        await fresh.abandon_unfunded()
    assert json.loads(sink.path.read_text()) == on_disk
    rec = await fresh.abandon_unfunded(confirm_btc_htlc_empty=True)
    assert rec.state is SwapState.ABORTED and json.loads(sink.path.read_text())["read_without_role"] is True


async def test_a_record_read_without_a_role_is_refused_whatever_the_sink_holds(tmp_path):
    """A 0.26.x record read from one place and persisted to an empty sink elsewhere: the record itself
    says it was read without a role."""
    old = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()).to_dict()
    coord, _c, _leg = _setup(contract=False)
    coord.record = coord._adopted(SwapRecord.from_dict(old))
    assert coord.record.role is RecordRole.TAKER and coord.record.read_without_role
    coord._persist = JsonFileRecordSink(tmp_path / "elsewhere.json")
    with pytest.raises(ValidationError, match=r"\(this record was read without a role\)"):
        await coord.abandon_unfunded()
    assert not (tmp_path / "elsewhere.json").exists()
    assert (await coord.abandon_unfunded(confirm_btc_htlc_empty=True)).state is SwapState.ABORTED


async def test_with_no_persist_hook_the_refusal_says_so():
    coord, _c, _leg = _setup(contract=False)
    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER)
    coord._persist = None
    with pytest.raises(ValidationError, match=r"\(there is no persist hook to read the record on disk from\)"):
        await coord.abandon_unfunded()


async def test_the_sink_keeps_the_mark_on_a_write_that_names_no_role(tmp_path):
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    terms = _terms()
    await sink(SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=RecordRole.TAKER, read_without_role=True))
    await sink(SwapRecord(state=SwapState.NEGOTIATED, terms=terms))  # a record built outside a coordinator
    back = sink.load_record()
    assert back.role is RecordRole.TAKER and back.read_without_role


def test_HONEST_a_record_without_a_role_keeps_its_old_wire_form():
    """The mark is written only with a role: a record without one reads back marked and writes back
    byte-identical, so the v1 form of a BTC record is unchanged."""
    old = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms()).to_dict()
    back = SwapRecord.from_dict(old)
    assert back.read_without_role and back.to_dict() == old and "read_without_role" not in old
    unmarked = SwapRecord.from_dict(
        SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER).to_dict()
    )
    assert not unmarked.read_without_role


@pytest.mark.parametrize("value", [1, "true", None])
def test_a_mark_that_is_not_a_bool_is_refused_on_read(value):
    d = SwapRecord(state=SwapState.NEGOTIATED, terms=_terms(), role=RecordRole.TAKER).to_dict()
    d["read_without_role"] = value
    with pytest.raises(ValidationError, match="read_without_role must be a bool"):
        SwapRecord.from_dict(d)


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
    assert d["abort_reason"] == "taker_never_funds" and d["schema_version"] == SWAP_RECORD_SCHEMA_VERSION == 9
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


async def test_a_contract_that_is_settled_is_refused():
    """Review of #850 PR 8: a push that was never recorded landed and was claimed, so the balance is
    0 at F and at the tip. The settled slot shows it, and a claim makes the preimage public."""
    coord, chain, _leg = _setup(chain_kw={"timeout": 10**12})
    chain.claim(50)
    before = coord.record
    with pytest.raises(ValidationError, match="is settled"):
        await coord.abandon_unfunded()
    _unchanged(coord, before)


async def test_a_contract_settled_only_at_the_tip_is_refused():
    coord, chain, _leg = _setup(chain_kw={"timeout": 10**12})
    chain.claim(FINALIZED + 5)
    with pytest.raises(ValidationError, match="is settled"):
        await coord.abandon_unfunded()


@pytest.mark.parametrize(
    "odd", [{"claim_settled_at_tip": True}, {"lie_settled_at_blocks": True}], ids=["at_tip", "at_F"]
)
async def test_one_endpoint_that_sees_the_contract_settled_is_enough_to_refuse(odd):
    coord, _c, _leg = _setup(endpoints=lambda c: [FakeEvmEndpoint(c), FakeEvmEndpoint(c), FakeEvmEndpoint(c, **odd)])
    with pytest.raises(ValidationError, match="is settled"):
        await coord.abandon_unfunded()


@pytest.mark.parametrize("held", ["btc_funding_tx", "native_contract", "btc_locked"])
async def test_a_fresh_coordinator_never_overwrites_the_record_on_disk(tmp_path, held):
    """Review of #850 PR 8, HIGH: a coordinator built on a fresh NEGOTIATED record, not the one on
    disk, would have written ABORTED over the only record of a fund. It refuses first, and the file
    is left as it was."""
    from tests.test_btc_runners_record_the_fund import _signed_funding_tx_hex

    coord, _c, leg = _setup(contract=False)
    if held == "btc_funding_tx":
        terms = _terms()
        prior = SwapRecord(
            state=SwapState.NEGOTIATED, terms=terms, pending_btc_funding_tx=_signed_funding_tx_hex(terms)
        )
    elif held == "native_contract":
        terms = dataclasses.replace(coord.record.terms, token_address="")
        prior = SwapRecord(
            state=SwapState.NEGOTIATED,
            terms=terms,
            pending_counter_contract=CONTRACT,
            pending_counter_deploy_tx=DEPLOY_TX,
        )
    else:
        terms = _terms()
        prior = SwapRecord(state=SwapState.BTC_LOCKED, terms=terms)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(prior)
    before_bytes = sink.path.read_bytes()
    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
    coord._persist = sink
    with pytest.raises(ValidationError, match="already holds this swap's counter leg"):
        await coord.abandon_unfunded()
    assert sink.path.read_bytes() == before_bytes and leg.reads == []


async def test_a_coordinator_built_before_the_push_never_drops_the_signed_push_on_disk(tmp_path):
    """Re-review of #850 PR 8, MEDIUM: built from a copy taken after the deploy and before the push
    nonce was written, the coordinator's record has the same contract and no push. The disk has the
    signed push. Before the push lands the balance is 0, so ABORTED would have been written over the
    only record of the push's nonce and hash."""
    coord, _c, leg = _setup()
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(dataclasses.replace(coord.record, pending_push_nonce=7, pending_push_tx_hash="0x" + "ab" * 32))
    before_bytes = sink.path.read_bytes()
    coord._persist = sink
    with pytest.raises(ValidationError, match="already holds this swap's counter leg.*pending_push_nonce"):
        await coord.abandon_unfunded()
    assert sink.path.read_bytes() == before_bytes and leg.reads == []


async def test_the_fund_lock_is_held_from_the_disk_read_to_the_write(tmp_path):
    """A fund in another process holds the same lock across deploy and push, so it cannot sign a
    push between the read of the record on disk and the ABORTED write."""
    coord, _c, _leg = _setup()
    events: list[str] = []
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(coord.record)

    class _Lock:
        def __enter__(self):
            events.append("lock")

        def __exit__(self, *exc):
            events.append("unlock")

    class _Watched:
        path = sink.path

        def load_record(self):
            events.append("read")
            return sink.load_record()

        async def __call__(self, record):
            events.append("write")
            await sink(record)

    coord.config = dataclasses.replace(coord.config, fund_lock=_Lock)
    coord._persist = _Watched()
    await coord.abandon_unfunded()
    assert events == ["lock", "read", "write", "unlock"]


async def test_HONEST_the_record_on_disk_it_was_built_from_is_abandoned(tmp_path):
    coord, _c, _leg = _setup()
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(coord.record)
    coord._persist = sink
    rec = await coord.abandon_unfunded()
    assert sink.load_record() == rec and rec.state is SwapState.ABORTED


async def test_a_failed_persist_leaves_the_record_as_it_was():
    coord, _c, _leg = _setup()
    before = coord.record

    async def broken(_record):
        raise OSError("disk full")

    coord._persist = broken
    with pytest.raises(OSError, match="disk full"):
        await coord.abandon_unfunded()
    assert coord.record == before


async def test_a_cancelled_abandon_keeps_what_the_disk_holds():
    coord, _c, _leg = _setup(contract=False)
    gate, started = asyncio.Event(), asyncio.Event()

    async def slow(record):
        started.set()
        await gate.wait()
        coord.persisted.append(record)

    coord._persist = slow
    task = asyncio.ensure_future(coord.abandon_unfunded())
    await started.wait()
    task.cancel()
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(20):
        await asyncio.sleep(0)
    assert [r.state for r in coord.persisted] == [SwapState.ABORTED] and coord.record == coord.persisted[0]


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
    assert read.empty and not read.settled and read.finalized_block == FINALIZED and not read.single_source
    assert len(read.sources) == 2


async def test_the_finalized_block_is_the_lowest_any_endpoint_reports():
    """``F`` is the minimum: an endpoint that lags has not reached a higher one, and every endpoint
    must read the balance at ``F``."""
    chain = _chain()
    eps = [FakeEvmEndpoint(chain), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lag=20)]
    read = await read_unfunded_token_balance(MultiSourceEthRpc(eps), token=TOKEN, contract=CONTRACT)
    assert read.empty and not read.settled and read.finalized_block == chain.head - 20 < FINALIZED


async def test_the_shipped_eth_leg_reads_through_its_own_rpc():
    from tests.test_record_names_its_role_and_keeps_the_push import _shipped_token_eth_leg

    chain = _chain(token_balances={30: 7})
    leg, _seen = _shipped_token_eth_leg([])
    leg._leg._rpc = MultiSourceEthRpc([FakeEvmEndpoint(chain) for _ in range(2)])
    read = await leg.unfunded_token_balance(token=TOKEN, contract=CONTRACT)
    assert read.empty is False and read.finalized_block == FINALIZED

"""The gated explicit abandon, ``SwapCoordinator.abandon_counter_leg`` (#850 PR 7b, design §3.6).

An operator ends a record ABORTED on a counter-leg case that has no automatic end. The chain is read
first with the real reader over the fake EVM chain; the case it shows must be past the timeout at the
finalized block (or settled there), must be accepted from the record's state, and must be the case
the operator named. Nothing is broadcast. The operator's note lives in a sidecar file (D18), and the
record carries only its hash.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json

import pytest

from pyrxd.eth_wallet.disposition import ClaimSeen, CounterDisposition, DispositionKind
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import SwapCoordinator
from pyrxd.gravity.swap_state import AbandonCase, AbortReason, SwapRecord, SwapRole, SwapState
from pyrxd.security.errors import AbandonNotAccepted, NetworkError, ValidationError
from tests._fake_evm_chain import FakeEvmEndpoint
from tests.test_counter_leg_disposition_coordinator import _setup as _native_setup
from tests.test_expired_empty_token_counter_leg import PUSH_NONCE
from tests.test_expired_empty_token_counter_leg import _setup as _token_setup

NOTE = "checked the funding wallet by hand; the push never left it"


class _Sink:
    """A persist hook that also keeps the abandon note, like ``JsonFileRecordSink``."""

    def __init__(self, coord) -> None:
        self.coord = coord
        self.notes: list[bytes] = []

    async def __call__(self, record) -> None:
        self.coord.persisted.append(record)

    def write_abort_note(self, payload: bytes) -> str:
        self.notes.append(bytes(payload))
        return hashlib.sha256(bytes(payload)).hexdigest()


def _with_sink(coord) -> _Sink:
    sink = _Sink(coord)
    coord._persist = sink
    return sink


def _token(*, state=SwapState.BTC_LOCKED, role=SwapRole.TAKER, closed=False):
    """An expired, empty token contract: OPEN (the nonce not past the push) or CLOSED."""
    coord, chain, leg = _token_setup(state=state, role=role, nonces={20: PUSH_NONCE + (1 if closed else 0)})
    return coord, chain, leg, _with_sink(coord)


async def _abandon(coord, case, *, contract=None, note=NOTE):
    return await coord.abandon_counter_leg(
        confirm_contract=contract or coord.record.counterchain_locator.contract_address, reason_code=case, note=note
    )


def _unchanged(coord, sink, state) -> None:
    assert coord.record.state is state and coord.record.abort_reason is None
    assert coord.persisted == [] and sink.notes == []


# --------------------------------------------------------------------------- the accepted cases


async def test_an_open_empty_contract_is_abandoned_with_its_read_and_the_notes_hash():
    coord, chain, leg, sink = _token()
    rec = await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.OPERATOR_ABANDONED
    assert rec.abandon_case is AbandonCase.EXPIRED_EMPTY
    ((note,),) = [sink.notes]
    assert rec.abort_note_sha256 == hashlib.sha256(note).hexdigest()
    side = json.loads(note)
    assert side["note"] == NOTE and side["abandon_case"] == "expired_empty"
    assert side["contract"] == rec.counterchain_locator.contract_address
    ev = rec.counter_disposition
    assert ev.kind == "expired_empty_open" and ev.tx_hash is None and ev.block_number == chain.finalized
    assert ev.block_hash == "0x" + FakeEvmEndpoint(chain)._hash(chain.finalized).hex()
    assert len(ev.sources) == 3 and ev.single_source is False
    assert coord.persisted[-1] == rec and NOTE not in json.dumps(rec.to_dict())  # the record keeps no free text
    assert rec.counterchain_locator is not None  # a refund by address stays possible
    assert leg.closes == [] and leg.refunds == 0


@pytest.mark.parametrize(
    ("state", "role", "closed"),
    [
        (SwapState.PARAMS_MISMATCH, None, True),
        (SwapState.PARAMS_MISMATCH, SwapRole.MAKER, False),
        (SwapState.BOTH_LOCKED, SwapRole.TAKER, False),
        (SwapState.BOTH_LOCKED, SwapRole.TAKER, True),
        (SwapState.BOTH_LOCKED, None, True),
    ],
)
async def test_an_empty_contract_is_abandoned_where_the_table_accepts_it(state, role, closed):
    coord, _chain, _leg, _sink = _token(state=state, role=role, closed=closed)
    rec = await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert rec.state is SwapState.ABORTED and rec.abandon_case is AbandonCase.EXPIRED_EMPTY
    assert rec.counter_disposition.kind == ("expired_empty_closed" if closed else "expired_empty_open")


async def test_a_payout_that_reverts_is_abandoned_on_an_expired_contract():
    coord, chain, leg, sink = _token()
    chain.token_balances[30] = 1_000_000
    leg.revert_reason = "TransferFailed"
    rec = await _abandon(coord, AbandonCase.PAYOUT_REVERTS)
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.kind == "f_expired"
    assert json.loads(sink.notes[0])["read"]["kind"] == "payout_reverts"
    assert leg.refunds == 0


async def test_a_claim_after_a_params_mismatch_is_abandoned():
    coord, chain, _leg = _native_setup(state=SwapState.PARAMS_MISMATCH, role=None, chain_kw={"finalized": 90})
    _with_sink(coord)
    tx = chain.claim(70)
    rec = await _abandon(coord, AbandonCase.CLAIMED_AFTER_MISMATCH)
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.kind == "claimed"
    assert rec.counter_disposition.tx_hash == tx


async def test_a_settlement_that_cannot_be_verified_is_abandoned():
    def blind(chain):
        return [FakeEvmEndpoint(chain, hide_all_logs=True) for _ in range(3)]

    coord, chain, _leg = _native_setup(endpoints=blind, chain_kw={"finalized": 90})
    _with_sink(coord)
    chain.refund(85)
    rec = await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.kind == "unknown"
    assert rec.counter_disposition.tx_hash is None and rec.counter_disposition.block_number == 90


async def test_a_single_source_refund_on_a_value_bearing_chain_is_abandoned(monkeypatch):
    coord, chain, leg = _native_setup(chain_kw={"finalized": 90})
    _with_sink(coord)
    tx = chain.refund(85)
    leg._rpc = FakeEvmEndpoint(chain)
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    rec = await _abandon(coord, AbandonCase.SINGLE_SOURCE_REFUND)
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.kind == "refunded"
    assert rec.counter_disposition.single_source is True and rec.counter_disposition.tx_hash == tx


# --------------------------------------------------------------------------- refused, nothing recorded


async def test_a_case_other_than_the_one_named_is_refused():
    coord, _chain, _leg, sink = _token()
    with pytest.raises(AbandonNotAccepted, match="which is the case expired_empty, not payout_reverts") as e:
        await _abandon(coord, AbandonCase.PAYOUT_REVERTS)
    assert e.value.kind == "expired_empty_open"
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_another_contract_is_refused():
    coord, _chain, _leg, sink = _token()
    with pytest.raises(ValidationError, match="is not this record's counter-leg contract"):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY, contract="0x" + "12" * 20)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_HONEST_the_contract_is_confirmed_in_any_case():
    coord, _chain, _leg, _sink = _token()
    addr = coord.record.counterchain_locator.contract_address
    rec = await _abandon(coord, AbandonCase.EXPIRED_EMPTY, contract=addr.upper().replace("0X", "0x"))
    assert rec.state is SwapState.ABORTED


async def test_a_closed_empty_contract_at_btc_locked_has_its_own_end():
    coord, _chain, _leg, sink = _token(closed=True)
    with pytest.raises(AbandonNotAccepted, match="has its own end") as e:
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert e.value.next_step == "taker_refund_btc"
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.BOTH_LOCKED])
async def test_a_verified_claim_is_never_abandoned_where_it_has_an_edge(state):
    coord, chain, _leg = _native_setup(state=state, chain_kw={"finalized": 90})
    sink = _with_sink(coord)
    chain.claim(70)
    with pytest.raises(AbandonNotAccepted, match="p is public") as e:
        await _abandon(coord, AbandonCase.CLAIMED_AFTER_MISMATCH)
    assert e.value.next_step == "reconcile_counter_leg"
    _unchanged(coord, sink, state)


@pytest.mark.parametrize(
    ("state", "step"), [(SwapState.BTC_LOCKED, "reconcile_counter_leg"), (SwapState.BOTH_LOCKED, "mutual_refund")]
)
async def test_a_refund_verified_at_every_endpoint_has_its_own_end(state, step):
    coord, chain, _leg = _native_setup(state=state, chain_kw={"finalized": 90})
    sink = _with_sink(coord)
    chain.refund(85)
    with pytest.raises(AbandonNotAccepted, match="REFUNDED") as e:
        await _abandon(coord, AbandonCase.SINGLE_SOURCE_REFUND)
    assert e.value.next_step == step
    _unchanged(coord, sink, state)


async def test_tokens_that_can_still_be_refunded_are_not_abandoned():
    coord, chain, leg, sink = _token()
    chain.token_balances[30] = 1_000_000
    leg.revert_reason = None
    with pytest.raises(AbandonNotAccepted, match="would not revert") as e:
        await _abandon(coord, AbandonCase.PAYOUT_REVERTS)
    assert e.value.next_step == "taker_refund_btc"
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_a_contract_not_expired_at_the_finalized_block_is_not_abandoned():
    coord, chain, _leg, sink = _token()
    chain.finalized = 70  # before the timeout block
    with pytest.raises(AbandonNotAccepted, match="a claim may still succeed"):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_an_unknown_read_records_nothing():
    def throttled(chain):
        return [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]

    coord, chain, _leg = _native_setup(endpoints=throttled, chain_kw={"finalized": 90})
    sink = _with_sink(coord)
    chain.refund(85)
    with pytest.raises(NetworkError, match="unknown"):
        await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_a_settlement_with_a_verified_claim_seen_is_not_abandoned(monkeypatch):
    """Settled and unverifiable, but a nominated claim opens H: p is public, and the covenant claim is
    the step. The reader does not produce this combination today; the gate must not depend on that."""
    coord, _chain, _leg, _ = _token()
    sink = _with_sink(coord)
    seen = ClaimSeen(tx_hash="0x" + "c1" * 32, block_number=70, nominated_by=("a",), verified=True)
    read = CounterDisposition(
        DispositionKind.UNKNOWN,
        "settled",
        90,
        settled_at_finalized=True,
        settled_unexplained=True,
        claims_seen=(seen,),
        finalized_hash="0x" + "f9" * 32,
    )

    async def fake_read():
        return read

    monkeypatch.setattr(coord, "_read_counter_disposition", fake_read)
    for verified in (True, False):  # an unverified log that opens H carries p just the same
        read = dataclasses.replace(read, claims_seen=(dataclasses.replace(seen, verified=verified),))
        with pytest.raises(AbandonNotAccepted, match="p is public") as refused:
            await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
        assert refused.value.next_step == "reconcile_counter_leg"
        _unchanged(coord, sink, SwapState.BTC_LOCKED)

    async def fake_read_no_claim():
        return dataclasses.replace(read, claims_seen=())

    monkeypatch.setattr(coord, "_read_counter_disposition", fake_read_no_claim)
    rec = await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)  # honest: no verified claim
    assert rec.state is SwapState.ABORTED


@pytest.mark.parametrize(
    ("state", "role", "why"),
    [
        (SwapState.NEGOTIATED, SwapRole.TAKER, "not valid from negotiated"),
        (SwapState.SECRET_REVEALED, SwapRole.TAKER, "not valid from secret_revealed"),
        (SwapState.BTC_LOCKED, SwapRole.MAKER, "taker's step"),
        (SwapState.BOTH_LOCKED, SwapRole.MAKER, "taker's step"),
    ],
)
async def test_abandon_is_refused_where_the_design_gives_it_no_place(state, role, why):
    coord, _chain, _leg, sink = _token(role=role)
    coord.record = dataclasses.replace(coord.record, state=state)
    with pytest.raises(ValidationError, match=why):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert coord.persisted == [] and sink.notes == []


@pytest.mark.parametrize(
    ("note", "why"),
    [
        ("", "non-empty"),
        ("   ", "non-empty"),
        ("x" * 2001, "at most 2000"),
        ("ok\x1b[2J", "printable"),
        (7, "non-empty"),
    ],
)
async def test_a_bad_note_is_refused(note, why):
    coord, _chain, _leg, sink = _token()
    with pytest.raises(ValidationError, match=why):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY, note=note)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_HONEST_a_note_with_newlines_and_tabs_is_kept():
    coord, _chain, _leg, sink = _token()
    await _abandon(coord, AbandonCase.EXPIRED_EMPTY, note="line one\n\tline two")
    assert json.loads(sink.notes[0])["note"] == "line one\n\tline two"


async def test_a_reason_code_that_is_not_an_abandon_case_is_refused():
    coord, _chain, _leg, sink = _token()
    with pytest.raises(ValidationError, match="must be an AbandonCase"):
        await _abandon(coord, "expired_empty")
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_a_persist_hook_that_cannot_keep_the_note_is_refused():
    coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE})
    with pytest.raises(ValidationError, match="cannot write one"):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert coord.record.state is SwapState.BTC_LOCKED and coord.persisted == []


async def test_a_btc_counter_leg_is_refused():
    from tests.test_swap_coordinator import _coordinator, _terms

    coord = _coordinator(terms=_terms())
    coord.record = dataclasses.replace(coord.record, state=SwapState.BTC_LOCKED)
    sink = _Sink(coord)
    coord.persisted = []
    coord._persist = sink
    with pytest.raises(ValidationError, match="only to an ETH counter leg"):
        await coord.abandon_counter_leg(
            confirm_contract="0x" + "12" * 20, reason_code=AbandonCase.EXPIRED_EMPTY, note=NOTE
        )
    assert sink.notes == []


# --------------------------------------------------------------------------- the shipped sink


async def test_the_shipped_sink_keeps_the_note_beside_the_record_and_the_hash_names_it(tmp_path):
    from pyrxd.gravity.watch.adapters import JsonDirRecordStore

    coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE})
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord._persist = sink
    rec = await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    note = sink.abort_note_path.read_bytes()
    assert hashlib.sha256(note).hexdigest() == rec.abort_note_sha256
    assert json.loads(note)["note"] == NOTE
    assert oct(sink.abort_note_path.stat().st_mode & 0o777) == "0o600"
    assert SwapRecord.from_dict(json.loads((tmp_path / "swap1.json").read_text())) == rec
    # The record store's scan reads records only: the note is not taken for an unreadable record.
    assert sink.abort_note_path.name == "swap1.json.abort-note"
    store = JsonDirRecordStore(tmp_path)
    assert await store.list_active() == [] and store.unreadable == []  # ABORTED, and nothing unreadable


@pytest.mark.parametrize("missing", ["finalized_block", "finalized_hash"])
async def test_a_read_that_names_no_finalized_block_records_nothing(monkeypatch, missing):
    """The record keeps the block the read rests on; a read that cannot name it is not acted on."""
    coord, _chain, _leg, _ = _token()
    sink = _with_sink(coord)
    read = CounterDisposition(
        DispositionKind.UNKNOWN,
        "settled",
        90,
        settled_at_finalized=True,
        settled_unexplained=True,
        finalized_hash="0x" + "f9" * 32,
    )
    read = dataclasses.replace(read, **{missing: None})

    async def fake_read():
        return read

    monkeypatch.setattr(coord, "_read_counter_disposition", fake_read)
    with pytest.raises(NetworkError, match="names no finalized block"):
        await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_only_a_claim_or_a_refund_names_its_transaction_on_the_record(monkeypatch):
    """Evidence that carries a transaction on any other read (the reader does not produce it today) is
    not copied: an abandon-only kind names no transaction, and the record would refuse it."""
    from pyrxd.eth_wallet.disposition import DispositionEvidence

    coord, _chain, _leg, _ = _token()
    _with_sink(coord)
    evidence = DispositionEvidence(
        kind=DispositionKind.UNKNOWN,
        block_number=90,
        block_hash="0x" + "f9" * 32,
        tx_hash="0x" + "c2" * 32,
        sources=("a.test", "b.test"),
        single_source=False,
    )
    read = CounterDisposition(
        DispositionKind.UNKNOWN,
        "settled",
        90,
        evidence=evidence,
        settled_at_finalized=True,
        settled_unexplained=True,
        finalized_hash="0x" + "f9" * 32,
    )

    async def fake_read():
        return read

    monkeypatch.setattr(coord, "_read_counter_disposition", fake_read)
    rec = await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    assert rec.counter_disposition.kind == "unknown" and rec.counter_disposition.tx_hash is None
    assert rec.counter_disposition.sources == ("a.test", "b.test")


@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.BOTH_LOCKED])
async def test_one_endpoint_that_contradicts_a_claim_cannot_make_it_abandonable(state):
    """Review of #850 PR 7b, HIGH: claimed before the timeout, finalized before the timeout, and one
    endpoint of three forges a refund (the claim's log is pruned). The read is UNKNOWN and settled, but
    contradicted, so it is not SETTLED_UNVERIFIABLE: without the forger it reads CLAIMED (Gap B)."""
    forged = "0x" + "fa" * 32

    def lying(chain):
        return [  # the claim's log is pruned everywhere; the third endpoint forges a refund
            FakeEvmEndpoint(chain, hide_claimed=True),
            FakeEvmEndpoint(chain, hide_claimed=True),
            FakeEvmEndpoint(chain, hide_claimed=True, forge_refunded_tx=forged, forge_receipt=True),
        ]

    coord, chain, _leg = _native_setup(state=state, endpoints=lying, chain_kw={"finalized": 75})
    sink = _with_sink(coord)
    chain.claim(70)
    read = await coord._read_counter_disposition()
    assert read.kind is DispositionKind.UNKNOWN and read.settled_at_finalized and not read.settled_unexplained
    with pytest.raises(NetworkError, match="unknown"):
        await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    _unchanged(coord, sink, state)
    honest, chain2, _l = _native_setup(
        state=state,
        endpoints=lambda c: [FakeEvmEndpoint(c, hide_claimed=True) for _ in range(3)],
        chain_kw={"finalized": 75},
    )
    chain2.claim(70)
    assert (await honest._read_counter_disposition()).kind is DispositionKind.CLAIMED  # Gap B


@pytest.mark.parametrize("n", [2, 3])
async def test_a_claim_log_hidden_while_the_other_endpoints_fail_is_not_abandoned(n):
    """Re-review of #850 PR 7b, MEDIUM: claimed before the timeout, finalized past it. One endpoint
    hides the Claimed log and every other endpoint's log scan fails. The scan is partial, so the read
    is not SETTLED_UNVERIFIABLE: a retry may show the claim and ``p``."""

    def partial(chain):
        return [FakeEvmEndpoint(chain, hide_claimed=True)] + [
            FakeEvmEndpoint(chain, logs_429=True) for _ in range(n - 1)
        ]

    coord, chain, _leg = _native_setup(endpoints=partial, chain_kw={"finalized": 90})
    sink = _with_sink(coord)
    chain.claim(70)
    read = await coord._read_counter_disposition()
    assert read.kind is DispositionKind.UNKNOWN and read.logs_failed and not read.settled_unexplained
    with pytest.raises(NetworkError, match="unknown"):
        await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)
    honest, chain2, _l = _native_setup(chain_kw={"finalized": 90})
    chain2.claim(70)
    assert (await honest._read_counter_disposition()).kind is DispositionKind.CLAIMED


async def test_a_cancelled_abandon_keeps_what_the_disk_holds():
    """Re-review of #850 PR 7b, LOW: the shielded persist finishes after a cancellation, so the
    record in memory is the ABORTED one the disk holds, not the state before."""
    coord, _chain, _leg, sink = _token()
    gate = asyncio.Event()

    class _Slow(_Sink):
        async def __call__(self, record) -> None:
            await gate.wait()
            self.coord.persisted.append(record)

    sink.__class__ = _Slow
    task = asyncio.ensure_future(_abandon(coord, AbandonCase.EXPIRED_EMPTY))
    for _ in range(200):
        if sink.notes:
            break
        await asyncio.sleep(0)
    assert sink.notes  # the persist has started
    await asyncio.sleep(0)
    task.cancel()
    gate.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    for _ in range(20):
        await asyncio.sleep(0)
    assert [r.state for r in coord.persisted] == [SwapState.ABORTED]
    assert coord.record.state is SwapState.ABORTED and coord.record == coord.persisted[0]


async def test_a_failed_persist_leaves_the_record_as_it_was():
    """The abandon is taken only once it is durable: a persist that fails leaves memory as the disk
    has it, so a retry reads the chain again rather than finding an ABORTED record in memory."""
    coord, _chain, _leg, sink = _token()

    async def broken(_record):
        raise OSError("disk full")

    sink.coord.persisted.clear()
    coord._persist = sink
    sink.__class__ = type("_BrokenSink", (_Sink,), {"__call__": lambda self, r: broken(r)})
    with pytest.raises(OSError, match="disk full"):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert coord.record.state is SwapState.BTC_LOCKED and coord.record.abort_reason is None
    assert coord.record.abandon_case is None


async def test_every_claim_log_seen_is_kept_in_the_note():
    """D14 leaves the abandon to the operator while a Claimed log is seen; the evidence is kept."""
    coord, chain, leg, sink = _token()
    chain.token_balances[30] = 1_000_000
    leg.revert_reason = "TransferFailed"
    seen = ClaimSeen(tx_hash="0x" + "c3" * 32, block_number=70, nominated_by=("a",), verified=False)
    real = coord._read_counter_disposition

    async def with_a_claim():
        return dataclasses.replace(await real(), claims_seen=(seen,))

    coord._read_counter_disposition = with_a_claim
    await _abandon(coord, AbandonCase.PAYOUT_REVERTS)
    kept = json.loads(sink.notes[0])["read"]["claims_seen"]
    assert kept == [{"tx_hash": seen.tx_hash, "block_number": 70, "verified": False}]


# --------------------------------------------------------------------------- Mythos review of 7b


def _blind(chain):
    return [FakeEvmEndpoint(chain, hide_all_logs=True) for _ in range(3)]


async def test_a_claim_on_record_is_read_by_its_receipt_when_its_log_is_gone():
    """F1: a claim an earlier read saw (``counter_claim_tx``) and whose log no endpoint serves any more.
    The record nominates it, its receipt verifies, and the read is CLAIMED: p is public, so no abandon."""
    coord, chain, _leg = _native_setup(endpoints=_blind, chain_kw={"finalized": 90})
    sink = _with_sink(coord)
    tx = chain.claim(70)
    coord.record = dataclasses.replace(coord.record, counter_claim_tx=tx)
    read = await coord._read_counter_disposition()
    assert read.kind is DispositionKind.CLAIMED and read.evidence.tx_hash == tx
    with pytest.raises(AbandonNotAccepted, match="p is public") as refused:
        await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    assert refused.value.next_step == "reconcile_counter_leg"
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_a_claim_on_record_holds_a_settlement_its_receipt_cannot_show(monkeypatch):
    """F1: the recorded claim holds ``SETTLED_UNVERIFIABLE`` even when the read shows no claim at all."""
    coord, _chain, _leg, _ = _token()
    sink = _with_sink(coord)
    coord.record = dataclasses.replace(coord.record, counter_claim_tx="0x" + "c7" * 32)
    read = CounterDisposition(
        DispositionKind.UNKNOWN,
        "settled",
        90,
        settled_at_finalized=True,
        settled_unexplained=True,
        finalized_hash="0x" + "f9" * 32,
    )

    async def fake_read():
        return read

    monkeypatch.setattr(coord, "_read_counter_disposition", fake_read)
    with pytest.raises(AbandonNotAccepted, match="seen or on record, so p is public"):
        await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    _unchanged(coord, sink, SwapState.BTC_LOCKED)


async def test_HONEST_a_claim_the_record_names_is_nominated_only_when_there_is_one():
    coord, chain, leg = _native_setup(endpoints=_blind, chain_kw={"finalized": 90})
    _with_sink(coord)
    chain.refund(85)
    seen = []
    real = leg.counter_disposition

    async def spy(locator, **kw):
        seen.append(kw.get("recorded_claim_hashes"))
        return await real(locator, **kw)

    leg.counter_disposition = spy
    rec = await _abandon(coord, AbandonCase.SETTLED_UNVERIFIABLE)
    assert rec.state is SwapState.ABORTED and seen == [None]


def _one_endpoint_case(case):
    """A record whose counter leg is read from ONE endpoint, showing *case*."""
    if case is AbandonCase.EXPIRED_EMPTY:
        coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE}, endpoints=lambda c: [FakeEvmEndpoint(c)])
        return coord
    if case is AbandonCase.PAYOUT_REVERTS:
        coord, chain, leg = _token_setup(nonces={20: PUSH_NONCE}, endpoints=lambda c: [FakeEvmEndpoint(c)])
        chain.token_balances[30] = 1_000_000
        leg.revert_reason = "TransferFailed"
        return coord
    if case is AbandonCase.SETTLED_UNVERIFIABLE:
        coord, chain, leg = _native_setup(chain_kw={"finalized": 90})
        chain.refund(85)
        leg._rpc = FakeEvmEndpoint(chain, hide_all_logs=True)
        return coord
    coord, chain, leg = _native_setup(state=SwapState.PARAMS_MISMATCH, role=None, chain_kw={"finalized": 90})
    chain.claim(70)
    leg._rpc = FakeEvmEndpoint(chain)
    return coord


_ONE_ENDPOINT_CASES = [
    AbandonCase.EXPIRED_EMPTY,
    AbandonCase.PAYOUT_REVERTS,
    AbandonCase.SETTLED_UNVERIFIABLE,
    AbandonCase.CLAIMED_AFTER_MISMATCH,
]


@pytest.mark.parametrize("case", _ONE_ENDPOINT_CASES)
async def test_one_endpoint_on_a_chain_that_carries_value_ends_no_record(monkeypatch, case):
    """F2 / D4: only a one-endpoint refund is accepted on a value-bearing chain (SINGLE_SOURCE_REFUND)."""
    coord = _one_endpoint_case(case)
    sink = _with_sink(coord)
    state = coord.record.state
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    with pytest.raises(NetworkError, match="from one endpoint, on a chain that carries value"):
        await _abandon(coord, case)
    _unchanged(coord, sink, state)


@pytest.mark.parametrize("case", _ONE_ENDPOINT_CASES)
async def test_HONEST_one_endpoint_on_a_testnet_may_end_a_record(monkeypatch, case):
    coord = _one_endpoint_case(case)
    _with_sink(coord)
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: True))
    rec = await _abandon(coord, case)
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.single_source is True


async def test_a_claim_log_the_read_saw_goes_on_the_aborted_record():
    """F3: the record keeps the claim as well as the note, so what reads the record later sees p may be public."""
    coord, chain, leg, _sink = _token()
    chain.token_balances[30] = 1_000_000
    leg.revert_reason = "TransferFailed"
    seen = ClaimSeen(tx_hash="0x" + "c4" * 32, block_number=70, nominated_by=("a",), verified=False)
    real = coord._read_counter_disposition

    async def with_a_claim():
        return dataclasses.replace(await real(), claims_seen=(seen,))

    coord._read_counter_disposition = with_a_claim
    rec = await _abandon(coord, AbandonCase.PAYOUT_REVERTS)
    assert rec.state is SwapState.ABORTED and rec.counter_claim_tx == seen.tx_hash
    assert SwapRecord.from_dict(rec.to_dict()).counter_claim_tx == seen.tx_hash


@pytest.mark.parametrize("newer", ["revealed", "claim_recorded"])
async def test_a_record_on_disk_that_moved_on_is_never_abandoned_over(tmp_path, newer):
    """F4: a coordinator built on a stale record must not write an abandon beside a newer record on disk."""
    coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE})
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    if newer == "revealed":
        on_disk = dataclasses.replace(coord.record, state=SwapState.SECRET_REVEALED)
    else:
        on_disk = dataclasses.replace(coord.record, counter_claim_tx="0x" + "c5" * 32)
    await sink(on_disk)
    before = (tmp_path / "swap.json").read_text()
    coord._persist = sink
    with pytest.raises(ValidationError, match="rebuild the coordinator from the record on disk"):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert (tmp_path / "swap.json").read_text() == before and not sink.abort_note_path.exists()
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_HONEST_the_record_on_disk_it_was_built_from_is_abandoned(tmp_path):
    coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE})
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(coord.record)
    coord._persist = sink
    rec = await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert rec.state is SwapState.ABORTED and sink.load_record() == rec


async def test_a_record_on_disk_that_moves_on_during_the_read_is_not_abandoned_over(tmp_path):
    """F4, re-review: the record on disk is checked again once the (long) read is done, so a reveal
    written by another process while the read ran is not written over."""
    coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE})
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(coord.record)
    coord._persist = sink
    real = coord._read_counter_disposition

    async def a_reveal_lands_meanwhile():
        read = await real()
        await sink(dataclasses.replace(coord.record, state=SwapState.SECRET_REVEALED))
        return read

    coord._read_counter_disposition = a_reveal_lands_meanwhile
    with pytest.raises(ValidationError, match="rebuild the coordinator from the record on disk"):
        await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    assert sink.load_record().state is SwapState.SECRET_REVEALED and sink.load_record().abort_reason is None
    assert not sink.abort_note_path.exists() and coord.record.state is SwapState.BTC_LOCKED


async def test_the_sink_refuses_a_merged_write_that_would_not_load(tmp_path):
    """An abandon written over a revealed record keeps the revealed state beside the abandon fields,
    which no reader accepts; the sink refuses it and the file stays the record that loads."""
    coord, _chain, _leg, _ = _token()
    revealed = dataclasses.replace(coord.record, state=SwapState.SECRET_REVEALED)
    aborted = await _abandon(coord, AbandonCase.EXPIRED_EMPTY)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(revealed)
    before = (tmp_path / "swap.json").read_text()
    with pytest.raises(ValidationError, match="would not load.*The record on disk is unchanged"):
        await sink(aborted)
    assert (tmp_path / "swap.json").read_text() == before


async def test_HONEST_the_sink_still_keeps_a_reveal_under_a_rewound_write(tmp_path):
    coord, _chain, _leg = _token_setup(nonces={20: PUSH_NONCE})
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    await sink(dataclasses.replace(coord.record, state=SwapState.SECRET_REVEALED))
    await sink(dataclasses.replace(coord.record, counter_claim_tx="0x" + "c6" * 32))
    kept = sink.load_record()
    assert kept.state is SwapState.SECRET_REVEALED and kept.counter_claim_tx == "0x" + "c6" * 32


async def test_a_verified_claim_is_the_one_the_aborted_record_names():
    coord, chain, leg, _sink = _token()
    chain.token_balances[30] = 1_000_000
    leg.revert_reason = "TransferFailed"
    guessed = ClaimSeen(tx_hash="0x" + "c1" * 32, block_number=70, nominated_by=("a",), verified=False)
    proven = ClaimSeen(tx_hash="0x" + "c2" * 32, block_number=71, nominated_by=("b",), verified=True)
    real = coord._read_counter_disposition

    async def with_two_claims():
        return dataclasses.replace(await real(), claims_seen=(guessed, proven))

    coord._read_counter_disposition = with_two_claims
    rec = await _abandon(coord, AbandonCase.PAYOUT_REVERTS)
    assert rec.state is SwapState.ABORTED and rec.counter_claim_tx == proven.tx_hash


def test_a_record_may_not_carry_an_abandon_before_it_is_aborted():
    from pyrxd.security.errors import ValidationError as VE

    coord, _chain, _leg, _ = _token()
    d = coord.record.to_dict()
    d.update(abort_reason="operator_abandoned", abandon_case="payout_reverts", abort_note_sha256="0" * 64)
    with pytest.raises(VE, match="ABORTED record"):
        SwapRecord.from_dict(d)

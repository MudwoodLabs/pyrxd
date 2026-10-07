"""A BTC fund whose post-broadcast readback fails must stay recoverable, in-band.

``BitcoinTaprootLeg.fund`` broadcasts the funding transaction and THEN reads the amount back. The
readback can fail after the broadcast succeeded — a confirmation slower than
``fund_confirm_timeout_s``, a transport error — and before this fix that left real BTC on chain under
a NEGOTIATED record with no locator and H reserved: a retry was refused as "hashlock H reused",
``taker_refund_btc`` and ``mutual_refund`` refused from NEGOTIATED, the watchtower read the record
as "no action due", and the operator had no durable copy of the funding outpoint that ``swap status``
asks for. Found by the 2026-10-07 calibration review (finding F-3) and
reproduced on unplanted main.

Every test here drives the REAL :class:`BitcoinTaprootLeg` through the coordinator's production entry
points (``taker_funds_btc``, ``resume_interrupted_fund`` with a real :class:`JsonFileRecordSink`); the
fake leg in ``test_swap_coordinator.py`` builds no transaction and cannot exercise any of this.
"""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_state import SwapRecord, SwapState
from pyrxd.security.errors import InsufficientConfirmationsError, NetworkError, ValidationError
from tests import test_taker_asset_funding_gate_adversarial as A
from tests import test_taker_funding_spv_gate as T


class _Btc(A._BtcChainView):
    """The BTC node, with a readback whose answer the test controls. ``events`` interleaves with the
    persist log so a test can prove the funding bytes were durable BEFORE they were broadcast."""

    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events
        self.read = "ok"  # "ok" | "unconfirmed" | "network"

    async def broadcast(self, raw_tx: bytes) -> str:
        self.events.append("broadcast")
        return await super().broadcast(raw_tx)

    async def read_output_amount_sats(self, txid, vout, *, min_confirmations):
        if self.read == "unconfirmed":
            raise InsufficientConfirmationsError(have=0, required=min_confirmations)
        if self.read == "network":
            raise NetworkError("transport failure reading the funding output")
        return await super().read_output_amount_sats(txid, vout, min_confirmations=min_confirmations)


def _coord(*, persist="log", radiant_view=None, terms=None):
    """A regtest taker coordinator over the real BTC leg, its BTC view, its terms, and the shared event log."""
    events: list[str] = []
    terms = terms or T._ab_terms(90)
    view = radiant_view or T._ChainView(pays=T._covenant(terms), value=terms.radiant_amount, confs=6)
    btc = _Btc(events)

    async def _log_sink(record):
        events.append("persist:pending" if record.pending_btc_funding_tx else "persist")

    sink = _log_sink if persist == "log" else persist
    coord, _ = T._btc_coord(terms, T._real_leg(view, network="bcrt"), btc_view=btc, persist=sink)
    return coord, btc, terms, events


def test_a_failed_readback_leaves_the_funding_tx_on_the_record_and_names_it():
    coord, btc, terms, events = _coord()
    btc.read = "network"
    with pytest.raises(NetworkError) as exc:
        asyncio.run(coord.taker_funds_btc(terms))
    assert len(btc.broadcasts) == 1
    sent_txid = t.btc_txid_from_raw(btc.broadcasts[0])
    rec = coord.record
    assert rec.state is SwapState.NEGOTIATED and rec.counterchain_locator is None
    # The record carries EXACTLY the bytes that were broadcast, and the error names their txid.
    assert bytes.fromhex(rec.pending_btc_funding_tx) == btc.broadcasts[0]
    assert rec.pending_btc_funding_txid == sent_txid
    assert sent_txid in str(exc.value)
    # Durable BEFORE the broadcast — the only moment the bytes are certain to be ours and unsent.
    assert events.index("persist:pending") < events.index("broadcast")


def test_a_resume_after_the_funding_confirms_records_the_lock_without_sending_again():
    coord, btc, terms, _ = _coord()
    btc.read = "unconfirmed"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    recorded = coord.record.pending_btc_funding_txid
    btc.read = "ok"  # it confirmed
    rec = asyncio.run(coord.taker_funds_btc(terms))
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.counterchain_locator.funding_outpoint.txid == recorded
    assert rec.pending_btc_funding_tx is None  # superseded by the locator
    assert len(btc.broadcasts) == 1  # found on chain: nothing re-sent


def test_a_resume_of_an_unconfirmed_fund_resends_the_SAME_bytes():
    coord, btc, terms, _ = _coord()
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    first = btc.broadcasts[0]

    reads = {"n": 0}
    orig = btc.read_output_amount_sats

    async def unconfirmed_then_ok(txid, vout, *, min_confirmations):
        reads["n"] += 1
        if reads["n"] == 1:  # the resume's "already confirmed?" read: not yet
            raise InsufficientConfirmationsError(have=0, required=min_confirmations)
        btc.read = "ok"
        return await orig(txid, vout, min_confirmations=min_confirmations)

    btc.read_output_amount_sats = unconfirmed_then_ok
    rec = asyncio.run(coord.taker_funds_btc(terms))
    assert rec.state is SwapState.BTC_LOCKED
    assert len(btc.broadcasts) == 2 and btc.broadcasts[1] == first  # same bytes, so it cannot fund twice


def test_a_resume_the_gate_now_refuses_sends_nothing_and_keeps_the_record():
    terms = T._ab_terms(90)
    view = T._ChainView(pays=T._covenant(terms), value=terms.radiant_amount, confs=6)
    coord, btc, terms, _ = _coord(radiant_view=view, terms=terms)
    btc.read = "unconfirmed"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    before = coord.record
    view.listed_spk = b"\x51"  # the maker's covenant is gone (listunspent finds nothing): the gate must refuse
    with pytest.raises(ValidationError):
        asyncio.run(coord.taker_funds_btc(terms))
    assert len(btc.broadcasts) == 1  # never re-sent under a refused gate
    assert coord.record.pending_btc_funding_tx == before.pending_btc_funding_tx
    assert coord.record.state is SwapState.NEGOTIATED


def test_resume_interrupted_fund_completes_from_the_record_file(tmp_path):
    """The production read side: the record a crashed run left in its JsonFileRecordSink."""
    sink = JsonFileRecordSink(tmp_path / "swap.swaprec.json")
    coord, btc, terms, _ = _coord(persist=sink)
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    on_disk = sink.load_record()
    assert isinstance(on_disk, SwapRecord) and on_disk.pending_btc_funding_tx is not None

    coord.record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms)  # a fresh process: nothing in memory
    btc.read = "ok"
    rec = asyncio.run(coord.resume_interrupted_fund(terms, sink=sink, now_unix_s=None))
    assert rec.state is SwapState.BTC_LOCKED
    assert rec.counterchain_locator.funding_outpoint.txid == on_disk.pending_btc_funding_txid
    assert sink.load_record().state is SwapState.BTC_LOCKED
    assert len(btc.broadcasts) == 1


async def test_a_value_bearing_btc_fund_without_a_persist_hook_is_refused_before_anything_is_sent(monkeypatch):
    """The honest value-bearing setup of ``test_honest_value_bearing_funding_verifies_and_the_lock_proceeds``
    — a fund that passes every gate — minus the persist hook: refused before the broadcast."""
    base, _chain = T._value_bearing_chain(monkeypatch)
    terms = T._vb_terms(400)
    view = T._ChainView(
        pays=T._covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=T._HARD_BITS, tip_time=T._NOW
    )
    coord, btc = T._btc_coord(
        terms, T._real_leg(view, network="bc"), policy=T._vb_policy(), accept_nondurable_seen=True, persist=None
    )
    with pytest.raises(ValidationError, match="durable persist hook"):
        await coord.taker_funds_btc(terms, now_unix_s=T._NOW)
    assert btc.broadcasts == []
    assert coord.record.state is SwapState.NEGOTIATED


def test_a_regtest_btc_fund_without_a_persist_hook_still_funds():
    """The honest path the guard must not refuse: nothing of value is at stake on regtest."""
    coord, btc, terms, _ = _coord(persist=None)
    rec = asyncio.run(coord.taker_funds_btc(terms))
    assert rec.state is SwapState.BTC_LOCKED and len(btc.broadcasts) == 1


def test_a_recorded_tx_that_does_not_pay_this_htlc_is_refused_not_broadcast():
    coord, btc, terms, _ = _coord()
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    other, _b, _t, _e = _coord()  # a different swap's funding transaction
    other_btc = other.counter_leg.broadcaster
    other_btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(other.taker_funds_btc(other.record.terms))
    import dataclasses

    coord.record = dataclasses.replace(coord.record, pending_btc_funding_tx=other.record.pending_btc_funding_tx)
    with pytest.raises(ValidationError, match="does not pay this swap's HTLC"):
        asyncio.run(coord.taker_funds_btc(terms))
    assert len(btc.broadcasts) == 1


def test_a_confirmed_fund_is_recorded_even_when_the_seen_store_lost_its_hashlock():
    """Recording an output already on chain sends nothing, so it needs no reservation — refusing here
    re-created the original stranding (adversarial review M2)."""
    coord, btc, terms, _ = _coord()
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    coord.seen_store._seen.clear()  # a restored backup / rotated store: the stores have diverged
    btc.read = "ok"  # ...and the fund confirmed
    rec = asyncio.run(coord.taker_funds_btc(terms))
    assert rec.state is SwapState.BTC_LOCKED
    assert len(btc.broadcasts) == 1


def test_an_unconfirmed_fund_is_not_re_sent_when_the_seen_store_lost_its_hashlock():
    coord, btc, terms, _ = _coord()
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    coord.seen_store._seen.clear()
    btc.read = "unconfirmed"
    with pytest.raises(ValidationError, match="NOT reserved"):
        asyncio.run(coord.taker_funds_btc(terms))
    assert len(btc.broadcasts) == 1  # not re-sent


def test_a_failed_pre_broadcast_write_sends_nothing_and_claims_nothing():
    """If the durable write of the bytes fails, the leg never broadcasts — and the record and the error
    must not claim a transaction was recorded (adversarial review LOW-4)."""

    async def _sink(record):
        if record.pending_btc_funding_tx:
            raise OSError("disk full")

    coord, btc, terms, _ = _coord(persist=_sink)
    with pytest.raises(OSError, match="disk full"):
        asyncio.run(coord.taker_funds_btc(terms))
    assert btc.broadcasts == []
    assert coord.record.pending_btc_funding_tx is None


def test_a_resume_with_different_terms_under_the_same_hashlock_is_refused(tmp_path):
    import dataclasses

    sink = JsonFileRecordSink(tmp_path / "swap.swaprec.json")
    coord, btc, terms, _ = _coord(persist=sink)
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    drifted = dataclasses.replace(terms, radiant_amount=terms.radiant_amount + 1)
    with pytest.raises(ValidationError, match="different parameters"):
        asyncio.run(coord.resume_interrupted_fund(drifted, sink=sink, now_unix_s=None))
    assert len(btc.broadcasts) == 1


# --------------------------------------------------------------------------- the record field


def test_the_pending_field_round_trips_and_is_cleared_by_the_lock():
    coord, btc, terms, _ = _coord()
    btc.read = "network"
    with pytest.raises(NetworkError):
        asyncio.run(coord.taker_funds_btc(terms))
    rec = coord.record
    back = SwapRecord.from_dict(rec.to_dict())
    assert back.pending_btc_funding_tx == rec.pending_btc_funding_tx
    # Absent -> not written, so a record without it keeps its existing wire form.
    assert "pending_btc_funding_tx" not in SwapRecord(state=SwapState.NEGOTIATED, terms=terms).to_dict()


def test_the_pending_field_refuses_bytes_that_are_not_a_transaction():
    terms = T._ab_terms(90)
    with pytest.raises(ValidationError):
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms, pending_btc_funding_tx="zz")
    with pytest.raises(ValidationError):
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms, pending_btc_funding_tx="00" * 10)  # not a tx

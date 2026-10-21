"""A landed fund resumed in a FRESH process pins the maker's covenant, as a fresh fund does (#850 PR 1b).

Found by the security review of PR 1b (MEDIUM): the pin came only from the lock-time re-run, which
the resume-landed path skips, so a taker record resumed after a crash was BTC_LOCKED, role=taker,
unpinned. The tower reads the covenant only through the pin, so it armed the autonomous BTC refund
with "maker never locked" text while the covenant was on chain: the case PR 1b exists to stop.

Reached through the production path: a real coordinator and leg, a real ``JsonFileRecordSink``, a
second coordinator instance resuming from the file, and the production ``Reconciler`` /
``ChainObserver`` / ``JsonDirRecordStore`` reading what was written.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.gravity.watch import Reconciler
from pyrxd.gravity.watch.adapters import JsonDirRecordStore
from pyrxd.gravity.watch.quorum import BtcClaimStatus, ChainObserver
from pyrxd.security.errors import NetworkError
from tests import test_btc_fund_interrupted_resume as R
from tests import test_taker_funding_spv_gate as T
from tests.test_watch_quorum import FakeRxd, _policy


class _Btc:
    def __init__(self, funding: int) -> None:
        self.funding = funding

    async def claim_status(self, txid, vout):
        return BtcClaimStatus(claimed=False)

    async def confirmations(self, txid):
        return 0

    async def funding_confirmations(self, txid):
        return self.funding


class _Spy:
    def __init__(self) -> None:
        self.seen: list = []

    async def execute(self, swap_id, record, decision):
        self.seen.append(decision)

    async def handle(self, swap_id, decision):
        self.seen.append(decision)


def _coordinator(sink, terms=None):
    terms = terms or T._ab_terms(90)
    view = T._ChainView(pays=T._covenant(terms), value=terms.radiant_amount, confs=6)
    btc = R._Btc([])
    coord, _ = T._btc_coord(terms, T._real_leg(view, network="bcrt"), btc_view=btc, persist=sink, role=SwapRole.TAKER)
    return coord, btc, terms, view


async def _crash_then_resume(tmp_path: Path, *, break_reproof: bool = False, older_record: bool = False):
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc, terms, _view = _coordinator(sink)
    btc.read = "network"  # the broadcast lands; the readback fails
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms)
    if older_record:
        # What a version that did not write the pin ahead left on disk at the same moment.
        crashed = sink.load_record()
        await sink(dataclasses.replace(crashed, radiant_covenant_outpoint=None, radiant_covenant_spk_hex=None))
    fresh, _b, _t, _v = _coordinator(sink, terms=terms)  # a new process
    fresh.counter_leg = coord.counter_leg  # the same chain view, so the landed tx is found
    btc.read = "ok"
    if break_reproof:

        async def _gone(*_a, **_k):
            raise NetworkError("covenant read failed")

        fresh.taker_verify_asset_funding = _gone
    await fresh.resume_interrupted_fund(terms, sink=sink, now_unix_s=None)
    return sink.load_record()


async def _tower(tmp_path: Path, record):
    spy = _Spy()
    rec = Reconciler(
        store=JsonDirRecordStore(tmp_path),
        observer=ChainObserver(rxd=FakeRxd(tip=1000, cov_confs=50), btc=_Btc(record.terms.t_btc.value)),
        alerter=spy,
        policy=_policy(),
        safety_window_blocks=6,
        executor=spy,
    )
    return (await rec.tick())[0].decision


async def test_a_resumed_landed_fund_is_pinned_and_the_tower_does_not_arm_autonomy(tmp_path):
    record = await _crash_then_resume(tmp_path)
    assert record.state is SwapState.BTC_LOCKED and record.role is not None
    assert record.radiant_covenant_outpoint is not None
    decision = await _tower(tmp_path, record)
    assert decision.autonomous_btc_refund is False
    assert "maker never locked" not in decision.reason


async def test_the_pin_is_on_disk_before_the_broadcast_so_a_resume_needs_no_reproof(tmp_path):
    """The rare leftover of PR 1b: a resume whose re-proof failed stayed unpinned. The proof is now
    written ahead with the funding bytes, so the crashed record already carries it."""
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc, terms, _view = _coordinator(sink)
    btc.read = "network"
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms)
    crashed = sink.load_record()
    assert crashed.state is SwapState.NEGOTIATED and crashed.pending_btc_funding_tx is not None
    assert crashed.radiant_covenant_outpoint is not None
    (tmp_path / "again").mkdir()
    record = await _crash_then_resume(tmp_path / "again", break_reproof=True)
    assert record.state is SwapState.BTC_LOCKED and record.radiant_covenant_outpoint is not None


async def test_a_pinned_record_is_not_reproved_on_resume(tmp_path, caplog):
    """Review of the write-ahead (F3): a pinned record was re-proved anyway, and a failed re-proof
    logged "without pinning" over a record that was pinned."""
    import logging

    caplog.set_level(logging.WARNING)
    record = await _crash_then_resume(tmp_path, break_reproof=True)
    assert record.radiant_covenant_outpoint is not None
    assert not [r for r in caplog.records if "without pinning" in r.getMessage()]


async def test_an_older_record_whose_reproof_fails_still_records_the_lock_unpinned(tmp_path):
    """Recording the landed lock never depends on the re-proof: the funds already moved."""
    record = await _crash_then_resume(tmp_path, break_reproof=True, older_record=True)
    assert record.state is SwapState.BTC_LOCKED
    assert record.radiant_covenant_outpoint is None


async def test_an_older_record_is_pinned_by_the_reproof(tmp_path):
    record = await _crash_then_resume(tmp_path, older_record=True)
    assert record.radiant_covenant_outpoint is not None


# --------------------------------------------------------------------------- a value-bearing chain


def _vb_coordinator(sink, base, terms):
    view = T._ChainView(
        pays=T._covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=T._HARD_BITS, tip_time=T._NOW
    )
    btc = R._Btc([])
    coord, _ = T._btc_coord(
        terms,
        T._real_leg(view, network="bc"),
        btc_view=btc,
        persist=sink,
        role=SwapRole.TAKER,
        policy=T._vb_policy(),
        accept_nondurable_seen=True,
    )
    return coord, btc


async def test_on_a_value_bearing_chain_the_resumed_fund_is_pinned_too(tmp_path, monkeypatch):
    """Mythos review of PR 1b (MEDIUM): the re-proof ran without the caller's clock, and on a
    value-bearing chain the proof refuses without one, so the pin never happened where it matters.
    The regtest tests above could not see it: there the clock is optional."""
    base, _chain = T._value_bearing_chain(monkeypatch)
    terms = T._vb_terms(400)
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc = _vb_coordinator(sink, base, terms)
    btc.read = "network"  # the broadcast lands; the readback fails
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms, now_unix_s=T._NOW)
    fresh, _btc = _vb_coordinator(sink, base, terms)  # a new process
    fresh.counter_leg = coord.counter_leg
    btc.read = "ok"
    await fresh.resume_interrupted_fund(terms, sink=sink, now_unix_s=T._NOW)
    record = sink.load_record()
    assert record.state is SwapState.BTC_LOCKED
    assert record.radiant_covenant_outpoint is not None
    decision = await _tower(tmp_path, record)
    assert decision.autonomous_btc_refund is False
    assert "maker never locked" not in decision.reason


async def test_a_reused_coordinators_stale_proof_never_replaces_the_pin_on_disk(tmp_path):
    """Review of the write-ahead, round 2: the lock record now always applies this call's proof, so a
    proof left on the coordinator object by an EARLIER fund must not survive into this one."""
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc, terms, _view = _coordinator(sink)
    btc.read = "network"
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms)
    pinned = sink.load_record().radiant_covenant_outpoint
    fresh, _b, _t, _v = _coordinator(sink, terms=terms)
    fresh.counter_leg = coord.counter_leg
    fresh._fund_verified_covenant = ("aa" * 32 + ":5", "51")  # another swap's proof, left behind
    btc.read = "ok"
    await fresh.resume_interrupted_fund(terms, sink=sink, now_unix_s=None)
    assert sink.load_record().radiant_covenant_outpoint == pinned


async def test_on_a_value_bearing_chain_an_older_records_reproof_uses_the_clock(tmp_path, monkeypatch):
    """Mythos review of #891, F1: with the write-ahead the value-bearing test above takes the
    "already pinned" branch, so it no longer guarded the #888 fix (the re-proof's clock). A record
    from an older version, with no pin, still needs that re-proof on mainnet."""
    base, _chain = T._value_bearing_chain(monkeypatch)
    terms = T._vb_terms(400)
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc = _vb_coordinator(sink, base, terms)
    btc.read = "network"
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms, now_unix_s=T._NOW)
    crashed = sink.load_record()
    await sink(dataclasses.replace(crashed, radiant_covenant_outpoint=None, radiant_covenant_spk_hex=None))
    fresh, _btc = _vb_coordinator(sink, base, terms)
    fresh.counter_leg = coord.counter_leg
    btc.read = "ok"
    await fresh.resume_interrupted_fund(terms, sink=sink, now_unix_s=T._NOW)
    record = sink.load_record()
    assert record.state is SwapState.BTC_LOCKED and record.radiant_covenant_outpoint is not None


async def test_the_tower_does_not_read_the_covenant_of_a_negotiated_record(tmp_path):
    """Mythos review of #891, F3: a crash now leaves a NEGOTIATED record pinned. Reading its covenant
    gained nothing (decide() only watches NEGOTIATED) and paged "reconcile error" every tick when the
    RXD source was below quorum."""
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc, terms, _view = _coordinator(sink)
    btc.read = "network"
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms)
    record = sink.load_record()
    assert record.state is SwapState.NEGOTIATED and record.radiant_covenant_outpoint is not None

    class _BelowQuorum(FakeRxd):
        async def covenant_confirmations(self, outpoint):
            raise NetworkError("covenant_confirmations: below quorum")

    obs = await ChainObserver(rxd=_BelowQuorum(tip=1000, cov_confs=50), btc=_Btc(0)).observe("swap1", record)
    assert obs.asset_locked_at_height is None

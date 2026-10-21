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


async def _crash_then_resume(tmp_path: Path, *, break_reproof: bool = False):
    sink = JsonFileRecordSink(tmp_path / "swap1.json")
    coord, btc, terms, _view = _coordinator(sink)
    btc.read = "network"  # the broadcast lands; the readback fails
    with pytest.raises(NetworkError):
        await coord.taker_funds_btc(terms)
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


async def test_a_failed_reproof_still_records_the_lock_unpinned(tmp_path):
    """Recording the landed lock never depends on the re-proof: the funds already moved."""
    record = await _crash_then_resume(tmp_path, break_reproof=True)
    assert record.state is SwapState.BTC_LOCKED
    assert record.radiant_covenant_outpoint is None


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

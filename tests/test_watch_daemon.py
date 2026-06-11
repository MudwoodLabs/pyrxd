"""Tests for the watchtower poll loop (``gravity.watch.daemon``)."""

from __future__ import annotations

import asyncio
import logging

import pytest

from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.watch import Decision, Intent, Reconciler, ReconcileResult, default_heartbeat, run_loop
from pyrxd.security.errors import ValidationError


class EmptyStore:
    async def list_active(self):
        return []


class _Null:
    async def observe(self, swap_id, record):  # pragma: no cover - never called (empty store)
        raise AssertionError

    async def handle(self, swap_id, decision):  # pragma: no cover
        raise AssertionError


def _reconciler() -> Reconciler:
    return Reconciler(
        store=EmptyStore(),
        observer=_Null(),
        alerter=_Null(),
        policy=MarginPolicy.estimated(),
        safety_window_blocks=6,
    )


async def _noop_sleep(_s):
    return None


async def test_run_loop_max_iterations():
    hb: list[tuple[int, int]] = []
    n = await run_loop(
        _reconciler(),
        interval_s=0,
        on_heartbeat=lambda i, res: hb.append((i, len(res))),
        sleep=_noop_sleep,
        max_iterations=3,
    )
    assert n == 3
    assert hb == [(1, 0), (2, 0), (3, 0)]


async def test_run_loop_stops_on_event():
    stop = asyncio.Event()
    seen: list[int] = []

    def cb(i, res):
        seen.append(i)
        if i >= 2:
            stop.set()

    n = await run_loop(_reconciler(), interval_s=0, stop=stop, on_heartbeat=cb, sleep=_noop_sleep)
    assert n == 2
    assert seen == [1, 2]


async def test_run_loop_validates_args():
    with pytest.raises(ValidationError):
        await run_loop("not a reconciler", interval_s=1)
    with pytest.raises(ValidationError):
        await run_loop(_reconciler(), interval_s=-1)
    with pytest.raises(ValidationError):
        await run_loop(_reconciler(), interval_s=1, tick_timeout_s=0, max_iterations=1)


def test_default_heartbeat_logs_paged_count(caplog):
    results = [
        ReconcileResult("a", Decision(Intent.PAGE_CLAIM, reason="x")),
        ReconcileResult("b", Decision(Intent.WATCH, reason="y")),
    ]
    with caplog.at_level(logging.INFO, logger="pyrxd.gravity.watch.daemon"):
        default_heartbeat()(7, results)
    rec = next(r for r in caplog.records if "heartbeat" in r.message)
    assert "tick=7" in rec.message and "swaps=2" in rec.message and "paged=1" in rec.message


def test_default_heartbeat_warns_on_undelivered(caplog):
    # red-team #5: an UNDELIVERED page must log at ERROR (loud), not blend into a healthy INFO beat.
    results = [ReconcileResult("a", Decision(Intent.PAGE_CLAIM, reason="x"), alert_delivered=False)]
    with caplog.at_level(logging.INFO, logger="pyrxd.gravity.watch.daemon"):
        default_heartbeat()(1, results)
    rec = next(r for r in caplog.records if "heartbeat" in r.message)
    assert "undelivered=1" in rec.message and rec.levelno == logging.ERROR


async def test_run_loop_heartbeat_sink_failure_does_not_crash():
    # red-team #11: a heartbeat-sink failure (e.g. ENOSPC writing the heartbeat file) must degrade to
    # a stale beat the deadman catches, NOT crash the reconcile loop.
    def _boom(i, res):
        raise OSError("ENOSPC")

    n = await run_loop(_reconciler(), interval_s=0, on_heartbeat=_boom, sleep=_noop_sleep, max_iterations=2)
    assert n == 2  # loop survived despite the sink raising every tick


async def test_run_loop_tick_timeout_skips_heartbeat():
    # LOW-R3: a tick that exceeds the watchdog budget is "blind" — it must NOT refresh the
    # cross-process heartbeat, so a slow-loris source that wedges every tick lets the age-only
    # dead-man's-switch go stale and PAGE (rather than reporting a healthy-but-blind tower). The
    # loop still times the tick out and continues; it just emits no beat for the blind tick.
    class _SlowStore:
        async def list_active(self):
            await asyncio.sleep(10)  # longer than the tick budget
            return []  # pragma: no cover - cancelled by wait_for

    slow = Reconciler(
        store=_SlowStore(), observer=_Null(), alerter=_Null(), policy=MarginPolicy.estimated(), safety_window_blocks=6
    )
    beats: list[int] = []
    n = await run_loop(
        slow,
        interval_s=0,
        on_heartbeat=lambda i, res: beats.append(len(res)),
        sleep=_noop_sleep,
        max_iterations=1,
        tick_timeout_s=0.01,
    )
    assert n == 1
    assert beats == []  # blind (timed-out) tick emits NO heartbeat → deadman sees staleness if it persists

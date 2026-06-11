"""Watchtower poll loop (daemon helper) — v1 alert-only.

The reconciler is "the loop body" and never sleeps; :func:`run_loop` is the thin
driver that calls ``reconciler.tick()`` on an interval and emits a heartbeat after
each tick. The heartbeat is the **dead-man's-switch signal**: an independent monitor
watches for it and pages the operator (fallback) if it stops — so a wedged/killed
tower surfaces rather than going silent. ``sleep`` and ``max_iterations`` are injected
so the loop is unit-testable without real time.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from pyrxd.gravity.watch.executor import ExecOutcome
from pyrxd.gravity.watch.reconciler import Reconciler, ReconcileResult
from pyrxd.security.errors import ValidationError

logger = logging.getLogger(__name__)

__all__ = ["combine_heartbeats", "default_heartbeat", "run_loop"]

# heartbeat(iteration, results) — called after each tick (the liveness signal).
Heartbeat = Callable[[int, list[ReconcileResult]], None]


def combine_heartbeats(*heartbeats: Heartbeat) -> Heartbeat:
    """Fan the heartbeat out to several sinks (e.g. log line + cross-process file).

    Per-sink isolation (red-team LOW): one failing sink (e.g. a heartbeat-FILE write hitting
    ENOSPC/EROFS) must NOT prevent the others from firing or crash the loop — log and continue."""

    def _hb(iteration: int, results: list[ReconcileResult]) -> None:
        for hb in heartbeats:
            try:
                hb(iteration, results)
            except Exception:  # a heartbeat sink failure must not crash the loop
                logger.exception("heartbeat sink %r failed (continuing)", getattr(hb, "__name__", hb))

    return _hb


def default_heartbeat(log: logging.Logger | None = None) -> Heartbeat:
    """A heartbeat that logs tick count, swaps watched, pages decided, UNDELIVERED pages, and the v2
    autonomous-execution outcomes (broadcast / failed)."""
    log = log or logger

    def _hb(iteration: int, results: list[ReconcileResult]) -> None:
        paged = sum(1 for r in results if r.decision.intent.value.startswith("page_"))
        undelivered = sum(1 for r in results if r.alert_delivered is False)
        broadcast = sum(1 for r in results if r.executed is ExecOutcome.BROADCAST)
        exec_failed = sum(1 for r in results if r.executed is ExecOutcome.FAILED)
        # An undelivered CRITICAL page OR a FAILED autonomous broadcast must be LOUD, not buried in a
        # healthy-looking INFO tick — so a persistently-failing broadcaster surfaces on the heartbeat,
        # not only on the per-tick alerter page.
        level = logging.ERROR if (undelivered or exec_failed) else logging.INFO
        log.log(
            level,
            "watchtower heartbeat: tick=%d swaps=%d paged=%d undelivered=%d broadcast=%d exec_failed=%d",
            iteration,
            len(results),
            paged,
            undelivered,
            broadcast,
            exec_failed,
        )

    return _hb


async def run_loop(
    reconciler: Reconciler,
    *,
    interval_s: float,
    stop: asyncio.Event | None = None,
    on_heartbeat: Heartbeat | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    max_iterations: int | None = None,
    tick_timeout_s: float | None = None,
) -> int:
    """Tick the reconciler on ``interval_s`` until ``stop`` is set (or ``max_iterations``).

    Returns the number of ticks run. ``reconciler.tick()`` never raises (it fails closed to a
    page for a per-swap OR store fault), so the loop is robust by construction. Two further
    backstops (red-team): (1) a watchdog — ``tick_timeout_s`` bounds a single tick so one slow
    source can't outlast the dead-man's-switch window and trip a false "tower DOWN"; on timeout we
    emit an alive (degraded) heartbeat and move on. (2) ``on_heartbeat`` is GUARDED — a
    heartbeat-sink failure degrades to a stale heartbeat (which the dead-man's-switch then reports),
    never a crash.
    """
    if not isinstance(reconciler, Reconciler):
        raise ValidationError("run_loop requires a Reconciler")
    if not isinstance(interval_s, (int, float)) or interval_s < 0:
        raise ValidationError("run_loop interval_s must be >= 0")
    if max_iterations is not None and (not isinstance(max_iterations, int) or max_iterations < 0):
        raise ValidationError("run_loop max_iterations must be a non-negative int or None")
    if tick_timeout_s is not None and (not isinstance(tick_timeout_s, (int, float)) or tick_timeout_s <= 0):
        raise ValidationError("run_loop tick_timeout_s must be > 0 or None")

    iterations = 0
    while not (stop is not None and stop.is_set()):
        if max_iterations is not None and iterations >= max_iterations:
            break
        tick_timed_out = False
        try:
            if tick_timeout_s is None:
                results = await reconciler.tick()
            else:
                results = await asyncio.wait_for(reconciler.tick(), timeout=tick_timeout_s)
        except (asyncio.TimeoutError, TimeoutError):
            logger.error(
                "watchtower tick %d exceeded %.0fs budget (slow source?) — degraded; SKIPPING the "
                "heartbeat so the cross-process dead-man's-switch sees staleness if this persists",
                iterations + 1,
                tick_timeout_s,
            )
            results = []
            tick_timed_out = True
        iterations += 1
        # LOW-R3: only beat on a tick that actually OBSERVED the chain. A timed-out (blind) tick must
        # NOT refresh the cross-process heartbeat — else a slow-loris source that wedges every tick
        # keeps the age-only dead-man's-switch reporting ALIVE while the tower sees nothing. A
        # PERSISTENT timeout → no fresh beats → the switch goes stale and pages; a single transient
        # timeout is harmless (the next good tick beats well within max_silence).
        if on_heartbeat is not None and not tick_timed_out:
            try:
                on_heartbeat(iterations, results)
            except Exception:  # a heartbeat-sink failure must not crash the reconcile loop
                logger.exception(
                    "on_heartbeat failed at tick %d (continuing; deadman will see a stale beat)", iterations
                )
        if (stop is not None and stop.is_set()) or (max_iterations is not None and iterations >= max_iterations):
            break
        await sleep(interval_s)
    return iterations

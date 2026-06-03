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

from pyrxd.gravity.watch.reconciler import Reconciler, ReconcileResult
from pyrxd.security.errors import ValidationError

logger = logging.getLogger(__name__)

__all__ = ["combine_heartbeats", "default_heartbeat", "run_loop"]

# heartbeat(iteration, results) — called after each tick (the liveness signal).
Heartbeat = Callable[[int, list[ReconcileResult]], None]


def combine_heartbeats(*heartbeats: Heartbeat) -> Heartbeat:
    """Fan the heartbeat out to several sinks (e.g. log line + cross-process file)."""

    def _hb(iteration: int, results: list[ReconcileResult]) -> None:
        for hb in heartbeats:
            hb(iteration, results)

    return _hb


def default_heartbeat(log: logging.Logger | None = None) -> Heartbeat:
    """A heartbeat that logs tick count + how many swaps were paged this tick."""
    log = log or logger

    def _hb(iteration: int, results: list[ReconcileResult]) -> None:
        paged = sum(1 for r in results if r.decision.intent.value.startswith("page_"))
        log.info("watchtower heartbeat: tick=%d swaps=%d paged=%d", iteration, len(results), paged)

    return _hb


async def run_loop(
    reconciler: Reconciler,
    *,
    interval_s: float,
    stop: asyncio.Event | None = None,
    on_heartbeat: Heartbeat | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    max_iterations: int | None = None,
) -> int:
    """Tick the reconciler on ``interval_s`` until ``stop`` is set (or ``max_iterations``).

    Returns the number of ticks run. ``reconciler.tick()`` never raises for a per-swap
    failure (it fails closed to a page), so the loop is robust by construction.
    """
    if not isinstance(reconciler, Reconciler):
        raise ValidationError("run_loop requires a Reconciler")
    if not isinstance(interval_s, (int, float)) or interval_s < 0:
        raise ValidationError("run_loop interval_s must be >= 0")
    if max_iterations is not None and (not isinstance(max_iterations, int) or max_iterations < 0):
        raise ValidationError("run_loop max_iterations must be a non-negative int or None")

    iterations = 0
    while not (stop is not None and stop.is_set()):
        if max_iterations is not None and iterations >= max_iterations:
            break
        results = await reconciler.tick()
        iterations += 1
        if on_heartbeat is not None:
            on_heartbeat(iterations, results)
        if (stop is not None and stop.is_set()) or (max_iterations is not None and iterations >= max_iterations):
            break
        await sleep(interval_s)
    return iterations

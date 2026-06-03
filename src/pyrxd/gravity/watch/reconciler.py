"""Watchtower reconciler — the loop body (v1 alert-only, BTC).

One :meth:`Reconciler.tick` pass: list the in-flight swaps from a read-only store,
observe each (quorum-agreed chain reads), run the pure :func:`decide`, and route any
actionable :class:`Decision` to the alerter. v1 **broadcasts nothing** — the alerter
pages the operator, who runs the named one-shot coordinator step.

Design (mirrors the brainstorm/plan):
* The ports (:class:`RecordStore`, :class:`Observer`, :class:`Alerter`) are injected
  Protocols, so the brain is unit-testable with fakes and the daemon shell wires the
  real transports. The shell — not this module — owns the sleep/poll loop (so the
  brain never sleeps and stays deterministic).
* **Per-swap-id single-flight:** ``_inflight`` prevents two overlapping ticks from
  reconciling the same swap concurrently. This is the only concurrency primitive the
  tower needs in v1 (it holds no coordinator instance and broadcasts nothing).
* **Fail-closed + crash-safe:** an observe/decide error never crashes the loop — it
  becomes a ``PAGE_SQUEEZED`` "investigate" page, so a broken swap surfaces loudly
  rather than going silent. Restart re-reads the store (no load-bearing in-memory
  state; dedup lives in the alerter).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch.decide import Decision, Intent, Observations, decide
from pyrxd.security.errors import ValidationError

logger = logging.getLogger(__name__)

__all__ = ["Alerter", "Observer", "ReconcileResult", "Reconciler", "RecordStore"]

# Intents that the alerter is told about: the actionable pages + the terminal RETIRE
# (so it can emit an INFO "done" and clear its dedup state). WATCH/NOOP are silent.
_ROUTED_INTENTS = frozenset({Intent.PAGE_CLAIM, Intent.PAGE_REFUND, Intent.PAGE_SQUEEZED, Intent.RETIRE})


@runtime_checkable
class RecordStore(Protocol):
    """Read-only view of the operator's in-flight swaps (v1 never writes)."""

    async def list_active(self) -> list[tuple[str, SwapRecord]]:
        """Return ``(swap_id, record)`` for every non-terminal swap to watch."""
        ...


@runtime_checkable
class Observer(Protocol):
    """Builds quorum-agreed chain :class:`Observations` for one swap (the quorum layer)."""

    async def observe(self, swap_id: str, record: SwapRecord) -> Observations: ...


@runtime_checkable
class Alerter(Protocol):
    """Receives an actionable :class:`Decision` and pages the operator (the alert layer)."""

    async def handle(self, swap_id: str, decision: Decision) -> None: ...


@dataclass(frozen=True)
class ReconcileResult:
    """The outcome for one swap, this tick (for observability + tests)."""

    swap_id: str
    decision: Decision
    error: str | None = None


class Reconciler:
    """Stateless-across-ticks reconciler. Inject the store/observer/alerter ports."""

    def __init__(
        self,
        *,
        store: RecordStore,
        observer: Observer,
        alerter: Alerter,
        policy: MarginPolicy,
        safety_window_blocks: int,
    ) -> None:
        if not isinstance(policy, MarginPolicy):
            raise ValidationError("Reconciler requires a MarginPolicy")
        if (
            not isinstance(safety_window_blocks, int)
            or isinstance(safety_window_blocks, bool)
            or safety_window_blocks < 0
        ):
            raise ValidationError("Reconciler requires a non-negative safety_window_blocks")
        self._store = store
        self._observer = observer
        self._alerter = alerter
        self._policy = policy
        self._safety = safety_window_blocks
        self._inflight: set[str] = set()

    async def tick(self) -> list[ReconcileResult]:
        """Reconcile every in-flight swap once. Never raises for a per-swap failure."""
        active = await self._store.list_active()
        results: list[ReconcileResult] = []
        for swap_id, record in active:
            results.append(await self._reconcile_one(swap_id, record))
        return results

    async def _reconcile_one(self, swap_id: str, record: SwapRecord) -> ReconcileResult:
        if swap_id in self._inflight:
            # Another (overlapping) tick is already on this swap — skip, don't double-act.
            return ReconcileResult(
                swap_id, Decision(Intent.WATCH, reason="single-flight: reconcile already in progress")
            )
        self._inflight.add(swap_id)
        try:
            try:
                obs = await self._observer.observe(swap_id, record)
                decision = decide(
                    record=record,
                    observations=obs,
                    policy=self._policy,
                    safety_window_blocks=self._safety,
                )
            except Exception as exc:  # observe/decide failure must not crash the loop
                err = f"{type(exc).__name__}: {exc}"
                logger.exception("reconcile failed for swap %s", swap_id)
                decision = Decision(
                    Intent.PAGE_SQUEEZED,
                    reason=f"reconcile error, fail-closed (investigate manually): {err}",
                    recommended_action="investigate",
                )
                await self._safe_handle(swap_id, decision)
                return ReconcileResult(swap_id, decision, error=err)
            if decision.intent in _ROUTED_INTENTS:
                await self._safe_handle(swap_id, decision)
            else:
                logger.debug("swap %s: %s (%s)", swap_id, decision.intent.value, decision.reason)
            return ReconcileResult(swap_id, decision)
        finally:
            self._inflight.discard(swap_id)

    async def _safe_handle(self, swap_id: str, decision: Decision) -> None:
        """Route to the alerter; an alert-channel failure must not crash the loop."""
        try:
            await self._alerter.handle(swap_id, decision)
        except Exception:
            logger.exception("alerter.handle failed for swap %s (intent=%s)", swap_id, decision.intent.value)

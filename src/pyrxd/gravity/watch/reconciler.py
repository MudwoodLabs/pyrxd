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

import dataclasses
import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch.decide import Decision, Intent, LegacyCheck, Observations, decide, decide_legacy
from pyrxd.gravity.watch.executor import ExecOutcome, Executor, NullExecutor
from pyrxd.security.errors import ValidationError

logger = logging.getLogger(__name__)

__all__ = ["Alerter", "Observer", "ReconcileResult", "Reconciler", "RecordStore"]

# swap_id used for tower-level pages not tied to one swap (store unreadable, etc.).
_STORE = "<records-store>"

# Intents that the alerter is told about: the actionable pages + the terminal RETIRE
# (so it can emit an INFO "done" and clear its dedup state). WATCH/NOOP are silent.
_ROUTED_INTENTS = frozenset(
    {Intent.PAGE_CLAIM, Intent.PAGE_REFUND, Intent.PAGE_SQUEEZED, Intent.RECONCILE, Intent.RETIRE}
)


@runtime_checkable
class RecordStore(Protocol):
    """View of the operator's in-flight swaps. It never writes a record.

    A store MAY also expose ``legacy`` (``(swap_id, record)`` for the legacy terminal records to read
    this tick) and ``mark_legacy_checked(swap_id, verdict, *, rxd_height, evidence)``, the D9 net (#850
    PR 9b): :class:`~pyrxd.gravity.watch.adapters.JsonDirRecordStore` does. A store without them has
    no legacy net."""

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
    """The outcome for one swap, this tick (for observability + tests).

    ``alert_delivered`` is ``None`` when no page was routed (WATCH/NOOP), ``True`` when the
    alerter delivered it, ``False`` when delivery FAILED (red-team MEDIUM: a swallowed delivery
    failure must be visible to the heartbeat, not look healthy)."""

    swap_id: str
    decision: Decision
    error: str | None = None
    alert_delivered: bool | None = None
    # The autonomous-execution outcome (v2). ``None`` = nothing attempted (no executor / not a refund);
    # otherwise BROADCAST / DECLINED / FAILED — surfaced so the heartbeat counts BROADCAST/FAILED and a
    # swallowed broadcast failure cannot look healthy (same discipline as ``alert_delivered``).
    executed: ExecOutcome | None = None
    #: A legacy terminal record read by the D9 net (#850 PR 9b): never executed, only paged.
    legacy: bool = False


def _executor_outcome_note(outcome: ExecOutcome | None) -> str:
    """What this tick's executor did with an armed refund page, appended to the page (#850 PR 9b,
    Mythos F2). ``None`` means no executor acted (the alert-only default)."""
    if outcome is ExecOutcome.BROADCAST:
        return " This tick the tower broadcast the pre-signed refund."
    if outcome is ExecOutcome.FAILED:
        return " This tick the tower's refund broadcast FAILED: refund the BTC yourself (taker_refund_btc)."
    return (
        " This tick the tower did NOT broadcast a refund (no executor, dormant, or one of its gates refused): "
        "refund the BTC yourself (taker_refund_btc)."
    )


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
        executor: Executor | None = None,
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
        # Default = NullExecutor → no autonomy, alert-only wiring byte-identical (broadcasts nothing).
        self._executor: Executor = executor if executor is not None else NullExecutor()
        self._policy = policy
        self._safety = safety_window_blocks
        self._inflight: set[str] = set()

    @property
    def alerter(self) -> Alerter:
        """The injected alerter — exposed so the shell can wire its operator-ACK inbox + the
        un-ACK'd CRITICAL count into the heartbeat (a :class:`DedupAlerter` provides both)."""
        return self._alerter

    async def tick(self) -> list[ReconcileResult]:
        """Reconcile every in-flight swap once. NEVER raises (red-team LOW: a directory-level store
        I/O fault — missing/typo'd/unmounted dir, EACCES/ESTALE/EIO, or every record unreadable —
        must become a PAGE, not crash the daemon and stop the heartbeat)."""
        try:
            active = await self._store.list_active()
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            logger.exception("watchtower records store unreadable")
            decision = Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"records store unreadable — the tower may be watching NOTHING (investigate): {err}",
                recommended_action="check the records dir exists/is mounted/readable; manually watch in-flight swaps",
            )
            delivered = await self._safe_handle(_STORE, decision)
            return [ReconcileResult(_STORE, decision, error=err, alert_delivered=delivered)]
        results: list[ReconcileResult] = []
        # Each record the store could not read pages BY NAME (#850 PR 3). The store skips it so one
        # bad file cannot blind the tower to the rest, but a skipped record is a swap nobody is
        # watching: before this it paged only if EVERY record failed. A store without the attribute
        # (any other RecordStore) reports none.
        for swap_id, why in list(getattr(self._store, "unreadable", ()) or ()):
            decision = Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"swap record {swap_id} is NOT being watched: {why}",
                recommended_action="read the record with a pyrxd that can, and watch this swap manually until then",
            )
            delivered = await self._safe_handle(swap_id, decision)
            results.append(ReconcileResult(swap_id, decision, error=why, alert_delivered=delivered))
        for swap_id, record in active:
            results.append(await self._reconcile_one(swap_id, record))
        for swap_id, record in list(getattr(self._store, "legacy", ()) or ()):
            results.append(await self._check_legacy(swap_id, record))
        return results

    async def _check_legacy(self, swap_id: str, record: SwapRecord) -> ReconcileResult:
        """The D9 net for one legacy terminal record (#850 PR 9b, design §5.2). One observation, the
        pure :func:`decide_legacy`, a page when it names one, and the marker only on a conclusive
        verdict. Never the executor: nothing here is autonomous. A read that fails writes nothing
        and pages nothing: the record is read again on a later tick (``UNKNOWN`` writes nothing)."""
        try:
            obs = await self._observer.observe(swap_id, record)
            check: LegacyCheck = decide_legacy(
                record=record, observations=obs, policy=self._policy, safety_window_blocks=self._safety
            )
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            logger.warning("legacy check of swap %s failed; read again later: %s", swap_id, err)
            return ReconcileResult(
                swap_id, Decision(Intent.WATCH, reason=f"legacy check failed: {err}"), error=err, legacy=True
            )
        decision = check.decision
        delivered: bool | None = None
        if decision.intent in _ROUTED_INTENTS:
            delivered = await self._safe_handle(swap_id, decision)
        if check.conclusive or (check.conclusive_once_delivered and delivered):
            mark = getattr(self._store, "mark_legacy_checked", None)
            if callable(mark):
                try:
                    mark(
                        swap_id,
                        check.verdict,
                        rxd_height=int(obs.now_rxd_height),
                        evidence={
                            "btc_disposition": obs.btc_disposition.value if obs.btc_disposition else None,
                            "btc_refund_txid": obs.btc_refund_txid,
                            "reason": obs.btc_disposition_reason,
                        },
                    )
                except Exception:
                    logger.exception("could not write the legacy-checked marker for %s; read again later", swap_id)
        return ReconcileResult(swap_id, decision, alert_delivered=delivered, legacy=True)

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
                delivered = await self._safe_handle(swap_id, decision)
                return ReconcileResult(swap_id, decision, error=err, alert_delivered=delivered)
            if decision.intent in _ROUTED_INTENTS:
                # Autonomy (v2) runs FIRST but is ADDITIVE — the alerter ALWAYS still fires, so a
                # dormant/declined/failed broadcast never silences the operator.
                executed = await self._safe_execute(swap_id, record, decision)
                if decision.autonomous_btc_refund:
                    # decide() cannot know whether this tower broadcasts; the page says what it did
                    # (#850 PR 9b, Mythos F2), so an alert-only or dormant tower never claims a broadcast.
                    decision = dataclasses.replace(decision, reason=decision.reason + _executor_outcome_note(executed))
                delivered = await self._safe_handle(swap_id, decision)
                return ReconcileResult(swap_id, decision, alert_delivered=delivered, executed=executed)
            logger.debug("swap %s: %s (%s)", swap_id, decision.intent.value, decision.reason)
            return ReconcileResult(swap_id, decision)
        finally:
            self._inflight.discard(swap_id)

    async def _safe_execute(self, swap_id: str, record: SwapRecord, decision: Decision) -> ExecOutcome | None:
        """Run the autonomous executor for an autonomy-eligible decision. A broadcast failure must NOT
        crash the loop and must NOT silence the operator — it is recorded as ``FAILED`` and the alerter
        still pages. ``PAGE_REFUND`` (keyless refund) and ``PAGE_CLAIM`` (the asset claim) are
        autonomy-eligible; every other routed intent is observed-only. Each executor self-gates on its
        own typed discriminator, so a wired RefundExecutor/ClaimExecutor only acts on its own intent.
        With the default :class:`NullExecutor` this is always a no-op (returns ``None``)."""
        if decision.intent not in (Intent.PAGE_REFUND, Intent.PAGE_CLAIM):
            return None
        try:
            return await self._executor.execute(swap_id, record, decision)
        except Exception:
            logger.exception("autonomous executor FAILED for swap %s — alerter will still page", swap_id)
            return ExecOutcome.FAILED

    async def _safe_handle(self, swap_id: str, decision: Decision) -> bool:
        """Route to the alerter; an alert-channel failure must not crash the loop. Returns True iff
        the page was delivered — a FALSE is surfaced on the ReconcileResult (red-team MEDIUM) so the
        heartbeat counts DELIVERED pages, not merely DECIDED ones, and a persistently-failing channel
        cannot look healthy while dropping CRITICAL pages."""
        try:
            await self._alerter.handle(swap_id, decision)
            return True
        except Exception:
            logger.exception(
                "alerter.handle FAILED to DELIVER page for swap %s (intent=%s)", swap_id, decision.intent.value
            )
            return False

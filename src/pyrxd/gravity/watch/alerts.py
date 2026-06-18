"""Alert layer for the watchtower (v1 alert-only, BTC).

Turns a :class:`~pyrxd.gravity.watch.decide.Decision` into a :class:`Page` —
severity + a human-actionable message naming the one-shot coordinator step and the
deadline — and sends it over an injected :class:`AlertChannel`, de-duplicated so the
operator is paged once per distinct situation, not every tick.

Scope split: this module owns severity + dedup + payload shape. The *transport*
(authenticated, tamper-evident delivery) and the dead-man's-switch heartbeat are the
daemon shell's job — the :class:`AlertChannel` port is where the shell plugs the real
(authenticated) channel in. v1 never broadcasts a transaction; a Page is a
notification to the operator, who runs the named step.

Dedup is by ``(swap_id, intent)``: ``_last`` is updated only AFTER a successful send,
so a transient channel failure is retried on the next tick rather than silently lost.

Time-critical CRITICAL intents (``PAGE_CLAIM`` / ``PAGE_SQUEEZED``) are the exception to
"page once per situation": a single missed page on a claim/squeeze race silently loses
funds if the operator does not see it (review MEDIUM). Those intents RE-PAGE on a
tick-count backoff (``repage_critical_every_ticks``, default every tick) for as long as
the situation persists — bounded by the swap's lifecycle (it stops when the intent
changes or the swap retires). WARN/INFO intents keep the once-per-situation dedup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.security.errors import ValidationError

__all__ = ["AlertChannel", "DedupAlerter", "FileAckInbox", "Page", "Severity"]


class Severity(Enum):
    INFO = "info"
    WARN = "warn"
    CRITICAL = "critical"


# Time-critical / decision-required pages are CRITICAL; a stall refund is WARN
# (recoverable, not a race); a terminal swap is an INFO "done". WATCH/NOOP never reach
# the alerter (the reconciler does not route them).
_SEVERITY: dict[Intent, Severity] = {
    Intent.PAGE_CLAIM: Severity.CRITICAL,
    Intent.PAGE_SQUEEZED: Severity.CRITICAL,
    Intent.PAGE_REFUND: Severity.WARN,
    Intent.RETIRE: Severity.INFO,
}


@dataclass(frozen=True)
class Page:
    """A single operator notification. ``message`` is human-readable; the structured
    fields let a richer channel render/route it. ``intent`` is ``None`` for a *system*
    page not tied to a swap action (e.g. the dead-man's-switch liveness alert)."""

    swap_id: str
    intent: Intent | None
    severity: Severity
    message: str
    recommended_action: str | None
    deadline_rxd_height: int | None
    low_corroboration: bool


@runtime_checkable
class AlertChannel(Protocol):
    """The (authenticated) delivery transport — wired by the shell."""

    async def send(self, page: Page) -> None: ...


def _message(swap_id: str, decision: Decision, severity: Severity) -> str:
    parts = [f"[{severity.value.upper()}] swap {swap_id}: {decision.reason}"]
    if decision.recommended_action:
        parts.append(f"action: {decision.recommended_action}")
    if decision.deadline_rxd_height is not None:
        parts.append(f"by RXD height {decision.deadline_rxd_height}")
    if decision.low_corroboration:
        parts.append("(LOW CORROBORATION — single-source RXD read; verify before acting)")
    return " | ".join(parts)


class DedupAlerter:
    """Routes actionable Decisions to an :class:`AlertChannel`, de-duplicated by
    ``(swap_id, intent)``. Satisfies the reconciler's ``Alerter`` port structurally."""

    def __init__(self, *, channel: AlertChannel, repage_critical_every_ticks: int = 1) -> None:
        if (
            not isinstance(repage_critical_every_ticks, int)
            or isinstance(repage_critical_every_ticks, bool)
            or repage_critical_every_ticks < 1
        ):
            raise ValidationError("repage_critical_every_ticks must be an int >= 1")
        self._channel = channel
        self._last: dict[str, Intent] = {}
        # Ticks (handle() calls) a CRITICAL situation has persisted since its last successful
        # page — the re-page backoff counter (review MEDIUM). Keyed by swap_id because a swap
        # has exactly one live intent per tick. Reset to 0 after each (re)page.
        self._critical_ticks: dict[str, int] = {}
        # Operator-ACK'd CRITICAL situations: swap_id -> the exact CRITICAL Intent acknowledged.
        # An ACK suppresses re-paging for THAT situation (the operator is handling it) and drops
        # it from unacked_critical_count(); a DIFFERENT/escalated intent re-arms paging.
        self._acked: dict[str, Intent] = {}
        self._repage_every = repage_critical_every_ticks

    def ack(self, swap_id: str) -> bool:
        """Operator acknowledgement of a swap's current CRITICAL page (claim/squeeze race).

        Suppresses further re-pages for that exact situation and removes it from
        :meth:`unacked_critical_count`. Only a live CRITICAL situation is ack-able (WARN/INFO
        page once anyway). Returns True if an ACK was recorded, False if there was nothing
        CRITICAL to ack. An escalation to a different CRITICAL intent re-arms paging.
        """
        intent = self._last.get(swap_id)
        if intent is not None and _SEVERITY.get(intent) is Severity.CRITICAL:
            self._acked[swap_id] = intent
            return True
        return False

    def unacked_critical_count(self) -> int:
        """Number of swaps currently in a paged CRITICAL situation the operator has NOT ACK'd.

        The escalation signal fed into the heartbeat (review MEDIUM): a persistent non-zero count
        means time-critical claim/squeeze pages are outstanding and unacknowledged, so an external
        monitor / second channel can escalate beyond the primary page channel.
        """
        return sum(
            1
            for sid, intent in self._last.items()
            if _SEVERITY.get(intent) is Severity.CRITICAL and self._acked.get(sid) is not intent
        )

    async def handle(self, swap_id: str, decision: Decision) -> None:
        if not isinstance(decision, Decision):
            raise ValidationError("DedupAlerter.handle requires a Decision")
        intent = decision.intent
        severity = _SEVERITY.get(intent)
        if severity is None:
            # WATCH / NOOP — not an alertable event (the reconciler shouldn't route these,
            # but stay defensive rather than paging noise).
            return
        if intent is Intent.RETIRE:
            # The swap is done — clear its re-page backoff + ACK state so they cannot leak or
            # mis-count a future swap reusing the id. The INFO "done" page still dedups via _last.
            self._critical_ticks.pop(swap_id, None)
            self._acked.pop(swap_id, None)
        if self._last.get(swap_id) is intent:
            # Same situation still live. WARN/INFO page once. A CRITICAL (claim/squeeze)
            # race RE-PAGES on the tick-count backoff so a single missed page cannot
            # silently lose funds (review MEDIUM) — unless the operator ACK'd this exact
            # situation (they are handling it), then stay quiet until it changes.
            if severity is not Severity.CRITICAL:
                return
            if self._acked.get(swap_id) is intent:
                return
            self._critical_ticks[swap_id] = self._critical_ticks.get(swap_id, 0) + 1
            if self._critical_ticks[swap_id] < self._repage_every:
                return
        page = Page(
            swap_id=swap_id,
            intent=intent,
            severity=severity,
            message=_message(swap_id, decision, severity),
            recommended_action=decision.recommended_action,
            deadline_rxd_height=decision.deadline_rxd_height,
            low_corroboration=decision.low_corroboration,
        )
        # Send first; record dedup state only on success so a transient channel failure
        # is retried next tick rather than silently swallowed.
        await self._channel.send(page)
        self._last[swap_id] = intent
        self._critical_ticks[swap_id] = 0  # reset the re-page backoff after a successful (re)page


class FileAckInbox:
    """Operator → watchtower ACK transport (the mirror of :class:`FileHeartbeat`).

    The operator acknowledges a paged CRITICAL situation by appending the swap_id (one per
    line) to a file — e.g. ``echo <swap_id> >> $WATCHTOWER_ACKS``. The daemon shell drains
    this inbox once per tick (wire it as ``run_loop(on_tick_start=...)``) and calls
    :meth:`DedupAlerter.ack` for each id, so re-paging for that situation stops and the
    un-ACK'd CRITICAL count drops.

    :meth:`drain` is atomic against a concurrent appender: it renames the inbox aside before
    reading, so ids appended during the read land in a fresh file and are consumed next tick
    (an ACK is never lost or double-consumed).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def drain(self) -> list[str]:
        tmp = self._path.with_name(self._path.name + ".draining")
        try:
            os.replace(self._path, tmp)  # atomically claim the current inbox contents
        except FileNotFoundError:
            return []
        try:
            content = tmp.read_text()
        finally:
            tmp.unlink(missing_ok=True)
        return [line.strip() for line in content.splitlines() if line.strip()]

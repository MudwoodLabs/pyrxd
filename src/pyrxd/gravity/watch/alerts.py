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
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.security.errors import ValidationError

__all__ = ["AlertChannel", "DedupAlerter", "Page", "Severity"]


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

    def __init__(self, *, channel: AlertChannel) -> None:
        self._channel = channel
        self._last: dict[str, Intent] = {}

    async def handle(self, swap_id: str, decision: Decision) -> None:
        if not isinstance(decision, Decision):
            raise ValidationError("DedupAlerter.handle requires a Decision")
        intent = decision.intent
        severity = _SEVERITY.get(intent)
        if severity is None:
            # WATCH / NOOP — not an alertable event (the reconciler shouldn't route these,
            # but stay defensive rather than paging noise).
            return
        if self._last.get(swap_id) is intent:
            return  # already paged this situation; don't re-page every tick
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

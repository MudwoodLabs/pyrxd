"""Dead-man's-switch for the watchtower (v1).

The tower's :func:`run_loop` emits a heartbeat each tick, but an *external* monitor
needs a cross-process signal: :class:`FileHeartbeat` writes the tick + timestamp to a
file each tick (wire it as ``on_heartbeat``). An independent process runs
:class:`DeadMansSwitch`, which pages the operator the moment that file goes
**stale or absent** — i.e. the tower was killed/wedged/partitioned, which is exactly
the precondition for the attacks the tower defends against. The monitor MUST run as a
separate process (if it shared the tower's process, a crash would take both down).

Time is injected (``clock`` / explicit ``now``) so the logic is unit-testable without
wall-clock flakiness.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from pyrxd.gravity.watch.alerts import Page, Severity
from pyrxd.security.errors import ValidationError

__all__ = ["DeadManVerdict", "DeadMansSwitch", "FileHeartbeat", "heartbeat_age_s", "run_monitor"]

_WATCHTOWER = "<watchtower>"


class FileHeartbeat:
    """A heartbeat sink that atomically writes ``{ts, tick, swaps, paged}`` to a file each
    tick — the cross-process liveness signal the :class:`DeadMansSwitch` watches."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self._path = Path(path)
        self._clock = clock

    def __call__(self, iteration: int, results) -> None:
        paged = sum(1 for r in results if r.decision.intent.value.startswith("page_"))
        data = {"ts": self._clock(), "tick": iteration, "swaps": len(results), "paged": paged}
        tmp = self._path.with_name(self._path.name + ".tmp")
        tmp.write_text(json.dumps(data))
        os.replace(tmp, self._path)  # atomic on the same filesystem


def heartbeat_age_s(path: str | Path, *, now: float) -> float | None:
    """Seconds since the heartbeat file was last written, or ``None`` if it is
    missing / unreadable / has no timestamp (treated as 'no liveness signal')."""
    try:
        data = json.loads(Path(path).read_text())
    except (FileNotFoundError, ValueError, OSError):
        return None
    ts = data.get("ts") if isinstance(data, dict) else None
    if not isinstance(ts, (int, float)):
        return None
    return now - ts


@dataclass(frozen=True)
class DeadManVerdict:
    alive: bool
    age_s: float | None  # None = no heartbeat file / unreadable


class DeadMansSwitch:
    """Pages the operator when the tower's heartbeat goes stale/absent, and again (INFO)
    when it recovers. Edge-triggered: fires once per stale→fresh transition, so it does
    not spam every check while the tower stays down."""

    def __init__(
        self,
        *,
        heartbeat_path: str | Path,
        max_silence_s: float,
        channel,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(max_silence_s, (int, float)) or max_silence_s <= 0:
            raise ValidationError("DeadMansSwitch max_silence_s must be > 0")
        self._path = Path(heartbeat_path)
        self._max = float(max_silence_s)
        self._channel = channel
        self._clock = clock
        self._fired = False

    async def check(self, *, now: float | None = None) -> DeadManVerdict:
        now = self._clock() if now is None else now
        age = heartbeat_age_s(self._path, now=now)
        stale = age is None or age > self._max
        verdict = DeadManVerdict(alive=not stale, age_s=age)
        if stale and not self._fired:
            await self._channel.send(self._stale_page(age))
            self._fired = True
        elif not stale and self._fired:
            await self._channel.send(self._recovered_page(age))
            self._fired = False
        return verdict

    def _stale_page(self, age: float | None) -> Page:
        where = "absent" if age is None else f"stale (age {age:.0f}s > max {self._max:.0f}s)"
        return Page(
            swap_id=_WATCHTOWER,
            intent=None,
            severity=Severity.CRITICAL,
            message=(
                f"watchtower heartbeat {where} — the tower may be DOWN; "
                "operator must self-defend any in-flight swaps (claim/refund) until it is restored"
            ),
            recommended_action="restart the watchtower and/or manually watch in-flight swaps",
            deadline_rxd_height=None,
            low_corroboration=False,
        )

    def _recovered_page(self, age: float | None) -> Page:
        return Page(
            swap_id=_WATCHTOWER,
            intent=None,
            severity=Severity.INFO,
            message=f"watchtower heartbeat recovered (age {age:.0f}s)",
            recommended_action=None,
            deadline_rxd_height=None,
            low_corroboration=False,
        )


async def run_monitor(
    switch: DeadMansSwitch,
    *,
    interval_s: float,
    stop=None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    max_iterations: int | None = None,
) -> int:
    """Poll the dead-man's switch on ``interval_s`` until ``stop`` (or ``max_iterations``).
    Returns the number of checks run. ``sleep``/``max_iterations`` are injected for tests."""
    import asyncio

    if not isinstance(switch, DeadMansSwitch):
        raise ValidationError("run_monitor requires a DeadMansSwitch")
    if not isinstance(interval_s, (int, float)) or interval_s < 0:
        raise ValidationError("run_monitor interval_s must be >= 0")
    sleep = sleep or asyncio.sleep
    checks = 0
    while not (stop is not None and stop.is_set()):
        if max_iterations is not None and checks >= max_iterations:
            break
        await switch.check()
        checks += 1
        if (stop is not None and stop.is_set()) or (max_iterations is not None and checks >= max_iterations):
            break
        await sleep(interval_s)
    return checks

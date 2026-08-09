#!/usr/bin/env python3
"""Second-channel escalation monitor for the watchtower.

The tower pages the operator on the **primary** channel and re-pages a time-critical
CRITICAL situation (claim/squeeze race) every tick until the operator ACKs it
(``FileAckInbox`` → :meth:`~pyrxd.gravity.watch.alerts.DedupAlerter.ack`). The number of
still-un-ACK'd CRITICAL situations is published on the heartbeat as ``unacked_critical``.

That signal answers the question the primary channel cannot answer about *itself*: **the
operator is not seeing the page.** A pager that is muted, a webhook whose receiver is down,
a phone in a drawer — the tower keeps paging into it happily. This module is the consumer
that notices, and pages a **different** channel.

It is a THIRD process, supervised separately from both the tower and the dead-man's-switch,
and it talks to them only through files:

    tower ──writes──▶ heartbeat.json ──read by──▶ dead-man's-switch   (is the tower alive?)
                            │
                            └────────read by──▶ escalation monitor    (is the OPERATOR alive?)

Example::

    pyrxd-watchtower-escalate \\
        --heartbeat-file /run/wt/hb.json \\
        --escalate-after-s 900 --max-silence-s 180 --check-interval-s 60 \\
        --primary-webhook-url https://ntfy.sh/my-watchtower \\
        --webhook-url https://escalation.example/hook

Design notes that are load-bearing (each one is a way this could silently do nothing):

**The threshold is TIME, not ticks.** This process does not tick with the tower and has no
idea what its poll interval is. "Un-ACK'd for 15 minutes" is measured in the **tower's own
clock** — the ``ts`` of the first consecutive beat that reported ``unacked_critical > 0``,
compared against the ``ts`` of the latest beat. A monitor that counted its own iterations
would escalate at a wall-clock time that silently depends on someone else's config.

**The count is read fail-closed.** Zero is the only value that means "nothing to escalate":

===========================  ==========================================================
observed                     action
===========================  ==========================================================
``unacked_critical`` absent  refuse to start — the producer is not wired, and "absent"
                             is not "zero" (at runtime: escalate, we went blind)
``-1``                       escalate immediately — the count source raised; blind
``> 0`` past the threshold   escalate
beat stale / future-dated    do NOT escalate on the count (the dead-man's-switch owns
                             that alarm); ONE edge-triggered WARN on the escalation
                             channel, which doubles as proof that channel is alive
heartbeat file absent        refuse to start — a typo'd path must not read as "quiet"
unknown ``schema_version``   refuse to start (at runtime: escalate, we went blind)
===========================  ==========================================================

**State is persisted, not in-memory.** ``first_unacked_ts`` lives in a 0600 file written
atomically beside the heartbeat. An in-memory clock would let a crash-restart loop defer
escalation forever — every restart would begin the countdown again, which is precisely the
condition (a sick host) under which you most want the escalation to fire.

**The channel must actually be different.** The monitor refuses to start when its webhook
URL equals the tower's (normalized compare) unless ``--allow-same-channel``. A "second
channel" that shares the first one's outage is not a second channel.

Run it under a supervisor with ``Restart=on-failure``. Delivery failures are guarded (log,
retry next interval, never advance ``fired``) so a flaky escalation endpoint cannot crash
the monitor, but a supervisor still covers an unexpected exit / OOM.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import stat
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

from pyrxd.gravity.watch.alerts import Page, Severity

# `_CLOCK_SKEW_TOLERANCE_S` and `_WATCHTOWER` are imported rather than re-declared: the skew
# tolerance is a fail-closed security constant that MUST match the dead-man's-switch (two
# monitors disagreeing about what "future-dated" means is a gap), and the system-page swap_id
# is the convention a receiver filters on. Same package, one source of truth.
from pyrxd.gravity.watch.heartbeat import (
    _CLOCK_SKEW_TOLERANCE_S,
    _WATCHTOWER,
    HEARTBEAT_SCHEMA_VERSION,
)
from pyrxd.security.errors import RxdSdkError, ValidationError

__all__ = [
    "MAX_STATE_FILE_BYTES",
    "BeatReading",
    "EscalationMonitor",
    "EscalationState",
    "EscalationVerdict",
    "check_distinct_channels",
    "default_state_path",
    "main",
    "preflight_heartbeat",
    "read_beat",
    "run_escalation_monitor",
]

logger = logging.getLogger(__name__)

#: Ceiling on a state-file read. The state is five scalars; anything approaching this is a
#: wrong path or a hostile file, and an unbounded read would wedge the check.
MAX_STATE_FILE_BYTES = 64 * 1024

#: Suffix appended to the heartbeat path for the default state file.
_STATE_SUFFIX = ".escalation-state.json"


# --------------------------------------------------------------------------------------
# Reading the heartbeat
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class BeatReading:
    """One read of the heartbeat file, with every failure mode kept DISTINGUISHABLE.

    Collapsing "absent", "unparseable", "key missing" and "0" into one value is the whole bug
    class this type exists to prevent, so nothing here defaults to a healthy-looking value:

    * ``ts`` — ``None`` when the file is absent/unreadable/has no timestamp.
    * ``unacked`` — ``None`` when the key is ABSENT or not an int (producer not wired);
      ``-1`` is the producer's own "my count source raised" sentinel and is passed through.
    * ``schema_version`` — ``None`` when absent or not an int.
    * ``error`` — a human-readable reason when the read failed at all.
    """

    ts: float | None
    unacked: int | None
    schema_version: int | None
    error: str | None = None

    def __post_init__(self) -> None:
        if self.ts is not None and not isinstance(self.ts, (int, float)):
            raise ValidationError("BeatReading ts must be a number or None")
        if self.unacked is not None and (not isinstance(self.unacked, int) or isinstance(self.unacked, bool)):
            raise ValidationError("BeatReading unacked must be an int or None")
        if self.schema_version is not None and (
            not isinstance(self.schema_version, int) or isinstance(self.schema_version, bool)
        ):
            raise ValidationError("BeatReading schema_version must be an int or None")

    @property
    def schema_known(self) -> bool:
        return self.schema_version == HEARTBEAT_SCHEMA_VERSION


def read_beat(path: str | Path) -> BeatReading:
    """Read one heartbeat without raising: every fault becomes a field on :class:`BeatReading`.

    This runs on every check of a long-lived monitor, so a transient/hostile file must degrade
    to a *readable verdict*, never to a crash — the caller decides what each fault means.
    """
    try:
        raw = Path(path).read_text()
    except (OSError, ValueError) as exc:  # ValueError covers a non-UTF-8 file (UnicodeDecodeError)
        return BeatReading(ts=None, unacked=None, schema_version=None, error=f"unreadable: {exc}")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return BeatReading(ts=None, unacked=None, schema_version=None, error=f"not JSON: {exc}")
    if not isinstance(data, dict):
        return BeatReading(ts=None, unacked=None, schema_version=None, error="not a JSON object")
    ts = data.get("ts")
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        ts = None
    version = data.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        version = None
    unacked = data.get("unacked_critical")
    if not isinstance(unacked, int) or isinstance(unacked, bool):
        # Absent OR non-int — both mean "this beat does not carry a trustworthy count".
        unacked = None
    return BeatReading(ts=None if ts is None else float(ts), unacked=unacked, schema_version=version)


def preflight_heartbeat(path: str | Path) -> BeatReading:
    """Startup gate: the heartbeat must exist AND carry a count this monitor can interpret.

    Refusing here is the point. Every condition below is one where the monitor would otherwise
    run forever looking perfectly healthy while escalating nothing:

    * file absent → a typo'd ``--heartbeat-file`` would read as "no swaps in trouble" forever.
    * ``unacked_critical`` absent → the tower was started WITHOUT the count source wired
      (``run.py`` wires it automatically; a custom shell may not), so the count can never rise.
    * ``schema_version`` unknown → this monitor does not know what the fields mean.

    Staleness is deliberately NOT fatal here: the tower may legitimately be starting up
    alongside the monitor, and staleness is the dead-man's-switch's alarm, not this one's.

    Raises:
        ValidationError: on any of the above.
    """
    beat = read_beat(path)
    if beat.error is not None:
        raise ValidationError(
            f"--heartbeat-file {path} is {beat.error} — refusing to start. An escalation monitor "
            "pointed at a file that is not there would report 'nothing to escalate' forever. Start "
            "the tower with --heartbeat-file first, and pass the SAME path here."
        )
    if beat.schema_version is None or not beat.schema_known:
        raise ValidationError(
            f"--heartbeat-file {path} has schema_version={beat.schema_version!r}; this monitor "
            f"understands only {HEARTBEAT_SCHEMA_VERSION}. Refusing to guess at the meaning of the "
            "escalation count. Upgrade the tower (it writes the version) before the monitor."
        )
    if beat.unacked is None:
        raise ValidationError(
            f"--heartbeat-file {path} carries no `unacked_critical` key — refusing to start. An "
            "absent count is NOT zero: it means the tower is running without the un-ACK'd CRITICAL "
            "count wired into its heartbeat, so this monitor could never escalate. Run the tower "
            "from `pyrxd-watchtower` (which wires it) and give the operator an --ack-inbox."
        )
    return beat


# --------------------------------------------------------------------------------------
# Persisted state
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EscalationState:
    """The monitor's memory, persisted so a restart cannot rewind the escalation clock.

    ``first_unacked_ts`` and ``last_escalated_ts`` are in the **tower's** clock domain (beat
    ``ts`` values), because the threshold is compared against beat timestamps.

    ``blind_warned`` is the edge for the stale-beat WARN. It is persisted for the same reason
    as the rest: a crash loop would otherwise re-send that WARN on every restart.
    """

    first_unacked_ts: float | None = None
    last_escalated_ts: float | None = None
    fired: bool = False
    blind_warned: bool = False

    def __post_init__(self) -> None:
        for name in ("first_unacked_ts", "last_escalated_ts"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool)):
                raise ValidationError(f"EscalationState {name} must be a number or None")
        for name in ("fired", "blind_warned"):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"EscalationState {name} must be a bool")
        if self.fired and self.first_unacked_ts is None and self.last_escalated_ts is None:
            raise ValidationError("EscalationState cannot be `fired` with no timestamps recorded")

    def to_dict(self) -> dict:
        return {
            "first_unacked_ts": self.first_unacked_ts,
            "last_escalated_ts": self.last_escalated_ts,
            "fired": self.fired,
            "blind_warned": self.blind_warned,
        }


def default_state_path(heartbeat_path: str | Path) -> Path:
    """The state file sits beside the heartbeat (same directory, derived name)."""
    hb = Path(heartbeat_path)
    return hb.with_name(hb.name + _STATE_SUFFIX)


def _load_state(path: Path) -> EscalationState:
    """Read the persisted state, or a fresh one.

    A missing file is the normal first run. A corrupt / wrong-mode / foreign-owned file is
    logged loudly and treated as fresh rather than fatal: refusing to start would turn a
    cosmetic corruption into *no escalation at all*, which is strictly the worse failure. The
    deferral this costs is bounded by one ``escalate_after_s`` window, not unbounded — and an
    attacker who can rewrite this 0600 file can equally well delete it.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except FileNotFoundError:
        return EscalationState()
    except OSError as exc:
        logger.error("escalation state %s is unreadable (%s) — starting from a FRESH state", path, exc)
        return EscalationState()
    try:
        if os.name == "posix":
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                logger.error("escalation state %s is not a regular file — starting FRESH", path)
                return EscalationState()
            if st.st_mode & 0o077:
                logger.error(
                    "escalation state %s has mode %s; must be 0o600 (anyone who can write it can defer "
                    "escalation) — starting FRESH. Run `chmod 600 %s`.",
                    path,
                    oct(st.st_mode & 0o777),
                    path,
                )
                return EscalationState()
            if st.st_uid != os.geteuid():
                logger.error(
                    "escalation state %s is owned by uid %d, not this process's uid %d — starting FRESH",
                    path,
                    st.st_uid,
                    os.geteuid(),
                )
                return EscalationState()
        data = os.read(fd, MAX_STATE_FILE_BYTES + 1)
    except OSError as exc:
        logger.error("escalation state %s read failed (%s) — starting FRESH", path, exc)
        return EscalationState()
    finally:
        os.close(fd)
    if len(data) > MAX_STATE_FILE_BYTES:
        logger.error("escalation state %s exceeds %d bytes — starting FRESH", path, MAX_STATE_FILE_BYTES)
        return EscalationState()
    try:
        parsed = json.loads(data.decode("utf-8"))
        return EscalationState(
            first_unacked_ts=parsed.get("first_unacked_ts"),
            last_escalated_ts=parsed.get("last_escalated_ts"),
            fired=bool(parsed.get("fired", False)),
            blind_warned=bool(parsed.get("blind_warned", False)),
        )
    except (UnicodeDecodeError, ValueError, AttributeError, ValidationError) as exc:
        logger.error("escalation state %s is corrupt (%s) — starting FRESH", path, exc)
        return EscalationState()


def _store_state(path: Path, state: EscalationState) -> None:
    """Atomically persist the state, 0600, tmp + ``os.replace`` (the ``FileHeartbeat`` convention).

    The 0600 is applied by ``os.open`` at creation, not by a later ``chmod`` — a chmod leaves a
    window in which the file is world-readable/writable at the umask's mercy.
    """
    tmp = path.with_name(path.name + ".tmp")
    body = json.dumps(state.to_dict()).encode()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        os.write(fd, body)
    finally:
        os.close(fd)
    os.replace(tmp, path)  # atomic on the same filesystem


# --------------------------------------------------------------------------------------
# Channel distinctness
# --------------------------------------------------------------------------------------


def _normalize_url(url: str) -> tuple[str, str, str, str]:
    """Normalize for an equality compare: scheme/host case + default port + trailing slash.

    Path and query keep their case — a webhook token or an ntfy topic is case-sensitive, and
    lowercasing them would make two genuinely distinct endpoints compare equal (the one
    direction of error this check must not make).
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    try:
        host = (parts.hostname or "").lower()
        default_port = {"http": 80, "https": 443}.get(scheme)
        port = parts.port if parts.port is not None else default_port
        netloc = host if port is None else f"{host}:{port}"
    except ValueError:
        # An unparseable port. Fall back to the raw authority: a malformed URL is the webhook
        # channel's problem to report, and this compare must still be conservative (two
        # identical malformed URLs are still the same channel).
        netloc = parts.netloc.lower()
    path = parts.path.rstrip("/")
    return (scheme, netloc, path, parts.query)


def check_distinct_channels(escalation_url: str, primary_url: str | None, *, allow_same: bool = False) -> None:
    """Enforce that the escalation channel is not the tower's own channel.

    "Use a different channel" as documentation is a suggestion the busy operator skips; the one
    configuration that makes this whole process pointless is worth failing on. A shared channel
    that is itself down (or muted, which is the *reason* the count is climbing) hides both the
    original page and its escalation.

    A same-HOST/different-endpoint pair (two ntfy topics, say) is allowed but WARNED: it does
    survive a muted topic, not a provider outage.

    Raises:
        ValidationError: the two URLs are the same endpoint and ``allow_same`` is False.
    """
    if primary_url is None:
        return
    esc, pri = _normalize_url(escalation_url), _normalize_url(primary_url)
    if esc == pri:
        if allow_same:
            logger.warning(
                "--allow-same-channel: escalating to the SAME endpoint the tower already pages. If the "
                "operator is missing the primary page because that channel is muted or down, they will "
                "miss the escalation for the identical reason."
            )
            return
        raise ValidationError(
            "--webhook-url is the same endpoint as --primary-webhook-url. The escalation channel exists "
            "to survive the primary one being muted/down/ignored — pointing both at one endpoint makes "
            "this monitor a no-op. Use a different channel, or pass --allow-same-channel if you really "
            "mean it (e.g. a smoke test)."
        )
    if esc[1] == pri[1]:
        logger.warning(
            "escalation and primary webhooks share the host %r — distinct endpoints, but one provider "
            "outage still hides BOTH signals. Prefer a different provider/transport.",
            esc[1],
        )


# --------------------------------------------------------------------------------------
# The monitor
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class EscalationVerdict:
    """Outcome of one check — what the monitor saw and whether it acted."""

    unacked: int | None  # None = the beat carried no trustworthy count
    fresh: bool  # False = stale/absent/future-dated; the dead-man's-switch owns that alarm
    unacked_for_s: float | None  # tower-clock seconds the count has been non-zero
    escalated: bool  # a CRITICAL escalation page was DELIVERED on this check
    blind_warned: bool  # the edge-triggered "monitor is blind" WARN was DELIVERED on this check
    recovered: bool  # the INFO recovery page was DELIVERED on this check

    def __post_init__(self) -> None:
        if self.unacked is not None and (not isinstance(self.unacked, int) or isinstance(self.unacked, bool)):
            raise ValidationError("EscalationVerdict unacked must be an int or None")
        if self.unacked_for_s is not None and (
            not isinstance(self.unacked_for_s, (int, float)) or isinstance(self.unacked_for_s, bool)
        ):
            raise ValidationError("EscalationVerdict unacked_for_s must be a number or None")
        for name in ("fresh", "escalated", "blind_warned", "recovered"):
            if not isinstance(getattr(self, name), bool):
                raise ValidationError(f"EscalationVerdict {name} must be a bool")


class EscalationMonitor:
    """Escalates a persistently un-ACK'd CRITICAL situation to a second channel.

    Edge-triggered: one escalation per un-ACK'd episode (plus an optional
    ``re_escalate_every_s`` reminder), and one INFO recovery when the count returns to zero —
    so a stuck situation does not turn the escalation channel into the noise the operator was
    already ignoring.

    Args:
        heartbeat_path: the file the tower writes each tick.
        channel: the ESCALATION :class:`~pyrxd.gravity.watch.alerts.AlertChannel` — distinct
            from the tower's (see :func:`check_distinct_channels`).
        escalate_after_s: tower-clock seconds ``unacked_critical`` must stay non-zero.
        max_silence_s: a beat older than this is stale — the count is not acted on.
        state_path: where the persisted state lives (defaults beside the heartbeat).
        re_escalate_every_s: ``0`` (default) = escalate once per episode; otherwise re-send a
            reminder no more often than this many tower-clock seconds.
        clock: injected wall clock (freshness only; the threshold uses the tower's ``ts``).
    """

    def __init__(
        self,
        *,
        heartbeat_path: str | Path,
        channel,
        escalate_after_s: float,
        max_silence_s: float,
        state_path: str | Path | None = None,
        re_escalate_every_s: float = 0.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(escalate_after_s, (int, float)) or escalate_after_s < 0:
            raise ValidationError("EscalationMonitor escalate_after_s must be >= 0")
        if not isinstance(max_silence_s, (int, float)) or max_silence_s <= 0:
            raise ValidationError("EscalationMonitor max_silence_s must be > 0")
        if not isinstance(re_escalate_every_s, (int, float)) or re_escalate_every_s < 0:
            raise ValidationError("EscalationMonitor re_escalate_every_s must be >= 0")
        self._path = Path(heartbeat_path)
        self._channel = channel
        self._after = float(escalate_after_s)
        self._max = float(max_silence_s)
        self._re_escalate = float(re_escalate_every_s)
        self._state_path = Path(state_path) if state_path is not None else default_state_path(self._path)
        self._clock = clock
        self._state = _load_state(self._state_path)

    @property
    def state(self) -> EscalationState:
        return self._state

    @property
    def state_path(self) -> Path:
        return self._state_path

    async def check(self, *, now: float | None = None) -> EscalationVerdict:
        """One poll: read the beat, advance the state machine, page if warranted."""
        now = self._clock() if now is None else now
        beat = read_beat(self._path)
        age = None if beat.ts is None else now - beat.ts
        # Freshness uses OUR clock against the tower's ts; the same fail-closed skew guard the
        # dead-man's-switch applies (a future-dated ts is a fault, not liveness) — importing the
        # constant rather than re-declaring it keeps the two monitors in lockstep.
        fresh = age is not None and age <= self._max and age >= -_CLOCK_SKEW_TOLERANCE_S

        before = self._state
        if fresh and beat.ts is not None:
            verdict = await self._on_fresh(beat, beat.ts)
        else:
            verdict = await self._on_blind(beat, age)
        if self._state != before:
            self._persist()
        return verdict

    async def _on_blind(self, beat: BeatReading, age: float | None) -> EscalationVerdict:
        """Stale/absent/future-dated beat: the dead-man's-switch owns this alarm, not us.

        Double-paging two processes on one condition is its own failure — it trains the operator
        that escalation pages are duplicates. But going quiet is not right either: we cannot see
        the count, and an operator who never hears from this channel cannot tell "healthy" from
        "this monitor died in March". So: ONE edge-triggered WARN, which doubles as a liveness
        proof for the escalation channel itself.

        ``first_unacked_ts`` / ``fired`` are deliberately PRESERVED across the blind window — a
        tower that dies while a CRITICAL is un-ACK'd must not get the escalation clock reset.
        """
        warned = False
        if not self._state.blind_warned and await self._try_send(self._blind_page(beat, age)):
            self._state = replace(self._state, blind_warned=True)
            warned = True
        return EscalationVerdict(
            unacked=beat.unacked,
            fresh=False,
            unacked_for_s=None,
            escalated=False,
            blind_warned=warned,
            recovered=False,
        )

    async def _on_fresh(self, beat: BeatReading, beat_ts: float) -> EscalationVerdict:
        if self._state.blind_warned:
            # Re-arm the blind edge (no page: the recovery of OUR visibility is not the operator's
            # problem, and the dead-man's-switch already pages the tower's own recovery).
            logger.info("escalation monitor can read the heartbeat again")
            self._state = replace(self._state, blind_warned=False)

        # Fail-closed on an uninterpretable count. Absent, non-int, the producer's -1 sentinel, or
        # a schema we do not know all mean the SAME thing: we cannot see the escalation signal.
        # "Cannot see" is not "zero" — it is the state in which an unacknowledged claim race would
        # go unnoticed, so it escalates immediately rather than after the threshold.
        if not beat.schema_known or beat.unacked is None or beat.unacked < 0:
            return await self._escalate_blind_count(beat, beat_ts)

        if beat.unacked == 0:
            return await self._recover()

        first = self._state.first_unacked_ts
        if first is None:
            first = beat_ts
            self._state = replace(self._state, first_unacked_ts=first)
        # Tower-clock elapsed. Both endpoints come from beats, so the monitor's own clock, its
        # restart history, and its check interval are all irrelevant to WHEN this fires.
        elapsed = beat_ts - first
        escalated = False
        due = elapsed >= self._after and self._should_send(beat_ts)
        if due and await self._try_send(self._escalation_page(beat, elapsed)):
            self._state = replace(self._state, fired=True, last_escalated_ts=beat_ts)
            escalated = True
        return EscalationVerdict(
            unacked=beat.unacked,
            fresh=True,
            unacked_for_s=elapsed,
            escalated=escalated,
            blind_warned=False,
            recovered=False,
        )

    def _should_send(self, beat_ts: float) -> bool:
        """First crossing of the threshold, or a due re-escalation reminder."""
        if not self._state.fired:
            return True
        if self._re_escalate <= 0:
            return False
        last = self._state.last_escalated_ts
        return last is None or (beat_ts - last) >= self._re_escalate

    async def _escalate_blind_count(self, beat: BeatReading, beat_ts: float) -> EscalationVerdict:
        escalated = False
        if not self._state.fired and await self._try_send(self._blind_count_page(beat)):
            self._state = replace(self._state, fired=True, last_escalated_ts=beat_ts, first_unacked_ts=beat_ts)
            escalated = True
        return EscalationVerdict(
            unacked=beat.unacked,
            fresh=True,
            unacked_for_s=None,
            escalated=escalated,
            blind_warned=False,
            recovered=False,
        )

    async def _recover(self) -> EscalationVerdict:
        """Count back to zero: reset, and page INFO if we had escalated (mirrors the
        dead-man's-switch's recovery notification — an escalation with no visible end leaves the
        operator unsure whether it is still live)."""
        recovered = False
        if self._state.fired:
            if not await self._try_send(self._recovered_page()):
                # Do NOT clear the state on a failed send: the next check re-sends the recovery
                # rather than silently leaving the operator on a CRITICAL that has already passed.
                return EscalationVerdict(
                    unacked=0, fresh=True, unacked_for_s=None, escalated=False, blind_warned=False, recovered=False
                )
            recovered = True
        self._state = replace(self._state, first_unacked_ts=None, last_escalated_ts=None, fired=False)
        return EscalationVerdict(
            unacked=0, fresh=True, unacked_for_s=None, escalated=False, blind_warned=False, recovered=recovered
        )

    def _persist(self) -> None:
        try:
            _store_state(self._state_path, self._state)
        except OSError as exc:
            # A read-only/full filesystem must not crash the monitor: the in-memory state is still
            # correct for this process, we have merely lost restart-durability. Loud, not fatal.
            logger.error(
                "escalation state %s could NOT be persisted (%s) — the escalation clock will reset "
                "if this process restarts",
                self._state_path,
                exc,
            )

    async def _try_send(self, page: Page) -> bool:
        try:
            await self._channel.send(page)
            return True
        except Exception as exc:  # a channel error must never crash the escalation monitor
            logger.error("escalation alert delivery FAILED (will retry next interval): %s", exc)
            return False

    def _escalation_page(self, beat: BeatReading, elapsed: float) -> Page:
        return Page(
            swap_id=_WATCHTOWER,
            intent=None,
            severity=Severity.CRITICAL,
            message=(
                f"ESCALATION: {beat.unacked} CRITICAL watchtower page(s) have gone UNACKNOWLEDGED for "
                f"{elapsed:.0f}s (threshold {self._after:.0f}s). The tower is alive and paging — the "
                "primary channel is not reaching anyone. Time-critical claim/refund deadlines are "
                "running down while nobody is acting."
            ),
            recommended_action=(
                "check the primary alert channel, then act on the outstanding swap(s) and ACK them "
                "(append each swap_id to the tower's --ack-inbox)"
            ),
            deadline_rxd_height=None,
            low_corroboration=False,
        )

    def _blind_count_page(self, beat: BeatReading) -> Page:
        if not beat.schema_known:
            why = (
                f"the heartbeat reports schema_version={beat.schema_version!r}, which this monitor does "
                f"not understand (expected {HEARTBEAT_SCHEMA_VERSION})"
            )
        elif beat.unacked is None:
            why = "the heartbeat carries no `unacked_critical` key — the tower's count source is not wired"
        else:
            why = "the tower's un-ACK'd CRITICAL count source RAISED (it published the -1 sentinel)"
        return Page(
            swap_id=_WATCHTOWER,
            intent=None,
            severity=Severity.CRITICAL,
            message=(
                f"ESCALATION (blind): {why}. The tower is alive, but the escalation signal is "
                "unreadable — an unacknowledged claim race would now go unnoticed. This is NOT 'zero "
                "outstanding'."
            ),
            recommended_action="fix the tower's heartbeat/ACK wiring; until then watch in-flight swaps manually",
            deadline_rxd_height=None,
            low_corroboration=False,
        )

    def _blind_page(self, beat: BeatReading, age: float | None) -> Page:
        if age is None:
            where = f"absent or unreadable ({beat.error or 'no timestamp'})"
        elif age < 0:
            where = f"future-dated (age {age:.0f}s — clock skew or a stuck/forged heartbeat)"
        else:
            where = f"stale (age {age:.0f}s > max {self._max:.0f}s)"
        return Page(
            swap_id=_WATCHTOWER,
            intent=None,
            severity=Severity.WARN,
            message=(
                f"escalation monitor is BLIND: the heartbeat is {where}, so the un-ACK'd CRITICAL count "
                "cannot be read. The dead-man's-switch owns the 'tower is down' alarm — this is a "
                "one-shot notice that second-channel escalation is not covering you right now (and "
                "that this channel works)."
            ),
            recommended_action="check the dead-man's-switch page and restore the tower",
            deadline_rxd_height=None,
            low_corroboration=False,
        )

    def _recovered_page(self) -> Page:
        return Page(
            swap_id=_WATCHTOWER,
            intent=None,
            severity=Severity.INFO,
            message="escalation cleared: all CRITICAL watchtower pages are acknowledged (unacked_critical=0)",
            recommended_action=None,
            deadline_rxd_height=None,
            low_corroboration=False,
        )


async def run_escalation_monitor(
    monitor: EscalationMonitor,
    *,
    interval_s: float,
    stop=None,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    max_iterations: int | None = None,
) -> int:
    """Poll the escalation monitor on ``interval_s`` until ``stop`` (or ``max_iterations``).

    Returns the number of checks run. ``sleep``/``max_iterations`` are injected for tests
    (mirrors :func:`~pyrxd.gravity.watch.heartbeat.run_monitor` and
    :func:`~pyrxd.gravity.watch.daemon.run_loop`).
    """
    import asyncio

    if not isinstance(monitor, EscalationMonitor):
        raise ValidationError("run_escalation_monitor requires an EscalationMonitor")
    if not isinstance(interval_s, (int, float)) or interval_s < 0:
        raise ValidationError("run_escalation_monitor interval_s must be >= 0")
    if max_iterations is not None and (not isinstance(max_iterations, int) or max_iterations < 0):
        raise ValidationError("run_escalation_monitor max_iterations must be a non-negative int or None")
    sleep = sleep or asyncio.sleep
    checks = 0
    while not (stop is not None and stop.is_set()):
        if max_iterations is not None and checks >= max_iterations:
            break
        await monitor.check()
        checks += 1
        if (stop is not None and stop.is_set()) or (max_iterations is not None and checks >= max_iterations):
            break
        await sleep(interval_s)
    return checks


# --------------------------------------------------------------------------------------
# Console-script shell
# --------------------------------------------------------------------------------------


def _build_alert_channel(args, session):
    from pyrxd.gravity.watch.adapters import CompositeAlertChannel, LoggingAlertChannel, WebhookAlertChannel
    from pyrxd.gravity.watch.cli_secrets import resolve_secret

    auth = None
    auth_header = resolve_secret(
        args.webhook_auth_header,
        args.webhook_auth_header_file,
        "PYRXD_WATCHTOWER_ESCALATE_WEBHOOK_AUTH_HEADER",
        flag="--webhook-auth-header",
        logger=logger,
    )
    if auth_header:
        key, _, val = auth_header.partition(":")
        auth = {key.strip(): val.strip()}
    secret = resolve_secret(
        args.webhook_secret,
        args.webhook_secret_file,
        "PYRXD_WATCHTOWER_ESCALATE_WEBHOOK_SECRET",
        flag="--webhook-secret",
        logger=logger,
    )
    return CompositeAlertChannel(
        LoggingAlertChannel(logging.getLogger("pyrxd.watchtower.escalation.alert")),
        WebhookAlertChannel(args.webhook_url, session=session, auth_header=auth, hmac_secret=secret),
    )


def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Watchtower second-channel escalation monitor (un-ACK'd CRITICAL pages)")
    p.add_argument("--heartbeat-file", required=True, help="the liveness file the tower writes each tick")
    p.add_argument(
        "--webhook-url",
        required=True,
        help="the ESCALATION channel — POST the escalation page here. Must be a DIFFERENT channel "
        "from the tower's --webhook-url (that is the entire point).",
    )
    p.add_argument(
        "--primary-webhook-url",
        help="the tower's own --webhook-url, so this monitor can REFUSE to escalate to the same "
        "endpoint. Required unless --allow-same-channel.",
    )
    p.add_argument(
        "--allow-same-channel",
        action="store_true",
        help="permit the escalation webhook to equal the tower's (smoke tests only — a shared "
        "channel that is muted or down hides both the page and its escalation)",
    )
    p.add_argument(
        "--escalate-after-s",
        type=float,
        default=900.0,
        help="escalate once unacked_critical has been non-zero for this many seconds of the TOWER's "
        "clock (default 900). Size it well under the tightest in-flight (deadline - safety window).",
    )
    p.add_argument(
        "--max-silence-s",
        type=float,
        default=180.0,
        help="a heartbeat older than this is stale: the count is not acted on (the dead-man's-switch "
        "owns that alarm). Match the value you run pyrxd-watchtower-deadman with.",
    )
    p.add_argument("--check-interval-s", type=float, default=60.0)
    p.add_argument(
        "--re-escalate-every-s",
        type=float,
        default=0.0,
        help="0 (default) = one escalation per episode. Otherwise re-send a reminder no more often "
        "than this many seconds while the count stays non-zero.",
    )
    p.add_argument(
        "--state-file",
        help="persisted {first_unacked_ts, last_escalated_ts, fired} (0600). Defaults to the "
        "heartbeat path + '.escalation-state.json'. Persisted so a restart loop cannot rewind the "
        "escalation clock.",
    )
    p.add_argument(
        "--webhook-auth-header",
        help="DEPRECATED (process-table/shell-history exposure) optional 'Header: value' for the "
        "webhook; prefer --webhook-auth-header-file or PYRXD_WATCHTOWER_ESCALATE_WEBHOOK_AUTH_HEADER",
    )
    p.add_argument(
        "--webhook-auth-header-file",
        help="read the 'Header: value' auth header from this (0600) file instead of the command line",
    )
    p.add_argument(
        "--webhook-secret",
        help="DEPRECATED (process-table/shell-history exposure) optional HMAC-SHA256 secret -> "
        "X-Watchtower-Signature header; prefer --webhook-secret-file or "
        "PYRXD_WATCHTOWER_ESCALATE_WEBHOOK_SECRET",
    )
    p.add_argument(
        "--webhook-secret-file",
        help="read the HMAC-SHA256 secret from this (0600) file instead of the command line",
    )
    p.add_argument("--once", action="store_true", help="check once and exit")
    return p.parse_args(argv)


async def _amain(argv=None) -> int:
    import asyncio
    import contextlib
    import signal

    import aiohttp

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = _parse_args(argv)

    if args.primary_webhook_url is None and not args.allow_same_channel:
        raise ValidationError(
            "--primary-webhook-url is required so this monitor can verify it is escalating to a "
            "DIFFERENT channel than the tower pages. Pass the tower's --webhook-url, or "
            "--allow-same-channel to skip the check."
        )
    check_distinct_channels(args.webhook_url, args.primary_webhook_url, allow_same=args.allow_same_channel)
    # Startup gates BEFORE the event loop does any real work: a bad heartbeat path or an unwired
    # count must be an exit code the supervisor shows, not a monitor that runs forever seeing
    # nothing.
    preflight_heartbeat(args.heartbeat_file)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    async with aiohttp.ClientSession() as session:
        monitor = EscalationMonitor(
            heartbeat_path=args.heartbeat_file,
            channel=_build_alert_channel(args, session),
            escalate_after_s=args.escalate_after_s,
            max_silence_s=args.max_silence_s,
            state_path=args.state_file,
            re_escalate_every_s=args.re_escalate_every_s,
        )
        logger.info(
            "escalation monitor watching %s (escalate after %.0fs un-ACK'd, stale past %.0fs, check "
            "every %.0fs, state %s)",
            args.heartbeat_file,
            args.escalate_after_s,
            args.max_silence_s,
            args.check_interval_s,
            monitor.state_path,
        )
        checks = await run_escalation_monitor(
            monitor,
            interval_s=args.check_interval_s,
            stop=stop,
            max_iterations=1 if args.once else None,
        )
    logger.info("escalation monitor stopped after %d check(s)", checks)
    return 0


def main(argv=None) -> int:
    """Console-script shell. Returns the process exit code (0 ok, 1 config/preflight refusal).

    Every refusal in this module is a typed :class:`~pyrxd.security.errors.ValidationError`
    (package code must be embeddable, and the watch package has an AST test enforcing that no
    bare ``SystemExit`` survives in it); this shell is the single place that becomes an exit code.
    """
    import asyncio

    try:
        return asyncio.run(_amain(argv))
    except RxdSdkError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

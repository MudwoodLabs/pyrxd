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

Dedup is by swap and situation (the intent and the decision's ``situation`` tag); a page is
recorded only AFTER a successful send, so a transient channel failure is retried on the next
tick rather than silently lost.

Time-critical CRITICAL intents (``PAGE_CLAIM`` / ``PAGE_SQUEEZED``) are the exception to
"page once per situation": a single missed page on a claim/squeeze race silently loses
funds if the operator does not see it (review MEDIUM). Those intents RE-PAGE on a
tick-count backoff (``repage_critical_every_ticks``, default every tick) for as long as
the situation persists — bounded by the swap's lifecycle (it stops when the intent
changes or the swap retires). WARN/INFO intents keep the once-per-situation dedup.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol, runtime_checkable

from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.security.errors import ValidationError

__all__ = ["AlertChannel", "DedupAlerter", "FileAckInbox", "Page", "Severity"]

logger = logging.getLogger("pyrxd.watchtower.alerts")


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
    # The chain settled the counter leg and the record lags it (#850 PR 9b): nothing is at risk.
    Intent.RECONCILE: Severity.INFO,
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


@runtime_checkable
class AckingAlerter(Protocol):
    """An alerter that can consume operator acknowledgements.

    Deliberately NOT folded into the reconciler's ``Alerter`` port: the reconciler never
    calls ``ack``, and requiring it would break every minimal third-party alerter. It is
    the *shell* that needs it, to wire ``--ack-inbox``, so the shell probes for it with
    ``isinstance`` and refuses to start when the configured alerter cannot honour the
    inbox — rather than raising ``AttributeError`` inside the per-tick hook, where the
    loop's guard would log it and carry on with every ACK silently discarded.

    :class:`DedupAlerter` satisfies it.
    """

    def ack(self, swap_id: str, situation_key: str | None = None) -> bool: ...


def _situation_key(intent: Intent, situation: str | None) -> str:
    """The text an operator writes after the swap id to ACK one situation (third Mythos pass, F2)."""
    return intent.value if situation is None else f"{intent.value}:{situation}"


def _message(swap_id: str, decision: Decision, severity: Severity) -> str:
    parts = [f"[{severity.value.upper()}] swap {swap_id}: {decision.reason}"]
    if decision.recommended_action:
        parts.append(f"action: {decision.recommended_action}")
    if decision.deadline_rxd_height is not None:
        parts.append(f"by RXD height {decision.deadline_rxd_height}")
    if decision.low_corroboration:
        parts.append("(LOW CORROBORATION — single-source RXD or BTC read; verify before acting)")
    if severity is Severity.CRITICAL:
        parts.append(f"ack: {swap_id} {_situation_key(decision.intent, decision.situation)}")
    return " | ".join(parts)


#: What one swap's page is about, for dedup and ACK: its intent and the decision's ``situation`` tag.
#: Two decisions with the same intent but a different tag are different situations (#850 PR 9b,
#: Mythos F1). Severity is not part of it: a situation that paged CRITICAL stays CRITICAL while it is
#: open, so one ``urgent`` tick keeps it CRITICAL, re-paged, until it is ACKed, and a tick that reads
#: it less urgent neither pages again nor drops the ACK (re-review of the F3 fix; second pass, L1).
_Situation = tuple[Intent, "str | None"]

#: How many ticks in a row a swap's situation may be absent (another situation, or a quiet tick)
#: before it closes: its ACK ends, it leaves the escalation count, and it pages again if it comes
#: back. Chosen, not measured: at the shipped 30 s poll interval it is 5 minutes, longer than the
#: one- or two-tick read failures the third Mythos pass and its re-review drove through the alerter.
DEFAULT_SITUATION_HOLD_TICKS = 10


def _severity(decision: Decision) -> Severity | None:
    """The page's severity: the intent's, raised to CRITICAL on an ``urgent`` refund page."""
    if decision.urgent:
        return Severity.CRITICAL
    return _SEVERITY.get(decision.intent)


@dataclass
class _SwapPages:
    """One swap's page state. ``tick`` counts the swap's ticks (each :meth:`DedupAlerter.handle` or
    :meth:`DedupAlerter.resolve`); a situation is *open* while it is in ``paged``."""

    tick: int = 0
    live: _Situation | None = None
    paged: dict[_Situation, Severity] = field(default_factory=dict)  # open situations, highest severity
    seen: dict[_Situation, int] = field(default_factory=dict)  # the last tick each was live
    acked: set[_Situation] = field(default_factory=set)
    # CRITICAL situations whose page failed to send: open and counted for escalation (the second
    # channel exists for a primary that is down), and sent as new once the channel is back.
    undelivered: set[_Situation] = field(default_factory=set)
    critical_ticks: int = 0  # ticks since the live CRITICAL last (re)paged: the re-page backoff


class DedupAlerter:
    """Routes actionable Decisions to an :class:`AlertChannel`, de-duplicated by swap and
    situation (intent and ``situation`` tag). Satisfies the reconciler's ``Alerter`` port
    structurally.

    A situation is *open* from its first delivered page until it has been absent for
    ``situation_hold_ticks`` ticks in a row (another situation, or a quiet tick reported through
    :meth:`resolve`), or the swap retires (third Mythos pass and its re-review):

    * a WARN or INFO situation pages once while it is open, even when the swap alternates between
      two of them (F4, F5);
    * a CRITICAL situation re-pages on the backoff while it is live, unless the operator ACKed it,
      and counts in :meth:`unacked_critical_count` while it is open and un-ACKed, so a one-tick read
      failure neither ends an ACK nor resets escalation (F1);
    * an ACK binds to one open situation and ends when that situation closes, so the same danger
      coming back later pages again, and an ACK written after it closed records nothing.
    """

    def __init__(
        self,
        *,
        channel: AlertChannel,
        repage_critical_every_ticks: int = 1,
        situation_hold_ticks: int = DEFAULT_SITUATION_HOLD_TICKS,
    ) -> None:
        for name, value in (
            ("repage_critical_every_ticks", repage_critical_every_ticks),
            ("situation_hold_ticks", situation_hold_ticks),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValidationError(f"{name} must be an int >= 1")
        self._channel = channel
        self._swaps: dict[str, _SwapPages] = {}
        self._repage_every = repage_critical_every_ticks
        self._hold = situation_hold_ticks

    def _advance(self, swap_id: str) -> _SwapPages:
        """Start a tick for the swap and close the situations absent for longer than the hold."""
        st = self._swaps.setdefault(swap_id, _SwapPages())
        st.tick += 1
        for situation in [x for x, last in st.seen.items() if st.tick - last > self._hold]:
            st.seen.pop(situation, None)
            st.paged.pop(situation, None)
            st.acked.discard(situation)
            st.undelivered.discard(situation)
            if st.live == situation:
                st.live = None
        return st

    @staticmethod
    def _open_critical(st: _SwapPages) -> list[_Situation]:
        # An undelivered CRITICAL is open too: escalation counts it, so the operator the second
        # channel reaches must be able to ACK it (tower Mythos pass, F6).
        opened = [x for x, sev in st.paged.items() if sev is Severity.CRITICAL]
        return opened + [x for x in st.undelivered if x not in opened]

    def ack(self, swap_id: str, situation_key: str | None = None) -> bool:
        """Operator acknowledgement of one of a swap's open CRITICAL pages.

        With ``situation_key`` (the text after the swap id on the page's ``ack:`` line) it ACKs that
        situation if it is open. A bare swap id ACKs only when the swap has exactly one open, un-ACKed
        CRITICAL situation and no ACK yet; otherwise the operator may have meant another page, so nothing is
        recorded and the pages keep firing (third Mythos pass, F2). Returns True if an ACK was
        recorded.
        """
        st = self._swaps.get(swap_id)
        if st is None:
            return False
        if situation_key is not None:
            for situation in self._open_critical(st):
                if _situation_key(*situation) == situation_key:
                    st.acked.add(situation)
                    return True
            return False
        pending = [x for x in self._open_critical(st) if x not in st.acked]
        if st.acked or len(pending) != 1:
            # A swap with an ACK already: the same bare line appended again (shell history) would
            # otherwise land on a page that opened after it was written (re-review, finding 2a).
            return False
        st.acked.add(pending[0])
        return True

    def resolve(self, swap_id: str) -> None:
        """The swap's decision is quiet this tick (WATCH or NOOP): a tick on which no situation is
        live, so open situations move toward closing (F3)."""
        st = self._advance(swap_id)
        st.live = None

    def unacked_critical_count(self) -> int:
        """Number of swaps with an open CRITICAL situation the operator has NOT ACK'd.

        The escalation signal fed into the heartbeat (review MEDIUM): a persistent non-zero count
        means time-critical claim/squeeze pages are outstanding and unacknowledged, so an external
        monitor / second channel can escalate beyond the primary page channel.
        """
        # An ACK takes an undelivered page off the count too: one written while the channel is
        # down otherwise counted until the situation closed (tower Mythos pass, F2).
        return sum(1 for st in self._swaps.values() if any(x not in st.acked for x in self._open_critical(st)))

    async def handle(self, swap_id: str, decision: Decision) -> None:
        if not isinstance(decision, Decision):
            raise ValidationError("DedupAlerter.handle requires a Decision")
        intent = decision.intent
        severity = _severity(decision)
        if severity is None:
            # WATCH / NOOP — not an alertable event (the reconciler shouldn't route these,
            # but stay defensive rather than paging noise).
            return
        situation: _Situation = (intent, decision.situation)
        if intent is Intent.RETIRE:
            # The swap is done — clear its state so it cannot leak or mis-count a future swap
            # reusing the id. The INFO "done" page still dedups below.
            old = self._swaps.get(swap_id)
            fresh = _SwapPages()
            if old is not None and situation in old.paged:
                fresh.tick, fresh.live = old.tick, situation
                fresh.paged[situation], fresh.seen[situation] = old.paged[situation], old.tick
            self._swaps[swap_id] = fresh
        st = self._advance(swap_id)
        before = st.paged.get(situation)
        was_live = st.live == situation
        if before is not None:
            # Open already, so it is live this tick whether or not a page goes out.
            st.live, st.seen[situation] = situation, st.tick
        if before is not None and not (severity is Severity.CRITICAL and before is not Severity.CRITICAL):
            # Paged while open, at no lower severity (an escalation to CRITICAL pages at once).
            # WARN/INFO page once while open. A CRITICAL (claim/squeeze) race RE-PAGES on the
            # tick-count backoff so a single missed page cannot silently lose funds (review MEDIUM),
            # unless the operator ACK'd it (they are handling it); one that comes back from another
            # situation re-pages at once.
            severity = before
            if severity is not Severity.CRITICAL:
                return
            if situation in st.acked:
                return
            if was_live:
                st.critical_ticks += 1
                if st.critical_ticks < self._repage_every:
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
        # Send first; record the page only on success so a transient channel failure is retried
        # next tick rather than silently swallowed. A CRITICAL that never went out is kept apart
        # (``undelivered``) so escalation still counts it.
        try:
            await self._channel.send(page)
        except BaseException:
            if severity is Severity.CRITICAL:  # new, or a WARN escalating: counts while undelivered
                st.undelivered.add(situation)
                st.seen[situation] = st.tick
            raise
        st.undelivered.discard(situation)
        st.paged[situation] = severity
        st.live, st.seen[situation] = situation, st.tick
        st.critical_ticks = 0  # reset the re-page backoff after a successful (re)page


#: A drained ACK line: a swap id, optionally followed by the situation key the page printed on its
#: ``ack:`` line (third Mythos pass, F2). The records store keys swaps by a JSON file stem, so the
#: id is deliberately filename-shaped. Anything else is a typo or a probe, and is dropped before it
#: ever reaches :meth:`DedupAlerter.ack`.
_ACK_LINE_RE = re.compile(
    # ``<records-store>`` is the reconciler's id for its store-unreadable page.
    r"\A(?:[A-Za-z0-9._:-]{1,128}|<records-store>)(?: [a-z_]{1,32}(?::[A-Za-z0-9._:-]{1,96})?)?\Z"
)

#: Ceiling on one drain. The drain runs on the daemon's ``on_tick_start`` hook, which fires
#: OUTSIDE the per-tick watchdog (``daemon.run_loop`` calls it before ``asyncio.wait_for``),
#: so an unbounded read of an attacker-grown file would stall the tower past the
#: dead-man's-switch window with no timeout to catch it. 64 KiB is ~1000 ACKs.
MAX_ACK_INBOX_BYTES = 64 * 1024


class FileAckInbox:
    """Operator → watchtower ACK transport (the mirror of :class:`FileHeartbeat`).

    The operator acknowledges a paged CRITICAL situation by appending the page's ``ack:`` line
    (the swap id and the situation key, one per line) to a file — e.g.
    ``(umask 077; echo "<swap_id> <key>" >> $WATCHTOWER_ACKS)``. A bare swap id still works when it is
    unambiguous (:meth:`DedupAlerter.ack`). The daemon shell drains this inbox once per tick
    (wire it as ``run_loop(on_tick_start=...)``) and calls :meth:`DedupAlerter.ack` for each
    line, so re-paging for that situation stops and the un-ACK'd CRITICAL count drops.

    :meth:`drain` is atomic against a concurrent appender: it renames the inbox aside before
    reading and puts an empty 0600 inbox back at once, so ids appended during the read land in
    that file and are consumed next tick (an ACK is never double-consumed; one appended in the
    instant between the rename and the re-create lands in a file made under the writer's umask,
    which the gate below refuses unless the writer used ``umask 077``).

    **This inbox is a control channel, not a log.** An ACK suppresses CRITICAL re-pages and
    zeroes ``unacked_critical_count`` — the external escalation signal — so anyone who can
    write the file can silence the tower during a claim race. It is therefore held to the
    same bar as the (far lower-value) webhook secret file:

    * **0600 + owner** — a group/world-writable or foreign-owned inbox is REFUSED. Refusal
      is fail-closed *toward paging*: the claimed contents are dropped (so the pages keep
      firing) and an ERROR names the required ``chmod``. Create it with
      ``install -m 600 /dev/null "$WATCHTOWER_ACKS"``.
    * **no symlink / regular file only** — checked via ``O_NOFOLLOW`` + ``fstat`` on the same
      fd that is read, so there is no stat/read TOCTOU.
    * **bounded read** (:data:`MAX_ACK_INBOX_BYTES`) — see that constant: this runs outside
      the tick watchdog.
    * **lossy decode** — decoded with ``errors="replace"``. A strict decode would raise
      *after* the ``os.replace`` had already claimed the file, and the ``finally: unlink``
      would then destroy every pending ACK because of one bad byte. The mangled line simply
      fails :data:`_ACK_LINE_RE` and is dropped.

    Lines that do not match :data:`_ACK_LINE_RE` are dropped here; lines that match but name no
    CRITICAL situation are already inert (:meth:`DedupAlerter.ack` returns ``False``
    without recording anything).
    """

    def __init__(self, path: str | Path, *, max_bytes: int = MAX_ACK_INBOX_BYTES) -> None:
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
            raise ValidationError("FileAckInbox max_bytes must be an int >= 1")
        self._path = Path(path)
        self._max_bytes = max_bytes

    def drain(self) -> list[str]:
        tmp = self._path.with_name(self._path.name + ".draining")
        try:
            os.replace(self._path, tmp)  # atomically claim the current inbox contents
        except FileNotFoundError:
            self._recreate()
            return []
        except OSError as exc:  # e.g. EACCES/EISDIR on a hostile path — never crash the tick
            logger.error("ACK inbox %s could not be claimed for draining: %s", self._path, exc)
            return []
        # Put an empty 0600 inbox back at once. Without it the operator's next ``echo ... >>``
        # created the file under their umask (0644 or 0664 by default), the gate below refused it,
        # and every ACK written as the runbook says was dropped (tower Mythos pass, F1).
        self._recreate()
        try:
            content = self._read_checked(tmp)
        finally:
            tmp.unlink(missing_ok=True)
        if content is None:
            return []
        ids: list[str] = []
        for line in content.splitlines():
            candidate = " ".join(line.split())
            if not candidate:
                continue
            if not _ACK_LINE_RE.match(candidate):
                logger.warning("ACK inbox %s: dropping malformed swap id (%d chars)", self._path, len(candidate))
                continue
            ids.append(candidate)
        return ids

    def _recreate(self) -> None:
        """Create the inbox empty, owner-only, unless something is already there. An append that
        lands between the claim and this create makes the file under the writer's umask; such a
        file is refused at the next drain and replaced here, so that ACK is dropped (the page keeps
        firing) and the next one works. The runbook's ``umask 077`` closes that window."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            os.close(os.open(str(self._path), flags, 0o600))
        except (FileExistsError, FileNotFoundError):  # already there, or no directory (nothing to fix here)
            pass
        except OSError as exc:
            logger.error("ACK inbox %s could not be recreated (%s) — create it with mode 600", self._path, exc)

    def _read_checked(self, tmp: Path) -> str | None:
        """Read the claimed inbox under the mode/owner/size gate. ``None`` = refused."""
        # O_NONBLOCK so a FIFO left at this path returns instead of blocking the tick forever
        # (it is then refused by the S_ISREG check); inert for a regular file.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            fd = os.open(str(tmp), flags)
        except OSError as exc:
            logger.error("ACK inbox %s is unreadable (%s) — ACKs dropped, pages will keep firing", self._path, exc)
            return None
        try:
            if os.name == "posix":
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    logger.error("ACK inbox %s is not a regular file — REFUSED (ACKs dropped)", self._path)
                    return None
                mode = st.st_mode & 0o777
                if mode & 0o077:
                    logger.error(
                        "ACK inbox %s has mode %s; must be 0o600 (owner-only) — REFUSED, ACKs dropped and "
                        "CRITICAL pages will keep firing. Any local user who can write this file can silence "
                        "the tower. Run `chmod 600 %s`.",
                        self._path,
                        oct(mode),
                        self._path,
                    )
                    return None
                if st.st_uid != os.geteuid():
                    logger.error(
                        "ACK inbox %s is owned by uid %d, not this process's uid %d — REFUSED (ACKs dropped)",
                        self._path,
                        st.st_uid,
                        os.geteuid(),
                    )
                    return None
            data = os.read(fd, self._max_bytes + 1)
        except OSError as exc:
            logger.error("ACK inbox %s read failed (%s) — ACKs dropped", self._path, exc)
            return None
        finally:
            os.close(fd)
        truncated = len(data) > self._max_bytes
        if truncated:
            # Keep only whole lines: the cut can land mid-id, and a half id must not be ACK'd.
            data = data[: self._max_bytes]
            data = data[: data.rfind(b"\n") + 1]
            logger.error(
                "ACK inbox %s exceeded %d bytes — truncated to whole lines; the remainder is DROPPED "
                "(re-append any ids that were not acknowledged)",
                self._path,
                self._max_bytes,
            )
        # errors="replace": a strict decode would raise after the file was already claimed, and
        # the caller's `finally: unlink` would destroy every pending ACK over one bad byte.
        return data.decode("utf-8", errors="replace")

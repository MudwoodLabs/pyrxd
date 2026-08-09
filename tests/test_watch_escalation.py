"""Second-channel escalation monitor (`pyrxd.gravity.watch.escalation`).

The producer side of this signal shipped first: the tower re-pages a CRITICAL claim/squeeze
race every tick, an operator ACK inbox quiets it, and the un-ACK'd count rides on the
heartbeat. What was missing is a consumer -- an *automatic* escalation to a DIFFERENT channel
when that count persists, i.e. when the primary channel is not reaching anyone.

Everything here is about the ways such a monitor silently does nothing:

* it reads a count that is absent and calls it zero,
* it counts its own iterations instead of the tower's clock,
* it keeps its clock in memory, so a crash loop restarts the countdown forever,
* it escalates to the channel that is already being ignored,
* it double-pages the dead-man's-switch's alarm until the operator mutes both.

Each of those has a test below. Time is injected everywhere -- no wall clock, no sleeps.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from pyrxd.gravity.watch import DedupAlerter, FileAckInbox, FileHeartbeat
from pyrxd.gravity.watch.alerts import Severity
from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.gravity.watch.escalation import (
    EscalationMonitor,
    EscalationState,
    check_distinct_channels,
    default_state_path,
    preflight_heartbeat,
    read_beat,
    run_escalation_monitor,
)
from pyrxd.gravity.watch.escalation import main as escalation_main
from pyrxd.gravity.watch.heartbeat import HEARTBEAT_SCHEMA_VERSION
from pyrxd.gravity.watch.reconciler import ReconcileResult
from pyrxd.security.errors import ValidationError

TOWER_TS = 1_000_000.0


class RecordingChannel:
    """Collects pages. `fail_next` makes one send raise, to model a flaky endpoint."""

    def __init__(self) -> None:
        self.pages: list = []
        self.fail_next = 0

    async def send(self, page) -> None:
        if self.fail_next > 0:
            self.fail_next -= 1
            raise RuntimeError("escalation endpoint unreachable")
        self.pages.append(page)

    @property
    def severities(self) -> list[Severity]:
        return [p.severity for p in self.pages]


def write_beat(path: Path, *, ts: float = TOWER_TS, unacked: int | None = 0, schema: int | None = -1) -> None:
    """Write a heartbeat by hand. `schema=-1` means "use the current version"; `None` omits the
    key entirely (an older tower); `unacked=None` omits the count (an unwired tower)."""
    data: dict = {"ts": ts, "tick": 1, "swaps": 0, "paged": 0}
    if schema is not None:
        data["schema_version"] = HEARTBEAT_SCHEMA_VERSION if schema == -1 else schema
    if unacked is not None:
        data["unacked_critical"] = unacked
    path.write_text(json.dumps(data))


def make_monitor(
    hb: Path,
    channel: RecordingChannel,
    *,
    escalate_after_s: float = 900.0,
    max_silence_s: float = 180.0,
    now: float = TOWER_TS,
    **kwargs,
) -> EscalationMonitor:
    return EscalationMonitor(
        heartbeat_path=hb,
        channel=channel,
        escalate_after_s=escalate_after_s,
        max_silence_s=max_silence_s,
        clock=lambda: now,
        **kwargs,
    )


# --- the heartbeat producer contract -------------------------------------------------


def test_heartbeat_carries_the_schema_version(tmp_path: Path) -> None:
    """The version is what lets a consumer refuse to guess at the fields' meaning."""
    beat = FileHeartbeat(tmp_path / "hb.json", clock=lambda: TOWER_TS)
    beat(1, [ReconcileResult("a", Decision(Intent.WATCH, reason="x"))])

    payload = json.loads((tmp_path / "hb.json").read_text())
    assert payload["schema_version"] == HEARTBEAT_SCHEMA_VERSION
    assert payload["ts"] == TOWER_TS  # purely additive: the dead-man's-switch still reads ts


def test_read_beat_distinguishes_every_failure_mode(tmp_path: Path) -> None:
    """Absent / unparseable / key-missing / zero must NOT collapse into one value."""
    hb = tmp_path / "hb.json"
    assert read_beat(hb).error is not None  # absent

    hb.write_text("{not json")
    assert read_beat(hb).error is not None

    write_beat(hb, unacked=None)
    reading = read_beat(hb)
    assert reading.error is None and reading.unacked is None  # key ABSENT, not zero

    write_beat(hb, unacked=0)
    assert read_beat(hb).unacked == 0

    write_beat(hb, unacked=-1)
    assert read_beat(hb).unacked == -1


# --- startup refusals ----------------------------------------------------------------


def test_preflight_refuses_an_absent_heartbeat(tmp_path: Path) -> None:
    """A typo'd path would otherwise report "nothing to escalate" forever."""
    with pytest.raises(ValidationError, match="refusing to start"):
        preflight_heartbeat(tmp_path / "nope.json")


def test_preflight_refuses_a_heartbeat_with_no_count(tmp_path: Path) -> None:
    """The core fail-closed reading: an ABSENT count is not zero, it is "not wired"."""
    hb = tmp_path / "hb.json"
    write_beat(hb, unacked=None)
    with pytest.raises(ValidationError, match="no `unacked_critical` key"):
        preflight_heartbeat(hb)


def test_preflight_refuses_an_unknown_schema_version(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    write_beat(hb, unacked=0, schema=HEARTBEAT_SCHEMA_VERSION + 7)
    with pytest.raises(ValidationError, match="schema_version"):
        preflight_heartbeat(hb)

    write_beat(hb, unacked=0, schema=None)  # an older tower: no version at all
    with pytest.raises(ValidationError, match="schema_version"):
        preflight_heartbeat(hb)


def test_preflight_accepts_a_stale_but_well_formed_beat(tmp_path: Path) -> None:
    """Staleness is the dead-man's-switch's alarm; the tower may simply be starting up."""
    hb = tmp_path / "hb.json"
    write_beat(hb, ts=1.0, unacked=0)
    assert preflight_heartbeat(hb).unacked == 0


# --- channel distinctness ------------------------------------------------------------


def test_identical_channel_is_refused() -> None:
    with pytest.raises(ValidationError, match="same endpoint"):
        check_distinct_channels("https://ntfy.sh/wt", "https://ntfy.sh/wt")


def test_identical_channel_is_detected_through_url_normalization() -> None:
    """Case, default port and a trailing slash must not disguise the same endpoint."""
    with pytest.raises(ValidationError, match="same endpoint"):
        check_distinct_channels("https://NTFY.sh:443/wt/", "https://ntfy.sh/wt")


def test_distinct_topics_on_one_host_are_allowed() -> None:
    """Path case is significant -- two ntfy topics are genuinely different endpoints."""
    check_distinct_channels("https://ntfy.sh/wt-escalate", "https://ntfy.sh/wt")


def test_allow_same_channel_is_an_explicit_opt_out() -> None:
    check_distinct_channels("https://ntfy.sh/wt", "https://ntfy.sh/wt", allow_same=True)


# --- the time-based threshold --------------------------------------------------------


async def test_no_escalation_before_the_threshold(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=900.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    verdict = await monitor.check(now=TOWER_TS)
    assert verdict.escalated is False and verdict.unacked_for_s == 0.0

    write_beat(hb, ts=TOWER_TS + 899, unacked=1)
    assert (await monitor.check(now=TOWER_TS + 899)).escalated is False
    assert channel.pages == []


async def test_escalates_on_the_towers_clock_not_on_tick_count(tmp_path: Path) -> None:
    """The decisive property: the monitor does not tick with the tower, so the threshold is
    measured between BEAT timestamps. One hundred fast checks must not escalate early, and a
    single check that observes an old-enough first beat must."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=900.0)

    write_beat(hb, ts=TOWER_TS, unacked=2)
    for _ in range(100):  # a monitor counting its own iterations would have fired by now
        await monitor.check(now=TOWER_TS)
    assert channel.pages == []

    write_beat(hb, ts=TOWER_TS + 900, unacked=2)
    verdict = await monitor.check(now=TOWER_TS + 900)
    assert verdict.escalated is True
    assert verdict.unacked_for_s == 900.0
    assert channel.severities == [Severity.CRITICAL]
    assert "UNACKNOWLEDGED" in channel.pages[0].message


async def test_escalation_is_edge_triggered(tmp_path: Path) -> None:
    """One page per episode -- an escalation channel that repeats becomes the channel the
    operator is already ignoring."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=10.0)

    for offset in (0, 10, 20, 30):
        write_beat(hb, ts=TOWER_TS + offset, unacked=1)
        await monitor.check(now=TOWER_TS + offset)
    assert len(channel.pages) == 1


async def test_re_escalation_reminder_is_opt_in_and_rate_limited(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=0.0, re_escalate_every_s=100.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    await monitor.check(now=TOWER_TS)
    assert len(channel.pages) == 1

    write_beat(hb, ts=TOWER_TS + 50, unacked=1)  # too soon for a reminder
    await monitor.check(now=TOWER_TS + 50)
    assert len(channel.pages) == 1

    write_beat(hb, ts=TOWER_TS + 100, unacked=1)
    await monitor.check(now=TOWER_TS + 100)
    assert len(channel.pages) == 2


# --- fail-closed readings of the count -----------------------------------------------


async def test_minus_one_sentinel_escalates_immediately(tmp_path: Path) -> None:
    """`FileHeartbeat` writes -1 when the count source raises. That is "blind", not "zero" --
    and blind must not wait out a threshold that assumes we can see."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=9_000.0)

    write_beat(hb, ts=TOWER_TS, unacked=-1)
    verdict = await monitor.check(now=TOWER_TS)

    assert verdict.escalated is True
    assert channel.severities == [Severity.CRITICAL]
    assert "-1 sentinel" in channel.pages[0].message


async def test_a_count_that_vanishes_at_runtime_escalates_immediately(tmp_path: Path) -> None:
    """Startup refuses an absent key; at runtime we cannot refuse, so we escalate. Reading it
    as zero here would be the same bug one process later."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=9_000.0)

    write_beat(hb, ts=TOWER_TS, unacked=None)
    assert (await monitor.check(now=TOWER_TS)).escalated is True
    assert "not wired" in channel.pages[0].message


async def test_an_unknown_schema_at_runtime_escalates_immediately(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel)

    write_beat(hb, ts=TOWER_TS, unacked=0, schema=HEARTBEAT_SCHEMA_VERSION + 1)
    assert (await monitor.check(now=TOWER_TS)).escalated is True
    assert "does not understand" in channel.pages[0].message


# --- staleness belongs to the dead-man's-switch --------------------------------------


async def test_a_stale_beat_warns_once_and_never_escalates_on_the_count(tmp_path: Path) -> None:
    """Double-paging one condition from two processes trains the operator to ignore both.
    The WARN is one-shot and doubles as proof the escalation channel is alive."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, max_silence_s=180.0)

    write_beat(hb, ts=TOWER_TS, unacked=5)
    for offset in (500, 600, 700):
        verdict = await monitor.check(now=TOWER_TS + offset)
        assert verdict.fresh is False and verdict.escalated is False
    assert channel.severities == [Severity.WARN]
    assert "BLIND" in channel.pages[0].message


async def test_a_future_dated_beat_is_a_fault_not_freshness(tmp_path: Path) -> None:
    """Same fail-closed skew guard the dead-man's-switch applies: a ts ahead of our clock is a
    stuck/forged/skewed beat, so we must not act on the count it carries."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=0.0)

    write_beat(hb, ts=TOWER_TS + 5_000, unacked=3)
    verdict = await monitor.check(now=TOWER_TS)

    assert verdict.fresh is False and verdict.escalated is False
    assert channel.severities == [Severity.WARN]
    assert "future-dated" in channel.pages[0].message


async def test_an_absent_heartbeat_at_runtime_does_not_escalate_on_the_count(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=0.0)

    verdict = await monitor.check(now=TOWER_TS)
    assert verdict.fresh is False and verdict.escalated is False
    assert channel.severities == [Severity.WARN]


async def test_going_blind_does_not_rewind_the_escalation_clock(tmp_path: Path) -> None:
    """A tower that dies WHILE a CRITICAL is un-ACK'd must not buy itself a fresh countdown."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=300.0, max_silence_s=180.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    await monitor.check(now=TOWER_TS)  # clock starts
    await monitor.check(now=TOWER_TS + 1_000)  # tower silent -> blind WARN
    assert monitor.state.first_unacked_ts == TOWER_TS

    write_beat(hb, ts=TOWER_TS + 1_100, unacked=1)  # tower back, still un-ACK'd
    verdict = await monitor.check(now=TOWER_TS + 1_100)
    assert verdict.escalated is True  # would be False had the blind window reset `first_unacked_ts`


# --- recovery ------------------------------------------------------------------------


async def test_recovery_pages_info_and_resets(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=0.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    await monitor.check(now=TOWER_TS)
    write_beat(hb, ts=TOWER_TS + 10, unacked=0)
    verdict = await monitor.check(now=TOWER_TS + 10)

    assert verdict.recovered is True
    assert channel.severities == [Severity.CRITICAL, Severity.INFO]
    assert monitor.state == EscalationState()  # fully reset -> the next episode escalates again

    write_beat(hb, ts=TOWER_TS + 20, unacked=1)
    assert (await monitor.check(now=TOWER_TS + 20)).escalated is True


async def test_zero_without_a_prior_escalation_pages_nothing(tmp_path: Path) -> None:
    """The healthy steady state must be silent."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel)

    write_beat(hb, ts=TOWER_TS, unacked=0)
    await monitor.check(now=TOWER_TS)
    assert channel.pages == []


async def test_a_transient_non_zero_that_clears_never_escalates(tmp_path: Path) -> None:
    """An operator who ACKs promptly must reset the clock, not shorten the next episode."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=300.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    await monitor.check(now=TOWER_TS)
    write_beat(hb, ts=TOWER_TS + 60, unacked=0)  # ACK'd well inside the window
    await monitor.check(now=TOWER_TS + 60)
    write_beat(hb, ts=TOWER_TS + 120, unacked=1)  # a new situation
    await monitor.check(now=TOWER_TS + 120)
    write_beat(hb, ts=TOWER_TS + 320, unacked=1)  # 200s into the NEW episode, not 320
    await monitor.check(now=TOWER_TS + 320)

    assert channel.pages == []


# --- delivery failures ---------------------------------------------------------------


async def test_a_failed_send_never_advances_fired_and_never_crashes(tmp_path: Path) -> None:
    """The escalation channel being down is the least surprising failure here. It must retry,
    not crash, and must not record an escalation that never left the building."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    channel.fail_next = 1
    monitor = make_monitor(hb, channel, escalate_after_s=0.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    verdict = await monitor.check(now=TOWER_TS)
    assert verdict.escalated is False
    assert monitor.state.fired is False

    write_beat(hb, ts=TOWER_TS + 60, unacked=1)
    assert (await monitor.check(now=TOWER_TS + 60)).escalated is True


async def test_a_failed_recovery_send_is_retried(tmp_path: Path) -> None:
    """Leaving the operator on a CRITICAL that has already passed is its own alert-fatigue bug."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=0.0)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    await monitor.check(now=TOWER_TS)
    channel.fail_next = 1
    write_beat(hb, ts=TOWER_TS + 10, unacked=0)
    assert (await monitor.check(now=TOWER_TS + 10)).recovered is False
    assert monitor.state.fired is True  # not cleared -> the recovery is still owed

    write_beat(hb, ts=TOWER_TS + 20, unacked=0)
    assert (await monitor.check(now=TOWER_TS + 20)).recovered is True


# --- persisted state ------------------------------------------------------------------


async def test_a_restart_loop_cannot_defer_escalation(tmp_path: Path) -> None:
    """The reason the clock is on disk. With in-memory state, a process that dies every check
    restarts the countdown forever -- and "the host is sick" is exactly when you want the page."""
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()

    write_beat(hb, ts=TOWER_TS, unacked=1)
    await make_monitor(hb, channel, escalate_after_s=300.0).check(now=TOWER_TS)

    for offset in (60, 120, 180, 240):  # a fresh process each time
        write_beat(hb, ts=TOWER_TS + offset, unacked=1)
        assert (await make_monitor(hb, channel, escalate_after_s=300.0).check(now=TOWER_TS + offset)).escalated is False

    write_beat(hb, ts=TOWER_TS + 300, unacked=1)
    reborn = make_monitor(hb, channel, escalate_after_s=300.0)
    assert reborn.state.first_unacked_ts == TOWER_TS  # loaded from disk, not reset
    assert (await reborn.check(now=TOWER_TS + 300)).escalated is True


async def test_the_state_file_is_created_0600_beside_the_heartbeat(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel)
    write_beat(hb, ts=TOWER_TS, unacked=1)
    await monitor.check(now=TOWER_TS)

    state_file = default_state_path(hb)
    assert monitor.state_path == state_file
    assert state_file.parent == hb.parent
    assert json.loads(state_file.read_text())["first_unacked_ts"] == TOWER_TS
    if os.name == "posix":
        assert state_file.stat().st_mode & 0o777 == 0o600


async def test_a_corrupt_state_file_starts_fresh_rather_than_bricking_the_monitor(tmp_path: Path) -> None:
    """Refusing to start on a corrupt state file would convert cosmetic damage into no
    escalation at all -- strictly the worse failure. The deferral is one window, not unbounded."""
    hb = tmp_path / "hb.json"
    state = default_state_path(hb)
    state.write_text("}{ not json")
    state.chmod(0o600)
    channel = RecordingChannel()

    write_beat(hb, ts=TOWER_TS, unacked=1)
    monitor = make_monitor(hb, channel, escalate_after_s=0.0)
    assert monitor.state == EscalationState()
    assert (await monitor.check(now=TOWER_TS)).escalated is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
async def test_a_group_writable_state_file_is_not_trusted(tmp_path: Path) -> None:
    """Anyone who can write this file can defer an escalation, so it is held to the same 0600
    bar as the ACK inbox and the webhook secret."""
    hb = tmp_path / "hb.json"
    state = default_state_path(hb)
    state.write_text(json.dumps({"first_unacked_ts": TOWER_TS - 10_000, "fired": False}))
    state.chmod(0o666)

    write_beat(hb, ts=TOWER_TS, unacked=1)
    monitor = make_monitor(hb, RecordingChannel(), escalate_after_s=300.0)

    assert monitor.state == EscalationState()  # the planted early timestamp is ignored
    assert (await monitor.check(now=TOWER_TS)).escalated is False


async def test_an_unpersistable_state_file_logs_but_does_not_crash(tmp_path: Path) -> None:
    """A read-only or full filesystem costs restart-durability, not the escalation itself."""
    hb = tmp_path / "hb.json"
    write_beat(hb, ts=TOWER_TS, unacked=1)
    channel = RecordingChannel()
    monitor = make_monitor(hb, channel, escalate_after_s=0.0, state_path=tmp_path / "no-such-dir" / "state.json")

    assert (await monitor.check(now=TOWER_TS)).escalated is True
    assert monitor.state.fired is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only path types")
async def test_a_state_path_that_is_not_a_regular_file_starts_fresh(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    directory = tmp_path / "state-dir"
    directory.mkdir()
    monitor = make_monitor(hb, RecordingChannel(), state_path=directory)
    assert monitor.state == EscalationState()


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only symlink refusal")
async def test_a_symlinked_state_file_is_refused(tmp_path: Path) -> None:
    """O_NOFOLLOW: a symlink lets someone point our 0600-checked read at a file they control."""
    hb = tmp_path / "hb.json"
    real = tmp_path / "real.json"
    real.write_text(json.dumps({"first_unacked_ts": 1.0, "fired": False}))
    real.chmod(0o600)
    link = tmp_path / "state.json"
    link.symlink_to(real)

    assert make_monitor(hb, RecordingChannel(), state_path=link).state == EscalationState()


async def test_an_oversized_state_file_starts_fresh(tmp_path: Path) -> None:
    from pyrxd.gravity.watch.escalation import MAX_STATE_FILE_BYTES

    hb = tmp_path / "hb.json"
    state = default_state_path(hb)
    state.write_text(" " * (MAX_STATE_FILE_BYTES + 10))
    state.chmod(0o600)
    assert make_monitor(hb, RecordingChannel()).state == EscalationState()


def test_beat_reading_validates_its_fields() -> None:
    from pyrxd.gravity.watch.escalation import BeatReading

    with pytest.raises(ValidationError):
        BeatReading(ts="now", unacked=0, schema_version=1)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        BeatReading(ts=1.0, unacked=1.5, schema_version=1)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        BeatReading(ts=1.0, unacked=0, schema_version="1")  # type: ignore[arg-type]


def test_a_malformed_url_still_compares_conservatively() -> None:
    """An unparseable port must not make two identical URLs look like distinct channels."""
    with pytest.raises(ValidationError, match="same endpoint"):
        check_distinct_channels("https://host:notaport/x", "https://host:notaport/x")


def test_escalation_state_validates_its_fields() -> None:
    with pytest.raises(ValidationError):
        EscalationState(first_unacked_ts="soon")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        EscalationState(fired="yes")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        EscalationState(fired=True)  # fired with nothing recorded is not a reachable state


# --- the loop -------------------------------------------------------------------------


async def test_run_escalation_monitor_honors_max_iterations(tmp_path: Path) -> None:
    hb = tmp_path / "hb.json"
    write_beat(hb, ts=TOWER_TS, unacked=0)
    monitor = make_monitor(hb, RecordingChannel())
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    checks = await run_escalation_monitor(monitor, interval_s=30.0, sleep=fake_sleep, max_iterations=3)

    assert checks == 3
    assert slept == [30.0, 30.0]  # no trailing sleep after the last check


async def test_run_escalation_monitor_rejects_a_wrong_type() -> None:
    with pytest.raises(ValidationError):
        await run_escalation_monitor(object(), interval_s=1.0)  # type: ignore[arg-type]


def test_monitor_validates_its_thresholds(tmp_path: Path) -> None:
    for kwargs in ({"escalate_after_s": -1.0}, {"max_silence_s": 0.0}, {"re_escalate_every_s": -5.0}):
        with pytest.raises(ValidationError):
            make_monitor(tmp_path / "hb.json", RecordingChannel(), **kwargs)


# --- the console-script shell ---------------------------------------------------------


def test_main_runs_a_single_check_and_exits_clean(tmp_path) -> None:
    """The happy path end to end through the real shell: gates pass, one check runs, state is
    written. Nothing is sent (the count is zero), so no network is touched."""
    hb = tmp_path / "hb.json"
    write_beat(hb, ts=TOWER_TS, unacked=1)
    code = escalation_main(
        [
            "--heartbeat-file",
            str(hb),
            "--webhook-url",
            "https://escalate.example/x",
            "--primary-webhook-url",
            "https://ntfy.sh/wt",
            # The fixed test timestamp is ancient in wall-clock terms, and the threshold is set
            # past the heat death of the test suite: the beat counts as fresh, the count is
            # observed and recorded, and nothing is ever sent.
            "--max-silence-s",
            "1e12",
            "--escalate-after-s",
            "1e12",
            "--state-file",
            str(tmp_path / "state.json"),
            "--once",
        ]
    )
    assert code == 0
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["fired"] is False
    assert state["first_unacked_ts"] == TOWER_TS  # the clock started, on disk, from one check


def test_main_refuses_a_bad_webhook_secret_file(tmp_path, capsys) -> None:
    """Secret handling is `cli_secrets.resolve_secret`, not a re-implementation: its 0600 gate
    surfaces here as the same exit code every other watchtower entrypoint produces."""
    hb = tmp_path / "hb.json"
    write_beat(hb, ts=TOWER_TS, unacked=0)
    secret = tmp_path / "secret"
    secret.write_text("hunter2")
    secret.chmod(0o644)
    code = escalation_main(
        [
            "--heartbeat-file",
            str(hb),
            "--webhook-url",
            "https://escalate.example/x",
            "--primary-webhook-url",
            "https://ntfy.sh/wt",
            "--webhook-secret-file",
            str(secret),
            "--once",
        ]
    )
    assert code == 1
    assert "must be 0o600" in capsys.readouterr().err


def test_main_refuses_a_same_channel_config(tmp_path, capsys) -> None:
    """A typed error out of package code, an exit CODE out of the shell -- never a
    process-killing SystemExit an embedder cannot catch."""
    hb = tmp_path / "hb.json"
    write_beat(hb, unacked=0)
    code = escalation_main(
        [
            "--heartbeat-file",
            str(hb),
            "--webhook-url",
            "https://ntfy.sh/wt",
            "--primary-webhook-url",
            "https://ntfy.sh/wt",
            "--once",
        ]
    )
    assert code == 1
    assert "same endpoint" in capsys.readouterr().err


def test_main_requires_the_primary_url_for_the_distinctness_check(tmp_path, capsys) -> None:
    """Distinctness is ENFORCED, so the monitor needs to be told what it must differ from."""
    hb = tmp_path / "hb.json"
    write_beat(hb, unacked=0)
    code = escalation_main(["--heartbeat-file", str(hb), "--webhook-url", "https://escalate.example/x", "--once"])
    assert code == 1
    assert "--primary-webhook-url is required" in capsys.readouterr().err


def test_main_refuses_an_unwired_heartbeat(tmp_path, capsys) -> None:
    hb = tmp_path / "hb.json"
    write_beat(hb, unacked=None)
    code = escalation_main(
        [
            "--heartbeat-file",
            str(hb),
            "--webhook-url",
            "https://escalate.example/x",
            "--primary-webhook-url",
            "https://ntfy.sh/wt",
            "--once",
        ]
    )
    assert code == 1
    assert "unacked_critical" in capsys.readouterr().err


# --- end to end against the real producer ---------------------------------------------


async def test_ack_then_escalation_to_a_different_intent_re_arms_the_count(tmp_path: Path) -> None:
    """The reason `DedupAlerter.ack` keys on the EXACT intent, proven through the whole chain.

    The operator ACKs a claim race; the situation then worsens into a *different* CRITICAL
    (SQUEEZED). If the ACK were keyed by swap_id alone, the count would stay at zero and this
    monitor would never escalate the worse situation. It is keyed by intent, so the count rises
    again -- and once it persists, the escalation fires on the second channel.
    """
    hb = tmp_path / "hb.json"
    inbox_path = tmp_path / "acks"
    alerter = DedupAlerter(channel=RecordingChannel())
    inbox = FileAckInbox(inbox_path)
    tower_clock = {"ts": TOWER_TS}
    beat = FileHeartbeat(hb, clock=lambda: tower_clock["ts"], unacked_critical=alerter.unacked_critical_count)
    escalation_channel = RecordingChannel()
    monitor = make_monitor(hb, escalation_channel, escalate_after_s=300.0)

    results = [ReconcileResult("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))]

    # 1) a CRITICAL claim race is paged and rides the heartbeat
    await alerter.handle("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))
    beat(1, results)
    assert json.loads(hb.read_text())["unacked_critical"] == 1
    assert (await monitor.check(now=tower_clock["ts"])).escalated is False

    # 2) the operator ACKs it -> the count clears, the escalation clock resets
    inbox_path.write_text("swap-1\n")
    inbox_path.chmod(0o600)
    for swap_id in inbox.drain():
        alerter.ack(swap_id)
    tower_clock["ts"] += 60
    beat(2, results)
    assert json.loads(hb.read_text())["unacked_critical"] == 0
    await monitor.check(now=tower_clock["ts"])
    assert monitor.state.first_unacked_ts is None

    # 3) the situation ESCALATES to a different CRITICAL intent -- the ACK does not cover it
    await alerter.handle("swap-1", Decision(Intent.PAGE_SQUEEZED, reason="winner-take-all"))
    tower_clock["ts"] += 60
    beat(3, results)
    assert json.loads(hb.read_text())["unacked_critical"] == 1
    assert (await monitor.check(now=tower_clock["ts"])).escalated is False  # clock restarts here

    # 4) it stays unacknowledged past the threshold -> the SECOND channel is paged
    tower_clock["ts"] += 300
    beat(4, results)
    verdict = await monitor.check(now=tower_clock["ts"])
    assert verdict.escalated is True
    assert escalation_channel.severities == [Severity.CRITICAL]

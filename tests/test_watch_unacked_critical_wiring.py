"""The un-ACK'd CRITICAL escalation signal must survive end to end.

Every piece of this chain already existed -- ``DedupAlerter.unacked_critical_count``,
``DedupAlerter.ack``, ``FileAckInbox`` (with atomic drain), ``FileHeartbeat(unacked_critical=...)``,
``Reconciler.alerter``, and ``run_loop(on_tick_start=...)`` -- but nothing connected them. The
shipped watchtower therefore wrote a heartbeat with **no** ``unacked_critical`` key at all, and had
no ACK path, so the count could never fall to zero even once wired.

That is worse than it sounds for a consumer: an escalation monitor reading the beat cannot tell
"no outstanding pages" from "not wired", and one that latched on a stuck non-zero count would page
forever. These tests pin the assembled chain, not the individual pieces -- those already had
passing unit tests while the composed behavior was broken.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pyrxd.gravity.watch import DedupAlerter, FileAckInbox, FileHeartbeat, default_heartbeat
from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.gravity.watch.reconciler import ReconcileResult


class _CollectingChannel:
    """Collects pages; the transport is not under test here."""

    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, page) -> None:
        self.sent.append(page)


def _results() -> list[ReconcileResult]:
    return [ReconcileResult("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))]


async def test_heartbeat_carries_unacked_critical_when_wired(tmp_path: Path) -> None:
    """A wired FileHeartbeat must emit the key -- absence is indistinguishable from zero."""
    alerter = DedupAlerter(channel=_CollectingChannel())
    hb_path = tmp_path / "beat.json"
    beat = FileHeartbeat(hb_path, clock=lambda: 1000.0, unacked_critical=alerter.unacked_critical_count)

    await alerter.handle("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))
    beat(1, _results())

    payload = json.loads(hb_path.read_text())
    assert "unacked_critical" in payload, "the escalation signal must be present in the beat"
    assert payload["unacked_critical"] == 1


async def test_ack_drops_the_count_to_zero(tmp_path: Path) -> None:
    """Draining an ACK must actually clear the signal -- otherwise escalation latches forever."""
    alerter = DedupAlerter(channel=_CollectingChannel())
    hb_path = tmp_path / "beat.json"
    inbox_path = tmp_path / "acks"
    beat = FileHeartbeat(hb_path, clock=lambda: 1000.0, unacked_critical=alerter.unacked_critical_count)
    inbox = FileAckInbox(inbox_path)

    await alerter.handle("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))
    assert alerter.unacked_critical_count() == 1

    # The operator's documented gesture: append the swap id to the inbox (owner-only, 0600 —
    # a group/world-accessible inbox is a silencing channel and is refused).
    inbox_path.write_text("swap-1\n")
    inbox_path.chmod(0o600)
    for swap_id in inbox.drain():
        alerter.ack(swap_id)

    beat(2, _results())
    assert json.loads(hb_path.read_text())["unacked_critical"] == 0


async def test_unwired_heartbeat_omits_the_key(tmp_path: Path) -> None:
    """Pins the pre-fix shape as the thing a consumer must fail closed on.

    A monitor cannot treat a missing key as "healthy": this is exactly what the shipped tower
    produced, and it means the producer was never connected.
    """
    hb_path = tmp_path / "beat.json"
    beat = FileHeartbeat(hb_path, clock=lambda: 1000.0)  # no unacked_critical= -- the old wiring

    beat(1, _results())

    assert "unacked_critical" not in json.loads(hb_path.read_text())


async def test_the_log_heartbeat_gets_the_count_too(caplog) -> None:
    """The LOG side of the same signal was dead.

    ``default_heartbeat`` raises its tick line to ERROR when un-ACK'd CRITICALs are outstanding,
    but ``run.py`` built it WITHOUT the count source -- so it fell back to the "not wired" -1
    forever, the ERROR escalation could never fire (-1 is not > 0), and the log line contradicted
    the file heartbeat sitting next to it.
    """
    alerter = DedupAlerter(channel=_CollectingChannel())
    await alerter.handle("swap-1", Decision(Intent.PAGE_CLAIM, reason="claim race"))
    beat = default_heartbeat(logging.getLogger("t"), unacked_critical=alerter.unacked_critical_count)

    with caplog.at_level(logging.INFO, logger="t"):
        beat(1, _results())

    record = caplog.records[-1]
    assert "unacked_critical=1" in record.getMessage()
    assert record.levelno == logging.ERROR  # outstanding un-ACK'd CRITICALs must be LOUD

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

import pytest

from pyrxd.gravity.watch import (
    AckingAlerter,
    DedupAlerter,
    FileAckInbox,
    FileHeartbeat,
    default_heartbeat,
)
from pyrxd.gravity.watch.decide import Decision, Intent
from pyrxd.gravity.watch.reconciler import ReconcileResult
from pyrxd.gravity.watch.run import _require_acking_alerter
from pyrxd.security.errors import ValidationError


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


# ---------------------------------------------------------------------------
# The ACK capability must be PROBED, not assumed
# ---------------------------------------------------------------------------
#
# ``Reconciler.alerter`` is typed as the ``Alerter`` port, which declares ``handle`` and
# nothing else — ``ack`` belongs to ``DedupAlerter``. The tick hook called
# ``alerter.ack(...)`` unconditionally. With any other alerter that is an AttributeError
# inside a hook ``run_loop`` deliberately guards, so the tower logged and kept going —
# while ``FileAckInbox.drain`` had already claimed and deleted the inbox, destroying every
# acknowledgement in it. Every tick. The count stays latched and the operator's ACKs
# vanish. The shell now refuses to start instead.


class _HandleOnlyAlerter:
    """A minimal, entirely valid ``Alerter``: it satisfies the port and nothing more."""

    async def handle(self, swap_id: str, decision: Decision) -> None:
        return None


def test_dedup_alerter_satisfies_the_acking_protocol() -> None:
    assert isinstance(DedupAlerter(channel=_CollectingChannel()), AckingAlerter)


def test_a_handle_only_alerter_does_not() -> None:
    assert not isinstance(_HandleOnlyAlerter(), AckingAlerter)


def test_ack_inbox_against_a_non_acking_alerter_is_refused_at_startup() -> None:
    with pytest.raises(ValidationError) as ei:
        _require_acking_alerter(_HandleOnlyAlerter(), "/tmp/acks")
    message = str(ei.value)
    assert "_HandleOnlyAlerter" in message  # names what was actually wired
    assert "ack(swap_id)" in message
    assert "/tmp/acks" in message


def test_ack_inbox_against_a_dedup_alerter_is_accepted() -> None:
    alerter = DedupAlerter(channel=_CollectingChannel())
    assert _require_acking_alerter(alerter, "/tmp/acks") is alerter


def test_the_hook_would_have_destroyed_acks_rather_than_deferring_them(tmp_path: Path) -> None:
    """Why a startup refusal, and not "let the guarded hook log it": the drain is
    destructive and happens BEFORE the first ack() call, so a raise mid-loop loses the
    operator's acknowledgements permanently instead of leaving them for the next tick."""
    inbox_path = tmp_path / "acks"
    inbox_path.write_text("swap-1\nswap-2\n")
    inbox_path.chmod(0o600)
    inbox = FileAckInbox(inbox_path)

    drained = inbox.drain()

    assert drained == ["swap-1", "swap-2"]
    assert not inbox_path.exists()  # already consumed — an AttributeError here loses them
    assert inbox.drain() == []

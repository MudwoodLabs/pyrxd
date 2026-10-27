"""Fixes for the whole-component Mythos pass over the watchtower (register run on e6fb4b2).

* F1: the drain renamed the inbox away, so the runbook's ``echo ... >> $ACKS`` recreated it under the
  operator's umask (0644 by default) and the owner-only gate refused it: every ACK was dropped.
* F2: an ACK written while the page channel was down never took the swap off the escalation count.
* F6: a CRITICAL that never went out counted toward escalation but could not be ACKed.

Every refusal has its honest twin.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.gravity.watch.alerts import DedupAlerter, FileAckInbox
from pyrxd.gravity.watch.decide import SITUATION_CLAIM_RACE, Decision, Intent

SWAP = "swap-1"
RACE = Decision(Intent.PAGE_SQUEEZED, reason="maker revealed p", situation=SITUATION_CLAIM_RACE)
RACE_KEY = "page_squeezed:claim_race"

posix_only = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")


class _Channel:
    def __init__(self) -> None:
        self.sent: list = []
        self.down = False

    async def send(self, page) -> None:
        if self.down:
            raise ConnectionError("channel down")
        self.sent.append(page)


def _append_as_operator(path, line: str, umask: int) -> None:
    """What ``echo "<line>" >> path`` does in a shell with this umask."""
    old = os.umask(umask)
    try:
        with open(path, "a") as f:
            f.write(line + "\n")
    finally:
        os.umask(old)


# --------------------------------------------------------------------------- F1: the inbox keeps its mode


@posix_only
@pytest.mark.parametrize("umask", [0o022, 0o002], ids=["umask-022", "umask-002"])
def test_an_ack_appended_after_a_drain_under_a_default_umask_is_read(tmp_path, umask):
    path = tmp_path / "acks"
    _append_as_operator(path, "first", 0o077)  # created as the runbook's install -m 600 does
    inbox = FileAckInbox(path)
    assert inbox.drain() == ["first"]
    _append_as_operator(path, f"{SWAP} {RACE_KEY}", umask)
    assert inbox.drain() == [f"{SWAP} {RACE_KEY}"], "the ACK was refused: the drain left no inbox to append to"


@posix_only
def test_a_missing_inbox_is_created_owner_only(tmp_path):
    path = tmp_path / "acks"
    inbox = FileAckInbox(path)
    assert inbox.drain() == []
    assert path.stat().st_mode & 0o777 == 0o600
    _append_as_operator(path, SWAP, 0o022)
    assert inbox.drain() == [SWAP]


@posix_only
def test_an_inbox_others_can_write_is_still_refused(tmp_path):
    """The honest twin: the gate is unchanged. A group-writable inbox is refused, and the next
    one, put back owner-only, works."""
    path = tmp_path / "acks"
    path.write_text(f"{SWAP}\n")
    path.chmod(0o620)
    inbox = FileAckInbox(path)
    assert inbox.drain() == [], "a group-writable inbox was read"
    assert path.stat().st_mode & 0o777 == 0o600
    _append_as_operator(path, SWAP, 0o022)
    assert inbox.drain() == [SWAP]


@posix_only
def test_the_inbox_is_not_recreated_through_a_symlink(tmp_path):
    """A link planted at the inbox path between the claim and the re-create is not followed: the
    re-create leaves it alone, and the next drain claims and refuses it."""
    target = tmp_path / "elsewhere"
    path = tmp_path / "acks"
    inbox = FileAckInbox(path)
    path.symlink_to(target)
    inbox._recreate()  # the instant after a claim, with the link already there
    assert not target.exists(), "the re-create followed a planted link"
    assert inbox.drain() == []
    assert not target.exists() and path.is_file() and not path.is_symlink()


# --------------------------------------------------------------------------- F2 and F6: ACKs of undelivered pages


async def test_an_ack_written_while_the_channel_is_down_clears_escalation():
    """F2: the claim race paged, the channel went down, the re-page failed, the operator ACKed it."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(SWAP, RACE)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, RACE)  # the re-page
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack(SWAP, RACE_KEY) is True
    for _ in range(5):
        await alerter.handle(SWAP, RACE)  # ACKed: no re-page is attempted
    assert alerter.unacked_critical_count() == 0, "the ACK did not take the swap off the escalation count"


async def test_an_unacked_page_still_counts_while_the_channel_is_down():
    """The honest twin: without the ACK the swap keeps counting through the outage."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    await alerter.handle(SWAP, RACE)
    ch.down = True
    for _ in range(5):
        with pytest.raises(ConnectionError):
            await alerter.handle(SWAP, RACE)
        assert alerter.unacked_critical_count() == 1


@pytest.mark.parametrize("key", [RACE_KEY, None], ids=["keyed", "bare"])
async def test_a_critical_that_never_went_out_can_be_acked(key):
    """F6: the escalation page tells the operator to ACK; a page whose first send failed could not be."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, RACE)
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack(SWAP, key) is True
    assert alerter.unacked_critical_count() == 0


async def test_an_undelivered_page_is_not_acked_by_a_key_it_does_not_have():
    """The honest twin: only the undelivered page's own key (or an unambiguous bare id) ACKs it."""
    ch = _Channel()
    alerter = DedupAlerter(channel=ch)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, RACE)
    assert alerter.ack(SWAP, "page_squeezed:reconcile_error") is False
    assert alerter.unacked_critical_count() == 1

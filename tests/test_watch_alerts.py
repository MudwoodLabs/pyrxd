"""Tests for the watchtower alert layer (``gravity.watch.alerts``).

Covers severity mapping, dedup by (swap_id, intent), re-page on intent change,
payload contents, the low-corroboration marker, and retry-on-channel-failure
(dedup state only advances after a successful send).
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.watch import DedupAlerter, FileAckInbox, Intent, Page, Severity
from pyrxd.gravity.watch.decide import Decision
from pyrxd.security.errors import ValidationError


class FakeChannel:
    def __init__(self):
        self.sent: list[Page] = []

    async def send(self, page):
        self.sent.append(page)


class FlakyChannel:
    """Raises on the first ``fail_times`` sends, then succeeds."""

    def __init__(self, fail_times: int):
        self._left = fail_times
        self.sent: list[Page] = []

    async def send(self, page):
        if self._left > 0:
            self._left -= 1
            raise RuntimeError("channel down")
        self.sent.append(page)


def _d(intent: Intent, *, action="taker_scrape_and_claim_asset", deadline=172, corr=False) -> Decision:
    return Decision(
        intent,
        reason=f"{intent.value} test",
        recommended_action=action,
        deadline_rxd_height=deadline,
        low_corroboration=corr,
    )


async def test_pages_claim_critical_once():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert len(ch.sent) == 1
    p = ch.sent[0]
    assert p.severity is Severity.CRITICAL
    assert p.intent is Intent.PAGE_CLAIM
    assert p.recommended_action == "taker_scrape_and_claim_asset"
    assert p.deadline_rxd_height == 172


async def test_dedup_noncritical_same_intent_not_resent():
    # WARN/INFO intents page once per situation (a stall refund is not racing a deadline).
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_REFUND, action="mutual_refund"))
    await a.handle("s1", _d(Intent.PAGE_REFUND, action="mutual_refund"))
    assert len(ch.sent) == 1  # deduped


async def test_critical_intent_repages_each_tick_by_default():
    # review MEDIUM: a time-critical claim race must NOT dedup away — re-page every tick so a
    # single missed page cannot silently lose funds. Default repage_critical_every_ticks=1.
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    for _ in range(3):
        await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert len(ch.sent) == 3
    assert all(p.intent is Intent.PAGE_CLAIM for p in ch.sent)


async def test_critical_repage_honours_backoff_interval():
    # With a backoff of 3, a persisting CRITICAL situation re-pages on tick 1 and tick 4.
    ch = FakeChannel()
    a = DedupAlerter(channel=ch, repage_critical_every_ticks=3)
    for _ in range(6):
        await a.handle("s1", _d(Intent.PAGE_SQUEEZED, action="taker_claim_asset_from_vulnerable"))
    assert len(ch.sent) == 2  # ticks 1 and 4


async def test_repage_interval_validation():
    for bad in (0, -1, True, 1.5):
        with pytest.raises(ValidationError):
            DedupAlerter(channel=FakeChannel(), repage_critical_every_ticks=bad)


async def test_intent_change_repages():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_REFUND, action="mutual_refund"))
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert [p.intent for p in ch.sent] == [Intent.PAGE_REFUND, Intent.PAGE_CLAIM]


@pytest.mark.parametrize(
    "intent,severity",
    [
        (Intent.PAGE_CLAIM, Severity.CRITICAL),
        (Intent.PAGE_SQUEEZED, Severity.CRITICAL),
        (Intent.PAGE_REFUND, Severity.WARN),
        (Intent.RETIRE, Severity.INFO),
    ],
)
async def test_severity_mapping(intent, severity):
    ch = FakeChannel()
    await DedupAlerter(channel=ch).handle("s1", _d(intent))
    assert ch.sent[0].severity is severity


@pytest.mark.parametrize("intent", [Intent.WATCH, Intent.NOOP])
async def test_non_alertable_intents_silent(intent):
    ch = FakeChannel()
    await DedupAlerter(channel=ch).handle("s1", _d(intent))
    assert ch.sent == []


async def test_low_corroboration_marked_in_message():
    ch = FakeChannel()
    await DedupAlerter(channel=ch).handle("s1", _d(Intent.PAGE_REFUND, corr=True))
    assert ch.sent[0].low_corroboration is True
    assert "LOW CORROBORATION" in ch.sent[0].message


async def test_channel_failure_is_retried_next_tick():
    ch = FlakyChannel(fail_times=1)
    a = DedupAlerter(channel=ch)
    # first attempt: channel raises (dedup state must NOT advance)
    with pytest.raises(RuntimeError):
        await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert ch.sent == []
    # next tick: same intent retried and now delivered (not deduped away)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert len(ch.sent) == 1


async def test_handle_rejects_non_decision():
    with pytest.raises(ValidationError):
        await DedupAlerter(channel=FakeChannel()).handle("s1", "not a decision")


async def test_ack_suppresses_repage_of_acknowledged_situation():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))  # first page
    assert a.ack("s1") is True  # operator acknowledges
    for _ in range(3):
        await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert len(ch.sent) == 1  # no re-pages after ACK


async def test_ack_returns_false_when_nothing_critical_to_ack():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    assert a.ack("unknown") is False  # never paged
    await a.handle("s1", _d(Intent.PAGE_REFUND, action="mutual_refund"))  # WARN, not CRITICAL
    assert a.ack("s1") is False


async def test_unacked_critical_count_tracks_and_drops_on_ack():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    await a.handle("s2", _d(Intent.PAGE_SQUEEZED, action="taker_claim_asset_from_vulnerable"))
    assert a.unacked_critical_count() == 2
    a.ack("s1")
    assert a.unacked_critical_count() == 1  # s1 acknowledged


async def test_escalation_to_a_different_critical_intent_rearms_paging():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    a.ack("s1")
    assert a.unacked_critical_count() == 0
    # PAGE_CLAIM -> PAGE_SQUEEZED is a new, worse situation: it re-pages and is un-ACK'd again.
    await a.handle("s1", _d(Intent.PAGE_SQUEEZED, action="taker_claim_asset_from_vulnerable"))
    assert len(ch.sent) == 2
    assert a.unacked_critical_count() == 1


async def test_retire_clears_ack_and_backoff_state():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    a.ack("s1")
    await a.handle("s1", _d(Intent.RETIRE, action=None))  # swap done
    assert a.unacked_critical_count() == 0  # RETIRE is INFO, not a live CRITICAL
    assert a.ack("s1") is False  # state cleared; nothing CRITICAL to ack


def test_file_ack_inbox_drain(tmp_path):
    path = tmp_path / "acks.txt"
    inbox = FileAckInbox(path)
    assert inbox.drain() == []  # missing file -> empty
    path.write_text("s1\n s2 \n\ns3\n")  # operator-appended ids, whitespace/blank tolerant
    assert inbox.drain() == ["s1", "s2", "s3"]
    assert inbox.drain() == []  # drained: consumed exactly once
    assert not path.exists()

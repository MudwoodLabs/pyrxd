"""Tests for the watchtower alert layer (``gravity.watch.alerts``).

Covers severity mapping, dedup by (swap_id, intent), re-page on intent change,
payload contents, the low-corroboration marker, and retry-on-channel-failure
(dedup state only advances after a successful send).
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.watch import DedupAlerter, Intent, Page, Severity
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


async def test_dedup_same_intent_not_resent():
    ch = FakeChannel()
    a = DedupAlerter(channel=ch)
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    await a.handle("s1", _d(Intent.PAGE_CLAIM))
    assert len(ch.sent) == 1  # deduped


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

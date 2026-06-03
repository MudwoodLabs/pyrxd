"""Tests for the watchtower notification channel (#1) + dead-man's-switch (#2)."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from pyrxd.gravity.watch import (
    CompositeAlertChannel,
    DeadMansSwitch,
    Decision,
    FileHeartbeat,
    Intent,
    Page,
    ReconcileResult,
    Severity,
    WebhookAlertChannel,
    combine_heartbeats,
    heartbeat_age_s,
    run_monitor,
)


def _page(severity=Severity.CRITICAL, intent=Intent.PAGE_CLAIM) -> Page:
    return Page(
        swap_id="s1",
        intent=intent,
        severity=severity,
        message="maker revealed p; claim now",
        recommended_action="taker_scrape_and_claim_asset",
        deadline_rxd_height=434828,
        low_corroboration=True,
    )


# --- fakes ----------------------------------------------------------------


class _Resp:
    def __init__(self, status=200):
        self._status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def raise_for_status(self):
        if self._status >= 400:
            raise RuntimeError(f"HTTP {self._status}")


class FakePostSession:
    def __init__(self, status=200):
        self._status = status
        self.calls: list[dict] = []

    def post(self, url, *, data=None, headers=None, timeout=None):
        self.calls.append({"url": url, "data": data, "headers": headers})
        return _Resp(self._status)


class RecChannel:
    def __init__(self, fail=False):
        self.pages: list[Page] = []
        self._fail = fail

    async def send(self, page):
        self.pages.append(page)
        if self._fail:
            raise RuntimeError("channel down")


# --- #1 WebhookAlertChannel -----------------------------------------------


async def test_webhook_posts_signed_body():
    sess = FakePostSession()
    ch = WebhookAlertChannel(
        "https://hook.example/notify",
        session=sess,
        hmac_secret="s3cret",
        auth_header={"Authorization": "Bearer T"},
    )
    await ch.send(_page())

    call = sess.calls[0]
    assert call["url"] == "https://hook.example/notify"
    body = call["data"]
    decoded = json.loads(body)
    assert decoded["severity"] == "critical"
    assert decoded["recommended_action"] == "taker_scrape_and_claim_asset"
    assert decoded["intent"] == "page_claim"
    assert decoded["low_corroboration"] is True
    # auth + tamper-evident signature over the exact bytes
    assert call["headers"]["Authorization"] == "Bearer T"
    expected = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert call["headers"]["X-Watchtower-Signature"] == expected


async def test_webhook_system_page_intent_none():
    sess = FakePostSession()
    await WebhookAlertChannel("https://h", session=sess).send(_page(intent=None))
    assert json.loads(sess.calls[0]["data"])["intent"] is None


async def test_webhook_non_2xx_raises():
    with pytest.raises(RuntimeError):
        await WebhookAlertChannel("https://h", session=FakePostSession(status=500)).send(_page())


# --- #1 CompositeAlertChannel ---------------------------------------------


async def test_composite_fans_out_and_surfaces_failure():
    a, b, c = RecChannel(), RecChannel(fail=True), RecChannel()
    with pytest.raises(RuntimeError):
        await CompositeAlertChannel(a, b, c).send(_page())
    # every channel attempted despite b failing (so the log still records it)
    assert len(a.pages) == 1 and len(b.pages) == 1 and len(c.pages) == 1


async def test_composite_all_ok():
    a, b = RecChannel(), RecChannel()
    await CompositeAlertChannel(a, b).send(_page())
    assert len(a.pages) == 1 and len(b.pages) == 1


# --- #2 FileHeartbeat + heartbeat_age_s + combine -------------------------


def test_file_heartbeat_writes_atomically(tmp_path):
    hb = FileHeartbeat(tmp_path / "hb.json", clock=lambda: 1000.0)
    results = [
        ReconcileResult("a", Decision(Intent.PAGE_CLAIM, reason="x")),
        ReconcileResult("b", Decision(Intent.WATCH, reason="y")),
    ]
    hb(5, results)
    assert json.loads((tmp_path / "hb.json").read_text()) == {"ts": 1000.0, "tick": 5, "swaps": 2, "paged": 1}


def test_heartbeat_age(tmp_path):
    p = tmp_path / "hb.json"
    p.write_text(json.dumps({"ts": 1000.0}))
    assert heartbeat_age_s(p, now=1030.0) == 30.0
    assert heartbeat_age_s(tmp_path / "missing.json", now=1.0) is None
    p.write_text(json.dumps({"no": "ts"}))
    assert heartbeat_age_s(p, now=1.0) is None


def test_combine_heartbeats():
    seen = []
    hb = combine_heartbeats(
        lambda i, r: seen.append(("a", i)),
        lambda i, r: seen.append(("b", i)),
    )
    hb(7, [])
    assert seen == [("a", 7), ("b", 7)]


# --- #2 DeadMansSwitch ----------------------------------------------------


async def test_deadman_fresh_stale_recover(tmp_path):
    p = tmp_path / "hb.json"
    ch = RecChannel()
    sw = DeadMansSwitch(heartbeat_path=p, max_silence_s=60, channel=ch)

    p.write_text(json.dumps({"ts": 1000.0}))
    assert (await sw.check(now=1030.0)).alive is True
    assert ch.pages == []  # fresh → silent

    v = await sw.check(now=1100.0)  # age 100 > 60 → stale
    assert v.alive is False
    assert len(ch.pages) == 1 and ch.pages[0].severity is Severity.CRITICAL
    assert ch.pages[0].intent is None  # a system page

    await sw.check(now=1200.0)  # still stale → edge-triggered, no repeat
    assert len(ch.pages) == 1

    p.write_text(json.dumps({"ts": 1250.0}))
    v = await sw.check(now=1260.0)  # recovered
    assert v.alive is True
    assert len(ch.pages) == 2 and ch.pages[1].severity is Severity.INFO


async def test_deadman_missing_file_is_stale(tmp_path):
    ch = RecChannel()
    sw = DeadMansSwitch(heartbeat_path=tmp_path / "none.json", max_silence_s=60, channel=ch)
    v = await sw.check(now=100.0)
    assert v.alive is False and v.age_s is None
    assert len(ch.pages) == 1 and ch.pages[0].severity is Severity.CRITICAL


async def test_run_monitor_max_iterations(tmp_path):
    p = tmp_path / "hb.json"
    p.write_text(json.dumps({"ts": 0.0}))
    ch = RecChannel()
    sw = DeadMansSwitch(heartbeat_path=p, max_silence_s=60, channel=ch, clock=lambda: 100.0)

    async def _nosleep(_s):
        return None

    n = await run_monitor(sw, interval_s=0, sleep=_nosleep, max_iterations=3)
    assert n == 3
    assert len(ch.pages) == 1  # stale fires once, not every check

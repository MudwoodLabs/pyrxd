"""`wait_for_claim` must bound WALL-CLOCK time, not a number of polls (#475).

It derived `max_polls = timeout_seconds // poll_interval` and looped that many times without
consulting a clock. Every network round trip inside the loop is then unbudgeted, so the real
bound is `max_polls * (poll_interval + latency)`. At the shipped defaults — 30 s interval, 3600 s
timeout, 120 polls — a 1 s per-iteration latency overruns by 120 s and 3 s by 360 s.

This is the same defect the confirmation waits carried before 0.20.0, and it takes the same fix:
a deadline from an injectable monotonic clock, with the sleep clamped so the poll-then-sleep
order cannot run past it.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from pyrxd.gravity.maker import GravityMakerSession
from pyrxd.security.errors import NetworkError, ValidationError


class _FakeClock:
    """Advances only when the code under test sleeps, plus a fixed per-poll latency."""

    def __init__(self, latency_s: float) -> None:
        self.now = 1000.0
        self.latency_s = latency_s
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def poll_happened(self) -> None:
        self.now += self.latency_s


@dataclass
class _Offer:
    offer_txid: str
    offer_vout: int
    offer: object


class _Redeem:
    offer_redeem_hex = "51"


def _session(rxd) -> GravityMakerSession:
    s = object.__new__(GravityMakerSession)
    s._rxd = rxd
    s._poll_interval = 30
    return s


class _Rxd:
    """Never spends the offer, so the wait always runs to its deadline."""

    def __init__(self, clock: _FakeClock, *, fail: bool = False) -> None:
        self.clock = clock
        self.polls = 0
        self.fail = fail

    async def get_utxos(self, script_hash):
        self.polls += 1
        self.clock.poll_happened()
        if self.fail:
            raise NetworkError("boom")
        return [type("U", (), {"tx_hash": "aa" * 32, "tx_pos": 0})()]


def _run(session, offer, clock, timeout=3600):
    async def go():
        real_sleep = asyncio.sleep
        asyncio.sleep = clock.sleep  # type: ignore[assignment]
        try:
            return await session.wait_for_claim(offer, timeout_seconds=timeout, clock=clock)
        finally:
            asyncio.sleep = real_sleep  # type: ignore[assignment]

    return asyncio.run(go())


@pytest.mark.parametrize("latency", [0.0, 1.0, 3.0])
def test_the_overrun_is_ONE_poll_not_one_per_poll(latency: float) -> None:
    """The bug, stated as its consequence, and stated HONESTLY.

    A polling loop cannot know a poll's duration before making it, so it can always overrun by up
    to one poll. That is not the defect. The defect was paying that overrun ONCE PER POLL: at the
    shipped defaults (120 polls) a 3 s latency ran 3,960 s against a 3,600 s budget.

    My first version of this asserted `elapsed <= 3600` flat, which the corrected code cannot
    satisfy either — an assertion the fix could not meet is a bad test, not a bad fix.
    """
    clock = _FakeClock(latency)
    offer = _Offer("aa" * 32, 0, _Redeem())
    assert _run(_session(_Rxd(clock)), offer, clock) is None
    elapsed = clock.now - 1000.0
    assert elapsed <= 3600.0 + latency, f"overran by {elapsed - 3600.0}s at {latency}s latency"
    # And the old shape's overrun, for contrast: 120 polls x latency.
    assert elapsed <= 3600.0 + latency < 3600.0 + 120 * latency or latency == 0.0


def test_latency_reduces_the_POLL_COUNT_rather_than_extending_the_wait() -> None:
    """The mechanism, not just the outcome: a slower endpoint must cost polls, not overrun.
    Asserting only the deadline would also pass if the loop simply stopped polling."""
    slow, fast = _FakeClock(10.0), _FakeClock(0.0)
    offer = _Offer("aa" * 32, 0, _Redeem())
    slow_rxd, fast_rxd = _Rxd(slow), _Rxd(fast)
    _run(_session(slow_rxd), offer, slow)
    _run(_session(fast_rxd), offer, fast)
    assert slow_rxd.polls < fast_rxd.polls
    assert slow.now - 1000.0 <= 3600.0 + slow.latency_s
    assert fast.now - 1000.0 <= 3600.0 + fast.latency_s


def test_a_short_budget_still_polls_at_least_once() -> None:
    """Honest path. A guard that refuses valid work is a bug: a timeout shorter than one poll
    interval must still LOOK, not return immediately having done nothing."""
    clock = _FakeClock(0.0)
    offer = _Offer("aa" * 32, 0, _Redeem())
    rxd = _Rxd(clock)
    assert _run(_session(rxd), offer, clock, timeout=5) is None
    assert rxd.polls >= 1


def test_the_sleep_is_clamped_to_the_remaining_budget() -> None:
    """The poll happens BEFORE the sleep, so an unclamped `sleep(interval)` overshoots. Pinned
    directly, because the elapsed assertion alone would pass with a loop that never slept."""
    clock = _FakeClock(0.0)
    offer = _Offer("aa" * 32, 0, _Redeem())
    _run(_session(_Rxd(clock)), offer, clock, timeout=95)
    assert clock.slept, "it never slept at all"
    assert sum(clock.slept) <= 95.0
    assert clock.slept[-1] <= 30.0


def test_a_failing_endpoint_does_not_retry_past_the_deadline() -> None:
    """The retry lane had its own unclamped sleep. It must raise at the deadline rather than
    keep retrying a dead endpoint forever."""
    clock = _FakeClock(1.0)
    offer = _Offer("aa" * 32, 0, _Redeem())
    with pytest.raises(NetworkError):
        _run(_session(_Rxd(clock, fail=True)), offer, clock, timeout=100)
    assert clock.now - 1000.0 <= 100.0 + clock.latency_s


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1])
def test_non_finite_or_negative_budgets_are_refused(bad) -> None:
    """`nan` passed every comparison and made the deadline unreachable; `inf` never arrives."""
    clock = _FakeClock(0.0)
    offer = _Offer("aa" * 32, 0, _Redeem())
    with pytest.raises(ValidationError):
        _run(_session(_Rxd(clock)), offer, clock, timeout=bad)


def test_a_recovered_endpoint_does_NOT_raise_at_the_deadline() -> None:
    """The honest-path half of the dead-endpoint rule.

    Carrying the last error out to the deadline break is right for an endpoint that is still
    failing, and wrong for one that failed once and recovered — that swap simply had no claim,
    and raising would report a network fault that is over.
    """

    class _FlakyOnce:
        def __init__(self, clock: _FakeClock) -> None:
            self.clock = clock
            self.polls = 0

        async def get_utxos(self, script_hash):
            self.polls += 1
            self.clock.poll_happened()
            if self.polls == 1:
                raise NetworkError("one blip")
            return [type("U", (), {"tx_hash": "aa" * 32, "tx_pos": 0})()]

    clock = _FakeClock(0.0)
    offer = _Offer("aa" * 32, 0, _Redeem())
    rxd = _FlakyOnce(clock)
    assert _run(_session(rxd), offer, clock, timeout=120) is None  # timed out, did not raise
    assert rxd.polls > 1

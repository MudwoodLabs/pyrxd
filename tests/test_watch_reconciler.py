"""Tests for the watchtower reconciler (``gravity.watch.reconciler``).

Uses fake store/observer/alerter ports. Covers routing (pages vs silent WATCH/NOOP),
RETIRE, fail-closed on an observe error (loop never crashes), alerter-failure
isolation, and the per-swap-id single-flight guard.
"""

from __future__ import annotations

import asyncio
import hashlib
import os

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.gravity.watch import Intent, Observations, Reconciler

# --- fixtures -------------------------------------------------------------


def _xonly() -> bytes:
    import coincurve

    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _terms() -> NegotiatedTerms:
    return NegotiatedTerms(
        hashlock=hashlib.sha256(os.urandom(32)).digest(),
        btc_sats=100_000,
        radiant_amount=1_000,
        t_btc=t.Timelock(144, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(72, t.TimeUnit.BLOCKS),
        asset_variant="ft",
        genesis_ref=b"\xaa" * 36,
        taker_dest_hash=b"\x11" * 32,
        maker_dest_hash=b"\x22" * 32,
        btc_claim_pubkey_xonly=_xonly(),
        btc_refund_pubkey_xonly=_xonly(),
    )


def _policy() -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
    )


def _rec(state: SwapState) -> SwapRecord:
    return SwapRecord(state=state, terms=_terms())


class FakeStore:
    def __init__(self, active):
        self._active = active

    async def list_active(self):
        return list(self._active)


class FakeObserver:
    def __init__(self, by_id, raise_for=None):
        self._by_id = by_id
        self._raise_for = raise_for or set()

    async def observe(self, swap_id, record):
        if swap_id in self._raise_for:
            raise RuntimeError("rxd source unreachable")
        return self._by_id[swap_id]


class FakeAlerter:
    def __init__(self, fail=False):
        self.pages = []
        self._fail = fail

    async def handle(self, swap_id, decision):
        self.pages.append((swap_id, decision.intent))
        if self._fail:
            raise RuntimeError("alert channel down")


def _reconciler(store, observer, alerter):
    return Reconciler(store=store, observer=observer, alerter=alerter, policy=_policy(), safety_window_blocks=6)


# --- tests ----------------------------------------------------------------


async def test_routes_pages_but_not_watch():
    claim_obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=100, btc_claim_confirmations=6
    )
    watch_obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=100)
    store = FakeStore([("claim", _rec(SwapState.SECRET_REVEALED)), ("watch", _rec(SwapState.BOTH_LOCKED))])
    observer = FakeObserver({"claim": claim_obs, "watch": watch_obs})
    alerter = FakeAlerter()
    results = await _reconciler(store, observer, alerter).tick()

    assert len(results) == 2
    assert alerter.pages == [("claim", Intent.PAGE_CLAIM)]  # WATCH not routed
    by_id = {r.swap_id: r.decision.intent for r in results}
    assert by_id == {"claim": Intent.PAGE_CLAIM, "watch": Intent.WATCH}


async def test_retire_is_routed():
    store = FakeStore([("done", _rec(SwapState.COMPLETED))])
    observer = FakeObserver({"done": Observations(maker_has_claimed_btc=False, now_rxd_height=150)})
    alerter = FakeAlerter()
    results = await _reconciler(store, observer, alerter).tick()
    assert results[0].decision.intent is Intent.RETIRE
    assert alerter.pages == [("done", Intent.RETIRE)]


async def test_observe_failure_fails_closed_and_does_not_crash():
    store = FakeStore([("bad", _rec(SwapState.BOTH_LOCKED))])
    observer = FakeObserver({}, raise_for={"bad"})
    alerter = FakeAlerter()
    results = await _reconciler(store, observer, alerter).tick()

    assert len(results) == 1
    assert results[0].error is not None
    assert results[0].decision.intent is Intent.PAGE_SQUEEZED  # fail-closed page
    assert alerter.pages == [("bad", Intent.PAGE_SQUEEZED)]


async def test_alerter_failure_does_not_crash_loop():
    obs = Observations(
        maker_has_claimed_btc=True, now_rxd_height=150, asset_locked_at_height=100, btc_claim_confirmations=6
    )
    store = FakeStore([("claim", _rec(SwapState.SECRET_REVEALED))])
    observer = FakeObserver({"claim": obs})
    alerter = FakeAlerter(fail=True)
    # Should not raise despite the alerter throwing.
    results = await _reconciler(store, observer, alerter).tick()
    assert results[0].decision.intent is Intent.PAGE_CLAIM


async def test_single_flight_skips_concurrent_reconcile():
    class BlockingObserver:
        def __init__(self, obs):
            self.started = asyncio.Event()
            self.release = asyncio.Event()
            self.calls = 0
            self._obs = obs

        async def observe(self, swap_id, record):
            self.calls += 1
            self.started.set()
            await self.release.wait()
            return self._obs

    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=150, asset_locked_at_height=100)
    store = FakeStore([("s1", _rec(SwapState.BOTH_LOCKED))])
    observer = BlockingObserver(obs)
    r = _reconciler(store, observer, FakeAlerter())

    t1 = asyncio.create_task(r.tick())
    await observer.started.wait()  # t1 is inside observe → "s1" is in _inflight
    res2 = await r.tick()  # overlapping tick must skip s1, not re-observe
    observer.release.set()
    res1 = await t1

    assert observer.calls == 1
    assert "single-flight" in res2[0].decision.reason
    assert res1[0].decision.intent is Intent.WATCH

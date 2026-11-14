"""One ACK of an armed claim page holds for at most one safety window (#988).

Before #988 the armed claim page's situation was the executor's outcome and kind alone. A server
that dropped the covenant claim but echoed its true txid left the claim marked seen, so every later
tick declined it with the same untagged reason, under the generic ``claim_race:declined:other`` key.
One ACK of that page silenced the swap until ``PAGE_SQUEEZED``: 122 blocks on regtest.

Everything is production code except the SERVER and the observer: a real ``Reconciler`` with the real
``decide`` drives a real ``ClaimExecutor`` over a real ``RadiantCovenantLeg``, ``RadiantChainIO`` and
``ElectrumXClient``, whose wire is :class:`_Node` (see its module), and pages a real ``DedupAlerter``.
The clock is injected so a safety window passes without waiting.
"""

from __future__ import annotations

import dataclasses

from pyrxd.gravity.radiant_leg import SeenStore
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import RecordRole
from pyrxd.gravity.watch import ExecOutcome
from pyrxd.gravity.watch.alerts import DedupAlerter
from pyrxd.gravity.watch.decide import SITUATION_CLAIM_RACE, Decision, Intent, Observations
from pyrxd.gravity.watch.reconciler import Reconciler, reconcile_error_repage_s

from test_claim_executor_echo_mismatch import _armed, _Node  # isort: skip

_SWAP = "swap-1"
_SAFETY = 6
_POLICY = MarginPolicy.estimated()
_WINDOW = reconcile_error_repage_s(_POLICY, _SAFETY)
_AWAITING = f"{SITUATION_CLAIM_RACE}:declined:awaiting_confirmation"


class _Store:
    def __init__(self, rec) -> None:
        self.active = [(_SWAP, rec)]

    async def list_active(self):
        return list(self.active)


class _Observer:
    """The SAFE claim race that arms ``autonomous_asset_claim``, or, with ``quiet``, a tick on which
    the maker's BTC claim is not seen, so ``decide`` pages nothing for the claim."""

    def __init__(self) -> None:
        self.quiet = False

    async def observe(self, swap_id, record):
        return Observations(
            maker_has_claimed_btc=not self.quiet,
            btc_claim_confirmations=0 if self.quiet else 1_000,
            asset_locked_at_height=100,
            now_rxd_height=101,
        )


class _Pages:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, page) -> None:
        self.sent.append(page.message)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


async def _wired(node: _Node):
    seen = SeenStore()
    ex, rec, _fees = await _armed(node, seen)
    rec = dataclasses.replace(rec, role=RecordRole.TAKER)  # autonomy acts only for the taker's record
    pages, clock, observer, store = _Pages(), _Clock(), _Observer(), _Store(rec)
    r = Reconciler(
        store=store,
        observer=observer,
        alerter=DedupAlerter(channel=pages),
        policy=_POLICY,
        safety_window_blocks=_SAFETY,
        executor=ex,
        clock=clock,
    )
    return r, pages, clock, observer, store


async def _tick(r):
    [res] = await r.tick()
    return res


async def _dropped_claim_acked(node: _Node):
    """The #988 sequence up to the operator's ACK: the server drops the claim and echoes its txid
    (tick 1, BROADCAST), so tick 2 declines it as already broadcast, and the operator ACKs that."""
    node.relay = False
    r, pages, clock, observer, store = await _wired(node)
    res = await _tick(r)
    assert res.executed is ExecOutcome.BROADCAST, res.decision.reason
    res = await _tick(r)
    assert res.executed is ExecOutcome.DECLINED
    assert res.decision.situation == _AWAITING, "the decline has its own kind, not 'other'"
    assert r.alerter.ack(_SWAP, f"page_claim:{res.decision.situation}")
    return r, pages, clock, observer, store


async def test_an_ack_of_a_dropped_claim_holds_one_safety_window() -> None:
    node = _Node()
    r, pages, clock, _observer, _store = await _dropped_claim_acked(node)
    sent = len(pages.sent)

    clock.now += _WINDOW - 1  # inside the window the ACK holds (the honest use of an ACK)
    res = await _tick(r)
    assert res.decision.situation == _AWAITING
    assert len(pages.sent) == sent, "an ACK still silences re-pages inside its window"

    clock.now += 1  # one window after the outcome first appeared: a new situation, so a new page
    res = await _tick(r)
    assert res.decision.situation == f"{_AWAITING}:1"
    assert len(pages.sent) == sent + 1, "the dropped claim pages again after one window"
    assert "awaiting confirmation" in pages.sent[-1]

    # The next ACK holds one window too, and no longer.
    assert r.alerter.ack(_SWAP, f"page_claim:{res.decision.situation}")
    await _tick(r)
    assert len(pages.sent) == sent + 1
    clock.now += _WINDOW
    res = await _tick(r)
    assert res.decision.situation == f"{_AWAITING}:2"
    assert len(pages.sent) == sent + 2
    assert len(node.broadcasts) == 1, "re-paging sends nothing: the claim is still seen"


async def test_a_quiet_tick_in_between_does_not_restart_the_count() -> None:
    """A count that restarted on a quiet tick would hand the earlier ACK back its key: a source that
    hides the BTC claim for one tick in each window would keep the swap silent."""
    node = _Node()
    r, pages, clock, observer, _store = await _dropped_claim_acked(node)
    sent = len(pages.sent)

    clock.now += _WINDOW - 1
    observer.quiet = True
    res = await _tick(r)
    assert res.decision.intent is not Intent.PAGE_CLAIM, res.decision
    observer.quiet = False
    clock.now += 1
    res = await _tick(r)
    assert res.decision.situation == f"{_AWAITING}:1"
    assert len(pages.sent) > sent, "the window ran from when the outcome first appeared"


async def test_each_outcome_keeps_its_own_count() -> None:
    """Another outcome in between neither restarts the first one's count nor inherits it."""
    node = _Node()
    r, _pages, clock, _observer, _store = await _dropped_claim_acked(node)
    first = r._claim_since[_SWAP][_AWAITING]
    clock.now += _WINDOW
    other = f"{SITUATION_CLAIM_RACE}:declined:consensus_rejection"
    assert r._claim_situation(_SWAP, other) == other, "a new outcome starts at its bare key"
    assert r._claim_situation(_SWAP, _AWAITING) == f"{_AWAITING}:1"
    assert r._claim_since[_SWAP][_AWAITING] == first


async def test_a_swap_that_leaves_the_store_drops_its_counts() -> None:
    node = _Node()
    r, _pages, _clock, _observer, store = await _dropped_claim_acked(node)
    assert _SWAP in r._claim_since
    store.active = []
    assert await r.tick() == []
    assert _SWAP not in r._claim_since


async def test_the_mempool_aware_decline_has_its_own_kind() -> None:
    """A client that reads the mempool sees the claim there; that decline is not 'other' either."""
    node = _Node()
    ex, rec, _fees = await _armed(node)
    rec = dataclasses.replace(rec, role=RecordRole.TAKER)
    leg = await ex._resolve_leg(_SWAP, rec)

    async def _spent_in_mempool(_outpoint):
        return False

    leg.chain_io.covenant_unspent_incl_mempool = _spent_in_mempool
    decision = Decision(Intent.PAGE_CLAIM, reason="r", autonomous_asset_claim=True, situation=SITUATION_CLAIM_RACE)
    assert await ex.execute(_SWAP, rec, decision) is ExecOutcome.DECLINED
    reason = ex.take_reason(_SWAP)
    assert reason is not None and reason.kind == "claim_in_mempool", reason
    assert node.broadcasts == [], "nothing was sent"

    # Honest path: a client that reads the covenant unspent in its mempool lets the claim go out.
    async def _unspent(_outpoint):
        return True

    leg.chain_io.covenant_unspent_incl_mempool = _unspent
    assert await ex.execute(_SWAP, rec, decision) is ExecOutcome.BROADCAST
    assert len(node.broadcasts) == 1

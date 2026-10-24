"""The D9 net for legacy terminal BTC records (#850 PR 9b, design §5.2, D9, D13, §7.2 scenario 20).

Before 0.27 a BTC taker refund ended its record on BROADCAST, and the tower's store dropped terminal
records. A refund that lost to the maker's claim then left ``p`` public with nobody told to claim the
covenant before t_rxd. The store now lists a bounded number of such records per tick (terminal, BTC,
funded, no ``counter_disposition``, no marker), the tower reads each one's funding outpoint once, pages
what it finds, and writes the marker only on a conclusive verdict.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import os
import stat

import pytest

from pyrxd.gravity.swap_state import (
    AbortReason,
    CounterDispositionRecord,
    RecordRole,
    SwapState,
)
from pyrxd.gravity.watch.adapters import LEGACY_CHECKS_PER_TICK, JsonDirRecordStore, is_legacy_candidate
from pyrxd.gravity.watch.decide import Intent
from pyrxd.gravity.watch.executor import ExecOutcome
from tests.test_watch_btc_spender_classification import BURIAL, COV_CONFS, SWAP, T_RXD, TIP, _Tower

LOCKED_AT = TIP - COV_CONFS + 1
T_RXD_OPENS = LOCKED_AT + T_RXD


class _SpyExecutor:
    """An executor that records every decision it is asked about. The legacy net must ask it none."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    async def execute(self, swap_id, record, decision):
        self.asked.append(swap_id)
        return ExecOutcome.DECLINED


def _legacy(tmp_path, *, state=SwapState.ABORTED, role=None, **kw) -> _Tower:
    """A tower whose one record an old pyrxd ended on its refund's broadcast."""
    w = _Tower(tmp_path, role=role, **kw)
    w.write(w.record().with_state(state))
    return w


def _marker(w: _Tower) -> dict | None:
    path = w.store.legacy_marker_path(w.swap_id)
    return json.loads(path.read_text()) if path.exists() else None


# --------------------------------------------------------------------------- what the store lists


async def test_a_legacy_terminal_btc_record_is_listed_once_and_not_as_active(tmp_path):
    w = _legacy(tmp_path)
    assert await w.store.list_active() == []
    assert [sid for sid, _r in w.store.legacy] == [SWAP]


@pytest.mark.parametrize(
    "change",
    ["completed", "maker", "has_disposition", "marker", "unfunded", "abandoned", "eth"],
)
async def test_records_the_net_leaves_alone(tmp_path, change):
    w = _legacy(tmp_path)
    rec = w.record()
    if change == "completed":
        w.write(rec.with_state(SwapState.COMPLETED))
    elif change == "maker":
        w.write(dataclasses.replace(rec, role=RecordRole.MAKER))
    elif change == "has_disposition":
        w.write(
            dataclasses.replace(
                rec,
                abort_reason=AbortReason.COUNTER_LEG_REFUNDED,
                counter_disposition=CounterDispositionRecord(
                    kind="refunded",
                    block_number=151,
                    block_hash="ab" * 32,
                    tx_hash="cd" * 32,
                    sources=("a", "b"),
                    single_source=False,
                ),
            )
        )
    elif change == "marker":
        w.store.mark_legacy_checked(SWAP, "refunded", rxd_height=TIP, evidence={})
    elif change == "unfunded":
        w.write(dataclasses.replace(rec, counterchain_locator=None))
    elif change in ("abandoned", "eth"):
        # A valid abandon needs its note and read, and a valid ETH record its own locator; the
        # predicate is what is under test, so set the one field on a copy past validation.
        assert is_legacy_candidate(rec)
        rec = copy.copy(rec)
        if change == "abandoned":
            object.__setattr__(rec, "abort_reason", AbortReason.OPERATOR_ABANDONED)
        else:
            terms = copy.copy(rec.terms)
            object.__setattr__(terms, "counter_chain", "eth")
            object.__setattr__(rec, "terms", terms)
        assert not is_legacy_candidate(rec)
        return
    await w.store.list_active()
    assert w.store.legacy == []


async def test_the_honest_candidate_predicate_is_not_vacuous(tmp_path):
    """Both terminals an old refund ended a record in, with and without a role."""
    for state in (SwapState.ABORTED, SwapState.MUTUAL_REFUND):
        for role in (None, RecordRole.TAKER, RecordRole.NONE):
            w = _legacy(tmp_path / f"{state.value}-{role}", state=state, role=role)
            assert is_legacy_candidate(w.record()), (state, role)


async def test_at_most_the_per_tick_bound_is_read_and_every_record_gets_its_turn(tmp_path):
    n = LEGACY_CHECKS_PER_TICK * 2 + 1
    for i in range(n):
        _legacy(tmp_path, swap_id=f"s{i:02d}")
    store = JsonDirRecordStore(tmp_path / "records")
    seen: list[str] = []
    for _ in range(3):
        await store.list_active()
        assert 0 < len(store.legacy) <= LEGACY_CHECKS_PER_TICK
        seen += [sid for sid, _r in store.legacy]
    assert sorted(set(seen)) == sorted(f"s{i:02d}" for i in range(n)), "a record was never read"


async def test_the_marker_is_not_counted_as_an_unreadable_record(tmp_path):
    w = _legacy(tmp_path)
    w.store.mark_legacy_checked(SWAP, "refunded", rxd_height=TIP, evidence={})
    await w.store.list_active()
    assert w.store.unreadable == []


# --------------------------------------------------------------------------- what the tower pages


async def test_a_refund_that_lost_to_a_claim_pages_the_covenant_claim_not_a_refund(tmp_path):
    w = _legacy(tmp_path)
    spy = _SpyExecutor()
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(BURIAL)
    (res,) = await w.reconciler(executor=spy).tick()
    d = res.decision
    assert res.legacy is True
    assert d.intent is Intent.PAGE_CLAIM
    assert "build-claim" in d.recommended_action and "not a refund" in d.recommended_action
    assert "refund lost" in d.reason
    assert d.deadline_rxd_height == T_RXD_OPENS
    assert d.autonomous_asset_claim is False and d.autonomous_btc_refund is False
    assert spy.asked == [], "the legacy net reached an executor"
    assert _marker(w) is None, "marked before the claim window closed"
    assert [sid for sid, _d in w.pages.got] == [SWAP]


async def test_the_claim_page_is_marked_once_delivered_after_t_rxd(tmp_path):
    w = _legacy(tmp_path)
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(BURIAL)
    w.rxd.tip = T_RXD_OPENS
    w.rxd.cov_confs = T_RXD_OPENS - LOCKED_AT + 1
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_CLAIM and res.alert_delivered is True
    marker = _marker(w)
    assert marker["verdict"] == "claimed" and marker["rxd_height"] == T_RXD_OPENS


async def test_an_undelivered_claim_page_is_not_marked(tmp_path):
    w = _legacy(tmp_path)
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(BURIAL)
    w.rxd.tip = T_RXD_OPENS
    w.rxd.cov_confs = T_RXD_OPENS - LOCKED_AT + 1

    async def down(swap_id, decision):
        raise ConnectionError("webhook down")

    w.pages.handle = down  # type: ignore[method-assign]
    (res,) = await w.reconciler().tick()
    assert res.alert_delivered is False
    assert _marker(w) is None


async def test_an_unspent_htlc_pages_a_refund_by_address_and_is_never_marked(tmp_path):
    w = _legacy(tmp_path)
    w.rxd.tip = T_RXD_OPENS + 100  # long past every deadline
    w.rxd.cov_confs = w.rxd.tip - LOCKED_AT + 1
    (res,) = await w.reconciler().tick()
    d = res.decision
    assert d.intent is Intent.PAGE_REFUND
    assert "build-refund" in d.recommended_action
    assert "never confirmed" in d.reason
    assert d.autonomous_btc_refund is False
    assert _marker(w) is None
    await w.store.list_active()
    assert [sid for sid, _r in w.store.legacy] == [SWAP], "an unspent HTLC dropped out of the net"


async def test_our_buried_refund_agrees_and_writes_the_marker_mode_600(tmp_path):
    w = _legacy(tmp_path)
    txid = w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.WATCH
    assert w.pages.got == [], "an agreeing record was paged"
    marker = _marker(w)
    assert marker["verdict"] == "refunded" and marker["evidence"]["btc_refund_txid"] == txid
    mode = stat.S_IMODE(os.stat(w.store.legacy_marker_path(SWAP)).st_mode)
    assert mode == 0o600
    await w.store.list_active()
    assert w.store.legacy == [], "a marked record is read again"


async def test_a_pending_refund_is_read_again_and_not_marked(tmp_path):
    w = _legacy(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL - 1)
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.WATCH
    assert _marker(w) is None


async def test_an_unreadable_chain_writes_nothing_and_pages_nothing(tmp_path):
    """UNKNOWN writes nothing, so the record is retried (design §5.2 item 4)."""
    w = _legacy(tmp_path)
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(BURIAL)
    for s in w.sources:
        s.down = True
    (res,) = await w.reconciler().tick()
    assert res.legacy is True and res.error is not None
    assert w.pages.got == [] and _marker(w) is None


async def test_a_claim_on_a_non_terminal_record_is_still_the_normal_claim_race(tmp_path):
    """The honest twin of the net: the same chain under a live record goes through decide(), not the
    legacy path, and the store does not list it as legacy."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(BURIAL)
    (res,) = await w.reconciler().tick()
    assert res.legacy is False
    assert res.decision.intent is Intent.PAGE_CLAIM
    assert w.store.legacy == []


async def test_a_claim_served_beside_the_buried_refund_pages_the_covenant_claim(tmp_path):
    """Review of PR 9b, L2: D14 on a legacy record was paged as an unclassified spend."""
    w = _legacy(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    w.sources[2].forge_spender = w.chain.claim_tx()
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_CLAIM, res.decision.reason
    assert "build-claim" in res.decision.recommended_action
    assert "could not classify" not in res.decision.reason
    assert _marker(w) is None

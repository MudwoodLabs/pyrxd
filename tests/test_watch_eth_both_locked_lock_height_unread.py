"""BOTH_LOCKED on an ETH counter leg with the covenant's lock height unread (the ETH side of register
R1 with R8).

A taker whose RXD sources could not read the covenant got WATCH at BOTH_LOCKED, past the ETH deadline
and past t_rxd too: the tower cannot tell where t_rxd is without the lock height, and the WATCH held
for as long as the read failed. The ETH contract's absolute deadline is now the clock there, as at
BTC_LOCKED. The swap was gated so the covenant refund opens after that deadline plus a margin
(``pyrxd.gravity.eth_rxd_timelock``), so before it the tower WATCHes, and from it, or with the clock
unread, it pages the refund that is due.

The production path runs the real observer over ``tests._fake_evm_chain``; the clock's branches are
pinned on ``decide`` directly, each beside its twin.
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.swap_state import RecordRole, SwapRecord, SwapState
from pyrxd.gravity.watch.decide import (
    SITUATION_BOTH_LOCKED_LOCK_HEIGHT_UNREAD,
    SITUATION_MAKER_REFUND_LOCK_HEIGHT_UNREAD,
    Intent,
    Observations,
    decide,
)
from pyrxd.security.units import ChainHeight, Seconds
from tests.test_watch_eth_disposition_table import SAFETY, TIP, _EthTower, _policy
from tests.test_watch_pages_name_state_valid_steps import _named_steps, _state_guards


@pytest.mark.parametrize("role", [RecordRole.TAKER, None])
async def test_an_unreadable_covenant_past_the_eth_deadline_pages_the_refund(tmp_path, role):
    w = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED, role=role)  # head 100, past the timeout block 50
    w.rxd.cov_confs = None
    obs = await w.observe()
    assert obs.asset_locked_at_height is None
    assert obs.now_unix_s is not None and obs.now_unix_s >= w.record().terms.eth_timeout_unix_s
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND, d.reason
    assert d.situation == SITUATION_BOTH_LOCKED_LOCK_HEIGHT_UNREAD
    assert d.recommended_action == "mutual_refund" and not d.autonomous_btc_refund
    assert "has passed" in d.reason
    guards = _state_guards()
    steps = _named_steps(d.recommended_action, guards)
    assert steps == ["mutual_refund"] and SwapState.BOTH_LOCKED in guards["mutual_refund"]


async def test_a_makers_unreadable_covenant_past_the_eth_deadline_gets_its_covenant_refund_page(tmp_path):
    w = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED, role=RecordRole.MAKER)
    w.rxd.cov_confs = None
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.situation == SITUATION_MAKER_REFUND_LOCK_HEIGHT_UNREAD, d.reason
    assert not d.urgent


def _record(tmp_path, *, role=RecordRole.TAKER, covenant=True) -> SwapRecord:
    record = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED, role=role).record()
    if not covenant:
        record = SwapRecord.from_dict({**record.to_dict(), "radiant_covenant_outpoint": None})
    return record


def _obs(**kw) -> Observations:
    return Observations(maker_has_claimed_btc=False, now_rxd_height=ChainHeight(TIP), **kw)


def _decide(record: SwapRecord, obs: Observations):
    return decide(record=record, observations=obs, policy=_policy(), safety_window_blocks=SAFETY)


async def test_an_unreadable_covenant_before_the_eth_deadline_watches(tmp_path):
    """Honest twin: before the deadline, by the swap's gate, t_rxd is not near."""
    record = _record(tmp_path)
    deadline = record.terms.eth_timeout_unix_s
    d = _decide(record, _obs(now_unix_s=Seconds(deadline - 1)))
    assert d.intent is Intent.WATCH and "has not passed" in d.reason
    d = _decide(record, _obs(now_unix_s=Seconds(deadline)))
    assert d.intent is Intent.PAGE_REFUND and d.situation == SITUATION_BOTH_LOCKED_LOCK_HEIGHT_UNREAD


async def test_an_unreadable_covenant_and_clock_pages(tmp_path):
    d = _decide(_record(tmp_path), _obs())
    assert d.intent is Intent.PAGE_REFUND and "could not be read" in d.reason
    assert d.recommended_action == "mutual_refund"


async def test_an_unreadable_covenant_with_none_pinned_still_watches(tmp_path):
    record = _record(tmp_path, covenant=False)
    assert record.radiant_covenant_outpoint is None
    d = _decide(record, _obs())
    assert d.intent is Intent.WATCH and d.reason == "asset lock height not yet observed"

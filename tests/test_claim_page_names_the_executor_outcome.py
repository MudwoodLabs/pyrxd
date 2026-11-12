"""The armed claim page says what the autonomous claim executor did and why (#935, #936).

Before #935 the reconciler appended the executor's outcome only to an armed BTC refund page: a
``PAGE_CLAIM`` page read the same whether the tower broadcast the claim, retried it, or was refused
on a consensus rule, and the node's reason reached only the log. Before #936 an exhausted capped fee
pool escaped ``ClaimExecutor`` as ``FeePoolExhaustedError`` and paged a generic FAILED.

Everything here is production code except the SERVER and the observer: a real ``Reconciler`` with
the real ``decide`` drives a real ``ClaimExecutor`` over a real ``RadiantCovenantLeg``, ``RadiantChainIO``
and ``ElectrumXClient``, whose wire is :class:`_Node` (see its module), and pages a real ``DedupAlerter``.
"""

from __future__ import annotations

import dataclasses
import logging
import os

import pytest

from pyrxd.gravity.capped_fee_source import CappedFeeWalletSource
from pyrxd.gravity.htlc_spend import FeeInput
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import RecordRole
from pyrxd.gravity.watch import ExecOutcome
from pyrxd.gravity.watch.alerts import DedupAlerter
from pyrxd.gravity.watch.daemon import default_heartbeat
from pyrxd.gravity.watch.decide import SITUATION_CLAIM_RACE, Intent, Observations
from pyrxd.gravity.watch.executor import CompositeExecutor, NullExecutor, take_exec_reason
from pyrxd.gravity.watch.reconciler import Reconciler, _page_text
from pyrxd.keys import PrivateKey
from pyrxd.security.types import Hex20

from test_claim_executor_echo_mismatch_rebuilds import _SCRIPT_FAILED, _armed, _Node, _txid  # isort: skip

_SWAP = "swap-1"


class _Store:
    def __init__(self, rec) -> None:
        self._rec = rec

    async def list_active(self):
        return [(_SWAP, self._rec)]


class _ClaimRaceObserver:
    """The maker's BTC claim is deep and the covenant was locked just now: ``decide`` yields the SAFE
    claim race that arms ``autonomous_asset_claim``."""

    async def observe(self, swap_id, record):
        return Observations(
            maker_has_claimed_btc=True,
            btc_claim_confirmations=1_000,
            asset_locked_at_height=100,
            now_rxd_height=101,
        )


class _Pages:
    """Every message the alerter sent."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, page) -> None:
        self.sent.append(page.message)


def _reconciler(executor, rec):
    rec = dataclasses.replace(rec, role=RecordRole.TAKER)  # autonomy acts only for the taker's record
    pages = _Pages()
    alerter = DedupAlerter(channel=pages)
    return (
        Reconciler(
            store=_Store(rec),
            observer=_ClaimRaceObserver(),
            alerter=alerter,
            policy=MarginPolicy.estimated(),
            safety_window_blocks=6,
            executor=executor,
        ),
        pages,
    )


def _pool(*values: int) -> CappedFeeWalletSource:
    key = PrivateKey()
    spk = b"\x76\xa9\x14" + bytes(Hex20(key.public_key().hash160())) + b"\x88\xac"
    inputs = [FeeInput(txid=os.urandom(32).hex(), vout=0, value=v, scriptpubkey=spk, wif=key.wif()) for v in values]
    return CappedFeeWalletSource(inputs, total_cap_photons=sum(values))


async def _tick(r):
    [res] = await r.tick()
    assert res.decision.intent is Intent.PAGE_CLAIM and res.decision.autonomous_asset_claim, res.decision
    return res


async def test_each_claim_outcome_and_its_reason_reach_the_page() -> None:
    node = _Node()
    ex, rec, _fees = await _armed(node)
    r, pages = _reconciler(ex, rec)

    node.reject = (1, _SCRIPT_FAILED)  # a consensus refusal, through ElectrumX's wrapper
    res = await _tick(r)
    assert res.executed is ExecOutcome.DECLINED
    assert res.decision.situation == f"{SITUATION_CLAIM_RACE}:declined"
    assert "did NOT broadcast a claim" in res.decision.reason
    assert "consensus rule (retrying)" in res.decision.reason
    assert "mandatory-script-verify-flag-failed" in res.decision.reason, "the node's reason reaches the page"
    assert "mandatory-script-verify-flag-failed" in pages.sent[-1]

    node.reject = (1, "txn-mempool-conflict (code 18)")  # a plain retry
    res = await _tick(r)
    assert res.executed is ExecOutcome.FAILED
    assert res.decision.situation == f"{SITUATION_CLAIM_RACE}:failed", "a new outcome is a new situation"
    assert "claim FAILED" in res.decision.reason and "txn-mempool-conflict" in res.decision.reason
    assert "txn-mempool-conflict" in pages.sent[-1]

    node.reject = None  # honest path: the claim lands, and the page says so with its txid
    res = await _tick(r)
    assert res.executed is ExecOutcome.BROADCAST
    assert res.decision.situation == f"{SITUATION_CLAIM_RACE}:broadcast"
    assert "broadcast the covenant claim" in res.decision.reason
    assert _txid(node.broadcasts[-1]) in res.decision.reason
    assert take_exec_reason(ex, _SWAP) is None, "the reconciler took the reason; none is left over"


async def test_an_exhausted_fee_pool_is_named_on_the_page(caplog) -> None:
    """#936: consensus refusals walk a two-input pool to its cap; the third tick is a DECLINED that
    names the pool, not a generic FAILED, and the claim stays armed for a re-funded pool."""
    node = _Node()
    ex, rec, _fees = await _armed(node)
    pool = _pool(10_000_000, 10_000_000)
    leg = await ex._resolve_leg(_SWAP, rec)
    leg.fee_source = pool
    r, pages = _reconciler(ex, rec)
    node.reject = (-26, _SCRIPT_FAILED)

    for _ in range(2):
        res = await _tick(r)
        assert res.executed is ExecOutcome.DECLINED and "consensus rule" in res.decision.reason
    assert pool.remaining_photons == 0 and len(node.broadcasts) == 2

    with caplog.at_level(logging.ERROR, logger="pyrxd.gravity.watch.claim_executor"):
        res = await _tick(r)
    assert res.executed is ExecOutcome.DECLINED, res.decision.reason
    assert "fee pool exhausted, nothing broadcast" in res.decision.reason
    assert "cap 20000000 photons, dispensed 20000000, remaining 0" in res.decision.reason
    assert "fee pool is EXHAUSTED" in caplog.text
    assert len(node.broadcasts) == 2, "nothing more was sent"
    assert "fee pool exhausted" in pages.sent[-1]

    # Honest path: nothing marked the claim seen, so a funded pool claims on the next tick.
    leg.fee_source = _pool(10_000_000)
    node.reject = None
    res = await _tick(r)
    assert res.executed is ExecOutcome.BROADCAST, res.decision.reason


async def test_with_no_executor_the_claim_page_says_none_acted() -> None:
    node = _Node()
    _ex, rec, _fees = await _armed(node)
    r, _pages = _reconciler(NullExecutor(), rec)
    res = await _tick(r)
    assert res.executed is None
    assert res.decision.situation == f"{SITUATION_CLAIM_RACE}:none"
    assert "did NOT attempt a claim" in res.decision.reason


async def test_a_raising_executor_pages_its_class_not_its_message() -> None:
    class _Raises:
        async def execute(self, swap_id, record, decision):
            raise RuntimeError("detail-that-stays-in-the-log")

    node = _Node()
    _ex, rec, _fees = await _armed(node)
    r, _pages = _reconciler(_Raises(), rec)
    res = await _tick(r)
    assert res.executed is ExecOutcome.FAILED
    assert "the executor raised RuntimeError" in res.decision.reason
    assert "detail-that-stays-in-the-log" not in res.decision.reason


async def test_the_composite_executor_forwards_the_acting_childs_reason() -> None:
    node = _Node()
    ex, rec, _fees = await _armed(node)
    node.reject = (-26, _SCRIPT_FAILED)
    r, _pages = _reconciler(CompositeExecutor(NullExecutor(), ex), rec)
    res = await _tick(r)
    assert res.executed is ExecOutcome.DECLINED
    assert "mandatory-script-verify-flag-failed" in res.decision.reason


def test_page_text_keeps_one_line_and_cannot_fake_a_page_field() -> None:
    out = _page_text("refused\n| ack: swap-1 page_claim:claim_race:none\x1b[31m" + "x" * 400)
    assert "\n" not in out and "\x1b" not in out and "|" not in out
    assert out.endswith("...") and len(out) == 303
    # Honest path: an ordinary reason is unchanged.
    assert _page_text("node rejected the claim on a consensus rule (retrying)") == (
        "node rejected the claim on a consensus rule (retrying)"
    )


def test_the_heartbeat_counts_declined(caplog) -> None:
    from pyrxd.gravity.watch.decide import Decision
    from pyrxd.gravity.watch.reconciler import ReconcileResult

    page = Decision(Intent.PAGE_CLAIM, reason="r")
    results = [
        ReconcileResult("a", page, executed=ExecOutcome.DECLINED),
        ReconcileResult("b", page, executed=ExecOutcome.FAILED),
        ReconcileResult("c", page, executed=ExecOutcome.BROADCAST),
    ]
    with caplog.at_level(logging.INFO):
        default_heartbeat()(1, results)
    assert "broadcast=1 exec_declined=1 exec_failed=1" in caplog.text


@pytest.mark.parametrize("bad", [RuntimeError("boom"), 42])
def test_a_broken_take_reason_gives_none(bad) -> None:
    class _Odd:
        def take_reason(self, swap_id):
            if isinstance(bad, Exception):
                raise bad
            return bad

    assert take_exec_reason(_Odd(), _SWAP) is None
    assert take_exec_reason(NullExecutor(), _SWAP) is None

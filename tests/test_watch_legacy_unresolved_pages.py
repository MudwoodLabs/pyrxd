"""A legacy record's D9 read that one endpoint holds unresolved pages "investigate" in the end (#921).

The D9 net (``Reconciler._check_legacy``) reads a legacy terminal record again whenever its read fails
or retries (``UNKNOWN``, ``settled_unfinal``, a refund not yet buried). Before #921 that was silent for
good, and one endpoint could keep it there: a stale finalized block (the reader takes the quorum MIN)
keeps a final refund ``settled_unfinal``; a deploy receipt the others disagree with keeps it
``UNKNOWN``. Now a record unresolved for longer than ``legacy_unresolved_page_after_s`` pages
``PAGE_SQUEEZED`` on every read until it resolves. A WATCH the tower's configuration explains (one
endpoint, a source that cannot read the leg) is quiet by design and never pages.

Every refusal here has its honest twin.
"""

from __future__ import annotations

import dataclasses
import importlib

import pytest

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import SwapState
from pyrxd.gravity.watch.alerts import DedupAlerter, Page
from pyrxd.gravity.watch.decide import Decision, Intent, LegacyCheck
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.gravity.watch.reconciler import (
    DEFAULT_LEGACY_UNRESOLVED_PAGE_AFTER_S,
    SITUATION_LEGACY_UNRESOLVED,
    Reconciler,
    legacy_honest_wait_s,
    legacy_unresolved_bound_s,
)
from pyrxd.security.errors import ValidationError
from tests import test_watch_btc_spender_classification as btc
from tests import test_watch_eth_disposition_table as eth

reconciler_mod = importlib.import_module("pyrxd.gravity.watch.reconciler")
decide_mod = importlib.import_module("pyrxd.gravity.watch.decide")

AFTER = 4_000.0  # above the test policies' longest honest wait (6 BTC blocks of 600 s)


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def _reconciler(w, clock: _Clock, *, alerter=None, policy=None) -> Reconciler:
    return Reconciler(
        store=w.store,
        observer=w.observer,
        alerter=w.pages if alerter is None else alerter,
        policy=eth._policy() if policy is None else policy,
        safety_window_blocks=6,
        legacy_unresolved_page_after_s=AFTER,
        clock=clock,
    )


async def _tick(rec: Reconciler):
    (res,) = await rec.tick()
    assert res.legacy is True
    return res


def _unresolved_pages(w) -> list:
    return [d for _s, d in w.pages.got if d.situation == SITUATION_LEGACY_UNRESOLVED]


class _StaleFinalized(eth._Endpoint):
    """Honest, except that it reports a finalized block from before the refund."""

    async def finalized_block_number(self) -> int:
        return eth.REFUND_BLOCK - 25


class _Channel:
    def __init__(self) -> None:
        self.sent: list[Page] = []

    async def send(self, page: Page) -> None:
        self.sent.append(page)


# --------------------------------------------------------------------------- ETH: one endpoint holds the read


@pytest.mark.parametrize("liar_at", [0, 1, 2])
async def test_a_stale_finalized_block_on_one_endpoint_pages_once_the_bound_passes(tmp_path, liar_at):
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    w.endpoints[liar_at].__class__ = _StaleFinalized
    clock = _Clock()
    rec = _reconciler(w, clock)
    res = await _tick(rec)
    assert res.decision.intent is Intent.WATCH and "settled_unfinal" in res.decision.reason
    clock.now += AFTER - 1
    assert (await _tick(rec)).decision.intent is Intent.WATCH
    assert w.pages.got == []
    clock.now += 1
    res = await _tick(rec)
    assert res.decision.intent is Intent.PAGE_SQUEEZED
    assert res.decision.situation == SITUATION_LEGACY_UNRESOLVED
    assert res.alert_delivered is True
    assert "settled_unfinal" in res.decision.reason and "investigate" in res.decision.recommended_action
    # It stays loud while the read stays unresolved, and writes no marker.
    clock.now += 30
    assert (await _tick(rec)).decision.intent is Intent.PAGE_SQUEEZED
    assert len(_unresolved_pages(w)) == 2
    assert w.marker() is None


async def test_HONEST_a_final_refund_on_every_endpoint_is_marked_and_never_pages(tmp_path):
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    clock = _Clock()
    rec = _reconciler(w, clock)
    assert (await _tick(rec)).decision.intent is Intent.WATCH
    assert w.marker()["verdict"] == "refunded"
    clock.now += 10 * AFTER
    assert await rec.tick() == []  # marked: never read again
    assert w.pages.got == []


@pytest.mark.parametrize("liar_at", [0, 1, 2])
async def test_a_deploy_receipt_one_endpoint_disagrees_on_pages_once_the_bound_passes(tmp_path, liar_at):
    """The case #921 was filed for: one endpoint's deploy answer differs, so the reader's identity
    read is UNKNOWN on every tick."""
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    liar = w.endpoints[liar_at]
    real = liar.get_transaction_receipt

    async def _other_block(tx_hash):
        r = await real(tx_hash)
        return r if tx_hash != w.chain.deploy_tx else {**r, "blockNumber": r["blockNumber"] + 1}

    liar.get_transaction_receipt = _other_block
    clock = _Clock()
    rec = _reconciler(w, clock)
    res = await _tick(rec)
    assert res.decision.intent is Intent.WATCH and "unknown" in res.decision.reason
    clock.now += AFTER
    res = await _tick(rec)
    assert res.decision.intent is Intent.PAGE_SQUEEZED
    assert res.decision.situation == SITUATION_LEGACY_UNRESOLVED
    assert w.marker() is None


async def test_HONEST_one_endpoint_tower_reads_the_refund_again_and_never_pages(tmp_path):
    """One endpoint's answer is quiet by design (the tower's configuration), not a stuck read."""
    w = eth._legacy(tmp_path, endpoints=1)
    w.chain.refund(eth.REFUND_BLOCK)
    clock = _Clock()
    rec = _reconciler(w, clock)
    for _ in range(3):
        res = await _tick(rec)
        assert res.decision.intent is Intent.WATCH and "only one endpoint" in res.decision.reason
        clock.now += AFTER
    assert w.pages.got == [] and w.marker() is None


async def test_HONEST_a_refund_that_finalizes_inside_the_bound_never_pages(tmp_path):
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    for e in w.endpoints:
        e.__class__ = _StaleFinalized
    clock = _Clock()
    rec = _reconciler(w, clock)
    assert (await _tick(rec)).decision.intent is Intent.WATCH
    clock.now += AFTER - 1
    for e in w.endpoints:
        e.__class__ = eth._Endpoint  # the finalized block catches up
    assert (await _tick(rec)).decision.intent is Intent.WATCH
    assert w.marker()["verdict"] == "refunded"
    assert w.pages.got == []


async def test_the_page_is_acked_once_and_stays_acked_while_the_read_stays_unresolved(tmp_path):
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    w.endpoints[0].__class__ = _StaleFinalized
    channel = _Channel()
    sent = channel.sent
    alerter = DedupAlerter(channel=channel)
    clock = _Clock()
    rec = _reconciler(w, clock, alerter=alerter)
    await _tick(rec)
    clock.now += AFTER
    await _tick(rec)
    assert len(sent) == 1
    assert alerter.unacked_critical_count() == 1
    assert alerter.ack(eth.SWAP, f"{Intent.PAGE_SQUEEZED.value}:{SITUATION_LEGACY_UNRESOLVED}")
    for _ in range(3):
        clock.now += 30
        await _tick(rec)
    assert len(sent) == 1 and alerter.unacked_critical_count() == 0


async def test_a_page_whose_record_then_resolves_leaves_no_unacked_critical(tmp_path):
    """The record is marked and never read again, so nothing else would close its page (review MED-1)."""
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    w.endpoints[1].__class__ = _StaleFinalized
    alerter = DedupAlerter(channel=_Channel())
    clock = _Clock()
    rec = _reconciler(w, clock, alerter=alerter)
    await _tick(rec)
    clock.now += AFTER
    assert (await _tick(rec)).decision.situation == SITUATION_LEGACY_UNRESOLVED
    assert alerter.unacked_critical_count() == 1
    w.endpoints[1].__class__ = eth._Endpoint  # the endpoint catches up
    clock.now += 30
    assert (await _tick(rec)).decision.intent is Intent.WATCH
    assert w.marker()["verdict"] == "refunded"
    for _ in range(20):
        assert await rec.tick() == []
    assert alerter.unacked_critical_count() == 0


async def test_HONEST_a_resolved_record_closes_only_its_own_page(tmp_path):
    """Another swap's open CRITICAL page is not touched when a legacy record resolves."""
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    w.endpoints[1].__class__ = _StaleFinalized
    alerter = DedupAlerter(channel=_Channel())
    await alerter.handle("other", Decision(Intent.PAGE_CLAIM, reason="claim it"))
    clock = _Clock()
    rec = _reconciler(w, clock, alerter=alerter)
    await _tick(rec)
    clock.now += AFTER
    await _tick(rec)
    assert alerter.unacked_critical_count() == 2
    w.endpoints[1].__class__ = eth._Endpoint
    await _tick(rec)
    assert w.marker() is not None
    assert alerter.unacked_critical_count() == 1


async def test_HONEST_a_resolved_record_keeps_its_other_open_page(tmp_path):
    """The tower ACKs its legacy_unresolved page by name, never by a bare swap id: the same swap's
    other open CRITICAL page stays un-ACKed."""
    w = eth._legacy(tmp_path)
    w.chain.refund(eth.REFUND_BLOCK)
    w.endpoints[1].__class__ = _StaleFinalized
    alerter = DedupAlerter(channel=_Channel())
    await alerter.handle(eth.SWAP, Decision(Intent.PAGE_CLAIM, reason="claim it"))
    clock = _Clock()
    rec = _reconciler(w, clock, alerter=alerter)
    await _tick(rec)
    clock.now += AFTER
    await _tick(rec)
    w.endpoints[1].__class__ = eth._Endpoint
    await _tick(rec)
    assert w.marker() is not None
    assert alerter.unacked_critical_count() == 1  # counted per swap: the claim page still counts
    pages = alerter._swaps[eth.SWAP]
    assert set(pages.paged) == {(Intent.PAGE_CLAIM, None), (Intent.PAGE_SQUEEZED, SITUATION_LEGACY_UNRESOLVED)}
    assert pages.acked == {(Intent.PAGE_SQUEEZED, SITUATION_LEGACY_UNRESOLVED)}


async def test_a_tower_with_no_eth_source_pages_a_legacy_eth_record_once_the_bound_passes(tmp_path):
    """A failed read counts, whatever made it fail: here the tower cannot read the leg at all."""
    w = eth._legacy(tmp_path)
    w.observer = ChainObserver(
        btc=btc._Tower(tmp_path / "btc").observer._btc, rxd=w.rxd, btc_burial_blocks=btc.BURIAL
    )  # BTC only
    clock = _Clock()
    rec = _reconciler(w, clock)
    res = await _tick(rec)
    assert res.decision.intent is Intent.WATCH and res.error is not None
    clock.now += AFTER
    assert (await _tick(rec)).decision.situation == SITUATION_LEGACY_UNRESOLVED


# --------------------------------------------------------------------------- BTC


async def test_a_btc_read_that_keeps_failing_pages_once_the_bound_passes(tmp_path):
    w = btc._Tower(tmp_path, role=None)
    w.write(w.record().with_state(SwapState.ABORTED))
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(btc.BURIAL)
    for s in w.sources:
        s.down = True
    clock = _Clock()
    rec = _reconciler(w, clock, policy=btc._policy())
    res = await _tick(rec)
    assert res.decision.intent is Intent.WATCH and res.error is not None
    clock.now += AFTER
    res = await _tick(rec)
    assert res.decision.intent is Intent.PAGE_SQUEEZED
    assert res.decision.situation == SITUATION_LEGACY_UNRESOLVED
    assert res.error is not None


def _buried_btc_refund(tmp_path):
    w = btc._Tower(tmp_path, role=None)
    w.write(w.record().with_state(SwapState.ABORTED))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(btc.BURIAL + 2)
    return w


@pytest.mark.parametrize("liar_at", [0, 2])
async def test_one_btc_source_naming_another_block_holds_a_buried_refund_and_pages(tmp_path, liar_at):
    w = _buried_btc_refund(tmp_path)
    w.sources[liar_at].lie_block = (1, "00" * 32)
    clock = _Clock()
    rec = _reconciler(w, clock, policy=btc._policy())
    res = await _tick(rec)
    assert res.decision.intent is Intent.WATCH
    clock.now += AFTER
    res = await _tick(rec)
    assert res.decision.situation == SITUATION_LEGACY_UNRESOLVED
    assert w.store.legacy_marker_path(w.swap_id).exists() is False


async def test_HONEST_a_buried_btc_refund_is_marked_and_never_pages(tmp_path):
    w = _buried_btc_refund(tmp_path)
    clock = _Clock()
    rec = _reconciler(w, clock, policy=btc._policy())
    assert (await _tick(rec)).decision.intent is Intent.WATCH
    assert w.store.legacy_marker_path(w.swap_id).exists()
    assert w.pages.got == []


async def test_HONEST_a_btc_tower_that_cannot_classify_spenders_never_pages(tmp_path):
    w = btc._Tower(tmp_path, role=None, classify=False)
    w.write(w.record().with_state(SwapState.ABORTED))
    clock = _Clock()
    rec = _reconciler(w, clock, policy=btc._policy())
    for _ in range(3):
        res = await _tick(rec)
        assert res.decision.intent is Intent.WATCH and "does not classify" in res.decision.reason
        clock.now += AFTER
    assert w.pages.got == []


# --------------------------------------------------------------------------- what starts and ends the bound


class _OneRecordStore:
    def __init__(self, record) -> None:
        self.legacy = [("s1", record)]

    async def list_active(self):
        return []


class _Observer:
    async def observe(self, swap_id, record):
        return None


class _Pages:
    def __init__(self) -> None:
        self.got: list[tuple[str, Decision]] = []

    async def handle(self, swap_id, decision) -> None:
        self.got.append((swap_id, decision))

    def resolve(self, swap_id) -> None:
        pass


_UNRESOLVED = LegacyCheck(Decision(Intent.WATCH, reason="read again later"), "unknown")
_QUIET = LegacyCheck(Decision(Intent.WATCH, reason="one endpoint"), "refunded_single_source", quiet_by_design=True)
_PAGE = LegacyCheck(Decision(Intent.PAGE_REFUND, reason="refund it"), "open")


async def _run(monkeypatch, tmp_path, checks: list[tuple[float, LegacyCheck]]) -> list[Decision]:
    """Tick once per ``(seconds since the first tick, check)``; return each tick's decision."""
    w = eth._legacy(tmp_path)
    queue = list(checks)
    monkeypatch.setattr(reconciler_mod, "decide_legacy", lambda **_kw: queue[0][1])
    clock = _Clock()
    start = clock.now
    pages = _Pages()
    rec = Reconciler(
        store=_OneRecordStore(w.record()),
        observer=_Observer(),
        alerter=pages,
        policy=eth._policy(),
        safety_window_blocks=6,
        legacy_unresolved_page_after_s=AFTER,
        clock=clock,
    )
    out = []
    while queue:
        clock.now = start + queue[0][0]
        out.append((await _tick(rec)).decision)
        queue.pop(0)
    return out


async def test_a_page_restarts_the_bound(monkeypatch, tmp_path):
    out = await _run(monkeypatch, tmp_path, [(0, _UNRESOLVED), (AFTER - 10, _PAGE), (AFTER + 10, _UNRESOLVED)])
    assert [d.intent for d in out] == [Intent.WATCH, Intent.PAGE_REFUND, Intent.WATCH]


async def test_a_quiet_by_design_read_does_not_restart_the_bound(monkeypatch, tmp_path):
    """A liar that alternates an unresolved read with one that is quiet by design gains nothing."""
    out = await _run(monkeypatch, tmp_path, [(0, _UNRESOLVED), (AFTER / 2, _QUIET), (AFTER, _UNRESOLVED)])
    assert [d.intent for d in out] == [Intent.WATCH, Intent.WATCH, Intent.PAGE_SQUEEZED]


async def test_HONEST_quiet_by_design_alone_never_starts_the_bound(monkeypatch, tmp_path):
    out = await _run(monkeypatch, tmp_path, [(0, _QUIET), (AFTER, _QUIET), (2 * AFTER, _QUIET)])
    assert [d.intent for d in out] == [Intent.WATCH] * 3


async def test_a_conclusive_read_ends_the_bound(monkeypatch, tmp_path):
    done = LegacyCheck(Decision(Intent.WATCH, reason="agrees"), "refunded", conclusive=True)
    out = await _run(monkeypatch, tmp_path, [(0, _UNRESOLVED), (AFTER - 10, done), (AFTER + 10, _UNRESOLVED)])
    assert [d.intent for d in out] == [Intent.WATCH] * 3


# --------------------------------------------------------------------------- which verdicts are quiet by design


def test_only_configuration_verdicts_are_quiet_by_design():
    """Derived from the source: every ``LegacyCheck`` built with ``quiet_by_design=True`` returns one
    of the verdicts no endpoint can hold while value is at stake, and there is at least one."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(decide_mod))
    verdicts = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "LegacyCheck"
            and any(k.arg == "quiet_by_design" for k in node.keywords)
        ):
            verdicts.append(ast.unparse(node.args[1]))
    assert verdicts
    assert sorted(set(verdicts)) == sorted(
        {"'skipped'", "'unclassified'", "'refunded_single_source'", "f'{kind.value}_single_source'", "kind.value"}
    )
    # The one ``kind.value`` among them is the empty-at-every-tip answer.
    src = inspect.getsource(decide_mod._decide_legacy_eth)
    block = src[src.index("if kind is DispositionKind.EXPIRED_EMPTY_OPEN:") :]
    assert block.index("quiet_by_design=True") < block.index("agreeing = (")


# --------------------------------------------------------------------------- the knob


@pytest.mark.parametrize("bad", [0, -1.0, float("nan"), float("inf"), True, "600"])
def test_the_bound_must_be_positive_and_finite(tmp_path, bad):
    w = eth._legacy(tmp_path)
    with pytest.raises(ValidationError):
        Reconciler(
            store=w.store,
            observer=w.observer,
            alerter=w.pages,
            policy=eth._policy(),
            safety_window_blocks=6,
            legacy_unresolved_page_after_s=bad,
        )


def test_the_cli_flag_parses_to_the_default():
    from pyrxd.gravity.watch import run

    parser = run._build_parser()
    assert parser.get_default("legacy_unresolved_page_after_s") is None  # derived from the policy
    flag = next(a for a in parser._actions if a.dest == "legacy_unresolved_page_after_s")
    assert flag.type is float


def test_the_builder_hands_the_bound_to_the_reconciler():
    from pyrxd.gravity.swap_coordinator import MarginPolicy
    from pyrxd.gravity.watch import run
    from pyrxd.gravity.watch.adapters import LoggingAlertChannel
    from pyrxd.network.bitcoin import MultiSourceBtcFundingReader

    def build(**kw) -> Reconciler:
        return run.build_reconciler(
            records_dir="/nonexistent-records",  # read only when a tick runs
            rxd_source=eth._Rxd(),
            rxd_corroborated=False,
            btc_funding_reader=MultiSourceBtcFundingReader.from_endpoints(["https://x.test", "https://y.test"]),
            http_session=None,  # type: ignore[arg-type]  # only used when a tick runs
            mempool_base_urls=["https://x.test"],
            policy=MarginPolicy.estimated(),
            safety_window_blocks=6,
            alert_channel=LoggingAlertChannel(),
            **kw,
        )

    assert build(legacy_unresolved_page_after_s=7_200.0)._legacy_page_after_s == 7_200.0
    assert build()._legacy_page_after_s == legacy_unresolved_bound_s(MarginPolicy.estimated())


def _deep(policy: MarginPolicy, blocks: int) -> MarginPolicy:
    return dataclasses.replace(policy, btc_claim_reorg_depth=Timelock(blocks, TimeUnit.BLOCKS))


def test_the_honest_wait_is_the_policys_btc_burial_or_eth_finality():
    est = MarginPolicy.estimated()
    assert legacy_honest_wait_s(est) == 6 * 600  # the estimated policy's reorg depth and block interval
    assert legacy_honest_wait_s(_deep(est, 50)) == 50 * 600
    eth_policy = eth._policy()
    assert legacy_honest_wait_s(eth_policy) == max(6 * 600, eth_policy.eth_finalization_window_s)
    slow = dataclasses.replace(eth_policy, eth_finalization_window_s=10_000)
    assert legacy_honest_wait_s(slow) == 10_000  # ETH finality longer than the BTC burial


def test_the_default_bound_follows_a_deep_policy():
    est = MarginPolicy.estimated()
    assert legacy_unresolved_bound_s(est) == DEFAULT_LEGACY_UNRESOLVED_PAGE_AFTER_S
    deep = _deep(est, 50)
    assert legacy_unresolved_bound_s(deep) == 2 * 50 * 600 > legacy_honest_wait_s(deep)


@pytest.mark.parametrize("blocks", [6, 50])
def test_a_bound_at_or_below_the_honest_wait_is_refused(tmp_path, blocks):
    w = eth._legacy(tmp_path)
    policy = _deep(MarginPolicy.estimated(), blocks)
    honest = legacy_honest_wait_s(policy)

    def make(bound):
        return Reconciler(
            store=w.store,
            observer=w.observer,
            alerter=w.pages,
            policy=policy,
            safety_window_blocks=6,
            legacy_unresolved_page_after_s=bound,
        )

    with pytest.raises(ValidationError, match="--legacy-unresolved-page-after-s"):
        make(honest)
    assert make(honest + 1)._legacy_page_after_s == honest + 1
    assert make(None)._legacy_page_after_s == legacy_unresolved_bound_s(policy)

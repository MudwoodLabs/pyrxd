"""One faulty ETH endpoint cannot lower or silence the tower's page (0.27 release review, A-1, A-2, A-3,
A-5).

The BTC side of the tower holds the profile invariant "one faulty source cannot lower a page" in a
stateful test; the ETH side did not, and the release review found four ways in, each reproduced on
the fakes before it was fixed:

* A-1: a primary endpoint that failed every scan turned every page for the swap into one
  ``reconcile_error``; once that page was ACKed, a final claim the other endpoints served paged
  nothing.
* A-2: one endpoint's lagging ``finalized`` (the tower read the MIN) held a final claim at "not yet
  final", so the tower WATCHed where it should page the claim race.
* A-3: at PARAMS_MISMATCH, one forked endpoint turned the CRITICAL "claimed after a params mismatch"
  page into the WARN refund page.
* A-5: the "refund is now runnable" transition of an ETH HTLC (legacy record, or BOTH_LOCKED) shared
  a situation with the page before it, so it never paged.

Each refusal is driven with the fault at every index and has its honest twin.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.disposition import DispositionKind
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.swap_state import RecordRole, SwapState
from pyrxd.gravity.watch.alerts import DedupAlerter, Severity, ack_id
from pyrxd.gravity.watch.decide import Intent
from pyrxd.gravity.watch.eth_adapters import RpcEthChainSource
from pyrxd.gravity.watch.reconciler import SITUATION_RECONCILE_ERROR
from pyrxd.security.errors import NetworkError
from tests.test_watch_eth_disposition_table import (
    CLAIM_BLOCK,
    SWAP,
    TIMEOUT_BLOCK,
    _Endpoint,
    _EthTower,
    decide_mod,
)

INDICES = [0, 1, 2]


class _Channel:
    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, page) -> None:
        self.sent.append(page)


async def _boom(*_a, **_kw):
    raise NetworkError("429 Too Many Requests")


def _fail(endpoint: _Endpoint, method: str) -> None:
    setattr(endpoint, method, _boom)


def _ack_line(page) -> tuple[str, str]:
    swap, key = page.message.rsplit("ack: ", 1)[1].strip().split(" ", 1)
    return swap, key


async def _honest_decision(w: _EthTower):
    """What a tower with every endpoint honest decides on the same chain and record."""
    honest = _EthTower.__new__(_EthTower)
    honest.__dict__.update(w.__dict__)
    rpc = MultiSourceEthRpc([_Endpoint(w.chain) for _ in w.endpoints])
    honest.observer = type(w.observer)(
        eth=RpcEthChainSource(rpc), rxd=w.rxd, clock=lambda: float(w.chain.ts(w.chain.head))
    )
    return await honest.decide()


# --------------------------------------------------------------------------- A-1: a failing primary


@pytest.mark.parametrize("method", ["get_logs", "get_transaction"])
@pytest.mark.parametrize("index", INDICES)
async def test_a_failing_endpoint_never_hides_a_claim_the_others_serve(tmp_path, index, method):
    w = _EthTower(tmp_path)
    claim = w.chain.claim(CLAIM_BLOCK)
    _fail(w.endpoints[index], method)
    status = await w.observer._eth.claim_status(w.chain.locator().contract_address, w.chain.deploy_tx)
    assert status.claimed is True and status.claim_tx_hash == claim
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM and d.situation == decide_mod.SITUATION_CLAIM_RACE, d
    assert (d.intent, d.situation) == ((h := await _honest_decision(w)).intent, h.situation)


@pytest.mark.parametrize("index", INDICES)
async def test_an_acked_reconcile_error_does_not_swallow_a_later_claim(tmp_path, index):
    """The release review's sequence: the primary fails while nothing is claimed, so the tower pages a
    reconcile error and the operator ACKs it. The maker's claim then lands before the timeout and is
    final on the other endpoints. It must page, whichever endpoint keeps failing."""
    w = _EthTower(tmp_path)
    w.chain.head, w.chain.finalized = 30, 20
    _fail(w.endpoints[index], "get_logs")
    if index != 0:
        _fail(w.endpoints[0], "get_transaction")  # the ACKed page needs a failing scan on some endpoint
    channel = _Channel()
    alerter = DedupAlerter(channel=channel)
    rec = w.reconciler(alerter=alerter)

    (first,) = await rec.tick()
    assert first.decision.situation == SITUATION_RECONCILE_ERROR
    assert channel.sent and channel.sent[-1].severity is Severity.CRITICAL
    swap, key = _ack_line(channel.sent[-1])
    assert swap == ack_id(SWAP) and alerter.ack(SWAP, key) is True
    before = len(channel.sent)

    w.chain.head, w.chain.finalized = 100, 64
    w.chain.claim(CLAIM_BLOCK)
    assert CLAIM_BLOCK < TIMEOUT_BLOCK

    (second,) = await rec.tick()
    assert second.decision.intent is Intent.PAGE_CLAIM, second.decision
    assert len(channel.sent) == before + 1 and channel.sent[-1].severity is Severity.CRITICAL
    assert alerter.unacked_critical_count() == 1


async def test_HONEST_a_failing_primary_with_no_claim_anywhere_still_raises(tmp_path):
    """The union scan's fail-closed side is unchanged: with nothing claimed, the primary's failure is
    not read as "no claim", so the reconciler still pages a reconcile error."""
    w = _EthTower(tmp_path)
    _fail(w.endpoints[0], "get_logs")
    with pytest.raises(NetworkError):
        await w.observer._eth.claim_status(w.chain.locator().contract_address, w.chain.deploy_tx)
    channel = _Channel()
    (res,) = await w.reconciler(alerter=DedupAlerter(channel=channel)).tick()
    assert res.decision.situation == SITUATION_RECONCILE_ERROR
    assert channel.sent[-1].severity is Severity.CRITICAL


async def test_HONEST_a_failing_secondary_with_no_claim_is_no_claim(tmp_path):
    w = _EthTower(tmp_path)
    _fail(w.endpoints[2], "get_logs")
    status = await w.observer._eth.claim_status(w.chain.locator().contract_address, w.chain.deploy_tx)
    assert status.claimed is False


# --------------------------------------------------------------------------- A-2: a lagging finalized


@pytest.mark.parametrize("role", [RecordRole.TAKER, RecordRole.MAKER, None])
@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.BOTH_LOCKED])
@pytest.mark.parametrize("index", INDICES)
async def test_one_endpoint_lagging_finalized_does_not_hold_a_final_claim(tmp_path, index, state, role):
    """The endpoint's head is honest and its ``finalized`` trails by 30 blocks, below the claim's
    block; the other two read the claim final. The tower decides what the honest tower decides."""
    kw: list[dict] = [{}, {}, {}]
    kw[index] = {"finalized_lag": 30}
    w = _EthTower(tmp_path, state=state, role=role, endpoint_kw=kw)
    w.chain.claim(CLAIM_BLOCK)
    assert w.chain.finalized - 30 < CLAIM_BLOCK <= w.chain.finalized
    obs = await w.observe()
    assert obs.eth_claim_detected is True
    assert obs.eth_claim_finality is CounterClaimState.FINAL, obs
    d = await w.decide()
    h = await _honest_decision(w)
    assert (d.intent, d.situation) == (h.intent, h.situation), (d, h)
    assert d.intent is not Intent.WATCH


async def test_HONEST_a_quorum_lagging_finalized_still_reads_not_final(tmp_path):
    """The quorum-th ``finalized`` is the value a quorum (two of three) stand at or above: when two
    endpoints trail below the claim, it is not final, as before."""
    w = _EthTower(tmp_path, endpoint_kw=[{"finalized_lag": 30}, {}, {"finalized_lag": 30}])
    w.chain.claim(CLAIM_BLOCK)
    obs = await w.observe()
    assert obs.eth_claim_finality is not CounterClaimState.FINAL


@pytest.mark.parametrize("index", INDICES)
async def test_one_endpoint_cannot_move_the_stall_trackers_finalized(tmp_path, index):
    """The across-time stall input reads the same quorum-th value, so one endpoint whose ``finalized``
    trails, or runs ahead within its own head, does not reset the tracker."""
    for lag in (30, -10):
        kw: list[dict] = [{}, {}, {}]
        kw[index] = {"finalized_lag": lag}
        w = _EthTower(tmp_path / f"{index}{lag}", endpoint_kw=kw)
        _head, finalized = await w.observer._eth.finality_checkpoint()
        assert finalized == w.chain.finalized


async def test_a_single_endpoint_tower_reads_its_own_finalized(tmp_path):
    w = _EthTower(tmp_path, endpoint_kw=[{"finalized_lag": 30}])
    _head, finalized = await w.observer._eth.finality_checkpoint()
    assert finalized == w.chain.finalized - 30


# --------------------------------------------------------------------------- A-3: PARAMS_MISMATCH


@pytest.mark.parametrize("role", [RecordRole.TAKER, RecordRole.MAKER])
@pytest.mark.parametrize("index", INDICES)
async def test_one_forked_endpoint_does_not_lower_a_claim_after_a_params_mismatch(tmp_path, index, role):
    """The maker's claim is final on the honest endpoints. One forked endpoint makes the reader UNKNOWN
    and the claim's finality un-assessable; the refund page it falls back to says p may be public and is
    CRITICAL, re-paged until ACKed, as the honest tower's page is."""
    kw: list[dict] = [{}, {}, {}]
    kw[index] = {"fork": "x"}
    w = _EthTower(tmp_path, state=SwapState.PARAMS_MISMATCH, role=role, endpoint_kw=kw)
    w.chain.claim(CLAIM_BLOCK)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.UNKNOWN and obs.eth_claim_finality is None
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.urgent is True, d
    assert "p may be public" in d.reason
    channel = _Channel()
    alerter = DedupAlerter(channel=channel)
    await alerter.handle(SWAP, d)
    assert channel.sent[-1].severity is Severity.CRITICAL
    h = await _honest_decision(w)
    assert h.situation == decide_mod.SITUATION_ETH_CLAIMED_AFTER_MISMATCH


@pytest.mark.parametrize("index", INDICES)
async def test_HONEST_one_odd_log_on_a_clean_read_keeps_the_warn_refund_page(tmp_path, index):
    """Mythos F2 (PR 10) is unchanged: a clean read that finds no claim beside one endpoint's odd log
    keeps the plain refund page, not urgent."""
    from tests.test_watch_eth_disposition_table import _odd_claimed_log

    kw: list[dict] = [{}, {}, {}]
    kw[index] = {"extra_logs": (_odd_claimed_log(),)}
    w = _EthTower(tmp_path, state=SwapState.PARAMS_MISMATCH, endpoint_kw=kw)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.urgent is False
    assert d.situation == decide_mod.SITUATION_PARAMS_MISMATCH_REFUND


# --------------------------------------------------------------------------- A-5: the runnable step


async def test_a_both_locked_eth_refund_pages_again_when_its_timeout_passes(tmp_path):
    """BOTH_LOCKED, t_rxd near: the refund page goes out while the ETH timeout is ahead, and again,
    under its own situation, once the timeout has passed and mutual_refund can run."""
    w = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED)
    w.chain.head, w.chain.finalized = TIMEOUT_BLOCK - 10, TIMEOUT_BLOCK - 20
    w.rxd.cov_confs = 40  # t_rxd for these terms is 40 blocks: the refund window is open
    channel = _Channel()
    alerter = DedupAlerter(channel=channel)
    rec = w.reconciler(alerter=alerter)
    (due,) = await rec.tick()
    assert due.decision.situation == decide_mod.SITUATION_BOTH_LOCKED_REFUND_DUE, due.decision
    assert len(channel.sent) == 1
    (again,) = await rec.tick()
    assert again.decision.situation == decide_mod.SITUATION_BOTH_LOCKED_REFUND_DUE
    assert len(channel.sent) == 1

    w.chain.head, w.chain.finalized = 100, 64
    (runnable,) = await rec.tick()
    assert runnable.decision.situation == decide_mod.SITUATION_BOTH_LOCKED_REFUND_RUNNABLE, runnable.decision
    assert runnable.decision.recommended_action == "mutual_refund"
    assert runnable.decision.urgent is False  # past its timeout the contract refuses a claim
    assert len(channel.sent) == 2


async def test_a_maker_both_locked_record_keeps_its_covenant_page(tmp_path):
    w = _EthTower(tmp_path, state=SwapState.BOTH_LOCKED, role=RecordRole.MAKER)
    w.rxd.cov_confs = 40
    d = await w.decide()
    assert d.situation == decide_mod.SITUATION_MAKER_REFUND_T_RXD_NEAR


async def test_a_legacy_eth_refund_pages_again_once_it_can_run(tmp_path):
    """A pre-0.27 terminal record whose refund never landed: the WARN sent while the contract was OPEN
    said it can be refunded once its timeout passes; the timeout passing pages "refund it" under its own
    situation, and the record is still never marked."""
    from tests.test_watch_eth_disposition_table import _legacy

    w = _legacy(tmp_path)
    w.chain.head, w.chain.finalized = TIMEOUT_BLOCK - 10, TIMEOUT_BLOCK - 20
    channel = _Channel()
    rec = w.reconciler(alerter=DedupAlerter(channel=channel))
    for _ in range(2):
        [res] = await rec.tick()
        assert res.legacy is True and res.decision.situation == decide_mod.SITUATION_LEGACY_ETH_UNSETTLED
    assert len(channel.sent) == 1
    w.chain.head, w.chain.finalized = 100, 64
    for _ in range(2):
        [res] = await rec.tick()
        assert res.decision.situation == decide_mod.SITUATION_LEGACY_ETH_REFUND_RUNNABLE, res.decision
        assert "refund it" in res.decision.reason
    assert len(channel.sent) == 2
    assert w.marker() is None


@pytest.mark.parametrize("frozen_at", [None, *INDICES])
async def test_one_endpoint_with_a_frozen_head_does_not_hold_off_the_stall(tmp_path, frozen_at):
    """Re-review of the A-2 fix: the tracker's head was the MIN, so one endpoint answering a frozen head
    kept the head's progress at 0 and no stall was ever declared. ``finalized`` is frozen below the
    claim while the head climbs; the stall is declared whichever endpoint freezes its head."""
    w = _EthTower(tmp_path)
    w.chain.claim(CLAIM_BLOCK)
    w.chain.finalized, w.chain.head = 30, 100
    if frozen_at is not None:

        async def frozen():
            return 100

        w.endpoints[frozen_at].block_number = frozen
    states = []
    for _ in range(8):
        states.append((await w.observe()).eth_claim_finality)
        w.chain.head += 60
    assert CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING in states, states


async def test_HONEST_two_endpoints_one_lagging_finalized_still_holds_the_claim(tmp_path):
    """The limit the docstring states: with two endpoints the default quorum is both, the quorum-th
    value is the MIN, and one lagging endpoint still reads the claim not final."""
    w = _EthTower(tmp_path, endpoint_kw=[{}, {"finalized_lag": 30}])
    w.chain.claim(CLAIM_BLOCK)
    assert (await w.observe()).eth_claim_finality is not CounterClaimState.FINAL

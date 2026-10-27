"""One faulty BTC source, or one unreadable RXD read, must not lower the tower's page (register R12,
R13, R1 with R8; whole-component tower Mythos pass, 2026-10-27).

* **R12.** One source that alone serves a refund of ours (dropped, replaced, or never relayed) beside
  a quorum that reads the outpoint unspent made the read REFUND_PENDING. The tower then WATCHed that
  refund, armed nothing, and paged only near t_rxd, naming a refund that was on no chain. The read
  is now taken as unspent (``BtcCounterDisposition.refund_outvoted``).
* **R13.** The BTC depth was the MINIMUM across sources, so one source under-reporting a buried
  maker claim held the claim page back until the t_rxd window closed (and the page then named the
  winner-take-all path). The depth is now the one a quorum vouches for
  (``pyrxd.network.quorum_depth.depth_vouched_by_quorum``); one over-reporter still cannot raise it.
* **R1 with R8.** A BOTH_LOCKED taker whose RXD sources could not read the covenant got WATCH, past
  t_rxd too. The BTC funding depth is now the clock there, as at BTC_LOCKED.

Each refusal is paired with its honest twin, on the real Taproot fake chain behind the production
observer, reader and reconciler (``tests._fake_btc_chain``).
"""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.disposition import BtcDispositionKind, read_btc_counter_disposition
from pyrxd.gravity.swap_state import RecordRole, SwapState
from pyrxd.gravity.watch.decide import (
    SITUATION_BOTH_LOCKED_LOCK_HEIGHT_UNREAD,
    SITUATION_BTC_REFUND_DUE,
    SITUATION_BTC_REFUND_PENDING,
    SITUATION_CLAIM_RACE,
    SITUATION_MAKER_REFUND_LOCK_HEIGHT_UNREAD,
    Intent,
    Observations,
    decide,
)
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
from pyrxd.network.quorum_depth import depth_vouched_by_quorum
from pyrxd.security.errors import ValidationError
from pyrxd.security.units import ChainHeight, Confirmations
from tests._fake_btc_chain import FakeBtcChain, FakeBtcSource
from tests.test_btc_counter_disposition import _with_witness_of
from tests.test_watch_btc_spender_classification import BURIAL, COV_CONFS, T_RXD, TIP, _policy, _Tower
from tests.test_watch_legacy_btc_net import _legacy

K = BtcDispositionKind
LOCKED_AT = TIP - COV_CONFS + 1
T_RXD_OPENS = LOCKED_AT + T_RXD


def _stale_refund(w: _Tower, i: int = 2) -> str:
    """Source *i* serves a refund of ours that is on no chain (signed, never relayed or since dropped)."""
    raw = w.chain.refund_tx(fee_sats=777)
    w.sources[i].forge_spender = raw
    return t.btc_txid_from_raw(raw)


# --------------------------------------------------------------------------- R12


async def test_one_stale_refund_beside_a_quorum_of_unspent_neither_disarms_nor_quiets_the_refund(tmp_path):
    w = _Tower(tmp_path)  # BTC_LOCKED taker, funding matured, covenant known, t_rxd far
    honest = await w.decide()
    assert honest.intent is Intent.PAGE_REFUND and honest.autonomous_btc_refund
    stale = _stale_refund(w)
    obs = await w.observe()
    assert obs.btc_disposition is K.REFUND_PENDING and obs.btc_refund_outvoted
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND, d.reason
    assert d.autonomous_btc_refund is True
    assert d.situation == SITUATION_BTC_REFUND_DUE == honest.situation
    assert stale in d.reason and "not on the chain" in d.reason


def _near_t_rxd(w: _Tower) -> None:
    w.rxd.tip = T_RXD_OPENS - 3
    w.rxd.cov_confs = w.rxd.tip - LOCKED_AT + 1


async def test_at_both_locked_near_t_rxd_a_stale_refund_keeps_the_critical_pending_refund_page(tmp_path):
    """Review F1: read as unspent near t_rxd, the BOTH_LOCKED page fell from the CRITICAL pending-refund
    squeeze to a WARN naming a step not yet runnable. Nothing arms at BOTH_LOCKED; the squeeze stays."""
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    _near_t_rxd(w)
    stale = _stale_refund(w)
    d = await w.decide()
    assert d.intent is Intent.PAGE_SQUEEZED and d.situation == SITUATION_BTC_REFUND_PENDING, d.reason
    assert stale in d.reason and "not on the chain" in d.reason


@pytest.mark.parametrize("role", [RecordRole.TAKER, RecordRole.NONE, None])
async def test_at_both_locked_with_the_lock_height_unread_a_stale_refund_decides_as_the_honest_tower(tmp_path, role):
    """Re-review 2, L1: with the lock height unread, _t_rxd_near fails toward True, so the F1 guard
    paged a CRITICAL squeeze where the honest tower WATCHes on the funding-depth clock."""
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED, role=role)
    w.rxd.cov_confs = None
    record = w.record()
    for depth in (3, 51):  # immature: WATCH; matured: the urgent refund page
        obs = dataclasses.replace(await w.observe(), btc_funding_confirmations=Confirmations(depth))
        honest = _decide(record, obs)
        w.sources[2].forge_spender = None
        _stale_refund(w)
        stale_obs = dataclasses.replace(await w.observe(), btc_funding_confirmations=Confirmations(depth))
        w.sources[2].forge_spender = None
        assert stale_obs.btc_refund_outvoted
        d = _decide(record, stale_obs)
        assert (d.intent, d.urgent, d.situation) == (honest.intent, honest.urgent, honest.situation), d.reason


@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH])
async def test_near_t_rxd_a_stale_refund_still_lets_the_pre_signed_refund_go_out(tmp_path, state):
    """Re-review G1: limiting the override to "t_rxd not near" kept the squeeze here too, and the
    pre-signed refund the honest tower sends near t_rxd stayed home."""
    w = _Tower(tmp_path, state=state)
    _near_t_rxd(w)
    honest = await w.decide()
    assert honest.intent is Intent.PAGE_REFUND and honest.urgent and honest.autonomous_btc_refund
    w.presign()
    _stale_refund(w)
    (res,) = await w.reconciler(executor=w.executor()).tick()
    d = res.decision
    assert d.intent is Intent.PAGE_REFUND and d.urgent and d.autonomous_btc_refund, d.reason
    assert w.chain.mempool is not None, "the pre-signed refund was not broadcast"


async def test_one_stale_refund_does_not_stop_the_pre_signed_refund_going_out(tmp_path):
    w = _Tower(tmp_path)
    w.presign()
    _stale_refund(w)
    (res,) = await w.reconciler(executor=w.executor()).tick()
    assert res.decision.autonomous_btc_refund
    assert w.chain.mempool is not None, "the pre-signed refund was not broadcast"


async def test_a_refund_a_quorum_names_is_still_pending_and_arms_nothing(tmp_path):
    """Honest twin: our refund relayed to every source is the pending refund it was."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    obs = await w.observe()
    assert obs.btc_disposition is K.REFUND_PENDING and not obs.btc_refund_outvoted
    d = await w.decide()
    assert d.intent is Intent.WATCH and not d.autonomous_btc_refund


async def test_a_stale_refund_beside_a_source_that_is_down_is_not_outvoted(tmp_path):
    """A source that is down is never a vote for "unspent": one honest "unspent" is below the quorum."""
    w = _Tower(tmp_path)
    _stale_refund(w, 2)
    w.sources[1].down = True
    obs = await w.observe()
    assert obs.btc_disposition is K.REFUND_PENDING and not obs.btc_refund_outvoted
    d = await w.decide()
    assert not d.autonomous_btc_refund


async def test_a_stale_refund_beside_a_claim_is_not_outvoted():
    """A claim seen anywhere is the claim race, whatever the refunds read."""
    chain = FakeBtcChain()
    sources = [
        FakeBtcSource(chain, forge_spender=chain.claim_tx(fee_sats=900)),
        FakeBtcSource(chain),
        FakeBtcSource(chain),
        FakeBtcSource(chain, forge_spender=chain.refund_tx(fee_sats=777)),
    ]
    d = await read_btc_counter_disposition(
        sources, chain.locator, hashlock=chain.hashlock, burial_blocks=BURIAL, quorum=2
    )
    assert d.claims_seen and not d.refund_outvoted


async def test_a_claim_witness_served_over_a_minority_refund_is_not_outvoted():
    """Re-review G2: a refund spender can carry a claim witness served for its txid (``claim_raw``);
    that read is REFUND_PENDING with a claim seen, and is never read as unspent."""
    chain = FakeBtcChain()
    refund = chain.refund_tx(fee_sats=777)
    claim_witness = _with_witness_of(refund, chain.claim_tx())
    sources = [
        FakeBtcSource(chain, forge_spender=refund),
        FakeBtcSource(chain, forge_spender=claim_witness),
        *[FakeBtcSource(chain) for _ in range(3)],
    ]
    d = await read_btc_counter_disposition(
        sources, chain.locator, hashlock=chain.hashlock, burial_blocks=BURIAL, quorum=3
    )
    assert d.kind is K.REFUND_PENDING and d.claims_seen
    assert not d.refund_outvoted


@pytest.mark.parametrize("quorum", [1, 2, 3])
async def test_refund_outvoted_needs_a_quorum_of_unspent_and_a_minority_of_refunds(quorum):
    chain = FakeBtcChain()
    stale = FakeBtcSource(chain, forge_spender=chain.refund_tx(fee_sats=777))
    sources = [stale, FakeBtcSource(chain), FakeBtcSource(chain)]
    d = await read_btc_counter_disposition(
        sources, chain.locator, hashlock=chain.hashlock, burial_blocks=BURIAL, quorum=quorum
    )
    assert d.kind is K.REFUND_PENDING and d.quorum == quorum
    # quorum 1: the one source that names it is a quorum. quorum 3: two "unspent" are not.
    assert d.refund_outvoted is (quorum == 2)


async def test_the_legacy_net_pages_an_unspent_htlc_over_a_stale_refund(tmp_path):
    w = _legacy(tmp_path)
    honest = (await w.reconciler().tick())[0].decision
    assert honest.intent is Intent.PAGE_REFUND
    _stale_refund(w)
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_REFUND and "never confirmed" in res.decision.reason
    assert res.decision.situation == honest.situation


def test_btc_refund_outvoted_needs_a_refund_pending_read():
    with pytest.raises(ValidationError, match="btc_refund_outvoted"):
        Observations(
            maker_has_claimed_btc=False,
            now_rxd_height=ChainHeight(1),
            btc_spend_classified=True,
            btc_disposition=K.UNSPENT,
            btc_refund_outvoted=True,
        )


# --------------------------------------------------------------------------- R13


def _claim_buried(w: _Tower) -> str:
    txid = w.chain.submit(w.chain.claim_tx(fee_sats=2_000))
    w.chain.mine(BURIAL + 2)
    return txid


async def test_one_source_under_reporting_a_buried_claim_does_not_hold_the_claim_page(tmp_path):
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    _claim_buried(w)
    honest = await w.decide()
    assert honest.intent is Intent.PAGE_CLAIM and honest.situation == SITUATION_CLAIM_RACE, honest.reason
    w.sources[0].lie_depth = 0
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM, d.reason
    assert d.autonomous_asset_claim == honest.autonomous_asset_claim


async def test_one_source_over_reporting_a_shallow_claim_cannot_make_it_safe(tmp_path):
    """Honest twin, the other direction (F-17): one over-reporter cannot bury a 1-deep claim."""
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    w.chain.submit(w.chain.claim_tx(fee_sats=2_000))
    w.chain.mine(1)
    w.sources[0].lie_depth = BURIAL + 100
    d = await w.decide()
    assert d.intent is Intent.WATCH and "awaiting reorg-safe burial" in d.reason, d.reason
    assert not d.autonomous_asset_claim


async def test_two_sources_under_reporting_still_hold_it_at_two_of_three(tmp_path):
    """The quorum's stated limit: two faulty sources out of three are a quorum."""
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    _claim_buried(w)
    w.sources[0].lie_depth = 0
    w.sources[1].lie_depth = 0
    d = await w.decide()
    assert d.intent is Intent.WATCH, d.reason


@pytest.mark.parametrize(
    ("depths", "quorum", "expected"),
    [
        ([8, 8, 0], 2, 8),  # one under-reporter, outvoted
        ([0, 0, 99], 2, 0),  # one over-reporter, outvoted
        ([8, 3, 5], 2, 5),  # the quorum-th deepest
        ([8, 0], 2, 0),  # exactly a quorum answering: their minimum
        ([8, 7, 0], 3, 0),  # every source is needed
        ([8, 0, 0], 1, 0),  # a quorum of one never takes the deepest
        ([5], 2, 5),  # fewer answers than the quorum (a below-dust read): the minimum
    ],
)
def test_depth_vouched_by_quorum(depths, quorum, expected):
    assert depth_vouched_by_quorum(depths, quorum) == expected


@pytest.mark.parametrize(("depths", "quorum"), [([], 2), ([1], 0), ([1], True)])
def test_depth_vouched_by_quorum_refuses_what_it_cannot_answer(depths, quorum):
    with pytest.raises(ValidationError):
        depth_vouched_by_quorum(depths, quorum)


async def test_the_funding_reader_takes_the_depth_a_quorum_vouches_for():
    chain = FakeBtcChain()
    txid = chain.submit(chain.claim_tx())
    chain.mine(9)
    sources = [FakeBtcSource(chain), FakeBtcSource(chain), FakeBtcSource(chain, lie_depth=0)]
    assert await MultiSourceBtcFundingReader(sources, quorum=2).confirmations(txid) == 9
    sources[2].lie_depth = 500
    sources[1].lie_depth = None
    assert await MultiSourceBtcFundingReader(sources, quorum=2).confirmations(txid) == 9
    sources[2].lie_depth = 0
    assert await MultiSourceBtcFundingReader(sources, quorum=3).confirmations(txid) == 0


# --------------------------------------------------------------------------- R1 with R8


async def test_both_locked_with_an_unreadable_covenant_pages_once_the_btc_refund_has_matured(tmp_path):
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)  # funding buried 51 >= t_btc 10
    w.rxd.tip = T_RXD_OPENS + 50  # past t_rxd
    w.rxd.cov_confs = w.rxd.tip - LOCKED_AT + 1
    honest = await w.decide()
    assert honest.intent is Intent.PAGE_REFUND and honest.urgent
    w.rxd.cov_confs = None
    obs = await w.observe()
    assert obs.asset_locked_at_height is None and obs.btc_funding_confirmations is not None
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.urgent, d.reason
    assert d.situation == SITUATION_BOTH_LOCKED_LOCK_HEIGHT_UNREAD
    assert d.recommended_action == "mutual_refund" and not d.autonomous_btc_refund


async def test_both_locked_reads_the_funding_depth_only_when_the_lock_height_is_unread(tmp_path):
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    assert (await w.observe()).btc_funding_confirmations is None
    w.rxd.cov_confs = None
    assert (await w.observe()).btc_funding_confirmations == 51


def _both_locked_obs(**kw) -> Observations:
    return Observations(maker_has_claimed_btc=False, now_rxd_height=ChainHeight(TIP), **kw)


def _both_locked_record(tmp_path, *, role=RecordRole.TAKER, covenant=True):
    return _Tower(tmp_path, state=SwapState.BOTH_LOCKED, role=role, covenant=covenant).record()


def _decide(record, obs):
    return decide(record=record, observations=obs, policy=_policy(), safety_window_blocks=6)


async def test_both_locked_with_an_unreadable_covenant_watches_while_the_btc_refund_is_immature(tmp_path):
    """Honest twin: the BTC refund leaf has not matured, so by the swap's gate t_rxd is not near."""
    record = _both_locked_record(tmp_path)
    d = _decide(record, _both_locked_obs(btc_funding_confirmations=Confirmations(3)))
    assert d.intent is Intent.WATCH and "has not matured" in d.reason
    d = _decide(record, _both_locked_obs(btc_funding_confirmations=Confirmations(10)))
    assert d.intent is Intent.PAGE_REFUND and d.urgent


async def test_both_locked_with_neither_clock_readable_pages(tmp_path):
    d = _decide(_both_locked_record(tmp_path), _both_locked_obs())
    assert d.intent is Intent.PAGE_REFUND and d.urgent and "could not be read" in d.reason


async def test_both_locked_with_t_btc_in_seconds_pages(tmp_path):
    record = _both_locked_record(tmp_path)
    terms = dataclasses.replace(record.terms, t_btc=t.Timelock(512 * 20, t.TimeUnit.SECONDS))
    d = _decide(dataclasses.replace(record, terms=terms), _both_locked_obs(btc_funding_confirmations=Confirmations(3)))
    assert d.intent is Intent.PAGE_REFUND and d.urgent and "not blocks" in d.reason


async def test_a_maker_with_an_unreadable_covenant_gets_its_covenant_refund_page(tmp_path):
    record = _both_locked_record(tmp_path, role=RecordRole.MAKER)
    d = _decide(record, _both_locked_obs(btc_funding_confirmations=Confirmations(10)))
    assert d.intent is Intent.PAGE_REFUND and d.situation == SITUATION_MAKER_REFUND_LOCK_HEIGHT_UNREAD
    assert not d.urgent


async def test_both_locked_with_no_covenant_pinned_still_watches(tmp_path):
    d = _decide(_both_locked_record(tmp_path, covenant=False), _both_locked_obs())
    assert d.intent is Intent.WATCH and d.reason == "asset lock height not yet observed"

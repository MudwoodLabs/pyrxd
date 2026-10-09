"""#850 (PR 1): a TAKER-role ``mutual_refund`` on an ETH counter leg must not send the covenant refund.

The covenant's CSV refund pays the MAKER and needs no key, so any process can broadcast it once it
matures. ``mutual_refund`` used to "attempt both, always": it refunded the counter leg AND the
covenant, and kept going to the covenant even when the counter refund failed. Run from the
TAKER's process after the maker had claimed the ETH HTLC with ``p``, the counter refund fails
(``AlreadySettled``) and the covenant refund then pays the maker the asset the taker could still
have claimed with ``p`` — the taker loses both legs, and its own tool did it.

Interim scope, by leg × role:

=========  ======  ====================================================================
leg        role    ``mutual_refund`` from BOTH_LOCKED
=========  ======  ====================================================================
ETH        TAKER   counter-leg refund only; record stays BOTH_LOCKED (changed here)
ETH        MAKER   both refunds; MUTUAL_REFUND if both return (unchanged)
ETH        None    both refunds; MUTUAL_REFUND if both return (unchanged)
BTC        any     both refunds; MUTUAL_REFUND if both return (unchanged — see below)
=========  ======  ====================================================================

BTC is deliberately unchanged in this PR. Leaving a taker's BTC record non-terminal would make the
watchtower page the taker's OWN refund as a maker claim on every tick
(``OutspendBtcClaimSource`` treats any spend of the HTLC as a claim), so the BTC half waits for
spender classification (#850 plan, PR 9). The BTC tests below pin the unchanged behaviour on
purpose: when BTC is fixed they must fail and be rewritten.

Every coordinator here is rebuilt from a record that went through ``JsonFileRecordSink`` — a
fresh process, in effect — and the assertions are on the fake legs' calls and on the record read
back from disk, not on a return value.
"""

from __future__ import annotations

import hashlib

import pytest

from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.gravity.watch import Intent, Observations, decide
from pyrxd.security.errors import NetworkError
from pyrxd.security.units import ChainHeight
from tests.test_swap_coordinator import (
    _NOW,
    FakeBtcLeg,
    FakeEthLeg,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _coordinator,
    _eth_coord_full,
    _eth_fund_policy,
    _eth_terms,
    _final,
    _terms,
    generate_secret,
)

_SAFETY = 6


class _SettledEthLeg(FakeEthLeg):
    """The ETH HTLC after the maker claimed it before its timeout: ``refund()`` reverts.

    This is what the real contracts do — ``EthHtlc``/``Erc20Htlc`` set ``settled`` on a claim and
    revert ``refund()`` with ``AlreadySettled`` — and a claim AFTER the timeout reverts with
    ``Expired``, so on ETH the maker's claim necessarily comes before the taker's refund attempt.
    """

    async def refund(self, locator, timeout=None) -> str:
        self.calls.append("refund")
        raise NetworkError("execution reverted: AlreadySettled()")


async def _eth_both_locked_on_disk(tmp_path, *, secret, h):
    """Drive an ETH swap to BOTH_LOCKED through the real coordinator with a real sink."""
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    coord = _eth_coord_full(terms=terms, eth_leg=FakeEthLeg(preimage=secret, verdict=_final()), radiant_leg=rxd)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    coord._persist = sink
    await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms), now_unix_s=_NOW)
    assert sink.load_record().state is SwapState.BOTH_LOCKED
    return sink


def _eth_reloaded(sink, *, eth_leg, radiant_leg, role):
    """A fresh coordinator over the record READ BACK from disk."""
    record = sink.load_record()
    assert record is not None and record.state is SwapState.BOTH_LOCKED
    return SwapCoordinator(
        record=record,
        counter_leg=eth_leg,
        radiant_leg=radiant_leg,
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=_eth_fund_policy(), maker_stall_safety_window_blocks=_SAFETY, role=role),
        persist=sink,
    )


# ---------------------------------------------------------------------------
# ETH, TAKER: the counter leg only
# ---------------------------------------------------------------------------


async def test_taker_eth_mutual_refund_refunds_the_counter_leg_and_never_the_covenant(tmp_path):
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    eth, rxd = FakeEthLeg(preimage=secret, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)

    rec = await coord.mutual_refund()

    assert eth.calls == ["refund"], eth.calls
    assert "refund_asset" not in rxd.calls and not rxd.refunded, "the taker's process sent the maker's covenant refund"
    assert rec.state is SwapState.BOTH_LOCKED, "one of two refunds happened; MUTUAL_REFUND would say both did"
    assert sink.load_record().state is SwapState.BOTH_LOCKED


async def test_the_race_maker_claims_first_and_the_taker_can_still_claim_the_covenant(tmp_path):
    """The interleaving the defect lost money on. The maker claims the ETH with p before the
    timeout; the taker, not having noticed, runs mutual_refund. The counter refund reverts, the
    covenant is NOT refunded, the record is still BOTH_LOCKED, and the existing claim steps then
    take the covenant with the p the maker revealed."""
    secret, h = generate_secret()
    p_bytes = secret.unsafe_raw_bytes()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    eth, rxd = _SettledEthLeg(preimage=p_bytes, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)

    with pytest.raises(NetworkError, match="AlreadySettled"):
        await coord.mutual_refund()
    assert "refund_asset" not in rxd.calls, "the covenant went back to the maker; the taker's claim is gone"
    assert sink.load_record().state is SwapState.BOTH_LOCKED

    # A fresh process again, then the existing claim path.
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    rec = await coord.taker_observed_reveal("0xethclaim")
    assert rec.state is SwapState.SECRET_REVEALED
    rec = await coord.taker_scrape_and_claim_asset("0xethclaim", now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with is not None and hashlib.sha256(rxd.claimed_with).digest() == h
    assert sink.load_record().state is SwapState.COMPLETED


# ---------------------------------------------------------------------------
# ETH, MAKER / None: unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("role", [SwapRole.MAKER, None])
async def test_a_maker_or_single_operator_eth_mutual_refund_still_does_both(tmp_path, role):
    """The honest half: the guard is scoped to the TAKER. A maker's covenant refund is its own
    money, and a single operator (role None) owns both legs. The record here comes from the taker's
    funding flow; mutual_refund reads only its state and locators, not how it got there."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    eth, rxd = FakeEthLeg(preimage=secret, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=role)

    rec = await coord.mutual_refund()

    assert eth.calls == ["refund"] and rxd.calls == ["refund_asset"]
    assert rec.state is SwapState.MUTUAL_REFUND
    assert sink.load_record().state is SwapState.MUTUAL_REFUND


# ---------------------------------------------------------------------------
# BTC, any role: unchanged in this PR (pinned so the BTC fix has to rewrite it)
# ---------------------------------------------------------------------------


async def _btc_taker_after_mutual_refund(tmp_path):
    _p, h = generate_secret()
    terms = _terms(hashlock=h)
    rxd = FakeRadiantLeg()
    coord = _coordinator(terms=terms, btc_leg=FakeBtcLeg(), radiant_leg=rxd, role=SwapRole.TAKER)
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    coord._persist = sink
    await coord.taker_funds_btc(terms)
    await coord.post_asset_lock_revalidate(await rxd.expected_covenant_scriptpubkey(terms))
    record = sink.load_record()
    assert record.state is SwapState.BOTH_LOCKED
    btc, rxd2 = FakeBtcLeg(), FakeRadiantLeg()
    reloaded = SwapCoordinator(
        record=record,
        btc_leg=btc,
        radiant_leg=rxd2,
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=MarginPolicy.estimated(), maker_stall_safety_window_blocks=_SAFETY, role=SwapRole.TAKER
        ),
        persist=sink,
    )
    rec = await reloaded.mutual_refund()
    return sink, rec, btc, rxd2


async def test_btc_taker_mutual_refund_is_unchanged_in_this_release(tmp_path):
    """#850 interim: KNOWN OPEN on BTC. This pins the old behaviour so the BTC fix cannot land
    without someone rewriting it."""
    sink, rec, btc, rxd = await _btc_taker_after_mutual_refund(tmp_path)
    assert btc.refunded and rxd.refunded
    assert rec.state is SwapState.MUTUAL_REFUND
    assert sink.load_record().state is SwapState.MUTUAL_REFUND


# ---------------------------------------------------------------------------
# The watchtower's decision for the taker's record afterwards
# ---------------------------------------------------------------------------


async def test_eth_tower_after_a_taker_only_refund_pages_refund_with_text_that_says_it_repeats(tmp_path):
    """The record stays BOTH_LOCKED and the ETH tower sees no Claimed event for a refund, so past
    the stall window it keeps paging the refund. That page must not send the operator round in a
    loop: it says the page repeats after mutual_refund and to check the refund on-chain."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    coord = _eth_reloaded(
        sink, eth_leg=FakeEthLeg(preimage=secret, verdict=_final()), radiant_leg=FakeRadiantLeg(), role=SwapRole.TAKER
    )
    await coord.mutual_refund()
    record = sink.load_record()
    locked = 1_000
    past_window = ChainHeight(locked + record.terms.t_rxd.value)

    d = decide(
        record=record,
        observations=Observations(
            maker_has_claimed_btc=False, now_rxd_height=past_window, asset_locked_at_height=ChainHeight(locked)
        ),
        policy=_eth_fund_policy(),
        safety_window_blocks=_SAFETY,
    )
    assert d.intent is Intent.PAGE_REFUND
    assert d.recommended_action == "mutual_refund"
    assert "repeats after you have run it" in d.reason
    assert "BOTH_LOCKED" in d.reason

    # And a maker claim on that same record still pages the claim race through the claim path.
    d = decide(
        record=record,
        observations=Observations(
            maker_has_claimed_btc=False,
            now_rxd_height=ChainHeight(locked + 1),
            asset_locked_at_height=ChainHeight(locked),
            eth_claim_detected=True,
            eth_claim_finality=CounterClaimState.FINAL,
        ),
        policy=_eth_fund_policy(),
        safety_window_blocks=_SAFETY,
    )
    assert d.intent is Intent.PAGE_CLAIM, d
    assert d.recommended_action.startswith("taker_observed_reveal"), d.recommended_action


async def test_btc_tower_after_a_taker_mutual_refund_retires_the_record(tmp_path):
    """BTC is unchanged, so the taker's record is terminal and the tower stops watching it — it
    never sees the taker's own refund spend and misreads it as a claim."""
    sink, _rec, _btc, _rxd = await _btc_taker_after_mutual_refund(tmp_path)
    record = sink.load_record()
    d = decide(
        record=record,
        observations=Observations(maker_has_claimed_btc=True, now_rxd_height=ChainHeight(2_000)),
        policy=MarginPolicy.estimated(),
        safety_window_blocks=_SAFETY,
    )
    assert d.intent is Intent.RETIRE

"""#850 (PR 1): a TAKER-role ``mutual_refund`` on an ETH counter leg must not send the covenant refund.

The covenant's CSV refund pays the MAKER and needs no key, so any process can broadcast it once it
matures. ``mutual_refund`` used to "attempt both, always": it refunded the counter leg AND the
covenant, and kept going to the covenant even when the counter refund failed. Run from the
TAKER's process after the maker had claimed the ETH HTLC with ``p``, the counter refund fails
(``AlreadySettled``) and the covenant refund then pays the maker the asset the taker could still
have claimed with ``p`` — the taker loses both legs, and its own tool did it.

Scope, by leg × role, for a counter leg that reads NO disposition (``FakeEthLeg``, a leg written
before 0.27). A leg that reads one is #850 PR 6's, in ``tests/test_mutual_refund_reads_the_chain.py``:

=========  ======  ====================================================================
leg        role    ``mutual_refund`` from BOTH_LOCKED
=========  ======  ====================================================================
ETH        TAKER   counter-leg refund only; record stays BOTH_LOCKED (changed in PR 1)
ETH        MAKER   refused (PR 6)
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

import pytest

from pyrxd.eth_wallet.events import function_selector
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.gravity.watch import Intent, Observations, decide
from pyrxd.security.errors import NetworkError, ValidationError
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


def _preflight_revert() -> ValidationError:
    """What the REAL leg raises for a refund against a settled contract.

    ``EthHtlcContractLeg.refund`` preflights with ``eth_call``; the contract reverts
    ``AlreadySettled()`` and ``EthRpc.preflight`` raises ``ValidationError("tx would revert
    (preflight eth_call): <web3's rendering>")``, which carries the 4-byte selector, not the name.
    The same text comes back whether the maker claimed or the taker's own refund already landed.
    """
    sel = "0x" + function_selector("AlreadySettled()").hex()
    return ValidationError(f"tx would revert (preflight eth_call): ('{sel}', '{sel}')")


class _ChainEthLeg(FakeEthLeg):
    """``FakeEthLeg`` whose refund fails the way the real leg's does: ``settled=True`` models a
    contract already settled (the preflight reverts), ``refund_error`` any other refusal. Like
    ``FakeEthLeg`` it reads no disposition, so the coordinator takes its pre-0.27 path."""

    def __init__(self, *, settled: bool = False, refund_error=None, **kw) -> None:
        super().__init__(**kw)
        self.refund_error = refund_error if refund_error is not None else (_preflight_revert() if settled else None)

    async def refund(self, locator, timeout=None) -> str:
        self.calls.append("refund")
        if self.refund_error is not None:
            raise self.refund_error
        return await super().refund(locator, timeout)


async def _eth_both_locked_on_disk(tmp_path, *, secret, h, role=SwapRole.TAKER):
    """Drive an ETH swap to BOTH_LOCKED through the real coordinator with a real sink, as *role*.

    The record names the role that wrote it (#850 PR 3), and a coordinator of another role refuses
    it, so the reload in each test must run as the role that drove the swap here."""
    terms = _eth_terms(hashlock=h, eth_timeout_unix_s=_NOW + 40000)
    rxd = FakeRadiantLeg()
    coord = _eth_coord_full(
        terms=terms, eth_leg=FakeEthLeg(preimage=secret, verdict=_final()), radiant_leg=rxd, role=role
    )
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


@pytest.mark.parametrize("case", ["not_yet_expired", "settled"])
async def test_a_failed_refund_propagates_the_original_error(tmp_path, case):
    """A leg that reads no disposition gets no explanation since #850 PR 6 (#851's single-endpoint
    one is gone; a leg that reads one is tested in test_mutual_refund_reads_the_chain.py). Its
    refusal propagates unchanged, and nothing else is sent."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    if case == "not_yet_expired":
        original = NetworkError("ETH HTLC refund is not yet mature: matures at unix 1, now 0")
        eth = _ChainEthLeg(refund_error=original, preimage=secret, verdict=_final())
    else:
        eth = _ChainEthLeg(settled=True, preimage=secret, verdict=_final())
        original = eth.refund_error
    rxd = FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    with pytest.raises(type(original)) as raised:
        await coord.mutual_refund()
    assert raised.value is original
    assert "refund_asset" not in rxd.calls
    assert sink.load_record().state is SwapState.BOTH_LOCKED


# ---------------------------------------------------------------------------
# ETH, MAKER / None: unchanged
# ---------------------------------------------------------------------------


async def test_a_single_operator_eth_mutual_refund_without_a_reader_still_does_both(tmp_path):
    """The honest half: the guard is scoped to the TAKER. A single operator (role None) owns both
    legs. The record is driven, and reloaded, as that role. (A maker's ETH mutual_refund is refused
    since #850 PR 6: test_a_makers_eth_mutual_refund_is_refused.)"""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h, role=None)
    eth, rxd = FakeEthLeg(preimage=secret, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=None)

    rec = await coord.mutual_refund()

    assert eth.calls == ["refund"] and rxd.calls == ["refund_asset"]
    assert rec.state is SwapState.MUTUAL_REFUND
    assert sink.load_record().state is SwapState.MUTUAL_REFUND


async def test_a_makers_eth_mutual_refund_is_refused(tmp_path):
    """#850 PR 6: the counter leg is the taker's to refund; the maker's step is
    maybe_refund_asset_on_maker_stall. Refused before anything is read or sent, reader or not."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h, role=SwapRole.MAKER)
    eth, rxd = FakeEthLeg(preimage=secret, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.MAKER)
    with pytest.raises(ValidationError, match="not the maker's step"):
        await coord.mutual_refund()
    assert eth.calls == [] and rxd.calls == []
    assert sink.load_record().state is SwapState.BOTH_LOCKED


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
    the stall window the decision stays PAGE_REFUND. (DedupAlerter delivers that WARN once per
    situation; it repeats only after a tower restart.) The text must not send the operator round in
    a loop: it says the situation does not clear after mutual_refund and to check the refund."""
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
    assert "does not clear after you run it" in d.reason
    # #850 PR 6: a leg that reads its disposition is followed by running it again (Mythos review, F2).
    assert "run it again" in d.reason and "CounterLegDispositionUnknown" in d.reason
    assert "repeats" not in d.reason  # it does not: a WARN is paged once per situation
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

"""``mutual_refund`` on an ETH counter leg acts on what the chain shows (#850 PR 6, design §3.3).

Driven through the real ``SwapCoordinator`` and the real disposition reader over the fake EVM chain,
read through the production ``MultiSourceEthRpc`` (``tests/test_counter_leg_disposition_coordinator.py``
has the harness). Where a scenario crosses a restart, the record goes through ``JsonFileRecordSink``
and a NEW coordinator is built from what was read back.

What changed from #851 (PR 1): the taker's ``mutual_refund`` used to send the counter refund and
explain a failure from ONE endpoint's logs (``_explain_failed_taker_eth_refund``). It now reads the
disposition first, records our refund before sending it and follows it like ``taker_refund_btc``,
and takes MUTUAL_REFUND once the counter leg is refunded at the finalized block. A single operator
(role ``None``) refunds the covenant only after that. A maker is refused.
"""

from __future__ import annotations

import pytest

from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import SwapCoordinator
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.security.errors import (
    CounterLegDispositionUnknown,
    CounterLegRefundNeedsOperator,
    CounterLegSingleSourceAnswer,
    NetworkError,
    NothingToRefund,
    ValidationError,
)
from tests._fake_evm_chain import FakeEvmEndpoint
from tests._fake_evm_chain import _tx_hash as _fake_tx_hash
from tests.test_counter_leg_disposition_coordinator import _count_asset_refunds, _setup, refund_label


def _on_disk(coord, tmp_path):
    """Persist *coord*'s record through a real sink from here on."""
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    coord._persist = sink
    return sink


def _reloaded(coord, sink):
    """A NEW coordinator over the record read back from disk, with the same legs and config."""
    fresh = SwapCoordinator(
        record=sink.load_record(),
        counter_leg=coord.counter_leg,
        radiant_leg=coord.radiant_leg,
        indexer=coord.indexer,
        seen_store=coord.seen_store,
        config=coord.config,
        persist=sink,
    )
    return fresh


# --------------------------------------------------------------------------- TAKER


async def test_a_takers_refund_is_recorded_followed_and_ends_in_mutual_refund_across_a_restart(tmp_path):
    """Scenario 1 for mutual_refund: our refund is RECORDED before it is sent, the record waits at
    BOTH_LOCKED, a restarted process follows it without sending a second one, and the record goes to
    MUTUAL_REFUND only once the chain shows OUR refund at the finalized block. The covenant is never
    touched: it is the maker's."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"head": 95, "finalized": 82})
    sink = _on_disk(coord, tmp_path)
    asset = _count_asset_refunds(coord)

    rec = await coord.mutual_refund()
    ours = _fake_tx_hash(refund_label(1))
    assert rec.state is SwapState.BOTH_LOCKED and leg.refunds == 1
    assert sink.load_record().counter_refund_tx_hash == ours  # durable, before anything mined

    coord = _reloaded(coord, sink)
    chain.refund(88, label=refund_label(1))  # mined above F (82): not final yet
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.BOTH_LOCKED and leg.refunds == 1, "a retry sent a second refund"

    chain.finalized = 90
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and leg.refunds == 1 and asset == []
    stored = sink.load_record()
    assert stored.state is SwapState.MUTUAL_REFUND and stored.counter_disposition.tx_hash == ours
    assert stored.asset_refund_txid is None and coord.radiant_leg.refunded is False


async def test_the_race_maker_claims_first_and_the_taker_claims_the_covenant(tmp_path):
    """The interleaving #851 lost money on, now through the shared reader. The maker claims before
    the timeout; the taker runs mutual_refund. Nothing is sent, the covenant is not refunded, and
    the record goes to SECRET_REVEALED, from where the existing claim step takes the covenant."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    sink = _on_disk(coord, tmp_path)
    claim_tx = chain.claim(70)
    asset = _count_asset_refunds(coord)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.SECRET_REVEALED and rec.counter_claim_tx == claim_tx
    assert leg.refunds == 0 and leg.preflight_refusals == 0 and asset == []

    coord = _reloaded(coord, sink)
    rec = await coord.taker_scrape_and_claim_asset(claim_tx, now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED and sink.load_record().state is SwapState.COMPLETED
    assert coord.radiant_leg.claimed_with == chain.preimage


@pytest.mark.parametrize("served", ["withheld", "forged_refunded"])
async def test_a_hidden_claim_is_never_read_as_refunded(served):
    """The #851 re-review probe through the shared reader. The maker really claimed (before the
    timeout), and the endpoints withhold the claim log, or one forges a Refunded(). Settled at F with
    nothing that verifies is UNKNOWN: the refund the leg refuses is reported as such, the record stays
    BOTH_LOCKED, and nothing says "refunded"."""

    def endpoints(chain):
        if served == "withheld":
            return [FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(3)]
        forged = _fake_tx_hash("forged")
        return [FakeEvmEndpoint(chain, forge_refunded_tx=forged, hide_claimed=True)] + [
            FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(2)
        ]

    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, endpoints=endpoints, chain_kw={"finalized": 90})
    chain.claim(70)
    asset = _count_asset_refunds(coord)
    with pytest.raises(CounterLegDispositionUnknown) as raised:
        await coord.mutual_refund()
    msg = str(raised.value)
    assert "NOT a refund" in msg and "t_rxd" in msg, msg
    assert isinstance(raised.value.__cause__, ValidationError)  # the leg's own refusal, chained
    assert leg.preflight_refusals == 1 and leg.refunds == 0 and asset == []
    assert coord.record.state is SwapState.BOTH_LOCKED and coord.record.counter_disposition is None


async def test_HONEST_a_refund_someone_else_sent_ends_the_takers_record():
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    chain.refund(85)
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and leg.refunds == 0 and coord.radiant_leg.refunded is False


async def test_HONEST_an_unknown_disposition_still_sends_when_the_leg_allows_it():
    """Design §3.3, UNKNOWN: no state change, but the refund still goes out when its own checks pass."""
    coord, _chain, leg = _setup(
        state=SwapState.BOTH_LOCKED,
        endpoints=lambda c: [FakeEvmEndpoint(c, logs_429=True) for _ in range(3)],
        chain_kw={"finalized": 90},
    )
    rec = await coord.mutual_refund()
    assert rec.state is SwapState.BOTH_LOCKED and leg.refunds == 1


async def test_one_endpoint_on_a_value_bearing_chain_sends_nothing(monkeypatch):
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    chain.refund(85)
    leg._rpc = FakeEvmEndpoint(chain)
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    asset = _count_asset_refunds(coord)
    with pytest.raises(CounterLegSingleSourceAnswer):
        await coord.mutual_refund()
    assert leg.refunds == 0 and asset == [] and coord.record.state is SwapState.BOTH_LOCKED


async def test_a_reverted_refund_names_mutual_refund_and_the_flag_sends_one_more():
    coord, _chain, leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    await coord.mutual_refund()
    leg.reverted.add(coord.record.counter_refund_tx_hash)
    with pytest.raises(CounterLegRefundNeedsOperator, match=r"mutual_refund\(resend_reverted_refund=True\)"):
        await coord.mutual_refund()
    assert leg.refunds == 1
    await coord.mutual_refund(resend_reverted_refund=True)
    assert leg.refunds == 2 and coord.record.state is SwapState.BOTH_LOCKED


# --------------------------------------------------------------------------- empty contract (N2)


@pytest.mark.parametrize("role", [SwapRole.TAKER, None])
async def test_an_empty_counter_contract_points_at_the_abandon(role):
    """Design N2: an empty token contract (for example an issuer wipe after the maker verified the
    funding) has no refund. mutual_refund says so, names the gated abandon, and sends nothing."""
    coord, _chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=role, chain_kw={"finalized": 90})

    async def empty(locator, timeout=None, **_kw):
        raise NothingToRefund("nothing to refund: the HTLC holds 0 USDC", contract_address=locator.contract_address)

    leg.refund = empty
    asset = _count_asset_refunds(coord)
    with pytest.raises(NothingToRefund, match="abandon_counter_leg") as raised:
        await coord.mutual_refund()
    assert raised.value.contract_address == coord.record.counterchain_locator.contract_address
    assert asset == [] and coord.record.state is SwapState.BOTH_LOCKED


# --------------------------------------------------------------------------- role None ordering


async def test_a_single_operators_covenant_waits_for_the_counter_leg_to_be_refunded():
    """Design §3.3 step 4: the covenant refund is sent only after the counter leg is REFUNDED at F.
    Neither our refund being sent, nor mined above F, is enough."""
    coord, chain, leg = _setup(state=SwapState.BOTH_LOCKED, role=None, chain_kw={"head": 95, "finalized": 82})
    asset = _count_asset_refunds(coord)
    await coord.mutual_refund()
    chain.refund(88, label=refund_label(1))
    rec = await coord.mutual_refund()
    assert asset == [] and rec.state is SwapState.BOTH_LOCKED and leg.refunds == 1
    chain.finalized = 90
    rec = await coord.mutual_refund()
    assert asset == [1] and rec.state is SwapState.MUTUAL_REFUND


async def test_the_taker_refund_reports_an_unknown_disposition_the_same_way():
    """``taker_refund_btc`` shares the UNKNOWN branch (it used #851's runner-side explanation)."""
    coord, chain, leg = _setup(
        endpoints=lambda c: [FakeEvmEndpoint(c, hide_claimed=True) for _ in range(3)], chain_kw={"finalized": 90}
    )
    chain.claim(70)
    with pytest.raises(CounterLegDispositionUnknown):
        await coord.taker_refund_btc()
    assert coord.record.state is SwapState.BTC_LOCKED and leg.refunds == 0


async def test_a_refusal_under_a_known_disposition_is_not_relabelled():
    """Only UNKNOWN relabels the leg's refusal. With the contract read unsettled and expired, a
    preflight revert (a race) is the leg's own error, unchanged."""
    coord, _chain, leg = _setup(state=SwapState.BOTH_LOCKED, chain_kw={"finalized": 90})
    boom = ValidationError("tx would revert (preflight eth_call): something else")

    async def refuses(*_a, **_k):
        raise boom

    leg.refund = refuses
    with pytest.raises(ValidationError) as raised:
        await coord.mutual_refund()
    assert raised.value is boom


async def test_a_network_failure_under_unknown_is_not_relabelled():
    coord, _chain, leg = _setup(
        state=SwapState.BOTH_LOCKED,
        endpoints=lambda c: [FakeEvmEndpoint(c, logs_429=True) for _ in range(3)],
        chain_kw={"finalized": 90},
    )
    down = NetworkError("eth_sendRawTransaction failed")

    async def fails(*_a, **_k):
        raise down

    leg.refund = fails
    with pytest.raises(NetworkError) as raised:
        await coord.mutual_refund()
    assert raised.value is down

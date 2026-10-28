"""Two LOW findings from a sandbox review of the ETH watchtower (after #850 PR 10).

N-C: the shared counter-leg reader (``pyrxd.eth_wallet.disposition.read_counter_disposition``) verified
every transaction any endpoint's log scan nominated, each by a receipt read and a canonical-hash read
on EVERY endpoint. One endpoint serving N ghost ``Refunded`` logs (no preimage needed) forced about 3N
reads per endpoint per tick. Now an endpoint nominating more than ``MAX_NOMINATIONS_PER_ENDPOINT``
distinct transactions is a failed scan and none of its nominations are used. The other endpoints'
nominations are all verified, so the liar neither hides the real claim or refund nor picks what is
read, and "too many logs" is never "nothing there".

N-D: ``RpcEthChainSource.claim_receipt_opens_h`` let one endpoint's malformed receipt field escape as
an untyped ``ValueError``. ``ChainObserver`` catches ``NetworkError`` only, so ``observe()`` raised
and the page was the generic reconcile error instead of the claim race. It is now that endpoint's
typed failure.

Both drive the production ``RpcEthChainSource`` / ``ChainObserver`` / ``decide`` / ``Reconciler`` over
``tests._fake_evm_chain``, with honest twins.
"""

from __future__ import annotations

import pytest

from pyrxd.eth_wallet.disposition import MAX_NOMINATIONS_PER_ENDPOINT, DispositionKind
from pyrxd.eth_wallet.events import CLAIMED_TOPIC0, REFUNDED_TOPIC0
from pyrxd.eth_wallet.htlc_leg import _receipt_facts
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.swap_state import SwapState
from pyrxd.gravity.watch.decide import Intent
from pyrxd.gravity.watch.eth_adapters import RpcEthChainSource
from pyrxd.gravity.watch.reconciler import SITUATION_RECONCILE_ERROR
from pyrxd.security.errors import NetworkError
from tests._fake_evm_chain import CONTRACT, FakeEvmEndpoint
from tests.test_counter_leg_disposition_coordinator import _setup as _coordinator
from tests.test_watch_eth_disposition_table import CLAIM_BLOCK, REFUND_BLOCK, _EthTower, decide_mod


def _ghosts(n: int, *, kind: str, preimage: bytes) -> tuple[dict, ...]:
    """``n`` logs on ``n`` distinct transactions no chain holds. A ``Refunded`` ghost needs nothing; a
    ``Claimed`` ghost carries ``p``, public once the real claim mined."""
    topic, data = (REFUNDED_TOPIC0, "0x") if kind == "refunded" else (CLAIMED_TOPIC0, "0x" + preimage.hex())
    return tuple(
        {
            "address": CONTRACT,
            "topics": [topic],
            "data": data,
            "transactionHash": "0x" + (i + 1).to_bytes(32, "big").hex(),
            "blockNumber": 41 + i % 20,
        }
        for i in range(n)
    )


def _count_receipt_reads(w: _EthTower) -> list[int]:
    calls = [0]
    for endpoint in w.endpoints:
        real = endpoint.get_transaction_receipt

        async def counted(tx, _real=real):
            calls[0] += 1
            return await _real(tx)

        endpoint.get_transaction_receipt = counted
    return calls


def _settle(w: _EthTower, real: str) -> str:
    return w.chain.claim(CLAIM_BLOCK) if real == "claim" else w.chain.refund(REFUND_BLOCK)


async def _honest_decision(tmp_path, real: str):
    honest = _EthTower(tmp_path / "honest")
    _settle(honest, real)
    return await honest.decide()


# --------------------------------------------------------------------------- N-C: over the cap


@pytest.mark.parametrize("liar", [0, 1, 2])
@pytest.mark.parametrize("real", ["claim", "refund"])
@pytest.mark.parametrize("ghost_kind", ["refunded", "claimed"])
@pytest.mark.parametrize("hide", [False, True])
async def test_an_endpoint_over_the_cap_is_dropped_and_the_real_settlement_still_reads(
    tmp_path, liar, real, ghost_kind, hide
):
    """A liar at any index serves one more ghost than the cap, hiding the real log or not. Its scan is
    recorded failed and none of its nominations are verified; the honest endpoints still nominate the
    real claim or refund, which verifies, and the tower decides exactly as it does with no liar."""
    w = _EthTower(tmp_path / "w")
    tx = _settle(w, real)
    w.endpoints[liar].extra_logs = _ghosts(MAX_NOMINATIONS_PER_ENDPOINT + 1, kind=ghost_kind, preimage=w.chain.preimage)
    w.endpoints[liar].hide_all_logs = hide
    d = await w.observer._eth.counter_disposition(w.chain.locator())
    liar_key = w.endpoints[liar].source_key
    assert liar_key in d.logs_failed and liar_key not in d.logs_answered
    assert "nominated" in d.logs_failed[liar_key]
    assert d.kind is (DispositionKind.CLAIMED if real == "claim" else DispositionKind.REFUNDED)
    assert d.evidence is not None and d.evidence.tx_hash == tx
    obs = await w.observe()
    assert obs.eth_disposition is d.kind and obs.eth_disposition_tx == tx
    if real == "claim":
        assert obs.eth_claim_finality is CounterClaimState.FINAL
    got = await w.decide()
    if ghost_kind == "claimed" and real == "refund":
        # Claimed ghosts beside a verified refund. Under the cap they join ``claims_seen`` and the tower
        # pages the covenant claim (p is public); over it they are dropped from the reader, and the
        # detection scan, which still sees them, pages "investigate". Either way a page, never a WATCH
        # or a quiet reconcile: one endpoint may add a page, never remove one.
        assert got.intent is Intent.PAGE_SQUEEZED, got
        assert got.situation == decide_mod.SITUATION_ETH_DISCOVERY_DISAGREES, got
        return
    honest = await _honest_decision(tmp_path, real)
    assert (got.intent, got.situation) == (honest.intent, honest.situation)


@pytest.mark.parametrize("liar", [0, 2])
async def test_thousands_of_ghost_logs_cost_a_bounded_number_of_reads(tmp_path, liar):
    """The reviewer's measurement was 15,033 calls for 5000 ghost logs. With the cap, the receipt reads
    of one observe() do not grow with the ghosts: they match a tower with no liar, give or take the
    liar's own scan."""
    w = _EthTower(tmp_path / "w")
    _settle(w, "claim")
    w.endpoints[liar].extra_logs = _ghosts(5000, kind="refunded", preimage=w.chain.preimage)
    calls = _count_receipt_reads(w)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.CLAIMED
    honest = _EthTower(tmp_path / "honest")
    _settle(honest, "claim")
    honest_calls = _count_receipt_reads(honest)
    await honest.observe()
    assert honest_calls[0] > 0
    assert calls[0] == honest_calls[0], (calls[0], honest_calls[0])


async def test_every_endpoint_over_the_cap_is_unknown_never_nothing_there(tmp_path):
    """Too many logs is never "no logs". With every endpoint over the cap the scan has no answer, so
    the read is UNKNOWN, while the honest twin (the same unsettled, expired contract) reads F_EXPIRED."""
    honest = _EthTower(tmp_path / "honest")
    assert (await honest.observe()).eth_disposition is DispositionKind.F_EXPIRED
    w = _EthTower(tmp_path / "w")
    for endpoint in w.endpoints:
        endpoint.extra_logs = _ghosts(MAX_NOMINATIONS_PER_ENDPOINT + 1, kind="refunded", preimage=w.chain.preimage)
    obs = await w.observe()
    assert obs.eth_disposition is DispositionKind.UNKNOWN
    assert "no endpoint answered the log scan" in obs.eth_disposition_reason
    d = await w.decide()
    assert d.intent is not Intent.WATCH, d


async def test_a_single_endpoint_over_the_cap_is_unknown(tmp_path):
    """One endpoint: dropping it leaves no scan, so UNKNOWN; its honest twin reads F_EXPIRED."""
    honest = _EthTower(tmp_path / "honest", endpoints=1)
    assert (await honest.observe()).eth_disposition is DispositionKind.F_EXPIRED
    w = _EthTower(tmp_path / "w", endpoints=1)
    w.endpoints[0].extra_logs = _ghosts(MAX_NOMINATIONS_PER_ENDPOINT + 1, kind="refunded", preimage=w.chain.preimage)
    assert (await w.observe()).eth_disposition is DispositionKind.UNKNOWN


@pytest.mark.parametrize("kind", ["odd_claimed", "foreign"])
async def test_logs_that_nominate_nothing_do_not_count_toward_the_cap(tmp_path, kind):
    """The cap counts what ``_nominates`` would verify, nothing else: a sole endpoint serving more than the
    cap of ``Claimed`` logs whose data does not open H, or of logs from another contract, still answers,
    so its F_EXPIRED stands (counting every log would drop it and read UNKNOWN)."""
    w = _EthTower(tmp_path, endpoints=1)
    ghosts = _ghosts(MAX_NOMINATIONS_PER_ENDPOINT + 1, kind="claimed", preimage=b"\x5b" * 32)
    if kind == "foreign":
        ghosts = tuple(
            {**g, "address": "0x" + "77" * 20}
            for g in _ghosts(MAX_NOMINATIONS_PER_ENDPOINT + 1, kind="refunded", preimage=b"")
        )
    w.endpoints[0].extra_logs = ghosts
    assert (await w.observe()).eth_disposition is DispositionKind.F_EXPIRED


# --------------------------------------------------------------------------- N-C: at the cap (honest twin)


@pytest.mark.parametrize("liar", [0, 1, 2])
@pytest.mark.parametrize("real", ["claim", "refund"])
async def test_an_endpoint_at_the_cap_keeps_its_nominations(tmp_path, liar, real):
    """At the cap an endpoint still answers: each ghost is verified (and found unmined), the real
    settlement verifies, and the tower decides as it does with no liar. The cap refuses nothing an
    honest endpoint can serve (an honest contract emits at most one Claimed or Refunded log)."""
    w = _EthTower(tmp_path / "w")
    tx = _settle(w, real)
    w.endpoints[liar].extra_logs = _ghosts(MAX_NOMINATIONS_PER_ENDPOINT - 1, kind="refunded", preimage=w.chain.preimage)
    d = await w.observer._eth.counter_disposition(w.chain.locator())
    assert w.endpoints[liar].source_key in d.logs_answered and not d.logs_failed
    assert d.evidence is not None and d.evidence.tx_hash == tx
    got, want = await w.decide(), await _honest_decision(tmp_path, real)
    assert (got.intent, got.situation) == (want.intent, want.situation)


async def test_an_honest_tower_answers_every_endpoint(tmp_path):
    w = _EthTower(tmp_path)
    tx = _settle(w, "claim")
    d = await w.observer._eth.counter_disposition(w.chain.locator())
    assert d.kind is DispositionKind.CLAIMED and d.evidence.tx_hash == tx
    assert len(d.logs_answered) == 3 and not d.logs_failed


# --------------------------------------------------------------------------- N-D: a malformed receipt

_MALFORMED = [
    {"blockNumber": "0xzz"},
    {"status": "yes"},
    {"status": {"nested": 1}},
    {"logs": ["not a log"]},
    {"logs": [{"address": CONTRACT, "topics": 7, "data": "0x"}]},
    {"status": float("inf")},
    {"blockNumber": float("inf")},
    {"blockHash": "zz"},
]


def _malform(endpoint, tx: str, change: dict) -> None:
    real = endpoint.get_transaction_receipt

    async def malformed(h):
        r = await real(h)
        return {**r, **change} if (h == tx and r is not None) else r

    endpoint.get_transaction_receipt = malformed


@pytest.mark.parametrize("liar", [0, 1, 2])
@pytest.mark.parametrize("change", _MALFORMED)
async def test_one_endpoints_malformed_receipt_pages_the_claim_race_not_a_reconcile_error(tmp_path, liar, change):
    """The claim is mined, not yet final, and one endpoint returns its receipt malformed. The reader
    drops that endpoint (two of three still agree), the claim is seen unverified, and the observer
    checks it with ``claim_receipt_opens_h``. That raised an untyped error out of observe(); it is now
    the endpoint's NetworkError, so the claim race pages fail-closed, through the production reconciler."""
    w = _EthTower(tmp_path)
    w.chain.finalized = CLAIM_BLOCK - 5
    claim = w.chain.claim(CLAIM_BLOCK)
    _malform(w.endpoints[liar], claim, change)
    with pytest.raises(NetworkError):
        await w.observer._eth.claim_receipt_opens_h(w.chain.locator(), claim)
    obs = await w.observe()
    assert obs.eth_claim_detected is True and obs.eth_claim_finality is None
    d = await w.decide()
    assert d.intent is Intent.PAGE_SQUEEZED and d.situation == decide_mod.SITUATION_CLAIM_RACE_UNASSESSABLE
    await w.reconciler().tick()
    assert [(s, p.situation) for s, p in w.pages.got] == [("e1", decide_mod.SITUATION_CLAIM_RACE_UNASSESSABLE)]
    assert all(p.situation != SITUATION_RECONCILE_ERROR for _s, p in w.pages.got)


@pytest.mark.parametrize("change", _MALFORMED)
def test_the_receipt_normaliser_types_a_malformed_field(change):
    """The root of N-D: ``_receipt_facts`` (and ``_int_or_none`` under it) raise NetworkError on a
    malformed field, as ``_b`` already did, so every caller that catches NetworkError sees it. The
    unchanged receipt normalises."""
    good = {"status": "0x1", "blockNumber": "0x28", "blockHash": "0x" + "ab" * 32, "logs": []}
    assert _receipt_facts(good) == (1, bytes.fromhex("ab" * 32), 40, ())
    with pytest.raises(NetworkError):
        _receipt_facts({**good, **change})


async def test_the_honest_twin_of_a_malformed_receipt_waits_for_finality(tmp_path):
    w = _EthTower(tmp_path)
    w.chain.finalized = CLAIM_BLOCK - 5
    claim = w.chain.claim(CLAIM_BLOCK)
    assert await w.observer._eth.claim_receipt_opens_h(w.chain.locator(), claim) is True
    obs = await w.observe()
    assert obs.eth_claim_finality is CounterClaimState.NOT_YET_FINAL_LIVE
    assert (await w.decide()).intent is Intent.WATCH


@pytest.mark.parametrize(
    "change",
    [
        {"blockNumber": "0xzz"},
        {"status": "yes"},
        {"blockNumber": None},
        {"status": float("inf")},
        {"blockNumber": float("inf")},
        {"blockHash": "zz"},
    ],
)
async def test_a_sole_endpoints_malformed_receipt_is_a_typed_verdict_failure(tmp_path, change):
    """``claim_finality_verdict`` over one endpoint (no quorum to catch the field) raises NetworkError,
    which the observer reads as finality un-assessable; the unchanged receipt reads a verdict."""
    w = _EthTower(tmp_path, endpoints=1)
    claim = w.chain.claim(CLAIM_BLOCK)
    source = RpcEthChainSource(w.endpoints[0])
    assert (await source.claim_finality_verdict(claim)).state is CounterClaimState.FINAL
    _malform(w.endpoints[0], claim, change)
    with pytest.raises(NetworkError):
        await source.claim_finality_verdict(claim)


# --------------------------------------------------------------------------- N-C: the coordinator's read


def _with_ghosts(liars: tuple[int, ...], *, hide: bool):
    def build(chain):
        return [
            FakeEvmEndpoint(
                chain,
                hide_all_logs=hide and i in liars,
                extra_logs=_ghosts(MAX_NOMINATIONS_PER_ENDPOINT + 1, kind="refunded", preimage=chain.preimage)
                if i in liars
                else (),
            )
            for i in range(3)
        ]

    return build


@pytest.mark.parametrize("liar", [0, 1, 2])
async def test_the_coordinator_reads_a_claim_past_one_endpoints_ghosts(liar):
    """The coordinator asks the same reader: one endpoint over the cap, hiding the real claim, still
    leaves the record moved by the verified claim, as with every endpoint honest."""
    coord, chain, _leg = _coordinator(endpoints=_with_ghosts((liar,), hide=True), chain_kw={"finalized": 90})
    tx = chain.claim(70)
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.SECRET_REVEALED and rec.counter_claim_tx == tx


async def test_the_coordinator_moves_nothing_when_every_endpoint_is_over_the_cap():
    """Every endpoint serves the real refund AND more ghosts than the cap: none of them answered the
    scan, so the read is UNKNOWN and the record does not move (the cap never reads as "no logs", and
    a log only over-cap endpoints served is not acted on)."""
    coord, chain, _leg = _coordinator(endpoints=_with_ghosts((0, 1, 2), hide=False), chain_kw={"finalized": 90})
    chain.refund(85)
    with pytest.raises(NetworkError, match="unknown"):
        await coord.reconcile_counter_leg()
    assert coord.record.state is SwapState.BTC_LOCKED and coord.persisted == []

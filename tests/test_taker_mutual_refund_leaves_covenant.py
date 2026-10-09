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

from pyrxd.eth_wallet.events import function_selector
from pyrxd.gravity.finality import CounterClaimState
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import SwapRole, SwapState
from pyrxd.gravity.watch import Intent, Observations, decide
from pyrxd.security.errors import (
    CounterLegClaimedByCounterparty,
    CounterLegSettledUnverified,
    NetworkError,
    ValidationError,
)
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


_CLAIM_TX = "0xethclaim"


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
    """``FakeEthLeg`` plus the two chain reads the shipped ``EthLeg`` exposes for explaining a
    failed refund (``observed_claim_tx`` from the contract logs, ``is_settled`` from storage).

    ``claimed=True`` models the maker having claimed before the timeout (``EthHtlc``/``Erc20Htlc``
    reject a claim at or after it, so on ETH the claim necessarily precedes the refund attempt):
    the contract is settled, the logs carry the claim, and ``refund()`` raises the preflight error.
    """

    def __init__(self, *, claimed: bool = False, settled: bool = False, refund_error=None, **kw) -> None:
        super().__init__(**kw)
        self.claim_tx = _CLAIM_TX if claimed else None
        self.settled = settled or claimed
        self.refund_error = (
            refund_error if refund_error is not None else (_preflight_revert() if self.settled else None)
        )

    async def refund(self, locator, timeout=None) -> str:
        self.calls.append("refund")
        if self.refund_error is not None:
            raise self.refund_error
        return await super().refund(locator, timeout)

    async def observed_claim_tx(self, locator):
        self.calls.append("observed_claim_tx")
        return self.claim_tx

    async def is_settled(self, locator) -> bool:
        self.calls.append("is_settled")
        return self.settled


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
    eth, rxd = _ChainEthLeg(claimed=True, preimage=p_bytes, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)

    with pytest.raises(CounterLegClaimedByCounterparty) as raised:
        await coord.mutual_refund()
    assert raised.value.tx_hash == _CLAIM_TX
    assert "refund_asset" not in rxd.calls, "the covenant went back to the maker; the taker's claim is gone"
    assert sink.load_record().state is SwapState.BOTH_LOCKED

    # A fresh process again, then the existing claim path, with the tx the error named.
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    rec = await coord.taker_observed_reveal(raised.value.tx_hash)
    assert rec.state is SwapState.SECRET_REVEALED
    rec = await coord.taker_scrape_and_claim_asset("0xethclaim", now_rxd_height=1000, asset_locked_at_height=1000)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with is not None and hashlib.sha256(rxd.claimed_with).digest() == h
    assert sink.load_record().state is SwapState.COMPLETED


async def test_the_race_past_t_rxd_goes_through_asset_vulnerable_to_completed(tmp_path):
    """The same race, with the taker noticing only after the covenant's CSV refund has opened (the
    maker has not sent it yet). The gate squeezes to ASSET_VULNERABLE and the deliberate
    winner-take-all claim still takes the covenant — reachable only because the record was left
    BOTH_LOCKED and the covenant untouched."""
    secret, h = generate_secret()
    p_bytes = secret.unsafe_raw_bytes()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    eth, rxd = _ChainEthLeg(claimed=True, preimage=p_bytes, verdict=_final()), FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    with pytest.raises(CounterLegClaimedByCounterparty):
        await coord.mutual_refund()

    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    await coord.taker_observed_reveal(_CLAIM_TX)
    locked = 1_000
    past_t_rxd = locked + coord.record.terms.t_rxd.value
    rec = await coord.taker_scrape_and_claim_asset(_CLAIM_TX, now_rxd_height=past_t_rxd, asset_locked_at_height=locked)
    assert rec.state is SwapState.ASSET_VULNERABLE, rec.state
    rec = await coord.taker_claim_asset_from_vulnerable(_CLAIM_TX)
    assert rec.state is SwapState.COMPLETED
    assert rxd.claimed_with is not None and hashlib.sha256(rxd.claimed_with).digest() == h
    assert "refund_asset" not in rxd.calls
    assert sink.load_record().state is SwapState.COMPLETED


def _assert_settled_unverified_never_says_refunded(exc: CounterLegSettledUnverified, contract: str) -> None:
    """The (b) message must not conclude "refunded" / "nothing more is needed" — that conclusion is
    what made the taker stop while the maker kept both legs (#851 re-review probe)."""
    msg = str(exc)
    assert "ALREADY SETTLED" in msg and "NO VERIFIED CLAIM" in msg, msg
    assert "does not mean it was refunded" in msg, msg
    assert "it was REFUNDED" not in msg and "Nothing more is needed on the ETH side" not in msg, msg
    assert contract in msg and "t_rxd" in msg and "maker_claim.json" in msg and "--phase claim" in msg, msg
    assert exc.contract_address == contract


@pytest.mark.parametrize(
    "case",
    ["no_claim_log", "claim_does_not_verify", "log_read_fails"],
)
async def test_settled_without_a_verified_claim_is_never_concluded_refunded(tmp_path, case):
    """(b): the contract is settled and no claim VERIFIES. Every one of these is also what a real
    maker claim looks like through a log source that is incomplete or lying, so the error tells the
    operator to check elsewhere and how to claim, and never says "refunded"."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    if case == "no_claim_log":
        eth = _ChainEthLeg(settled=True, preimage=secret, verdict=_final())
    elif case == "claim_does_not_verify":
        eth = _ChainEthLeg(claimed=True, preimage=secret, verdict=_final(), provenance_ok=False)
    else:
        eth = _ChainEthLeg(claimed=True, preimage=secret, verdict=_final())

        async def _boom(locator):
            raise NetworkError("eth_getLogs: range too large")

        eth.observed_claim_tx = _boom
    rxd = FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    with pytest.raises(CounterLegSettledUnverified) as raised:
        await coord.mutual_refund()
    assert not isinstance(raised.value, CounterLegClaimedByCounterparty)
    assert isinstance(raised.value.__cause__, ValidationError)  # the original preflight error is chained
    _assert_settled_unverified_never_says_refunded(raised.value, coord.record.counterchain_locator.contract_address)
    assert "refund_asset" not in rxd.calls
    assert sink.load_record().state is SwapState.BOTH_LOCKED


@pytest.mark.parametrize("case", ["not_yet_expired", "settled_flag_unreadable"])
async def test_any_other_failure_propagates_the_original_error(tmp_path, case):
    """(c): not settled, or the settled flag cannot be read — the original error, unchanged."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    if case == "not_yet_expired":
        original = NetworkError("ETH HTLC refund is not yet mature: matures at unix 1, now 0")
        eth = _ChainEthLeg(refund_error=original, preimage=secret, verdict=_final())
    else:
        original = _preflight_revert()
        eth = _ChainEthLeg(refund_error=original, preimage=secret, verdict=_final())

        async def _boom(locator):
            raise NetworkError("eth_getStorageAt failed")

        eth.is_settled = _boom
    rxd = FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=eth, radiant_leg=rxd, role=SwapRole.TAKER)
    with pytest.raises(type(original)) as raised:
        await coord.mutual_refund()
    assert raised.value is original
    assert "refund_asset" not in rxd.calls
    assert sink.load_record().state is SwapState.BOTH_LOCKED


# ---------------------------------------------------------------------------
# The same, through the SHIPPED EthLeg over EthHtlcContractLeg (only the RPC is faked)
# ---------------------------------------------------------------------------

_ART = {
    "abi": [],
    "bytecode": "0x00",
    "runtime_bytecode": "0x" + "00" * 32,
    "immutableReferences": {"1": [{"start": 0, "length": 32}]},
    "immutable_names": {"1": "hashlock"},
}


class _ChainRpc:
    """An Ethereum RPC as the real leg reads it: deploy tx, contract logs, receipts, and storage.

    ``claim_p`` set → the contract was claimed with it (a ``Claimed(p)`` log, a claim tx whose
    calldata carries p, settled). ``claim_p`` None and ``refunded`` → only ``Refunded()``, settled.
    ``serve_logs`` overrides what the (single) endpoint's ``eth_getLogs`` returns, to model one that
    withholds the claim (``[]``) or forges a refund, while storage still says what the chain says.
    """

    def __init__(
        self,
        *,
        contract: str,
        deploy_tx: str,
        claim_p: bytes | None,
        refunded: bool = False,
        serve_logs: list | None = None,
    ):
        from types import SimpleNamespace

        from pyrxd.eth_wallet.events import CLAIMED_TOPIC0, REFUNDED_TOPIC0

        self._contract, self._deploy_tx = contract, deploy_tx
        self._claim_p = claim_p
        if claim_p is not None:
            self._logs = [
                {
                    "address": contract,
                    "topics": [CLAIMED_TOPIC0],
                    "data": "0x" + claim_p.hex(),
                    "transactionHash": _REAL_CLAIM_TX,
                }
            ]
        elif refunded:
            self._logs = [
                {"address": contract, "topics": [REFUNDED_TOPIC0], "data": "0x", "transactionHash": "0x" + "77" * 32}
            ]
        else:
            self._logs = []
        settled = claim_p is not None or refunded
        if serve_logs is not None:
            self._logs = serve_logs

        async def _get_storage_at(addr, slot, block_identifier=None):
            return (b"\x00" * 31 + b"\x01") if settled else b"\x00" * 32

        self.w3 = SimpleNamespace(eth=SimpleNamespace(get_storage_at=_get_storage_at))

    async def get_transaction(self, tx_hash):
        if tx_hash == self._deploy_tx:
            return {"blockNumber": 5}
        sel = function_selector("claim(bytes32)").hex()
        return {"to": self._contract, "input": "0x" + sel + (self._claim_p or b"").hex(), "blockNumber": 9}

    async def get_logs(self, *, address, topics=None, from_block="earliest", to_block="latest"):
        assert address == self._contract
        return list(self._logs)

    async def wait_receipt(self, tx_hash):
        return {"status": 1, "blockNumber": 9, "logs": [lg for lg in self._logs if lg["transactionHash"] == tx_hash]}


_REAL_CLAIM_TX = "0x" + "88" * 32


def _real_eth_leg(rpc):
    from pyrxd.eth_wallet.htlc_leg import EthHtlcContractLeg
    from pyrxd.gravity.eth_leg import EthLeg
    from pyrxd.security.secrets import PrivateKeyMaterial

    contract_leg = EthHtlcContractLeg(rpc=rpc, signing_key=PrivateKeyMaterial.generate(), chain_id=31337, artifact=_ART)

    async def _refund_reverts(locator):
        # Everything before the preflight needs a live node; the preflight's failure is what matters.
        raise _preflight_revert()

    contract_leg.refund = _refund_reverts
    return EthLeg(
        contract_leg=contract_leg,
        network="regtest",  # an audit-cleared tag: not value-bearing, so no durable seen-store needed
        claim_to="0x" + "11" * 20,
        refund_to="0x" + "22" * 20,
        eth_timeout_unix_s=_NOW + 40000,
    )


async def test_the_shipped_eth_leg_turns_a_maker_claim_into_the_claim_error(tmp_path):
    secret, h = generate_secret()
    p_bytes = secret.unsafe_raw_bytes()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    loc = sink.load_record().counterchain_locator
    rpc = _ChainRpc(contract=loc.contract_address, deploy_tx=loc.deploy_tx_hash, claim_p=p_bytes)
    rxd = FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=_real_eth_leg(rpc), radiant_leg=rxd, role=SwapRole.TAKER)
    with pytest.raises(CounterLegClaimedByCounterparty) as raised:
        await coord.mutual_refund()
    assert raised.value.tx_hash == _REAL_CLAIM_TX
    assert "taker_observed_reveal" in str(raised.value) and "t_rxd" in str(raised.value)
    assert "refund_asset" not in rxd.calls


def _forged_refunded_log(contract: str) -> dict:
    from pyrxd.eth_wallet.events import REFUNDED_TOPIC0

    return {"address": contract, "topics": [REFUNDED_TOPIC0], "data": "0x", "transactionHash": "0x" + "77" * 32}


@pytest.mark.parametrize("served", ["withheld", "forged_refunded", "honest_refund"])
async def test_the_shipped_eth_leg_never_concludes_refunded_from_one_endpoints_logs(tmp_path, served):
    """The #851 re-review probe, as a regression test. A REAL maker claim (settled on chain), seen
    through one endpoint that withholds the claim log or serves a forged ``Refunded()`` — and, for
    contrast, a contract genuinely refunded. From one endpoint's logs the three are the same
    answer, so all three raise CounterLegSettledUnverified; none may conclude "refunded"."""
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    loc = sink.load_record().counterchain_locator
    if served == "honest_refund":
        rpc = _ChainRpc(contract=loc.contract_address, deploy_tx=loc.deploy_tx_hash, claim_p=None, refunded=True)
    else:
        logs = [] if served == "withheld" else [_forged_refunded_log(loc.contract_address)]
        rpc = _ChainRpc(
            contract=loc.contract_address,
            deploy_tx=loc.deploy_tx_hash,
            claim_p=secret.unsafe_raw_bytes(),
            serve_logs=logs,
        )
    rxd = FakeRadiantLeg()
    coord = _eth_reloaded(sink, eth_leg=_real_eth_leg(rpc), radiant_leg=rxd, role=SwapRole.TAKER)
    with pytest.raises(CounterLegSettledUnverified) as raised:
        await coord.mutual_refund()
    _assert_settled_unverified_never_says_refunded(raised.value, loc.contract_address)
    assert "refund_asset" not in rxd.calls
    assert sink.load_record().state is SwapState.BOTH_LOCKED


async def test_the_shipped_eth_leg_leaves_an_unexplained_failure_alone(tmp_path):
    secret, h = generate_secret()
    sink = await _eth_both_locked_on_disk(tmp_path, secret=secret, h=h)
    loc = sink.load_record().counterchain_locator
    rpc = _ChainRpc(contract=loc.contract_address, deploy_tx=loc.deploy_tx_hash, claim_p=None)
    coord = _eth_reloaded(sink, eth_leg=_real_eth_leg(rpc), radiant_leg=FakeRadiantLeg(), role=SwapRole.TAKER)
    with pytest.raises(ValidationError, match="tx would revert") as raised:
        await coord.mutual_refund()
    assert not isinstance(raised.value, (CounterLegClaimedByCounterparty, CounterLegSettledUnverified))


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

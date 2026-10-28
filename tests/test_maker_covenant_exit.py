"""A maker's record ends on what spent its own covenant (#850 PR 11, design §8, D10).

Driven through the real ``SwapCoordinator`` and the real ``RadiantCovenantLeg`` / ``RadiantChainIO``
over a fake Radiant chain served by ElectrumX-shaped sources (``tests/_fake_radiant_chain.py``). The
refund and claim transactions are the production builders' own bytes; the read classifies them from
those bytes.

Before this PR a maker's record had no exit from NEGOTIATED (the taker never funded), BTC_LOCKED or
PARAMS_MISMATCH (the maker's own revalidation failed): the runner refunded the covenant through the
leg and left the record where it was. ``maker_refund_covenant`` sends the CSV refund and, once the
spend reads buried, ends the record at ABORTED (``covenant_refunded``). ``reconcile_covenant``
records a refund made elsewhere, BOTH_LOCKED included (MUTUAL_REFUND).
"""

from __future__ import annotations

import dataclasses
import hashlib
import os

import coincurve
import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity import swap_coordinator as sc
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.htlc_spend import FeeInput, build_htlc_claim_tx, build_htlc_refund_tx
from pyrxd.gravity.radiant_leg import MAX_COVENANT_HISTORY, CovenantSpendKind, RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import (
    AbortReason,
    CounterDispositionRecord,
    NegotiatedTerms,
    RecordRole,
    SwapRecord,
    SwapRole,
    SwapState,
)
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20
from tests._fake_radiant_chain import FakeRadiantChain, FakeRadiantSource, payment
from tests.test_swap_coordinator import FakeBtcLeg, FakeIndexer, FakeSeenStore

T_RXD = 6
AMOUNT = 100_000


def _xonly() -> bytes:
    return coincurve.PublicKeyXOnly.from_secret(os.urandom(32)).format()


def _pkh() -> bytes:
    return bytes(Hex20(PrivateKey(os.urandom(32)).public_key().hash160()))


class _FeeSource:
    """A fresh generated key per fee input, so two refunds of one covenant are distinct bytes."""

    def next_fee_input(self) -> FeeInput:
        k = PrivateKey(os.urandom(32))
        pkh = bytes(Hex20(k.public_key().hash160()))
        return FeeInput(
            txid=os.urandom(32).hex(),
            vout=0,
            value=10_000_000,
            scriptpubkey=b"\x76\xa9\x14" + pkh + b"\x88\xac",
            wif=k.wif(),
        )


class _Swap:
    """One swap: its preimage, covenant, terms, chain and sources."""

    def __init__(self, *, sources: int = 3, age: int = T_RXD + 2) -> None:
        self.p = os.urandom(32)
        self.taker_pkh, self.maker_pkh = _pkh(), _pkh()
        self.cov = build_htlc_covenant_rxd(
            amount=AMOUNT,
            taker_pkh=self.taker_pkh,
            maker_pkh=self.maker_pkh,
            hashlock=hashlib.sha256(self.p).digest(),
            refund_csv=T_RXD,
        )
        self.terms = NegotiatedTerms(
            hashlock=hashlib.sha256(self.p).digest(),
            btc_sats=100_000,
            radiant_amount=AMOUNT,
            t_btc=t.Timelock(T_RXD // 2, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(T_RXD, t.TimeUnit.BLOCKS),
            asset_variant="rxd",
            genesis_ref=b"",
            taker_dest_hash=self.cov.expected_taker_hash,
            maker_dest_hash=self.cov.expected_maker_hash,
            btc_claim_pubkey_xonly=_xonly(),
            btc_refund_pubkey_xonly=_xonly(),
        )
        self.chain = FakeRadiantChain(tip=1_000)
        self.funding_txid = self.chain.add(payment(self.cov.funded_spk, AMOUNT), height=self.chain.tip - age + 1)
        self.outpoint = f"{self.funding_txid}:0"
        self.sources = [FakeRadiantSource(self.chain, f"https://rxd{i}.example-{i}.org") for i in range(sources)]

    def leg(self, *, sources=None, min_confirmations: int = 1, network: str = "bcrt") -> RadiantCovenantLeg:
        srcs = list(sources if sources is not None else self.sources)
        return RadiantCovenantLeg(
            network=network,
            taker_pkh=self.taker_pkh,
            maker_pkh=self.maker_pkh,
            chain_io=RadiantChainIO(srcs[0], depth_sources=tuple(srcs[1:])),
            fee_source=_FeeSource(),
            min_confirmations=min_confirmations,
        )

    def refund_tx(self) -> bytes:
        return build_htlc_refund_tx(
            covenant=self.cov, covenant_outpoint=self.outpoint, carrier_value=AMOUNT, fee=_FeeSource().next_fee_input()
        ).serialize()

    def claim_tx(self) -> bytes:
        return build_htlc_claim_tx(
            covenant=self.cov,
            covenant_outpoint=self.outpoint,
            carrier_value=AMOUNT,
            preimage=self.p,
            fee=_FeeSource().next_fee_input(),
        ).serialize()

    def coordinator(self, *, state=SwapState.NEGOTIATED, role=SwapRole.MAKER, pin=False, leg=None, record=None):
        rec = record or SwapRecord(state=state, terms=self.terms)
        if pin:
            rec = rec.with_radiant_lock(self.outpoint, self.cov.funded_spk.hex())
        coord = SwapCoordinator(
            record=rec,
            btc_leg=FakeBtcLeg(),
            radiant_leg=leg or self.leg(),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(margin_policy=MarginPolicy.estimated(), role=role),
        )
        coord.persisted = []

        async def _persist(r):
            coord.persisted.append(r)

        coord._persist = _persist
        return coord


def _broadcasts(swap: _Swap) -> int:
    return sum(len(s.broadcasts) for s in swap.sources)


# --------------------------------------------------------------------------- the exit itself


async def test_a_makers_negotiated_record_is_refunded_then_ends_when_the_refund_is_buried():
    """The taker never funded. The first call pins the covenant (persisted BEFORE the broadcast),
    sends the CSV refund and records it; the record stays NEGOTIATED. Once mined, the next call
    reads the refund from every source and ends the record, sending nothing more."""
    swap = _Swap()
    coord = swap.coordinator()
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.NEGOTIATED and _broadcasts(swap) == 1
    assert rec.radiant_covenant_outpoint == swap.outpoint and rec.asset_refund_txid is not None
    pinned_first = coord.persisted[0]
    assert pinned_first.radiant_covenant_outpoint == swap.outpoint and pinned_first.asset_refund_txid is None

    swap.chain.mine(1)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COVENANT_REFUNDED
    assert rec.asset_refund_txid == coord.persisted[-1].asset_refund_txid and _broadcasts(swap) == 1
    assert coord.persisted[-1] == rec


async def test_a_refund_not_yet_buried_holds_the_record_and_sends_nothing():
    swap = _Swap()
    coord = swap.coordinator(leg=swap.leg(min_confirmations=3))
    await coord.maker_refund_covenant()
    swap.chain.mine(1)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.NEGOTIATED and _broadcasts(swap) == 1
    swap.chain.mine(2)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED and _broadcasts(swap) == 1


@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH])
async def test_the_maker_exits_btc_locked_and_params_mismatch_the_same_way(state):
    """PARAMS_MISMATCH arises only in the maker's process (post_asset_lock_revalidate), and until
    now its only exits were the taker's. The maker's record ends on its own covenant refund."""
    swap = _Swap()
    coord = swap.coordinator(state=state, pin=True)
    await coord.maker_refund_covenant()
    swap.chain.mine(1)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COVENANT_REFUNDED


async def test_a_refund_made_elsewhere_ends_the_record_without_a_send():
    """The pre-PR-11 runner refunded the covenant through the leg and left the record. The read
    recognises any refund-leaf spend, by its bytes, not by a txid the record holds."""
    swap = _Swap()
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    coord = swap.coordinator(pin=True)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED and _broadcasts(swap) == 0


async def test_reconcile_ends_a_makers_both_locked_record_at_mutual_refund():
    swap = _Swap()
    txid = swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    coord = swap.coordinator(state=SwapState.BOTH_LOCKED, pin=True)
    rec = await coord.reconcile_covenant()
    assert rec.state is SwapState.MUTUAL_REFUND and rec.asset_refund_txid == txid and rec.abort_reason is None
    assert _broadcasts(swap) == 0


async def test_reconcile_on_an_unspent_covenant_changes_nothing():
    swap = _Swap()
    coord = swap.coordinator(state=SwapState.BOTH_LOCKED, pin=True)
    rec = await coord.reconcile_covenant()
    assert rec.state is SwapState.BOTH_LOCKED and coord.persisted == [] and _broadcasts(swap) == 0


# --------------------------------------------------------------------------- refusals


@pytest.mark.parametrize("role", [SwapRole.TAKER, None])
async def test_only_a_maker_runs_it(role):
    """The CSV refund pays the maker (P3). The honest case is every MAKER test above."""
    swap = _Swap()
    coord = swap.coordinator(role=role)
    with pytest.raises(ValidationError, match="MAKER-side step"):
        await coord.maker_refund_covenant()
    with pytest.raises(ValidationError, match="MAKER-side step"):
        await coord.reconcile_covenant()
    assert _broadcasts(swap) == 0 and coord.persisted == []


async def test_from_both_locked_the_send_is_refused_and_named():
    swap = _Swap()
    coord = swap.coordinator(state=SwapState.BOTH_LOCKED, pin=True)
    with pytest.raises(ValidationError, match="maybe_refund_asset_on_maker_stall"):
        await coord.maker_refund_covenant()
    assert _broadcasts(swap) == 0


@pytest.mark.parametrize(
    "state", [SwapState.SECRET_REVEALED, SwapState.ASSET_VULNERABLE, SwapState.COMPLETED, SwapState.ABORTED]
)
async def test_no_state_after_the_reveal_or_terminal_is_accepted(state):
    swap = _Swap()
    coord = swap.coordinator(state=state, pin=True)
    for step in (coord.maker_refund_covenant, coord.reconcile_covenant):
        with pytest.raises(ValidationError, match="valid from"):
            await step()
    assert _broadcasts(swap) == 0


@pytest.mark.parametrize("how", ["counter_claim_tx", "claimed_disposition"])
async def test_a_counter_leg_claim_on_record_refuses_the_send(how):
    """p is public and the counter leg was paid to the maker: refunding the covenant too takes both."""
    swap = _Swap()
    rec = SwapRecord(state=SwapState.BTC_LOCKED, terms=swap.terms)
    if how == "counter_claim_tx":
        rec = dataclasses.replace(rec, counter_claim_tx="ab" * 32)
    else:
        claimed = CounterDispositionRecord(
            kind="claimed", block_number=1, block_hash="cd" * 32, tx_hash="ab" * 32, sources=("a",), single_source=False
        )
        rec = dataclasses.replace(rec, counter_disposition=claimed)
    coord = swap.coordinator(record=rec, pin=True)
    with pytest.raises(ValidationError, match="take both legs"):
        await coord.maker_refund_covenant()
    assert _broadcasts(swap) == 0 and coord.persisted == []


async def test_both_locked_with_a_counter_claim_on_record_does_not_read_as_mutual_refund():
    swap = _Swap()
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    rec = SwapRecord(state=SwapState.BOTH_LOCKED, terms=swap.terms)
    rec = dataclasses.replace(rec, counter_claim_tx="ab" * 32)
    coord = swap.coordinator(record=rec, pin=True)
    with pytest.raises(ValidationError, match="both legs"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BOTH_LOCKED and coord.persisted == []


@pytest.mark.parametrize("state", [SwapState.NEGOTIATED, SwapState.BOTH_LOCKED])
async def test_a_claimed_covenant_raises_and_changes_nothing(state):
    """The taker claimed the covenant with p. Nothing is sent and no state is invented."""
    swap = _Swap()
    swap.chain.add(swap.claim_tx(), height=swap.chain.tip)
    coord = swap.coordinator(state=state, pin=True)
    step = coord.reconcile_covenant if state is SwapState.BOTH_LOCKED else coord.maker_refund_covenant
    with pytest.raises(ValidationError, match="CLAIMED"):
        await step()
    assert coord.record.state is state and coord.persisted == [] and _broadcasts(swap) == 0


# --------------------------------------------------------------------------- one source must not decide


async def test_a_lying_primary_with_a_decoy_refund_that_withholds_the_real_spend_decides_nothing():
    """The primary (the client every send goes through) serves a refund of its own making and hides
    the real spender, a claim. The other sources name the claim. The sources disagree: UNKNOWN, no
    edge, and the record is unchanged."""
    swap = _Swap()
    real = swap.chain.add(swap.claim_tx(), height=swap.chain.tip - 3)
    liar = FakeRadiantSource(swap.chain, "https://liar.example-x.org", hide={real}, extra=[swap.refund_tx()])
    leg = swap.leg(sources=[liar, *swap.sources])
    coord = swap.coordinator(state=SwapState.BOTH_LOCKED, pin=True, leg=leg)
    with pytest.raises(NetworkError, match="disagree"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BOTH_LOCKED and coord.persisted == []


async def test_a_liar_at_a_later_index_cannot_end_the_record_either():
    swap = _Swap()
    liar = FakeRadiantSource(swap.chain, "https://liar.example-x.org", extra=[swap.refund_tx()])
    leg = swap.leg(sources=[*swap.sources, liar])
    coord = swap.coordinator(state=SwapState.BTC_LOCKED, pin=True, leg=leg)
    with pytest.raises(NetworkError, match="disagree"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_a_source_that_withholds_the_refund_holds_the_record():
    """A source that hides the refund answers 'unspent'. A lag looks the same, so the record waits."""
    swap = _Swap()
    refund = swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    swap.sources[1].hide = {refund}
    coord = swap.coordinator(state=SwapState.BTC_LOCKED, pin=True)
    with pytest.raises(NetworkError, match="disagree"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_one_source_over_reporting_depth_does_not_bury_the_refund():
    swap = _Swap()
    swap.chain.add(swap.refund_tx())  # in the mempool
    swap.sources[0].depth_bonus = 50
    coord = swap.coordinator(pin=True)
    rec = await coord.reconcile_covenant()
    assert rec.state is SwapState.NEGOTIATED and coord.persisted == []


async def test_a_spend_that_matches_neither_leaf_is_unknown():
    """Consensus binds each leaf to its output, so this cannot be mined; a source can still serve it."""
    swap = _Swap()
    tx = build_htlc_refund_tx(
        covenant=swap.cov, covenant_outpoint=swap.outpoint, carrier_value=AMOUNT, fee=_FeeSource().next_fee_input()
    )
    tx.outputs[0].locking_script = type(tx.outputs[0].locking_script)(b"\x76\xa9\x14" + _pkh() + b"\x88\xac")
    swap.chain.add(tx.serialize(), height=swap.chain.tip)
    coord = swap.coordinator(pin=True, state=SwapState.BOTH_LOCKED)
    with pytest.raises(NetworkError, match="neither leaf"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BOTH_LOCKED


async def test_on_a_value_bearing_network_one_operator_does_not_end_the_record(monkeypatch):
    swap = _Swap(sources=1)
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    coord = swap.coordinator(pin=True)
    monkeypatch.setattr(sc, "_leg_is_value_bearing", lambda leg: True)
    with pytest.raises(NetworkError, match="fewer than 2 operators"):
        await coord.maker_refund_covenant()
    assert coord.record.state is SwapState.NEGOTIATED and _broadcasts(swap) == 0


async def test_HONEST_on_a_value_bearing_network_two_operators_end_it(monkeypatch):
    swap = _Swap(sources=2)
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    coord = swap.coordinator(pin=True)
    monkeypatch.setattr(sc, "_leg_is_value_bearing", lambda leg: True)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED


async def test_HONEST_a_source_that_is_down_is_left_out():
    swap = _Swap()
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    swap.sources[2].down = True
    coord = swap.coordinator(pin=True)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED


async def test_an_unknown_read_still_sends_the_refund_when_the_leg_can():
    """One source that answers wrongly delays the end of the record, never the refund itself."""
    swap = _Swap()
    liar = FakeRadiantSource(swap.chain, "https://liar.example-x.org", extra=[swap.refund_tx()])
    coord = swap.coordinator(pin=True, leg=swap.leg(sources=[*swap.sources, liar]))
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.NEGOTIATED and rec.asset_refund_txid is not None and _broadcasts(swap) == 1


async def test_the_read_never_raises_for_an_unreadable_chain():
    swap = _Swap()
    for s in swap.sources:
        s.down = True
    spend = await swap.leg().covenant_spend(
        SwapRecord(state=SwapState.NEGOTIATED, terms=swap.terms).with_radiant_lock(swap.outpoint, "51"), burial_blocks=1
    )
    assert spend.kind is CovenantSpendKind.UNKNOWN and len(spend.failed) == 3


async def test_the_record_carries_the_maker_role():
    swap = _Swap()
    coord = swap.coordinator()
    await coord.maker_refund_covenant()
    assert coord.persisted[-1].role is RecordRole.MAKER


def test_each_steps_spelled_out_guard_matches_its_module_set():
    """The two steps spell their states out (so the watch tower's page sweep can read them); the
    guard the sweep reads must be the set the refusal message names."""
    from tests.test_watch_pages_name_state_valid_steps import _state_guards

    guards = _state_guards()
    assert guards["maker_refund_covenant"] == sc._MAKER_COVENANT_SEND_STATES
    assert guards["reconcile_covenant"] == sc._MAKER_COVENANT_READ_STATES


# --------------------------------------------------------------------------- review round 1 (M1, M2, L2)


def _spam(swap: _Swap, n: int = MAX_COVENANT_HISTORY + 1) -> list[str]:
    """*n* payments to the covenant's public script, mined: anyone can make them."""
    return [swap.chain.add(payment(swap.cov.funded_spk, 600), height=swap.chain.tip - 1) for _ in range(n)]


async def test_a_source_that_trims_a_spammed_history_cannot_decide_alone():
    """Review M1. The covenant script is spammed past the read cap, so the honest sources cannot read
    it; a liar that trims its history and serves a decoy refund must not then decide on its own.
    Each honest source answers 'unread', which blocks a decision: the record stays, nothing persisted."""
    swap = _Swap()
    spam = _spam(swap)
    liar = FakeRadiantSource(swap.chain, "https://liar.example-x.org", hide=set(spam), extra=[swap.refund_tx()])
    coord = swap.coordinator(state=SwapState.BTC_LOCKED, pin=True, leg=swap.leg(sources=[*swap.sources, liar]))
    with pytest.raises(NetworkError, match="cannot be read from every answering source"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BTC_LOCKED and coord.persisted == []


async def test_a_spammed_history_still_ends_the_record_on_its_own_recorded_refund():
    """The honest pair to the above: the record's own refund (``asset_refund_txid``, a txid no source
    nominated) is checked at each source despite the spam, so the record still ends once it is buried."""
    swap = _Swap()
    coord = swap.coordinator()
    await coord.maker_refund_covenant()
    _spam(swap)
    swap.chain.mine(1)
    rec = await coord.maker_refund_covenant()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COVENANT_REFUNDED
    assert _broadcasts(swap) == 1


async def test_a_spammed_history_without_a_recorded_refund_says_why_it_cannot_decide():
    swap = _Swap()
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip - 3)  # made elsewhere, so not on the record
    _spam(swap)
    coord = swap.coordinator(state=SwapState.BTC_LOCKED, pin=True)
    with pytest.raises(NetworkError, match=f"more than the {MAX_COVENANT_HISTORY} read"):
        await coord.reconcile_covenant()
    assert coord.record.state is SwapState.BTC_LOCKED


async def test_a_params_mismatch_record_with_the_unverifiable_placeholder_is_repinned_and_refunded():
    """Review M2. post_asset_lock_revalidate pins a placeholder when it cannot recompute the covenant.
    The maker's exit re-pins the covenant the terms build, then refunds it."""
    swap = _Swap()
    rec = SwapRecord(state=SwapState.PARAMS_MISMATCH, terms=swap.terms).with_radiant_lock(
        sc._UNVERIFIABLE_COVENANT_PIN, "00"
    )
    coord = swap.coordinator(record=rec)
    rec = await coord.maker_refund_covenant()
    assert rec.radiant_covenant_outpoint == swap.outpoint and _broadcasts(swap) == 1
    swap.chain.mine(1)
    assert (await coord.maker_refund_covenant()).state is SwapState.ABORTED


async def test_reconcile_treats_the_placeholder_as_no_pin():
    swap = _Swap()
    rec = SwapRecord(state=SwapState.PARAMS_MISMATCH, terms=swap.terms).with_radiant_lock(
        sc._UNVERIFIABLE_COVENANT_PIN, "00"
    )
    with pytest.raises(ValidationError, match="needs the covenant outpoint pinned"):
        await swap.coordinator(record=rec).reconcile_covenant()


class _NoFundingInHistory(FakeRadiantSource):
    async def get_history(self, script_hash):
        return [h for h in await super().get_history(script_hash) if h["tx_hash"] != self.funding_txid]


class _NoUtxos(FakeRadiantSource):
    async def get_utxos(self, script_hash):
        return []


async def _one(swap: _Swap, src: FakeRadiantSource):
    return await RadiantChainIO._spender_from_one("s", src, swap.cov.funded_spk, swap.outpoint)


async def test_a_source_whose_history_lacks_the_funding_gives_no_answer():
    """Review L2: each of the per-source guards, removed, lets a source answer it should not."""
    swap = _Swap()
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    src = _NoFundingInHistory(swap.chain, "https://a.example-a.org")
    src.funding_txid = swap.funding_txid
    with pytest.raises(NetworkError, match="funding transaction is not in"):
        await _one(swap, src)
    honest = await _one(swap, FakeRadiantSource(swap.chain, "https://b.example-b.org"))
    assert honest.spender_txid is not None


async def test_a_source_naming_two_spenders_gives_no_answer():
    swap = _Swap()
    swap.chain.add(swap.refund_tx(), height=swap.chain.tip)
    src = FakeRadiantSource(swap.chain, "https://a.example-a.org", extra=[swap.refund_tx()])
    with pytest.raises(NetworkError, match="two transactions"):
        await _one(swap, src)


async def test_an_unspent_answer_needs_the_outpoint_in_the_sources_utxo_set():
    swap = _Swap()
    with pytest.raises(NetworkError, match="not in this source's UTXO set"):
        await _one(swap, _NoUtxos(swap.chain, "https://a.example-a.org"))
    honest = await _one(swap, FakeRadiantSource(swap.chain, "https://b.example-b.org"))
    assert honest.spender_txid is None and honest.unread is None

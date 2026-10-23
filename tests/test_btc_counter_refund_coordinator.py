"""The coordinator's BTC counter-leg refund, read from the chain (#850 PR 9a, design §6, §7.2 scenario 21).

Through ``tests._fake_btc_chain``: a real Taproot HTLC, the real ``BitcoinTaprootLeg`` signing real
refunds, ``MultiSourceBtcFundingReader`` over three sources, and a mempool with BIP125 replacement.
Each step runs on a coordinator rebuilt from the record read back from ``JsonFileRecordSink`` (a
fresh process, in effect, design §7), and the assertions are on that record and on the fake chain.
Each refusal has its honest twin.
"""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.gravity import swap_coordinator as sc
from pyrxd.gravity.record_sink import JsonFileRecordSink
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import AbortReason, SwapRecord, SwapRole, SwapState
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
from pyrxd.security.errors import (
    CounterLegDispositionUnknown,
    CounterLegRefundNeedsOperator,
    CounterLegSingleSourceAnswer,
    NetworkError,
    ValidationError,
)
from tests._fake_btc_chain import CLAIM_SPK, REFUND_SPK, FakeBtcChain, FakeBtcSource, _xonly
from tests.test_btc_counter_disposition import _claim_signed_over
from tests.test_swap_coordinator import FakeIndexer, FakeRadiantLeg, FakeSeenStore, _terms

#: The leg's ``min_confirmations``: the burial an estimated policy uses (``_btc_burial_blocks``).
BURIAL = 3
_COVENANT = "ef" * 32 + ":0"


class _ChainIO:
    """The Radiant reader the D14 hold asks: the covenant funding transaction's depth."""

    def __init__(self, confs: int) -> None:
        self.confs = confs

    async def confirmations(self, txid: str) -> int:
        return self.confs


class _Swap:
    """One swap on one fake chain: the sources, the sink, and a coordinator per step."""

    def __init__(self, tmp_path, *, state=SwapState.BTC_LOCKED, role=SwapRole.TAKER, network="bcrt", n=3, quorum=2):
        self.chain = FakeBtcChain()
        self.sources = [FakeBtcSource(self.chain) for _ in range(n)]
        self.reader = MultiSourceBtcFundingReader(self.sources, quorum=quorum) if n > 1 else self.sources[0]
        self.network = network
        self.role = role
        self.rxd = FakeRadiantLeg()
        self.rxd.chain_io = _ChainIO(0)  # the covenant was just mined: t_rxd far off
        self.sink = JsonFileRecordSink(tmp_path / "swap.json")
        terms = _terms(hashlock=self.chain.hashlock, t_btc_blocks=self.chain.t_btc_blocks, t_rxd_blocks=144)
        record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms).with_counter_lock(self.chain.locator)
        self.first = record.with_radiant_lock(_COVENANT, "51").with_state(state)

    def leg(self) -> BitcoinTaprootLeg:
        return BitcoinTaprootLeg(
            network=self.network,
            taker_keypair=self.chain.taker,
            funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
            maker_claim_pubkey_xonly=_xonly(self.chain.maker),
            broadcaster=self.sources[0],
            funding_reader=self.reader,
            refund_to_scriptpubkey=REFUND_SPK,
            claim_to_scriptpubkey=CLAIM_SPK,
            fee_sats=500,
            min_confirmations=BURIAL,
        )

    def coord(self, *, role=None) -> SwapCoordinator:
        record = self.sink.load_record() or self.first
        return SwapCoordinator(
            record=record,
            counter_leg=self.leg(),
            radiant_leg=self.rxd,
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(
                margin_policy=MarginPolicy.estimated(),
                role=role or self.role,
                accept_nondurable_seen=True,  # the "bc" case; nothing here is about the seen-store
            ),
            persist=self.sink,
        )

    def on_disk(self) -> SwapRecord:
        """The record on disk, or the one the swap started from while no step has changed it."""
        return self.sink.load_record() or self.first

    @property
    def sent(self) -> list[bytes]:
        return self.sources[0].broadcasts


def _fee(raw: bytes) -> int:
    return FakeBtcChain.fee_of(raw)


# --------------------------------------------------------------------------- taker_refund_btc


async def test_the_refund_is_recorded_before_it_is_sent_and_the_record_waits_until_it_is_buried(tmp_path):
    s = _Swap(tmp_path)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED, "advanced on its own broadcast"
    raw = bytes.fromhex(s.on_disk().counter_refund_raw)
    assert s.sent == [raw] and s.chain.mempool == t.btc_txid_from_raw(raw)
    # In the mempool, then shallow: nothing more is sent, the record waits.
    assert (await s.coord().taker_refund_btc()).state is SwapState.BTC_LOCKED
    s.chain.mine(BURIAL - 1)
    assert (await s.coord().taker_refund_btc()).state is SwapState.BTC_LOCKED
    assert s.sent == [raw]
    s.chain.mine(1)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COUNTER_LEG_REFUNDED
    back = s.on_disk()
    assert back.state is SwapState.ABORTED
    assert back.counter_disposition.kind == "refunded"
    assert back.counter_disposition.tx_hash == t.btc_txid_from_raw(raw)
    assert back.counter_disposition.block_hash == s.chain.block_hash(s.chain.mined[t.btc_txid_from_raw(raw)])
    assert s.sent == [raw]


async def test_a_failed_broadcast_leaves_the_signed_refund_on_disk(tmp_path):
    s = _Swap(tmp_path)
    s.sources[0].down = True  # the broadcaster; the other two still read
    with pytest.raises(NetworkError):
        await s.coord().taker_refund_btc()
    recorded = s.on_disk().counter_refund_raw
    assert recorded is not None and s.chain.mempool is None
    # The next pass sends those same bytes, not a new refund.
    s.sources[0].down = False
    await s.coord().taker_refund_btc()
    assert s.sent[-1].hex() == recorded and s.chain.mempool == t.btc_txid_from_raw(bytes.fromhex(recorded))


async def test_a_refund_before_csv_maturity_records_and_sends_nothing(tmp_path):
    s = _Swap(tmp_path)
    s.chain.funding_height = s.chain.head - s.chain.t_btc_blocks + 2  # one block short
    with pytest.raises(NetworkError, match="not yet mature"):
        await s.coord().taker_refund_btc()
    assert s.on_disk().counter_refund_raw is None and s.sent == []


async def test_a_dropped_refund_is_sent_again_with_the_same_bytes(tmp_path):
    s = _Swap(tmp_path)
    await s.coord().taker_refund_btc()
    first = s.sent[0]
    s.chain.drop()
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and s.sent == [first, first]
    assert s.chain.mempool == t.btc_txid_from_raw(first)


async def test_a_pending_refund_is_replaced_by_bip125_after_the_wait_and_the_bump_is_recorded(tmp_path, monkeypatch):
    s = _Swap(tmp_path)
    coord = s.coord()
    await coord.taker_refund_btc()
    first = s.sent[0]
    clock = [1_000.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    await coord.taker_refund_btc()  # first seen pending now
    clock[0] += sc.REFUND_REPLACE_AFTER_S - 1
    await coord.taker_refund_btc()
    assert s.sent == [first], "replaced before REFUND_REPLACE_AFTER_S"
    clock[0] += 2
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and len(s.sent) == 2
    bump = s.sent[1]
    assert bytes.fromhex(s.on_disk().counter_refund_raw) == bump
    assert s.chain.mempool == t.btc_txid_from_raw(bump) != t.btc_txid_from_raw(first)
    assert _fee(bump) == 2 * _fee(first)
    s.chain.mine(BURIAL)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.tx_hash == t.btc_txid_from_raw(bump)


async def test_a_bump_past_the_cap_is_left_to_the_operator(tmp_path, monkeypatch):
    s = _Swap(tmp_path)
    expensive = s.chain.refund_tx(fee_sats=6_000)  # the tower's pre-signed refund, say: twice is past 10%
    s.chain.submit(expensive)
    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord = s.coord()
    await coord.taker_refund_btc()
    clock[0] += sc.REFUND_REPLACE_AFTER_S + 1
    with pytest.raises(CounterLegRefundNeedsOperator) as exc:
        await coord.taker_refund_btc()
    assert exc.value.cause == "fee_cap" and exc.value.tx_hash == t.btc_txid_from_raw(expensive)
    assert s.sent == [] and s.chain.mempool == t.btc_txid_from_raw(expensive)


async def test_with_two_of_our_refunds_pending_the_bump_is_priced_over_the_dearer(tmp_path, monkeypatch):
    """One source still holds the refund another source's mempool replaced: the bump must clear the
    one paying the most, or the node refuses it."""
    s = _Swap(tmp_path)
    cheap, dear = s.chain.refund_tx(fee_sats=300), s.chain.refund_tx(fee_sats=600)
    s.chain.submit(cheap)
    s.chain.submit(dear)  # BIP125: dear replaces cheap at the chain
    s.sources[2].forge_spender = cheap  # a source that has not seen the replacement
    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord = s.coord()
    await coord.taker_refund_btc()
    assert s.sent == []
    clock[0] += sc.REFUND_REPLACE_AFTER_S + 1
    await coord.taker_refund_btc()
    assert len(s.sent) == 1 and _fee(s.sent[0]) == 2 * 600
    assert s.chain.mempool == t.btc_txid_from_raw(s.sent[0])


async def test_a_mined_refund_at_a_depth_below_the_quorum_of_answers_is_waited_on(tmp_path, monkeypatch):
    """Mined, but too few sources answer its depth: not pending in the mempool, so never bumped."""
    s = _Swap(tmp_path)
    coord = s.coord()
    await coord.taker_refund_btc()
    s.chain.mine(1)
    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    s.sources[1].down = s.sources[2].down = True
    await coord.taker_refund_btc()
    clock[0] += sc.REFUND_REPLACE_AFTER_S + 1
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and len(s.sent) == 1


async def test_a_refund_only_one_mempool_holds_is_still_bumped(tmp_path, monkeypatch):
    """Review of part 2, F2: the other sources hold the HTLC unspent and know nothing of the refund,
    so its depth is below the quorum of answers. No source has it in a block: it is pending, not
    mined, and is bumped after the wait."""
    s = _Swap(tmp_path)
    for src in s.sources[1:]:
        src.sees_mempool = False
        honest = src.confirmations

        async def depth(txid, _honest=honest):
            if txid != s.chain.funding_txid:
                raise NetworkError("404 Transaction not found")
            return await _honest(txid)

        async def block(txid):
            raise NetworkError("404 Transaction not found")

        src.confirmations, src.tx_block = depth, block
    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord = s.coord()
    await coord.taker_refund_btc()
    await coord.taker_refund_btc()
    assert len(s.sent) == 1
    clock[0] += sc.REFUND_REPLACE_AFTER_S + 1
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and len(s.sent) == 2 and _fee(s.sent[1]) == 2 * _fee(s.sent[0])
    assert bytes.fromhex(s.on_disk().counter_refund_raw) == s.sent[1]


async def test_a_refund_the_node_keeps_refusing_is_replaced_after_the_wait(tmp_path, monkeypatch):
    """Review of part 2, F3: a refund that never enters a mempool reads UNSPENT; re-sending the same
    bytes for ever would never end. After REFUND_REPLACE_AFTER_S of failed re-broadcasts it is bumped."""
    s = _Swap(tmp_path)
    accept = s.chain.submit

    def submit(raw):
        if _fee(raw) < 1_000:
            raise NetworkError("min relay fee not met")
        return accept(raw)

    s.chain.submit = submit
    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord = s.coord()
    with pytest.raises(NetworkError):
        await coord.taker_refund_btc()  # signed, recorded, refused
    first = s.on_disk().counter_refund_raw
    with pytest.raises(NetworkError):
        await coord.taker_refund_btc()  # the same bytes again; the wait starts
    clock[0] += sc.REFUND_REPLACE_AFTER_S - 1
    with pytest.raises(NetworkError):
        await coord.taker_refund_btc()
    assert {r.hex() for r in s.sent} == {first}, "replaced before REFUND_REPLACE_AFTER_S"
    clock[0] += 2
    rec = await coord.taker_refund_btc()
    bump = s.sent[-1]
    assert rec.state is SwapState.BTC_LOCKED and _fee(bump) == 1_000 and s.chain.mempool == t.btc_txid_from_raw(bump)
    assert s.on_disk().counter_refund_raw == bump.hex()


async def test_a_quorum_of_one_on_mainnet_is_one_source(tmp_path):
    """Review of part 2, F1: three sources at quorum one let any one decide. A lying source then
    must not end the record on mainnet while our refund is only in the mempool."""
    s = _Swap(tmp_path, network="bc", n=3, quorum=1)
    s.chain.submit(s.chain.refund_tx())
    s.sources[1].down = s.sources[2].down = True
    s.sources[0].lie_depth = 50
    s.sources[0].lie_block = (190, "aa" * 32)
    with pytest.raises(CounterLegSingleSourceAnswer):
        await s.coord().taker_refund_btc()
    assert s.on_disk().state is SwapState.BTC_LOCKED and s.on_disk().counter_disposition is None


async def test_the_towers_presigned_refund_is_followed_as_ours(tmp_path):
    """Classification is by leaf, not txid (M1): a refund we did not record is still our refund."""
    s = _Swap(tmp_path)
    presigned = s.chain.refund_tx(fee_sats=700)
    s.chain.submit(presigned)
    assert (await s.coord().taker_refund_btc()).state is SwapState.BTC_LOCKED
    assert s.sent == [] and s.on_disk().counter_refund_raw is None
    s.chain.mine(BURIAL)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.tx_hash == t.btc_txid_from_raw(presigned)


async def test_scenario_21_a_refund_replaced_by_a_claim_is_claim_seen_then_secret_revealed(tmp_path):
    """Design §7.2 scenario 21: the claim leaf has no timelock, so the maker can replace a pending
    refund by BIP125. Seen: recorded, nothing sent. Buried: SECRET_REVEALED, p public."""
    s = _Swap(tmp_path)
    await s.coord().taker_refund_btc()
    claim = s.chain.claim_tx(fee_sats=2_000)
    s.chain.submit(claim)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and rec.counter_claim_tx == t.btc_txid_from_raw(claim)
    assert len(s.sent) == 1, "a refund was sent against a claim"
    s.chain.mine(BURIAL)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.SECRET_REVEALED
    back = s.on_disk()
    assert back.counter_disposition.kind == "claimed" and back.counter_claim_tx == t.btc_txid_from_raw(claim)
    assert t.scrape_secret(claim, s.chain.hashlock) == s.chain.preimage
    assert len(s.sent) == 1


async def test_a_claim_seen_holds_a_buried_refund_until_t_rxd_matures(tmp_path):
    """D14 / N1: once a claim has been seen, p is public, so the refunded leg does not take the
    record terminal before the covenant claim could be made."""
    s = _Swap(tmp_path)
    claim = s.chain.claim_tx(fee_sats=500)
    s.chain.submit(claim)
    await s.coord().taker_refund_btc()  # CLAIM_SEEN: recorded
    s.chain.drop()  # the claim leaves the mempool; p stays public
    await s.coord().taker_refund_btc()
    s.chain.mine(BURIAL)
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and rec.counter_claim_tx == t.btc_txid_from_raw(claim)
    assert rec.counter_disposition.kind == "refunded"
    s.rxd.chain_io = _ChainIO(int(rec.terms.t_rxd.value))
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.ABORTED


async def test_a_maker_coordinator_is_refused(tmp_path):
    s = _Swap(tmp_path, role=SwapRole.MAKER)
    with pytest.raises(ValidationError, match="taker's step"):
        await s.coord().taker_refund_btc()
    assert s.sent == []


async def test_one_source_on_mainnet_changes_nothing_and_on_regtest_it_decides(tmp_path):
    for network, ends in (("bc", None), ("bcrt", SwapState.ABORTED)):
        s = _Swap(tmp_path / network, network=network, n=1, quorum=1)
        refund = s.chain.refund_tx()
        s.chain.submit(refund)
        s.chain.mine(BURIAL)
        if ends is None:
            with pytest.raises(CounterLegSingleSourceAnswer):
                await s.coord().taker_refund_btc()
            assert s.on_disk().state is SwapState.BTC_LOCKED and s.on_disk().counter_disposition is None
        else:
            rec = await s.coord().taker_refund_btc()
            assert rec.state is ends and rec.counter_disposition.single_source


async def test_contradicting_sources_send_nothing(tmp_path):
    s = _Swap(tmp_path)
    refund = s.chain.refund_tx()
    s.chain.submit(refund)
    s.chain.mine(BURIAL)
    s.sources[2].forge_spender = _claim_signed_over(s.chain, refund)
    with pytest.raises(CounterLegDispositionUnknown):
        await s.coord().taker_refund_btc()
    assert s.sent == [] and s.on_disk().state is SwapState.BTC_LOCKED
    assert s.on_disk().counter_claim_tx == t.btc_txid_from_raw(refund)


async def test_a_read_below_quorum_with_no_spender_resends_our_refund_and_moves_nothing(tmp_path):
    s = _Swap(tmp_path)
    await s.coord().taker_refund_btc()
    s.chain.drop()
    s.sources[1].down = s.sources[2].down = True
    rec = await s.coord().taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and s.sent == [s.sent[0], s.sent[0]]


async def test_a_read_below_quorum_signs_no_new_refund(tmp_path):
    """Without a recorded refund, a new one needs the funding depth read at the quorum (the CSV
    maturity check), so a below-quorum read signs nothing."""
    s = _Swap(tmp_path)
    s.sources[1].down = s.sources[2].down = True
    with pytest.raises(NetworkError):
        await s.coord().taker_refund_btc()
    assert s.sent == [] and s.on_disk().counter_refund_raw is None


# --------------------------------------------------------------------------- mutual_refund, reconcile


@pytest.mark.parametrize("role", [SwapRole.TAKER, None])
async def test_a_claim_seen_holds_a_mutual_refund_until_t_rxd_matures(tmp_path, role):
    """D14 / N1 at BOTH_LOCKED: p is public, so neither terminal is taken and a single operator's
    covenant is not refunded before t_rxd."""
    s = _Swap(tmp_path, state=SwapState.BOTH_LOCKED, role=role)
    claim = s.chain.claim_tx(fee_sats=500)
    s.chain.submit(claim)
    await s.coord().mutual_refund()  # CLAIM_SEEN: recorded
    s.chain.drop()
    await s.coord().mutual_refund()  # our refund now
    s.chain.mine(BURIAL)
    rec = await s.coord().mutual_refund()
    assert rec.state is SwapState.BOTH_LOCKED and rec.counter_disposition.kind == "refunded"
    assert not s.rxd.refunded
    s.rxd.chain_io = _ChainIO(int(rec.terms.t_rxd.value))
    rec = await s.coord().mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and s.rxd.refunded is (role is None)


async def test_a_takers_mutual_refund_never_touches_the_covenant(tmp_path):
    """F-A on BTC: the covenant's CSV refund pays the maker, and the taker may still need to
    claim it with p."""
    s = _Swap(tmp_path, state=SwapState.BOTH_LOCKED)
    assert (await s.coord().mutual_refund()).state is SwapState.BOTH_LOCKED
    s.chain.mine(BURIAL)
    rec = await s.coord().mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and not s.rxd.refunded
    assert s.on_disk().counter_disposition.kind == "refunded"


async def test_a_single_operators_covenant_refund_waits_for_the_buried_btc_refund(tmp_path):
    s = _Swap(tmp_path, state=SwapState.BOTH_LOCKED, role=None)
    assert (await s.coord().mutual_refund()).state is SwapState.BOTH_LOCKED
    assert not s.rxd.refunded, "the covenant was refunded while the BTC refund could still lose to a claim"
    s.chain.mine(BURIAL - 1)
    await s.coord().mutual_refund()
    assert not s.rxd.refunded
    s.chain.mine(1)
    rec = await s.coord().mutual_refund()
    assert rec.state is SwapState.MUTUAL_REFUND and s.rxd.refunded and len(s.sent) == 1


async def test_a_mutual_refund_that_finds_a_buried_claim_reveals_and_sends_nothing(tmp_path):
    s = _Swap(tmp_path, state=SwapState.BOTH_LOCKED, role=None)
    s.chain.submit(s.chain.claim_tx())
    s.chain.mine(BURIAL)
    rec = await s.coord().mutual_refund()
    assert rec.state is SwapState.SECRET_REVEALED and s.sent == [] and not s.rxd.refunded


async def test_reconcile_follows_the_chain_and_sends_nothing(tmp_path):
    s = _Swap(tmp_path)
    refund = s.chain.refund_tx()
    s.chain.submit(refund)
    assert (await s.coord().reconcile_counter_leg()).state is SwapState.BTC_LOCKED
    s.chain.mine(BURIAL)
    assert (await s.coord().reconcile_counter_leg()).state is SwapState.ABORTED
    assert s.sent == []


async def test_reconcile_on_an_unreadable_chain_raises(tmp_path):
    s = _Swap(tmp_path)
    for src in s.sources:
        src.down = True
    with pytest.raises(NetworkError, match="unknown"):
        await s.coord().reconcile_counter_leg()


async def test_a_leg_that_reads_no_disposition_keeps_the_old_path(tmp_path):
    """A BTC leg written before 0.27 (no ``counter_disposition``) still refunds and advances on
    broadcast; the record it writes carries no refund raw."""
    s = _Swap(tmp_path)
    leg = s.leg()
    coord = s.coord()
    coord.counter_leg = _NoDisposition(leg)
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.counter_refund_raw is None and len(s.sent) == 1


class _NoDisposition:
    def __init__(self, leg: BitcoinTaprootLeg) -> None:
        self._leg = leg

    async def refund(self, locator, timeout):
        return await self._leg.refund(locator, timeout)


# --------------------------------------------------------------------------- the leg's bump rule


def test_the_bump_doubles_the_fee_or_clears_bip125_rule_4_and_refuses_past_the_cap(tmp_path):
    s = _Swap(tmp_path)
    leg = s.leg()
    cheap = s.chain.refund_tx(fee_sats=130)  # the relay floor: 1 sat/vB of 125 vB
    vsize = t.btc_vsize_from_raw(cheap)
    assert leg.refund_bump_fee(s.chain.locator, cheap) == max(260, 130 + vsize) == 260
    assert leg.refund_bump_fee(s.chain.locator, s.chain.refund_tx(fee_sats=500)) == 1_000
    assert leg.refund_bump_fee(s.chain.locator, s.chain.refund_tx(fee_sats=5_000)) == 10_000  # at the cap
    with pytest.raises(ValidationError, match="not bumped"):
        leg.refund_bump_fee(s.chain.locator, s.chain.refund_tx(fee_sats=5_001))
    small = dataclasses.replace(s.chain.locator, amount_sats=1_000)
    with pytest.raises(ValidationError):
        leg.refund_bump_fee(small, s.chain.refund_tx(fee_sats=500))


def test_the_bump_leaves_the_output_above_dust_whatever_the_cap(tmp_path, monkeypatch):
    """Under the 1/10 cap the dust floor cannot bind (the bump is at least one vsize, ~125 sats);
    it is checked on its own, so a wider cap cannot spend the output into dust."""
    from pyrxd.btc_wallet import htlc_leg

    s = _Swap(tmp_path)
    monkeypatch.setattr(htlc_leg, "REFUND_BUMP_MAX_FEE_FRACTION", (1, 1))
    leg = s.leg()
    amount = s.chain.locator.amount_sats
    edge = (amount - htlc_leg.REFUND_BUMP_MIN_OUTPUT_SATS) // 2
    assert leg.refund_bump_fee(s.chain.locator, s.chain.refund_tx(fee_sats=edge)) == 2 * edge
    with pytest.raises(ValidationError, match="dust"):
        leg.refund_bump_fee(s.chain.locator, s.chain.refund_tx(fee_sats=edge + 1))


def test_the_bump_clears_rule_4_for_our_size_when_the_replaced_refund_is_smaller(tmp_path):
    """Review of part 2, F5: the tower's pre-signed refund may pay a shorter script than ours, and
    BIP125 rule 4 is priced on the replacement's size."""
    s = _Swap(tmp_path)
    leg = s.leg()
    leg.refund_to_scriptpubkey = b"\x51\x20" + b"\x55" * 32  # P2TR, 12 bytes longer than REFUND_SPK
    short = s.chain.refund_tx(fee_sats=130)  # pays REFUND_SPK (P2WPKH), at the relay floor
    rule_4 = 130 + t.btc_vsize_from_raw(short) + 12
    assert rule_4 > 2 * 130, "the case needs rule 4 to bind, not the doubling"
    assert leg.refund_bump_fee(s.chain.locator, short) == rule_4


def test_vsize_needs_a_segwit_transaction():
    chain = FakeBtcChain()
    raw = chain.refund_tx()
    stripped = raw[:4] + raw[6:]
    with pytest.raises(ValidationError, match="segwit"):
        t.btc_vsize_from_raw(stripped)

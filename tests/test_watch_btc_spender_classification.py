"""The watchtower tells a taker's BTC refund from the maker's claim (#850 PR 9b, design §5.1, §6, D12).

Before 9b ``OutspendBtcClaimSource.claim_status`` reported ANY spend of the BTC HTLC funding outpoint
as the maker's claim. Our own refund spends that outpoint too, so PR 1b had to keep the pre-signed
refund off while the maker's covenant was observed. Here the spender is classified by the leaf it
spends (the shared reader of PR 9a), the autonomy is re-armed on a classified read that holds the
outpoint unspent, and a claim that replaces our refund still pages.

The chain is ``tests._fake_btc_chain``: a real Taproot HTLC, real signed refunds and claims, three
sources behind the production ``MultiSourceBtcFundingReader``, and BIP125 replacement in the mempool.
Every refusal here has its honest twin.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.disposition import BtcDispositionKind
from pyrxd.gravity.swap_coordinator import MarginPolicy
from pyrxd.gravity.swap_state import RecordRole, SwapRecord, SwapState
from pyrxd.gravity.watch import alerts
from pyrxd.gravity.watch.adapters import JsonDirRecordStore, OutspendBtcClaimSource
from pyrxd.gravity.watch.decide import Intent, Observations, _required_btc_depth_blocks, decide
from pyrxd.gravity.watch.executor import ExecOutcome, PresignedRefund, RefundExecutor
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.gravity.watch.reconciler import Reconciler
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
from pyrxd.security.errors import ValidationError
from pyrxd.security.units import ChainHeight, Confirmations
from tests._fake_btc_chain import AMOUNT_SATS, REFUND_SPK, FakeBtcChain, FakeBtcSource
from tests.test_swap_coordinator import _terms

_COVENANT = "ef" * 32 + ":0"
SWAP = "s1"
T_RXD = 144
#: The RXD tip, and the covenant's depth: it was mined at TIP - COV_CONFS + 1, so t_rxd is far off.
TIP = 1_000
COV_CONFS = 10


def _policy() -> MarginPolicy:
    return MarginPolicy(
        margin=t.Timelock(72, t.TimeUnit.BLOCKS),
        block_interval_s=600.0,
        is_measured=False,
        btc_claim_reorg_depth=t.Timelock(6, t.TimeUnit.BLOCKS),
        rxd_claim_burial=t.Timelock(2, t.TimeUnit.BLOCKS),
        rxd_block_interval_s=300.0,
    )


BURIAL = int(_required_btc_depth_blocks(_policy()))


class _Rxd:
    """A Radiant source: the tip, and the covenant's depth (``None``: not seen)."""

    def __init__(self, *, tip: int = TIP, cov_confs: int | None = COV_CONFS) -> None:
        self.tip = tip
        self.cov_confs = cov_confs

    async def tip_height(self) -> ChainHeight:
        return ChainHeight(self.tip)

    async def covenant_confirmations(self, outpoint: str) -> Confirmations | None:
        return None if self.cov_confs is None else Confirmations(self.cov_confs)


class _Pages:
    """An alerter that keeps every decision it is handed."""

    def __init__(self) -> None:
        self.got: list[tuple[str, object]] = []

    async def handle(self, swap_id, decision) -> None:
        self.got.append((swap_id, decision))


def _outspend(src: FakeBtcSource):
    """The tower's discovery read over one fake source: ``(spent, spender txid)``."""

    async def outspend(txid: str, vout: int):
        raw = await src.outpoint_spender(txid, vout)
        return (raw is not None, None if raw is None else t.btc_txid_from_raw(raw))

    return outspend


class _Tower:
    """One BTC swap on one fake chain, watched by the production observer, store and reconciler."""

    def __init__(
        self,
        tmp_path,
        *,
        state: SwapState = SwapState.BTC_LOCKED,
        role: RecordRole | None = RecordRole.TAKER,
        covenant: bool = True,
        classify: bool = True,
        swap_id: str = SWAP,
        quorum: int = 2,
    ) -> None:
        self.chain = FakeBtcChain()  # funding mined at 150, head 200: buried 51 >= t_btc 10, matured
        self.sources = [FakeBtcSource(self.chain) for _ in range(3)]
        self.reader = MultiSourceBtcFundingReader(self.sources, quorum=quorum)
        self.dir = tmp_path / "records"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.swap_id = swap_id
        terms = _terms(hashlock=self.chain.hashlock, t_btc_blocks=self.chain.t_btc_blocks, t_rxd_blocks=T_RXD)
        record = SwapRecord(state=SwapState.NEGOTIATED, terms=terms, role=role).with_counter_lock(self.chain.locator)
        if covenant:
            record = record.with_radiant_lock(_COVENANT, "51")
        self.write(record.with_state(state))
        self.rxd = _Rxd(cov_confs=COV_CONFS if covenant else None)
        src = OutspendBtcClaimSource(outspend_fns=[_outspend(s) for s in self.sources], funding_reader=self.reader)
        if not classify:
            src = _Unclassified(src)
        self.observer = ChainObserver(btc=src, rxd=self.rxd, btc_burial_blocks=BURIAL if classify else None)
        self.pages = _Pages()
        self.store = JsonDirRecordStore(self.dir)

    def write(self, record: SwapRecord) -> None:
        (self.dir / f"{self.swap_id}.json").write_text(json.dumps(record.to_dict()))

    def record(self) -> SwapRecord:
        return SwapRecord.from_dict(json.loads((self.dir / f"{self.swap_id}.json").read_text()))

    def presign(self, fee_sats: int = 500) -> bytes:
        raw = self.chain.refund_tx(fee_sats=fee_sats)
        blob = PresignedRefund(raw_tx=raw, swap_id=self.swap_id)
        (self.dir / f"{self.swap_id}.refund.json").write_text(json.dumps(blob.to_dict()))
        return raw

    def reconciler(self, *, executor=None, alerter=None) -> Reconciler:
        return Reconciler(
            store=self.store,
            observer=self.observer,
            alerter=self.pages if alerter is None else alerter,
            policy=_policy(),
            safety_window_blocks=6,
            executor=executor,
        )

    def executor(self) -> RefundExecutor:
        return RefundExecutor(
            broadcaster=self.sources[0],
            blobs_dir=self.dir,
            network="bcrt",
            cap_sats=AMOUNT_SATS,
            refund_spk=REFUND_SPK,
            accept_single_source=True,  # the RXD source here is one fake; nothing here is about RXD quorum
        )

    async def observe(self) -> Observations:
        return await self.observer.observe(self.swap_id, self.record())

    async def decide(self):
        return decide(record=self.record(), observations=await self.observe(), policy=_policy(), safety_window_blocks=6)


class _Unclassified:
    """The same source without the classification: a third-party ``BtcClaimSource`` from before 9b."""

    def __init__(self, inner: OutspendBtcClaimSource) -> None:
        self._inner = inner

    async def claim_status(self, txid, vout):
        return await self._inner.claim_status(txid, vout)

    async def confirmations(self, txid):
        return await self._inner.confirmations(txid)

    async def funding_confirmations(self, txid):
        return await self._inner.funding_confirmations(txid)


# --------------------------------------------------------------------------- the observer


async def test_our_refund_in_the_mempool_is_not_read_as_the_makers_claim(tmp_path):
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    obs = await w.observe()
    assert obs.maker_has_claimed_btc is False
    assert obs.btc_disposition is BtcDispositionKind.REFUND_PENDING
    assert obs.btc_refund_txid == w.chain.mempool


async def test_the_makers_claim_in_the_mempool_is_still_the_claim_trigger(tmp_path):
    """The honest twin: a claim is a claim, from the mempool on, with its own txid's depth."""
    w = _Tower(tmp_path)
    claim = w.chain.claim_tx()
    w.chain.submit(claim)
    obs = await w.observe()
    assert obs.maker_has_claimed_btc is True
    assert obs.btc_disposition is BtcDispositionKind.CLAIM_SEEN
    assert obs.btc_claim_confirmations == 0
    assert obs.btc_refund_txid is None


async def test_without_classification_our_refund_is_read_as_a_claim_as_before(tmp_path):
    """A source that cannot classify keeps the pre-9b reading: every spend is the claim trigger."""
    w = _Tower(tmp_path, classify=False)
    w.chain.submit(w.chain.refund_tx())
    obs = await w.observe()
    assert obs.maker_has_claimed_btc is True
    assert obs.btc_spend_classified is False and obs.btc_disposition is None


async def test_a_spend_whose_bytes_no_source_serves_stays_a_claim(tmp_path):
    """Classification takes a spend OUT of the claim trigger only on proof. A spender the discovery
    read names but no source serves (every source's spender read fails) is still the trigger."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    for s in w.sources:
        s.spender_reads_fail = True  # the panel's reads fail ...
    spent_txid = w.chain.mempool

    async def discovery(txid, vout):  # ... while the discovery read still names the spender
        return True, spent_txid

    w.observer = ChainObserver(
        btc=OutspendBtcClaimSource(outspend_fns=[discovery], funding_reader=w.reader),
        rxd=w.rxd,
        btc_burial_blocks=BURIAL,
    )
    obs = await w.observe()
    assert obs.btc_disposition is BtcDispositionKind.UNKNOWN
    assert obs.maker_has_claimed_btc is True


async def test_a_claim_only_the_disposition_read_sees_is_still_a_claim(tmp_path):
    """The other direction: discovery lags (says unspent) while the panel serves the maker's claim."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.claim_tx())

    async def lagging(txid, vout):
        return False, None

    w.observer = ChainObserver(
        btc=OutspendBtcClaimSource(outspend_fns=[lagging], funding_reader=w.reader),
        rxd=w.rxd,
        btc_burial_blocks=BURIAL,
    )
    obs = await w.observe()
    assert obs.maker_has_claimed_btc is True
    assert obs.btc_claim_confirmations == 0


def test_a_classifying_source_needs_the_burial_depth():
    src = OutspendBtcClaimSource(outspend_fns=[_outspend(FakeBtcSource(FakeBtcChain()))], funding_reader=object())
    with pytest.raises(ValidationError, match="btc_burial_blocks is required"):
        ChainObserver(btc=src, rxd=_Rxd())
    ChainObserver(btc=src, rxd=_Rxd(), btc_burial_blocks=BURIAL)  # the honest twin


def test_a_claim_kind_without_the_claim_trigger_is_refused():
    with pytest.raises(ValidationError, match="maker_has_claimed_btc"):
        Observations(
            maker_has_claimed_btc=False,
            now_rxd_height=TIP,
            btc_spend_classified=True,
            btc_disposition=BtcDispositionKind.CLAIM_SEEN,
        )


# --------------------------------------------------------------------------- decide(): autonomy re-armed


async def test_covenant_observed_and_the_outpoint_unspent_arms_the_pre_signed_refund(tmp_path):
    w = _Tower(tmp_path)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert d.autonomous_btc_refund is True
    assert "bump it with taker_refund_btc" in d.reason


async def test_without_classification_the_covenant_keeps_the_autonomy_off(tmp_path):
    """PR 1b's rule stands for a tower that cannot classify (design §5.1, H3)."""
    w = _Tower(tmp_path, classify=False)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert d.autonomous_btc_refund is False
    assert "could not tell its own refund from a claim" in d.reason


async def test_a_read_below_quorum_does_not_arm(tmp_path):
    w = _Tower(tmp_path)
    w.sources[0].spender_reads_fail = True  # their depth reads still answer
    w.sources[1].spender_reads_fail = True
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND, "the page still goes out"
    assert d.autonomous_btc_refund is False
    assert "unknown" in d.reason


@pytest.mark.parametrize("role", [RecordRole.MAKER, None], ids=["maker", "no-role"])
async def test_the_re_arm_is_still_only_for_a_record_that_says_it_is_the_takers(tmp_path, role):
    w = _Tower(tmp_path, role=role)
    d = await w.decide()
    assert d.autonomous_btc_refund is False


async def test_our_pending_refund_watches_and_never_re_arms(tmp_path):
    w = _Tower(tmp_path)
    txid = w.chain.submit(w.chain.refund_tx())
    d = await w.decide()
    assert d.intent is Intent.WATCH
    assert d.autonomous_btc_refund is False
    assert txid in d.reason


@pytest.mark.parametrize(
    ("state", "step"),
    [
        (SwapState.BTC_LOCKED, "reconcile_counter_leg"),
        (SwapState.PARAMS_MISMATCH, "reconcile_counter_leg"),
        (SwapState.BOTH_LOCKED, "mutual_refund"),
    ],
)
async def test_our_buried_refund_asks_for_a_reconcile_not_a_claim(tmp_path, state, step):
    w = _Tower(tmp_path, state=state)
    txid = w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert d.intent is Intent.RECONCILE
    assert d.recommended_action == step
    assert txid in d.reason
    assert alerts._SEVERITY[Intent.RECONCILE] is alerts.Severity.INFO


async def test_a_buried_refund_on_a_makers_record_pages_its_covenant_refund(tmp_path):
    w = _Tower(tmp_path, role=RecordRole.MAKER)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND
    assert "refund your covenant" in d.recommended_action


async def test_a_buried_refund_with_a_claim_on_record_pages_the_covenant_claim(tmp_path):
    """D14: a claim that opens H is on record, so p is public although our refund won."""
    w = _Tower(tmp_path)
    claim_txid = t.btc_txid_from_raw(w.chain.claim_tx())
    w.write(dataclasses.replace(w.record(), counter_claim_tx=claim_txid))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM
    assert claim_txid in d.reason and "build-claim" in d.recommended_action
    assert d.autonomous_asset_claim is False and d.autonomous_btc_refund is False


def _near_t_rxd(w: _Tower, *, past: int = 0) -> None:
    """Move the RXD tip into the safety window before t_rxd (or *past* blocks beyond it)."""
    locked = TIP - COV_CONFS + 1
    w.rxd.tip = locked + T_RXD - 3 + past
    w.rxd.cov_confs = w.rxd.tip - locked + 1


@pytest.mark.parametrize(
    ("state", "step"), [(SwapState.BTC_LOCKED, "taker_refund_btc"), (SwapState.BOTH_LOCKED, "mutual_refund")]
)
@pytest.mark.parametrize("past", [0, 60], ids=["near", "past"])
async def test_our_refund_still_unburied_near_t_rxd_pages_critical(tmp_path, state, step, past):
    """Review of PR 9b, H1: an unconfirmed refund was WATCHed silently past t_rxd, when the maker can
    refund the covenant AND still claim the BTC by replacing the refund."""
    w = _Tower(tmp_path, state=state)
    w.chain.submit(w.chain.refund_tx())
    _near_t_rxd(w, past=past)
    d = await w.decide()
    assert d.intent is Intent.PAGE_SQUEEZED, d.reason
    assert d.recommended_action.startswith(step)
    assert "REFUND_REPLACE_AFTER_S" in d.recommended_action
    assert d.autonomous_btc_refund is False


async def test_our_refund_unburied_far_from_t_rxd_still_watches(tmp_path):
    """The honest twin: early in the window a pending refund is not a page."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    assert (await w.decide()).intent is Intent.WATCH


async def test_a_claim_served_beside_our_buried_refund_pages_the_covenant_claim(tmp_path):
    """Review of PR 9b, M1: D14 seen on the chain. The claim lost (it is never mined), so it is not
    a claim race at WAIT; its depth is not read; the covenant claim is paged."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    w.sources[2].forge_spender = w.chain.claim_tx()  # a real signed claim, never broadcast
    obs = await w.observe()
    assert obs.btc_disposition is BtcDispositionKind.REFUNDED and obs.maker_has_claimed_btc is True
    assert obs.btc_claim_confirmations is None, "the lost claim's depth was read"
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_CLAIM, d.reason
    assert "build-claim" in d.recommended_action
    assert d.autonomous_asset_claim is False


@pytest.mark.parametrize("pending", [False, True], ids=["unspent", "refund-pending"])
async def test_a_claim_on_record_pages_the_covenant_claim_and_arms_nothing(tmp_path, pending):
    """Review of PR 9b, M2: a recorded claim that opens H means p is public whatever the outpoint
    shows now; the unspent case used to arm the pre-signed refund and say nothing of the covenant."""
    w = _Tower(tmp_path)
    claim_txid = t.btc_txid_from_raw(w.chain.claim_tx())
    w.write(dataclasses.replace(w.record(), counter_claim_tx=claim_txid))
    if pending:
        w.chain.submit(w.chain.refund_tx())
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM, d.reason
    assert claim_txid in d.reason and "refund the BTC" in d.reason
    assert d.autonomous_btc_refund is False and d.autonomous_asset_claim is False


async def test_sources_that_contradict_each_other_page_an_investigation(tmp_path):
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    w.sources[0].lie_block = (w.chain.head, "ab" * 32)  # one source places it in another block
    w.sources[1].lie_block = (w.chain.head - 1, "cd" * 32)
    obs = await w.observe()
    assert obs.btc_disposition is BtcDispositionKind.REFUND_PENDING, "no agreed block: not buried"
    # A contradiction the reader calls UNKNOWN with spenders named.
    contradicted = Observations(
        maker_has_claimed_btc=False,
        now_rxd_height=TIP,
        asset_locked_at_height=TIP - COV_CONFS + 1,
        btc_funding_confirmations=51,
        btc_spend_classified=True,
        btc_disposition=BtcDispositionKind.UNKNOWN,
        btc_disposition_reason="two buried spenders",
        btc_spenders_named=True,
    )
    d = decide(record=w.record(), observations=contradicted, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_SQUEEZED
    assert d.recommended_action.startswith("investigate")
    assert d.autonomous_btc_refund is False
    assert d.situation == "btc_spender_contradiction", "an ACK of it would silence the claim race"


async def test_params_mismatch_with_our_refund_pending_does_not_arm_again(tmp_path):
    w = _Tower(tmp_path, state=SwapState.PARAMS_MISMATCH)
    w.chain.submit(w.chain.refund_tx())
    d = await w.decide()
    assert d.intent is Intent.WATCH and d.autonomous_btc_refund is False


async def test_params_mismatch_unspent_still_arms(tmp_path):
    """The honest twin: PARAMS_MISMATCH matured and unspent arms as it did before 9b."""
    w = _Tower(tmp_path, state=SwapState.PARAMS_MISMATCH)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.autonomous_btc_refund is True


# --------------------------------------------------------------------------- the whole tower (design §7.2, 21)


async def test_the_pre_signed_refund_is_recognised_as_ours_and_a_claim_replacing_it_pages(tmp_path):
    """Scenario 21 at the tower: the pre-signed refund goes out while the covenant is observed, is
    read back as ours (no claim page, no second broadcast), and a maker's claim that replaces it
    pages the claim race."""
    w = _Tower(tmp_path)
    raw = w.presign()
    rec = w.reconciler(executor=w.executor())

    first = (await rec.tick())[0]
    assert first.decision.autonomous_btc_refund is True
    assert first.executed is ExecOutcome.BROADCAST
    assert w.chain.mempool == t.btc_txid_from_raw(raw)

    second = (await rec.tick())[0]
    assert second.decision.intent is Intent.WATCH, second.decision.reason
    assert second.executed is None
    assert w.sources[0].broadcasts == [raw]

    # The claim leaf has no timelock: the maker replaces our refund (BIP125, a higher fee).
    claim = w.chain.claim_tx(fee_sats=5_000)
    w.chain.submit(claim)
    w.chain.mine(BURIAL)
    third = (await rec.tick())[0]
    assert third.decision.intent is Intent.PAGE_CLAIM, third.decision.reason
    assert third.executed is None, "nothing armed: a refund is no longer due"
    assert w.sources[0].broadcasts == [raw]


async def test_the_pre_signed_refund_buried_asks_for_a_reconcile_and_is_never_sent_twice(tmp_path):
    w = _Tower(tmp_path)
    raw = w.presign()
    rec = w.reconciler(executor=w.executor())
    assert (await rec.tick())[0].executed is ExecOutcome.BROADCAST
    w.chain.mine(BURIAL - 1)
    shallow = (await rec.tick())[0]
    assert shallow.decision.intent is Intent.WATCH, "not at depth yet"
    w.chain.mine(1)
    buried = (await rec.tick())[0]
    assert buried.decision.intent is Intent.RECONCILE
    assert buried.decision.recommended_action == "reconcile_counter_leg"
    assert buried.executed is None
    assert w.sources[0].broadcasts == [raw]
    # A record ended without the chain read (as pyrxd before 0.27 did) is read once by the legacy net,
    # which agrees with it and writes its marker; after that the tower reads nothing for it.
    w.write(w.record().with_state(SwapState.ABORTED))
    (legacy,) = await rec.tick()
    assert legacy.legacy is True and legacy.decision.intent is Intent.WATCH and legacy.executed is None
    assert w.store.legacy_marker_path(SWAP).exists()
    assert (await rec.tick()) == []
    assert w.sources[0].broadcasts == [raw]


async def test_without_classification_the_tower_reads_its_own_refund_as_a_claim(tmp_path):
    """Why the re-arm needs the classification: the same broadcast, read by a tower that cannot
    classify, is paged as the maker's claim (and the pre-signed refund is never armed there)."""
    w = _Tower(tmp_path, classify=False)
    w.presign()
    rec = w.reconciler(executor=w.executor())
    first = (await rec.tick())[0]
    assert first.executed is None and first.decision.autonomous_btc_refund is False
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    second = (await rec.tick())[0]
    assert second.decision.intent is Intent.PAGE_CLAIM, "an unclassified spend is a claim"

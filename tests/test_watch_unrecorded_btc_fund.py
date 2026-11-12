"""The watchtower pages a BTC fund the record never took as its lock (#842).

``taker_funds_btc`` writes the signed funding transaction to the record before it broadcasts
(``pending_btc_funding_tx``) and replaces it with the locator once the lock confirms. A fund
interrupted in between leaves a NEGOTIATED record whose BTC may be on chain. The tower read that as
"no action due", so a maker claim with ``p`` on that HTLC went unobserved. Now it watches the HTLC the
record's own bytes pay, as a lock, and pages:

* a claim race or a refund that falls due through the BTC_LOCKED rules, each action starting with
  ``resume_interrupted_fund``, with no autonomy and situation tags of their own;
* a fund that went quiet (``PAGE_RESUME_FUND``, WARN, once) when some source sees it ``G`` deep;
* nothing for a healthy fund in flight, and no covenant read until the BTC side gives a reason. A
  fund not yet engaged stays silent near t_rxd too: a known gap (combined Mythos pass, 1.1), pinned
  below and tracked for a design of its own.

The chain is ``tests._fake_btc_chain`` with a real funding transaction paying a real Taproot HTLC
built from the terms' keys. Reads go through the production ``MultiSourceBtcFundingReader`` (quorum 2
of 3), ``OutspendBtcClaimSource`` and ``ChainObserver``; pages through the production ``Reconciler``
and ``DedupAlerter``. Every refusal here has its honest twin.
"""

from __future__ import annotations

import dataclasses
import json
import os

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_coordinator import assert_timelock_margin, taker_refund_window_open
from pyrxd.gravity.swap_state import RecordRole, SwapRecord, SwapState
from pyrxd.gravity.watch.adapters import JsonDirRecordStore, OutspendBtcClaimSource
from pyrxd.gravity.watch.alerts import _ACK_LINE_RE, DedupAlerter, Severity
from pyrxd.gravity.watch.decide import (
    SITUATION_BTC_REFUND_DUE,
    SITUATION_CLAIM_RACE,
    SITUATION_UNRECORDED_FUND_PREFIX,
    SITUATION_UNRECORDED_FUND_STOPPED,
    Intent,
    Observations,
    decide,
)
from pyrxd.gravity.watch.executor import ExecOutcome, PresignedRefund, RefundExecutor
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.gravity.watch.reconciler import Reconciler
from pyrxd.gravity.watch.unrecorded_fund import (
    DEFAULT_UNRECORDED_FUND_GRACE_BLOCKS,
    is_unrecorded_btc_fund,
    unrecorded_btc_fund_locator,
    unrecorded_fund_engaged,
    unrecorded_lock_view,
)
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.units import ChainHeight, Confirmations
from tests._fake_btc_chain import AMOUNT_SATS, REFUND_SPK, FakeBtcChain, FakeBtcSource, _xonly
from tests.test_swap_coordinator import _terms
from tests.test_watch_btc_spender_classification import BURIAL, COV_CONFS, T_RXD, TIP, _outspend, _policy

SWAP = "u1"
G = DEFAULT_UNRECORDED_FUND_GRACE_BLOCKS
_COVENANT = "ef" * 32 + ":0"
LOCKED_AT = TIP - COV_CONFS + 1
T_RXD_OPENS = LOCKED_AT + T_RXD
RESUME = "resume_interrupted_fund"


def _funding_tx(htlc_spk: bytes, *, amount: int = AMOUNT_SATS, change_first: bool = False) -> bytes:
    """A real (unsigned, legacy-serialised) transaction whose output 0 pays *htlc_spk* *amount*, with
    a change output: what ``taker_funds_btc`` records before its broadcast, as far as the tower reads it.
    ``change_first`` puts the change at output 0 and the HTLC at output 1."""
    change_spk = b"\x00\x14" + b"\x55" * 20
    htlc_out = amount.to_bytes(8, "little") + bytes([len(htlc_spk)]) + htlc_spk
    change_out = (5_000).to_bytes(8, "little") + bytes([len(change_spk)]) + change_spk
    outs = change_out + htlc_out if change_first else htlc_out + change_out
    return (
        (2).to_bytes(4, "little")
        + b"\x01"
        + os.urandom(32)
        + (0).to_bytes(4, "little")
        + b"\x00"
        + b"\xff\xff\xff\xff"
        + b"\x02"
        + outs
        + (0).to_bytes(4, "little")
    )


class _PendingChain(FakeBtcChain):
    """The fake chain, funded by a real transaction (so its txid is the one the record's bytes give),
    whose funding may be unmined (``funding_height=None``) or seen by no source (``funding_seen``)."""

    def __post_init__(self) -> None:
        super().__post_init__()
        self.funding_raw = _funding_tx(self.htlc.scriptpubkey)
        self.funding_txid = t.btc_txid_from_raw(self.funding_raw)
        self.locator = self.htlc.with_funding(t.BtcOutpoint(txid=self.funding_txid, vout=0), AMOUNT_SATS)
        self.funding_seen = True

    def funding_confirmations(self, at_head: int | None = None) -> int:
        if self.funding_height is None:
            return 0
        return super().funding_confirmations(at_head)

    def block_hash(self, height: int) -> str:
        if self.funding_height is None:
            return f"{self.fork}h{height}"
        return super().block_hash(height)

    def at_depth(self, depth: int) -> None:
        """Put the funding *depth* blocks deep (0: in the mempool)."""
        self.funding_height = None if depth == 0 else self.head - depth + 1


class _PendingSource(FakeBtcSource):
    """A fake source that also reads an unmined or unknown funding tx, and can lie about its depth."""

    def __init__(self, chain: _PendingChain, *, lie_funding_depth: int | None = None, **kw) -> None:
        super().__init__(chain, **kw)
        self.lie_funding_depth = lie_funding_depth
        self.funding_reads_fail = False

    def _height_of(self, txid: str) -> int | None:
        if txid == self.chain.funding_txid:
            if not self.chain.funding_seen:
                raise NetworkError(f"transaction {txid[:16]}… not found")
            height = self.chain.funding_height
            return height if height is not None and height <= self.head else None
        return super()._height_of(txid)

    async def confirmations(self, txid: str) -> int:
        if txid == self.chain.funding_txid and self.funding_reads_fail:
            raise NetworkError("tx status: 503")
        if txid == self.chain.funding_txid and self.lie_funding_depth is not None:
            self._up()
            return self.lie_funding_depth
        return await super().confirmations(txid)


class _Rxd:
    """A Radiant source that counts covenant reads."""

    def __init__(self) -> None:
        self.tip = TIP
        self.cov_confs: int | None = COV_CONFS
        self.covenant_reads = 0
        self.covenant_fails = False  # below quorum: every covenant read raises

    async def tip_height(self) -> ChainHeight:
        return ChainHeight(self.tip)

    async def covenant_confirmations(self, outpoint: str) -> Confirmations | None:
        self.covenant_reads += 1
        if self.covenant_fails:
            raise NetworkError("covenant depth below quorum")
        return None if self.cov_confs is None else Confirmations(self.cov_confs)


class _Channel:
    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, page) -> None:
        self.sent.append(page)


class _Tower:
    """One taker's interrupted BTC fund, watched by the production observer, store and reconciler."""

    def __init__(
        self,
        tmp_path,
        *,
        depth: int = 1,
        role: RecordRole | None = RecordRole.TAKER,
        grace: int = G,
        hold: int = 2,
    ) -> None:
        self.chain = _PendingChain()
        self.chain.at_depth(depth)
        self.sources = [_PendingSource(self.chain) for _ in range(3)]
        self.reader = MultiSourceBtcFundingReader(self.sources, quorum=2)
        self.dir = tmp_path / "records"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.terms = dataclasses.replace(
            _terms(hashlock=self.chain.hashlock, t_btc_blocks=self.chain.t_btc_blocks, t_rxd_blocks=T_RXD),
            btc_claim_pubkey_xonly=_xonly(self.chain.maker),
            btc_refund_pubkey_xonly=_xonly(self.chain.taker),
        )
        # As taker_funds_btc leaves it: the covenant pinned, the funding bytes written, no locator.
        self.write(
            dataclasses.replace(
                SwapRecord(state=SwapState.NEGOTIATED, terms=self.terms, role=role).with_radiant_lock(_COVENANT, "51"),
                pending_btc_funding_tx=self.chain.funding_raw.hex(),
            )
        )
        self.rxd = _Rxd()
        self.grace = grace
        self.channel = _Channel()
        self.alerter = DedupAlerter(channel=self.channel, situation_hold_ticks=hold)
        self.store = JsonDirRecordStore(self.dir)
        self.build_observer()

    def build_observer(self, outspend_fns=None) -> None:
        src = OutspendBtcClaimSource(
            outspend_fns=outspend_fns or [_outspend(s) for s in self.sources], funding_reader=self.reader
        )
        self.observer = ChainObserver(
            btc=src, rxd=self.rxd, btc_burial_blocks=BURIAL, btc_network="bcrt", unrecorded_fund_grace_blocks=self.grace
        )

    def write(self, record: SwapRecord) -> None:
        (self.dir / f"{SWAP}.json").write_text(json.dumps(record.to_dict()))

    def record(self) -> SwapRecord:
        return SwapRecord.from_dict(json.loads((self.dir / f"{SWAP}.json").read_text()))

    def record_the_lock(self) -> None:
        """What a runner still alive (or ``resume_interrupted_fund``) does once the fund confirms."""
        self.write(self.record().with_counter_lock(self.chain.locator).with_state(SwapState.BTC_LOCKED))

    def reconciler(self, *, executor=None) -> Reconciler:
        return Reconciler(
            store=self.store,
            observer=self.observer,
            alerter=self.alerter,
            policy=_policy(),
            safety_window_blocks=6,
            executor=executor,
        )

    async def observe(self) -> Observations:
        return await self.observer.observe(SWAP, self.record())

    async def decide(self):
        return decide(record=self.record(), observations=await self.observe(), policy=_policy(), safety_window_blocks=6)

    def presign(self) -> None:
        blob = PresignedRefund(raw_tx=self.chain.refund_tx(), swap_id=SWAP)
        (self.dir / f"{SWAP}.refund.json").write_text(json.dumps(blob.to_dict()))

    def executor(self) -> RefundExecutor:
        return RefundExecutor(
            broadcaster=self.sources[0],
            blobs_dir=self.dir,
            network="bcrt",
            cap_sats=AMOUNT_SATS,
            refund_spk=REFUND_SPK,
            accept_single_source=True,
        )

    def near_t_rxd(self) -> None:
        self.rxd.tip = T_RXD_OPENS - 3
        self.rxd.cov_confs = self.rxd.tip - LOCKED_AT + 1


def _mine_claim(w: _Tower, *, buried: int = BURIAL) -> None:
    w.chain.submit(w.chain.claim_tx())
    w.chain.mine(buried)


# --------------------------------------------------------------------------- the record and the outpoint


def test_the_outpoint_is_output_0_of_the_records_own_bytes(tmp_path):
    w = _Tower(tmp_path)
    rec = w.record()
    assert is_unrecorded_btc_fund(rec)
    loc = unrecorded_btc_fund_locator(rec, network="bcrt")
    assert loc.funding_outpoint == t.BtcOutpoint(txid=w.chain.funding_txid, vout=0)
    assert loc.amount_sats == AMOUNT_SATS
    assert loc.script_tree.claim_script == w.chain.htlc.script_tree.claim_script


def test_bytes_that_do_not_pay_this_swaps_htlc_are_refused(tmp_path):
    w = _Tower(tmp_path)
    for raw in (
        _funding_tx(b"\x51\x20" + b"\x66" * 32),
        _funding_tx(w.chain.htlc.scriptpubkey, amount=AMOUNT_SATS - 1),
        # P12 (combined Mythos pass, 1.5): the HTLC at output 1 is not the fund's outpoint.
        _funding_tx(w.chain.htlc.scriptpubkey, change_first=True),
    ):
        rec = dataclasses.replace(w.record(), pending_btc_funding_tx=raw.hex())
        with pytest.raises(ValidationError, match="does not pay this swap's HTLC"):
            unrecorded_btc_fund_locator(rec, network="bcrt")


def test_the_lock_view_refuses_a_record_without_an_unrecorded_fund(tmp_path):
    """P11 (combined Mythos pass, 1.5): the BTC_LOCKED view is only for a record that is one."""
    w = _Tower(tmp_path)
    rec = w.record()
    assert unrecorded_lock_view(rec).state is SwapState.BTC_LOCKED, "the honest twin"
    for other in (
        dataclasses.replace(rec, pending_btc_funding_tx=None),
        dataclasses.replace(rec, role=RecordRole.MAKER),
        dataclasses.replace(rec, state=SwapState.BTC_LOCKED),
    ):
        with pytest.raises(ValidationError, match="needs a record with an unrecorded BTC fund"):
            unrecorded_lock_view(other)


def test_only_a_negotiated_takers_unrecorded_btc_fund_is_one(tmp_path):
    w = _Tower(tmp_path)
    rec = w.record()
    assert is_unrecorded_btc_fund(rec)
    assert is_unrecorded_btc_fund(dataclasses.replace(rec, role=None)), "a role-less record is the taker's"
    assert is_unrecorded_btc_fund(dataclasses.replace(rec, role=RecordRole.NONE))
    assert not is_unrecorded_btc_fund(dataclasses.replace(rec, role=RecordRole.MAKER))
    assert not is_unrecorded_btc_fund(dataclasses.replace(rec, pending_btc_funding_tx=None))
    assert not is_unrecorded_btc_fund(rec.with_counter_lock(w.chain.locator))


def test_engaged_threshold_is_the_grace_or_t_btc_when_that_is_sooner(tmp_path):
    rec = _Tower(tmp_path).record()  # t_btc 10 blocks
    kw = {"spend_seen": False, "grace_blocks": 3}
    assert not unrecorded_fund_engaged(rec, deepest_confirmations=None, **kw)
    assert not unrecorded_fund_engaged(rec, deepest_confirmations=2, **kw)
    assert unrecorded_fund_engaged(rec, deepest_confirmations=3, **kw)
    assert unrecorded_fund_engaged(rec, deepest_confirmations=0, spend_seen=True, grace_blocks=3)
    assert not unrecorded_fund_engaged(rec, deepest_confirmations=9, spend_seen=False, grace_blocks=50)
    assert unrecorded_fund_engaged(rec, deepest_confirmations=10, spend_seen=False, grace_blocks=50), "t_btc first"


def test_the_observer_refuses_a_grace_that_is_not_a_positive_int(tmp_path):
    w = _Tower(tmp_path)
    src = OutspendBtcClaimSource(outspend_fns=[_outspend(w.sources[0])], funding_reader=w.reader)
    for bad in (0, -1, True, 2.5):
        with pytest.raises(ValidationError, match="unrecorded_fund_grace_blocks"):
            ChainObserver(btc=src, rxd=w.rxd, btc_burial_blocks=BURIAL, unrecorded_fund_grace_blocks=bad)
    with pytest.raises(ValidationError, match="btc_network"):
        ChainObserver(btc=src, rxd=w.rxd, btc_burial_blocks=BURIAL, btc_network="")


# --------------------------------------------------------------------------- a healthy fund pages nothing


async def test_a_healthy_fund_pages_nothing_and_reads_no_covenant_until_it_is_recorded(tmp_path):
    w = _Tower(tmp_path, depth=0)
    rec = w.reconciler()
    for depth in (0, 0, 1, 1):
        w.chain.at_depth(depth)
        (res,) = await rec.tick()
        assert res.decision.intent is Intent.WATCH, res.decision.reason
        assert w.alerter.unacked_critical_count() == 0
    assert w.rxd.covenant_reads == 0, "a covenant read during a healthy fund pages an RXD source below quorum"
    w.record_the_lock()
    for _ in range(3):
        (res,) = await rec.tick()
        assert res.decision.intent is Intent.WATCH
    assert w.channel.sent == []
    assert w.alerter.unacked_critical_count() == 0


async def test_a_fund_no_source_has_seen_is_watched_and_reads_no_covenant(tmp_path):
    w = _Tower(tmp_path, depth=0)
    w.chain.funding_seen = False  # evicted, conflicted, or never sent
    for _ in range(3):
        (res,) = await w.reconciler().tick()
        assert res.decision.intent is Intent.WATCH
        assert "no source reports it" in res.decision.reason
    assert w.channel.sent == [] and w.rxd.covenant_reads == 0


async def test_a_failed_covenant_read_once_engaged_still_pages(tmp_path):
    """Once the BTC side engages, the lock rules need the covenant, so a failed read is the reconcile
    error it is for a recorded lock (the observer engages on the deepest depth, as decide())."""
    w = _Tower(tmp_path, depth=0)
    w.sources[0].lie_funding_depth = G
    w.rxd.covenant_fails = True
    (res,) = await w.reconciler().tick()
    assert res.error is not None
    assert [p.severity for p in w.channel.sent] == [Severity.CRITICAL]


# --------------------------------------------------------------------------- a fund that went quiet


async def test_an_interrupted_fund_at_the_grace_depth_pages_warn_once_with_a_source_lagging(tmp_path):
    w = _Tower(tmp_path, depth=G)
    w.sources[2].lag = G  # this source has not seen the funding block yet
    rec = w.reconciler()
    for _ in range(4):
        (res,) = await rec.tick()
        assert res.decision.intent is Intent.PAGE_RESUME_FUND, res.decision.reason
        assert res.decision.situation == SITUATION_UNRECORDED_FUND_STOPPED
        assert res.decision.recommended_action.startswith(RESUME)
        assert not (res.decision.autonomous_btc_refund or res.decision.autonomous_asset_claim)
    assert [p.severity for p in w.channel.sent] == [Severity.WARN]
    assert w.rxd.covenant_reads > 0


async def test_the_resume_warn_quotes_the_lock_rules_without_saying_nothing_else_is_due(tmp_path):
    """Combined Mythos pass, 1.4b: the WARN said "Nothing else is due yet: maker revealed p; awaiting
    burial", which reads as calm while p is public. It now quotes the lock rules as what they are."""
    w = _Tower(tmp_path, depth=G)
    _mine_claim(w, buried=1)
    d = await w.decide()
    assert d.intent is Intent.PAGE_RESUME_FUND, d.reason
    assert "Nothing else is due" not in d.reason
    assert "The rules for a recorded lock read: maker revealed p" in d.reason


async def test_an_unrecorded_fund_below_the_grace_depth_does_not_page(tmp_path):
    """The honest twin: a runner still inside its poll window is left alone."""
    w = _Tower(tmp_path, depth=G - 1)
    for _ in range(3):
        (res,) = await w.reconciler().tick()
        assert res.decision.intent is Intent.WATCH
    assert w.channel.sent == []


async def test_one_source_reporting_the_grace_depth_is_enough_to_page(tmp_path):
    """The WARN reads the deepest source, not the quorum: two sources at 0 cannot hold it down. One
    lying source can raise it: a spurious page, the safe direction."""
    w = _Tower(tmp_path, depth=0)
    w.sources[0].lie_funding_depth = G
    d = await w.decide()
    assert d.intent is Intent.PAGE_RESUME_FUND, d.reason
    assert (await w.observe()).btc_funding_confirmations == 0, "the quorum depth is still 0"


async def test_the_observer_reads_the_covenant_when_only_the_deepest_source_reaches_the_grace(tmp_path):
    """The observer and decide() must engage on the same depth: decide() reads the deepest source, so an
    observer gating on the quorum depth would leave the covenant unread under rules that need it."""
    w = _Tower(tmp_path, depth=0)
    w.sources[0].lie_funding_depth = G
    obs = await w.observe()
    assert w.rxd.covenant_reads == 1
    assert obs.asset_locked_at_height == ChainHeight(LOCKED_AT)


async def test_the_observer_reads_the_covenant_when_a_spender_is_named_that_is_not_a_claim(tmp_path):
    """Our own refund in the mempool names a spender without setting the claim trigger. decide() engages
    on it, so the observer must read the covenant too."""
    w = _Tower(tmp_path, depth=w_depth_past_t_btc())
    w.chain.submit(w.chain.refund_tx())
    for s in w.sources:
        s.funding_reads_fail = True  # no depth at all: only the spender engages
    obs = await w.observe()
    assert obs.btc_spenders_named and not obs.maker_has_claimed_btc and obs.btc_unrecorded_fund_deepest is None
    assert w.rxd.covenant_reads == 1
    # P10 (combined Mythos pass, 1.5): decide() engages on the named spender alone, so the reason is the
    # lock rules' (behind the lead), not the pre-engagement "nothing spends it".
    d = await w.decide()
    assert "the record never took the lock" in d.reason and "nothing spends it" not in d.reason, d.reason
    # ... and the observer engaged too: a failed covenant read is now the reconcile error.
    w.rxd.covenant_fails = True
    with pytest.raises(NetworkError):
        await w.observe()


async def test_one_source_claiming_an_unseen_fund_near_t_rxd_pages_critical_and_never_broadcasts(tmp_path):
    """Pinned on purpose (review of #842): one source is then the only evidence that BTC sits in an HTLC
    the maker can claim after refunding the covenant at t_rxd. The tower fails toward the page, which
    says the maturity could not be read; it never arms a broadcast."""
    w = _Tower(tmp_path, depth=0)
    w.chain.funding_seen = False
    w.sources[0].lie_funding_depth = G
    w.near_t_rxd()
    w.presign()
    (res,) = await w.reconciler(executor=w.executor()).tick()
    d = res.decision
    assert d.intent is Intent.PAGE_REFUND and d.urgent is True, d.reason
    assert "could not be read" in d.reason
    assert d.autonomous_btc_refund is False and res.executed is None
    assert [p.severity for p in w.channel.sent] == [Severity.CRITICAL]


@pytest.mark.parametrize("seen", [True, False], ids=["in-mempool", "seen-by-no-source"])
async def test_known_gap_a_fund_not_yet_engaged_near_t_rxd_is_watched(tmp_path, seen):
    """Pinned known gap (combined Mythos pass, 1.1): a fund not yet engaged (unconfirmed, or seen by no
    source) is watched in silence near t_rxd, though bytes that confirm then let the maker refund the
    covenant and still claim the BTC. Two attempts to page it were wrong (too late; the tower's margin
    is not the runner's), so it waits for a design. When that lands, this test changes."""
    w = _Tower(tmp_path, depth=0)
    w.chain.funding_seen = seen
    w.near_t_rxd()
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.WATCH and w.channel.sent == []
    assert w.rxd.covenant_reads == 0


async def test_the_deepest_source_survives_the_others_failing(tmp_path):
    w = _Tower(tmp_path, depth=G)
    w.sources[0].down = True
    w.sources[1].down = True
    assert (await w.observe()).btc_unrecorded_fund_deepest == G


# --------------------------------------------------------------------------- a claim on the unrecorded fund


async def test_a_buried_claim_on_an_unrecorded_fund_pages_the_claim_race_naming_the_resume_first(tmp_path):
    w = _Tower(tmp_path, depth=1)
    _mine_claim(w)
    rec = w.reconciler()
    (res,) = await rec.tick()
    d = res.decision
    assert d.intent is Intent.PAGE_CLAIM, d.reason
    assert d.situation == SITUATION_UNRECORDED_FUND_PREFIX + SITUATION_CLAIM_RACE
    assert d.recommended_action.startswith(RESUME + " ")
    assert "reconcile_counter_leg" in d.recommended_action
    assert d.autonomous_asset_claim is False, "a claim the record cannot run must not arm the ClaimExecutor"
    assert [p.severity for p in w.channel.sent] == [Severity.CRITICAL]
    assert w.alerter.unacked_critical_count() == 1


async def test_the_same_claim_on_a_recorded_lock_arms_the_claim(tmp_path):
    """The honest twin: once the lock is on the record the BTC_LOCKED rules apply unchanged."""
    w = _Tower(tmp_path, depth=1)
    _mine_claim(w)
    w.record_the_lock()
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM and d.situation == SITUATION_CLAIM_RACE
    assert d.autonomous_asset_claim is True
    assert not d.recommended_action.startswith(RESUME)


async def test_a_lying_primary_that_hides_the_claim_does_not_suppress_the_page(tmp_path):
    w = _Tower(tmp_path, depth=1)
    _mine_claim(w)
    w.sources[0].hide_spender = True  # the first source reads the outpoint unspent
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM, d.reason


async def test_an_ack_before_the_resume_does_not_carry_over_to_the_recorded_swap(tmp_path):
    w = _Tower(tmp_path, depth=1)
    _mine_claim(w)
    rec = w.reconciler()
    (res,) = await rec.tick()
    key = f"{Intent.PAGE_CLAIM.value}:{res.decision.situation}"
    assert _ACK_LINE_RE.match(f"{SWAP} {key}"), "the inbox must accept the page's ack: line"
    assert w.alerter.ack(SWAP, key) is True
    await rec.tick()
    assert len(w.channel.sent) == 1, "the ACK held while the situation was open"
    w.record_the_lock()
    (res,) = await rec.tick()
    # The recorded swap's claim may be armed, so #976 suffixes the executor's outcome (claim_race:none).
    situation = res.decision.situation
    assert situation == SITUATION_CLAIM_RACE or situation.startswith(SITUATION_CLAIM_RACE + ":"), situation
    assert len(w.channel.sent) == 2, "the recorded swap's claim page was silenced by the unrecorded one's ACK"
    assert w.alerter.unacked_critical_count() == 1


# --------------------------------------------------------------------------- a refund that falls due


async def test_a_matured_unrecorded_fund_pages_the_refund_and_never_broadcasts(tmp_path):
    w = _Tower(tmp_path, depth=w_depth_past_t_btc())
    w.presign()  # even with a pre-signed refund on disk beside the record
    (res,) = await w.reconciler(executor=w.executor()).tick()
    d = res.decision
    assert d.intent is Intent.PAGE_REFUND, d.reason
    assert d.situation == SITUATION_UNRECORDED_FUND_PREFIX + SITUATION_BTC_REFUND_DUE
    assert d.recommended_action.startswith(RESUME) and "taker_refund_btc" in d.recommended_action
    assert d.autonomous_btc_refund is False
    assert res.executed is None
    assert w.chain.mempool is None and all(not s.broadcasts for s in w.sources)
    # 1.4a/1.4c: the recorded lock's armed-refund note is false here, and every sentence ends.
    assert "If this tower is armed" not in d.reason
    assert ". Not autonomous: the lock is not on the record." in d.reason


async def test_a_matured_unrecorded_fund_with_no_covenant_ends_each_sentence(tmp_path):
    """1.4c: the never-locked page's reason ends without a full stop; the suffix must not run on."""
    w = _Tower(tmp_path, depth=w_depth_past_t_btc())
    w.write(dataclasses.replace(w.record(), radiant_covenant_outpoint=None))
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and "maker never locked" in d.reason, d.reason
    assert "leg. Not autonomous: the lock is not on the record." in d.reason
    # With the spender unclassified the inner reason has no note and no full stop of its own.
    obs = dataclasses.replace(
        await w.observe(), btc_spend_classified=False, btc_disposition=None, btc_disposition_reason=None
    )
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_REFUND and "If this tower is armed" not in d.reason, d.reason
    assert "leg. Not autonomous: the lock is not on the record." in d.reason


async def test_the_same_matured_fund_once_recorded_is_autonomous(tmp_path):
    """The honest twin: the recorded lock with its pre-signed refund broadcasts as before."""
    w = _Tower(tmp_path, depth=w_depth_past_t_btc())
    w.presign()
    w.record_the_lock()
    (res,) = await w.reconciler(executor=w.executor()).tick()
    assert res.decision.autonomous_btc_refund is True
    assert res.executed is ExecOutcome.BROADCAST


async def test_a_matured_unrecorded_fund_near_t_rxd_is_critical(tmp_path):
    w = _Tower(tmp_path, depth=w_depth_past_t_btc())
    w.near_t_rxd()
    rec = w.reconciler()
    for _ in range(2):
        (res,) = await rec.tick()
        assert res.decision.intent is Intent.PAGE_REFUND and res.decision.urgent is True
    assert [p.severity for p in w.channel.sent] == [Severity.CRITICAL, Severity.CRITICAL]


def w_depth_past_t_btc() -> int:
    return FakeBtcChain().t_btc_blocks + 1


# --------------------------------------------------------------------------- what it leaves alone


async def test_a_corrupt_pending_fund_pages_rather_than_watching(tmp_path):
    w = _Tower(tmp_path)
    w.write(dataclasses.replace(w.record(), pending_btc_funding_tx=_funding_tx(b"\x51\x20" + b"\x66" * 32).hex()))
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_SQUEEZED
    assert "does not pay this swap's HTLC" in res.decision.reason
    assert [p.severity for p in w.channel.sent] == [Severity.CRITICAL]


async def test_a_makers_record_carrying_funding_bytes_is_not_read_as_a_taker_fund(tmp_path):
    w = _Tower(tmp_path, depth=G, role=RecordRole.MAKER)
    d = await w.decide()
    assert d.intent is Intent.WATCH and d.reason == "no action due in negotiated"
    assert w.rxd.covenant_reads == 0


async def test_an_observer_that_does_not_read_the_fund_keeps_the_old_watch(tmp_path):
    w = _Tower(tmp_path, depth=G)
    obs = Observations(maker_has_claimed_btc=False, now_rxd_height=ChainHeight(TIP))
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.WATCH and "does not read the unrecorded BTC fund" in d.reason


def test_the_unrecorded_fund_fields_are_validated():
    base = {"maker_has_claimed_btc": False, "now_rxd_height": ChainHeight(TIP)}
    with pytest.raises(ValidationError, match="grace_blocks is set exactly"):
        Observations(**base, btc_unrecorded_fund=True)
    with pytest.raises(ValidationError, match="grace_blocks is set exactly"):
        Observations(**base, btc_unrecorded_fund_grace_blocks=3)
    with pytest.raises(ValidationError, match="deepest needs it"):
        Observations(**base, btc_unrecorded_fund_deepest=Confirmations(1))
    with pytest.raises(ValidationError, match="positive int"):
        Observations(**base, btc_unrecorded_fund=True, btc_unrecorded_fund_grace_blocks=0)
    Observations(**base, btc_unrecorded_fund=True, btc_unrecorded_fund_grace_blocks=3)  # the honest twin


def test_the_resume_gate_refuses_a_re_send_wherever_the_tower_says_t_rxd_is_near(tmp_path):
    """Combined Mythos pass, 1.3: near t_rxd the pages for an unrecorded fund start with
    ``resume_interrupted_fund``. Pin the order of the two rules: the resume's own pre-lock gate
    (``assert_timelock_margin`` with the covenant's age elapsed) refuses a re-send at every covenant age
    where the tower's safety window is open, so near t_rxd a resume can only record a fund that has
    already confirmed (``resume_interrupted_fund`` records that with no gate), never send one. The two
    rules use different margins, so this holds for the policy here, not for every pairing."""
    # This module's terms fail the margin at age 0 already, which would make the pin vacuous: widen t_rxd
    # so the gate passes at a young covenant (asserted below) and the pin can fail.
    terms = dataclasses.replace(_Tower(tmp_path).record().terms, t_rxd=t.Timelock(200, t.TimeUnit.BLOCKS))
    policy = _policy()
    assert_timelock_margin(terms.t_btc, terms.t_rxd, policy, elapsed_blocks=1)  # the honest twin
    window_open_ages = []
    for age in range(1, terms.t_rxd.value + 10):
        if not taker_refund_window_open(
            now_block_height=ChainHeight(LOCKED_AT + age - 1),
            asset_locked_at_height=ChainHeight(LOCKED_AT),
            t_rxd=terms.t_rxd,
            safety_window_blocks=6,
            maker_has_claimed_btc=False,
            block_interval_s=policy.block_interval_s,
        ):
            continue
        window_open_ages.append(age)
        with pytest.raises(ValidationError):
            assert_timelock_margin(terms.t_btc, terms.t_rxd, policy, elapsed_blocks=age)
    assert window_open_ages, "the window never opened: the pin checked nothing"

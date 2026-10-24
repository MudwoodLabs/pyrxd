"""The 9b refund pages as the operator receives them (#850 PR 9b, Mythos review of 7d008c2).

The other 9b tests hand every decision to a recorder that never dedups or ACKs. These run the same
tower through the production ``DedupAlerter``, which is what decides whether a page reaches the
operator twice, and cover the fixes for the Mythos findings:

* F1: an ACK of "our refund is pending near t_rxd" silenced the claim race that replaced the refund,
  because both are PAGE_SQUEEZED and the ACK was keyed on the intent.
* F2: the armed refund page said the tower broadcasts, whatever the executor did.
* F3: an unspent, refund-due HTLC near or past t_rxd paged WARN once.
* F4: a spender only discovery named, beside our buried refund, was paged as a served claim witness.
* F5: the refund the page named was the smallest txid seen, not the buried one.
* F6: a quorum-1 read was acted on like a corroborated one.

Every refusal has its honest twin.
"""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.disposition import BtcDispositionKind
from pyrxd.gravity.swap_state import SwapState
from pyrxd.gravity.watch.adapters import OutspendBtcClaimSource
from pyrxd.gravity.watch.alerts import DedupAlerter, Severity
from pyrxd.gravity.watch.decide import (
    SITUATION_BTC_DISCOVERY_DISAGREES,
    SITUATION_BTC_REFUND_PENDING,
    SITUATION_BTC_SPENDER_CONTRADICTION,
    Decision,
    Intent,
    decide,
)
from pyrxd.gravity.watch.executor import ExecOutcome
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.security.errors import ValidationError
from tests.test_watch_btc_spender_classification import (
    BURIAL,
    COV_CONFS,
    SWAP,
    T_RXD,
    TIP,
    _outspend,
    _policy,
    _Tower,
)

LOCKED_AT = TIP - COV_CONFS + 1
T_RXD_OPENS = LOCKED_AT + T_RXD


class _Channel:
    """The delivery transport: keeps every page the alerter actually sends."""

    def __init__(self) -> None:
        self.sent: list = []

    async def send(self, page) -> None:
        self.sent.append(page)


def _alerter() -> tuple[DedupAlerter, _Channel]:
    ch = _Channel()
    return DedupAlerter(channel=ch), ch


def _at(w: _Tower, tip: int) -> None:
    """Move the RXD tip, keeping the covenant mined at LOCKED_AT."""
    w.rxd.tip = tip
    w.rxd.cov_confs = tip - LOCKED_AT + 1


def _near(w: _Tower, past: int = 0) -> None:
    _at(w, T_RXD_OPENS - 3 + past)


# --------------------------------------------------------------------------- F1: an ACK binds to its situation


async def test_an_ack_of_the_pending_refund_page_does_not_silence_the_claim_that_replaces_it(tmp_path):
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    _near(w)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    (first,) = await rec.tick()
    assert first.decision.intent is Intent.PAGE_SQUEEZED
    assert first.decision.situation == SITUATION_BTC_REFUND_PENDING
    assert len(ch.sent) == 1 and ch.sent[0].severity is Severity.CRITICAL
    assert alerter.ack(SWAP) is True
    # The maker replaces our unburied refund with a claim (the claim leaf has no timelock).
    w.chain.submit(w.chain.claim_tx(fee_sats=5_000))
    (race,) = await rec.tick()
    assert race.decision.intent is Intent.PAGE_SQUEEZED, race.decision.reason
    assert race.decision.situation is None, "the claim race carries no refund tag"
    assert len(ch.sent) == 2, "the ACK of the refund page silenced the claim race"
    assert alerter.unacked_critical_count() == 1


async def test_an_ack_still_holds_while_the_pending_refund_page_is_unchanged(tmp_path):
    """The honest twin: the operator who ACKed the refund page is not paged again for it."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    _near(w)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    await rec.tick()
    assert alerter.ack(SWAP) is True
    for _ in range(3):
        await rec.tick()
    assert len(ch.sent) == 1
    assert alerter.unacked_critical_count() == 0


def test_a_situation_tag_must_name_something():
    with pytest.raises(ValidationError, match="situation"):
        Decision(Intent.PAGE_SQUEEZED, reason="r", situation="")


# --------------------------------------------------------------------------- F2: the page says what the executor did


async def test_an_alert_only_tower_never_says_it_broadcast_the_refund(tmp_path):
    w = _Tower(tmp_path)
    (res,) = await w.reconciler().tick()  # no executor: the shipped default
    d = res.decision
    assert d.autonomous_btc_refund is True and res.executed is None
    assert "did NOT broadcast" in d.reason
    assert "The tower broadcasts" not in d.reason
    assert w.chain.mempool is None
    assert w.pages.got[0][1].reason == d.reason, "the routed page is not the one reported"


async def test_a_declining_executor_is_said_too(tmp_path):
    w = _Tower(tmp_path)  # no pre-signed blob on disk: the executor declines
    (res,) = await w.reconciler(executor=w.executor()).tick()
    assert res.executed is ExecOutcome.DECLINED
    assert "did NOT broadcast" in res.decision.reason


async def test_a_broadcast_is_said_when_it_happened(tmp_path):
    """The honest twin: an armed tower that broadcast says so."""
    w = _Tower(tmp_path)
    w.presign()
    (res,) = await w.reconciler(executor=w.executor()).tick()
    assert res.executed is ExecOutcome.BROADCAST
    assert "broadcast the pre-signed refund" in res.decision.reason
    assert "did NOT" not in res.decision.reason


async def test_decide_itself_never_asserts_a_broadcast(tmp_path):
    d = await _Tower(tmp_path).decide()
    assert d.autonomous_btc_refund is True
    assert "If this tower is armed" in d.reason and "The tower broadcasts" not in d.reason


# --------------------------------------------------------------------------- F3: unspent near t_rxd is urgent


@pytest.mark.parametrize("past", [0, 60], ids=["near", "past"])
async def test_an_unspent_refund_due_htlc_near_t_rxd_re_pages_critical_and_stays_armed(tmp_path, past):
    w = _Tower(tmp_path)
    _near(w, past)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    for _ in range(3):
        (res,) = await rec.tick()
        assert res.decision.intent is Intent.PAGE_REFUND and res.decision.urgent is True
        assert res.decision.autonomous_btc_refund is True, "the urgency dropped the autonomy"
    assert [p.severity for p in ch.sent] == [Severity.CRITICAL] * 3


async def test_an_unspent_refund_due_htlc_far_from_t_rxd_pages_warn_once(tmp_path):
    """The honest twin: early in the window the refund page is a WARN, sent once."""
    w = _Tower(tmp_path)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    for _ in range(3):
        (res,) = await rec.tick()
        assert res.decision.urgent is False
    assert [p.severity for p in ch.sent] == [Severity.WARN]


async def test_a_role_less_record_near_t_rxd_is_urgent_too(tmp_path):
    """No autonomy to fall back on: the operator is the only refund."""
    w = _Tower(tmp_path, role=None)
    _near(w)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.urgent is True and d.autonomous_btc_refund is False


async def test_both_locked_refund_due_is_urgent(tmp_path):
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    _near(w)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.recommended_action == "mutual_refund" and d.urgent is True


async def test_params_mismatch_matured_near_t_rxd_is_urgent(tmp_path):
    w = _Tower(tmp_path, state=SwapState.PARAMS_MISMATCH)
    _near(w)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.urgent is True
    far = _Tower(tmp_path / "far", state=SwapState.PARAMS_MISMATCH)
    assert (await far.decide()).urgent is False


async def test_a_legacy_unspent_htlc_past_t_rxd_re_pages_critical(tmp_path):
    w = _Tower(tmp_path)
    w.write(w.record().with_state(SwapState.ABORTED))
    _at(w, T_RXD_OPENS + 60)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    for _ in range(3):
        (res,) = await rec.tick()
        assert res.legacy is True and res.decision.intent is Intent.PAGE_REFUND and res.decision.urgent is True
    assert [p.severity for p in ch.sent] == [Severity.CRITICAL] * 3


async def test_a_legacy_unspent_htlc_with_no_covenant_pin_is_urgent(tmp_path):
    """Pre-0.27 records pin no covenant: the tower cannot say where t_rxd is, so it fails toward urgent."""
    w = _Tower(tmp_path, covenant=False)
    w.write(w.record().with_state(SwapState.ABORTED))
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_REFUND and res.decision.urgent is True


async def test_a_legacy_unspent_htlc_far_from_t_rxd_is_a_warn(tmp_path):
    """The honest twin: a pinned covenant far from t_rxd."""
    w = _Tower(tmp_path)
    w.write(w.record().with_state(SwapState.ABORTED))
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_REFUND and res.decision.urgent is False


@pytest.mark.parametrize("intent", [i for i in Intent if i is not Intent.PAGE_REFUND])
def test_only_a_refund_page_can_be_urgent(intent):
    assert len(Intent) > 1
    with pytest.raises(ValidationError, match="urgent"):
        Decision(intent, reason="r", urgent=True)


# --------------------------------------------------------------------------- F4: a discovery-only spender


def _stale_discovery(w: _Tower, txid: str) -> None:
    """Put a discovery source first that names *txid* as the outpoint's spender, serving no bytes."""

    async def stale(funding_txid: str, vout: int):
        return True, txid

    src = OutspendBtcClaimSource(outspend_fns=[stale] + [_outspend(s) for s in w.sources], funding_reader=w.reader)
    w.observer = ChainObserver(btc=src, rxd=w.rxd, btc_burial_blocks=BURIAL)


async def test_a_spender_only_discovery_names_beside_our_buried_refund_is_not_a_served_claim(tmp_path):
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    _stale_discovery(w, "ab" * 32)
    obs = await w.observe()
    assert obs.btc_disposition is BtcDispositionKind.REFUNDED and obs.maker_has_claimed_btc is True
    assert obs.btc_claim_witness_seen is False
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_SQUEEZED, d.reason
    assert "no source served" in d.reason
    assert "a claim witness a source served" not in d.reason
    assert "recover-preimage" not in (d.recommended_action or "")


async def test_a_legacy_record_with_a_discovery_only_spender_is_never_marked(tmp_path):
    w = _Tower(tmp_path)
    w.write(w.record().with_state(SwapState.ABORTED))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    _stale_discovery(w, "ab" * 32)
    _at(w, T_RXD_OPENS + 10)
    (res,) = await w.reconciler().tick()
    assert res.legacy is True and res.decision.intent is Intent.PAGE_SQUEEZED, res.decision.reason
    assert res.alert_delivered is True
    assert not w.store.legacy_marker_path(SWAP).exists()


async def test_a_served_claim_witness_beside_our_buried_refund_still_pages_the_covenant_claim(tmp_path):
    """The honest twin: a claim whose bytes a source served is D14, p is public."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    w.sources[2].forge_spender = w.chain.claim_tx()
    obs = await w.observe()
    assert obs.btc_claim_witness_seen is True
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_CLAIM and "recover-preimage" in d.recommended_action


# --------------------------------------------------------------------------- F5: the refund the page names


def _replaced_pair(w: _Tower) -> tuple[bytes, bytes]:
    """Two refunds R1 (first) and R2 (its bump), with R1's txid the smaller, so the old rule names R1."""
    first = w.chain.refund_tx(fee_sats=500)
    for fee in range(2_000, 20_000, 7):  # a BIP125 bump pays the incremental relay fee
        bump = w.chain.refund_tx(fee_sats=fee)
        if t.btc_txid_from_raw(first) < t.btc_txid_from_raw(bump):
            return first, bump
    raise AssertionError("no fee gave the ordering")


async def test_the_page_names_the_buried_refund_not_a_replaced_one(tmp_path):
    w = _Tower(tmp_path)
    r1, r2 = _replaced_pair(w)
    w.chain.submit(r1)
    w.chain.submit(r2)  # BIP125: the bump replaces R1
    w.chain.mine(BURIAL)
    w.sources[2].forge_spender = r1  # one source still serves the replaced refund
    obs = await w.observe()
    assert obs.btc_disposition is BtcDispositionKind.REFUNDED
    assert obs.btc_refund_txid == t.btc_txid_from_raw(r2)
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.RECONCILE and t.btc_txid_from_raw(r2) in d.reason


async def test_one_refund_is_named_as_before(tmp_path):
    """The honest twin: with one refund, that is the one named."""
    w = _Tower(tmp_path)
    txid = w.chain.submit(w.chain.refund_tx())
    assert (await w.observe()).btc_refund_txid == txid
    w.chain.mine(BURIAL)
    assert (await w.observe()).btc_refund_txid == txid


# --------------------------------------------------------------------------- F6: a quorum-1 read


def _corroborated(w: _Tower) -> _Tower:
    """The RXD side corroborated, so only the BTC read can make a decision low-corroboration."""
    w.rxd.corroborated = True  # stands in for a multi-source RXD quorum; nothing here is about RXD
    w.observer = ChainObserver(btc=w.observer._btc, rxd=w.rxd, btc_burial_blocks=BURIAL, rxd_corroborated=True)
    return w


async def test_a_quorum_1_read_marks_the_armed_refund_low_corroboration_and_the_executor_declines(tmp_path):
    w = _corroborated(_Tower(tmp_path, quorum=1))
    w.presign()
    obs = await w.observe()
    assert obs.btc_single_source is True
    exe = w.executor()
    exe._accept_single_source = False  # the shipped default; the fixture accepts for its fake RXD source
    (res,) = await w.reconciler(executor=exe).tick()
    assert res.decision.autonomous_btc_refund is True and res.decision.low_corroboration is True
    assert res.executed is ExecOutcome.DECLINED
    assert w.chain.mempool is None


async def test_a_quorum_1_refunded_read_is_still_pending_and_never_marks_a_legacy_record(tmp_path):
    w = _corroborated(_Tower(tmp_path, quorum=1))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert d.intent is Intent.WATCH and "only one source" in d.reason, d.reason
    w.write(w.record().with_state(SwapState.ABORTED))
    (res,) = await w.reconciler().tick()
    assert res.legacy is True and res.decision.intent is Intent.WATCH
    assert not w.store.legacy_marker_path(SWAP).exists()


async def test_a_quorum_2_read_is_acted_on_as_before(tmp_path):
    """The honest twin: two sources agree."""
    w = _corroborated(_Tower(tmp_path))
    assert (await w.observe()).btc_single_source is False
    armed = await w.decide()
    assert armed.autonomous_btc_refund is True and armed.low_corroboration is False
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert d.intent is Intent.RECONCILE and d.low_corroboration is False


# --------------------------------------------------------------------------- re-review of the fix round


def _refund_page(urgent: bool) -> Decision:
    return Decision(Intent.PAGE_REFUND, reason="refund the BTC", recommended_action="taker_refund_btc", urgent=urgent)


async def test_an_urgent_flag_that_flips_with_a_flaky_read_neither_storms_nor_drops_the_ack():
    """A known covenant whose lock height reads None on some ticks flips ``urgent``. The situation
    keeps the highest severity it paged at, so the count stays steady and an ACK holds."""
    alerter, ch = _alerter()
    flips = [True, False, True, False, True, False]
    counts = []
    for urgent in flips[:3]:
        await alerter.handle(SWAP, _refund_page(urgent))
        counts.append(alerter.unacked_critical_count())
    assert counts == [1, 1, 1], "the escalation signal alternated"
    assert [p.severity for p in ch.sent] == [Severity.CRITICAL] * 3, "a less urgent tick paged a WARN"
    assert alerter.ack(SWAP) is True
    for urgent in flips[3:]:
        await alerter.handle(SWAP, _refund_page(urgent))
    assert len(ch.sent) == 3, "the ACK did not hold across a flip"
    assert alerter.unacked_critical_count() == 0


async def test_a_warn_refund_page_that_turns_urgent_pages_critical_at_once():
    """The honest twin: an escalation is never deduped as the same situation."""
    alerter, ch = _alerter()
    await alerter.handle(SWAP, _refund_page(False))
    await alerter.handle(SWAP, _refund_page(False))
    await alerter.handle(SWAP, _refund_page(True))
    assert [p.severity for p in ch.sent] == [Severity.WARN, Severity.CRITICAL]


@pytest.mark.parametrize("tag", [SITUATION_BTC_DISCOVERY_DISAGREES, SITUATION_BTC_SPENDER_CONTRADICTION])
async def test_an_ack_of_an_investigate_page_does_not_silence_the_claim_race(tag):
    alerter, ch = _alerter()
    await alerter.handle(SWAP, Decision(Intent.PAGE_SQUEEZED, reason="investigate", situation=tag))
    assert alerter.ack(SWAP) is True
    race = Decision(Intent.PAGE_SQUEEZED, reason="maker revealed p but t_rxd window closing")
    for _ in range(2):
        await alerter.handle(SWAP, race)
    assert len(ch.sent) == 3 and alerter.unacked_critical_count() == 1


async def test_the_discovery_disagreement_page_carries_its_tag(tmp_path):
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    _stale_discovery(w, "ab" * 32)
    assert (await w.decide()).situation == SITUATION_BTC_DISCOVERY_DISAGREES


async def test_one_sources_buried_refund_beside_a_claim_witness_is_not_d14(tmp_path):
    """A single source's REFUNDED decides nothing: the claim beside it is not set aside as lost. Its
    depth is read, fails (it was never mined), and the tower pages fail-closed."""
    w = _corroborated(_Tower(tmp_path, quorum=1))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    for src in w.sources:
        src.forge_spender = w.chain.claim_tx()
    (res,) = await w.reconciler().tick()
    assert res.decision.intent is Intent.PAGE_SQUEEZED, res.decision.reason
    assert "is buried" not in res.decision.reason
    # At decide() itself: the same read with the claim trigger and a served witness is the claim race
    # (its depth unread: fail-closed), not D14 on a refund only one source calls buried.
    w.sources[0].forge_spender = w.sources[1].forge_spender = w.sources[2].forge_spender = None
    obs = dataclasses.replace(await w.observe(), maker_has_claimed_btc=True, btc_claim_witness_seen=True)
    assert obs.btc_single_source is True and obs.btc_disposition is BtcDispositionKind.REFUNDED
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_SQUEEZED and "finality un-assessable" in d.reason, d.reason
    # The honest twin, two sources: the claim beside the buried refund is D14, the covenant claim.
    h = _corroborated(_Tower(tmp_path / "q2"))
    h.chain.submit(h.chain.refund_tx())
    h.chain.mine(BURIAL)
    h.sources[2].forge_spender = h.chain.claim_tx()
    (ok,) = await h.reconciler().tick()
    assert ok.decision.intent is Intent.PAGE_CLAIM and "is buried" in ok.decision.reason


async def test_one_sources_buried_refund_on_a_makers_record_is_not_its_covenant_refund(tmp_path):
    from pyrxd.gravity.swap_state import RecordRole

    w = _corroborated(_Tower(tmp_path, quorum=1, role=RecordRole.MAKER))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert " is buried" not in d.reason, d.reason
    honest = _corroborated(_Tower(tmp_path / "q2", role=RecordRole.MAKER))
    honest.chain.submit(honest.chain.refund_tx())
    honest.chain.mine(BURIAL)
    assert "refund" in (await honest.decide()).reason and "is buried" in (await honest.decide()).reason


async def test_both_locked_with_unevaluable_heights_is_urgent(tmp_path, monkeypatch):
    """The predicate raises only on a t_rxd it cannot convert; the page then fails toward urgent."""
    import importlib

    decide_mod = importlib.import_module("pyrxd.gravity.watch.decide")

    def unevaluable(**kw):
        raise ValidationError("cannot convert t_rxd")

    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    monkeypatch.setattr(decide_mod, "taker_refund_window_open", unevaluable)
    d = await w.decide()
    assert "un-evaluable" in d.reason
    assert d.intent is Intent.PAGE_REFUND and d.urgent is True

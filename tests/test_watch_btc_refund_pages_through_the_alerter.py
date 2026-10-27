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
    SITUATION_BOTH_LOCKED_REFUND_DUE,
    SITUATION_BOTH_LOCKED_REFUND_RUNNABLE,
    SITUATION_BTC_DISCOVERY_DISAGREES,
    SITUATION_BTC_REFUND_PENDING,
    SITUATION_BTC_SPENDER_CONTRADICTION,
    SITUATION_CLAIM_RACE,
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


def _alerter(hold: int = 2) -> tuple[DedupAlerter, _Channel]:
    """The production alerter; a short hold window (``situation_hold_ticks``) keeps the tests short."""
    ch = _Channel()
    return DedupAlerter(channel=ch, situation_hold_ticks=hold), ch


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
    assert race.decision.situation == SITUATION_CLAIM_RACE, "the claim race carries its own tag"
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


async def test_both_locked_refund_due_is_urgent_once_t_rxd_has_matured(tmp_path):
    """mutual_refund runs only once both timeouts have elapsed, so the page turns CRITICAL at t_rxd,
    not at the start of the safety window (second Mythos pass, L4)."""
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    _near(w, past=3)
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and d.recommended_action == "mutual_refund" and d.urgent is True
    assert d.situation == SITUATION_BOTH_LOCKED_REFUND_RUNNABLE and "t_rxd has matured" in d.reason
    _near(w, past=2)  # one block before t_rxd: due (inside the window) but not runnable
    early = await w.decide()
    assert early.intent is Intent.PAGE_REFUND and early.urgent is False
    assert early.situation == SITUATION_BOTH_LOCKED_REFUND_DUE


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
    race = Decision(
        Intent.PAGE_SQUEEZED, reason="maker revealed p but t_rxd window closing", situation=SITUATION_CLAIM_RACE
    )
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
    assert "BTC refund" not in d.reason, d.reason  # not the page for the taker's buried refund
    assert d.intent is Intent.PAGE_REFUND and "funding is buried" in d.reason, "the maker's own page"
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


# --------------------------------------------------------------------------- second Mythos pass (29f6f4f)


def _critical_page_sites() -> list[tuple[str, int, set[str]]]:
    """Every ``Decision(<intent>, ...)`` built in the watch package whose intent pages CRITICAL, with
    its keyword names. The intents come from the alerter's own severity table."""
    import ast
    import importlib
    import pathlib

    from pyrxd.gravity.watch import alerts

    critical = {i.name for i, sev in alerts._SEVERITY.items() if sev is Severity.CRITICAL}
    assert critical, "the alerter pages nothing CRITICAL?"
    root = pathlib.Path(importlib.import_module("pyrxd.gravity.watch.decide").__file__).parent
    sites = []
    for path in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if name != "Decision":
                continue
            intent = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "intent"), None)
            if isinstance(intent, ast.Attribute) and intent.attr in critical:
                sites.append((path.name, node.lineno, {k.arg for k in node.keywords if k.arg}))
    return sites


def test_every_critical_page_names_its_situation():
    """H1: an untagged PAGE_SQUEEZED or PAGE_CLAIM shares one ACK key with every other untagged one,
    so an ACK of a routine page (a reconcile error) silenced the claim race that followed."""
    sites = _critical_page_sites()
    assert len(sites) >= 20, sites  # decide.py and reconciler.py build at least this many today
    assert {f for f, _, _ in sites} >= {"decide.py", "reconciler.py"}
    untagged = [(f, line) for f, line, kws in sites if "situation" not in kws]
    assert untagged == [], f"CRITICAL pages without a situation: {untagged}"


class _FlakyObserver:
    """The production observer, raising while ``fail`` is set (a source that times out)."""

    def __init__(self, inner: ChainObserver) -> None:
        self._inner = inner
        self.fail = False

    async def observe(self, swap_id, record):
        if self.fail:
            raise RuntimeError("source timed out")
        return await self._inner.observe(swap_id, record)


async def test_an_ack_of_a_reconcile_error_does_not_silence_the_claim_race(tmp_path):
    w = _Tower(tmp_path)
    flaky = _FlakyObserver(w.observer)
    w.observer = flaky
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    flaky.fail = True
    (err,) = await rec.tick()
    assert err.decision.intent is Intent.PAGE_SQUEEZED and "reconcile error" in err.decision.reason
    assert alerter.ack(SWAP) is True
    flaky.fail = False
    w.chain.submit(w.chain.claim_tx())
    _near(w)
    (race,) = await rec.tick()
    assert race.decision.intent is Intent.PAGE_SQUEEZED and race.decision.situation == SITUATION_CLAIM_RACE
    assert len(ch.sent) == 2, "the ACK of the reconcile error silenced the claim race"
    assert alerter.unacked_critical_count() == 1


async def test_an_ack_of_the_claim_race_does_not_silence_a_reconcile_error_and_holds_across_it(tmp_path):
    """The reverse. The claim race's ACK holds across the one-tick error (third Mythos pass, F1, F4),
    which reverses the second pass's L2 rule: that one let a blip re-arm escalation."""
    w = _Tower(tmp_path)
    flaky = _FlakyObserver(w.observer)
    w.observer = flaky
    w.chain.submit(w.chain.claim_tx())
    _near(w)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    await rec.tick()
    assert alerter.ack(SWAP) is True
    flaky.fail = True
    await rec.tick()
    assert len(ch.sent) == 2, "the ACK of the claim race silenced the reconcile error"
    flaky.fail = False
    await rec.tick()
    assert len(ch.sent) == 2, "the ACK of the claim race ended at a one-tick error"
    assert alerter.unacked_critical_count() == 1, "the error page was sent and nobody ACKed it"
    for _ in range(3):  # the error page closes after the hold window; the race stays ACKed
        await rec.tick()
    assert len(ch.sent) == 2 and alerter.unacked_critical_count() == 0


async def test_an_ack_holds_while_the_reconcile_error_repeats(tmp_path):
    """The honest twin: the same page, ACKed, is not sent again."""
    w = _Tower(tmp_path)
    flaky = _FlakyObserver(w.observer)
    flaky.fail = True
    w.observer = flaky
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    await rec.tick()
    assert alerter.ack(SWAP) is True
    for _ in range(3):
        await rec.tick()
    assert len(ch.sent) == 1 and alerter.unacked_critical_count() == 0


def _squeeze(tag: str) -> Decision:
    return Decision(Intent.PAGE_SQUEEZED, reason=tag, situation=tag)


async def test_an_ack_holds_across_other_pages_and_ends_when_its_situation_closes():
    """Third Mythos pass, F1 and F4: A ACKed, then B, then A is still ACKed, and alternating A and B
    page only B until B is ACKed. Once A has been absent for the hold window, its ACK is over, and an
    ACK written after that records nothing (re-review of 80c16a1, finding 1)."""
    alerter, ch = _alerter()
    await alerter.handle(SWAP, _squeeze("a"))
    assert alerter.ack(SWAP) is True
    for tag in ["b", "a", "b", "a"]:
        await alerter.handle(SWAP, _squeeze(tag))
    assert [p.message.split(": ", 1)[1].split(" |")[0] for p in ch.sent] == ["a", "b", "b"]
    assert alerter.ack(SWAP, "page_squeezed:b") is True
    for tag in ["b", "a", "b", "a"]:
        await alerter.handle(SWAP, _squeeze(tag))
    assert len(ch.sent) == 3 and alerter.unacked_critical_count() == 0
    alerter.resolve(SWAP)  # one quiet tick (the reconciler's WATCH) does not close anything
    assert alerter.unacked_critical_count() == 0
    for _ in range(2):
        alerter.resolve(SWAP)
    assert alerter.ack(SWAP, "page_squeezed:a") is False, "a late ACK of a closed page was recorded"
    await alerter.handle(SWAP, _squeeze("a"))
    assert len(ch.sent) == 4, "the danger came back after it closed, and its old ACK silenced it"
    assert alerter.unacked_critical_count() == 1


async def test_an_ack_of_one_situation_holds_while_it_lasts():
    """The honest twin."""
    alerter, ch = _alerter()
    await alerter.handle(SWAP, _squeeze("a"))
    assert alerter.ack(SWAP) is True
    for _ in range(3):
        await alerter.handle(SWAP, _squeeze("a"))
    assert len(ch.sent) == 1 and alerter.unacked_critical_count() == 0


async def test_a_makers_record_with_the_takers_refund_pending_still_gets_its_covenant_page(tmp_path):
    """M1: a WATCH for the taker's pending refund dropped the maker's own covenant refund page."""
    from pyrxd.gravity.swap_state import RecordRole

    w = _Tower(tmp_path, role=RecordRole.MAKER)
    w.chain.submit(w.chain.refund_tx())
    obs = await w.observe()
    assert obs.btc_disposition is BtcDispositionKind.REFUND_PENDING
    d = await w.decide()
    assert d.intent is Intent.PAGE_REFUND and "covenant is refundable to you" in d.reason, d.reason
    b = _Tower(tmp_path / "both", role=RecordRole.MAKER, state=SwapState.BOTH_LOCKED)
    b.chain.submit(b.chain.refund_tx())
    _near(b)
    assert (await b.decide()).intent is Intent.PAGE_REFUND


async def test_a_takers_record_with_its_refund_pending_far_from_t_rxd_is_watched(tmp_path):
    """The honest twin: on the taker's own record the pending refund is still watched."""
    w = _Tower(tmp_path)
    w.chain.submit(w.chain.refund_tx())
    d = await w.decide()
    assert d.intent is Intent.WATCH and "not yet buried" in d.reason


@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH])
async def test_an_unread_funding_depth_near_t_rxd_pages_critical(tmp_path, state):
    """M2: with the covenant known and t_rxd near, an unread funding depth was a silent WATCH (and a
    WARN at PARAMS_MISMATCH)."""
    w = _Tower(tmp_path, state=state)
    _near(w)
    obs = dataclasses.replace(await w.observe(), btc_funding_confirmations=None)
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.PAGE_REFUND and d.urgent is True, d.reason
    assert d.autonomous_btc_refund is False
    alerter, ch = _alerter()
    for _ in range(2):
        await alerter.handle(SWAP, d)
    assert [p.severity for p in ch.sent] == [Severity.CRITICAL] * 2


async def test_an_unread_funding_depth_far_from_t_rxd_is_not_urgent(tmp_path):
    """The honest twin: far from t_rxd it waits for the depth, as before."""
    w = _Tower(tmp_path)
    obs = dataclasses.replace(await w.observe(), btc_funding_confirmations=None)
    d = decide(record=w.record(), observations=obs, policy=_policy(), safety_window_blocks=6)
    assert d.intent is Intent.WATCH, d.reason


class _Outcomes:
    """An executor that reports the given outcomes, one per armed refund, and sends nothing."""

    def __init__(self, *outcomes: ExecOutcome) -> None:
        self._outcomes = list(outcomes)

    async def execute(self, swap_id, record, decision):
        return self._outcomes.pop(0) if decision.autonomous_btc_refund else None


async def test_a_failed_rebroadcast_after_a_broadcast_pages_again(tmp_path):
    """M3: the page saying FAILED was deduped behind the first page, which said the tower broadcast."""
    w = _Tower(tmp_path)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter, executor=_Outcomes(ExecOutcome.BROADCAST, ExecOutcome.FAILED))
    await rec.tick()
    await rec.tick()
    assert len(ch.sent) == 2, "the FAILED page was deduped"
    assert "FAILED" in ch.sent[1].message and "FAILED" not in ch.sent[0].message


async def test_the_same_executor_outcome_pages_once(tmp_path):
    """The honest twin: a WARN that says the same thing is sent once."""
    w = _Tower(tmp_path)
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter, executor=_Outcomes(*[ExecOutcome.DECLINED] * 3))
    for _ in range(3):
        await rec.tick()
    assert len(ch.sent) == 1


async def test_one_sources_buried_refund_beside_a_claim_on_record_still_says_refund_the_btc(tmp_path):
    """L3: the D14 page read one source's "buried" as buried and dropped "refund the BTC"."""
    w = _corroborated(_Tower(tmp_path, quorum=1))
    w.write(dataclasses.replace(w.record(), counter_claim_tx=t.btc_txid_from_raw(w.chain.claim_tx())))
    w.chain.submit(w.chain.refund_tx())
    w.chain.mine(BURIAL)
    d = await w.decide()
    assert d.intent is Intent.PAGE_CLAIM, d.reason
    assert "not yet buried" in d.reason and "only one source" in d.reason
    assert "refund the BTC if it is still unspent" in d.reason
    h = _corroborated(_Tower(tmp_path / "q2"))
    h.write(dataclasses.replace(h.record(), counter_claim_tx=t.btc_txid_from_raw(h.chain.claim_tx())))
    h.chain.submit(h.chain.refund_tx())
    h.chain.mine(BURIAL)
    ok = await h.decide()
    assert ok.intent is Intent.PAGE_CLAIM and " is buried" in ok.reason
    assert "refund the BTC if" not in ok.reason


# --------------------------------------------------------------------------- third Mythos pass (3b99919)


class _Degrading:
    """The production observer; while ``degraded`` the funding depth reads as unknown (2 of 3 BTC
    sources timed out for a tick)."""

    def __init__(self, inner: ChainObserver) -> None:
        self._inner = inner
        self.degraded = False

    async def observe(self, swap_id, record):
        obs = await self._inner.observe(swap_id, record)
        return dataclasses.replace(obs, btc_funding_confirmations=None) if self.degraded else obs


@pytest.mark.parametrize("state", [SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH])
@pytest.mark.parametrize("blip", [True, False], ids=["blip", "control"])
async def test_one_degraded_read_does_not_end_the_ack_of_the_urgent_refund_page(tmp_path, state, blip):
    """F1: the ACKed refund page came back un-ACKed after one tick with the funding depth unread,
    re-paged every tick, and re-armed escalation."""
    w = _Tower(tmp_path, state=state)
    _near(w)
    deg = _Degrading(w.observer)
    w.observer = deg
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    (first,) = await rec.tick()
    assert first.decision.urgent is True and ch.sent[0].severity is Severity.CRITICAL
    assert alerter.ack(SWAP) is True
    deg.degraded = blip
    await rec.tick()
    deg.degraded = False
    for _ in range(3):  # past the hold window: the blip's own page closes
        await rec.tick()
    assert alerter.unacked_critical_count() == 0, "the operator's ACK was dropped by a one-tick read failure"
    # The blip changes the page (the refund is no longer armed while the depth is unread), so it is
    # news and sent once; the ACKed page is not sent again after it.
    assert len(ch.sent) == (2 if blip else 1)


async def test_a_bare_ack_written_for_an_earlier_page_does_not_land_on_a_newer_one():
    """F2: a reconcile error paged, the operator wrote a bare ACK, the claim race paged before the
    drain, and the drain ACKed the claim race."""
    alerter, ch = _alerter(hold=10)
    error = Decision(Intent.PAGE_SQUEEZED, reason="reconcile error", situation="reconcile_error")
    race = Decision(Intent.PAGE_SQUEEZED, reason="maker revealed p", situation=SITUATION_CLAIM_RACE)
    await alerter.handle(SWAP, error)
    await alerter.handle(SWAP, race)
    assert alerter.ack(SWAP) is False, "a bare id bound to a page the operator may not have seen"
    await alerter.handle(SWAP, race)
    assert len(ch.sent) == 3 and alerter.unacked_critical_count() == 1
    # The ack: line the page printed names the situation, so it ACKs exactly that one.
    assert ch.sent[1].message.endswith(f"ack: {SWAP} page_squeezed:claim_race")
    assert alerter.ack(SWAP, "page_squeezed:reconcile_error") is True
    assert alerter.unacked_critical_count() == 1, "an ACK of the error silenced the race"
    assert alerter.ack(SWAP, "page_squeezed:claim_race") is True
    assert alerter.unacked_critical_count() == 0
    assert alerter.ack(SWAP, "page_claim:claim_race") is False, "a key the swap never paged ACKs nothing"


async def test_a_bare_ack_of_the_only_page_still_works():
    """The honest twin: one page, a bare ACK at the next drain."""
    alerter, ch = _alerter()
    race = Decision(Intent.PAGE_SQUEEZED, reason="maker revealed p", situation=SITUATION_CLAIM_RACE)
    await alerter.handle(SWAP, race)
    from pyrxd.gravity.watch.run import apply_acks

    apply_acks(alerter, [SWAP])
    for _ in range(3):
        await alerter.handle(SWAP, race)
    assert len(ch.sent) == 1 and alerter.unacked_critical_count() == 0


async def test_the_inbox_line_with_a_key_reaches_the_alerter(tmp_path):
    """The shipped drain splits ``<swap_id> <key>`` and passes both."""
    from pyrxd.gravity.watch.alerts import FileAckInbox
    from pyrxd.gravity.watch.run import apply_acks

    alerter, _ = _alerter()
    await alerter.handle(SWAP, Decision(Intent.PAGE_SQUEEZED, reason="e", situation="reconcile_error"))
    await alerter.handle(SWAP, Decision(Intent.PAGE_SQUEEZED, reason="r", situation=SITUATION_CLAIM_RACE))
    path = tmp_path / "acks"
    path.write_text(f"{SWAP}\n{SWAP} page_squeezed:claim_race\n{SWAP} page_squeezed:reconcile_error\n")
    path.chmod(0o600)
    apply_acks(alerter, FileAckInbox(path).drain())
    assert alerter.unacked_critical_count() == 0


async def test_quiet_ticks_take_a_page_off_the_escalation_count(tmp_path):
    """F3: after a one-tick outage paged CRITICAL and the swap went back to WATCH, the count stayed 1
    for good. It now drops once the page has been absent for the hold window."""
    w = _Tower(tmp_path)
    _near(w)
    deg = _Degrading(w.observer)
    w.observer = deg
    alerter, _ = _alerter()
    rec = w.reconciler(alerter=alerter)
    w.rxd.cov_confs = None  # the covenant's lock height unread too: only the record's pin is known
    deg.degraded = True
    (res,) = await rec.tick()
    assert res.decision.situation == "btc_refund_maturity_unread" and "could not be read" in res.decision.reason
    assert "t_rxd is near or past" not in res.decision.reason
    assert alerter.unacked_critical_count() == 1
    # Both reads back, far from t_rxd: the swap is not urgent, its funding not yet matured.
    _at(w, LOCKED_AT + 5)
    deg.degraded = False
    w.write(dataclasses.replace(w.record(), state=SwapState.BOTH_LOCKED))
    (quiet,) = await rec.tick()
    assert quiet.decision.intent is Intent.WATCH, quiet.decision.reason
    assert alerter.unacked_critical_count() == 1, "one quiet tick is not enough to close a page"
    for _ in range(2):  # the hold window (2 here)
        await rec.tick()
    assert alerter.unacked_critical_count() == 0


async def test_alternating_outcomes_page_each_warn_once(tmp_path):
    """F5: BROADCAST and FAILED alternating paged a WARN every tick."""
    w = _Tower(tmp_path)
    alerter, ch = _alerter()
    outcomes = [ExecOutcome.BROADCAST, ExecOutcome.FAILED] * 3
    rec = w.reconciler(alerter=alerter, executor=_Outcomes(*outcomes))
    for _ in outcomes:
        await rec.tick()
    assert len(ch.sent) == 2


def test_every_refund_page_names_a_definite_situation():
    """F6: four urgent refund pages were CRITICAL with no situation, and the scan took its intents
    from ``_SEVERITY``, which has PAGE_REFUND as WARN. The re-review of the fix found seven more
    untagged refund pages, two of which (a maker's) were one WARN, paged once (finding 6). Every
    PAGE_REFUND, and any other ``urgent=`` that is not a literal False, now needs a tag that cannot
    be None."""
    import ast
    import importlib
    import pathlib

    root = pathlib.Path(importlib.import_module("pyrxd.gravity.watch.decide").__file__).parent
    sites, bad = [], []
    for path in sorted(root.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not (
                isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", None)) == "Decision"
            ):
                continue
            kws = {k.arg: k.value for k in node.keywords if k.arg}
            intent = node.args[0] if node.args else kws.get("intent")
            urgent = kws.get("urgent")
            refund = isinstance(intent, ast.Attribute) and intent.attr == "PAGE_REFUND"
            may_be_urgent = urgent is not None and not (isinstance(urgent, ast.Constant) and urgent.value is False)
            if not (refund or may_be_urgent):
                continue
            sites.append((path.name, node.lineno))
            tag = kws.get("situation")
            if tag is None or any(isinstance(n, ast.Constant) and n.value is None for n in ast.walk(tag)):
                bad.append((path.name, node.lineno))
    assert len(sites) >= 13, sites  # decide.py builds 13 today
    assert bad == [], f"refund pages without a definite situation: {bad}"


# --------------------------------------------------------------------------- Opus re-review of 80c16a1


@pytest.mark.parametrize("acked", [True, False], ids=["acked", "unacked"])
async def test_one_quiet_tick_from_a_failed_read_neither_ends_an_ack_nor_zeroes_escalation(tmp_path, acked):
    """Finding 2: at BOTH_LOCKED a failed covenant-depth read decides WATCH (residual R1). One such
    tick ended the ACK of the CRITICAL page, and read 0 on an un-ACKed one, resetting escalation."""
    w = _Tower(tmp_path, state=SwapState.BOTH_LOCKED)
    _near(w, past=3)  # t_rxd matured: mutual_refund page, CRITICAL
    alerter, ch = _alerter()
    rec = w.reconciler(alerter=alerter)
    (first,) = await rec.tick()
    assert first.decision.urgent is True
    if acked:
        assert alerter.ack(SWAP) is True
    w.rxd.cov_confs = None
    (blind,) = await rec.tick()
    assert blind.decision.intent is Intent.WATCH, blind.decision.reason
    assert alerter.unacked_critical_count() == (0 if acked else 1), "one failed read moved the escalation count"
    _near(w, past=4)
    await rec.tick()
    assert len(ch.sent) == (1 if acked else 2), "the ACK ended at one failed read"


class _DownChannel(_Channel):
    def __init__(self) -> None:
        super().__init__()
        self.down = False

    async def send(self, page) -> None:
        if self.down:
            raise ConnectionError("channel down")
        await super().send(page)


async def test_a_page_that_never_went_out_changes_nothing_escalation_reads():
    """Finding 3: a new CRITICAL that failed to send replaced the live situation, and the count of
    an un-ACKed claim race dropped to 0 while nothing reached the operator."""
    ch = _DownChannel()
    alerter = DedupAlerter(channel=ch)
    race = Decision(Intent.PAGE_SQUEEZED, reason="race", situation=SITUATION_CLAIM_RACE)
    await alerter.handle(SWAP, race)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, Decision(Intent.PAGE_SQUEEZED, reason="e", situation="reconcile_error"))
    assert alerter.unacked_critical_count() == 1
    ch.down = False
    await alerter.handle(SWAP, Decision(Intent.PAGE_SQUEEZED, reason="e", situation="reconcile_error"))
    assert len(ch.sent) == 2, "the failed page was not retried"


async def test_a_critical_alternating_with_a_paged_warn_keeps_its_count():
    """Finding 3, second part: an un-ACKed CRITICAL alternating with a WARN read 1, 0, 1, 0."""
    alerter, _ = _alerter()
    race = Decision(Intent.PAGE_SQUEEZED, reason="race", situation=SITUATION_CLAIM_RACE)
    warn = Decision(Intent.PAGE_REFUND, reason="refund", situation="btc_refund_due")
    counts = []
    for d in [race, warn] * 3:
        await alerter.handle(SWAP, d)
        counts.append(alerter.unacked_critical_count())
    assert counts == [1] * 6


async def test_an_ack_does_not_outlive_its_danger_while_a_warn_persists():
    """Finding 4: a claim-race ACK held for as long as the swap sat in a once-paged WARN."""
    alerter, ch = _alerter()
    race = Decision(Intent.PAGE_SQUEEZED, reason="race", situation=SITUATION_CLAIM_RACE)
    warn = Decision(Intent.PAGE_REFUND, reason="refund", situation="btc_refund_due")
    await alerter.handle(SWAP, race)
    assert alerter.ack(SWAP) is True
    for _ in range(50):
        await alerter.handle(SWAP, warn)
    await alerter.handle(SWAP, race)
    assert len(ch.sent) == 3 and alerter.unacked_critical_count() == 1, "an old ACK silenced the race"


async def test_a_warn_pages_again_once_it_has_closed():
    """Finding 6: a WARN situation was swallowed for the rest of the swap's life once it had paged
    (the maker's covenant refund page, untagged, at BTC_LOCKED and again near t_rxd)."""
    alerter, ch = _alerter()
    warn = Decision(Intent.PAGE_REFUND, reason="refund your covenant at t_rxd")
    await alerter.handle(SWAP, warn)
    alerter.resolve(SWAP)
    await alerter.handle(SWAP, warn)
    assert len(ch.sent) == 1, "the honest twin: inside the hold window it is the same page"
    for _ in range(3):
        alerter.resolve(SWAP)
    await alerter.handle(SWAP, warn)
    assert len(ch.sent) == 2


class _Store:
    """A records store that can fail to list."""

    def __init__(self) -> None:
        self.fail = False

    async def list_active(self):
        if self.fail:
            raise OSError("records dir unmounted")
        return []


async def test_the_store_page_can_be_acked_and_closes_when_the_store_is_back(tmp_path):
    """Finding 5: the store page's ack: line was refused by the inbox, and nothing ever closed it, so
    the escalation count stayed 1 after the store came back."""
    from pyrxd.gravity.watch.alerts import FileAckInbox
    from pyrxd.gravity.watch.reconciler import Reconciler
    from pyrxd.gravity.watch.run import apply_acks

    store = _Store()
    alerter, ch = _alerter()
    rec = Reconciler(
        store=store, observer=_Tower(tmp_path).observer, alerter=alerter, policy=_policy(), safety_window_blocks=6
    )
    store.fail = True
    await rec.tick()
    line = ch.sent[0].message.rsplit("ack: ", 1)[1]
    path = tmp_path / "acks"
    path.write_text(line + "\n")
    path.chmod(0o600)
    assert FileAckInbox(path).drain() == [line]
    path.write_text(line + "\n")
    path.chmod(0o600)
    apply_acks(alerter, FileAckInbox(path).drain())
    assert alerter.unacked_critical_count() == 0
    # Un-ACKed, the page closes once the store has read for the hold window.
    alerter2, _ = _alerter()
    rec2 = Reconciler(
        store=store,
        observer=_Tower(tmp_path / "b").observer,
        alerter=alerter2,
        policy=_policy(),
        safety_window_blocks=6,
    )
    await rec2.tick()
    assert alerter2.unacked_critical_count() == 1
    store.fail = False
    for _ in range(3):
        await rec2.tick()
    assert alerter2.unacked_critical_count() == 0


@pytest.mark.parametrize("earlier_page", [True, False], ids=["after-a-refund-page", "control"])
async def test_a_makers_t_rxd_near_page_is_not_swallowed_by_its_earlier_refund_page(tmp_path, earlier_page):
    """Finding 6, through the tower: a maker's "taker funding buried, you have not claimed" WARN at
    BTC_LOCKED, then BOTH_LOCKED, then "t_rxd is near": the last page never went out."""
    from pyrxd.gravity.swap_state import RecordRole

    w = _Tower(tmp_path, role=RecordRole.MAKER)
    alerter, ch = _alerter(hold=10)
    rec = w.reconciler(alerter=alerter)
    _at(w, LOCKED_AT + 5)
    if earlier_page:
        (first,) = await rec.tick()
        assert first.decision.intent is Intent.PAGE_REFUND
    w.write(dataclasses.replace(w.record(), state=SwapState.BOTH_LOCKED))
    await rec.tick()
    _near(w)
    (near,) = await rec.tick()
    assert near.decision.intent is Intent.PAGE_REFUND and "t_rxd is near" in near.decision.reason
    assert "t_rxd is near" in ch.sent[-1].message, "the t_rxd page never went out"
    assert len(ch.sent) == (2 if earlier_page else 1)


async def test_a_warn_that_failed_to_send_is_sent_next_tick():
    """Finding 3, the other half: a page is recorded only once it is sent, so a WARN whose send
    failed is not taken as already paged."""
    ch = _DownChannel()
    alerter = DedupAlerter(channel=ch)
    warn = Decision(Intent.PAGE_REFUND, reason="refund", situation="btc_refund_due")
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, warn)
    ch.down = False
    await alerter.handle(SWAP, warn)
    assert len(ch.sent) == 1, "the WARN was recorded as paged although it never went out"


# --------------------------------------------------------------------------- second re-check of the hold window


@pytest.mark.parametrize("escalation", [False, True], ids=["new-critical", "warn-escalates"])
async def test_a_critical_that_never_went_out_counts_for_as_long_as_the_channel_is_down(escalation):
    """Re-check MEDIUM: a CRITICAL whose first send failed was never recorded, so through a channel
    outage the escalation count (the second channel's whole input) read 0."""
    ch = _DownChannel()
    alerter = DedupAlerter(channel=ch, situation_hold_ticks=2)
    refund = Decision(Intent.PAGE_REFUND, reason="refund", situation="btc_refund_due")
    if escalation:
        await alerter.handle(SWAP, refund)
        assert alerter.unacked_critical_count() == 0, "the honest twin: a WARN does not count"
    critical = (
        Decision(Intent.PAGE_REFUND, reason="refund now", situation="btc_refund_due", urgent=True)
        if escalation
        else Decision(Intent.PAGE_SQUEEZED, reason="race", situation=SITUATION_CLAIM_RACE)
    )
    ch.down = True
    for _ in range(10):  # well past the hold window
        with pytest.raises(ConnectionError):
            await alerter.handle(SWAP, critical)
        assert alerter.unacked_critical_count() == 1, "an undelivered CRITICAL dropped out of escalation"
    ch.down = False
    await alerter.handle(SWAP, critical)
    assert ch.sent[-1].severity is Severity.CRITICAL and alerter.unacked_critical_count() == 1
    assert alerter.ack(SWAP) is True
    assert alerter.unacked_critical_count() == 0


async def test_an_undelivered_critical_that_went_away_closes_after_the_hold():
    """The honest twin: a CRITICAL that never went out and is no longer live stops counting once its
    hold window has passed, as a delivered one would."""
    ch = _DownChannel()
    alerter = DedupAlerter(channel=ch, situation_hold_ticks=2)
    ch.down = True
    with pytest.raises(ConnectionError):
        await alerter.handle(SWAP, Decision(Intent.PAGE_SQUEEZED, reason="race", situation=SITUATION_CLAIM_RACE))
    for _ in range(3):
        alerter.resolve(SWAP)
    assert alerter.unacked_critical_count() == 0


async def test_a_repeated_bare_ack_does_not_land_on_a_newer_page():
    """Re-check 2a: the bare line ``<swap_id>`` appended again (shell history) after the first ACK
    landed on a page that opened after it was written."""
    alerter, ch = _alerter(hold=10)
    race = Decision(Intent.PAGE_SQUEEZED, reason="race", situation=SITUATION_CLAIM_RACE)
    error = Decision(Intent.PAGE_SQUEEZED, reason="reconcile error", situation="reconcile_error")
    await alerter.handle(SWAP, race)
    assert alerter.ack(SWAP) is True
    await alerter.handle(SWAP, error)
    assert alerter.ack(SWAP) is False, "a repeated bare ACK silenced a page the operator had not seen"
    assert alerter.unacked_critical_count() == 1
    # The honest twin: the key the new page printed still ACKs it.
    assert ch.sent[-1].message.endswith(f"ack: {SWAP} page_squeezed:reconcile_error")
    assert alerter.ack(SWAP, "page_squeezed:reconcile_error") is True
    assert alerter.unacked_critical_count() == 0

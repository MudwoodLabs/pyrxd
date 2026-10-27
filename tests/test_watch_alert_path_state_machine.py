"""The watchtower's alert path under random sequences of chain events, source faults and operator ACKs.

Every finding of the three Mythos passes on #902 came from a SEQUENCE: a healthy tick, a degraded tick,
a healthy tick, with an operator ACK somewhere in between. The other watch tests are single-tick or
steady-state. This one is a Hypothesis state machine over one BTC swap on the real Taproot fake chain
(``tests._fake_btc_chain``), watched by the production observer, ``decide``, ``Reconciler`` and
``DedupAlerter``. Its rules move the chain (our refund, a maker claim that replaces it, blocks, a
reorg, a dropped mempool), move the RXD tip toward and past t_rxd, break or corrupt one source at a
time, take the page channel down, and ACK pages late, early, or long after they closed.

The invariants are the alert-path contract, checked after every tick:

* **No silent CRITICAL.** A CRITICAL situation pages on every tick it is live, unless the operator
  ACKed that exact situation while it was open. An ACK of one situation never silences another.
* **An ACK is honoured.** An ACKed situation does not page again while it stays open.
* **An ACK binds to a page that was sent.** ``ack`` records nothing for a situation that never paged
  CRITICAL, and a bare ACK binds only when exactly one CRITICAL situation is open and un-ACKed.
* **The escalation signal follows.** A CRITICAL decision that was not delivered, or is open and
  un-ACKed, keeps ``unacked_critical_count`` above zero.
* **One source cannot lower a page, but for two known ways.** With at most one faulty source, the
  decision is at least as severe as the one the same tower takes over three honest sources of the
  same chain. The two exceptions this machine found, both left as they are pending a decision:

  - a source that alone holds a refund of ours (``pyrxd.btc_wallet.disposition``, "unspent_by")
    turns the refund page into a WATCH on that pending refund, until t_rxd comes near;
  - a source that under-reports a spender's depth holds it below burial (the reader takes the
    minimum depth), so a buried refund stays a WATCH and a buried maker claim stays a WATCH
    ("awaiting reorg-safe burial") instead of a CRITICAL claim page, until the t_rxd window closes
    and it pages as a squeeze.

  Neither exception may lower a squeeze: a decision the honest tower takes as PAGE_SQUEEZED is
  CRITICAL here too.
* **Autonomy needs a quorum of "unspent".** The pre-signed refund is armed only when at least a
  quorum of sources answer that the outpoint is unspent and none names a spender (the reader's rule,
  ``pyrxd.btc_wallet.disposition``). A source that is down or fails its read is never a vote for
  "unspent".
* **An unburied refund of ours near t_rxd is CRITICAL.** With every source honest, our refund on the
  chain short of burial while the taker's refund window is open (``taker_refund_window_open``, the
  coordinator's own predicate) pages CRITICAL: the maker can then refund the covenant and still claim
  the BTC.

The model below restates the rules ``DedupAlerter`` documents (a situation is open from its first
delivered page until it has been absent for ``situation_hold_ticks`` ticks; it keeps the highest
severity it paged at); it is a spec, not a copy of the implementation's bookkeeping.

The CI budget is small. The weekly deep-fuzz lane scales it with ``FUZZ_BUDGET_MULTIPLIER``.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import os
import re
import shutil
import tempfile
from pathlib import Path
from unittest import mock

from hypothesis import HealthCheck, event, settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

import tests.test_watch_btc_spender_classification as spender_tests
from pyrxd.gravity.swap_coordinator import taker_refund_window_open
from pyrxd.gravity.watch.adapters import OutspendBtcClaimSource
from pyrxd.gravity.watch.alerts import DedupAlerter, Severity
from pyrxd.gravity.watch.decide import Decision, Intent, decide
from pyrxd.gravity.watch.quorum import ChainObserver
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
from pyrxd.security.errors import NetworkError
from tests._fake_btc_chain import FakeBtcChain, FakeBtcSource
from tests.test_watch_btc_spender_classification import BURIAL, COV_CONFS, SWAP, T_RXD, TIP, _outspend, _policy, _Tower

LOCKED_AT = TIP - COV_CONFS + 1
T_RXD_OPENS = LOCKED_AT + T_RXD
HOLD = 3
SAFETY = 6  # the reconciler's safety_window_blocks in _Tower
QUORUM = 2

_BUDGET_MULT = int(os.environ.get("FUZZ_BUDGET_MULTIPLIER", "1"))

#: What a faulty source does. ``ok`` is honest.
FAULTS = ("ok", "down", "hide_spender", "forge_claim", "forge_refund", "lie_depth", "spender_reads_fail")

_ACK_RE = re.compile(r"ack: (\S+) (\S+)\Z")

_TEMPLATE: FakeBtcChain | None = None


def _fresh_chain() -> FakeBtcChain:
    """A new chain with the same HTLC, keys and funding txid every time.

    Hypothesis replays and shrinks a failing sequence, so a run must be a function of the drawn rules.
    A fresh :class:`FakeBtcChain` draws new keys and a new funding txid, and the reader orders spenders
    by txid, so the same sequence could decide differently. The keys are generated once per process
    (a shallow copy shares them; key material refuses a deep copy) and every chain field starts from
    its default. A transaction's txid does not cover its witness, so the signatures' fresh aux
    randomness changes no txid."""
    global _TEMPLATE
    if _TEMPLATE is None:
        _TEMPLATE = FakeBtcChain()
    chain = copy.copy(_TEMPLATE)
    for f in dataclasses.fields(FakeBtcChain):
        setattr(chain, f.name, f.default_factory() if f.default is dataclasses.MISSING else f.default)  # type: ignore[misc]
    return chain


_RANK = {None: 0, Severity.INFO: 1, Severity.WARN: 2, Severity.CRITICAL: 3}


def _severity(decision: Decision) -> Severity | None:
    """The severity the alert layer gives a decision, from its documented table (``alerts._SEVERITY``)."""
    if decision.urgent:
        return Severity.CRITICAL
    return {
        Intent.PAGE_CLAIM: Severity.CRITICAL,
        Intent.PAGE_SQUEEZED: Severity.CRITICAL,
        Intent.PAGE_REFUND: Severity.WARN,
        Intent.RECONCILE: Severity.INFO,
        Intent.RETIRE: Severity.INFO,
    }.get(decision.intent)


def _key(decision: Decision) -> str:
    """The situation key a page prints after the swap id on its ``ack:`` line."""
    return decision.intent.value if decision.situation is None else f"{decision.intent.value}:{decision.situation}"


class _Channel:
    """The page transport; ``up`` False makes every send fail, as a dead webhook does."""

    def __init__(self) -> None:
        self.sent: list = []
        self.up = True

    async def send(self, page) -> None:
        if not self.up:
            raise NetworkError("page channel down")
        self.sent.append(page)


class AlertPathMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self._tmp = Path(tempfile.mkdtemp(prefix="alert-path-"))
        self._loop = asyncio.new_event_loop()

    def teardown(self) -> None:
        self._loop.close()
        shutil.rmtree(self._tmp, ignore_errors=True)

    @initialize()
    def start(self) -> None:
        with mock.patch.object(spender_tests, "FakeBtcChain", _fresh_chain):
            self.w = _Tower(self._tmp, quorum=QUORUM)
        self.channel = _Channel()
        self.alerter = DedupAlerter(channel=self.channel, situation_hold_ticks=HOLD)
        self.rec = self.w.reconciler(alerter=self.alerter)
        self.faults = ["ok"] * len(self.w.sources)
        # The reference: the same chain, record and RXD view through three sources that never fault.
        honest = [FakeBtcSource(self.w.chain) for _ in self.w.sources]
        self.honest = ChainObserver(
            btc=OutspendBtcClaimSource(
                outspend_fns=[_outspend(x) for x in honest],
                funding_reader=MultiSourceBtcFundingReader(honest, quorum=QUORUM),
            ),
            rxd=self.w.rxd,
            btc_burial_blocks=BURIAL,
        )
        self.claims: set[str] = set()  # txids of the maker claims we put on the chain
        # The spec model: open situations (key -> [last live tick, highest severity]) and the ACKed ones.
        self.tick_no = 0
        self.open: dict[str, list] = {}
        self.acked: set[str] = set()
        self.critical_paged: set[str] = set()  # every key that ever paged CRITICAL

    # ------------------------------------------------------------------ the chain

    def _spender(self) -> str | None:
        return self.w.chain.confirmed_spender() or self.w.chain.mempool

    @rule(fee=st.integers(min_value=300, max_value=3_000), then_tick=st.booleans())
    def our_refund(self, fee: int, then_tick: bool) -> None:
        try:
            self.w.chain.submit(self.w.chain.refund_tx(fee_sats=fee))
        except NetworkError:
            pass  # already spent, or not a valid replacement: the node refused it
        self._maybe_tick(then_tick)

    @rule(fee=st.integers(min_value=300, max_value=20_000), then_tick=st.booleans())
    def maker_claim(self, fee: int, then_tick: bool) -> None:
        try:
            self.claims.add(self.w.chain.submit(self.w.chain.claim_tx(fee_sats=fee)))
        except NetworkError:
            pass
        self._maybe_tick(then_tick)

    @rule(blocks=st.integers(min_value=1, max_value=8), then_tick=st.booleans())
    def mine(self, blocks: int, then_tick: bool) -> None:
        self.w.chain.mine(blocks)
        self._maybe_tick(then_tick)

    @rule(then_tick=st.booleans())
    def drop_mempool(self, then_tick: bool) -> None:
        self.w.chain.drop()
        self._maybe_tick(then_tick)

    @rule(depth=st.integers(min_value=1, max_value=3), then_tick=st.booleans())
    def reorg(self, depth: int, then_tick: bool) -> None:
        self.w.chain.reorg(depth)
        self._maybe_tick(then_tick)

    @rule(tip=st.integers(min_value=TIP, max_value=T_RXD_OPENS + 12), then_tick=st.booleans())
    def rxd_tip(self, tip: int, then_tick: bool) -> None:
        self.w.rxd.tip = tip
        self.w.rxd.cov_confs = tip - LOCKED_AT + 1
        self._maybe_tick(then_tick)

    # ------------------------------------------------------------------ sources and the channel

    @rule(i=st.integers(min_value=0, max_value=2), fault=st.sampled_from(FAULTS), then_tick=st.booleans())
    def source(self, i: int, fault: str, then_tick: bool) -> None:
        src = self.w.sources[i]
        src.down = fault == "down"
        src.hide_spender = fault == "hide_spender"
        src.spender_reads_fail = fault == "spender_reads_fail"
        src.lie_depth = 0 if fault == "lie_depth" else None
        src.forge_spender = None
        if fault == "forge_claim":
            src.forge_spender = self.w.chain.claim_tx(fee_sats=777)
        elif fault == "forge_refund":
            src.forge_spender = self.w.chain.refund_tx(fee_sats=777)
        self.faults[i] = fault
        self._maybe_tick(then_tick)

    @rule(up=st.booleans(), then_tick=st.booleans())
    def channel(self, up: bool, then_tick: bool) -> None:
        self.channel.up = up
        self._maybe_tick(then_tick)

    # ------------------------------------------------------------------ the operator

    @precondition(lambda self: bool(self.critical_paged))
    @rule(data=st.data(), then_tick=st.booleans())
    def ack_keyed(self, data, then_tick: bool) -> None:
        """The operator appends a page's ``ack:`` line, possibly late or after the page closed."""
        key = data.draw(st.sampled_from(sorted(self.critical_paged)))
        recorded = self.alerter.ack(SWAP, key)
        if recorded:
            assert key in self.open and self.open[key][1] is Severity.CRITICAL, (
                f"ACK of {key} recorded while that situation is not open CRITICAL"
            )
            self.acked.add(key)
            event("keyed ACK recorded")
        self._maybe_tick(then_tick)

    @rule(then_tick=st.booleans())
    def ack_bare(self, then_tick: bool) -> None:
        """A bare swap id binds only when exactly one CRITICAL situation is open and un-ACKed."""
        pending = [k for k, (_, sev) in self.open.items() if sev is Severity.CRITICAL and k not in self.acked]
        recorded = self.alerter.ack(SWAP)
        if recorded:
            assert not self.acked and len(pending) == 1, f"a bare ACK bound with ACKed={self.acked} pending={pending}"
            self.acked.add(pending[0])
            event("bare ACK recorded")
        self._maybe_tick(then_tick)

    # ------------------------------------------------------------------ one tick of the tower

    def _maybe_tick(self, then_tick: bool) -> None:
        """Most events are followed by a poll: the sequences that matter interleave the two."""
        if then_tick:
            self.tick()

    @rule()
    def tick(self) -> None:
        before = len(self.channel.sent)
        results = self._loop.run_until_complete(self.rec.tick())
        sent = self.channel.sent[before:]
        assert [r.swap_id for r in results] == [SWAP], results
        decision = results[0].decision
        event(f"decision {_key(decision)}")
        self.tick_no += 1
        for k in [k for k, (last, _) in self.open.items() if self.tick_no - last > HOLD]:
            del self.open[k]
            self.acked.discard(k)
        self._check_sources(decision)
        sev = _severity(decision)
        if sev is None:
            assert not sent, f"a quiet decision paged: {sent}"
            return
        key = _key(decision)
        assert all(p.swap_id == SWAP for p in sent)
        was = self.open.get(key)
        effective = Severity.CRITICAL if (was is not None and was[1] is Severity.CRITICAL) else sev
        if was is None:
            expect_page = True
        elif effective is Severity.CRITICAL:
            expect_page = key not in self.acked
        else:
            expect_page = False
        if not self.channel.up:
            assert not sent
            if effective is Severity.CRITICAL and key not in self.acked:
                assert self.alerter.unacked_critical_count() >= 1, (
                    f"undelivered CRITICAL {key} is not counted for escalation"
                )
            if was is not None:
                was[0] = self.tick_no
            return
        if expect_page:
            assert len(sent) == 1, f"{key} ({effective.value}) did not page; ACKed={sorted(self.acked)}"
            assert sent[0].severity is effective
            if effective is Severity.CRITICAL:
                m = _ACK_RE.search(sent[0].message)
                assert m is not None and m.group(1) == SWAP and m.group(2) == key, sent[0].message
                self.critical_paged.add(key)
        else:
            assert not sent, f"{key} paged again while open ({'ACKed' if key in self.acked else effective.value})"
        self.open[key] = [self.tick_no, effective]
        if effective is Severity.CRITICAL and key not in self.acked:
            assert self.alerter.unacked_critical_count() >= 1

    def _check_sources(self, decision: Decision) -> None:
        healthy = self.faults.count("ok")
        spender = self._spender()
        if healthy >= len(self.faults) - 1:
            record = self.w.record()
            obs = self._loop.run_until_complete(self.honest.observe(SWAP, record))
            reference = decide(record=record, observations=obs, policy=_policy(), safety_window_blocks=SAFETY)
            if _RANK[_severity(decision)] < _RANK[_severity(reference)]:
                lowered = f"faults {self.faults} lowered {_key(reference)} ({reference.reason}) to {decision.intent.value} ({decision.reason})"
                assert reference.intent is not Intent.PAGE_SQUEEZED, lowered
                assert decision.intent is Intent.WATCH, lowered
                if "forge_refund" in self.faults:
                    assert _severity(reference) is not Severity.CRITICAL, lowered
                    assert "refunds the outpoint and is not yet buried" in decision.reason, lowered
                else:
                    assert "lie_depth" in self.faults, lowered
                    assert "awaiting reorg-safe burial" in decision.reason or "is not yet buried" in decision.reason, (
                        lowered
                    )
        if decision.autonomous_btc_refund:
            # What each source answers to "who spends the outpoint": an honest or depth-lying source the
            # chain's spender, a hiding one "unspent", a forging one its forgery; a source that is down or
            # fails the read answers nothing. Two hiding sources outvote one honest one at quorum 2 of 3,
            # and the machine allows that: it is the quorum's stated limit.
            says_unspent = sum(
                f == "hide_spender" or (f in ("ok", "lie_depth") and spender is None) for f in self.faults
            )
            names_one = sum(
                f.startswith("forge_") or (f in ("ok", "lie_depth") and spender is not None) for f in self.faults
            )
            assert says_unspent >= QUORUM and names_one == 0, (
                f"refund armed on faults {self.faults} with spender {spender}: {decision.reason}"
            )
        refund_unburied = (
            spender is not None
            and spender not in self.claims
            and self.w.chain.mined.get(spender, self.w.chain.head + 1) > self.w.chain.head - BURIAL + 1
        )
        window_open = taker_refund_window_open(
            now_block_height=self.w.rxd.tip,
            asset_locked_at_height=LOCKED_AT,
            t_rxd=self.w.record().terms.t_rxd,
            safety_window_blocks=SAFETY,
            maker_has_claimed_btc=False,
            block_interval_s=_policy().block_interval_s,
        )
        if healthy == len(self.faults) and refund_unburied and window_open:
            assert _severity(decision) is Severity.CRITICAL, (
                f"our unburied refund near t_rxd decided {decision.intent.value}: {decision.reason}"
            )

    @invariant()
    def count_never_negative(self) -> None:
        assert self.alerter.unacked_critical_count() >= 0


AlertPathMachine.TestCase.settings = settings(
    max_examples=200 * _BUDGET_MULT,
    stateful_step_count=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
test_alert_path_state_machine = AlertPathMachine.TestCase

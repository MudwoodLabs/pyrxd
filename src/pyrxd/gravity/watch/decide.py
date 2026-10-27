"""Pure decision core for the alert-only watchtower (BTC + ETH counter-legs).

``decide(record, observations, policy, safety_window_blocks)`` returns a
:class:`Decision` — an :class:`Intent` plus a human-actionable reason, the
coordinator step the operator should run, and the deadline. It is **pure**: no
chain calls, no I/O, exhaustively unit-testable, and it **consumes** the audited
gate (``assess_claim_finality``) and the maker-stall predicate
(``taker_refund_window_open``) rather than re-deriving them.

Key safety rules (mirrors the live coordinator, never routes around it):
* Chain truth dominates a lagging record: if the maker's counter-leg claim is
  observed on-chain (``maker_has_claimed_btc``), the asset claim is assessed
  REGARDLESS of ``record.state`` — a record stuck at ``BOTH_LOCKED`` while the
  chain shows the reveal must still page the claim race (spec-flow Gap 2/7).
  WHETHER to page is chain truth; WHICH STEP to name is the record, because the
  coordinator's claim methods are state-gated (``_claim_action``, #580).
* Fail-closed: any un-assessable input (missing depth/lock-height, a lying/lagging
  ``now < lock`` reading) pages a decision-required alert, never a silent "all
  clear".
* The page reflects the gate verdict: SAFE → page claim, WAIT → keep watching,
  SQUEEZED → page a decision-required (ASSET_VULNERABLE), never a silent claim.

Both counter-legs are handled (``counter_chain``): BTC's reorg finality is a PoW
confirmation DEPTH; ETH's is the post-Merge ``finalized`` CHECKPOINT (not a depth) —
the ETH path (``_decide_eth``) consumes the same ``assess_claim_finality`` via a
depth-less :class:`CounterClaimFinality`. Like v1 it broadcasts nothing — every
actionable Intent is a *page* to the operator, who runs the named one-shot
coordinator step (alert-only, outside the autonomy audit gate).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pyrxd.btc_wallet.disposition import BtcDispositionKind
from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.eth_wallet.disposition import DispositionKind
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.swap_coordinator import (
    ClaimFinality,
    MarginPolicy,
    assess_claim_finality,
    taker_refund_window_open,
)
from pyrxd.gravity.swap_state import NegotiatedTerms, RecordRole, SwapRecord, SwapState, is_terminal
from pyrxd.security.errors import ValidationError
from pyrxd.security.units import BlockSpan, ChainHeight, Confirmations, PhotonValue, Seconds

__all__ = ["Decision", "Intent", "LegacyCheck", "Observations", "decide", "decide_legacy"]


class Intent(Enum):
    """What the watchtower should do for one swap, this tick.

    v1 NEVER broadcasts; the ``PAGE_*`` intents are alerts that tell the operator
    which one-shot coordinator step to run and by when.

    * ``WATCH`` — nothing due yet; keep observing (no page, or a low-severity tick).
    * ``PAGE_CLAIM`` — the maker revealed ``p`` and the claim is reorg-safe + fits
      the window (gate SAFE). The tower **alerts and broadcasts nothing** — there is no
      autonomous claim executor in v1 — so the OPERATOR/taker MUST claim the asset before
      the deadline (the R1 free-option residual rests on this liveness; threat-model S20).
    * ``PAGE_REFUND`` — the maker stalled / params mismatch; the operator should
      refund (asset-on-stall or BTC counter-leg).
    * ``PAGE_SQUEEZED`` — a decision is required (gate SQUEEZED / ASSET_VULNERABLE,
      or finality un-assessable): winner-take-all claim vs accept loss. Never
      auto-resolved in v1.
    * ``RECONCILE`` — the chain has settled the counter leg (our refund is buried) and the record
      has not caught up; the operator runs the named step to bring it up to the chain (low
      severity: nothing is at risk, #850 PR 9b, design §5.1).
    * ``RETIRE`` — the swap reached a terminal state; stop watching it.
    * ``NOOP`` — an unsupported counter_chain (BTC and ETH are both handled).
    """

    WATCH = "watch"
    PAGE_CLAIM = "page_claim"
    PAGE_REFUND = "page_refund"
    PAGE_SQUEEZED = "page_squeezed"
    RECONCILE = "reconcile"
    RETIRE = "retire"
    NOOP = "noop"


@dataclass(frozen=True)
class Observations:
    """Chain-derived inputs for one swap, this tick. Built by the quorum layer.

    All heights are Radiant (RXD) block heights except where the field name says
    otherwise. ``btc_claim_confirmations`` is the quorum-agreed depth of the
    maker's BTC counter-leg claim (``None`` until/unless a claim is observed). The ETH
    counter-leg fields ``eth_claim_detected`` / ``eth_claim_finality`` are the
    checkpoint-not-depth analogue (the maker's ETH claim + its ``finalized``-checkpoint
    verdict state), populated only for an ETH swap — see the inline note below.
    ``low_corroboration`` flags an RXD (or single-source ETH RPC) read that could not be
    cross-checked against a source on another host — a false read here causes a false *page*,
    never a false broadcast.
    """

    # UNITS. This struct holds both HEIGHTS and DEPTHS side by side, which is exactly how the
    # two got swapped before: both are non-negative ints and 0 is meaningful under each
    # reading. They are unit-tagged now, so putting a depth in a height slot (or the reverse)
    # is a mypy error at the construction site — see `pyrxd.security.units`.
    maker_has_claimed_btc: bool
    now_rxd_height: ChainHeight
    asset_locked_at_height: ChainHeight | None = None
    btc_claim_confirmations: Confirmations | None = None
    # Quorum-agreed depth of the taker's BTC FUNDING outpoint (distinct from btc_claim_confirmations,
    # which is the maker's CLAIM-tx depth). Read only when heading toward a BTC refund (state
    # BTC_LOCKED / PARAMS_MISMATCH); gates the relative-CSV maturity (funding buried >= t_btc) for an
    # autonomous refund. ``None`` until/unless read — the refund branch fails closed on None.
    btc_funding_confirmations: Confirmations | None = None
    # ETH counter-leg (v3). ``eth_claim_detected`` = the maker's ETH claim tx was observed on-chain;
    # ``eth_claim_finality`` = its point-in-time finalized-checkpoint verdict STATE (FINAL /
    # NOT_YET_FINAL_LIVE / COUNTER_CHAIN_NOT_FINALIZING), ``None`` until/unless a claim is observed.
    # ETH finality is a CHECKPOINT, not a DEPTH — there is no ETH analogue of
    # ``btc_claim_confirmations``; ``decide()`` rebuilds a depth-less ``CounterClaimFinality`` from
    # this state (so it consumes the audited gate verdict and never re-derives finality).
    eth_claim_detected: bool = False
    eth_claim_finality: CounterClaimState | None = None
    # Wall-clock (unix seconds) for the ETH counter leg, whose refund deadline is the ABSOLUTE
    # ``terms.eth_timeout_unix_s`` contract immutable rather than a confirmation depth. It is the
    # ETH analogue of ``btc_funding_confirmations``: the one reading that lets the maker-never-locks
    # branch prove the taker's counter-leg refund is DUE. ``None`` (the default, and every
    # pre-existing caller) keeps that branch fail-closed to WATCH — exactly as the BTC branch
    # watches on an unread funding depth — so an absent clock can never manufacture a page.
    now_unix_s: Seconds | None = None
    low_corroboration: bool = False
    # BTC spender classification (#850 PR 9b, design §6). ``btc_spend_classified`` is True only when
    # this tick read the funding outpoint's spenders through the shared disposition reader, which
    # tells a spend by the refund leaf (ours, the operator's or the tower's pre-signed one: by
    # script path, never by txid) from a claim. False (the default, and every source that cannot
    # classify) keeps the pre-9b rules: any spend is a claim, and autonomy stays off while the
    # covenant is observed. ``btc_disposition`` is that read's kind; ``btc_refund_txid`` names a
    # refund-leaf spend it saw, buried or not; ``btc_disposition_reason`` is its reason, for the page.
    # ``maker_has_claimed_btc`` stays the claim trigger: the observer sets it on any claim seen, and
    # on any spend the read could not prove is a refund.
    btc_spend_classified: bool = False
    btc_disposition: BtcDispositionKind | None = None
    btc_refund_txid: str | None = None
    btc_disposition_reason: str | None = None
    #: Whether the read names any spender at all (an UNKNOWN with one is a contradiction, not a lag).
    btc_spenders_named: bool = False
    #: Whether a source SERVED a claim witness (one that opens H). ``maker_has_claimed_btc`` is also set
    #: by a spender only discovery named, which proves nothing about ``p`` (Mythos F4).
    btc_claim_witness_seen: bool = False
    #: Whether the read is one source's answer (quorum 1, or one source): it marks the decision
    #: ``low_corroboration``, and a single-source REFUNDED is read as still pending (Mythos F6; design
    #: §5.1, "a single endpoint's Refunded() never stops a page").
    btc_single_source: bool = False
    # ETH counter-leg disposition (#850 PR 10, design §5.1): the shared reader the coordinator uses
    # (``pyrxd.eth_wallet.disposition.read_counter_disposition``) over the ETH source's endpoints.
    # ``eth_disposition`` is its kind, set exactly when this tick read one; ``None`` (the default, and
    # every source that cannot read one) keeps the pre-10 rules. ``eth_claim_seen``: a ``Claimed(p)``
    # log that opens H was nominated, or a claim the record kept, so p is public; the observer then also
    # sets ``eth_claim_detected``. ``eth_single_source``: the read is one endpoint's; it may page, never
    # stop a page, and it marks the decision ``low_corroboration`` (design §5.1). ``eth_disposition_tx``
    # is the transaction a terminal answer rests on (``None`` for Gap B or a non-terminal answer).
    # ``eth_settled_at_finalized`` is the reader's flag on an UNKNOWN that read the contract settled at
    # the finalized block. ``eth_nonce_at_finalized`` is the push key's count there, on an
    # ``EXPIRED_EMPTY_*`` answer that read it (the nonce ``close_push_nonce`` consumes).
    eth_disposition: DispositionKind | None = None
    eth_disposition_reason: str | None = None
    eth_disposition_tx: str | None = None
    eth_claim_seen: bool = False
    eth_single_source: bool = False
    eth_settled_at_finalized: bool = False
    eth_nonce_at_finalized: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.maker_has_claimed_btc, bool):
            raise ValidationError("Observations.maker_has_claimed_btc must be bool")
        if not isinstance(self.now_rxd_height, int) or isinstance(self.now_rxd_height, bool) or self.now_rxd_height < 0:
            raise ValidationError("Observations.now_rxd_height must be a non-negative int")
        for label, val in (
            ("asset_locked_at_height", self.asset_locked_at_height),
            ("btc_claim_confirmations", self.btc_claim_confirmations),
            ("btc_funding_confirmations", self.btc_funding_confirmations),
            ("now_unix_s", self.now_unix_s),
        ):
            if val is not None and (not isinstance(val, int) or isinstance(val, bool) or val < 0):
                raise ValidationError(f"Observations.{label} must be a non-negative int or None")
        if not isinstance(self.eth_claim_detected, bool):
            raise ValidationError("Observations.eth_claim_detected must be bool")
        if self.eth_claim_finality is not None and not isinstance(self.eth_claim_finality, CounterClaimState):
            raise ValidationError("Observations.eth_claim_finality must be a CounterClaimState or None")
        if not isinstance(self.low_corroboration, bool):
            raise ValidationError("Observations.low_corroboration must be bool")
        if not isinstance(self.btc_spend_classified, bool) or not isinstance(self.btc_spenders_named, bool):
            raise ValidationError("Observations.btc_spend_classified and btc_spenders_named must be bool")
        if not isinstance(self.btc_single_source, bool) or (self.btc_single_source and not self.btc_spend_classified):
            raise ValidationError("Observations.btc_single_source must be bool, and needs a classified read")
        if not isinstance(self.btc_claim_witness_seen, bool):
            raise ValidationError("Observations.btc_claim_witness_seen must be bool")
        if self.btc_claim_witness_seen and not (self.btc_spend_classified and self.maker_has_claimed_btc):
            raise ValidationError("Observations.btc_claim_witness_seen needs a classified read and the claim trigger")
        if self.btc_disposition is not None and not isinstance(self.btc_disposition, BtcDispositionKind):
            raise ValidationError("Observations.btc_disposition must be a BtcDispositionKind or None")
        if self.btc_spend_classified != (self.btc_disposition is not None):
            raise ValidationError("Observations.btc_disposition is set exactly when btc_spend_classified")
        if self.btc_refund_txid is not None and (
            not isinstance(self.btc_refund_txid, str) or len(self.btc_refund_txid) != 64
        ):
            raise ValidationError("Observations.btc_refund_txid must be a 64-char txid or None")
        if self.btc_refund_txid is not None and not self.btc_spend_classified:
            raise ValidationError("Observations.btc_refund_txid needs a classified read")
        if (
            self.btc_disposition in (BtcDispositionKind.CLAIM_SEEN, BtcDispositionKind.CLAIMED)
            and not self.maker_has_claimed_btc
        ):
            raise ValidationError("a claim read must set maker_has_claimed_btc (the claim trigger)")
        if self.eth_disposition is not None and not isinstance(self.eth_disposition, DispositionKind):
            raise ValidationError("Observations.eth_disposition must be a DispositionKind or None")
        for label, flag in (
            ("eth_claim_seen", self.eth_claim_seen),
            ("eth_single_source", self.eth_single_source),
            ("eth_settled_at_finalized", self.eth_settled_at_finalized),
        ):
            if not isinstance(flag, bool):
                raise ValidationError(f"Observations.{label} must be bool")
        if self.eth_disposition is None and (
            self.eth_claim_seen
            or self.eth_single_source
            or self.eth_settled_at_finalized
            or self.eth_disposition_reason is not None
            or self.eth_disposition_tx is not None
            or self.eth_nonce_at_finalized is not None
        ):
            raise ValidationError("the eth_disposition_* fields need an ETH disposition read (eth_disposition)")
        if self.eth_disposition_reason is not None and not isinstance(self.eth_disposition_reason, str):
            raise ValidationError("Observations.eth_disposition_reason must be a str or None")
        if self.eth_disposition_tx is not None and (
            not isinstance(self.eth_disposition_tx, str) or not self.eth_disposition_tx.startswith("0x")
        ):
            raise ValidationError("Observations.eth_disposition_tx must be a 0x-prefixed hash or None")
        if self.eth_nonce_at_finalized is not None and (
            not isinstance(self.eth_nonce_at_finalized, int)
            or isinstance(self.eth_nonce_at_finalized, bool)
            or self.eth_nonce_at_finalized < 0
        ):
            raise ValidationError("Observations.eth_nonce_at_finalized must be a non-negative int or None")
        if (self.eth_claim_seen or self.eth_disposition is DispositionKind.CLAIMED) and not self.eth_claim_detected:
            raise ValidationError("an ETH claim read must set eth_claim_detected (the claim trigger)")
        if self.eth_settled_at_finalized and self.eth_disposition is not DispositionKind.UNKNOWN:
            raise ValidationError("Observations.eth_settled_at_finalized is the reader's flag on an UNKNOWN answer")


@dataclass(frozen=True)
class Decision:
    """The watchtower's conclusion for one swap, this tick.

    ``recommended_action`` names the coordinator step(s) the operator should run (a string,
    for the alert payload — v1 does not invoke it). It is chosen for the RECORD'S OWN STATE,
    because both claim methods are strictly state-gated and a name the record cannot run
    costs claim window (#580) — see :func:`_claim_action`. Usually one step; a lagging or
    already-squeezed record legitimately needs a short sequence, and where no step applies it
    says so rather than naming one. ``deadline_rxd_height``
    is the RXD height by which the action must land (the maker's CSV refund opens),
    or ``None`` when not time-bounded. ``low_corroboration`` is propagated from the
    observations so the alert layer can mark a single-source page.
    """

    intent: Intent
    reason: str
    recommended_action: str | None = None
    deadline_rxd_height: int | None = None
    low_corroboration: bool = False
    # TYPED autonomy discriminator. True ONLY on a BTC keyless-pre-signed-refund decision whose BTC CSV
    # has MATURED — the v2 autonomous executor keys on THIS, never on the ``recommended_action`` display
    # string (the ETH PARAMS_MISMATCH branch also emits "taker_refund_btc", so a string match would
    # wrongly arm on an ETH swap). Always False for every claim/squeeze/ETH/immature-refund decision.
    autonomous_btc_refund: bool = False
    # TYPED autonomy discriminator for the autonomous asset CLAIM (the ClaimExecutor keys on THIS). True
    # ONLY on a BTC↔RXD SAFE claim race (maker revealed p, BTC claim reorg-final, burial fits the window).
    # NEVER set on the ETH branch — the ETH SAFE PAGE_CLAIM branch emits the same "taker_scrape_and_claim_
    # asset" display string (decide.py ETH path), so a string match would wrongly arm on an ETH swap whose
    # p-scrape source + finality model are out of scope here. The executor additionally re-asserts SAFE
    # against a FRESH read before broadcasting (a tick-open verdict is stale on a cheap-reorg chain).
    autonomous_asset_claim: bool = False
    # Tells two situations with the same intent apart for the alerter's dedup and operator ACK (#850 PR
    # 9b, Mythos F1): an ACK of "our refund is pending near t_rxd" must not silence the claim race that
    # replaces it, which is a PAGE_SQUEEZED too. ``None`` for every decision that needs no such tag.
    situation: str | None = None
    # A refund page that is as time-critical as a race (#850 PR 9b, Mythos F3): the HTLC is still the
    # taker's to refund while t_rxd is near or past, so the alerter pages it CRITICAL and re-pages it,
    # rather than once as WARN. Only valid on PAGE_REFUND, which keeps its autonomy discriminator.
    urgent: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.intent, Intent):
            raise ValidationError("Decision.intent must be an Intent")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValidationError("Decision.reason must be a non-empty str")
        if not isinstance(self.autonomous_btc_refund, bool):
            raise ValidationError("Decision.autonomous_btc_refund must be bool")
        if not isinstance(self.autonomous_asset_claim, bool):
            raise ValidationError("Decision.autonomous_asset_claim must be bool")
        # Mutual exclusion FIRST (so it is reachable; each per-flag check below pins a different intent).
        # NOTE the identifiers keep the message out of redact()'s BIP-39 (>=8 lowercase words) heuristic.
        if self.autonomous_btc_refund and self.autonomous_asset_claim:
            raise ValidationError("a Decision cannot set both autonomous_btc_refund and autonomous_asset_claim")
        if self.autonomous_btc_refund and self.intent is not Intent.PAGE_REFUND:
            raise ValidationError("autonomous_btc_refund is only valid on a PAGE_REFUND decision")
        if self.autonomous_asset_claim and self.intent is not Intent.PAGE_CLAIM:
            raise ValidationError("autonomous_asset_claim is only valid on a PAGE_CLAIM decision")
        if self.situation is not None and (not isinstance(self.situation, str) or not self.situation):
            raise ValidationError("Decision.situation must be a non-empty str or None")
        if not isinstance(self.urgent, bool):
            raise ValidationError("Decision.urgent must be bool")
        if self.urgent and self.intent is not Intent.PAGE_REFUND:
            raise ValidationError("Decision.urgent is only valid on a PAGE_REFUND decision")


def _value_at_risk_photons(terms: NegotiatedTerms) -> PhotonValue | None:
    """The per-record value-at-risk (photons) for the value-scaled burial — the watchtower's
    per-swap input so one tower policy judges many swaps correctly (audit follow-up).

    Only an RXD swap's ``radiant_amount`` IS the photon economic value. For FT/NFT the on-chain
    amount is the token amount / NFT carrier dust, NOT the off-chain economic value the
    watchtower cannot see — so return None, and ``assess_claim_finality`` fails closed
    (SQUEEZED, never a value-blind SAFE) whenever value-scaling is configured on the policy.
    """
    # The variant check IS the proof of unit, so the re-tag belongs right here and nowhere
    # else: `radiant_amount` is `PhotonValue | TokenUnits`, and only the "rxd" branch has
    # established which. An "ft" amount reaching a photons-typed slot is #505.
    return PhotonValue(terms.radiant_amount) if terms.asset_variant == "rxd" else None


def _required_btc_depth_blocks(policy: MarginPolicy) -> BlockSpan:
    """The reorg depth the FINAL verdict requires, in blocks.

    THE SAME NUMBER AS THE GATE'S OWN RESERVE ONLY WHILE ``btc_claim_reorg_depth`` IS
    BLOCKS-TAGGED, which is what every constructor in this repo produces (``measured_policy``
    and ``watch/run.py`` both build a ``TimeUnit.BLOCKS`` Timelock, as does the field default).
    On a BLOCKS value both conversions are the identity and the two agree.

    THE DOCSTRING HERE CLAIMED MORE THAN THAT — "identical to the coordinator's construction
    (swap_coordinator.py:1258-1260), so the verdict and the gate's internal reserve cannot
    diverge". Both halves are wrong. The line reference has drifted onto an unrelated comment
    about the seen-store; the construction lives in ``assess_claim_finality`` as
    ``_reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s)``. And the two
    are NOT the same conversion: ``_reserve_to_blocks`` CEILS a seconds-tagged reserve (flooring
    under-counts a reserve — the unsafe direction), while ``normalize_to`` FLOORS. Measured at
    ``btc_claim_reorg_depth = Timelock(3700, SECONDS)`` with ``block_interval_s = 600``: this
    function returns 6 and the gate computes 7, and the divergence lands in BOTH directions —

      * 5 confirmations: the mismatch guard in ``assess_claim_finality`` raises, ``decide``
        catches it, and an honest WATCH is degraded to PAGE_SQUEEZED "un-assessable";
      * 6 confirmations: the FINAL branch returns BEFORE that guard is reached, so the tower
        pages PAGE_CLAIM and arms ``autonomous_asset_claim`` one block shallower than the
        policy's own reserve requires.

    So the mismatch guard did not make them agree; it fired only on the WAIT path.

    FIXED by using the gate's own conversion here rather than a second one. The two now
    agree by construction instead of by coincidence, which is what the original sentence
    claimed. Measured: identical for every BLOCKS-tagged value — everything this repo
    constructs — so no shipped configuration changes behaviour.
    """
    # ONE CONVERSION, the gate's. `_reserve_to_blocks` is what `assess_claim_finality`
    # uses, so calling it here is what makes "cannot diverge" true instead of merely
    # intended — the divergence above is not a documentation problem, it is two
    # roundings of one quantity.
    #
    # It CEILS, and that is the safe direction for a reserve: flooring under-counts,
    # which is what armed the autonomous claim a block shallow. Identity-preserving
    # for every BLOCKS-tagged value, which is everything this repo constructs, so
    # nothing in the shipped configuration space changes.
    from ..swap_coordinator import _reserve_to_blocks

    return BlockSpan(_reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s))


def _refund_opens_at(policy: MarginPolicy, terms: NegotiatedTerms, asset_locked_at_height: ChainHeight) -> ChainHeight:
    """RXD height at which the maker's CSV refund opens (the claim deadline).

    UNITS: a ChainHeight plus a BlockSpan is a ChainHeight. The anchor must be the height the
    covenant was MINED at — a confirmation depth here puts the deadline a whole chain-length
    out of place, which is precisely the inversion the shim fix created downstream.
    """
    # floor-is-deliberate: this IS the claim deadline, and every consumer counts blocks REMAINING
    # to it. A smaller deadline yields less headroom, so the tower pages a squeeze sooner rather
    # than certifying a claim race it has not got room for. (No-op: t_rxd is pinned to BLOCKS.)
    t_rxd_blocks = BlockSpan(terms.t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value)
    return ChainHeight(int(asset_locked_at_height) + int(t_rxd_blocks))


def _btc_refund_matured(terms: NegotiatedTerms, obs: Observations) -> bool:
    """True iff the taker's BTC CSV refund leaf has PROVABLY matured — the gate for an *autonomous*
    refund (an alert-only page still goes out regardless; this only decides ``autonomous_btc_refund``).

    Two fail-closed conditions: (1) ``t_btc`` is a BLOCKS relative lock — a SECONDS/MTP lock cannot be
    proven mature from a confirmation count, so we never auto-act on one; (2) the funding outpoint is
    buried ``>= t_btc`` blocks. The funding-depth read shares the dust-path single-source posture, but
    unlike the RXD *trigger* it is consensus-backstopped: a forged OVER-report still fails BIP68 (the
    real outpoint is not mature → the node rejects the spend) and an under-report only DELAYS.
    """
    return (
        terms.t_btc.unit is TimeUnit.BLOCKS
        and obs.btc_funding_confirmations is not None
        and obs.btc_funding_confirmations >= terms.t_btc.value
    )


# -- naming a coordinator step the coordinator will actually ACCEPT (#580) --------------------
#
# ``decide()`` assesses the claim race from CHAIN TRUTH and deliberately ignores ``record.state``
# when deciding WHETHER to page — a record stuck at BOTH_LOCKED while the chain shows the reveal
# must still page the claim race. But WHICH step to name is a different question, and it is
# answered by the record, because both claim methods are strictly state-gated:
#
#   taker_scrape_and_claim_asset       — SECRET_REVEALED only  (swap_coordinator.py:3979, :4049)
#   taker_claim_asset_from_vulnerable  — ASSET_VULNERABLE only (swap_coordinator.py:4122, :4138)
#   taker_observed_reveal              — BOTH_LOCKED only      (swap_coordinator.py:3910)
#
# Naming a step the record cannot run burns claim window at exactly the moment it is scarcest:
# after ``p`` is public, under a running timelock, at 3am. The page said
# "taker_scrape_and_claim_asset" for EVERY state, so an ASSET_VULNERABLE record — the state the
# gate itself creates when it squeezes — was paged an action that raises
# "only valid from SECRET_REVEALED, not asset_vulnerable".
#
# THE COORDINATOR IS RIGHT AND THE PAGE WAS WRONG. Both guards are load-bearing, not incidental:
# taker_scrape_and_claim_asset's own SQUEEZED branch advances TAKER_OFFLINE_OR_PINNED, a transition
# the FSM does not allow FROM ASSET_VULNERABLE, so accepting it there would trade a clear refusal
# for a raise several network reads later; and taker_claim_asset_from_vulnerable deliberately
# SKIPS the reorg gate ("a CONSCIOUS choice the caller makes after the gate refused the automatic
# SAFE claim — never invoked silently"), so accepting it from SECRET_REVEALED would make that gate
# skippable by accident. The FSM already allows both routes to COMPLETED; only the alert text was
# wrong, so only the alert text changes here.
#
# The pattern already existed for ONE action — "investigate (mutual_refund is only valid from
# BOTH_LOCKED)" on the MAKER_STALLS branches — and was never generalised. This generalises it.
# nosec B105 x2 below — bandit keys on the SECRET in these NAMES; the values are coordinator
# method names bound for an alert payload, the same false positive SwapState.SECRET_REVEALED
# carries. Nothing here is a credential and none of it goes near `p`.
_STEP_TO_SECRET_REVEALED = "taker_observed_reveal"  # nosec B105
_STEP_FROM_SECRET_REVEALED = "taker_scrape_and_claim_asset"  # nosec B105
_STEP_FROM_VULNERABLE = "taker_claim_asset_from_vulnerable"
_STEP_RECONCILE = "reconcile_counter_leg"

# The BOTH_LOCKED maker-stall page, per counter chain (#850). The two differ because mutual_refund
# does: on an ETH counter leg it reads the HTLC from the chain and keeps the record BOTH_LOCKED until
# our refund is final at the finalized block, so it is called until it ends (#850 PR 6). A
# TAKER-role coordinator then takes MUTUAL_REFUND without the covenant (its refund pays the maker
# and is the maker's to send); with no role the covenant refund follows. Until then the tower sees
# the same situation; DedupAlerter delivers a WARN once per situation, from in-memory state. On a BTC
# counter leg mutual_refund is unchanged in this release: it also sends the covenant refund, which
# cannot be mined before t_rxd, and reaches the terminal MUTUAL_REFUND.
#
# Both replace a sentence that said the counter leg "cannot mature until t_btc > t_rxd". The
# relation was inverted in #482. The gates require t_rxd's refund to open no earlier than the
# counter deadline plus the margin (``assert_timelock_margin`` on BTC, in wall clock; the
# ``eth_rxd_timelock`` cross-clock gate on ETH, against ``eth_timeout_unix_s``).
_BOTH_LOCKED_REFUND_COMMON = (
    "maker has not claimed and t_rxd maturity approaching — prepare to mutual_refund. The deadline "
    "shown is t_rxd, when the maker's CSV refund of the covenant opens. "
)
_BOTH_LOCKED_REFUND_REASON_BTC = _BOTH_LOCKED_REFUND_COMMON + (
    "The BTC refund opens first (the swap was gated so the covenant refund opens no earlier than the BTC refund plus the margin, in wall-clock time). On "
    "a BTC counter leg mutual_refund also broadcasts the covenant refund, so run it once BOTH timeouts "
    "have elapsed."
)
_BOTH_LOCKED_REFUND_REASON_ETH = _BOTH_LOCKED_REFUND_COMMON + (
    "The ETH refund opens first (the swap was gated on the covenant refund opening no earlier than "
    "eth_timeout_unix_s + margin). On an ETH counter leg that reads its disposition, mutual_refund "
    "reads the HTLC from the chain, then sends or follows your ETH refund; the record stays BOTH_LOCKED "
    "until that refund is final at the finalized block, so run it again (the two-host runner's --phase "
    "refund polls) until it ends. A TAKER-role run ends at MUTUAL_REFUND without touching the covenant "
    "(the maker's to refund); with no role the covenant refund follows. While a Claimed log that opens H "
    "is on record, neither happens until the covenant's own timelock has matured: claim the covenant first. If the chain cannot say what "
    "happened to the contract and the refund is refused, it raises CounterLegDispositionUnknown: check "
    "the contract's events on another source before the covenant's CSV refund opens. On a leg that "
    "cannot read its disposition, a TAKER-role run sends the refund once and the record stays "
    "BOTH_LOCKED, so this situation does not clear after you run it: check the refund on-chain."
)

# -- the record's role (#850 PR 1b, design §5.1) ------------------------------------------------
#
# A MAKER's record does not need its counter leg refunded: the counter leg is the TAKER's money. When
# the maker has not claimed by the counter deadline, what the maker is owed is its own covenant back
# by the CSV refund at t_rxd. Paging a maker "taker_refund_btc" or "mutual_refund" named the other
# party's step. A record with no role (written before 0.27) is paged as before, as the TAKER or
# single-operator row, but it never arms an autonomous broadcast: the tower cannot tell whose
# money the step would move.
_MAKER_COVENANT_REFUND_ACTION = (
    "refund your covenant by its CSV leg once t_rxd matures: it is the maker's to send and pays the "
    "maker (two-host runners: maker --phase abort if the taker never funded, --phase refund otherwise)"
)


def _maker_covenant_refund(why: str, *, deadline: ChainHeight | None, corr: bool, situation: str) -> Decision:
    return Decision(
        Intent.PAGE_REFUND,
        reason=f"{why}; your covenant is refundable to you at t_rxd (the deadline shown, when known)",
        recommended_action=_MAKER_COVENANT_REFUND_ACTION,
        deadline_rxd_height=deadline,
        low_corroboration=corr,
        situation=situation,
    )


def _covenant_known(record: SwapRecord, obs: Observations) -> bool:
    """Whether the maker's covenant is known to exist: observed this tick, OR pinned on the record.

    The pin is set when a taker's fund verifies the covenant (the gate cannot pass without it), so it
    is proof the maker locked. An empty or failed depth read is not evidence otherwise: the tower's
    sources return "absent" on a read that raised, and a gate keyed on the read alone armed the
    autonomous refund, with "maker never locked" text, the moment the read failed (review M1)."""
    return obs.asset_locked_at_height is not None or record.radiant_covenant_outpoint is not None


def _no_autonomy_note(record: SwapRecord) -> str:
    """Said on a page that would have been autonomous, when the record's role is what stops it."""
    if record.role is None:
        return " Not autonomous: the record names no role (written before 0.27), so the tower only pages."
    if record.role is RecordRole.MAKER:
        return " Not autonomous: this is the maker's record."
    return ""


def _autonomy_allowed(record: SwapRecord) -> bool:
    """An autonomous broadcast acts for the TAKER (or the single operator who is both). Never for a
    MAKER's record, and never for a record that does not say whose it is."""
    return record.role in (RecordRole.TAKER, RecordRole.NONE)


#: Coordinator steps, IN ORDER, that carry a record at this state to a claimed asset. A state
#: absent here has NO valid claim step and is paged "investigate" rather than a name that raises.
#: Cross-checked against the coordinator's own ``record.state is not …`` / ``state not in (…)``
#: guards, read out of the source by ``tests/test_watch_pages_name_state_valid_steps.py`` — so a
#: guard that moves, or a step renamed, is a failing test rather than a 3am refusal.
_CLAIM_PATH: dict[SwapState, tuple[str, ...]] = {
    # The record lags the chain (the case the module docstring calls spec-flow Gap 2/7).
    # ``taker_observed_reveal`` is the taker-side BOTH_LOCKED -> SECRET_REVEALED transition; it
    # re-verifies the reveal (sha256(p) == H + the per-swap provenance gate) and does NOT claim,
    # so the gated claim still runs its own finality gate afterwards.
    SwapState.BOTH_LOCKED: (_STEP_TO_SECRET_REVEALED, _STEP_FROM_SECRET_REVEALED),
    # A record at BTC_LOCKED lags a claim the chain already shows (#850 PR 10, design §5.1).
    # ``reconcile_counter_leg`` takes BTC_LOCKED -> SECRET_REVEALED on a CLAIMED disposition (verified at
    # the finalized block on ETH, buried at the coordinator's depth on BTC) for a taker's or single
    # operator's record that pins the covenant outpoint; on a claim not yet final it only records the
    # claim, and the operator runs it again. It sends nothing.
    SwapState.BTC_LOCKED: (_STEP_RECONCILE, _STEP_FROM_SECRET_REVEALED),
    SwapState.SECRET_REVEALED: (_STEP_FROM_SECRET_REVEALED,),
    SwapState.ASSET_VULNERABLE: (_STEP_FROM_VULNERABLE,),
}


def _claim_action(
    state: SwapState, *, role: RecordRole | None = None, winner_take_all: bool = False, note: str = ""
) -> str:
    """The claim step(s) the coordinator will ACCEPT from ``state``, as an alert-payload string.

    ``winner_take_all`` names the SQUEEZED decision, whose endpoint is always
    ``taker_claim_asset_from_vulnerable`` — ASSET_VULNERABLE-only, and the gated claim is what puts
    a record there. From SECRET_REVEALED/BOTH_LOCKED that is a genuine two-or-three-step sequence,
    and saying so is the point: the previous single name was a step the record could not run.

    Falls back to an ``investigate`` page — never a step name — for any state with no valid claim
    path, mirroring the MAKER_STALLS branches. That is a REPORT, not a refusal: the page still goes
    out at the same severity with the same deadline, and it states which step needs which state so
    the operator can act instead of discovering it from a ValidationError.
    """
    if role is RecordRole.MAKER and state is SwapState.BTC_LOCKED:
        # On a maker's record ``reconcile_counter_leg`` only records the claim and leaves the state, so
        # no claim step follows it; the covenant claim is the taker's (#850 PR 10, review F4).
        return (
            f"{_STEP_RECONCILE} (on a maker's record it records the claim and leaves btc_locked; "
            "no covenant claim step follows, that claim is the taker's)" + (f" ({note})" if note else "")
        )
    path = _CLAIM_PATH.get(state)
    if path is None:
        return (
            f"investigate — no coordinator claim step is valid from {state.value} "
            f"({_STEP_FROM_SECRET_REVEALED} requires secret_revealed, "
            f"{_STEP_FROM_VULNERABLE} requires asset_vulnerable, "
            f"{_STEP_TO_SECRET_REVEALED} requires both_locked, "
            f"{_STEP_RECONCILE} leads to secret_revealed only from btc_locked)"
        )
    if winner_take_all and path[-1] != _STEP_FROM_VULNERABLE:
        # The gated claim re-runs the finality gate against a FRESH read: it claims outright if the
        # window reopened to SAFE, does nothing on WAIT, and on SQUEEZED advances the record to
        # ASSET_VULNERABLE — which is what makes the final step runnable. All three are correct
        # outcomes, so naming it first is right regardless of which one the fresh read produces.
        path = (*path, _STEP_FROM_VULNERABLE)
        action = f"{', then '.join(path[:-1])} (its gate advances a still-squeezed record to asset_vulnerable), then {path[-1]}"
    else:
        action = ", then ".join(path)
    if winner_take_all:
        action += " (winner-take-all) vs accept loss"
    if note:
        action += f" ({note})"
    return action


# -- the BTC funding outpoint's spender, classified (#850 PR 9b, design §6, D12) ----------------
#
# Before 9b the tower's claim source reported ANY spend of the funding outpoint as the maker's claim
# (``OutspendBtcClaimSource.claim_status``). Our own refund spends that outpoint too, so the tower
# could not broadcast the pre-signed refund while the maker's covenant was observed (PR 1b): it would
# then have read its own refund as a claim, and a refund that lost to a real claim would have looked
# the same as one that won. With the spender classified by the leaf it spends, the refund leaf is
# ours whoever sent it, and a claim that replaces it pages the covenant claim, so the autonomy is
# re-armed on a classified read that holds the outpoint unspent.


#: How to bump our pending BTC refund, said wherever the tower tells the operator to (D12). The
#: coordinator recognises any refund-leaf spend as ours, and replaces it by BIP125 only once that one
#: process has seen it in the mempool for ``REFUND_REPLACE_AFTER_S``; a single call may only wait.
_BUMP_HOW = (
    "it follows our refund (the tower's pre-signed one too) and replaces it at a higher fee once it has been "
    "in the mempool for REFUND_REPLACE_AFTER_S in that one process, so keep it running (the two-host "
    "runner's --phase refund polls)"
)


def _btc_refund_maturity_unread(terms: NegotiatedTerms, obs: Observations) -> bool:
    """Whether the tower cannot tell if the BTC refund leaf has matured: the funding depth was not
    read, or ``t_btc`` is not in blocks (second Mythos pass, M2)."""
    return obs.btc_funding_confirmations is None or terms.t_btc.unit is not TimeUnit.BLOCKS


def _btc_refund_buried(obs: Observations) -> bool:
    """Our refund is buried on a corroborated read. One source's "buried" decides nothing here: it is
    read as still pending (design §5.1; Mythos F6 and its re-review)."""
    return obs.btc_disposition is BtcDispositionKind.REFUNDED and not obs.btc_single_source


def _btc_refunded_beside_claim_trigger(record: SwapRecord, obs: Observations) -> bool:
    """Our refund is buried and the claim trigger is set beside it: not a claim race on a claim that
    will never be mined (review of PR 9b, M1). Paged below as a covenant claim when a claim witness
    was served (:func:`_btc_refund_lost_claim_seen`), else as a disagreement to investigate."""
    return (
        obs.btc_spend_classified
        and _btc_refund_buried(obs)
        and obs.maker_has_claimed_btc
        and record.state in (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH, SwapState.BOTH_LOCKED)
    )


def _btc_refund_lost_claim_seen(record: SwapRecord, obs: Observations) -> bool:
    """Our refund is buried and a claim witness was SERVED beside it (D14 seen on the chain): the
    claim lost, but ``p`` is public. A spender that only discovery named is not this (Mythos F4)."""
    return _btc_refunded_beside_claim_trigger(record, obs) and obs.btc_claim_witness_seen


def _t_rxd_near(record: SwapRecord, obs: Observations, policy: MarginPolicy, safety_window_blocks: int) -> bool:
    """Whether the maker's covenant exists and t_rxd is within the safety window, or past it: once t_rxd
    matures the maker can refund the covenant by its CSV leg AND still claim the BTC (the claim leaf has
    no timelock), so a BTC HTLC still the taker's to refund is then as urgent as a race (#850 PR 9b,
    Mythos F3). The predicate the BOTH_LOCKED maker-stall page uses. A known covenant whose lock height
    could not be read, or heights the predicate cannot evaluate, fail closed toward urgent."""
    if not _covenant_known(record, obs):
        return False
    if obs.asset_locked_at_height is None:
        return True
    try:
        return taker_refund_window_open(
            now_block_height=obs.now_rxd_height,
            asset_locked_at_height=obs.asset_locked_at_height,
            t_rxd=record.terms.t_rxd,
            safety_window_blocks=safety_window_blocks,
            maker_has_claimed_btc=False,
            block_interval_s=policy.block_interval_s,
        )
    except ValidationError:
        return True


#: The ``Decision.situation`` of the page for our pending refund near t_rxd (Mythos F1). It is a
#: PAGE_SQUEEZED like the claim race that replaces the refund, and an ACK of one must not silence the
#: other.
SITUATION_BTC_REFUND_PENDING = "btc_refund_pending"
#: The ``situation`` of the page for sources that contradict each other on the spender, and of the
#: page for a spender only discovery names beside our buried refund: an ACK of either must not
#: silence the claim race (re-review of the F1 fix).
SITUATION_BTC_SPENDER_CONTRADICTION = "btc_spender_contradiction"
SITUATION_BTC_DISCOVERY_DISAGREES = "btc_discovery_disagrees"
#: The other CRITICAL page families (second Mythos pass, H1): every PAGE_SQUEEZED and PAGE_CLAIM names
#: one, so no two dangers share an ACK. ``tests/test_watch_btc_refund_pages_through_the_alerter.py``
#: derives the construction sites from the source and fails on one without a tag.
SITUATION_CLAIM_RACE = "claim_race"
SITUATION_CLAIM_SEEN_P_PUBLIC = "claim_seen_p_public"
SITUATION_ASSET_VULNERABLE = "asset_vulnerable"
SITUATION_UNEXPECTED_STATE = "unexpected_state"
SITUATION_LEGACY_UNCLASSIFIED_SPEND = "legacy_unclassified_spend"
#: A refund page whose step the record can run now (second Mythos pass, L4, M2): BOTH_LOCKED once
#: t_rxd has matured, and an HTLC near t_rxd whose refund maturity the tower could not read.
SITUATION_BOTH_LOCKED_REFUND_RUNNABLE = "both_locked_refund_runnable"
SITUATION_BTC_REFUND_MATURITY_UNREAD = "btc_refund_maturity_unread"
#: The other refund pages that can turn CRITICAL (``urgent``): each names its own situation too, so no
#: two of them share an ACK (third Mythos pass, F6), and the BOTH_LOCKED page inside the window is
#: distinct from an earlier refund page on the same record (F7).
SITUATION_BTC_REFUND_DUE = "btc_refund_due"
SITUATION_PARAMS_MISMATCH_REFUND = "params_mismatch_refund"
SITUATION_BOTH_LOCKED_REFUND_DUE = "both_locked_refund_due"
SITUATION_BOTH_LOCKED_REFUND_UNEVALUABLE = "both_locked_refund_unevaluable"
SITUATION_LEGACY_BTC_UNSPENT = "legacy_btc_unspent"
#: Every other refund page names its own situation too, so two different refund pages on one swap
#: are never one WARN, paged once (re-review of the third pass's fixes, finding 6).
SITUATION_BTC_REFUND_NEVER_LOCKED = "btc_refund_never_locked"
SITUATION_ETH_REFUND_TIMEOUT_PASSED = "eth_refund_timeout_passed"
SITUATION_MAKER_REFUND_AFTER_TAKER_REFUND = "maker_refund_after_taker_refund"
SITUATION_MAKER_REFUND_PARAMS_MISMATCH = "maker_refund_params_mismatch"
SITUATION_MAKER_REFUND_UNEVALUABLE = "maker_refund_unevaluable"
SITUATION_MAKER_REFUND_T_RXD_NEAR = "maker_refund_t_rxd_near"
SITUATION_MAKER_REFUND_T_RXD_MATURED = "maker_refund_t_rxd_matured"
SITUATION_MAKER_REFUND_TAKER_TIMEOUT = "maker_refund_taker_timeout"
#: Prefix of an armed refund page's situation; the reconciler appends this tick's executor outcome,
#: so a FAILED broadcast after a BROADCAST pages again (second Mythos pass, M3).
SITUATION_ARMED_BTC_REFUND = "armed_btc_refund"
#: The ETH disposition pages (#850 PR 10, design §5.1), each its own situation so no two share an ACK.
SITUATION_ETH_DISCOVERY_DISAGREES = "eth_discovery_disagrees"
SITUATION_ETH_DISPOSITION_CONTRADICTION = "eth_disposition_contradiction"
SITUATION_ETH_CLAIMED_AFTER_MISMATCH = "eth_claimed_after_mismatch"
SITUATION_ETH_EXPIRED_EMPTY_MISMATCH = "eth_expired_empty_mismatch"
SITUATION_ETH_EXPIRED_EMPTY_BOTH_LOCKED = "eth_expired_empty_both_locked"
SITUATION_ETH_EXPIRED_EMPTY_OPEN = "eth_expired_empty_open"
SITUATION_ETH_EXPIRED_EMPTY_CLOSED = "eth_expired_empty_closed"
SITUATION_LEGACY_ETH_UNSETTLED = "legacy_eth_unsettled"
SITUATION_LEGACY_UNCLASSIFIED_CLAIM = "legacy_unclassified_claim"


def _btc_spend_decision(
    record: SwapRecord, obs: Observations, policy: MarginPolicy, safety_window_blocks: int
) -> Decision | None:
    """The page for a spend of the funding outpoint by OUR refund leaf, a claim on record that is
    no longer on the chain, or a read whose sources contradict each other. ``None`` when the read
    changes nothing here: unclassified (and no claim on record), unspent, a read below quorum, or a
    claim on the chain (the claim race, run before this, pages that)."""
    corr = _corroboration(obs)
    kind = obs.btc_disposition
    deadline = (
        None
        if obs.asset_locked_at_height is None
        else _refund_opens_at(policy, record.terms, obs.asset_locked_at_height)
    )
    txid = obs.btc_refund_txid
    if kind is BtcDispositionKind.UNKNOWN and obs.btc_spenders_named:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason=(
                "the sources contradict each other on what spends the BTC HTLC funding outpoint "
                f"({obs.btc_disposition_reason}); nothing is autonomous"
            ),
            recommended_action=(
                "investigate — read the funding outpoint's spender on other sources; if it was claimed, p is "
                "public: claim the covenant before t_rxd"
            ),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_BTC_SPENDER_CONTRADICTION,
        )
    single = ""
    if kind is BtcDispositionKind.REFUNDED and obs.btc_single_source:
        # One source's "buried" stops no page (Mythos F6): read it as still pending, here before the
        # D14 page too, which then still says to refund the BTC (second Mythos pass, L3).
        kind = BtcDispositionKind.REFUND_PENDING
        single = "; only one source reads it buried, which this tower does not act on"
    if _btc_refund_buried(obs) and record.role is RecordRole.MAKER:
        return _maker_covenant_refund(
            f"the taker's BTC refund {txid} is buried",
            deadline=deadline,
            corr=corr,
            situation=SITUATION_MAKER_REFUND_AFTER_TAKER_REFUND,
        )
    claim_on_record = record.counter_claim_tx is not None and record.role is not RecordRole.MAKER
    if claim_on_record or _btc_refund_lost_claim_seen(record, obs):
        # D14: a claim that opens H was seen, so p is public, whatever the outpoint shows now (our
        # refund buried, pending, or the claim gone from the chain). The covenant is still ours to
        # claim until the maker's CSV refund at t_rxd. Never autonomous here.
        where = f"tx {record.counter_claim_tx}, on record" if claim_on_record else "a claim witness a source served"
        now = {
            BtcDispositionKind.REFUNDED: f"our BTC refund {txid} is buried",
            BtcDispositionKind.REFUND_PENDING: f"our BTC refund {txid} is not yet buried{single}",
            BtcDispositionKind.UNSPENT: "the BTC HTLC reads unspent",
        }.get(kind, "the BTC HTLC's spender is not known this tick" if kind else "the spender is not classified")  # type: ignore[arg-type]
        return Decision(
            Intent.PAGE_CLAIM,
            reason=(
                f"{now}, but a claim of the HTLC that opens H was seen ({where}), so p is public: claim the "
                "covenant before t_rxd"
                + ("" if kind is BtcDispositionKind.REFUNDED else ", and refund the BTC if it is still unspent")
            ),
            recommended_action=(
                "recover p from the claim tx (pyrxd swap recover-preimage), then claim the covenant (pyrxd swap "
                "build-claim) before t_rxd"
            ),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_CLAIM_SEEN_P_PUBLIC,
        )
    if _btc_refunded_beside_claim_trigger(record, obs):
        # A discovery source names a spender the disposition panel served no bytes for (a lagging
        # source still naming a replaced refund, or a different host set). Nothing proves p public,
        # and nothing proves it is not: say so, and name no step that needs a claim tx (Mythos F4).
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason=(
                f"our BTC refund {txid} is buried, but a discovery source names a different spender of the HTLC "
                "funding outpoint that no source served the bytes of; the tower cannot tell whether p is public"
            ),
            recommended_action=(
                "investigate — look up the spender the discovery source names; if it is a claim (its witness "
                "opens H), p is public: claim the covenant before t_rxd (pyrxd swap build-claim); if it is our "
                f"replaced refund, run {'mutual_refund' if record.state is SwapState.BOTH_LOCKED else 'reconcile_counter_leg'}"
            ),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_BTC_DISCOVERY_DISAGREES,
        )
    if not obs.btc_spend_classified:
        return None
    if kind is BtcDispositionKind.REFUNDED:
        step = "mutual_refund" if record.state is SwapState.BOTH_LOCKED else "reconcile_counter_leg"
        return Decision(
            Intent.RECONCILE,
            reason=(
                f"our BTC refund {txid} (a spend by the refund leaf: the operator's, or the tower's pre-signed "
                f"one) is buried at the policy's BTC reorg depth; the record still reads {record.state.value}. "
                "The coordinator buries at its own depth; if it still reads the refund as pending, run it again later"
            ),
            recommended_action=step,
            low_corroboration=corr,
        )
    if kind is BtcDispositionKind.REFUND_PENDING:
        if record.role is RecordRole.MAKER:
            # The taker's refund changes nothing a maker can do: its covenant refund pages as it would
            # without it (second Mythos pass, M1; a WATCH here dropped that page).
            return None
        step = "mutual_refund" if record.state is SwapState.BOTH_LOCKED else "taker_refund_btc"
        squeeze = Decision(
            Intent.PAGE_SQUEEZED,
            reason=(
                f"our BTC refund {txid} is still not buried and t_rxd is near or past: once t_rxd matures the "
                "maker can refund the covenant by its CSV leg AND still claim the BTC by replacing our refund "
                f"(the claim leaf has no timelock). Get the refund buried now ({obs.btc_disposition_reason}{single})"
            ),
            recommended_action=f"{step}: {_BUMP_HOW}; or bump it from a wallet that holds the refund key",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_BTC_REFUND_PENDING,
        )
        if _t_rxd_near(record, obs, policy, safety_window_blocks):
            return squeeze
        return Decision(
            Intent.WATCH,
            reason=(
                f"our BTC refund {txid} spends the HTLC by the refund leaf and is not yet buried: the maker can still "
                "claim until it is (the claim leaf has no timelock), and a claim pages; so does t_rxd coming near. "
                f"A pre-signed refund has a fixed fee: to bump it run {step}; {_BUMP_HOW} "
                f"({obs.btc_disposition_reason}{single})"
            ),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )
    return None


def _btc_spend_permits_autonomy(obs: Observations) -> bool:
    """Whether the spender read lets an autonomous refund go out: a classified read must hold the
    outpoint UNSPENT at its quorum (a read below quorum, or one that names a spender, never arms).
    A single-source read arms only as the executor allows any single-source read: it marks the
    decision ``low_corroboration`` (:func:`_corroboration`; Mythos F6). An unclassified read keeps
    the pre-9b rule, decided by the caller."""
    return not obs.btc_spend_classified or obs.btc_disposition is BtcDispositionKind.UNSPENT


def _corroboration(obs: Observations) -> bool:
    """``low_corroboration`` for a BTC decision: a single-source RXD read, or a single-source BTC
    spender read (quorum 1). The executor refuses to broadcast on either unless the operator accepted
    single-source reads (Mythos F6)."""
    return obs.low_corroboration or obs.btc_single_source


def _spend_read_note(obs: Observations) -> str:
    """Why a classified spender read did not arm the refund, for the page."""
    kind = obs.btc_disposition.value if obs.btc_disposition is not None else None
    return f" Not autonomous: the spender read is {kind} ({obs.btc_disposition_reason})."


def _autonomous_refund_note() -> str:
    """Said on a page whose pre-signed refund MAY go out (D12). ``decide()`` cannot know the executor:
    the shipped tower is alert-only unless it is given a refund script, and dormant on mainnet unless
    audit-cleared, so the note is conditional, and the reconciler appends what this tick's executor did
    (``reconciler._executor_outcome_note``; Mythos F2)."""
    return (
        " If this tower is armed it broadcasts the pre-signed refund (this page says below whether it did). Its "
        f"fee is fixed: if it does not confirm, bump it with taker_refund_btc ({_BUMP_HOW}). The tower keeps "
        "reading the spender by its leaf, so a claim that replaces the refund pages the claim race, and a refund "
        "still unburied near t_rxd pages too."
    )


def decide(
    *,
    record: SwapRecord,
    observations: Observations,
    policy: MarginPolicy,
    safety_window_blocks: int,
) -> Decision:
    """Decide the watchtower Intent for one swap. Pure; fail-closed.

    See the module docstring for the safety rules. ``safety_window_blocks`` is the
    ``N`` buffer before ``t_rxd`` maturity at which a maker-stall refund becomes due
    (the coordinator's ``CoordinatorConfig.maker_stall_safety_window_blocks``).
    """
    if not isinstance(record, SwapRecord):
        raise ValidationError("decide requires a SwapRecord")
    if not isinstance(observations, Observations):
        raise ValidationError("decide requires Observations")
    if not isinstance(policy, MarginPolicy):
        raise ValidationError("decide requires a MarginPolicy")
    if not isinstance(safety_window_blocks, int) or isinstance(safety_window_blocks, bool) or safety_window_blocks < 0:
        raise ValidationError("decide requires a non-negative safety_window_blocks")

    state = record.state
    obs = observations
    corr = _corroboration(obs)

    # 1. Terminal → stop watching.
    if is_terminal(state):
        return Decision(Intent.RETIRE, reason=f"terminal state {state.value}", low_corroboration=corr)

    terms = record.terms
    # ETH counter-leg (v3): finality is the post-Merge ``finalized`` checkpoint, not a PoW depth —
    # a structurally parallel branch that consumes the SAME audited gate via a depth-less verdict.
    if terms.counter_chain == "eth":
        return _decide_eth(record=record, observations=obs, policy=policy, safety_window_blocks=safety_window_blocks)
    # Defensive fail-safe: unreachable under NegotiatedTerms validation (counter_chain ∈ {btc, eth}).
    if terms.counter_chain != "btc":
        return Decision(
            Intent.NOOP, reason=f"counter_chain={terms.counter_chain} not supported", low_corroboration=corr
        )

    # 2. Claim race. p is (becoming) public if EITHER the chain shows the maker's counter-leg claim
    #    (obs.maker_has_claimed_btc) OR the RECORD already advanced to SECRET_REVEALED — OR'd so a
    #    suppressed single-source claim DETECTION cannot drop a known-revealed swap into the silent
    #    WATCH catch-all (red-team LOW: record-truth and chain-truth are independent; whichever
    #    indicates the reveal arms the gate). Assess regardless of whether record.state caught up.
    #    A claim that lost to our buried refund is not a race: it is paged below (D14, review M1).
    if (
        obs.maker_has_claimed_btc and not _btc_refunded_beside_claim_trigger(record, obs)
    ) or state is SwapState.SECRET_REVEALED:
        if obs.btc_claim_confirmations is None or obs.asset_locked_at_height is None:
            # Cannot assess finality — fail closed to a decision-required page.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason="maker claim observed but finality un-assessable (missing claim depth or asset-lock height) — fail-closed",
                recommended_action=_claim_action(state, role=record.role, note="verify finality manually"),
                low_corroboration=corr,
                situation=SITUATION_CLAIM_RACE,
            )
        verdict = CounterClaimFinality.from_btc_depth(obs.btc_claim_confirmations, _required_btc_depth_blocks(policy))
        deadline = _refund_opens_at(policy, terms, obs.asset_locked_at_height)
        try:
            finality = assess_claim_finality(
                counter_claim_finality=verdict,
                now_rxd_height=obs.now_rxd_height,
                asset_locked_at_height=obs.asset_locked_at_height,
                t_rxd=terms.t_rxd,
                policy=policy,
                value_at_risk_photons=_value_at_risk_photons(terms),
            )
        except ValidationError as exc:
            # e.g. now_rxd_height < asset_locked_at_height (lagging/lying node) → fail-closed.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"maker claim observed but finality gate un-assessable, fail-closed: {exc}",
                recommended_action=_claim_action(state, role=record.role, note="verify finality manually"),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_CLAIM_RACE,
            )
        if finality is ClaimFinality.SAFE:
            return Decision(
                Intent.PAGE_CLAIM,
                reason=(
                    f"maker revealed p; BTC claim reorg-safe ({obs.btc_claim_confirmations} conf) and burial fits "
                    "the window" + ("" if _autonomy_allowed(record) else "." + _no_autonomy_note(record))
                ),
                recommended_action=_claim_action(state, role=record.role),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                # BTC↔RXD SAFE claim race → arm the autonomous ClaimExecutor (BTC branch ONLY; the ETH
                # SAFE branch below must NOT set this). The executor re-asserts SAFE fresh before firing.
                # Only for a record that says it is the taker's (or the single operator's) (#850 PR 1b).
                autonomous_asset_claim=_autonomy_allowed(record),
                situation=SITUATION_CLAIM_RACE,
            )
        if finality is ClaimFinality.WAIT:
            return Decision(
                Intent.WATCH,
                reason=f"maker revealed p; awaiting reorg-safe burial (gate=WAIT, {obs.btc_claim_confirmations} conf)",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        # SQUEEZED
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="maker revealed p but t_rxd window closing (gate=SQUEEZED) — ASSET_VULNERABLE, decision required",
            recommended_action=_claim_action(state, role=record.role, winner_take_all=True),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_CLAIM_RACE,
        )

    # 3. Maker has NOT revealed p.
    # 3a. Already in the danger state — a decision is required (never auto-resolved).
    if state is SwapState.ASSET_VULNERABLE:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="ASSET_VULNERABLE: winner-take-all decision required",
            recommended_action="taker_claim_asset_from_vulnerable vs accept loss",
            low_corroboration=corr,
            situation=SITUATION_ASSET_VULNERABLE,
        )
    # 3a'. Our refund spends the funding outpoint, by the refund leaf (#850 PR 9b): it is not a claim.
    if state in (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH, SwapState.BOTH_LOCKED):
        seen = _btc_spend_decision(record, obs, policy, safety_window_blocks)
        if seen is not None:
            return seen
    # 3b. Maker locked the asset with wrong params — refund the BTC counter-leg. The page ALWAYS goes
    #     out (the swap is definitively broken); autonomous IFF the CSV refund has matured (else the
    #     operator refunds manually once it does — never an autonomous broadcast of an immature refund).
    if state is SwapState.PARAMS_MISMATCH:
        if record.role is RecordRole.MAKER:
            # PARAMS_MISMATCH arises in the MAKER's process (post_asset_lock_revalidate), so this is
            # the common case for it: the counter leg is the taker's to refund (review M2).
            return _maker_covenant_refund(
                "covenant params mismatch: the swap will not complete and the taker refunds its BTC",
                deadline=None
                if obs.asset_locked_at_height is None
                else _refund_opens_at(policy, terms, obs.asset_locked_at_height),
                corr=corr,
                situation=SITUATION_MAKER_REFUND_PARAMS_MISMATCH,
            )
        matured = _btc_refund_matured(terms, obs)
        armed = matured and _autonomy_allowed(record) and _btc_spend_permits_autonomy(obs)
        return Decision(
            Intent.PAGE_REFUND,
            reason="covenant params mismatch — refund the BTC counter-leg via the timelock leg"
            + (_no_autonomy_note(record) if matured else "")
            + (
                _spend_read_note(obs)
                if matured and _autonomy_allowed(record) and not armed and obs.btc_disposition is not None
                else ""
            ),
            recommended_action="taker_refund_btc",
            autonomous_btc_refund=armed,
            low_corroboration=corr,
            # A maturity the tower cannot read fails closed toward urgent (second Mythos pass, M2).
            urgent=(matured or _btc_refund_maturity_unread(terms, obs))
            and _t_rxd_near(record, obs, policy, safety_window_blocks),
            situation=SITUATION_PARAMS_MISMATCH_REFUND,
        )
    # 3c. Maker stall (FSM finding #2, 2026-06-09). Recovery is mutual_refund, NOT the asset-only
    #     maybe_refund_asset_on_maker_stall — IDENTICALLY to the ETH branch (_decide_eth). The maker
    #     locks the RXD covenant in this runbook too, so its CSV refund pays the MAKER; routing the
    #     taker to it is a one-sided taker LOSS: it destroys the taker's only recourse (the claimable
    #     covenant) while the taker's BTC stays locked until t_btc, and the maker (still privately
    #     holding p) then claims the BTC via the maker-only claim leaf. mutual_refund unwinds BOTH legs
    #     once both timeouts elapse (proven by the regtest PoC TestMakerStallAssetOnlyRefundIsTakerLoss).
    #     On BTC that is still true for a TAKER-role coordinator in this release (#850 interim; the ETH
    #     arm differs, see _BOTH_LOCKED_REFUND_REASON_ETH).
    if state is SwapState.MAKER_STALLS:
        # Unreachable on the coordinator-driven path post-fix: the only entry to MAKER_STALLS is
        # maybe_refund_asset_on_maker_stall, which is no longer a taker watchtower action and advances
        # straight to the terminal in the same call. If observed anyway, NO clean coordinator step
        # applies (mutual_refund is BOTH_LOCKED-only) → fail closed to a decision-required page rather
        # than name a step the coordinator rejects (mirrors the ETH branch).
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="unexpected MAKER_STALLS on a BTC swap — no clean coordinator refund from here; recover via mutual_refund once both timeouts elapse",
            recommended_action="investigate (mutual_refund is only valid from BOTH_LOCKED)",
            low_corroboration=corr,
            situation=SITUATION_UNEXPECTED_STATE,
        )
    if state is SwapState.BOTH_LOCKED:
        if obs.asset_locked_at_height is None:
            return Decision(Intent.WATCH, reason="asset lock height not yet observed", low_corroboration=corr)
        deadline = _refund_opens_at(policy, terms, obs.asset_locked_at_height)
        try:
            refund_due = taker_refund_window_open(
                now_block_height=obs.now_rxd_height,
                asset_locked_at_height=obs.asset_locked_at_height,
                t_rxd=terms.t_rxd,
                safety_window_blocks=safety_window_blocks,
                maker_has_claimed_btc=False,
                block_interval_s=policy.block_interval_s,
            )
        except ValidationError as exc:
            # Un-evaluable heights → fail-closed toward paging the refund (don't sit silently).
            if record.role is RecordRole.MAKER:
                return _maker_covenant_refund(
                    f"maker-stall predicate un-evaluable, fail-closed to a refund page: {exc}",
                    deadline=deadline,
                    corr=corr,
                    situation=SITUATION_MAKER_REFUND_UNEVALUABLE,
                )
            return Decision(
                Intent.PAGE_REFUND,
                reason=f"maker-stall predicate un-evaluable, fail-closed to refund page: {exc}",
                recommended_action="mutual_refund",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                # Un-evaluable heights: fail closed toward urgent, as _t_rxd_near does. Deliberately
                # without the t_rxd maturity check below, which needs the same heights (third pass, F7).
                urgent=True,
                situation=SITUATION_BOTH_LOCKED_REFUND_UNEVALUABLE,
            )
        if refund_due and record.role is RecordRole.MAKER:
            return _maker_covenant_refund(
                "you have not claimed the BTC counter leg and t_rxd is near; the taker refunds its BTC",
                deadline=deadline,
                corr=corr,
                situation=SITUATION_MAKER_REFUND_T_RXD_NEAR,
            )
        if refund_due:
            # Urgent once t_rxd has matured: mutual_refund runs only after both timeouts, so a CRITICAL
            # page earlier would name a step the operator cannot run yet (second Mythos pass, L4). From
            # then the maker can refund the covenant and still claim the BTC (Mythos F3). t_btc is not
            # read here (the observer reads no funding depth at BOTH_LOCKED): the swap was gated so the
            # BTC refund opens first in wall-clock time, and the page text says to run the step once
            # both have elapsed (third Mythos pass, F7).
            runnable = obs.now_rxd_height >= deadline
            return Decision(
                Intent.PAGE_REFUND,
                reason=_BOTH_LOCKED_REFUND_REASON_BTC
                + (
                    " t_rxd has matured: the maker can now refund the covenant and still claim the BTC."
                    if runnable
                    else ""
                ),
                recommended_action="mutual_refund",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                urgent=runnable,
                situation=SITUATION_BOTH_LOCKED_REFUND_RUNNABLE if runnable else SITUATION_BOTH_LOCKED_REFUND_DUE,
            )
        return Decision(
            Intent.WATCH,
            reason="both legs locked; maker not yet claimed; refund window not yet near",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )

    # 3d. Maker never locks the asset → the taker's stranded BTC becomes refundable once the BTC
    #     funding buries past t_btc (the relative-CSV refund leaf opens). We only page (and only then
    #     auto-act) once the refund is actually DUE — until then the maker may still lock, so we watch.
    #     Fail-closed: never auto-act while the covenant is known to exist, and never on an
    #     unread/seconds-unit maturity.
    #     #850 PR 1b: an OBSERVED covenant no longer silences the refund page. The maker locks first,
    #     so a taker's own record sits at BTC_LOCKED with the covenant on chain for the whole swap,
    #     and the old "asset lock observed → WATCH" rule meant a maker who locked and then never
    #     claimed left the taker unpaged past t_btc, forever (#850 item 6). The page now goes out;
    #     what the observed covenant changes is the autonomy (off: the maker can still claim while
    #     the refund is unconfirmed, the claim leaf has no timelock) and the text.
    if state is SwapState.BTC_LOCKED:
        matured = _btc_refund_matured(terms, obs)
        covenant_seen = _covenant_known(record, obs)
        if record.role is RecordRole.MAKER:
            if obs.asset_locked_at_height is not None and obs.now_rxd_height >= _refund_opens_at(
                policy, terms, obs.asset_locked_at_height
            ):
                # The funding depth may be unreadable; t_rxd from the covenant decides alone (review L3).
                return _maker_covenant_refund(
                    "t_rxd has matured and you have not claimed",
                    deadline=_refund_opens_at(policy, terms, obs.asset_locked_at_height),
                    corr=corr,
                    situation=SITUATION_MAKER_REFUND_T_RXD_MATURED,
                )
            if matured:
                return _maker_covenant_refund(
                    f"the taker's BTC funding is buried {obs.btc_funding_confirmations} >= t_btc "
                    f"{terms.t_btc.value} blocks and you have not claimed it, so the taker refunds",
                    deadline=(
                        None
                        if obs.asset_locked_at_height is None
                        else _refund_opens_at(policy, terms, obs.asset_locked_at_height)
                    ),
                    corr=corr,
                    situation=SITUATION_MAKER_REFUND_TAKER_TIMEOUT,
                )
            return Decision(
                Intent.WATCH,
                reason=(
                    "BTC_LOCKED (maker); the taker's BTC funding depth could not be read"
                    if obs.btc_funding_confirmations is None
                    else f"BTC_LOCKED (maker); the taker's refund is not due yet (funding {obs.btc_funding_confirmations} conf)"
                ),
                low_corroboration=corr,
            )
        if matured and covenant_seen:
            # Autonomous only on a CLASSIFIED read that holds the outpoint unspent (#850 PR 9b, D12).
            # Before 9b this was never autonomous (design §5.1, H3): the pre-signed refund could lose to
            # a claim, and a tower that reads any spend as a claim could not tell. With the spender
            # classified by its leaf, a claim replacing our refund pages the covenant claim.
            armed = _autonomy_allowed(record) and obs.btc_spend_classified and _btc_spend_permits_autonomy(obs)
            if armed:
                note = _autonomous_refund_note()
            elif not _autonomy_allowed(record):
                note = _no_autonomy_note(record)
            elif not obs.btc_spend_classified:
                note = (
                    " Not autonomous: this tower does not classify the outpoint's spender, so it could not tell "
                    "its own refund from a claim."
                )
            else:
                note = _spend_read_note(obs)
            return Decision(
                Intent.PAGE_REFUND,
                reason=(
                    f"the maker locked the covenant but has not claimed; BTC funding buried "
                    f"{obs.btc_funding_confirmations} >= t_btc {terms.t_btc.value} blocks — refund the BTC "
                    "counter leg, then watch until the refund is buried: the maker can still claim (the claim "
                    "leaf has no timelock), and a claim makes p public, so check whether the covenant is "
                    "still yours to claim before the maker's CSV refund at t_rxd"
                    + ("" if obs.asset_locked_at_height is not None else " (its depth could not be read this tick)")
                    + "."
                    + note
                ),
                recommended_action="taker_refund_btc",
                autonomous_btc_refund=armed,
                low_corroboration=corr,
                urgent=_t_rxd_near(record, obs, policy, safety_window_blocks),
                situation=SITUATION_BTC_REFUND_DUE,
            )
        if matured:
            armed = _autonomy_allowed(record) and _btc_spend_permits_autonomy(obs)
            return (
                Decision(
                    Intent.PAGE_REFUND,
                    reason=(
                        f"maker never locked the asset; BTC funding buried {obs.btc_funding_confirmations} "
                        f">= t_btc {terms.t_btc.value} blocks — refund the BTC counter-leg via the timelock leg"
                        + ("." + _autonomous_refund_note() if obs.btc_spend_classified else "")
                    ),
                    recommended_action="taker_refund_btc",
                    autonomous_btc_refund=True,
                    low_corroboration=corr,
                    situation=SITUATION_BTC_REFUND_NEVER_LOCKED,
                )
                if armed
                else Decision(
                    Intent.PAGE_REFUND,
                    reason=(
                        f"maker never locked the asset; BTC funding buried {obs.btc_funding_confirmations} "
                        f">= t_btc {terms.t_btc.value} blocks — refund the BTC counter-leg via the timelock leg."
                        + (_no_autonomy_note(record) if not _autonomy_allowed(record) else _spend_read_note(obs))
                    ),
                    recommended_action="taker_refund_btc",
                    low_corroboration=corr,
                    situation=SITUATION_BTC_REFUND_NEVER_LOCKED,
                )
            )
        if _btc_refund_maturity_unread(terms, obs) and _t_rxd_near(record, obs, policy, safety_window_blocks):
            # The covenant is known and t_rxd is near or past, but the refund leaf's maturity cannot be
            # read: fail closed toward the page, never autonomous (second Mythos pass, M2).
            return Decision(
                Intent.PAGE_REFUND,
                reason=(
                    (
                        "the maker's covenant is known and t_rxd is near or past"
                        if obs.asset_locked_at_height is not None
                        else "the maker's covenant is pinned on the record, but its lock height could not be read "
                        "this tick, so t_rxd may be near or past (failing toward this page)"
                    )
                    + ", and this tower cannot tell whether the BTC refund leaf has matured ("
                    + (
                        "the funding depth could not be read this tick"
                        if obs.btc_funding_confirmations is None
                        else f"t_btc is in {terms.t_btc.unit.value}, not blocks"
                    )
                    + "). Read the funding outpoint's depth on another source and refund the BTC once t_btc has "
                    "passed: once t_rxd matures the maker can refund the covenant and still claim the BTC (the "
                    "claim leaf has no timelock). Not autonomous."
                ),
                recommended_action="taker_refund_btc",
                deadline_rxd_height=(
                    None
                    if obs.asset_locked_at_height is None
                    else _refund_opens_at(policy, terms, obs.asset_locked_at_height)
                ),
                low_corroboration=corr,
                urgent=True,
                situation=SITUATION_BTC_REFUND_MATURITY_UNREAD,
            )
        return Decision(
            Intent.WATCH,
            reason=(
                f"BTC_LOCKED; awaiting t_btc maturity (funding {obs.btc_funding_confirmations} conf)"
                + ("; the maker's covenant is observed" if covenant_seen else " or an asset lock")
            ),
            low_corroboration=corr,
        )

    # 3e. Other pre-lock states (NEGOTIATED): nothing time-critical.
    return Decision(Intent.WATCH, reason=f"no action due in {state.value}", low_corroboration=corr)


#: Reader answers that read the contract unsettled on every endpoint in the quorum and found no log
#: that opens H among the logs it read: a scan's log beside one of these is not a claim the reader saw.
_ETH_CLEAN_UNCLAIMED = frozenset(
    {
        DispositionKind.OPEN,
        DispositionKind.TIP_EXPIRED,
        DispositionKind.F_EXPIRED,
        DispositionKind.EXPIRED_EMPTY_OPEN,
        DispositionKind.EXPIRED_EMPTY_CLOSED,
    }
)


def _eth_corroboration(obs: Observations) -> bool:
    """``low_corroboration`` for an ETH decision: a single-source RXD read, or a disposition read from
    one ETH endpoint (#850 PR 10)."""
    return obs.low_corroboration or obs.eth_single_source


def _eth_refund_final(obs: Observations) -> bool:
    """A refund of the contract verified at the finalized block, on a read of more than one endpoint.
    One endpoint's REFUNDED decides nothing here (design §5.1: "a single endpoint's Refunded() never
    stops a page")."""
    return obs.eth_disposition is DispositionKind.REFUNDED and not obs.eth_single_source


def _eth_disposition_decision(record: SwapRecord, obs: Observations, policy: MarginPolicy) -> Decision | None:
    """The page for what the shared reader says about the counter-leg contract (#850 PR 10, design
    §5.1), on a record at BTC_LOCKED, PARAMS_MISMATCH or BOTH_LOCKED once the claim race (run first)
    has nothing to say. ``None`` when the read changes nothing: no read, OPEN, TIP_EXPIRED,
    F_EXPIRED, SETTLED_UNFINAL, a single-source answer that would stop a page, or an UNKNOWN from a
    failed read (the rules after this page those as before)."""
    kind = obs.eth_disposition
    if kind is None:
        return None
    corr = _eth_corroboration(obs)
    state = record.state
    maker = record.role is RecordRole.MAKER
    deadline = (
        None
        if obs.asset_locked_at_height is None
        else _refund_opens_at(policy, record.terms, obs.asset_locked_at_height)
    )
    tx = obs.eth_disposition_tx
    why = f" ({obs.eth_disposition_reason})" if obs.eth_disposition_reason else ""
    if _eth_refund_final(obs):
        if maker:
            return _maker_covenant_refund(
                f"the taker's ETH refund {tx} is final at the finalized block",
                deadline=deadline,
                corr=corr,
                situation=SITUATION_MAKER_REFUND_AFTER_TAKER_REFUND,
            )
        if obs.eth_claim_seen or record.counter_claim_tx is not None:
            # D14: a Claimed(p) that opens H was seen, so p is public, whatever settled the contract. The
            # covenant is still ours to claim until the maker's CSV refund at t_rxd. The coordinator
            # holds the record off its terminal until t_rxd matures, so this page stays up until then.
            where = (
                "a Claimed log that opens H was served"
                if obs.eth_claim_seen
                else f"tx {record.counter_claim_tx}, on record"
            )
            return Decision(
                Intent.PAGE_CLAIM,
                reason=(
                    f"our ETH refund {tx} is final at the finalized block, but a claim that opens H was seen ({where}), "
                    "so p is public: claim the covenant before t_rxd"
                ),
                recommended_action=(
                    "recover p from the claim tx (pyrxd swap recover-preimage), then claim the covenant (pyrxd swap "
                    "build-claim) before t_rxd"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_CLAIM_SEEN_P_PUBLIC,
            )
        if obs.eth_claim_detected:
            # The detection scan names a log the reader does not count as a claim that opens H (an
            # unrecognised event, or a Claimed log whose data does not open H). Nothing proves p public,
            # and nothing proves it is not: say so, and name no step that needs a claim.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason=(
                    f"our ETH refund {tx} is final at the finalized block, but the detection scan names another log "
                    "on the contract that the reader does not count as a claim that opens H; the tower cannot tell "
                    "whether p is public"
                ),
                recommended_action=(
                    "investigate — read the contract's logs on another endpoint; if a Claimed log opens H, p is "
                    "public: claim the covenant before t_rxd (pyrxd swap build-claim)"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_ETH_DISCOVERY_DISAGREES,
            )
        step = "mutual_refund" if state is SwapState.BOTH_LOCKED else _STEP_RECONCILE
        return Decision(
            Intent.RECONCILE,
            reason=(
                f"our ETH refund {tx} is verified at the finalized block; the record still reads {state.value}. Run "
                f"{step} to bring it up to the chain"
                + (
                    " (with no role it also sends the covenant refund)"
                    if step == "mutual_refund" and record.role is not RecordRole.TAKER
                    else ""
                )
            ),
            recommended_action=step,
            low_corroboration=corr,
        )
    if kind in (DispositionKind.EXPIRED_EMPTY_OPEN, DispositionKind.EXPIRED_EMPTY_CLOSED) and not obs.eth_single_source:
        # Only on a read of more than one endpoint: these pages replace the refund page, and one
        # endpoint's "the contract holds nothing" must not.
        if state is SwapState.PARAMS_MISMATCH:
            # §3.2: no EXPIRED_EMPTY edge from PARAMS_MISMATCH (a maker-process population); the exit is
            # the gated abandon, after the covenant refund.
            return Decision(
                Intent.PAGE_REFUND,
                reason=(
                    "the ETH counter-leg contract expired EMPTY at the finalized block after a covenant params "
                    f"mismatch{why}. Refund your covenant by its CSV leg at t_rxd, then end the record with the "
                    "gated abandon"
                ),
                recommended_action=(
                    "refund your covenant by its CSV leg at t_rxd, then abandon_counter_leg (reason_code expired_empty)"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_ETH_EXPIRED_EMPTY_MISMATCH,
            )
        if maker:
            return None
        if state is SwapState.BOTH_LOCKED:
            # N2: no claim can succeed after F_EXPIRED, and an empty contract has nothing to refund.
            return Decision(
                Intent.PAGE_REFUND,
                reason=(
                    "the ETH counter-leg contract expired EMPTY at the finalized block (no claim can succeed, and "
                    f"there is nothing to refund){why}. End the record with the gated abandon"
                    + (
                        ""
                        if record.role is RecordRole.TAKER
                        else "; with no role, refund the covenant by its CSV leg at t_rxd too (the abandon does not)"
                    )
                ),
                recommended_action="abandon_counter_leg (reason_code expired_empty)",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_ETH_EXPIRED_EMPTY_BOTH_LOCKED,
            )
        if kind is DispositionKind.EXPIRED_EMPTY_OPEN:
            nonce = (
                f"nonce {obs.eth_nonce_at_finalized} (the key's count at the finalized block)"
                if obs.eth_nonce_at_finalized is not None
                else "the key's count at the finalized block (not read this tick)"
            )
            push = (
                f"; the recorded push is {record.pending_push_tx_hash}"
                if record.pending_push_tx_hash is not None
                else ""
            )
            return Decision(
                Intent.PAGE_REFUND,
                reason=(
                    "the ETH token counter-leg contract expired EMPTY at the finalized block, but a token push signed "
                    f"for it may still land{why}. Close the push nonce: a 0-value transaction from the funding key "
                    f"{record.push_signer or '(not named on this record)'} at {nonce}{push}"
                ),
                recommended_action="close_push_nonce",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_ETH_EXPIRED_EMPTY_OPEN,
            )
        return Decision(
            Intent.PAGE_REFUND,
            reason=(
                "the ETH token counter-leg contract expired EMPTY at the finalized block, and the funding key's nonce "
                f"there is past every push it signed for it{why}. Nothing is left to refund: run the step, which "
                "ends the record ABORTED"
            ),
            recommended_action="taker_refund_btc",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_ETH_EXPIRED_EMPTY_CLOSED,
        )
    if maker:
        return None
    if kind is DispositionKind.UNKNOWN and obs.eth_settled_at_finalized:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason=(
                "the ETH counter-leg contract is settled at the finalized block, but the reader cannot say how "
                f"({obs.eth_disposition_reason}); nothing proves whether p is public"
            ),
            recommended_action=(
                "investigate — read the contract's Claimed/Refunded logs and receipts on other endpoints; if a "
                "Claimed log opens H, p is public: claim the covenant before t_rxd (pyrxd swap build-claim)"
            ),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_ETH_DISPOSITION_CONTRADICTION,
        )
    # SETTLED_UNFINAL stops nothing: the reader returns it when ANY endpoint reads the contract settled
    # at its tip (a delay is cheap for the coordinator), so one endpoint would otherwise silence a page.
    return None


def _eth_claim_on_record_page(record: SwapRecord, obs: Observations, policy: MarginPolicy) -> Decision:
    """D14 off the record (#850 PR 10, review F1): the covenant claim and the refund, for a taker's or
    no-role record that holds ``counter_claim_tx`` while this tick's reads do not show that claim."""
    # D14, as on the BTC branch: a claim on record that this tick's reads do not show (a read one
    # endpoint broke, a log no endpoint serves, or a claim that never mined). Not the claim race,
    # whose WAIT would hold back the refund page for a claim that never finalises: this page names
    # both the covenant claim and the refund, and stays up until the refund is final (review F1).
    return Decision(
        Intent.PAGE_CLAIM,
        reason=(
            f"a claim of the ETH counter leg that opens H is on record (tx {record.counter_claim_tx}), and this "
            "tick's reads do not show it"
            + (f" ({obs.eth_disposition_reason})" if obs.eth_disposition_reason else "")
            + ", so p may be public: claim the covenant before t_rxd, and refund the ETH leg once its timeout "
            "has passed if it is still funded"
        ),
        recommended_action=(
            "recover p from the claim tx (pyrxd swap recover-preimage), then claim the covenant (pyrxd swap "
            "build-claim) before t_rxd"
        ),
        deadline_rxd_height=(
            None
            if obs.asset_locked_at_height is None
            else _refund_opens_at(policy, record.terms, obs.asset_locked_at_height)
        ),
        low_corroboration=_eth_corroboration(obs),
        situation=SITUATION_CLAIM_SEEN_P_PUBLIC,
    )


def _decide_eth(
    *,
    record: SwapRecord,
    observations: Observations,
    policy: MarginPolicy,
    safety_window_blocks: int,
) -> Decision:
    """The ETH counter-leg branch (v3). Structurally mirrors the BTC claim-race + maker-stall logic
    in :func:`decide`, with three differences inherent to ETH:

    * **Finality is a checkpoint, not a depth.** The verdict is a *depth-less*
      :class:`CounterClaimFinality` (``confirmations``/``required_depth`` both ``None``), which routes
      ``assess_claim_finality`` into its finalized-checkpoint branch (reserving
      ``ceil(eth_finalization_window_s / rxd_block_interval_s)`` RXD blocks). The watchtower CONSUMES
      the same gate; it never re-derives finality.
    * **Refund recovery is ``mutual_refund``, not ``maybe_refund_asset_on_maker_stall``.** The latter
      refunds ONLY the RXD covenant and is explicitly forbidden on the ETH stall path
      (``swap_coordinator.py`` — the taker's value sits in the ETH HTLC it does not touch); ``mutual_refund``
      refunds the taker's ETH HTLC and, on a TAKER-role coordinator, leaves the covenant to the maker
      and the record BOTH_LOCKED (#850).
    * **The maker-claim trigger is ``eth_claim_detected``** (an ETH claim tx observed) instead of a
      spent BTC funding outpoint. ``taker_refund_window_open`` is chain-agnostic (it keys purely
      on RXD heights) and is reused unchanged.

    Alert-only: like the BTC branch it broadcasts nothing and only names the coordinator step.
    """
    obs = observations
    corr = _eth_corroboration(obs)
    terms = record.terms
    state = record.state

    refund_final = _eth_refund_final(obs)
    # A claim the record kept (``counter_claim_tx``, which no step clears) says p may be public whatever
    # this tick's reads say: one endpoint can make the disposition read fail before it looks at any
    # claim, and the detection scan can miss a log no endpoint serves (#850 PR 10, review F1).
    claim_on_record = record.counter_claim_tx is not None

    # A claim after a params mismatch (#850 PR 10, design §3.2): there is deliberately no way into the
    # taker's claim flow from PARAMS_MISMATCH, so the claim race below could only name "investigate".
    if state is SwapState.PARAMS_MISMATCH and (obs.eth_claim_detected or claim_on_record) and not refund_final:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason=(
                "the ETH counter leg is claimed (or a claim is seen) after a covenant params mismatch: there is no "
                "coordinator path into the claim flow from params_mismatch. Refund your covenant by its CSV leg at "
                "t_rxd, then end the record with the gated abandon once the claim is final at the finalized block"
                + (f" ({obs.eth_disposition_reason})" if obs.eth_disposition_reason else "")
            ),
            recommended_action=(
                "refund your covenant by its CSV leg at t_rxd (two-host runner: maker --phase refund), then "
                "abandon_counter_leg (reason_code claimed_after_mismatch)"
            ),
            deadline_rxd_height=(
                None
                if obs.asset_locked_at_height is None
                else _refund_opens_at(policy, terms, obs.asset_locked_at_height)
            ),
            low_corroboration=corr,
            situation=SITUATION_ETH_CLAIMED_AFTER_MISMATCH,
        )

    # Claim race. p is (becoming) public if EITHER the chain shows the maker's ETH claim OR the
    # record already advanced to SECRET_REVEALED — OR'd so a suppressed single-source claim DETECTION
    # cannot drop a known-revealed swap into the silent WATCH catch-all (mirrors the BTC branch).
    # A claim beside our refund final at the finalized block is not a race: the contract paid us, so
    # no claim of it can be mined. It is paged below, as the covenant claim when p is public (D14).
    # A log the scan counts as a claim that the reader, over the endpoints whose logs it read, did not
    # count as one that opens H, on an answer that is not UNKNOWN: an endpoint served an odd or forged
    # log. It pages "investigate" rather than a claim race whose WAIT on a transaction that never mines
    # would hold back the refund page (re-review of the fix round, F-B). A record that holds a claim gets
    # the D14 page, which names it; a maker's record is told to check, then refund its covenant.
    if (
        obs.eth_claim_detected
        and not obs.eth_claim_seen
        and not refund_final
        and obs.eth_disposition in _ETH_CLEAN_UNCLAIMED
        and state in (SwapState.BTC_LOCKED, SwapState.BOTH_LOCKED)
    ):
        maker = record.role is RecordRole.MAKER
        if claim_on_record and not maker:
            return _eth_claim_on_record_page(record, obs, policy)
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason=(
                f"the detection scan names a log on the ETH counter-leg contract that the reader, over the endpoints "
                f"whose logs it read, does not count as a claim that opens H; it reads the contract "
                f"{obs.eth_disposition.value}"
                + (f" ({obs.eth_disposition_reason})" if obs.eth_disposition_reason else "")
            ),
            recommended_action=(
                f"investigate — your claim on record ({record.counter_claim_tx}) is not among the logs read this "
                "tick; if it is not on the canonical chain, re-send it before the ETH timeout (two-host runner: maker "
                "--phase lock-claim); refund your covenant by its CSV leg at t_rxd only if no claim of yours lands"
                if maker and claim_on_record
                else "investigate — read the contract's logs on another endpoint; if none opens H, refund your "
                "covenant by its CSV leg at t_rxd (two-host runner: maker --phase refund)"
                if maker
                else "investigate — read the contract's logs on another endpoint; if a Claimed log opens H, p is "
                "public: claim the covenant before t_rxd (pyrxd swap build-claim); if none does, the counter-leg "
                "refund is due once its timeout has passed"
            ),
            deadline_rxd_height=(
                None
                if obs.asset_locked_at_height is None
                else _refund_opens_at(policy, terms, obs.asset_locked_at_height)
            ),
            low_corroboration=corr,
            situation=SITUATION_ETH_DISCOVERY_DISAGREES,
        )
    if (obs.eth_claim_detected and not refund_final) or state is SwapState.SECRET_REVEALED:
        if obs.eth_claim_finality is None or obs.asset_locked_at_height is None:
            # Claim indicated but finality un-assessable (no finalized-checkpoint verdict or no
            # asset-lock height) → fail closed to a decision-required page.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason="maker ETH claim observed but finality un-assessable (missing finalized verdict or asset-lock height) — fail-closed",
                recommended_action=_claim_action(state, role=record.role, note="verify finality manually"),
                low_corroboration=corr,
                situation=SITUATION_CLAIM_RACE,
            )
        # Depth-less verdict (ETH finalized checkpoint): assess_claim_finality takes the no-depth path.
        verdict = CounterClaimFinality(state=obs.eth_claim_finality)
        deadline = _refund_opens_at(policy, terms, obs.asset_locked_at_height)
        try:
            finality = assess_claim_finality(
                counter_claim_finality=verdict,
                now_rxd_height=obs.now_rxd_height,
                asset_locked_at_height=obs.asset_locked_at_height,
                t_rxd=terms.t_rxd,
                policy=policy,
                value_at_risk_photons=_value_at_risk_photons(terms),
            )
        except ValidationError as exc:
            # e.g. now_rxd < asset_locked (lagging node) or missing eth_finalization_window_s → fail-closed.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"maker ETH claim observed but finality gate un-assessable, fail-closed: {exc}",
                recommended_action=_claim_action(state, role=record.role, note="verify finality manually"),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_CLAIM_RACE,
            )
        if finality is ClaimFinality.SAFE:
            return Decision(
                Intent.PAGE_CLAIM,
                reason="maker revealed p on ETH; claim finalized and burial fits the window",
                recommended_action=_claim_action(state, role=record.role),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_CLAIM_RACE,
            )
        if finality is ClaimFinality.WAIT:
            return Decision(
                Intent.WATCH,
                reason="maker revealed p on ETH; awaiting the finalized checkpoint (gate=WAIT)",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        # SQUEEZED
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="maker revealed p on ETH but t_rxd window closing (gate=SQUEEZED) — ASSET_VULNERABLE, decision required",
            recommended_action=_claim_action(state, role=record.role, winner_take_all=True),
            deadline_rxd_height=deadline,
            low_corroboration=corr,
            situation=SITUATION_CLAIM_RACE,
        )

    # Maker has NOT revealed p.
    if state is SwapState.ASSET_VULNERABLE:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="ASSET_VULNERABLE: winner-take-all decision required",
            recommended_action="taker_claim_asset_from_vulnerable vs accept loss",
            low_corroboration=corr,
            situation=SITUATION_ASSET_VULNERABLE,
        )
    # What the shared reader says about the contract (#850 PR 10): refunded, empty, settled, or a
    # contradiction. ``None`` leaves the rules below (OPEN, TIP_EXPIRED, F_EXPIRED, a failed read).
    if (
        claim_on_record
        and not refund_final
        and record.role is not RecordRole.MAKER
        and state in (SwapState.BTC_LOCKED, SwapState.BOTH_LOCKED)
    ):
        return _eth_claim_on_record_page(record, obs, policy)
    if state in (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH, SwapState.BOTH_LOCKED):
        seen = _eth_disposition_decision(record, obs, policy)
        if seen is not None:
            return seen
    if state is SwapState.PARAMS_MISMATCH:
        # The maker locked the wrong covenant; the taker only needs to recover its own ETH HTLC.
        # `taker_refund_btc` is the state-valid step (coordinator allows it from PARAMS_MISMATCH and it
        # services the counter-leg refund — the ETH HTLC here); `mutual_refund` is BOTH_LOCKED-only and
        # would also touch the maker's covenant. Mirror the BTC branch's action.
        if record.role is RecordRole.MAKER:
            return _maker_covenant_refund(
                "covenant params mismatch on the ETH swap: it will not complete and the taker refunds its ETH",
                deadline=None
                if obs.asset_locked_at_height is None
                else _refund_opens_at(policy, terms, obs.asset_locked_at_height),
                corr=corr,
                situation=SITUATION_MAKER_REFUND_PARAMS_MISMATCH,
            )
        return Decision(
            Intent.PAGE_REFUND,
            reason="covenant params mismatch on the ETH swap — refund the ETH counter-leg HTLC (taker_refund_btc)",
            recommended_action="taker_refund_btc",
            low_corroboration=corr,
            situation=SITUATION_PARAMS_MISMATCH_REFUND,
        )
    if state is SwapState.MAKER_STALLS:
        # Unreachable on the coordinator-driven ETH path (the only entry to MAKER_STALLS is
        # maybe_refund_asset_on_maker_stall, which is forbidden for ETH — it refunds ONLY the RXD
        # covenant and strands the taker's ETH). If observed anyway, NO clean coordinator step applies
        # (mutual_refund is BOTH_LOCKED-only; taker_refund_btc is not valid from MAKER_STALLS) → fail
        # closed to a decision-required page rather than name a step the coordinator rejects.
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="unexpected MAKER_STALLS on an ETH swap — no clean coordinator refund from here; recover the ETH HTLC manually",
            recommended_action="investigate (mutual_refund is only valid from BOTH_LOCKED)",
            low_corroboration=corr,
            situation=SITUATION_UNEXPECTED_STATE,
        )
    if state is SwapState.BOTH_LOCKED:
        if obs.asset_locked_at_height is None:
            return Decision(Intent.WATCH, reason="asset lock height not yet observed", low_corroboration=corr)
        deadline = _refund_opens_at(policy, terms, obs.asset_locked_at_height)
        try:
            refund_due = taker_refund_window_open(
                now_block_height=obs.now_rxd_height,
                asset_locked_at_height=obs.asset_locked_at_height,
                t_rxd=terms.t_rxd,
                safety_window_blocks=safety_window_blocks,
                maker_has_claimed_btc=False,  # chain-agnostic predicate: "has the maker claimed the counter-leg"
                block_interval_s=policy.block_interval_s,
            )
        except ValidationError as exc:
            if record.role is RecordRole.MAKER:
                return _maker_covenant_refund(
                    f"maker-stall predicate un-evaluable, fail-closed to a refund page: {exc}",
                    deadline=deadline,
                    corr=corr,
                    situation=SITUATION_MAKER_REFUND_UNEVALUABLE,
                )
            return Decision(
                Intent.PAGE_REFUND,
                reason=f"maker-stall predicate un-evaluable, fail-closed to refund page: {exc}",
                recommended_action="mutual_refund",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_BOTH_LOCKED_REFUND_UNEVALUABLE,
            )
        if refund_due and record.role is RecordRole.MAKER:
            return _maker_covenant_refund(
                "you have not claimed the ETH counter leg and t_rxd is near; the taker refunds its ETH",
                deadline=deadline,
                corr=corr,
                situation=SITUATION_MAKER_REFUND_T_RXD_NEAR,
            )
        if refund_due:
            return Decision(
                Intent.PAGE_REFUND,
                reason=_BOTH_LOCKED_REFUND_REASON_ETH,
                recommended_action="mutual_refund",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_BOTH_LOCKED_REFUND_DUE,
            )
        return Decision(
            Intent.WATCH,
            reason="both legs locked; maker not yet claimed; refund window not yet near",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )

    # Maker never locks the asset. The ETH mirror of the BTC branch in :func:`decide` — and until
    # now the ONLY state the two arms did not both handle. ``taker_funds_btc`` is the funding step
    # for BOTH counter-chains and advances to BTC_LOCKED, so an ETH swap sits here with the taker's
    # ETH HTLC funded and the maker's covenant absent. The BTC arm pages PAGE_REFUND once maturity
    # is provable; this arm had no branch at all and fell through to the silent WATCH catch-all
    # below, every tick, forever — the taker is never told its counter-leg refund is due.
    #
    # ETH maturity is the ABSOLUTE ``eth_timeout_unix_s`` (a contract immutable), not a depth, so it
    # needs ``obs.now_unix_s``. Fail-closed in the SAME direction as the BTC arm: an unread clock, or
    # terms without a deadline, WATCHes rather than pages — an alert-only tower that cries wolf on
    # every healthy pre-lock tick is its own failure. ``autonomous_btc_refund`` stays False: that
    # discriminator arms the BTC keyless pre-signed refund and has no ETH counterpart.
    if state is SwapState.BTC_LOCKED:
        # A REFUSED RESUME (`record.fund_refusal`): the taker's gate refused to complete the fund, so
        # this swap will not go on to BOTH_LOCKED, and the counter-leg contract it had already
        # deployed is refunded at its deadline whether or not the maker locked — the maker can still
        # claim it with p before then, which the claim race above pages.
        #
        # #850 PR 1b: the page past the deadline goes out WHETHER OR NOT the covenant is observed. The
        # maker locks first, so a taker's BTC_LOCKED record normally has it on chain, and the old
        # "asset lock observed → WATCH" rule left a taker unpaged past the ETH deadline for good
        # (#850 item 6). Past eth_timeout_unix_s the contract refuses a claim, so the refund is due.
        refused = record.fund_refusal
        # Pin-aware, as in the BTC branch: a taker's pinned record is proof the maker locked, and a
        # failed depth read must not turn that into "maker never locked" (security review, LOW).
        covenant_seen = _covenant_known(record, obs)
        deadline_s = terms.eth_timeout_unix_s
        past_deadline = obs.now_unix_s is not None and deadline_s is not None and obs.now_unix_s >= deadline_s
        if record.role is RecordRole.MAKER:
            if past_deadline:
                return _maker_covenant_refund(
                    f"the ETH HTLC timeout {deadline_s} has passed (now {obs.now_unix_s}) without your claim, so "
                    "the taker refunds",
                    deadline=(
                        None
                        if obs.asset_locked_at_height is None
                        else _refund_opens_at(policy, terms, obs.asset_locked_at_height)
                    ),
                    corr=corr,
                    situation=SITUATION_MAKER_REFUND_TAKER_TIMEOUT,
                )
            return Decision(
                Intent.WATCH,
                reason=f"BTC_LOCKED (maker) on an ETH swap; the ETH deadline ({deadline_s}) has not passed",
                low_corroboration=corr,
            )
        if past_deadline:
            return Decision(
                Intent.PAGE_REFUND,
                reason=(
                    f"the taker refused to complete the fund ({refused}); the ETH HTLC timeout {deadline_s} has "
                    f"passed (now {obs.now_unix_s}) — refund the ETH counter-leg HTLC"
                    if refused is not None
                    else f"the maker locked the covenant but never claimed; the ETH HTLC timeout {deadline_s} has "
                    f"passed (now {obs.now_unix_s}), so the contract refuses a claim — refund the ETH counter-leg HTLC"
                    if covenant_seen
                    else f"maker never locked the asset; the ETH HTLC timeout {deadline_s} has passed "
                    f"(now {obs.now_unix_s}) — refund the ETH counter-leg HTLC"
                )
                + (
                    f". Our refund {record.counter_refund_tx_hash} is recorded and not yet final: run "
                    "taker_refund_btc again to follow it (a retry reads it before sending anything)"
                    if record.counter_refund_tx_hash is not None
                    else ""
                ),
                recommended_action="taker_refund_btc",
                low_corroboration=corr,
                situation=SITUATION_ETH_REFUND_TIMEOUT_PASSED,
            )
        if covenant_seen and refused is None:
            return Decision(
                Intent.WATCH,
                reason=(
                    f"BTC_LOCKED on an ETH swap; the maker's covenant is observed; awaiting the maker's claim or the "
                    f"eth_timeout_unix_s deadline ({deadline_s}) (clock read: {obs.now_unix_s})"
                ),
                low_corroboration=corr,
            )
        if refused is not None:
            return Decision(
                Intent.WATCH,
                reason=(
                    f"BTC_LOCKED after a refused fund ({refused}); the ETH counter-leg contract is refunded at its "
                    f"deadline ({deadline_s}) unless the maker claims it with p first (clock read: {obs.now_unix_s})"
                ),
                low_corroboration=corr,
            )
        return Decision(
            Intent.WATCH,
            reason=(
                f"BTC_LOCKED on an ETH swap; awaiting the eth_timeout_unix_s deadline ({deadline_s}) "
                f"or an asset lock (clock read: {obs.now_unix_s})"
            ),
            low_corroboration=corr,
        )

    # Pre-lock states (NEGOTIATED): nothing time-critical.
    return Decision(Intent.WATCH, reason=f"no action due in {state.value}", low_corroboration=corr)


# -- legacy terminal records: the D9 net (#850 PR 9b for BTC, PR 10 for ETH; design §5.2) --------
#
# Before 0.27 a BTC taker refund ended its record on BROADCAST (ABORTED or MUTUAL_REFUND), and the
# store dropped terminal records, so a refund that lost to the maker's claim left ``p`` public with
# nobody told to claim the covenant before t_rxd. An ETH taker refund ended its record on broadcast the
# same way until PR 5b, so a refund that never landed, or a claim that beat it, went unseen too.
# Records 0.27 ends carry ``counter_disposition`` (the chain read that ended them); a terminal record
# without one, and without the tower's marker, is read once here.

#: The terminal states an old counter-leg refund ended a record in on its broadcast.
LEGACY_TERMINAL_STATES = frozenset({SwapState.ABORTED, SwapState.MUTUAL_REFUND})


@dataclass(frozen=True)
class LegacyCheck:
    """:func:`decide_legacy`'s answer for one legacy terminal record.

    ``decision`` is what to page (``WATCH``: nothing). ``verdict`` is the word the marker records.
    ``conclusive``: write the marker now. ``conclusive_once_delivered``: write it once this page is
    delivered. Neither: write nothing, and the record is read again on a later tick."""

    decision: Decision
    verdict: str
    conclusive: bool = False
    conclusive_once_delivered: bool = False


def decide_legacy(
    *, record: SwapRecord, observations: Observations, policy: MarginPolicy, safety_window_blocks: int
) -> LegacyCheck:
    """What a legacy terminal BTC record's funding outpoint says about how it really ended (D9).

    Pure, and never autonomous (no decision here sets an autonomy flag). The verdicts:

    * spent by a CLAIM (its witness opens H) → PAGE_CLAIM naming the covenant claim
      (``pyrxd swap build-claim``), not a refund: the refund lost and ``p`` is public. Conclusive
      once the page is delivered after t_rxd has matured (the claim window is then closed).
    * spent by a transaction this read could not classify → PAGE_SQUEEZED "investigate".
    * UNSPENT → PAGE_REFUND: the recorded refund never confirmed; refund by address
      (``pyrxd swap build-refund``) and watch for a claim. NEVER conclusive, a deliberate divergence
      from design §5.2 item 4 ("or the swap's last deadline has passed"): an unspent HTLC is the
      taker's BTC, the maker can claim it at any time, and past t_rxd the maker can also refund the
      covenant, so it is the taker's loss for as long as nobody refunds. The page is urgent (CRITICAL,
      re-paged until ACKed) inside the safety window of t_rxd or past it, and whenever this tower
      cannot say where t_rxd is (no covenant pin or lock height); otherwise a WARN once per tower run
      (Mythos F3). The check costs one of the per-tick slots.
    * our refund buried → agrees; conclusive. Pending, or UNKNOWN → retried, nothing written.
    """
    obs = observations
    corr = _corroboration(obs)
    state = record.state
    if record.terms.counter_chain == "eth":
        return _decide_legacy_eth(record=record, observations=obs, policy=policy)
    if record.terms.counter_chain != "btc":
        return LegacyCheck(
            Decision(Intent.WATCH, reason="legacy net: only a BTC or ETH counter leg is read here"), "skipped"
        )
    if not obs.btc_spend_classified:
        return LegacyCheck(
            Decision(
                Intent.WATCH, reason="legacy net: this tower does not classify BTC spenders", low_corroboration=corr
            ),
            "unclassified",
        )
    deadline = (
        None
        if obs.asset_locked_at_height is None
        else _refund_opens_at(policy, record.terms, obs.asset_locked_at_height)
    )
    past = deadline is not None and obs.now_rxd_height >= deadline
    ended = (
        f"this record ended at {state.value} when its BTC refund was broadcast (pyrxd before 0.27 did not "
        "follow a refund to burial)"
    )
    kind = obs.btc_disposition
    if obs.maker_has_claimed_btc and kind is BtcDispositionKind.REFUNDED and not obs.btc_claim_witness_seen:
        # A spender only discovery names, beside our buried refund (Mythos F4): never marked.
        return LegacyCheck(
            Decision(
                Intent.PAGE_SQUEEZED,
                reason=(
                    f"{ended}. The refund {obs.btc_refund_txid} is buried, but a discovery source names a different "
                    "spender of the HTLC that no source served the bytes of; the tower cannot tell whether p is public"
                ),
                recommended_action=(
                    "investigate — look up the spender the discovery source names; if it is a claim (its witness "
                    "opens H), p is public: claim the covenant before t_rxd (pyrxd swap build-claim)"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_BTC_DISCOVERY_DISAGREES,
            ),
            "discovery_disagrees",
        )
    if obs.maker_has_claimed_btc and _btc_refund_buried(obs):
        # D14 on the chain: our refund won, but a claim witness that opens H was served beside it.
        return LegacyCheck(
            Decision(
                Intent.PAGE_CLAIM,
                reason=(
                    f"{ended}. The refund {obs.btc_refund_txid} is buried, but a claim witness that opens H was "
                    "served for the HTLC, so p is public: claim the covenant before t_rxd if it is still unspent"
                ),
                recommended_action=(
                    "recover p from the claim tx (pyrxd swap recover-preimage), then claim the covenant with it "
                    "(pyrxd swap build-claim) if it is still unspent"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_CLAIM_SEEN_P_PUBLIC,
            ),
            "refunded_p_public",
            conclusive_once_delivered=past,
        )
    if obs.maker_has_claimed_btc:
        if kind in (BtcDispositionKind.CLAIM_SEEN, BtcDispositionKind.CLAIMED):
            return LegacyCheck(
                Decision(
                    Intent.PAGE_CLAIM,
                    reason=(
                        f"{ended}, but the BTC HTLC was spent by the maker's CLAIM (its witness opens H): the "
                        "refund lost and p is public. Claim the covenant before t_rxd, if it is still unspent"
                        + (" (t_rxd has matured: the maker may already have refunded it)" if past else "")
                        + (
                            ""
                            if deadline is not None
                            else " (this record pins no covenant, so the tower cannot say when t_rxd matures: ACK "
                            "this page once the covenant is claimed or gone)"
                        )
                    ),
                    recommended_action=(
                        "recover p from the claim tx (pyrxd swap recover-preimage), then claim the covenant with "
                        "it (pyrxd swap build-claim) — not a refund"
                    ),
                    deadline_rxd_height=deadline,
                    low_corroboration=corr,
                    situation=SITUATION_CLAIM_SEEN_P_PUBLIC,
                ),
                "claimed",
                conclusive_once_delivered=past,
            )
        return LegacyCheck(
            Decision(
                Intent.PAGE_SQUEEZED,
                reason=(
                    f"{ended}, and the BTC HTLC is spent by a transaction this tower could not classify "
                    f"({obs.btc_disposition_reason})"
                ),
                recommended_action=(
                    "investigate — read the spender of the HTLC funding outpoint; if it is a claim, p is public: "
                    "claim the covenant before t_rxd (pyrxd swap build-claim)"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_LEGACY_UNCLASSIFIED_SPEND,
            ),
            "unclassified_spend",
        )
    if kind is BtcDispositionKind.UNSPENT:
        return LegacyCheck(
            Decision(
                Intent.PAGE_REFUND,
                reason=(
                    f"{ended}, but the BTC HTLC is unspent: the recorded refund never confirmed. The maker can claim "
                    "it at any time while it is unspent"
                ),
                recommended_action=(
                    "refund by address (pyrxd swap build-refund, then broadcast it), and watch until the refund is "
                    "buried; a claim makes p public"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                urgent=not _covenant_known(record, obs) or _t_rxd_near(record, obs, policy, safety_window_blocks),
                situation=SITUATION_LEGACY_BTC_UNSPENT,
            ),
            "unspent",
        )
    if kind is BtcDispositionKind.REFUNDED and obs.btc_single_source:
        return LegacyCheck(
            Decision(
                Intent.WATCH,
                reason=f"legacy net: only one source reads our refund {obs.btc_refund_txid} buried; read again later",
                low_corroboration=corr,
            ),
            "refunded_single_source",
        )
    if kind is BtcDispositionKind.REFUNDED:
        return LegacyCheck(
            Decision(Intent.WATCH, reason=f"legacy net: our refund {obs.btc_refund_txid} is buried; the record agrees"),
            "refunded",
            conclusive=True,
        )
    if kind is BtcDispositionKind.UNKNOWN and obs.btc_spenders_named:
        return LegacyCheck(
            Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"{ended}, and the sources contradict each other on its spender ({obs.btc_disposition_reason})",
                recommended_action=(
                    "investigate — read the spender of the HTLC funding outpoint on other sources; if it is a claim, "
                    "p is public: claim the covenant before t_rxd"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_BTC_SPENDER_CONTRADICTION,
            ),
            "contradiction",
        )
    return LegacyCheck(
        Decision(
            Intent.WATCH,
            reason=f"legacy net: the spender read is {kind.value if kind else None} ({obs.btc_disposition_reason}); read again later",
            low_corroboration=corr,
        ),
        kind.value if kind else "unknown",
    )


def _decide_legacy_eth(*, record: SwapRecord, observations: Observations, policy: MarginPolicy) -> LegacyCheck:
    """:func:`decide_legacy` for an ETH counter leg (#850 PR 10, design §5.2 item 3). Pure, never
    autonomous. The verdicts, from the shared reader:

    * a claim that opens H seen, a claim on record (``counter_claim_tx``), or CLAIMED → PAGE_CLAIM naming
      the covenant claim: the refund lost, or
      p is public beside it. Conclusive once the page is delivered after t_rxd has matured.
    * a log the detection scan counts as a claim and the reader does not → PAGE_SQUEEZED "investigate".
    * unsettled (OPEN, TIP_EXPIRED, F_EXPIRED) → PAGE_REFUND: the recorded refund never landed, and
      ``refund()`` on the contract (anyone may call it after the timeout; it pays the refundee) is
      still due. Never conclusive, like an unspent BTC HTLC. Not urgent: before the timeout a refund
      cannot be sent yet, and from the timeout on the contract refuses a claim, so nothing races it.
    * REFUNDED, or EXPIRED_EMPTY_CLOSED, on a read of more than one endpoint → agrees; conclusive. One
      endpoint's answer, EXPIRED_EMPTY_OPEN (a signed push may still land), SETTLED_UNFINAL, or an
      UNKNOWN from a failed read → retried, nothing written. An UNKNOWN that read the contract settled → PAGE_SQUEEZED, retried.
    """
    obs = observations
    corr = _eth_corroboration(obs)
    if obs.eth_disposition is None:
        return LegacyCheck(
            Decision(
                Intent.WATCH,
                reason="legacy net: this tower's ETH source does not read dispositions",
                low_corroboration=corr,
            ),
            "unclassified",
        )
    locator = record.counterchain_locator
    contract = getattr(locator, "contract_address", "(no locator)")
    deadline = (
        None
        if obs.asset_locked_at_height is None
        else _refund_opens_at(policy, record.terms, obs.asset_locked_at_height)
    )
    past = deadline is not None and obs.now_rxd_height >= deadline
    ended = (
        f"this record ended at {record.state.value} when its ETH refund was sent (pyrxd before 0.27 did not follow "
        "a refund to the finalized block)"
    )
    kind = obs.eth_disposition
    why = f" ({obs.eth_disposition_reason})" if obs.eth_disposition_reason else ""
    if obs.eth_claim_seen or kind is DispositionKind.CLAIMED or record.counter_claim_tx is not None:
        refunded = _eth_refund_final(obs)
        seen = (
            "a Claimed log that opens H was served"
            if obs.eth_claim_seen or kind is DispositionKind.CLAIMED
            else f"a claim is on record (tx {record.counter_claim_tx})"
        )
        return LegacyCheck(
            Decision(
                Intent.PAGE_CLAIM,
                reason=(
                    f"{ended}. "
                    + (
                        f"The refund {obs.eth_disposition_tx} is final, but {seen}, so p is public"
                        if refunded
                        else f"The contract was CLAIMED (or {seen}): the refund lost and p is public"
                    )
                    + ". Claim the covenant before t_rxd, if it is still unspent"
                    + (" (t_rxd has matured: the maker may already have refunded it)" if past else "")
                    + (
                        ""
                        if deadline is not None
                        else " (the tower cannot say when t_rxd matures: ACK this page once the covenant is claimed "
                        "or gone)"
                    )
                ),
                recommended_action=(
                    "recover p from the claim tx (pyrxd swap recover-preimage), then claim the covenant with it "
                    "(pyrxd swap build-claim) — not a refund"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_CLAIM_SEEN_P_PUBLIC,
            ),
            "refunded_p_public" if refunded else "claimed",
            conclusive_once_delivered=past,
        )
    if obs.eth_claim_detected:
        return LegacyCheck(
            Decision(
                Intent.PAGE_SQUEEZED,
                reason=(
                    f"{ended}, and the detection scan names a log on the contract that the reader does not count as a "
                    f"claim that opens H{why}"
                ),
                recommended_action=(
                    "investigate — read the contract's logs on other endpoints; if a Claimed log opens H, p is "
                    "public: claim the covenant before t_rxd (pyrxd swap build-claim)"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_LEGACY_UNCLASSIFIED_CLAIM,
            ),
            "unclassified_claim",
        )
    if kind in (DispositionKind.OPEN, DispositionKind.TIP_EXPIRED, DispositionKind.F_EXPIRED):
        timeout = record.terms.eth_timeout_unix_s
        return LegacyCheck(
            Decision(
                Intent.PAGE_REFUND,
                reason=(
                    f"{ended}, but the contract {contract} is not settled: the recorded refund never landed{why}"
                    + (
                        f". It can be refunded once its timeout {timeout} has passed; until then the maker can still "
                        "claim it, which makes p public"
                        if kind is DispositionKind.OPEN
                        else ". Its timeout has passed, so it can no longer be claimed; refund it"
                    )
                ),
                recommended_action=(
                    f"call refund() on the contract {contract} from any account once its timeout has passed (it pays "
                    "the refundee; no coordinator step runs on a terminal record), and watch until it is final"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_LEGACY_ETH_UNSETTLED,
            ),
            kind.value,
        )
    if kind is DispositionKind.EXPIRED_EMPTY_OPEN:
        # Empty now, but a token push signed for the contract may still land (the funding key's nonce at
        # the finalized block has not passed it). A marker would stop every later read, and a push that
        # lands would leave value in the contract with no one told; read again, so a landed push reads
        # F_EXPIRED and pages the refund (review F2).
        return LegacyCheck(
            Decision(
                Intent.WATCH,
                reason=(
                    f"legacy net: the contract reads {kind.value}{why}: empty, but a signed push may still land; "
                    "read again later"
                ),
                low_corroboration=corr,
            ),
            kind.value,
        )
    agreeing = (DispositionKind.REFUNDED, DispositionKind.EXPIRED_EMPTY_CLOSED)
    if kind in agreeing and obs.eth_single_source:
        return LegacyCheck(
            Decision(
                Intent.WATCH,
                reason=f"legacy net: only one endpoint reads the contract {kind.value}; read again later",
                low_corroboration=corr,
            ),
            f"{kind.value}_single_source",
        )
    if kind in agreeing:
        return LegacyCheck(
            Decision(
                Intent.WATCH,
                reason=f"legacy net: the contract reads {kind.value} at the finalized block{why}; the record agrees",
            ),
            kind.value,
            conclusive=True,
        )
    if kind is DispositionKind.UNKNOWN and obs.eth_settled_at_finalized:
        return LegacyCheck(
            Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"{ended}; the contract is settled at the finalized block, but the reader cannot say how{why}",
                recommended_action=(
                    "investigate — read the contract's Claimed/Refunded logs and receipts on other endpoints; if a "
                    "Claimed log opens H, p is public: claim the covenant before t_rxd (pyrxd swap build-claim)"
                ),
                deadline_rxd_height=deadline,
                low_corroboration=corr,
                situation=SITUATION_ETH_DISPOSITION_CONTRADICTION,
            ),
            "contradiction",
        )
    return LegacyCheck(
        Decision(
            Intent.WATCH,
            reason=f"legacy net: the contract reads {kind.value}{why}; read again later",
            low_corroboration=corr,
        ),
        kind.value,
    )

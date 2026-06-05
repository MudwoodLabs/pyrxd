"""Pure decision core for the alert-only watchtower (BTC + ETH counter-legs).

``decide(record, observations, policy, safety_window_blocks)`` returns a
:class:`Decision` — an :class:`Intent` plus a human-actionable reason, the
coordinator step the operator should run, and the deadline. It is **pure**: no
chain calls, no I/O, exhaustively unit-testable, and it **consumes** the audited
gate (``assess_claim_finality``) and the maker-stall predicate
(``should_taker_refund_proactively``) rather than re-deriving them.

Key safety rules (mirrors the live coordinator, never routes around it):
* Chain truth dominates a lagging record: if the maker's counter-leg claim is
  observed on-chain (``maker_has_claimed_btc``), the asset claim is assessed
  REGARDLESS of ``record.state`` — a record stuck at ``BOTH_LOCKED`` while the
  chain shows the reveal must still page the claim race (spec-flow Gap 2/7).
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

from pyrxd.btc_wallet.taproot import TimeUnit
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.swap_coordinator import (
    ClaimFinality,
    MarginPolicy,
    assess_claim_finality,
    should_taker_refund_proactively,
)
from pyrxd.gravity.swap_state import SwapRecord, SwapState, is_terminal
from pyrxd.security.errors import ValidationError

__all__ = ["Decision", "Intent", "Observations", "decide"]


class Intent(Enum):
    """What the watchtower should do for one swap, this tick.

    v1 NEVER broadcasts; the ``PAGE_*`` intents are alerts that tell the operator
    which one-shot coordinator step to run and by when.

    * ``WATCH`` — nothing due yet; keep observing (no page, or a low-severity tick).
    * ``PAGE_CLAIM`` — the maker revealed ``p`` and the claim is reorg-safe + fits
      the window (gate SAFE). Operator must claim the asset before the deadline.
    * ``PAGE_REFUND`` — the maker stalled / params mismatch; the operator should
      refund (asset-on-stall or BTC counter-leg).
    * ``PAGE_SQUEEZED`` — a decision is required (gate SQUEEZED / ASSET_VULNERABLE,
      or finality un-assessable): winner-take-all claim vs accept loss. Never
      auto-resolved in v1.
    * ``RETIRE`` — the swap reached a terminal state; stop watching it.
    * ``NOOP`` — an unsupported counter_chain (BTC and ETH are both handled).
    """

    WATCH = "watch"
    PAGE_CLAIM = "page_claim"
    PAGE_REFUND = "page_refund"
    PAGE_SQUEEZED = "page_squeezed"
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
    cross-checked against an independent source — a false read here causes a false *page*,
    never a false broadcast.
    """

    maker_has_claimed_btc: bool
    now_rxd_height: int
    asset_locked_at_height: int | None = None
    btc_claim_confirmations: int | None = None
    # ETH counter-leg (v3). ``eth_claim_detected`` = the maker's ETH claim tx was observed on-chain;
    # ``eth_claim_finality`` = its point-in-time finalized-checkpoint verdict STATE (FINAL /
    # NOT_YET_FINAL_LIVE / COUNTER_CHAIN_NOT_FINALIZING), ``None`` until/unless a claim is observed.
    # ETH finality is a CHECKPOINT, not a DEPTH — there is no ETH analogue of
    # ``btc_claim_confirmations``; ``decide()`` rebuilds a depth-less ``CounterClaimFinality`` from
    # this state (so it consumes the audited gate verdict and never re-derives finality).
    eth_claim_detected: bool = False
    eth_claim_finality: CounterClaimState | None = None
    low_corroboration: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.maker_has_claimed_btc, bool):
            raise ValidationError("Observations.maker_has_claimed_btc must be bool")
        if not isinstance(self.now_rxd_height, int) or isinstance(self.now_rxd_height, bool) or self.now_rxd_height < 0:
            raise ValidationError("Observations.now_rxd_height must be a non-negative int")
        for label, val in (
            ("asset_locked_at_height", self.asset_locked_at_height),
            ("btc_claim_confirmations", self.btc_claim_confirmations),
        ):
            if val is not None and (not isinstance(val, int) or isinstance(val, bool) or val < 0):
                raise ValidationError(f"Observations.{label} must be a non-negative int or None")
        if not isinstance(self.eth_claim_detected, bool):
            raise ValidationError("Observations.eth_claim_detected must be bool")
        if self.eth_claim_finality is not None and not isinstance(self.eth_claim_finality, CounterClaimState):
            raise ValidationError("Observations.eth_claim_finality must be a CounterClaimState or None")
        if not isinstance(self.low_corroboration, bool):
            raise ValidationError("Observations.low_corroboration must be bool")


@dataclass(frozen=True)
class Decision:
    """The watchtower's conclusion for one swap, this tick.

    ``recommended_action`` names the one-shot coordinator step the operator should
    run (a string, for the alert payload — v1 does not invoke it). ``deadline_rxd_height``
    is the RXD height by which the action must land (the maker's CSV refund opens),
    or ``None`` when not time-bounded. ``low_corroboration`` is propagated from the
    observations so the alert layer can mark a single-source page.
    """

    intent: Intent
    reason: str
    recommended_action: str | None = None
    deadline_rxd_height: int | None = None
    low_corroboration: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.intent, Intent):
            raise ValidationError("Decision.intent must be an Intent")
        if not isinstance(self.reason, str) or not self.reason:
            raise ValidationError("Decision.reason must be a non-empty str")


def _required_btc_depth_blocks(policy: MarginPolicy) -> int:
    """The reorg depth the FINAL verdict requires, in blocks — identical to the
    coordinator's construction (swap_coordinator.py:1258-1260), so the verdict and
    the gate's internal reserve cannot diverge (assess_claim_finality fails closed
    on a mismatch)."""
    return policy.btc_claim_reorg_depth.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value


def _refund_opens_at(policy: MarginPolicy, terms, asset_locked_at_height: int) -> int:
    """RXD height at which the maker's CSV refund opens (the claim deadline)."""
    t_rxd_blocks = terms.t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
    return asset_locked_at_height + t_rxd_blocks


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
    corr = obs.low_corroboration

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
    if obs.maker_has_claimed_btc or state is SwapState.SECRET_REVEALED:
        if obs.btc_claim_confirmations is None or obs.asset_locked_at_height is None:
            # Cannot assess finality — fail closed to a decision-required page.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason="maker claim observed but finality un-assessable (missing claim depth or asset-lock height) — fail-closed",
                recommended_action="taker_scrape_and_claim_asset (verify finality manually)",
                low_corroboration=corr,
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
            )
        except ValidationError as exc:
            # e.g. now_rxd_height < asset_locked_at_height (lagging/lying node) → fail-closed.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"maker claim observed but finality gate un-assessable, fail-closed: {exc}",
                recommended_action="taker_scrape_and_claim_asset (verify finality manually)",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        if finality is ClaimFinality.SAFE:
            return Decision(
                Intent.PAGE_CLAIM,
                reason=f"maker revealed p; BTC claim reorg-safe ({obs.btc_claim_confirmations} conf) and burial fits the window",
                recommended_action="taker_scrape_and_claim_asset",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
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
            recommended_action="taker_claim_asset_from_vulnerable (winner-take-all) vs accept loss",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )

    # 3. Maker has NOT revealed p.
    # 3a. Already in the danger state — a decision is required (never auto-resolved).
    if state is SwapState.ASSET_VULNERABLE:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="ASSET_VULNERABLE: winner-take-all decision required",
            recommended_action="taker_claim_asset_from_vulnerable vs accept loss",
            low_corroboration=corr,
        )
    # 3b. Maker locked the asset with wrong params — refund the BTC counter-leg.
    if state is SwapState.PARAMS_MISMATCH:
        return Decision(
            Intent.PAGE_REFUND,
            reason="covenant params mismatch — refund the BTC counter-leg via the timelock leg",
            recommended_action="taker_refund_btc",
            low_corroboration=corr,
        )
    # 3c. Asset-leg proactive refund on maker stall (BOTH_LOCKED / MAKER_STALLS).
    if state in (SwapState.BOTH_LOCKED, SwapState.MAKER_STALLS):
        if obs.asset_locked_at_height is None:
            return Decision(Intent.WATCH, reason="asset lock height not yet observed", low_corroboration=corr)
        deadline = _refund_opens_at(policy, terms, obs.asset_locked_at_height)
        if state is SwapState.MAKER_STALLS:
            # The FSM already classified this as a stall — the refund is due.
            return Decision(
                Intent.PAGE_REFUND,
                reason="maker stalling (MAKER_STALLS) — refund the asset proactively before t_rxd",
                recommended_action="maybe_refund_asset_on_maker_stall",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        try:
            refund_due = should_taker_refund_proactively(
                now_block_height=obs.now_rxd_height,
                asset_locked_at_height=obs.asset_locked_at_height,
                t_rxd=terms.t_rxd,
                safety_window_blocks=safety_window_blocks,
                maker_has_claimed_btc=False,
                block_interval_s=policy.block_interval_s,
            )
        except ValidationError as exc:
            # Un-evaluable heights → fail-closed toward paging the refund (don't sit silently).
            return Decision(
                Intent.PAGE_REFUND,
                reason=f"maker-stall predicate un-evaluable, fail-closed to refund page: {exc}",
                recommended_action="maybe_refund_asset_on_maker_stall",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        if refund_due:
            return Decision(
                Intent.PAGE_REFUND,
                reason="maker has not claimed and t_rxd maturity is approaching — refund the asset proactively",
                recommended_action="maybe_refund_asset_on_maker_stall",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        return Decision(
            Intent.WATCH,
            reason="both legs locked; maker not yet claimed; refund window not yet near",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )

    # 3d. Pre-lock states (NEGOTIATED, BTC_LOCKED): nothing time-critical for v1.
    #     (The "maker never locks the asset → refund BTC after t_btc" stranded-BTC
    #     watch is a v1.1 add — it is recoverable, not a race, so v1 only watches.)
    return Decision(Intent.WATCH, reason=f"no action due in {state.value}", low_corroboration=corr)


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
      unwinds BOTH legs once their timeouts elapse.
    * **The maker-claim trigger is ``eth_claim_detected``** (an ETH claim tx observed) instead of a
      spent BTC funding outpoint. ``should_taker_refund_proactively`` is chain-agnostic (it keys purely
      on RXD heights) and is reused unchanged.

    Alert-only: like the BTC branch it broadcasts nothing and only names the coordinator step.
    """
    obs = observations
    corr = obs.low_corroboration
    terms = record.terms
    state = record.state

    # Claim race. p is (becoming) public if EITHER the chain shows the maker's ETH claim OR the
    # record already advanced to SECRET_REVEALED — OR'd so a suppressed single-source claim DETECTION
    # cannot drop a known-revealed swap into the silent WATCH catch-all (mirrors the BTC branch).
    if obs.eth_claim_detected or state is SwapState.SECRET_REVEALED:
        if obs.eth_claim_finality is None or obs.asset_locked_at_height is None:
            # Claim indicated but finality un-assessable (no finalized-checkpoint verdict or no
            # asset-lock height) → fail closed to a decision-required page.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason="maker ETH claim observed but finality un-assessable (missing finalized verdict or asset-lock height) — fail-closed",
                recommended_action="taker_scrape_and_claim_asset (verify finality manually)",
                low_corroboration=corr,
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
            )
        except ValidationError as exc:
            # e.g. now_rxd < asset_locked (lagging node) or missing eth_finalization_window_s → fail-closed.
            return Decision(
                Intent.PAGE_SQUEEZED,
                reason=f"maker ETH claim observed but finality gate un-assessable, fail-closed: {exc}",
                recommended_action="taker_scrape_and_claim_asset (verify finality manually)",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        if finality is ClaimFinality.SAFE:
            return Decision(
                Intent.PAGE_CLAIM,
                reason="maker revealed p on ETH; claim finalized and burial fits the window",
                recommended_action="taker_scrape_and_claim_asset",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
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
            recommended_action="taker_claim_asset_from_vulnerable (winner-take-all) vs accept loss",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )

    # Maker has NOT revealed p.
    if state is SwapState.ASSET_VULNERABLE:
        return Decision(
            Intent.PAGE_SQUEEZED,
            reason="ASSET_VULNERABLE: winner-take-all decision required",
            recommended_action="taker_claim_asset_from_vulnerable vs accept loss",
            low_corroboration=corr,
        )
    if state is SwapState.PARAMS_MISMATCH:
        # The maker locked the wrong covenant; the taker only needs to recover its own ETH HTLC.
        # `taker_refund_btc` is the state-valid step (coordinator allows it from PARAMS_MISMATCH and it
        # services the counter-leg refund — the ETH HTLC here); `mutual_refund` is BOTH_LOCKED-only and
        # would also touch the maker's covenant. Mirror the BTC branch's action.
        return Decision(
            Intent.PAGE_REFUND,
            reason="covenant params mismatch on the ETH swap — refund the ETH counter-leg HTLC (taker_refund_btc)",
            recommended_action="taker_refund_btc",
            low_corroboration=corr,
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
        )
    if state is SwapState.BOTH_LOCKED:
        if obs.asset_locked_at_height is None:
            return Decision(Intent.WATCH, reason="asset lock height not yet observed", low_corroboration=corr)
        deadline = _refund_opens_at(policy, terms, obs.asset_locked_at_height)
        try:
            refund_due = should_taker_refund_proactively(
                now_block_height=obs.now_rxd_height,
                asset_locked_at_height=obs.asset_locked_at_height,
                t_rxd=terms.t_rxd,
                safety_window_blocks=safety_window_blocks,
                maker_has_claimed_btc=False,  # chain-agnostic predicate: "has the maker claimed the counter-leg"
                block_interval_s=policy.block_interval_s,
            )
        except ValidationError as exc:
            return Decision(
                Intent.PAGE_REFUND,
                reason=f"maker-stall predicate un-evaluable, fail-closed to refund page: {exc}",
                recommended_action="mutual_refund",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        if refund_due:
            return Decision(
                Intent.PAGE_REFUND,
                reason="maker has not claimed and t_rxd maturity approaching — prepare to mutual_refund (broadcast once both timeouts elapse)",
                recommended_action="mutual_refund",
                deadline_rxd_height=deadline,
                low_corroboration=corr,
            )
        return Decision(
            Intent.WATCH,
            reason="both legs locked; maker not yet claimed; refund window not yet near",
            deadline_rxd_height=deadline,
            low_corroboration=corr,
        )

    # Pre-lock states (NEGOTIATED, ETH funded but asset not yet locked): nothing time-critical.
    return Decision(Intent.WATCH, reason=f"no action due in {state.value}", low_corroboration=corr)

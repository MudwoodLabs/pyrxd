"""Per-leg claim-finality verdict — the INPUT to ``assess_claim_finality``.

The mature reorg gate (``assess_claim_finality`` in ``swap_coordinator``) decides
SAFE / WAIT / SQUEEZED for the taker's asset claim from the *counter-leg* claim's finality.
But "final" means different things per chain: BTC/PoW finality is a confirmation DEPTH,
while ETH/PoS finality is the ``finalized`` CHECKPOINT (not a depth). This module is the
chain-neutral verdict both legs produce and the gate consumes, so the gate stays agnostic
to how a leg decides "final".

``confirmations`` / ``required_depth`` are carried ONLY for a depth-based (PoW) leg, so the
gate can reproduce its remaining-depth WAIT-vs-SQUEEZED refinement byte-for-byte; a
finalized-checkpoint leg leaves them ``None`` (finality is not a depth there).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pyrxd.security.errors import ValidationError

__all__ = ["CounterClaimFinality", "CounterClaimState", "FinalityStallTracker"]

# Post-Merge ETH: 1 epoch = 32 slots = 384 s; `finalized` normally advances one epoch at a
# time, so the steady-state head→finalized gap is ~2 epochs. A genuine stall (May-2023 mainnet,
# Sepolia/Holesky testnets) freezes `finalized` while the head keeps advancing. We declare a
# stall when `finalized` has not advanced across observations spanning at least this many slots
# of head progress AND the head-vs-finalized gap exceeds the normal ~2-epoch lag by a margin.
_SLOTS_PER_EPOCH = 32


class CounterClaimState(Enum):
    """Whether the counter-leg claim (which revealed ``p``) is final enough to act on."""

    FINAL = "final"
    NOT_YET_FINAL_LIVE = "not_yet_final_live"
    # RF-06: the counter chain is not advancing finalization (an ETH non-finality stall is
    # consensus liveness, not adversary action). The gate must SQUEEZE, never WAIT, on it.
    COUNTER_CHAIN_NOT_FINALIZING = "counter_chain_not_finalizing"


@dataclass(frozen=True)
class CounterClaimFinality:
    """A counter-leg claim's finality verdict.

    For a PoW leg, ``confirmations`` and ``required_depth`` carry the live confirmation
    count and the policy depth (both in counter-chain blocks); for a finalized-checkpoint
    (PoS) leg they are ``None`` — finality there is not a depth.
    """

    state: CounterClaimState
    confirmations: int | None = None
    required_depth: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.state, CounterClaimState):
            raise ValidationError("CounterClaimFinality.state must be a CounterClaimState")
        for name in ("confirmations", "required_depth"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                raise ValidationError(f"CounterClaimFinality.{name} must be a non-negative int or None")

    @classmethod
    def from_btc_depth(cls, confirmations: int, required_depth: int) -> CounterClaimFinality:
        """PoW adapter: ``FINAL`` iff ``confirmations >= required_depth``, else
        ``NOT_YET_FINAL_LIVE``. Carries ``(confirmations, required_depth)`` so the gate's
        remaining-depth guard is exactly reproducible. Never emits
        ``COUNTER_CHAIN_NOT_FINALIZING`` — PoW does not stall finalization.
        """
        if not isinstance(confirmations, int) or isinstance(confirmations, bool) or confirmations < 0:
            raise ValidationError("confirmations must be a non-negative int")
        if not isinstance(required_depth, int) or isinstance(required_depth, bool) or required_depth < 0:
            raise ValidationError("required_depth must be a non-negative int")
        state = CounterClaimState.FINAL if confirmations >= required_depth else CounterClaimState.NOT_YET_FINAL_LIVE
        return cls(state=state, confirmations=confirmations, required_depth=required_depth)

    @property
    def remaining_positive(self) -> bool:
        """Reproduces the old ``btc_blocks_remaining > 0`` guard.

        ``True`` when depth info is absent (a finalized-checkpoint leg — reserve the full
        window) or when ``required_depth - confirmations > 0`` (always true on the PoW
        not-final branch, where ``confirmations < required_depth`` by construction).
        """
        if self.confirmations is None or self.required_depth is None:
            return True
        return (self.required_depth - self.confirmations) > 0


class FinalityStallTracker:
    """RF-06 across-time stall detector for a finalized-checkpoint (PoS) counter leg.

    WIRED INTO THE LIVE WATCHTOWER ALERT PATH (A8): the watchtower's ``ChainObserver`` holds one
    tracker per ``swap_id`` and feeds it the current ``(head, finalized)`` each tick (via the ETH
    source's ``finality_checkpoint()`` capability), so a sustained PoS finality stall ("finalized"
    frozen while the head advances) upgrades ``NOT_YET_FINAL_LIVE`` → ``COUNTER_CHAIN_NOT_FINALIZING``,
    which ``decide()`` routes to an earlier SQUEEZE page. This is ALERT-ONLY — it sharpens/advances a
    page; the tower broadcasts nothing and there is NO autonomy change. (The production
    ``SwapCoordinator``'s own one-shot claim path still consults only the point-in-time
    ``claim_finality_verdict``; the across-time judgment lives in the polling tower, which is where
    samples accrue across time.)

    ``claim_finality_verdict`` is deliberately a single POINT-IN-TIME observation and never
    emits ``COUNTER_CHAIN_NOT_FINALIZING`` (a single non-advance of ``finalized`` is normal —
    it only moves at epoch boundaries). A genuine stall — ``finalized`` frozen while the head
    keeps advancing — can only be judged across time. This is that stateful judge: feed it the
    ``(head_block, finalized_block, observed_at_unix_s)`` the poll loop already reads, and it
    upgrades a ``NOT_YET_FINAL_LIVE`` verdict to ``COUNTER_CHAIN_NOT_FINALIZING`` once finality
    has been stuck long enough that it is a liveness fault, not just normal epoch lag.

    Stall predicate (BOTH must hold): (a) ``finalized`` has NOT advanced since the first sample
    in the current run, across head progress of at least ``patience_slots`` slots — i.e. many
    epochs' worth of blocks were produced with no new finalization; AND (b) the live head-to-
    finalized gap exceeds ``max_normal_lag_slots`` (so we never trip on the ~2-epoch steady-state
    lag). A new ``finalized`` value RESETS the run (finality is advancing again → live, not
    stalled). Pure / no chain I/O / fail-closed on malformed input.

    Defaults: ``patience_slots = 4 epochs`` (128 slots ≈ 25.6 min) cleanly separates normal lag
    from a stall — the May-2023 mainnet incident reached ~9 epochs; ``max_normal_lag_slots =
    3 epochs`` (96 slots) sits just above the ~2-epoch steady state. Both are CHOSEN, documented,
    and tunable; a tighter window false-positives on a slow-but-healthy epoch, a looser one is
    slower to react. The cost of declaring a stall is the gate SQUEEZES (never silently claims),
    so erring slightly eager is the safe direction.
    """

    def __init__(self, *, patience_slots: int = 4 * _SLOTS_PER_EPOCH, max_normal_lag_slots: int = 3 * _SLOTS_PER_EPOCH):
        for name, v in (("patience_slots", patience_slots), ("max_normal_lag_slots", max_normal_lag_slots)):
            if not isinstance(v, int) or isinstance(v, bool) or v < 1:
                raise ValidationError(f"{name} must be a positive int")
        self._patience_slots = patience_slots
        self._max_normal_lag_slots = max_normal_lag_slots
        # The current "finalized stuck at this value" run: the finalized block it froze at, and
        # the head block when we FIRST saw it frozen there. None until the first observation.
        self._stuck_finalized: int | None = None
        self._head_at_run_start: int | None = None

    def observe(self, *, head_block: int, finalized_block: int) -> bool:
        """Ingest one sample; return True once a finality STALL is declared.

        ``head_block`` / ``finalized_block`` are the current chain tip and ``finalized``
        checkpoint block numbers (``finalized_block <= head_block``). Returns True while the
        stall predicate holds; a fresh ``finalized`` resets and returns False.
        """
        for name, v in (("head_block", head_block), ("finalized_block", finalized_block)):
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValidationError(f"{name} must be a non-negative int")
        if finalized_block > head_block:
            raise ValidationError("finalized_block must be <= head_block")

        if self._stuck_finalized != finalized_block:
            # Finality advanced (or first ever sample) → start a fresh run, not stalled.
            self._stuck_finalized = finalized_block
            self._head_at_run_start = head_block
            return False

        # finalized has not moved since this run began. Has the head advanced far enough,
        # AND is the live gap beyond the normal steady-state lag?
        head_progress = head_block - (self._head_at_run_start if self._head_at_run_start is not None else head_block)
        live_gap = head_block - finalized_block
        return head_progress >= self._patience_slots and live_gap > self._max_normal_lag_slots

    def verdict(
        self, point_in_time: CounterClaimFinality, *, head_block: int, finalized_block: int
    ) -> CounterClaimFinality:
        """Combine a point-in-time verdict with the across-time stall judgment.

        If the point-in-time verdict is already ``FINAL``, the claim is final regardless of any
        stall — return it unchanged. Otherwise feed the sample to :meth:`observe`; if a stall is
        declared, upgrade ``NOT_YET_FINAL_LIVE`` → ``COUNTER_CHAIN_NOT_FINALIZING`` so the gate
        SQUEEZES (the documented RF-06 behaviour) instead of waiting forever.
        """
        if point_in_time.state is CounterClaimState.FINAL:
            return point_in_time
        stalled = self.observe(head_block=head_block, finalized_block=finalized_block)
        if stalled:
            return CounterClaimFinality(state=CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING)
        return point_in_time

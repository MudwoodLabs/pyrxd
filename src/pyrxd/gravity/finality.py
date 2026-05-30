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

__all__ = ["CounterClaimFinality", "CounterClaimState"]


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

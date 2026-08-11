"""Deadline-aware fee sizing for time-critical HTLC spends.

Why this module exists (gap-closure plan A1, spike 2026-08-09)
--------------------------------------------------------------
**Radiant supports neither RBF nor CPFP.** Verified against ``Radiant-Core`` @
``afdf57b1`` and the live mainnet node (Radiant Core 3.1.2):

* **No RBF.** ``src/validation.cpp:667`` and ``:856`` reject any mempool conflict
  outright (``txn-mempool-conflict`` / ``REJECT_DUPLICATE``). The only ``bip125``
  string in the tree is a DEPRECATED help label; there is no ``bumpfee`` RPC.
  Radiant ships DSProof (double-spend *proofs*) — it treats a conflict as fraud to
  broadcast, the opposite of replacement.
* **No CPFP.** ``src/miner.cpp:380`` selects on ``GetModifiedFeeRate()`` =
  ``(nFee + feeDelta) / vsize`` — the transaction's OWN fee over its OWN size — and
  ``break``s at ``blockMinFeeRate``. The ``backlog`` queue is topological ordering
  only. A high-fee child cannot lift a low-fee parent into a block.

**Consequence.** An under-fee'd honest time-critical claim or refund cannot be fixed
by any means. It sits in the mempool until expiry —
``DEFAULT_MEMPOOL_EXPIRY = 8`` hours (``src/validation.h:82``) — before its inputs
free for a rebuild. **If the deadline falls inside that window there is no remedy.**

Fee *pre-sizing* is therefore the only control. This module is that control, and it
is deliberately prevention-only: **do not add an RBF or CPFP path here.** Any
"just bump the fee" proposal is Bitcoin semantics assumed onto a BCH-lineage chain.

What the policy is, and is not
------------------------------
:meth:`DeadlineFeePolicy.min_relay_fee` is a **derivation** of the node's own check,
not an invention. ``AcceptToMemoryPool`` rejects with ``min relay fee not met`` when
``nModifiedFees < GetEffectiveMinRelayFee(height).GetFee(nSize)``
(``src/validation.cpp:778``), where:

* ``nSize = tx.GetTotalSize()`` — the **full serialized size**. The source carries an
  explicit "Do not change this to use virtualsize without coordinating a network
  policy upgrade" (``src/validation.cpp:770``). So the correct input is
  ``len(tx.serialize())``, measured after signing, not an estimate and not a vsize.
* the rate is ``RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB`` = **10,000,000 photons/kB**
  post-upgrade (``src/policy/policy.h:49``), vs the legacy 1,000,000
  (``:47``) — which is why ``getmempoolinfo`` reports ``effective_minrelaytxfee``
  0.10 RXD/kB alongside ``minrelaytxfee`` 0.01. **The effective one is what binds.**
* ``CFeeRate::GetFee`` **truncates** (``ceil=false``, ``src/feerate.cpp:51``). We round
  **up** instead, so this is at most one photon stricter than the node — deliberately,
  because being one photon short is a broadcast you cannot take back.

:meth:`DeadlineFeePolicy.urgency_multiplier` is a **policy choice**, not a measured
inclusion model. Nobody has measured a Radiant fee/confirmation-time curve, and this
module does not pretend to have one. The multiplier buys headroom above the relay
floor as a deadline closes, so that a *policy* change (the reference node's
``effective_minrelaytxfee`` is 10× its ``minrelaytxfee``, and either can move) or
transient mempool competition does not strand a spend that cannot be re-fee'd.
It is a linear ramp — explicit, monotone, and injectable — not a prediction.

Rates are **injected, never read from the network inside these functions**, so the
whole module is pure and testable. The reference-node values below are defaults, not
constants of the protocol: node policy can change, and an operator who reads a
different ``effective_minrelaytxfee`` should pass it in.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction

from pyrxd.fee_sizing import (
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    RADIANT_MIN_RELAY_PHOTONS_PER_KB,
    fee_for_kb_rate,
)
from pyrxd.security.errors import InsufficientFundsError, ValidationError

__all__ = [
    "BITCOIN_MIN_RELAY_SATS_PER_KB",
    "DEFAULT_BITCOIN_DEADLINE_FEE_POLICY",
    "DEFAULT_RADIANT_DEADLINE_FEE_POLICY",
    "MEMPOOL_EXPIRY_HOURS",
    "PHOTONS_PER_RXD",
    "RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB",
    "RADIANT_MIN_RELAY_PHOTONS_PER_KB",
    "DeadlineFeePolicy",
    "assert_fee_covers",
    "photons_per_kb_from_rxd_per_kb",
]

PHOTONS_PER_RXD = 100_000_000

# The two relay-floor constants are RE-EXPORTED from :mod:`pyrxd.fee_sizing`, not
# defined here, so the plain-RXD wallet and the swap stack cannot drift apart on what
# the node demands. They moved there rather than the other way round because
# ``pyrxd.wallet`` cannot import this package at module scope:
# ``pyrxd.gravity.__init__`` reaches ``pyrxd.hd.wallet``, which imports
# ``pyrxd.wallet`` — a genuine import cycle. Nothing about their meaning changed:
# Radiant-Core ``src/policy/policy.h``: ``LEGACY_MIN_RELAY_TX_FEE_PER_KB`` (:47) and
# ``RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB`` (:49). ``GetEffectiveMinRelayFee`` returns
# the legacy rate before the 2.0 activation + 5000-block grace period and the higher one
# after; the reference mainnet node reports the higher one (``getmempoolinfo``, read
# 2026-08-09: ``minrelaytxfee`` 0.01, ``effective_minrelaytxfee`` 0.10 RXD/kB).
# The EFFECTIVE rate is what ``AcceptToMemoryPool`` checks, and it is 10x the nominal
# one — precisely why this is a default to override, not a constant to hardcode.

# Bitcoin Core's ``DEFAULT_MIN_RELAY_TX_FEE`` (1 sat/vB). Used by the BTC-side
# pre-signed-refund affordability bind, which sizes against the blob's serialized
# length (>= its vsize for a witness tx, so the requirement errs high — the safe
# direction for a spend guard).
BITCOIN_MIN_RELAY_SATS_PER_KB = 1_000

# ``DEFAULT_MEMPOOL_EXPIRY`` (Radiant-Core ``src/validation.h:82``), in hours. How
# long an under-fee'd, un-bumpable transaction squats on its own inputs.
MEMPOOL_EXPIRY_HOURS = 8


def photons_per_kb_from_rxd_per_kb(rxd_per_kb: float) -> int:
    """Convert a node's ``getmempoolinfo`` fee rate (RXD/kB) to photons/kB.

    ``getmempoolinfo`` reports ``effective_minrelaytxfee`` in whole RXD per kB
    (e.g. ``0.10000000``). This is the one-line bridge from that reading to a
    :class:`DeadlineFeePolicy` rate, so an operator never hand-multiplies by 1e8.
    Rounds UP: a relay floor must never be under-stated.
    """
    if isinstance(rxd_per_kb, bool) or not isinstance(rxd_per_kb, (int, float)):
        raise ValidationError("rxd_per_kb must be a number")
    if not math.isfinite(rxd_per_kb) or rxd_per_kb < 0:
        raise ValidationError("rxd_per_kb must be a finite, non-negative number")
    # Fraction(float) is exact-binary; limit_denominator normalises 0.1 to 1/10 so
    # the conversion is the decimal one an operator expects, not 0.1000000000000000055.
    rate = Fraction(rxd_per_kb).limit_denominator(10**9) * PHOTONS_PER_RXD
    return -(-rate.numerator // rate.denominator)  # ceil


@dataclass(frozen=True)
class DeadlineFeePolicy:
    """How a time-critical HTLC spend is fee'd. Pure, injectable, no network reads.

    Attributes
    ----------
    relay_fee_per_kb:
        The node's min-relay rate in the chain's smallest unit **per kB** (photons
        on Radiant, satoshis on BTC). This is *node policy* and it moves — read it
        from ``getmempoolinfo`` (``effective_minrelaytxfee``, via
        :func:`photons_per_kb_from_rxd_per_kb`) rather than trusting the default.
    urgency_horizon_blocks:
        Blocks-to-deadline at (or above) which no urgency premium applies. Inside
        the horizon the multiplier ramps linearly toward
        ``max_urgency_multiplier``. Default 6 — the same order as the reorg depths
        the swap stack already reasons in, not a measured figure.
    max_urgency_multiplier:
        The premium at (or past) the deadline. Default 3.0. A POLICY CHOICE: no
        Radiant fee/confirmation curve has been measured, so this buys headroom
        against a relay-policy change or mempool competition, and claims nothing
        about inclusion latency.
    """

    relay_fee_per_kb: int = RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
    # The chain's own minimum relay rate, used ONLY to sanity-bound `relay_fee_per_kb`
    # (see __post_init__). Per-chain because the units differ: Radiant photons/kB vs
    # Bitcoin sats/kB. Set it to the target chain's floor when constructing a policy for
    # a chain other than Radiant.
    protocol_floor_per_kb: int = RADIANT_MIN_RELAY_PHOTONS_PER_KB
    # Escape hatch for regtest / a chain you control. Named so that using it is a
    # deliberate, greppable act rather than a silently-accepted low rate.
    allow_below_protocol_floor: bool = False
    urgency_horizon_blocks: int = 6
    max_urgency_multiplier: float = 3.0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.relay_fee_per_kb, int)
            or isinstance(self.relay_fee_per_kb, bool)
            or self.relay_fee_per_kb <= 0
        ):
            raise ValidationError("DeadlineFeePolicy.relay_fee_per_kb must be a positive int (units per kB)")
        # SECURITY (review finding): the rate is normally read from a NODE
        # (`getmempoolinfo` -> photons_per_kb_from_rxd_per_kb), so it crosses a trust
        # boundary. A lying or misconfigured endpoint advertising, say, 0.00000001 RXD/kB
        # would yield a policy whose "floor" is ~1 photon/kB — thousands of times under the
        # real requirement — and with no RBF/CPFP the resulting spend is unfixable for
        # MEMPOOL_EXPIRY_HOURS. Refuse a rate below the protocol's own legacy floor unless
        # the caller explicitly opts out (regtest/custom chains legitimately run lower).
        if not self.allow_below_protocol_floor and self.relay_fee_per_kb < self.protocol_floor_per_kb:
            raise ValidationError(
                f"DeadlineFeePolicy.relay_fee_per_kb={self.relay_fee_per_kb} is below the chain's "
                f"relay floor ({self.protocol_floor_per_kb}/kB). A rate read "
                "from an untrusted or misconfigured node can be arbitrarily low, and an under-fee'd "
                "time-critical spend cannot be bumped (no RBF, no CPFP). Pass "
                "allow_below_protocol_floor=True only for regtest or a chain you control."
            )
        if (
            not isinstance(self.urgency_horizon_blocks, int)
            or isinstance(self.urgency_horizon_blocks, bool)
            or self.urgency_horizon_blocks < 1
        ):
            raise ValidationError("DeadlineFeePolicy.urgency_horizon_blocks must be an int >= 1")
        if (
            not isinstance(self.max_urgency_multiplier, (int, float))
            or isinstance(self.max_urgency_multiplier, bool)
            or not math.isfinite(self.max_urgency_multiplier)
            or self.max_urgency_multiplier < 1.0
        ):
            # Reject NaN/inf at construction: NaN < 1.0 is False, so without the
            # isfinite guard a NaN would pass here and poison every later fee.
            raise ValidationError("DeadlineFeePolicy.max_urgency_multiplier must be a finite float >= 1.0")

    # -- the derivation -----------------------------------------------------
    def min_relay_fee(self, size_bytes: int) -> int:
        """The node's relay-fee floor for a ``size_bytes`` transaction: ``ceil(size * rate / 1000)``.

        Integer arithmetic and rounded UP, matching how a node computes the floor —
        a fee one unit short of the floor is rejected exactly like a zero fee.
        """
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes <= 0:
            raise ValidationError("size_bytes must be a positive int (the SERIALIZED transaction size)")
        # One implementation of the node's derivation, shared with the wallet and glyph
        # builders (:func:`pyrxd.fee_sizing.fee_for_kb_rate`) — see the constants note above.
        return fee_for_kb_rate(size_bytes, self.relay_fee_per_kb)

    # -- the policy ---------------------------------------------------------
    def _urgency_fraction(self, blocks_to_deadline: int | None) -> Fraction:
        """Exact-rational form of :meth:`urgency_multiplier` (no float drift in fees)."""
        if blocks_to_deadline is None:
            return Fraction(1)
        if not isinstance(blocks_to_deadline, int) or isinstance(blocks_to_deadline, bool):
            raise ValidationError("blocks_to_deadline must be an int or None")
        top = Fraction(self.max_urgency_multiplier).limit_denominator(10**6)
        if blocks_to_deadline <= 0:
            return top  # at or past the deadline — the maximum premium, never more
        horizon = self.urgency_horizon_blocks
        if blocks_to_deadline >= horizon:
            return Fraction(1)
        # Linear ramp: 1.0 at the horizon, `top` at the deadline. Monotone
        # non-increasing in blocks_to_deadline, so a closer deadline never fees LESS.
        return 1 + (top - 1) * Fraction(horizon - blocks_to_deadline, horizon)

    def urgency_multiplier(self, blocks_to_deadline: int | None) -> float:
        """The premium applied to :meth:`min_relay_fee` for a deadline this close.

        ``None`` (no deadline) and any distance at/beyond ``urgency_horizon_blocks``
        give exactly 1.0; it ramps linearly to ``max_urgency_multiplier`` at 0 blocks
        and stays there for a deadline already passed.
        """
        return float(self._urgency_fraction(blocks_to_deadline))

    def required_fee(self, size_bytes: int, *, blocks_to_deadline: int | None = None) -> int:
        """The minimum fee this spend must pay: ``ceil(min_relay_fee × urgency_multiplier)``.

        ``blocks_to_deadline`` is the number of chain blocks left before the spend
        stops being useful (for an HTLC claim: before the counterparty's CSV refund
        branch opens). ``None`` means "no deadline" — the plain relay floor.
        """
        base = self.min_relay_fee(size_bytes)
        mult = self._urgency_fraction(blocks_to_deadline)
        return -(-base * mult.numerator // mult.denominator)  # ceil, integer-only


DEFAULT_RADIANT_DEADLINE_FEE_POLICY = DeadlineFeePolicy()
DEFAULT_BITCOIN_DEADLINE_FEE_POLICY = DeadlineFeePolicy(
    relay_fee_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB,
    # Bitcoin's floor, in sats/kB — NOT Radiant's photon floor. The bound is per-chain.
    protocol_floor_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB,
)


def assert_fee_covers(
    *,
    fee_value: int,
    size_bytes: int,
    policy: DeadlineFeePolicy,
    blocks_to_deadline: int | None = None,
    what: str,
    unit: str = "photons",
) -> int:
    """Fail closed ONLY below the node's relay floor; the urgency premium is a target.

    This distinction is fund-safety-critical, and getting it wrong inverts the whole
    point of the gate (security review of the first cut of this module).

    * ``policy.min_relay_fee(size)`` is what the NODE demands
      (``nModifiedFees < effectiveMinRelayTxFee.GetFee(GetTotalSize())``). Below it the
      spend is unrelayable and — with no RBF and no CPFP — unfixable for
      ``MEMPOOL_EXPIRY_HOURS``. Refusing is strictly better than broadcasting.
    * ``policy.required_fee(size, blocks_to_deadline)`` adds an urgency PREMIUM. That is
      a pool-sizing target for getting mined *promptly*, not a relay requirement.

    Refusing to broadcast a spend that clears the floor but not the premium would be a
    guaranteed loss, not a safety measure: the node would have accepted it, refusing does
    not reduce the fee paid (the whole input is the fee either way), and on the claim path
    the counterparty's CSV refund then takes the asset. The premium also RISES as the
    deadline closes, so a hard gate on it would refuse hardest exactly when claiming
    matters most — including ``taker_claim_asset_from_vulnerable``, whose entire purpose
    is to race that deadline.

    So: raise below the floor; return normally above it. A caller that wants to page on a
    thin premium can compare against :meth:`DeadlineFeePolicy.required_fee` itself.

    Returns the premium-inclusive target fee (for logging/pool sizing) when the floor is
    covered. Raises :class:`~pyrxd.security.errors.InsufficientFundsError` (a
    ``ValidationError`` subclass, so existing handlers still catch it) carrying the
    machine-readable ``available`` / ``required`` / ``shortfall`` triple.
    """
    floor = policy.min_relay_fee(size_bytes)
    required = policy.required_fee(size_bytes, blocks_to_deadline=blocks_to_deadline)
    if fee_value >= floor:
        return required
    mult = policy.urgency_multiplier(blocks_to_deadline)
    required = floor  # report the shortfall against the HARD requirement, not the target
    deadline = "no deadline" if blocks_to_deadline is None else f"{blocks_to_deadline} block(s) to deadline"
    raise InsufficientFundsError(
        f"{what}: fee of {fee_value} {unit} is below the required {required} {unit} "
        f"(short by {required - fee_value} {unit}) for a {size_bytes}-byte transaction at "
        f"{policy.relay_fee_per_kb} {unit}/kB x{mult:.2f} urgency ({deadline}). "
        "Refusing to broadcast: Radiant has no RBF and no CPFP, so an under-fee'd "
        f"time-critical spend cannot be bumped by any means and squats on its own inputs "
        f"for up to {MEMPOOL_EXPIRY_HOURS}h (mempool expiry) before a rebuild is even possible. "
        "Fund a larger fee input and retry.",
        available=fee_value,
        required=required,
    )

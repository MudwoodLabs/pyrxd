"""The swap TAKER GATE: prove the maker's Radiant funding before the taker locks anything.

Before this module, :meth:`pyrxd.gravity.swap_coordinator.SwapCoordinator.taker_verify_asset_funding`
read the maker's covenant UTXO — its scriptPubKey, its value and its depth — from ONE ElectrumX
server's ``listunspent`` and verbose ``confirmations``, with no merkle proof and no header. A server
that invented the covenant made the real coordinator lock the taker's counter leg against an output
that exists on no chain. This module is what the coordinator runs instead.

WHAT IS PROVED, for the one funding transaction the taker is about to rely on:

* its raw bytes hash to its txid, and its output ``vout`` — parsed from those bytes, NOT taken from
  ``listunspent`` — pays exactly the covenant scriptPubKey the taker re-derived from its own terms,
  for exactly the negotiated photon value;
* it is in the block at the height the server named: its merkle branch leads to that block's header,
  at the depth the block's coinbase branch pins (:func:`pyrxd.glyph.mark_block.verify_mark_block`,
  the verifier ``pyrxd verify`` runs, reused here rather than re-implemented);
* that header is linked hash by hash to a checkpoint pyrxd ships, and every header above the newest
  checkpoint that the server served meets its own proof-of-work target and the work floor
  (checkpoint work ÷ :data:`~pyrxd.glyph.mark_block.FLOOR_WORK_DIVISOR`);
* at least ``k`` of those blocks, counting the funding block as 1, where ``k`` is the SETTLED RULE
  below. Anything short of that refuses the lock.

THE RULE (maintainer decision, 2026-09-30)::

    k = max(6, burial, ceil(2 × value_at_stake ÷ C))
    C = floor(subsidy(H) × floor_work ÷ max_header_work)

``C`` is what one forged confirmation costs, in photons: a server lying about the funding can serve
the real headers below the funding height and has to MINE only the headers from there up, each at
the floor or above (see :mod:`pyrxd.glyph.mark_block`, "WHAT THAT COSTS A LIAR"). Mining a
floor-work header costs the fraction ``floor_work ÷ real_work`` of a real block, whose reward is the
subsidy — so ``C`` prices it at the subsidy scaled by that fraction. Every input is pyrxd's own or
proved here, never a server's figure:

* ``subsidy(H)`` — Radiant Core's ``GetBlockSubsidy``: ``50000 * COIN >> (H /
  nSubsidyHalvingInterval)``, zero from 64 halvings (``tests/vendor/radiant_core/validation.cpp``
  lines 1108-1119), with ``nSubsidyHalvingInterval`` 210,000 on mainnet and 150 on regtest
  (``tests/vendor/radiant_core/chainparams.cpp`` lines 96 and 447). Both files are vendored verbatim
  at the pinned tag and a test re-derives these constants from them.
* ``floor_work`` — the newest shipped checkpoint's header work ÷ 16, the floor the verifier enforces.
* ``max_header_work`` — the MOST work any header carries, over every header the verifier checked
  in this run AND the whole last checkpoint interval (linked between the two newest shipped
  checkpoints). The maximum, because a higher real work makes the floor a smaller fraction of a real
  block, i.e. a cheaper forgery and a smaller ``C``; including the checkpoint interval keeps a server
  from lowering it by serving only easy headers above the checkpoint.

``burial`` is the swap's existing Radiant reorg burial (the policy's measured claim burial, raised by
the value-scaled burial of :func:`pyrxd.gravity.swap_coordinator._value_scaled_burial_blocks`), and
``value_at_stake`` is the swap's value in photons as the coordinator already assesses it. On a
value-bearing network a missing value, or a ``C`` of zero, refuses: there is nothing to size ``k``
from. On a test network (regtest) there is no value to protect, so ``k`` is the configured depth —
but the proof is the same one: the same linkage, proof-of-work and merkle code, anchored to the
network's genesis, which is its only checkpoint.

FRESHNESS. The walk from the newest checkpoint is capped at :data:`MAX_HEADERS_FROM_CHECKPOINT_SDK`
(20,160 headers) here, against the pages' 4,032 (maintainer decision, 2026-09-30). When ``H + k - 1``
lies past it, the refusal says to upgrade pyrxd (newer checkpoints) or verify against the taker's
own node — never to proceed.

THE UPPER BOUND ON ELAPSED DEPTH. SPV proves a LOWER bound on how deep the funding is. The timelock
gates that follow (``pre_btc_lock_check`` steps 6 and 7) need an UPPER bound, because ``t_rxd`` is a
CSV counted from the covenant's mining and an under-counted depth makes the maker's refund look
further away than it is. A server can under-count by serving fewer headers than exist. The bound
used is::

    max(proved, (R - H + 1) + blocks_upper(E), reported)
    E = max(0, now - MTP(R))
    blocks_upper(E) = the smallest n with P(Poisson(λ·E) > n) <= ε,   λ = surge_factor ÷ spacing

* ``R`` is the REFERENCE header: the one ``max(1, value_term)`` deep below the newest header served
  (the newest counting as 1). The blocks from the funding up to ``R`` are proved.
* ``MTP(R)`` is the reference time: the MEDIAN TIME PAST at ``R`` — the median of the timestamps of
  the :data:`MEDIAN_TIME_SPAN` (11) headers ending at ``R``, exactly as Radiant Core's
  ``CBlockIndex::GetMedianTimePast`` computes it (``tests/vendor/radiant_core/chain.h`` lines
  195-209; consensus requires each block's time to exceed it, ``validation.cpp`` line 3930). All 11
  headers are ones this gate has verified: ``R`` is linked to a checkpoint (and, above the newest
  checkpoint, proof-of-work checked), and each header below it in the window is linked to ``R`` by
  its hash.
* ``blocks_upper(E)`` counts the blocks after ``R`` statistically: blocks arrive as a Poisson
  process, and at a rate of ``surge_factor`` times the nominal (``nPowTargetSpacing``, 300 s,
  ``chainparams.cpp`` line 117) the number in ``E`` seconds exceeds ``blocks_upper(E)`` with
  probability at most ``ε`` (:func:`poisson_upper_quantile`, computed conservatively).
  ``ε = clamp(loss_budget ÷ value_at_stake, 1e-12, 1e-3)``: the confidence scales with the value,
  so the expected cost of an honest over-run stays at or below about the loss budget (1 RXD by
  default). The defaults are policy (:class:`ElapsedBoundPolicy`), listed for maintainer sign-off.
* ``reported`` is the largest depth any configured source reports for the funding — its verbose
  ``confirmations`` or ``tip - H + 1`` — grouped by operator (:func:`pyrxd.network.source_identity.source_key`).
  A report can only RAISE the bound; a source reporting less never lowers it. ABOVE DUST on a
  value-bearing network (a value at stake over ``ElapsedBoundPolicy.dust_threshold_photons``,
  1,000 RXD by default) the gate REFUSES unless at least :data:`MIN_REPORTING_OPERATORS` (two)
  distinct operators report a depth for the funding — a source that cannot say which operator runs
  it is not counted — and the refusal names how many answered and which. The coordinator refuses
  at construction, before anyone locks, a configuration with fewer operator groups than that. At
  or below dust one operator suffices: with one operator configured, the time term is what stands
  against a source that stops serving early, and the result says so. The user may move that
  threshold explicitly (``ElapsedBoundPolicy.accept_single_operator_up_to_photons``); raised, the
  gate logs a WARNING, and the result and the durable swap record state the override.

The result names the term that set the bound (``bound_term``). A server that stops serving at an
older header hands the taker an older ``MTP(R)`` and a larger ``E``: fewer headers served shows up as
elapsed time.

WHY THE MEDIAN. It is the time Radiant Core itself orders blocks by, and one header's timestamp moves
it by at most one position in the sorted window: on a chain at the nominal spacing, one block
interval. No lag term is added: on such a chain ``MTP(R)`` is the time of the block five below
``R``, so ``E`` already counts about five intervals more than have passed since ``R`` was mined.

WHY THAT DEPTH. The reference is taken deep enough that changing any header in its window costs as
much as the rule already demands of the depth: a different header at or below ``R`` means different
headers above it too, each mined at the floor or above, which prices it at ``value_term × C ≥ 2 ×
value at stake`` — the value term of ``k``. Deeper would charge every honest swap the time of more
blocks without raising that price past what ``k`` already settles. ``value_term <= k <= proved``, so
``R`` is never below the funding block. A test network has no value term, and ``R`` is the newest
header served.

The clock is the caller's (``now_unix_s``); the coordinator never reads one. It is REQUIRED on a
value-bearing network; on a test network without it the time term is omitted and the result says so.

THE NEGOTIATION-TIME CHECK. :func:`early_elapsed_blocks_upper` models the same bound for the
coordinator before anyone locks (``SwapCoordinator._funding_proof_room_failure``), and is built to be
AT LEAST AS LARGE as what step 6 computes on an honest chain, so that a swap it accepts is not
refused after the maker locks: it takes ``C`` no larger than the gate can compute (the shipped last
checkpoint interval's work, ``LAST_INTERVAL_MAX_WORK``, times ``early_work_margin`` for harder
headers served above the newest checkpoint; the lowest subsidy the walk cap allows), the largest
``k`` and value term that follow, a chain at the nominal spacing, and a newest header up to
``early_slack_s`` old. What it does not cover is stated on that function.

PER CORRIDOR, what bounds a faster-than-nominal chain before the taker locks. In the BTC corridor
it is this bound alone: the time term at ``surge_factor`` times the nominal rate, and, above dust,
the depth reports of two distinct operators. The BTC ordering check (step 7,
``swap_coordinator.assert_timelock_margin``) projects the rest of ``t_rxd`` at the nominal interval
and step 6 reserves no counter-leg blocks; the measured fast tail reaches BTC only at claim time
(``assess_claim_finality``). In the ETH/ERC-20 corridor step 7 also projects the rest of ``t_rxd``
at the measured fast tail (``eth_rxd_timelock``), and step 6 reserves the finalization window in
fast-tail blocks.

WHAT REMAINS THE SERVER'S WORD, stated rather than implied:

* that the covenant output is still UNSPENT. SPV proves a transaction was mined, never that an
  output has not been spent since; the ``listunspent`` read that locates the outpoint is kept for
  that, and is no longer the evidence of the output's existence, script or value.
* the elapsed-depth bound is a statistical upper bound at confidence ``1 - ε`` for block rates up to
  ``surge_factor`` times the nominal, measured from the median time past at ``R``; it is not a proof.
* which chain is Radiant's most-work chain, and whether each nBits is the value Radiant's
  difficulty rules require: neither is checked (see :mod:`pyrxd.glyph.mark_block`); the floor and
  ``k`` bound what a forgery costs instead.
* the checkpoint table itself is only as good as its sources (see
  :mod:`pyrxd.spv.radiant_checkpoints`).
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.eth_wallet.chains import KNOWN_EVM_CHAINS
from pyrxd.glyph.mark_block import (
    FLOOR_WORK_DIVISOR,
    MAX_HEADERS_PER_REQUEST,
    VERIFIED,
    plan_block_verification,
    verify_mark_block,
)
from pyrxd.glyph.wave_rules import format_rxd
from pyrxd.gravity.reorg_cost import PHOTONS_PER_RXD
from pyrxd.hash import hash256, radiant_block_hash
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import BlockHeight
from pyrxd.spv.radiant import radiant_header_prev_hash, radiant_header_work
from pyrxd.spv.radiant_checkpoints import CHECKPOINTS, LAST_INTERVAL_MAX_WORK, NEWEST_CHECKPOINT_WORK
from pyrxd.transaction.transaction import Transaction

logger = logging.getLogger(__name__)

__all__ = [
    "FORGERY_COST_FACTOR",
    "LOCAL_DEVNET_CHAIN_IDS",
    "MAX_HEADERS_FROM_CHECKPOINT_SDK",
    "MEDIAN_TIME_SPAN",
    "MIN_FUNDING_CONFIRMATIONS",
    "MIN_REPORTING_OPERATORS",
    "UNIDENTIFIED_SOURCE_PREFIX",
    "EarlyElapsedBound",
    "ElapsedBoundPolicy",
    "MakerFundingEvidence",
    "MakerFundingNotVerified",
    "RadiantChain",
    "VerifiedMakerFunding",
    "block_subsidy_photons",
    "counted_operators",
    "early_elapsed_blocks_upper",
    "elapsed_blocks_upper_bound",
    "forged_confirmation_cost_floor_photons",
    "funding_header_ranges",
    "median_time_past",
    "poisson_upper_quantile",
    "radiant_chain_for_leg",
    "required_funding_confirmations",
    "verify_maker_funding",
]

# ── PARAMETERS — maintainer decisions for phase 2b, 2026-09-30. ─────────────────────────────────
# Each changes what the taker gate accepts; a change needs the maintainer's sign-off and a
# CHANGELOG entry.

#: The fewest confirmations a value-bearing funding is accepted at, whatever the value.
MIN_FUNDING_CONFIRMATIONS = 6

#: ``k`` makes forging the funding cost at least this multiple of the value at stake.
FORGERY_COST_FACTOR = 2

#: Above the dust threshold (:attr:`ElapsedBoundPolicy.dust_threshold_photons`) on a value-bearing
#: network, the fewest DISTINCT OPERATORS — operator groups, by
#: :func:`pyrxd.network.source_identity.source_key` — that must report a depth for the funding.
MIN_REPORTING_OPERATORS = 2

#: The prefix of the label a depth report carries when its source cannot say which operator runs it
#: (no ``source_key``). Such a report can still raise the bound, but it is never counted as an
#: operator.
UNIDENTIFIED_SOURCE_PREFIX = "unidentified source"

#: The most headers linked above the newest checkpoint by this gate (ten checkpoint intervals).
#: The browser pages and ``pyrxd verify`` keep :data:`pyrxd.glyph.mark_block.MAX_HEADERS_FROM_CHECKPOINT`.
MAX_HEADERS_FROM_CHECKPOINT_SDK = 20_160

# ─────────────────────────────────────────────────────────────────────────────────────────────

#: Radiant Core's ``CBlockIndex::nMedianTimeSpan`` (``tests/vendor/radiant_core/chain.h`` line 195):
#: how many headers, ending at a block, its median time past is taken over. A test re-reads it.
MEDIAN_TIME_SPAN = 11

#: Radiant's nominal block spacing, ``consensus.nPowTargetSpacing`` (``chainparams.cpp`` line 117,
#: ``5 * 60``, the same on every network), in seconds. A test re-reads it.
TARGET_BLOCK_SPACING_S = 5 * 60

#: ``GetBlockSubsidy``'s starting reward, ``50000 * COIN`` (``tests/vendor/radiant_core/validation.cpp``
#: line 1115), in photons.
INITIAL_SUBSIDY_PHOTONS = 50_000 * PHOTONS_PER_RXD

#: How far below the true quantile's threshold :func:`poisson_upper_quantile` requires its computed
#: log-tail to fall. Its floating-point error is far smaller (measured against a 60-digit tail: under
#: 1e-9 up to a mean of 3e5, 3.3e-8 at the 1e7 limit below); the margin turns it into a result that
#: is never below the exact quantile, and at most one above it.
_QUANTILE_LOG_MARGIN = 1e-6

#: Above this mean the quantile is the closed-form Bernstein bound (never below the exact quantile)
#: instead of a summation.
_QUANTILE_EXACT_LIMIT = 1e7


class MakerFundingNotVerified(ValidationError):
    """The maker's Radiant funding could not be proved to the depth this swap requires.

    A :class:`~pyrxd.security.errors.ValidationError`, so every existing fail-closed handler on the
    lock path refuses on it. The message names what was required and what was proved.
    """


@dataclass(frozen=True)
class ElapsedBoundPolicy:
    """The policy inputs of the elapsed-depth upper bound — defaults for maintainer sign-off.

    * ``surge_factor`` — the block rate the bound allows for, as a multiple of the nominal spacing:
      ``λ = surge_factor ÷ nPowTargetSpacing``. Default 3.0: a backtest of this bound over every
      mainnet header from height 14,088 to 468,799 (every reference height, up to 3,000 blocks after
      it, at ``ε`` 1e-3 and 1e-12) found no block count it fell short of; at 2.0 it fell short in a
      sustained run of fast blocks near height 98,705. The heights below 14,088 are the chain's
      launch, when blocks ran far faster than nominal while difficulty caught up.
    * ``loss_budget_photons``, ``epsilon_min``, ``epsilon_max`` — the confidence:
      ``ε = clamp(loss_budget ÷ value_at_stake, epsilon_min, epsilon_max)``, so an honest swap's
      expected over-run cost is at most about the budget. Defaults 1 RXD, 1e-12, 1e-3. With no value
      (a test network) ``ε`` is ``epsilon_max``.
    * ``early_slack_s`` — the negotiation-time check only: how old the newest header may be when the
      taker reaches step 6, in seconds (the gap between the covenant reaching ``k`` and the taker
      locking). Default 3600. The at-lock check uses the actual clock instead.
    * ``early_work_margin`` — the negotiation-time check only: how much more work than the shipped
      last checkpoint interval's hardest header a header served above the newest checkpoint may
      carry before that check stops being at least as strict as step 6. Default 2.0.
    * ``dust_threshold_photons`` — above this value at stake, on a value-bearing network, the
      funding's depth must be reported by at least :data:`MIN_REPORTING_OPERATORS` distinct
      operators, or the gate refuses; at or below it one operator suffices and the time term may
      govern the bound. Default 1,000 RXD.
    * ``accept_single_operator_up_to_photons`` — an explicit USER OVERRIDE of that threshold: the
      value at stake up to which the gate accepts a depth reported by a single operator. ``None``
      (the default) uses ``dust_threshold_photons``. It may raise or lower the threshold; there is no
      cap. Raised, the swap relies on that one operator for the funding's depth: the gate logs a
      WARNING naming the value, and the result (``single_operator_override``, ``bound_note``) and the
      durable swap record carry :meth:`single_operator_override_statement`. Lowered, it is recorded
      the same way, without the warning. The swap scripts set it with
      ``--accept-single-operator-up-to RXD``; nothing sets it from the environment.
    """

    surge_factor: float = 3.0
    loss_budget_photons: int = PHOTONS_PER_RXD
    epsilon_min: float = 1e-12
    epsilon_max: float = 1e-3
    early_slack_s: int = 3600
    early_work_margin: float = 2.0
    dust_threshold_photons: int = 1_000 * PHOTONS_PER_RXD
    accept_single_operator_up_to_photons: int | None = None

    def __post_init__(self) -> None:
        def num(v: Any) -> bool:
            return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)

        if not num(self.surge_factor) or self.surge_factor < 1:
            raise ValidationError("ElapsedBoundPolicy.surge_factor must be a finite number >= 1")
        lb = self.loss_budget_photons
        if not isinstance(lb, int) or isinstance(lb, bool) or lb <= 0:
            raise ValidationError("ElapsedBoundPolicy.loss_budget_photons must be a positive int")
        if not (num(self.epsilon_min) and num(self.epsilon_max) and 0 < self.epsilon_min <= self.epsilon_max < 0.5):
            raise ValidationError("ElapsedBoundPolicy needs 0 < epsilon_min <= epsilon_max < 0.5")
        es = self.early_slack_s
        if not isinstance(es, int) or isinstance(es, bool) or es < 0:
            raise ValidationError("ElapsedBoundPolicy.early_slack_s must be a non-negative int")
        if not num(self.early_work_margin) or self.early_work_margin < 1:
            raise ValidationError("ElapsedBoundPolicy.early_work_margin must be a finite number >= 1")
        dt = self.dust_threshold_photons
        if not isinstance(dt, int) or isinstance(dt, bool) or dt < 0:
            raise ValidationError("ElapsedBoundPolicy.dust_threshold_photons must be a non-negative int")
        ov = self.accept_single_operator_up_to_photons
        if ov is not None and (not isinstance(ov, int) or isinstance(ov, bool) or ov < 0):
            raise ValidationError(
                "ElapsedBoundPolicy.accept_single_operator_up_to_photons must be None or a non-negative int "
                f"(photons), not {ov!r}"
            )

    @property
    def single_operator_threshold_photons(self) -> int:
        """The value at stake up to which one operator's depth report suffices: the user override
        when set, else ``dust_threshold_photons``."""
        ov = self.accept_single_operator_up_to_photons
        return self.dust_threshold_photons if ov is None else ov

    @property
    def single_operator_threshold_raised(self) -> bool:
        """True when the user override raises the threshold above ``dust_threshold_photons``."""
        return self.single_operator_threshold_photons > self.dust_threshold_photons

    def single_operator_override_statement(self) -> str | None:
        """The sentence the gate's result and the durable swap record carry when the user override is
        set, or ``None`` when it is not."""
        if self.accept_single_operator_up_to_photons is None:
            return None
        return (
            f"single-operator depth accepted up to {format_rxd(self.single_operator_threshold_photons)} "
            f"by user override (default {format_rxd(self.dust_threshold_photons)})"
        )

    def single_operator_refusal_hint(self) -> str:
        """What a two-operator refusal says about the override: how to set it and what it gives up."""
        now = self.single_operator_override_statement()
        return (
            "; or set accept_single_operator_up_to_photons on ElapsedBoundPolicy (the swap scripts' "
            "--accept-single-operator-up-to RXD) to at least the value at stake to accept one operator's report "
            "for this value (you then rely on that one operator for the funding's depth)"
            + (f"; currently {now}" if now else "")
        )

    def requires_operators(self, chain: RadiantChain, value_at_stake_photons: int | None) -> int:
        """How many distinct operators must report the funding's depth for a swap of this value on
        *chain*: :data:`MIN_REPORTING_OPERATORS` on a value-bearing network above
        :attr:`single_operator_threshold_photons` (``dust_threshold_photons`` unless the user override
        is set), else 0."""
        if (
            chain.value_bearing
            and value_at_stake_photons is not None
            and value_at_stake_photons > self.single_operator_threshold_photons
        ):
            return MIN_REPORTING_OPERATORS
        return 0

    def epsilon(self, value_at_stake_photons: int | None) -> float:
        """``ε`` for a swap of this value: ``clamp(loss_budget ÷ value, epsilon_min, epsilon_max)``."""
        if value_at_stake_photons is None or value_at_stake_photons <= 0:
            return self.epsilon_max
        return min(self.epsilon_max, max(self.epsilon_min, self.loss_budget_photons / value_at_stake_photons))

    def blocks_upper(self, elapsed_s: int, *, spacing_s: int, value_at_stake_photons: int | None) -> int:
        """``blocks_upper(E)``: the statistical upper bound on blocks mined in *elapsed_s* seconds."""
        if not isinstance(elapsed_s, int) or isinstance(elapsed_s, bool) or elapsed_s < 0:
            raise ValidationError("elapsed_s must be a non-negative int")
        mean = float(self.surge_factor) * elapsed_s / float(spacing_s)
        return poisson_upper_quantile(mean, self.epsilon(value_at_stake_photons))


#: The defaults, as listed for maintainer sign-off.
DEFAULT_ELAPSED_BOUND_POLICY = ElapsedBoundPolicy()


def _log_poisson_tail(mean: float, n: int) -> float:
    """``log P(X > n)`` for ``X ~ Poisson(mean)``, ``mean > 0``, ``n >= -1``.

    Sums the pmf from ``n + 1`` upward in scaled form (each term the previous times ``mean ÷ j``),
    starting from ``log pmf(n + 1)`` by ``lgamma``; once the terms are decreasing and below 1e-17 of
    the sum, the rest is bounded above by a geometric series and added. That remainder is below
    double precision: measured against a 60-digit tail, it moves the result by at most 4e-15 (at a
    mean of 1e7), while the result's own floating-point error reaches 3.3e-8 there (from ``lgamma``
    and ``j · log(mean)`` at that size). So the result can be BELOW the true log-tail by that error,
    and it is the caller's :data:`_QUANTILE_LOG_MARGIN` (1e-6) that makes the quantile conservative;
    a test pins that the error stays far inside it.
    """
    j = n + 1
    log_first = -mean + j * math.log(mean) - math.lgamma(j + 1)
    total = 1.0
    term = 1.0
    i = j
    while True:
        i += 1
        term *= mean / i
        total += term
        ratio = mean / (i + 1)
        if ratio < 1.0 and term <= total * 1e-17:
            total += term * ratio / (1.0 - ratio)
            break
    return log_first + math.log(total)


def poisson_upper_quantile(mean: float, epsilon: float) -> int:
    """The smallest ``n`` with ``P(Poisson(mean) > n) <= epsilon`` — never below the exact value.

    Exact up to floating-point error for ``mean`` up to :data:`_QUANTILE_EXACT_LIMIT` (a bisection on
    :func:`_log_poisson_tail`, accepting ``n`` only when the computed log-tail is at least
    :data:`_QUANTILE_LOG_MARGIN` below ``log epsilon``): the result is the exact quantile or one more.
    Above that limit it is the Bernstein bound ``ceil(mean + t)``, ``t = L/3 + sqrt(L²/9 + 2·L·mean)``,
    ``L = -log epsilon``, which is never below the exact quantile. A test compares both against an
    independent 60-digit summation over a grid of means and ``epsilon`` values.
    """
    if not (isinstance(mean, (int, float)) and not isinstance(mean, bool) and math.isfinite(mean) and mean >= 0):
        raise ValidationError("mean must be a finite number >= 0")
    if not (isinstance(epsilon, float) and 0 < epsilon < 1):
        raise ValidationError("epsilon must be a float in (0, 1)")
    if mean == 0:
        return 0
    big_l = -math.log(epsilon)
    hi = math.ceil(mean + big_l / 3 + math.sqrt(big_l * big_l / 9 + 2 * big_l * mean))
    if mean > _QUANTILE_EXACT_LIMIT:
        return hi
    target = math.log(epsilon) - _QUANTILE_LOG_MARGIN
    # Invariant: tail(lo) is above the target (lo = -1: the whole distribution); tail(hi) is not.
    lo = -1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if _log_poisson_tail(float(mean), mid) <= target:
            hi = mid
        else:
            lo = mid
    return hi


def median_time_past(times: Sequence[int]) -> int:
    """Radiant Core's ``GetMedianTimePast`` over *times*, the timestamps of up to
    :data:`MEDIAN_TIME_SPAN` consecutive headers: sort them and take the element at index
    ``len // 2`` (``chain.h`` lines 197-209)."""
    if not times or len(times) > MEDIAN_TIME_SPAN:
        raise ValidationError(f"median time past needs 1..{MEDIAN_TIME_SPAN} timestamps")
    ordered = sorted(int(t) for t in times)
    return ordered[len(ordered) // 2]


@dataclass(frozen=True)
class RadiantChain:
    """The consensus facts the gate needs for one Radiant network, all from the vendored sources."""

    name: str
    #: ``((height, block hash display hex), ...)`` ascending — the anchors headers are linked to.
    checkpoints: tuple[tuple[int, str], ...]
    #: ``consensus.powLimit``.
    pow_limit: int
    #: ``consensus.nSubsidyHalvingInterval``.
    subsidy_halving_interval: int
    #: Whether a swap on it moves real value (then the value term and the clock are required).
    value_bearing: bool
    #: ``consensus.nPowTargetSpacing``, seconds.
    target_spacing_s: int = TARGET_BLOCK_SPACING_S
    #: The most header work between the two newest checkpoints (both included), as shipped with the
    #: table (:data:`pyrxd.spv.radiant_checkpoints.LAST_INTERVAL_MAX_WORK`); ``None`` where none is
    #: shipped. The negotiation-time check prices ``C`` from it.
    last_interval_max_work: int | None = None
    #: The newest checkpoint header's own work, as shipped; ``None`` where none is shipped.
    newest_checkpoint_work: int | None = None


#: Radiant mainnet: the shipped checkpoint table and the last interval's work shipped with it;
#: ``powLimit`` ``00000000ff…ff`` and halving interval 210,000
#: (``tests/vendor/radiant_core/chainparams.cpp`` lines 113-114 and 96).
MAINNET_CHAIN = RadiantChain(
    name="mainnet",
    checkpoints=CHECKPOINTS["mainnet"],
    pow_limit=(1 << 224) - 1,
    subsidy_halving_interval=210_000,
    value_bearing=True,
    last_interval_max_work=LAST_INTERVAL_MAX_WORK["mainnet"],
    newest_checkpoint_work=NEWEST_CHECKPOINT_WORK["mainnet"],
)

#: Radiant regtest: no shipped table, so its genesis (``chainparams.cpp`` line 509, and
#: :data:`pyrxd.constants.GENESIS_BLOCK_HASHES`) is the one checkpoint; ``powLimit`` ``7fff…ff`` and
#: halving interval 150 (lines 465-466 and 447).
REGTEST_CHAIN = RadiantChain(
    name="regtest",
    checkpoints=((0, GENESIS_BLOCK_HASHES["regtest"]),),
    pow_limit=(1 << 255) - 1,
    subsidy_halving_interval=150,
    value_bearing=False,
)

_REGTEST_TAGS = frozenset({"bcrt", "regtest"})

#: EIP-155 chain ids of local development chains, which hold nothing: anvil's and hardhat's default.
LOCAL_DEVNET_CHAIN_IDS = frozenset({31337})

_EVM_TESTNET_CHAIN_IDS = frozenset(c.chain_id for c in KNOWN_EVM_CHAINS.values() if c.is_testnet)


def _counter_leg_value(leg: Any) -> str | None:
    """What makes the counter leg value-bearing, as a phrase for a refusal — or ``None`` if nothing.

    An EVM leg (one exposing an int ``chain_id``) is judged by the chain it signs for: value-bearing
    unless that is a testnet in :data:`~pyrxd.eth_wallet.chains.KNOWN_EVM_CHAINS` or a local
    development chain (:data:`LOCAL_DEVNET_CHAIN_IDS`). Its ``network`` tag cannot answer this — every
    EVM tag reads as uncleared (see :mod:`pyrxd.eth_wallet.chains`) — while EIP-155 makes a
    signature for one chain id invalid on every other. An unknown chain id counts as value-bearing.
    Any other leg is judged by the tag partition
    :func:`pyrxd.gravity.swap_coordinator._leg_is_value_bearing` draws; a leg with neither is a test
    fake.
    """
    chain_id = getattr(leg, "chain_id", None)
    if isinstance(chain_id, int) and not isinstance(chain_id, bool):
        if chain_id in LOCAL_DEVNET_CHAIN_IDS or chain_id in _EVM_TESTNET_CHAIN_IDS:
            return None
        return f"EVM chain id {chain_id}"
    net = getattr(leg, "network", None)
    if isinstance(net, str) and net and net not in AUDIT_CLEARED_NETWORKS:
        return f"network {net!r}"
    return None


def radiant_chain_for_leg(leg: Any, *, counter_leg: Any) -> RadiantChain:
    """The Radiant network the maker's funding is proved on, for a swap with these two legs.

    The Radiant leg's ``network`` tag, by the partition
    :func:`pyrxd.gravity.swap_coordinator._leg_is_value_bearing` draws: a non-empty tag outside
    :data:`~pyrxd.btc_wallet.htlc_leg.AUDIT_CLEARED_NETWORKS` moves real value, and is Radiant
    mainnet — there is no other value-bearing Radiant network. The regtest tags (and a leg with no
    tag, which is a test fake) are regtest; any other cleared tag has no chain parameters in pyrxd,
    and refuses.

    The COUNTER leg decides too, because it is what the taker is about to lock. When it moves real
    value (:func:`_counter_leg_value`) and the Radiant leg names a test network, this REFUSES: the
    proof would be anchored to regtest's genesis with no value term. So no tag on either leg selects
    a weaker check than mainnet's for a swap in which real value is locked.
    """
    net = getattr(leg, "network", None)
    if isinstance(net, str) and net and net not in AUDIT_CLEARED_NETWORKS:
        return MAINNET_CHAIN
    if isinstance(net, str) and net and net not in _REGTEST_TAGS:
        raise MakerFundingNotVerified(
            f"pyrxd has no Radiant chain parameters for the test network tag {net!r}, so the maker's "
            "funding cannot be proved there; use a regtest ('bcrt') or mainnet leg"
        )
    counter_value = _counter_leg_value(counter_leg)
    if counter_value is not None:
        tagged = f"tagged {net!r}" if isinstance(net, str) and net else "untagged"
        raise MakerFundingNotVerified(
            f"the counter leg moves real value ({counter_value}) but the Radiant leg is {tagged}, "
            "a test network: the maker's funding "
            "would be proved against a test chain, which proves nothing about value. Tag the Radiant leg "
            "for mainnet, or run both legs on test networks"
        )
    return REGTEST_CHAIN


def block_subsidy_photons(height: int, chain: RadiantChain) -> int:
    """``GetBlockSubsidy(height)`` in photons (``validation.cpp`` lines 1108-1119)."""
    if not isinstance(height, int) or isinstance(height, bool) or height < 0:
        raise ValidationError("height must be a non-negative int")
    halvings = height // chain.subsidy_halving_interval
    if halvings >= 64:
        return 0
    return INITIAL_SUBSIDY_PHOTONS >> halvings


def _shipped_work(chain: RadiantChain) -> tuple[int, int]:
    if chain.last_interval_max_work is None or chain.newest_checkpoint_work is None:
        raise MakerFundingNotVerified(
            f"pyrxd ships no last-checkpoint-interval work for Radiant {chain.name}, so the cost of a forged "
            "confirmation cannot be bounded before the chain is read"
        )
    return int(chain.last_interval_max_work), int(chain.newest_checkpoint_work)


def forged_confirmation_cost_floor_photons(
    chain: RadiantChain,
    policy: ElapsedBoundPolicy = DEFAULT_ELAPSED_BOUND_POLICY,
    *,
    cap: int = MAX_HEADERS_FROM_CHECKPOINT_SDK,
) -> int:
    """The LEAST ``C`` :func:`verify_maker_funding` can compute for a funding made from now on, from
    the SHIPPED table alone — for the negotiation-time check, which runs before any header exists.

    ``subsidy(newest checkpoint + cap) × floor_work ÷ ceil(early_work_margin × LAST_INTERVAL_MAX_WORK)``.
    Each factor is on the conservative side of the gate's own: the funding height is at most
    ``cap`` above the newest checkpoint (the gate refuses beyond it) and the subsidy never rises with
    height; ``floor_work`` is the same shipped checkpoint work ÷ 16; and the gate's
    ``max_header_work`` is the last interval's maximum — shipped exactly — or a header served above
    the newest checkpoint, which this assumes carries at most ``early_work_margin`` times that. A
    served header harder than that makes the gate's ``C`` smaller than this; see
    :func:`early_elapsed_blocks_upper` for what that leaves uncovered.
    """
    last_max, cp_work = _shipped_work(chain)
    newest_h = chain.checkpoints[-1][0]
    subsidy = block_subsidy_photons(newest_h + cap, chain)
    worst = math.ceil(Fraction(policy.early_work_margin) * last_max)
    return subsidy * (cp_work // FLOOR_WORK_DIVISOR) // worst


def required_funding_confirmations(
    *,
    value_bearing: bool,
    burial_blocks: int,
    value_at_stake_photons: int | None,
    forged_confirmation_cost_photons: int | None,
) -> tuple[int, int]:
    """``(k, value_term)`` — the settled rule. Raises :class:`MakerFundingNotVerified` when a
    value-bearing swap gives nothing to size ``k`` from."""
    if not isinstance(burial_blocks, int) or isinstance(burial_blocks, bool) or burial_blocks < 0:
        raise ValidationError("burial_blocks must be a non-negative int")
    if not value_bearing:
        return max(1, burial_blocks), 0
    if value_at_stake_photons is None or value_at_stake_photons <= 0:
        raise MakerFundingNotVerified(
            "no value at stake is available for this swap, so the confirmations that make forging "
            "the maker's funding cost more than it can win cannot be sized; set "
            "MarginPolicy.value_at_risk_photons to the swap's value in photons"
        )
    cost = forged_confirmation_cost_photons
    if cost is None or cost <= 0:
        raise MakerFundingNotVerified(
            f"one forged confirmation of the maker's funding prices at {cost} photons at this height, so "
            "no confirmation count makes forging it cost more than the value at stake"
        )
    value_term = -((-FORGERY_COST_FACTOR * value_at_stake_photons) // cost)
    return max(MIN_FUNDING_CONFIRMATIONS, burial_blocks, value_term), value_term


#: The bound's terms, in the order a tie is attributed.
_TERMS = ("time", "reported", "proved")


def elapsed_blocks_upper_bound(
    *,
    proved: int,
    through_reference: int,
    time_blocks: int | None,
    reported: int | None = None,
) -> tuple[int, str]:
    """THE upper bound on blocks since the funding (module docstring), and which term set it —
    ``(max(proved, through_reference + time_blocks, reported), "time" | "reported" | "proved")``.

    *through_reference* is ``R - H + 1`` (the proved blocks up to the reference header) and
    *time_blocks* ``blocks_upper(E)``; ``None`` for a term that is absent (no clock on a test
    network, no report). Used by :func:`verify_maker_funding` and, through
    :func:`early_elapsed_blocks_upper`, by the coordinator's negotiation-time check.
    """
    values = {
        "time": None if time_blocks is None else through_reference + time_blocks,
        "reported": reported,
        "proved": proved,
    }
    best = max(v for v in values.values() if v is not None)
    return best, next(t for t in _TERMS if values[t] == best)


def _quantile_scan(mean: float, epsilon: float, start: int) -> int:
    """:func:`poisson_upper_quantile`, scanning up from *start* — a value known not to exceed it
    (the quantile of a smaller mean at the same ``epsilon``). Never below the bisection's answer."""
    if mean == 0:
        return 0
    target = math.log(epsilon) - _QUANTILE_LOG_MARGIN
    if mean > _QUANTILE_EXACT_LIMIT:
        return poisson_upper_quantile(mean, epsilon)
    n = max(0, start)
    while _log_poisson_tail(float(mean), n) > target:
        n += 1
    return n


@dataclass(frozen=True)
class EarlyElapsedBound:
    """What the negotiation-time check models for step 6, and the inputs it took."""

    #: The largest ``k`` and value term the gate can require (with ``C`` at its floor).
    required_confirmations: int
    value_term: int
    #: :func:`forged_confirmation_cost_floor_photons`.
    cost_floor_photons: int
    burial_blocks: int
    epsilon: float
    #: The bound modelled for step 6 — at least what step 6 computes on an honest chain (see
    #: :func:`early_elapsed_blocks_upper`).
    elapsed_blocks_upper: int
    #: The reference depth, and the ``E`` in seconds, at which that maximum was reached.
    reference_depth: int
    elapsed_s: int


def early_elapsed_blocks_upper(
    *,
    chain: RadiantChain,
    value_at_stake_photons: int | None,
    burial_blocks: int,
    policy: ElapsedBoundPolicy = DEFAULT_ELAPSED_BOUND_POLICY,
    cap: int = MAX_HEADERS_FROM_CHECKPOINT_SDK,
) -> EarlyElapsedBound:
    """The elapsed-depth bound step 6 will judge, modelled BEFORE ANYONE LOCKS — at least as large as
    what :func:`verify_maker_funding` computes on an honest chain, so a swap whose ``t_rxd`` holds
    this is not refused at step 6 after the maker's covenant is on chain.

    The model of "an honest chain": blocks at the nominal spacing, the funding proved exactly ``k``
    deep, and the newest header at most ``early_slack_s`` old when step 6 runs. Then with a value
    term ``v`` and ``d = max(1, v)`` step 6 computes ``max(k, (k - d + 1) + blocks_upper(E(d)))`` with
    ``E(d) = (d - 1 + 5) × spacing + early_slack_s`` at most — ``MTP(R)`` is the time of the block
    five below ``R`` (the middle of 11), ``R`` is ``d - 1`` blocks below the newest header. (If more
    blocks have arrived by then, each adds one to the proved part and moves ``R``, and so ``MTP(R)``,
    one block later — about one spacing off ``E``, which the time term counts at ``surge_factor``
    blocks per spacing.) ``v`` is not known
    here: the gate's ``C`` lies between :func:`forged_confirmation_cost_floor_photons` and the
    shipped last interval's own price, so this takes the MAXIMUM of that expression over every value
    term the two allow, with ``k = max(6, burial, v)`` as the gate computes it.

    NOT COVERED, stated: a header served above the newest checkpoint carrying more than
    ``early_work_margin`` times the shipped last interval's hardest (the gate's ``C`` then falls below
    the floor used here, and its ``k`` and bound grow in proportion); a funding mined below the
    newest checkpoint (a covenant for terms agreed now is mined above it); and a chain whose blocks
    come slower than the nominal spacing by more than ``early_slack_s`` absorbs. In each case step 6
    still decides, on the proved bound, before the taker locks.

    HOW OFTEN THE SLOW-CHAIN CASE OCCURRED, measured 2026-09-30 at the defaults (``surge_factor``
    3.0, ``early_slack_s`` 3600) with burial 6, on every mainnet funding height from 400,000 whose
    ``k``-th block exists (tip 468,799), the taker checking when the funding reaches ``k`` deep, just
    before the next block: this bound was below step 6's in 98 of 68,793 fundings at 100 RXD, 95 of
    68,791 at 1,000 RXD and 106 of 68,721 at 10,000 RXD (none at 100,000 RXD), by at most 376
    blocks. Each was in a stretch where blocks came slower than this model assumes; the range holds
    7 inter-block gaps longer than an hour (the longest 27,752 s). Such a swap is refused at step 6
    after the maker locked, never locked against.
    """
    last_max, cp_work = _shipped_work(chain)
    newest_h = chain.checkpoints[-1][0]
    floor = cp_work // FLOOR_WORK_DIVISOR
    c_lo = forged_confirmation_cost_floor_photons(chain, policy, cap=cap)
    k_hi, v_hi = required_funding_confirmations(
        value_bearing=chain.value_bearing,
        burial_blocks=burial_blocks,
        value_at_stake_photons=value_at_stake_photons,
        forged_confirmation_cost_photons=c_lo,
    )
    c_hi = block_subsidy_photons(newest_h, chain) * floor // last_max
    _, v_lo = required_funding_confirmations(
        value_bearing=chain.value_bearing,
        burial_blocks=burial_blocks,
        value_at_stake_photons=value_at_stake_photons,
        forged_confirmation_cost_photons=max(c_hi, c_lo),
    )
    k0 = max(MIN_FUNDING_CONFIRMATIONS, burial_blocks) if chain.value_bearing else max(1, burial_blocks)
    eps = policy.epsilon(value_at_stake_photons)
    lag = (MEDIAN_TIME_SPAN - 1) // 2
    spacing = int(chain.target_spacing_s)

    def elapsed_s(d: int) -> int:
        return (d - 1 + lag) * spacing + int(policy.early_slack_s)

    def mean(d: int) -> float:
        return float(policy.surge_factor) * elapsed_s(d) / spacing

    best, best_d = k_hi, max(1, v_hi)
    if v_hi > k0:  # k = v = d: the bound 1 + blocks_upper(E(d)) grows with d, so its largest is at v_hi
        cand = 1 + poisson_upper_quantile(mean(v_hi), eps)
        if cand > best:
            best, best_d = cand, v_hi
    q = 0
    for d in range(max(1, v_lo), max(1, min(v_hi, k0)) + 1):  # k = k0 >= d
        q = _quantile_scan(mean(d), eps, q)
        cand = k0 - d + 1 + q
        if cand > best:
            best, best_d = cand, d
    return EarlyElapsedBound(
        required_confirmations=k_hi,
        value_term=v_hi,
        cost_floor_photons=c_lo,
        burial_blocks=burial_blocks,
        epsilon=eps,
        elapsed_blocks_upper=best,
        reference_depth=best_d,
        elapsed_s=elapsed_s(best_d),
    )


def _merged_ranges(spans: Sequence[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    """Inclusive ``(lo, hi)`` spans, merged, as ``(start, count)`` chunks of at most 2016."""
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(spans):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    chunks: list[tuple[int, int]] = []
    for lo, hi in out:
        h = lo
        while h <= hi:
            n = min(MAX_HEADERS_PER_REQUEST, hi - h + 1)
            chunks.append((h, n))
            h += n
    return tuple(chunks)


def funding_header_ranges(
    chain: RadiantChain, height: int, *, cap: int = MAX_HEADERS_FROM_CHECKPOINT_SDK
) -> tuple[tuple[int, int], ...]:
    """The ``(start, count)`` header ranges to fetch to judge a funding at *height* — decided here.

    Three spans, merged: the last checkpoint interval (between the two newest checkpoints, for
    ``max_header_work``); the funding block up to the checkpoint above it, when it is at or below
    the newest one (:func:`~pyrxd.glyph.mark_block.plan_block_verification`'s own range); and the
    newest checkpoint up to ``cap`` headers above it. A server answers FEWER headers past its tip,
    and that is where its chain ends for this gate. Raises :class:`MakerFundingNotVerified` for a
    height nothing fetched could prove.

    A funding at or below the newest checkpoint gets the WHOLE span from its block up to the newest
    checkpoint, when that span is at most ``cap`` headers: the reference header the elapsed-depth
    bound is measured from (:func:`verify_maker_funding`, step 5) can lie anywhere between the
    funding block and the served tip, which the three spans above leave a gap in once the funding
    is two or more checkpoint intervals down. Past ``cap`` the gap is not fetched, and a reference
    header that falls in it refuses there, naming it.

    Every span starts :data:`MEDIAN_TIME_SPAN` ``- 1`` headers lower than it otherwise would, so the
    window the reference header's median time past is taken over is fetched with it.
    """
    table = chain.checkpoints
    newest_h = table[-1][0]
    if not isinstance(height, int) or isinstance(height, bool) or not 0 <= height <= BlockHeight.MAX:
        raise MakerFundingNotVerified(f"the server named no usable funding height ({height!r})")
    top = newest_h + cap
    if height > top:
        raise MakerFundingNotVerified(
            f"the funding is at block {height}, {height - newest_h} blocks past this pyrxd's newest checkpoint "
            f"({newest_h}); this gate links at most {cap} — upgrade pyrxd (newer checkpoints) or verify "
            "against your own node"
        )
    plan = plan_block_verification(
        height=height,
        min_confirmations=top - height + 1,
        checkpoints=table,
        max_headers_from_checkpoint=cap,
    )
    if plan.reason is not None:
        raise MakerFundingNotVerified(f"the funding block cannot be verified: {plan.reason}")
    below = MEDIAN_TIME_SPAN - 1
    spans = [(start, start + count - 1) for start, count in plan.header_ranges]
    spans.append((max(0, height - below), height))
    if height <= newest_h and newest_h - height <= cap:
        spans.append((height, newest_h))
    if len(table) >= 2:
        spans.append((max(0, table[-2][0] - below), newest_h))
    spans.append((newest_h, top))
    return _merged_ranges(spans)


@dataclass(frozen=True)
class MakerFundingEvidence:
    """What the Radiant leg fetched for the coordinator to judge. Nothing here is trusted as given."""

    txid: str
    vout: int
    #: The height the server NAMED for the funding; the proof decides whether it holds.
    height: int
    raw_tx: bytes
    #: ``blockchain.transaction.get_merkle``'s reply (a dict), or a parsed ``TxMerkleBranch``.
    merkle: Any
    #: ``blockchain.transaction.id_from_pos(height, 0, true)``'s reply for the same block.
    coinbase_merkle: Any
    #: ``height -> raw 80-byte header`` for :func:`funding_header_ranges`' ranges, as served.
    headers: Mapping[int, bytes]
    #: ``((source, depth), ...)``: the depth each configured source REPORTS for the funding (its
    #: verbose ``confirmations``, or its tip height minus the funding height plus one), keyed by the
    #: source's operator group. Used to RAISE the elapsed upper bound, never as proof of depth, and
    #: counted by operator for the rule above dust (:data:`MIN_REPORTING_OPERATORS`).
    reported_depths: tuple[tuple[str, int], ...] = ()
    #: The operator groups the leg was configured to ask (whether or not they answered), for a
    #: refusal to name. Not evidence of anything.
    configured_operators: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifiedMakerFunding:
    """A funding proved to the required depth, with every number the decision rested on."""

    outpoint: str
    value_photons: int
    height: int
    blockhash: str
    #: Blocks proved from the funding block (counting it as 1) up to the newest header served.
    proved_depth: int
    #: ``k``: the depth required, and the value term that entered it (0 on a test network).
    required_confirmations: int
    value_term: int
    burial_blocks: int
    value_at_stake_photons: int | None
    #: ``C`` in photons, with its inputs.
    forged_confirmation_cost_photons: int
    subsidy_photons: int
    floor_work: int
    max_header_work: int
    #: The most work in the last checkpoint interval, as linked in this run (``None`` with one
    #: checkpoint). The shipped table records the same number for the negotiation-time check.
    last_interval_max_work: int | None
    #: The conservative UPPER bound on blocks since the funding was mined, for the timelock gates,
    #: and the term that set it: ``"time"``, ``"reported"`` or ``"proved"``.
    elapsed_blocks_upper: int
    bound_term: str
    #: The header the time term is measured from: ``max(1, value_term)`` deep below the served tip
    #: (the tip itself on a test network), and the median time past at it.
    reference_height: int
    reference_time: int
    #: ``E = max(0, now - reference_time)`` and ``blocks_upper(E)``; ``None`` when no clock was
    #: supplied (test networks only).
    elapsed_s: int | None
    time_blocks: int | None
    #: The confidence and block rate the time term used.
    epsilon: float
    surge_factor: float
    #: The largest depth each operator group reported, and the largest of them (``None``: no report).
    reported_by_operator: tuple[tuple[str, int], ...]
    reported_depth: int | None
    #: The distinct operators counted as having reported a depth (:func:`counted_operators`), and how
    #: many this swap required: :data:`MIN_REPORTING_OPERATORS` above dust on a value-bearing
    #: network, else 0.
    reporting_operators: tuple[str, ...]
    reporting_operators_required: int
    #: The value at stake up to which one operator's report sufficed for this run
    #: (:attr:`ElapsedBoundPolicy.single_operator_threshold_photons`), and — when the user override
    #: set it — the statement saying so (:meth:`ElapsedBoundPolicy.single_operator_override_statement`),
    #: which the coordinator also writes into the durable swap record. ``None``: no override.
    single_operator_threshold_photons: int
    single_operator_override: str | None
    served_tip: int
    #: One sentence: which term set the bound, and what stood behind it.
    bound_note: str
    #: The verifier's own sentence for what it proved.
    claim: str


def _log2(n: int) -> str:
    return f"2^{n.bit_length() - 1}" if n > 0 else "0"


def _rule(value_bearing: bool) -> str:
    if value_bearing:
        return (
            f"k = max({MIN_FUNDING_CONFIRMATIONS}, burial, ceil({FORGERY_COST_FACTOR} × value at stake ÷ C)), "
            "C = subsidy × floor work ÷ max header work"
        )
    return "k = the configured depth (test network: no value term)"


def _header_time(header: bytes) -> int:
    return int.from_bytes(header[68:72], "little")


def _reported_by_operator(reported: Any) -> tuple[tuple[str, int], ...]:
    """The largest depth per operator group, from ``((source, depth), ...)``; unusable entries dropped."""
    best: dict[str, int] = {}
    for item in reported if isinstance(reported, (tuple, list)) else ():
        if not (isinstance(item, (tuple, list)) and len(item) == 2):
            continue
        key, depth = item
        if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0:
            continue
        best[str(key)] = max(best.get(str(key), 0), depth)
    return tuple(sorted(best.items()))


def counted_operators(labels: Sequence[str]) -> tuple[str, ...]:
    """The distinct operator groups among *labels* that count toward :data:`MIN_REPORTING_OPERATORS`:
    every label but an unidentified source's (:data:`UNIDENTIFIED_SOURCE_PREFIX`), each once."""
    return tuple(dict.fromkeys(str(k) for k in labels if not str(k).startswith(UNIDENTIFIED_SOURCE_PREFIX)))


def verify_maker_funding(
    evidence: MakerFundingEvidence,
    *,
    chain: RadiantChain,
    expected_spk: bytes,
    expected_value: int,
    value_at_stake_photons: int | None,
    burial_blocks: int,
    now_unix_s: int | None,
    bound_policy: ElapsedBoundPolicy = DEFAULT_ELAPSED_BOUND_POLICY,
    cap: int = MAX_HEADERS_FROM_CHECKPOINT_SDK,
) -> VerifiedMakerFunding:
    """Prove *evidence* pays *expected_spk* / *expected_value* at the required depth, or RAISE.

    Raises :class:`MakerFundingNotVerified` (a ``ValidationError``) for anything short of a verified
    inclusion at depth ``k``; the message names what was required and what was proved. Never
    returns on the server's word. See the module docstring for the rule and the upper bound.
    """
    if not isinstance(evidence, MakerFundingEvidence):
        raise MakerFundingNotVerified("the Radiant leg returned no funding evidence")
    if not isinstance(bound_policy, ElapsedBoundPolicy):
        raise ValidationError("bound_policy must be an ElapsedBoundPolicy")
    if now_unix_s is not None and (not isinstance(now_unix_s, int) or isinstance(now_unix_s, bool)):
        raise ValidationError("now_unix_s must be an int or None")
    rule = _rule(chain.value_bearing)

    def refuse(what: str, required: str, proved: str) -> MakerFundingNotVerified:
        return MakerFundingNotVerified(f"{what}. Required: {required}. Proved: {proved}.")

    # 1. The bytes are the transaction, and ITS output is the covenant — not listunspent's report.
    txid = evidence.txid.lower() if isinstance(evidence.txid, str) else ""
    raw = evidence.raw_tx
    if not isinstance(raw, (bytes, bytearray)) or hash256(bytes(raw))[::-1].hex() != txid:
        raise refuse(
            "the raw funding transaction the server served does not hash to the funding txid",
            "the transaction's own bytes",
            "nothing",
        )
    tx = Transaction.from_hex(bytes(raw))
    vout = evidence.vout
    if tx is None or not isinstance(vout, int) or isinstance(vout, bool) or not 0 <= vout < len(tx.outputs):
        raise refuse(
            f"output {vout!r} of the funding transaction could not be read from its raw bytes",
            "the covenant output, parsed from the verified bytes",
            "nothing",
        )
    out = tx.outputs[vout]
    if out.locking_script.serialize() != bytes(expected_spk):
        raise refuse(
            f"output {txid}:{vout} does not pay the covenant scriptPubKey re-derived from the terms",
            "the exact covenant script",
            "a different script, from the transaction's own bytes",
        )
    if int(out.satoshis) != int(expected_value):
        raise refuse(
            f"output {txid}:{vout} carries {int(out.satoshis)} photons, not the negotiated {int(expected_value)}",
            "the negotiated value",
            f"{int(out.satoshis)} photons, from the transaction's own bytes",
        )

    # 2. Inclusion + linkage + PoW over every header served from the funding up to the served tip.
    table = chain.checkpoints
    newest_h, newest_hash = table[-1]
    headers = evidence.headers if isinstance(evidence.headers, Mapping) else {}
    height = evidence.height
    top = newest_h - 1
    while isinstance(headers.get(top + 1), (bytes, bytearray)) and top + 1 <= newest_h + cap:
        top += 1
    if top < newest_h:
        raise refuse(
            f"the server did not serve the header at pyrxd's newest checkpoint ({newest_h})",
            rule,
            "nothing",
        )
    if not isinstance(height, int) or isinstance(height, bool) or height < 0 or height > top:
        raise refuse(
            f"the funding height the server named ({height!r}) is not among the headers it served "
            f"(newest checkpoint {newest_h} to {top})",
            rule,
            "nothing",
        )
    v = verify_mark_block(
        txid=txid,
        raw_tx=bytes(raw),
        height=height,
        merkle=evidence.merkle,
        coinbase_merkle=evidence.coinbase_merkle,
        headers=headers,
        min_confirmations=top - height + 1,
        network=chain.name,
        checkpoints=table,
        max_headers_from_checkpoint=cap,
        pow_limit=chain.pow_limit,
    )
    if v.state != VERIFIED or v.verified_depth is None or v.blockhash is None:
        raise refuse(
            f"the funding transaction's block did not verify ({v.state}: {v.reason})",
            rule,
            "nothing — the depth rests on the server's word until the proof passes",
        )
    proved = v.verified_depth

    # 3. C, from pyrxd's own schedule and headers proved above or linked between two checkpoints.
    verified_heights = set(range(newest_h, top + 1))
    if height <= newest_h:
        cp_above = next(h for h, _ in table if h >= height)
        verified_heights.update(range(height, cp_above + 1))
    interval_max: int | None = None
    try:
        if len(table) >= 2:
            prev_h, prev_hash = table[-2]
            below = prev_hash
            if radiant_block_hash(bytes(headers[prev_h])) != prev_hash:
                raise KeyError(prev_h)
            for h in range(prev_h + 1, newest_h + 1):
                hdr = bytes(headers[h])
                if radiant_header_prev_hash(hdr) != below:
                    raise KeyError(h)
                below = radiant_block_hash(hdr)
            if below != newest_hash:
                raise KeyError(newest_h)
            verified_heights.update(range(prev_h, newest_h + 1))
            interval_max = max(
                radiant_header_work(bytes(headers[h]), pow_limit=chain.pow_limit) for h in range(prev_h, newest_h + 1)
            )
        max_work = max(radiant_header_work(bytes(headers[h]), pow_limit=chain.pow_limit) for h in verified_heights)
        floor_work = radiant_header_work(bytes(headers[newest_h]), pow_limit=chain.pow_limit) // FLOOR_WORK_DIVISOR
    except (KeyError, TypeError, ValueError, ValidationError):
        raise refuse(
            "the last checkpoint interval could not be linked from the headers served, so the cost of a "
            "forged confirmation cannot be priced from proved headers",
            rule,
            f"the funding in block {height}, at least {proved} deep",
        ) from None
    subsidy = block_subsidy_photons(height, chain)
    cost = subsidy * floor_work // max_work if max_work > 0 else 0

    # 4. k.
    try:
        k, value_term = required_funding_confirmations(
            value_bearing=chain.value_bearing,
            burial_blocks=burial_blocks,
            value_at_stake_photons=value_at_stake_photons,
            forged_confirmation_cost_photons=cost,
        )
    except MakerFundingNotVerified as exc:
        raise refuse(str(exc), rule, f"the funding in block {height}, at least {proved} deep") from None
    pricing = (
        f"C = {cost} photons (subsidy {subsidy} at block {height} × floor work {_log2(floor_work)} ÷ max header "
        f"work {_log2(max_work)})"
    )
    if chain.value_bearing:
        why = (
            f"k = {k} = max({MIN_FUNDING_CONFIRMATIONS}, burial {burial_blocks}, "
            f"ceil({FORGERY_COST_FACTOR} × value {value_at_stake_photons} photons ÷ C) = {value_term}); {pricing}"
        )
    else:
        why = f"k = {k} (test network {chain.name}: the configured depth {burial_blocks}, no value term)"
    if height + k - 1 > newest_h + cap:
        raise refuse(
            f"block {height + k - 1}, where the funding would reach the required depth, is "
            f"{height + k - 1 - newest_h} blocks past this pyrxd's newest checkpoint ({newest_h}) and this gate "
            f"links at most {cap} — upgrade pyrxd (newer checkpoints) or verify against your own node",
            why,
            f"the funding in block {height}, {proved} deep",
        )
    if proved < k:
        raise refuse(
            f"the maker's funding {txid}:{vout} is proved only {proved} block(s) deep; wait for {k - proved} "
            "more, then retry",
            why,
            f"inclusion in block {height} ({v.blockhash}), {proved} deep, linked to checkpoint {newest_h}",
        )

    # 5. The upper bound on elapsed depth, for the timelock gates. The time term is measured from the
    #    MEDIAN TIME PAST at the REFERENCE header, `max(1, value_term)` deep below the newest header
    #    served (the newest counts as 1): a different header at or below it means different headers
    #    above it too, each at the floor or above, so its window costs `value_term × C` to change —
    #    the price the rule already sets on the depth. `value_term <= k <= proved`, so the reference
    #    is never below the funding block. A test network has no value term: the reference is the
    #    newest header served.
    ref_depth = max(1, value_term)
    ref_h = top - ref_depth + 1
    window_lo = max(0, ref_h - (MEDIAN_TIME_SPAN - 1))
    cp_ref_h = newest_h
    try:
        if ref_h not in verified_heights:
            # Below the last checkpoint interval and above the funding block's own checkpoint: nothing
            # above linked it yet. Link it to the checkpoint at or above it before reading its time.
            cp_ref_h, cp_ref_hash = next((h, b) for h, b in table if h >= ref_h)
            below = radiant_block_hash(bytes(headers[ref_h]))
            for h in range(ref_h + 1, cp_ref_h + 1):
                hdr = bytes(headers[h])
                if radiant_header_prev_hash(hdr) != below:
                    raise KeyError(h)
                below = radiant_block_hash(hdr)
            if below != cp_ref_hash:
                raise KeyError(cp_ref_h)
    except (KeyError, TypeError, ValueError, ValidationError):
        raise refuse(
            f"the reference header the elapsed-depth bound is measured from (block {ref_h}, {ref_depth} "
            f"deep counting the newest header served as 1) was not served linked to checkpoint {cp_ref_h}, "
            "so the blocks since the funding cannot be bounded from above",
            why,
            f"the funding in block {height}, {proved} deep",
        ) from None
    # The median-time-past window below it: each header linked to the one above by its hash, so the
    # whole window is as fixed as the reference header itself.
    want = radiant_header_prev_hash(bytes(headers[ref_h]))
    for h in range(ref_h - 1, window_lo - 1, -1):
        below_hdr = headers.get(h)
        if not isinstance(below_hdr, (bytes, bytearray)) or radiant_block_hash(bytes(below_hdr)) != want:
            raise refuse(
                f"header {h}, in the {MEDIAN_TIME_SPAN}-header window the reference time is the median of "
                f"(blocks {window_lo} to {ref_h}), was not served linked to the reference header {ref_h}, so "
                "the blocks since the funding cannot be bounded from above",
                why,
                f"the funding in block {height}, {proved} deep",
            )
        want = radiant_header_prev_hash(bytes(below_hdr))
    mtp = median_time_past([_header_time(bytes(headers[h])) for h in range(window_lo, ref_h + 1)])
    eps = bound_policy.epsilon(value_at_stake_photons)
    if now_unix_s is None:
        if chain.value_bearing:
            raise refuse(
                "no wall clock (now_unix_s) was supplied, so the blocks mined since the reference header "
                "cannot be bounded, and the timelock checks would judge a CSV window that may already be "
                "shorter",
                "now_unix_s",
                f"the funding in block {height}, at least {proved} deep",
            )
        elapsed_s: int | None = None
        time_blocks: int | None = None
    else:
        elapsed_s = max(0, now_unix_s - mtp)
        time_blocks = bound_policy.blocks_upper(
            elapsed_s, spacing_s=int(chain.target_spacing_s), value_at_stake_photons=value_at_stake_photons
        )
    by_operator = _reported_by_operator(evidence.reported_depths)
    reported = max((d for _k, d in by_operator), default=None)
    # Above dust on a value-bearing network, the report term must come from at least two distinct
    # operators: a depth reported by one operator group alone is not enough to lock against.
    answered = counted_operators([k for k, d in by_operator if d >= 1])
    needed = bound_policy.requires_operators(chain, value_at_stake_photons)
    if len(answered) < needed:
        configured = (
            tuple(str(c) for c in evidence.configured_operators)
            if isinstance(evidence.configured_operators, (tuple, list))
            else ()
        )
        silent = [c for c in counted_operators(configured) if c not in answered]
        raise refuse(
            f"the value at stake ({value_at_stake_photons} photons) is above the dust threshold "
            f"({bound_policy.single_operator_threshold_photons} photons), so the funding's depth must be reported by at "
            f"least {needed} distinct operators; {len(answered)} answered"
            + (f" ({', '.join(answered)})" if answered else "")
            + (f", and {', '.join(silent)} did not" if silent else "")
            + ". Configure a depth source run by another operator (RadiantChainIO(..., depth_sources=...)) "
            "and retry" + bound_policy.single_operator_refusal_hint(),
            f"depth reports from {needed} distinct operators",
            f"the funding in block {height}, {proved} deep; "
            + (", ".join(f"{k} {d}" for k, d in by_operator) if by_operator else "no depth reports"),
        )
    # Blocks up to and including the reference header are proved; every block after it is inside the
    # time term. Never below the proved depth; a source's own count can only raise it.
    upper, term = elapsed_blocks_upper_bound(
        proved=proved,
        through_reference=ref_h - height + 1,
        time_blocks=time_blocks,
        reported=reported,
    )
    ops = len(by_operator)
    if time_blocks is None:
        time_part = "no clock was supplied (test network), so there is no time term"
    else:
        time_part = (
            f"time term {ref_h - height + 1} proved to block {ref_h} + {time_blocks} for the {elapsed_s} s since "
            f"the median time past at it ({mtp}), at ε = {eps:.3g} and {bound_policy.surge_factor:g}× the "
            f"{int(chain.target_spacing_s)} s nominal rate"
        )
    report_part = (
        "no source reported a depth"
        if not by_operator
        else f"reports from {ops} operator{'s' if ops != 1 else ''} ({', '.join(f'{k} {d}' for k, d in by_operator)})"
    )
    one_op = (
        "; with one operator configured, the time term is what stands against a source that stops serving early"
        if ops <= 1 and time_blocks is not None
        else ""
    )
    if needed:
        rule_part = f"; {len(answered)} distinct operators reported, {needed} required above the dust threshold"
    elif chain.value_bearing:
        rule_part = (
            f"; the value at stake is at or below the dust threshold ({bound_policy.single_operator_threshold_photons} "
            "photons), so a report from one operator suffices and the time term may govern"
        )
    else:
        rule_part = ""
    # THE USER OVERRIDE of the single-operator threshold. Stated in the result (and, by the
    # coordinator, in the durable record) whenever it is set; a WARNING, naming the value, whenever
    # it raises the threshold — above the default the swap relies on one operator for the depth.
    override = bound_policy.single_operator_override_statement()
    if override is not None:
        rule_part += f"; {override}"
        if bound_policy.single_operator_threshold_raised and chain.value_bearing:
            logger.warning(
                "taker gate: %s; the value at stake for this swap is %s",
                override,
                "unknown" if value_at_stake_photons is None else format_rxd(value_at_stake_photons),
            )
    note = f"the {term} term set the bound at {upper}: {time_part}; {report_part}; proved {proved}{one_op}{rule_part}"

    return VerifiedMakerFunding(
        outpoint=f"{txid}:{vout}",
        value_photons=int(out.satoshis),
        height=height,
        blockhash=v.blockhash,
        proved_depth=proved,
        required_confirmations=k,
        value_term=value_term,
        burial_blocks=burial_blocks,
        value_at_stake_photons=value_at_stake_photons,
        forged_confirmation_cost_photons=cost,
        subsidy_photons=subsidy,
        floor_work=floor_work,
        max_header_work=max_work,
        last_interval_max_work=interval_max,
        elapsed_blocks_upper=upper,
        bound_term=term,
        reference_height=ref_h,
        reference_time=mtp,
        elapsed_s=elapsed_s,
        time_blocks=time_blocks,
        epsilon=eps,
        surge_factor=float(bound_policy.surge_factor),
        reported_by_operator=by_operator,
        reported_depth=reported,
        reporting_operators=answered,
        reporting_operators_required=needed,
        single_operator_threshold_photons=bound_policy.single_operator_threshold_photons,
        single_operator_override=override,
        served_tip=top,
        bound_note=note,
        claim=v.claim or "",
    )

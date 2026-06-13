"""Live-participant coordinator for the Gravity Taproot-HTLC atomic swap.

Drives the pure FSM in :mod:`pyrxd.gravity.swap_state` for ONE participant. This
module owns the safety policy that the FSM deliberately leaves out:

* the hard role invariant ``MAKER_SECRET_TAKER_LOCKS_BTC_FIRST`` (named, not an
  opaque "Combination #1");
* the cross-chain timelock **margin** check (fail-closed; cross-unit normalised);
* the **two-phase gates** (pre-BTC-lock validation + post-asset-lock
  re-validation, plan deepen-review H4);
* the **MAKER_STALLS** proactive-refund trigger (plan deepen-review C1).

Chain access is injected as duck-typed *legs* (a BTC leg + a Radiant leg) plus an
*indexer* and a *seen-store*. Per the plan's simplicity review we do NOT define a
``Protocol`` for the legs — concrete classes (``BitcoinTaprootLeg`` for BTC; a thin
wrapper over ``build_htlc_claim``/``build_htlc_refund`` for Radiant) and duck-typed
test fakes cover every coordinator path; a ``CounterChainLeg`` Protocol is deferred
until a 2nd backend (ETH) gives a real shape to generalise against.

Nothing here touches a live chain directly — every chain effect goes through an
injected leg, so the whole coordinator is exercised with mocks.

Design rules (house style)
--------------------------
* Frozen config dataclasses; ``__post_init__`` raises ``ValidationError``.
* The preimage ``p`` is held ONLY as :class:`pyrxd.security.secrets.SecretBytes`,
  in memory, zeroized after the BTC claim. It is never persisted, never logged,
  never placed in :class:`NegotiatedTerms`/:class:`SwapRecord`.
* No ``assert`` in ``src/`` — all invariants raise.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import logging
import math
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import (
    BtcHtlcLocator,
    Timelock,
    TimeUnit,
    btc_input_outpoints_from_raw,
)
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.glyph.credential_binding import CredentialBindingError, assert_soulbound_credential
from pyrxd.gravity.htlc_covenant import holder_hash
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import SecretBytes

from .eth_rxd_timelock import CrossClockMargin, assert_covenant_confirms_before_eth_deadline
from .finality import CounterClaimFinality, CounterClaimState
from .ref_authenticity import verify_ref_authenticity
from .swap_state import (
    NegotiatedTerms,
    SwapEvent,
    SwapRecord,
    SwapState,
    advance,
)

# A durable-persist hook: ``await persist(record)`` writes the record so a crash
# between an awaited broadcast and the in-memory state advance cannot strand
# funds. Injected (None in tests that do not exercise crash-atomicity).
PersistHook = Callable[[SwapRecord], Awaitable[None]]

__all__ = [
    "ESTIMATED_BTC_CLAIM_REORG_DEPTH_BLOCKS",
    "ESTIMATED_DEFAULT_MARGIN_BLOCKS",
    "ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS",
    "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST",
    "ClaimFinality",
    "MarginPolicy",
    "SwapCoordinator",
    "assert_timelock_margin",
    "assess_claim_finality",
    "generate_secret",
    "measure_margin_from_btc_block_times",
    "should_taker_refund_proactively",  # deprecated alias of taker_refund_window_open
    "taker_refund_window_open",
]

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# The hard role invariant (the safety hinge — NOT an implementer choice)
# ---------------------------------------------------------------------------

MAKER_SECRET_TAKER_LOCKS_BTC_FIRST = (  # nosec B105 — a role-invariant doc string, not a secret/password
    "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST: "
    "the maker holds the Glyph asset and wants BTC; the taker holds BTC and wants "
    "the asset. (1) The MAKER generates the secret p (32 bytes CSPRNG, fresh per "
    "swap) and publishes H = SHA256(p). (2) The TAKER locks BTC FIRST (funds the "
    "P2TR HTLC). (3) The MAKER locks the asset SECOND (Radiant covenant). (4) The "
    "MAKER claims the BTC FIRST, revealing p in the Bitcoin witness. (5) The TAKER "
    "scrapes p from Bitcoin and claims the Radiant asset before its refund opens. "
    "Invariant: t_BTC > t_RXD + margin — the leg claimed second (Radiant) has the "
    "SHORTER refund window; the first-claimed leg (BTC) holds the LONGER refund. "
    "The taker's client MUST verify t_BTC - t_RXD >= margin before funding, or refuse."
)


# ---------------------------------------------------------------------------
# Margin (plan deepen-review C2/C3)
# ---------------------------------------------------------------------------
#
# The margin must cover three separately-sourced terms, expressed in ONE clock
# unit:
#   1. BTC inter-block tail — how long the maker's claim might take to confirm at
#      a chosen percentile of the inter-block-time distribution.
#   2. Radiant reorg-depth — confirmations before the taker's asset claim is final
#      (so a shallow reorg cannot un-do it before t_RXD).
#   3. Cross-chain interval conversion — the seconds<->blocks rounding slack.
#
# THE DEFAULT BELOW IS *ESTIMATED*, NOT MEASURED. It is a placeholder so tests can
# run; per the global honesty rules it is labelled ESTIMATED and "real-value" mode
# (require_measured=True) refuses to use it — a measured value MUST be supplied for
# any mainnet swap carrying real funds.

# ESTIMATED placeholder (test-only). 36 blocks ≈ several BTC blocks of tail plus a
# Radiant reorg buffer; the real number must come from measured block data on both
# chains plus a stated reorg depth. DO NOT treat this as a finding.
ESTIMATED_DEFAULT_MARGIN_BLOCKS = 36

# ESTIMATED placeholder (test-only) for the BTC-claim reorg-finality depth: how many
# confirmations the maker's BTC claim must reach before the taker relies on the
# revealed ``p`` (reorg gate, plan 2026-05-26-feat-gravity-reorg-gate-plan.md). 6 is
# the conventional Bitcoin reorg-safety depth; the real number is a measured policy
# input. DO NOT treat this as a finding — a measured swap MUST supply its own.
ESTIMATED_BTC_CLAIM_REORG_DEPTH_BLOCKS = 6

# ESTIMATED placeholder (test-only) for the Radiant-claim burial depth: how many
# confirmations the taker's OWN asset claim must reach to be reorg-safe, and the slack
# for it to get included — both consumed by the squeeze check below.
ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS = 6

# Hard safety floor (in BLOCKS) for any reorg depth, enforced at MarginPolicy
# construction. A 1-block depth is materially unsafe on a real chain (natural
# single-block reorgs happen; "dust" bounds the loss, not the reorg probability), so
# even a dust run must use >= 2. NOT a configurable knob — it is the fail-closed floor.
_MIN_REORG_DEPTH_BLOCKS = 2

# Hard safety floor (SECONDS) for the ETH/PoS finalization window. Post-Merge finality is two
# epochs (2 * 32 slots * 12 s = 768 s) in the steady state; a smaller window collapses the
# reorg-gate's finalization reserve toward zero. Enforced at MarginPolicy construction whenever
# eth_finalization_window_s is set (the ETH-swap PRESENCE of the field is enforced fail-closed
# at SwapCoordinator construction, where the counter chain is known).
_MIN_ETH_FINALIZATION_WINDOW_S = 768


@dataclass(frozen=True)
class MarginPolicy:
    """How the cross-chain timelock margin is computed and enforced.

    Attributes
    ----------
    margin:
        The required minimum ``t_btc - t_rxd``, as a unit-tagged
        :class:`Timelock`. If ``is_measured`` is False this is an ESTIMATE.
    block_interval_s:
        Seconds-per-block used to normalise across units. For BTC the canonical
        target is 600s; supply a *measured* value for mainnet. Used both to
        normalise t_btc/t_rxd to a common unit and to convert the margin.
    is_measured:
        True only when ``margin`` + ``block_interval_s`` were derived from real
        block data (both chains) + a stated reorg depth. Estimates are test-only.
    require_measured:
        "real-value" mode. When True, an estimated policy is refused at use time
        (fail-closed) — a mainnet swap must carry a measured margin.
    """

    margin: Timelock
    block_interval_s: float
    is_measured: bool
    require_measured: bool = False
    # F-007: Radiant's block interval (seconds). The squeeze check converts the BTC
    # reorg depth (BTC blocks) into RXD blocks via block_interval_s / rxd_block_interval_s,
    # because BTC and RXD block rates differ — treating BTC blocks 1:1 as RXD blocks
    # under-counts the RXD window the BTC burial consumes. Defaults to ~300s (Radiant).
    rxd_block_interval_s: float = 300.0
    # Reorg gate (plan 2026-05-26). The maker's BTC claim must reach this depth before
    # the taker relies on the revealed p; the taker's own Radiant claim must then bury
    # ``rxd_claim_burial`` deep — both BEFORE t_rxd opens. Unit-tagged so the squeeze
    # check normalises them alongside the margin. A measured policy MUST supply these
    # (require_measured rejects the estimated defaults) and they must be > 0.
    btc_claim_reorg_depth: Timelock = field(
        default_factory=lambda: Timelock(ESTIMATED_BTC_CLAIM_REORG_DEPTH_BLOCKS, TimeUnit.BLOCKS)
    )
    rxd_claim_burial: Timelock = field(
        default_factory=lambda: Timelock(ESTIMATED_RXD_CLAIM_BURIAL_BLOCKS, TimeUnit.BLOCKS)
    )
    # VALUE-SCALED claim burial (red-team 2026-06-12 HIGH). The flat ``rxd_claim_burial`` above
    # bounds reorg PROBABILITY, not reorg COST vs. value — a low-cap PoW chain like Radiant can be
    # shallow-reorged for ~a fixed marginal cost, so a swap whose Radiant-side value exceeds that
    # cost is economically reversible at a flat burial (Bitcoin's "6 conf" folklore does NOT
    # transfer to a low-cap chain; cf. THORChain value-scaled confs, Trail-of-Bits 25%-cost
    # method). When BOTH of the next two are set, the reorg gate raises the required burial to
    # ``ceil(value_at_risk_photons * burial_safety_factor / rxd_reorg_cost_per_block)`` (floored at
    # the flat ``rxd_claim_burial``), so an attacker must spend >= the value at stake to reorg the
    # taker's claim out. The coordinator REFUSES a value-bearing Radiant swap unless these are set
    # OR ``accept_flat_burial=True`` (the dust opt-out) — fail-closed, mirroring ``require_measured``.
    #
    # rxd_reorg_cost_per_block: the MEASURED marginal cost to reorg ONE Radiant block, in PHOTONS
    # (the honest reward + work an attacker must out-spend per block). Operator-supplied/refreshed
    # (it tracks hashrate + RXD price); never hardcoded — an estimate masquerading as a measurement
    # would size the whole defence wrong. None disables value-scaling (then accept_flat_burial gates).
    rxd_reorg_cost_per_block: int | None = None
    # value_at_risk_photons: the swap's ECONOMIC value to protect, in PHOTONS. For an RXD swap this
    # equals ``terms.radiant_amount``; for FT/NFT the on-chain amount (token units / NFT carrier
    # dust) is NOT the economic value, so the operator MUST assess and supply it explicitly.
    value_at_risk_photons: int | None = None
    # burial_safety_factor: required cost-to-reorg >= factor * value. 1.0 = break-even (an attack
    # costs exactly the value — marginally unprofitable); raise it for margin.
    burial_safety_factor: float = 1.0
    # accept_flat_burial: the explicit dust opt-out. True = "this value is below the reorg cost, a
    # flat burial is fine" — the conscious, logged escape from the fail-closed setup gate.
    accept_flat_burial: bool = False
    # Finalized-checkpoint (ETH/PoS) counter-leg finalization window, in SECONDS (re-audit §9
    # #3). For a depth-based (BTC/PoW) leg this stays None and the reorg gate uses
    # btc_claim_reorg_depth. For an ETH leg — whose finality is a TIME checkpoint, not a block
    # depth — the gate reserves ceil(eth_finalization_window_s / rxd_block_interval_s) RXD
    # blocks in the WAIT branch instead. CHOSEN/ESTIMATED (post-Merge ~2 epochs ≈ 12.8 min);
    # required (non-None) for an ETH (no-depth) finality verdict.
    eth_finalization_window_s: int | None = None
    # ETH cross-clock ordering (audit HIGH-1). The pre-fund ordering gate for an ETH swap
    # validates the ABSOLUTE eth_timeout_unix_s against the RELATIVE t_rxd window via the
    # cross-clock bridge; it needs the seconds margin budget + the worst-case covenant-
    # confirmation wait. Required (non-None) for an ETH swap at fund time; None for BTC (which
    # uses assert_timelock_margin on the same-clock t_btc/t_rxd).
    cross_clock_margin: CrossClockMargin | None = None
    max_covenant_confirm_wait_s: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.margin, Timelock):
            raise ValidationError("MarginPolicy.margin must be a Timelock")
        if not isinstance(self.block_interval_s, (int, float)) or self.block_interval_s <= 0:
            raise ValidationError("MarginPolicy.block_interval_s must be > 0")
        if not isinstance(self.rxd_block_interval_s, (int, float)) or self.rxd_block_interval_s <= 0:
            raise ValidationError("MarginPolicy.rxd_block_interval_s must be > 0")
        if not isinstance(self.is_measured, bool):
            raise ValidationError("MarginPolicy.is_measured must be bool")
        if not isinstance(self.require_measured, bool):
            raise ValidationError("MarginPolicy.require_measured must be bool")
        for label, depth in (
            ("btc_claim_reorg_depth", self.btc_claim_reorg_depth),
            ("rxd_claim_burial", self.rxd_claim_burial),
        ):
            if not isinstance(depth, Timelock):
                raise ValidationError(f"MarginPolicy.{label} must be a Timelock")
            # Floor in BLOCK terms (normalise so a seconds-tagged depth is floored too).
            # A 1-block reorg depth is materially unsafe on a real chain — natural
            # single-block reorgs happen, and "dust" bounds the LOSS, not the reorg
            # PROBABILITY. Require >= 2 (reorg-gate plan, security review). The
            # conventional value is 6; a chosen dust value of 2-3 is defensible if
            # recorded as below-conventional. 0/1 are rejected fail-closed.
            depth_blocks = depth.normalize_to(TimeUnit.BLOCKS, block_interval_s=self.block_interval_s).value
            if depth_blocks < _MIN_REORG_DEPTH_BLOCKS:
                raise ValidationError(
                    f"MarginPolicy.{label} = {depth_blocks} blk < safety floor {_MIN_REORG_DEPTH_BLOCKS}; "
                    "a 0/1-block reorg depth defeats the gate (single-block reorgs occur on real chains)"
                )
        if self.require_measured and not self.is_measured:
            raise ValidationError(
                "real-value mode (require_measured=True) requires a MEASURED margin; "
                "the ESTIMATED default is test-only — supply measured block data + reorg depth"
            )
        # Value-scaled-burial inputs (red-team 2026-06-12 HIGH): positive when set.
        for label, val in (
            ("rxd_reorg_cost_per_block", self.rxd_reorg_cost_per_block),
            ("value_at_risk_photons", self.value_at_risk_photons),
        ):
            if val is not None and (not isinstance(val, int) or isinstance(val, bool) or val <= 0):
                raise ValidationError(f"MarginPolicy.{label} must be a positive int (photons) or None")
        if not isinstance(self.burial_safety_factor, (int, float)) or isinstance(self.burial_safety_factor, bool):
            raise ValidationError("MarginPolicy.burial_safety_factor must be a number")
        if self.burial_safety_factor < 1.0:
            raise ValidationError(
                f"MarginPolicy.burial_safety_factor = {self.burial_safety_factor} < 1.0; a factor below "
                "break-even lets a reorg cost LESS than the value it reverses (the attack is profitable)"
            )
        if not isinstance(self.accept_flat_burial, bool):
            raise ValidationError("MarginPolicy.accept_flat_burial must be bool")
        if self.eth_finalization_window_s is not None:
            if (
                not isinstance(self.eth_finalization_window_s, int)
                or isinstance(self.eth_finalization_window_s, bool)
                or self.eth_finalization_window_s <= 0
            ):
                raise ValidationError("MarginPolicy.eth_finalization_window_s must be a positive int or None")
            if self.eth_finalization_window_s < _MIN_ETH_FINALIZATION_WINDOW_S:
                raise ValidationError(
                    f"MarginPolicy.eth_finalization_window_s = {self.eth_finalization_window_s}s < safety floor "
                    f"{_MIN_ETH_FINALIZATION_WINDOW_S}s (~2 post-Merge epochs); a smaller window collapses the "
                    "finalization reserve in the reorg gate"
                )
        if self.cross_clock_margin is not None and not isinstance(self.cross_clock_margin, CrossClockMargin):
            raise ValidationError("MarginPolicy.cross_clock_margin must be a CrossClockMargin or None")
        if self.max_covenant_confirm_wait_s is not None and (
            not isinstance(self.max_covenant_confirm_wait_s, int)
            or isinstance(self.max_covenant_confirm_wait_s, bool)
            or self.max_covenant_confirm_wait_s < 0
        ):
            raise ValidationError("MarginPolicy.max_covenant_confirm_wait_s must be a non-negative int or None")

    @classmethod
    def estimated(
        cls, *, block_interval_s: float = 600.0, require_measured: bool = False, accept_flat_burial: bool = False
    ) -> MarginPolicy:
        """The ESTIMATED, test-only policy. Refuses to construct in real-value mode.

        ``accept_flat_burial`` is the dust opt-out from the value-scaled-burial setup gate —
        set it for a deliberate dust run whose value is below the Radiant reorg cost.
        """
        return cls(
            margin=Timelock(ESTIMATED_DEFAULT_MARGIN_BLOCKS, TimeUnit.BLOCKS),
            block_interval_s=block_interval_s,
            is_measured=False,
            require_measured=require_measured,
            accept_flat_burial=accept_flat_burial,
        )

    @classmethod
    def measured(
        cls,
        *,
        margin: Timelock,
        block_interval_s: float,
        btc_claim_reorg_depth: Timelock | None = None,
        rxd_claim_burial: Timelock | None = None,
        rxd_block_interval_s: float | None = None,
        rxd_reorg_cost_per_block: int | None = None,
        value_at_risk_photons: int | None = None,
        burial_safety_factor: float = 1.0,
        accept_flat_burial: bool = False,
    ) -> MarginPolicy:
        """A measured policy for real-value mainnet swaps.

        ``btc_claim_reorg_depth`` / ``rxd_claim_burial`` are the reorg gate's measured
        inputs; if omitted they fall back to the ESTIMATED defaults (acceptable only
        because a measured policy still carries the estimated reorg depths — supply
        measured values for a real mainnet swap).

        ``rxd_reorg_cost_per_block`` (measured, photons/block) + ``value_at_risk_photons``
        (the assessed economic value) drive the VALUE-SCALED claim burial (red-team HIGH):
        supply both for a value-bearing Radiant swap, or set ``accept_flat_burial=True`` for
        a dust run — the coordinator refuses a value-bearing swap that leaves them unset.
        """
        kwargs: dict = {
            "margin": margin,
            "block_interval_s": block_interval_s,
            "is_measured": True,
            "require_measured": True,
            "burial_safety_factor": burial_safety_factor,
            "accept_flat_burial": accept_flat_burial,
        }
        if btc_claim_reorg_depth is not None:
            kwargs["btc_claim_reorg_depth"] = btc_claim_reorg_depth
        if rxd_claim_burial is not None:
            kwargs["rxd_claim_burial"] = rxd_claim_burial
        if rxd_block_interval_s is not None:
            kwargs["rxd_block_interval_s"] = rxd_block_interval_s
        if rxd_reorg_cost_per_block is not None:
            kwargs["rxd_reorg_cost_per_block"] = rxd_reorg_cost_per_block
        if value_at_risk_photons is not None:
            kwargs["value_at_risk_photons"] = value_at_risk_photons
        return cls(**kwargs)


def measure_margin_from_btc_block_times(
    *,
    btc_block_timestamps: list[int],
    btc_tail_percentile: float,
    btc_claim_reorg_depth_blocks: int,
    rxd_claim_burial_blocks: int,
    rxd_block_interval_s: float,
    accept_flat_burial: bool = False,
) -> tuple[MarginPolicy, dict]:
    """Build a MEASURED MarginPolicy from real mainnet BTC inter-block data (pure).

    PURE by design: it does NOT fetch anything. The caller supplies real, observed BTC
    block timestamps (e.g. parsed from headers fetched via MempoolSpaceSource — the
    4-byte LE field at header bytes 68:72) so the measurement is deterministic,
    testable, and cannot fabricate data it was not given (global honesty rules).

    What is MEASURED vs CHOSEN (separated in the returned provenance dict):
    * MEASURED — ``block_interval_s`` (median observed BTC inter-block gap) and the
      ``margin`` (the inter-block tail at ``btc_tail_percentile``, expressed in BTC
      blocks, capturing "how long the maker's claim might take to confirm").
    * CHOSEN — ``btc_claim_reorg_depth`` / ``rxd_claim_burial`` (operator policy, not
      derivable from block timing) and ``rxd_block_interval_s`` (Radiant's interval,
      recorded for the squeeze conversion).

    Returns ``(MarginPolicy.measured(...), provenance)``. The policy is real-value
    (``require_measured=True``); the floor + unit checks in ``MarginPolicy`` still apply
    (a < 2-block reorg depth is rejected). The provenance dict is the first report
    artifact — emit it verbatim so the run records exactly what was measured.

    Raises ``ValidationError`` on too-few samples or a nonsensical percentile (never
    guess a margin from thin data).
    """
    if not isinstance(btc_block_timestamps, list) or len(btc_block_timestamps) < 3:
        raise ValidationError("need >= 3 BTC block timestamps to measure inter-block intervals")
    if any(not isinstance(ts, int) or isinstance(ts, bool) for ts in btc_block_timestamps):
        raise ValidationError("btc_block_timestamps must all be ints (unix seconds)")
    if not isinstance(btc_tail_percentile, (int, float)) or not (50.0 <= btc_tail_percentile <= 99.9):
        raise ValidationError("btc_tail_percentile must be in [50, 99.9] (a tail, not the median or an extreme)")
    if not isinstance(rxd_block_interval_s, (int, float)) or rxd_block_interval_s <= 0:
        raise ValidationError("rxd_block_interval_s must be > 0")

    # Inter-block gaps (seconds). Sort timestamps first — headers may arrive unordered;
    # a negative gap (out-of-order/equal-time blocks happen on real chains) is clamped
    # to 0 so it can't shrink the measured interval below reality.
    ordered = sorted(int(ts) for ts in btc_block_timestamps)
    gaps = [max(0, ordered[i + 1] - ordered[i]) for i in range(len(ordered) - 1)]
    if not gaps:
        raise ValidationError("could not derive any inter-block gaps")

    sorted_gaps = sorted(gaps)
    median_gap = sorted_gaps[len(sorted_gaps) // 2]
    # Nearest-rank percentile (no interpolation — conservative, no fabricated precision).
    rank = max(1, math.ceil(btc_tail_percentile / 100.0 * len(sorted_gaps)))
    tail_gap_s = sorted_gaps[rank - 1]
    measured_block_interval_s = float(median_gap) if median_gap > 0 else 600.0

    # Margin = the BTC inter-block tail expressed in BTC blocks (ceil), >= 1 block. This
    # is the "maker's claim confirmation tail" term; the reorg depths are added on top
    # by the squeeze check, so the margin itself is the timing slack, not the depth.
    margin_blocks = max(1, math.ceil(tail_gap_s / measured_block_interval_s))

    policy = MarginPolicy.measured(
        margin=Timelock(margin_blocks, TimeUnit.BLOCKS),
        block_interval_s=measured_block_interval_s,
        btc_claim_reorg_depth=Timelock(btc_claim_reorg_depth_blocks, TimeUnit.BLOCKS),
        rxd_claim_burial=Timelock(rxd_claim_burial_blocks, TimeUnit.BLOCKS),
        rxd_block_interval_s=float(rxd_block_interval_s),  # F-007: stored for the squeeze conversion
        # Dust runs opt out of value-scaled burial (the value is below the Radiant reorg cost);
        # a real-value run leaves this False and supplies rxd_reorg_cost_per_block + value_at_risk.
        accept_flat_burial=accept_flat_burial,
    )
    provenance = {
        "measured": {
            "btc_block_interval_s_median": median_gap,
            "btc_tail_gap_s": tail_gap_s,
            "btc_tail_percentile": btc_tail_percentile,
            "btc_samples": len(btc_block_timestamps),
            "margin_blocks": margin_blocks,
            "block_interval_s_used": measured_block_interval_s,
        },
        "chosen": {
            "btc_claim_reorg_depth_blocks": btc_claim_reorg_depth_blocks,
            "rxd_claim_burial_blocks": rxd_claim_burial_blocks,
            "rxd_block_interval_s": rxd_block_interval_s,
            "min_reorg_depth_floor_blocks": _MIN_REORG_DEPTH_BLOCKS,
            "accept_flat_burial": accept_flat_burial,
        },
        "note": (
            "margin + block_interval_s are MEASURED from observed BTC block timestamps; "
            "reorg depths are CHOSEN operator policy. The squeeze normalises all via "
            "block_interval_s — a single-clock approximation across BTC/RXD; the depths "
            "carry slack to absorb it (reorg-gate plan)."
        ),
    }
    return policy, provenance


def assert_timelock_margin(t_btc: Timelock, t_rxd: Timelock, policy: MarginPolicy) -> None:
    """Assert ``t_btc - t_rxd >= margin`` — fail-closed, cross-unit normalised.

    Both legs and the margin are normalised to BLOCKS using
    ``policy.block_interval_s``. If either input is not a :class:`Timelock`, or the
    policy is an estimate in real-value mode, this RAISES (never silently passes).

    This is where the safety invariant lives: a malicious maker who sets a too-tight
    BTC refund (or a too-loose Radiant refund) is rejected here, before the taker
    funds anything.
    """
    if not isinstance(t_btc, Timelock) or not isinstance(t_rxd, Timelock):
        raise ValidationError("assert_timelock_margin requires Timelock inputs (fail-closed)")
    if not isinstance(policy, MarginPolicy):
        raise ValidationError("assert_timelock_margin requires a MarginPolicy")
    if policy.require_measured and not policy.is_measured:
        # Defense-in-depth: MarginPolicy.__post_init__ already blocks this, but the
        # check is repeated at the use site so a hand-built policy cannot slip past.
        raise ValidationError("real-value mode requires a measured margin (fail-closed)")

    # Normalise everything to BLOCKS in one place. normalize_to raises if it cannot
    # convert (e.g. block_interval_s <= 0), which is the fail-closed path.
    try:
        btc_blocks = t_btc.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        margin_blocks = policy.margin.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - normalize_to only raises ValidationError
        raise ValidationError(f"could not normalise timelocks to a common unit: {exc}") from exc

    if btc_blocks <= rxd_blocks:
        raise ValidationError(
            f"timelock ordering violated: t_btc ({btc_blocks} blk) must exceed t_rxd ({rxd_blocks} blk)"
        )
    if (btc_blocks - rxd_blocks) < margin_blocks:
        raise ValidationError(
            f"insufficient margin: t_btc - t_rxd = {btc_blocks - rxd_blocks} blk < required {margin_blocks} blk "
            f"({'measured' if policy.is_measured else 'ESTIMATED'})"
        )


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------


def generate_secret() -> tuple[SecretBytes, bytes]:
    """Generate a fresh CSPRNG preimage ``p`` and its hashlock ``H = SHA256(p)``.

    Returns ``(p_as_SecretBytes, H_bytes)``. ``p`` is wrapped in the
    intentionally-unpicklable :class:`SecretBytes` so it can never be serialised to
    disk. Only ``H`` is safe to put in :class:`NegotiatedTerms`/:class:`SwapRecord`.
    """
    p = os.urandom(32)
    h = hashlib.sha256(p).digest()
    return SecretBytes(p), h


# ---------------------------------------------------------------------------
# MAKER_STALLS proactive-refund trigger (plan deepen-review C1)
# ---------------------------------------------------------------------------


def taker_refund_window_open(
    *,
    now_block_height: int,
    asset_locked_at_height: int,
    t_rxd: Timelock,
    safety_window_blocks: int,
    maker_has_claimed_btc: bool,
    block_interval_s: float = 600.0,
) -> bool:
    """Return True once the taker's act-now window is open: ``t_RXD - N`` reached, maker silent.

    This is a TIMING PREDICATE only — "the maker has not claimed and ``t_RXD - N`` is
    approaching" — NOT a prescription of which refund to run. (Formerly named
    ``should_taker_refund_proactively``; renamed because the name described an action
    while the predicate only describes this window — deferred from PR #189.) The dominant adversarial
    risk it guards: because ``t_BTC > t_RXD``, a malicious maker can withhold the BTC
    claim until after ``t_RXD`` opens, then claim BTC (revealing ``p``) AND CSV-refund
    the asset, taking both. Treat the trigger as "stop waiting", never "keep waiting".

    IMPORTANT — what the taker DOES when this fires is :meth:`mutual_refund` (both legs
    unwind once both timeouts elapse), NOT an asset-only refund. The asset CSV refund
    pays the MAKER (the maker owns the covenant), so a taker that "refunds the asset
    proactively" strands itself — see :meth:`maybe_refund_asset_on_maker_stall` (a
    maker-only primitive) and ``gravity.watch.decide`` (FSM finding #2, 2026-06-09).
    An earlier version of this docstring described that superseded asset-only model;
    do not re-wire it.

    Returns False once the maker has claimed (``p`` is now public — the taker should
    instead scrape it and claim the asset). ``safety_window_blocks`` is the ``N``
    buffer before ``t_RXD`` maturity at which the taker acts.
    """
    if maker_has_claimed_btc:
        return False
    for label, val in (("now_block_height", now_block_height), ("asset_locked_at_height", asset_locked_at_height)):
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValidationError(f"{label} must be a non-negative int")
    if not isinstance(safety_window_blocks, int) or isinstance(safety_window_blocks, bool) or safety_window_blocks < 0:
        raise ValidationError("safety_window_blocks must be a non-negative int")
    rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=block_interval_s).value
    # The Radiant refund opens at asset_locked_at_height + t_rxd (relative timelock).
    # Act once we are within `safety_window_blocks` of that maturity.
    maturity = asset_locked_at_height + rxd_blocks
    return now_block_height >= (maturity - safety_window_blocks)


# Deprecated alias (pre-0.8.0 public name); will be removed in a future release.
should_taker_refund_proactively = taker_refund_window_open


# ---------------------------------------------------------------------------
# Reorg-finality gate on the taker's asset claim (plan 2026-05-26, security-HIGH)
# ---------------------------------------------------------------------------


class ClaimFinality(Enum):
    """The decision for whether the taker may claim the asset off the maker's BTC claim.

    * ``SAFE`` — the maker's BTC claim is reorg-deep AND the remaining ``t_rxd``
      window still admits the taker's own claim burying reorg-deep. Claim now.
    * ``WAIT`` — the BTC claim is not yet deep enough, but the window has room to keep
      waiting. Do NOT claim; retry later (the record stays SECRET_REVEALED).
    * ``SQUEEZED`` — the BTC claim is shallow and the ``t_rxd`` window is closing: there
      is no longer room to wait for a safe claim. This is the danger zone — the FSM
      goes ASSET_VULNERABLE and a deliberate policy (best-effort winner-take-all claim
      vs abandon) takes over. Never a silent claim.
    """

    SAFE = "safe"
    WAIT = "wait"
    SQUEEZED = "squeezed"


def _value_scaled_burial_blocks(policy: MarginPolicy, value_at_risk_photons: int | None) -> int:
    """Required claim-burial depth (Radiant blocks) so a reorg of the taker's claim costs at
    least the value at stake — 0 when value-scaling is not configured (then the flat burial
    stands). Pure (red-team 2026-06-12 HIGH).

    ``required = ceil(value_at_risk_photons * burial_safety_factor / rxd_reorg_cost_per_block)``:
    burying ``required`` blocks forces an attacker to out-spend ``required *
    rxd_reorg_cost_per_block >= value_at_risk_photons * factor`` to reverse the claim. The cost
    is the operator-supplied per-block reorg cost; ``value_at_risk_photons`` is the EFFECTIVE
    value at stake (the coordinator passes the policy's operator-assessed value; the watchtower
    passes the per-record value). When either is absent there is no basis to scale → 0.

    EXACT integer math (audit follow-up MEDIUM): the ceil is computed over ``Fraction``, not
    float division. ``value * factor / cost`` in float silently loses integer precision for a
    value > 2**53 photons (~90M RXD) and returns FEWER blocks than the true ceil — an
    UNDER-count of the very depth that forces the attacker to out-spend the value. ``Fraction``
    is exact for any ``burial_safety_factor``.
    """
    cost = policy.rxd_reorg_cost_per_block
    if cost is None or value_at_risk_photons is None:
        return 0
    required = Fraction(value_at_risk_photons) * Fraction(policy.burial_safety_factor) / cost
    return math.ceil(required)


def _reserve_to_blocks(reserve: Timelock, block_interval_s: float) -> int:
    """Convert a REQUIREMENT/reserve Timelock to BLOCKS, rounding UP for a seconds-tagged value.

    A reserve (claim burial, reorg depth) must round UP: flooring it under-counts the reserve —
    the UNSAFE direction (audit finality INFO). Identity for a BLOCKS-tagged value. Contrast a
    DEADLINE like ``t_rxd``, where flooring is safe because it only shrinks the available window.
    """
    if reserve.unit is TimeUnit.BLOCKS:
        return reserve.value
    return math.ceil(reserve.value / block_interval_s)


def assess_claim_finality(
    *,
    counter_claim_finality: CounterClaimFinality,
    now_rxd_height: int,
    asset_locked_at_height: int,
    t_rxd: Timelock,
    policy: MarginPolicy,
    value_at_risk_photons: int | None = None,
) -> ClaimFinality:
    """Decide SAFE / WAIT / SQUEEZED for the taker's asset claim — fail-closed, pure.

    Two serial finality requirements share the ``t_rxd`` deadline (security review):
      1. the maker's COUNTER-LEG claim must be FINAL (PoW: ``policy.btc_claim_reorg_depth``
         confirmations deep so ``p`` is reorg-safe; PoS: past the ``finalized`` checkpoint),
         supplied as a :class:`CounterClaimFinality` verdict, THEN
      2. the taker's own Radiant claim must bury deep enough — ``max(policy.rxd_claim_burial,
         value-scaled)``, where the value-scaled depth (red-team HIGH) makes a reorg of the
         claim cost at least the value at stake (see ``_value_scaled_burial_blocks``) —
      both BEFORE ``t_rxd`` (the maker's CSV refund) opens at
      ``asset_locked_at_height + t_rxd``.

    A bare depth gate without the deadline check is a NET REGRESSION: it can force the
    taker to choose between an unsafe early claim and losing the asset to the maker's
    refund. So this returns WAIT only while there is genuinely room to wait, and
    SQUEEZED (→ ASSET_VULNERABLE) once there is not. A counter chain that is not
    finalizing (verdict ``COUNTER_CHAIN_NOT_FINALIZING``) SQUEEZES — never WAIT.

    ``value_at_risk_photons`` (audit follow-up) is the EFFECTIVE per-assessment value the
    value-scaled burial uses, overriding ``policy.value_at_risk_photons`` when supplied. The
    coordinator passes None (its operator-assessed value lives on the policy); the watchtower
    passes the per-RECORD value (so one tower policy can judge many swaps of differing value
    — it must NOT apply one swap's value to another). If value-scaling is CONFIGURED on the
    policy (``rxd_reorg_cost_per_block`` set) but no effective value is available, this
    fails closed (SQUEEZED — never an optimistic value-blind SAFE): the watchtower cannot
    certify an FT/NFT swap SAFE on value it cannot see; the operator must decide.

    Raises ``ValidationError`` on any un-evaluable input (never assumes "plenty of
    time"). All depths normalised to Radiant BLOCKS via ``policy.block_interval_s``.
    """
    if not isinstance(policy, MarginPolicy):
        raise ValidationError("assess_claim_finality requires a MarginPolicy")
    if not isinstance(counter_claim_finality, CounterClaimFinality):
        raise ValidationError("assess_claim_finality requires a CounterClaimFinality verdict")
    for label, val in (
        ("now_rxd_height", now_rxd_height),
        ("asset_locked_at_height", asset_locked_at_height),
    ):
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise ValidationError(f"{label} must be a non-negative int (fail-closed)")
    if not isinstance(t_rxd, Timelock):
        raise ValidationError("assess_claim_finality requires a Timelock t_rxd")
    # F-013: the current Radiant height can never be BELOW where the covenant was
    # mined. A now < lock reading means a lagging or lying node — fail-closed
    # (refuse to assess) rather than computing an optimistic SAFE off bad data.
    if now_rxd_height < asset_locked_at_height:
        raise ValidationError(
            f"now_rxd_height ({now_rxd_height}) < asset_locked_at_height ({asset_locked_at_height}) "
            "is impossible on an honest chain (lagging/lying node); fail-closed"
        )
    try:
        rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        # Reserves round UP when seconds-tagged (flooring under-counts a reserve — unsafe);
        # t_rxd above floors, which is safe for a deadline (only shrinks the window).
        flat_burial = _reserve_to_blocks(policy.rxd_claim_burial, policy.block_interval_s)
        # VALUE-SCALED burial (red-team HIGH): the taker's claim must bury deep enough that
        # reorging it costs at least the value at stake; the flat burial is only a FLOOR.
        # Effective value: the explicit per-assessment value (watchtower per-record) overrides
        # the policy's operator-assessed value (coordinator).
        effective_value = value_at_risk_photons if value_at_risk_photons is not None else policy.value_at_risk_photons
        rxd_burial = max(flat_burial, _value_scaled_burial_blocks(policy, effective_value))
        required_depth_blocks = _reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s)
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - normalize_to only raises ValidationError
        raise ValidationError(f"could not normalise reorg depths to blocks: {exc}") from exc

    # Value-scaling configured (a reorg cost is set) but no value to scale against → we CANNOT
    # certify the claim is buried deep enough for its value. Fail closed (never a value-blind
    # SAFE): the watchtower hits this for an FT/NFT swap whose economic value it cannot read
    # off-chain; route to a decision (SQUEEZED → PAGE_SQUEEZED), never an optimistic claim. The
    # coordinator never reaches here unscaled — its setup gate requires value+cost or
    # accept_flat_burial (cost None) at construction.
    if policy.rxd_reorg_cost_per_block is not None and effective_value is None:
        return ClaimFinality.SQUEEZED

    # The maker's CSV refund opens here (Radiant blocks).
    refund_opens_at = asset_locked_at_height + rxd_blocks
    # To claim SAFELY from now we still need: bury our own claim rxd_burial deep,
    # which (if the counter-leg claim weren't yet final) would also require waiting out
    # the remaining counter-chain depth first. The binding deadline is refund_opens_at.
    blocks_left = refund_opens_at - now_rxd_height

    state = counter_claim_finality.state
    if state is CounterClaimState.COUNTER_CHAIN_NOT_FINALIZING:
        # RF-06: the counter chain is not advancing finalization — never WAIT on a stall.
        return ClaimFinality.SQUEEZED
    if state is CounterClaimState.FINAL:
        # Counter-leg claim is final/reorg-safe. Claim iff our own burial still fits.
        if blocks_left >= rxd_burial:
            return ClaimFinality.SAFE
        return ClaimFinality.SQUEEZED
    # NOT_YET_FINAL_LIVE: the counter-leg claim is not yet final. We can WAIT only if, after
    # the counter leg finalizes, there is STILL room to bury our own claim before the refund
    # opens. The RXD-block reserve that finalization consumes is chain-specific:
    if counter_claim_finality.required_depth is not None:
        # PoW (depth-based) leg. §9 #2: the verdict's depth MUST equal the policy depth, so the
        # FINAL decision (driven by the verdict) and this reserve (from the policy) cannot
        # diverge — fail-closed on a mismatch. The F-007 conversion is otherwise unchanged.
        if counter_claim_finality.required_depth != required_depth_blocks:
            raise ValidationError(
                f"finality verdict required_depth ({counter_claim_finality.required_depth}) != policy "
                f"reorg depth ({required_depth_blocks}) — refusing to assess on a divergent reserve"
            )
        # F-007: the reorg depth is in counter-chain blocks; convert the wall-clock it
        # represents into RXD blocks before subtracting (the rates differ; round UP).
        counter_reserve_rxd = math.ceil(required_depth_blocks * policy.block_interval_s / policy.rxd_block_interval_s)
    else:
        # Finalized-checkpoint (ETH) leg: finality is a TIME window, not a block depth (§9 #3).
        if policy.eth_finalization_window_s is None:
            raise ValidationError(
                "a finalized-checkpoint (no-depth) finality verdict requires "
                "policy.eth_finalization_window_s (the counter-chain finalization window)"
            )
        # Convert the finalization TIME window into RXD blocks; round UP (ceil) — this is a RESERVE,
        # so flooring would under-count it and let the gate say WAIT with too little margin. Same
        # direction as the depth branch above and reserve_to_blocks(); never floor a reserve.
        counter_reserve_rxd = math.ceil(policy.eth_finalization_window_s / policy.rxd_block_interval_s)
    if blocks_left - counter_reserve_rxd >= rxd_burial and counter_claim_finality.remaining_positive:
        return ClaimFinality.WAIT
    return ClaimFinality.SQUEEZED


# ---------------------------------------------------------------------------
# Pluggable indexer + seen-store interfaces (duck-typed; fail-closed contract)
# ---------------------------------------------------------------------------
#
# These are duck-typed: any object with the named methods works (a real RXinDexer
# client in production, a fake in tests). We document the contract here rather than
# enforce a Protocol — the failure semantics (indexer-unavailable => fail-closed)
# are what matter, and they live in the gate functions below.
#
#   RefAuthenticityIndexer (gravity.ref_authenticity):
#     async resolve_ref(genesis_ref: bytes) -> ResolvedRef | None
#       Resolves the genesis ref to its on-chain reveal (genesis outpoint, `gly`
#       marker, payload hash, confirmations). The pre-lock gate routes this through
#       ``verify_ref_authenticity`` (async), which binds the resolved reveal to the
#       advertised asset and fails closed on None / missing field / shallow genesis
#       / indexer error — never an optimistic pass. It is async because a SYNC gate
#       calling the async indexer would leak a truthy un-awaited coroutine = fail-OPEN.
#
#   SeenStore (H-freshness; replay / free-option defence):
#     reserve(hashlock: bytes) -> bool
#       ATOMIC test-and-set: record H and return True if unseen, else return False.
#       The coordinator's authoritative consume — called PRE-broadcast in
#       taker_funds_btc so a concurrent/repeat funder of the same H is refused
#       before any BTC moves (TOCTOU-1). A reused H is rejected for BOTH reasons:
#       economic (free-option replay) and collision/cross-swap preimage replay.
#     has_seen(hashlock: bytes) -> bool
#       Read-only advisory probe (the pre-lock gate's cheap early-reject); NEVER the
#       binding decision. A future durable impl declares ``durable = True`` and MUST
#       stay non-blocking (asyncio.to_thread behind an async reserve) and fsync the
#       reservation BEFORE the broadcast. The wired in-memory store is NON-durable
#       (durable = False) — freshness does NOT survive a restart or a second process;
#       the coordinator refuses it on a value-bearing network unless
#       CoordinatorConfig(accept_nondurable_seen=True) is set (single-process,
#       fresh-H-per-run runbooks only).


@dataclass(frozen=True)
class PreBtcLockGate:
    """Result of the pre-BTC-lock validation gate (plan H4(a))."""

    ok: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# The coordinator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CoordinatorConfig:
    """Tunables for :class:`SwapCoordinator`."""

    margin_policy: MarginPolicy
    # N: how many blocks before t_RXD maturity the taker proactively refunds (C1).
    maker_stall_safety_window_blocks: int = 6
    # Min confirmations the advertised asset's GENESIS tx must have before the taker
    # funds (ref-authenticity binding (e) — a shallow genesis can be reorged out
    # after payment, voiding the provenance the taker relied on).
    min_ref_confirmations: int = 6
    # Explicit opt-in to run a value-bearing swap with a NON-durable (in-process)
    # seen-store. A non-durable store loses H-freshness on a restart / second process
    # (SEEN-1), so the coordinator refuses one on a value-bearing network unless this
    # is set. Acceptable only for a single-process, single-shot, fresh-H-per-run
    # runbook (the dust harness); a long-lived / multi-process deployment needs a
    # durable store (audit track), not this flag.
    accept_nondurable_seen: bool = False
    # Explicit opt-in to run a VALUE-BEARING ETH (finalized-checkpoint) counter-leg swap
    # with an ESTIMATED (is_measured=False) margin policy. is_measured gates TWO ETH
    # defenses — the verify->lock 'finalized' reorg pin (a 'latest' re-verify cannot catch
    # a reorg that re-deploys a different contract at the same CREATE address) and the
    # proactive-refund N-floor — so the coordinator refuses a value-bearing ETH swap on an
    # estimated policy unless this is set (whole-stack audit MEDIUM-1). Acceptable only for
    # an operator-gated DUST run that consciously accepts estimated-margin risk on
    # negligible value; a real (non-dust) value-bearing ETH swap MUST use a measured policy.
    accept_estimated_eth_margins: bool = False
    # Min confirmations a gating credential's live UTXO must have (reorg safety),
    # when a swap sets terms.credential_ref. Mirrors min_ref_confirmations.
    min_credential_confirmations: int = 6

    def __post_init__(self) -> None:
        if not isinstance(self.margin_policy, MarginPolicy):
            raise ValidationError("margin_policy must be a MarginPolicy")
        w = self.maker_stall_safety_window_blocks
        if not isinstance(w, int) or isinstance(w, bool) or w < 0:
            raise ValidationError("maker_stall_safety_window_blocks must be a non-negative int")
        c = self.min_ref_confirmations
        if not isinstance(c, int) or isinstance(c, bool) or c < 0:
            raise ValidationError("min_ref_confirmations must be a non-negative int")
        cc = self.min_credential_confirmations
        if not isinstance(cc, int) or isinstance(cc, bool) or cc < 0:
            raise ValidationError("min_credential_confirmations must be a non-negative int")
        if not isinstance(self.accept_nondurable_seen, bool):
            raise ValidationError("accept_nondurable_seen must be a bool")
        if not isinstance(self.accept_estimated_eth_margins, bool):
            raise ValidationError("accept_estimated_eth_margins must be a bool")


def _serialized_step(method):
    """Serialize an FSM-advancing coordinator step under the per-instance lock.

    Defense-in-depth for a future concurrent driver (orderbook / watchtower / batch
    runner): one coordinator instance processes ONE swap step at a time, so a driver
    that fires two steps on the same instance concurrently cannot interleave a
    check-then-advance across an ``await``. The dangerous same-H double-fund is
    already closed by the atomic pre-broadcast ``reserve()``; this additionally
    serializes the consensus-backstopped sibling steps (claim / refund) so a buggy
    concurrent caller gets clean sequential execution instead of redundant
    broadcasts + a spurious FSM-transition error. The lock is per-instance, so it
    does NOT serialize independent swaps (each has its own coordinator). Read-only
    gates (``pre_btc_lock_check``) are intentionally NOT wrapped — they hold no lock
    and may be called from within a wrapped method (a reentrant acquire would
    deadlock).
    """

    @functools.wraps(method)
    async def _wrapper(self, *args, **kwargs):
        async with self._step_lock:
            return await method(self, *args, **kwargs)

    return _wrapper


def _leg_is_value_bearing(leg: object) -> bool:
    """True if a chain leg is tagged for a value-bearing network.

    Reuses the SAME definition as the leg audit gate
    (:data:`pyrxd.btc_wallet.htlc_leg.AUDIT_CLEARED_NETWORKS`): a non-empty
    ``network`` tag NOT in that set moves real value. A leg with no ``network``
    attribute (e.g. a test fake) is treated as non-value-bearing.
    """
    net = getattr(leg, "network", None)
    return isinstance(net, str) and bool(net) and net not in AUDIT_CLEARED_NETWORKS


class SwapCoordinator:
    """Drive the swap FSM for one live participant against injected chain legs.

    Parameters
    ----------
    record:
        The :class:`SwapRecord` (durable state). The coordinator advances and
        returns NEW records (frozen dataclass); it does not mutate in place. Persist
        the returned record after every step (crash-recovery is from the record).
    btc_leg / radiant_leg:
        Duck-typed chain legs. The BTC leg derives/funds/claims/refunds the P2TR
        HTLC and exposes the covenant-SPK derivation the gates need; the Radiant leg
        wraps the claim/refund builders. In tests these are fakes.
    indexer:
        Duck-typed ``RefIndexer`` (``verify_ref``). Indexer-unavailable => fail-closed.
    seen_store:
        Duck-typed ``SeenStore`` (``reserve``/``has_seen``) — H-freshness replay
        defence. A non-durable (in-process) store is refused on a value-bearing
        network unless ``config.accept_nondurable_seen`` is set.
    config:
        :class:`CoordinatorConfig` (margin policy + maker-stall window).
    persist:
        Optional ``async (SwapRecord) -> None`` durable-write hook. When supplied,
        the coordinator persists the *intent* record BEFORE an awaited broadcast and
        ``asyncio.shield()``-s the post-broadcast persist, so a task cancelled
        between "BTC is locked on-chain" and "record advanced" cannot double-fund on
        retry (kieran-python HIGH). ``None`` disables durability (tests that do not
        exercise crash-atomicity); the in-memory record still advances.
    """

    def __init__(
        self,
        *,
        record,
        counter_leg=None,
        btc_leg=None,
        radiant_leg,
        indexer,
        seen_store,
        config: CoordinatorConfig,
        persist: PersistHook | None = None,
        credential_resolver=None,
    ) -> None:
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        if not isinstance(config, CoordinatorConfig):
            raise ValidationError("config must be a CoordinatorConfig")
        if persist is not None and not callable(persist):
            raise ValidationError("persist must be an async callable or None")
        # Counter leg: the chain-neutral ``counter_leg`` (preferred) OR the legacy
        # ``btc_leg`` (transitional alias) — exactly one. The BTC path may pass either;
        # an ETH swap passes ``counter_leg=EthLeg``.
        if counter_leg is not None and btc_leg is not None:
            raise ValidationError("pass counter_leg OR btc_leg, not both")
        leg = counter_leg if counter_leg is not None else btc_leg
        if leg is None:
            raise ValidationError("a counter_leg (or btc_leg) is required")
        # SEEN-1 guard: refuse a NON-durable (in-process) seen-store on a
        # value-bearing network unless the operator explicitly accepts it. A
        # non-durable store loses H-freshness on a restart / second process, so a
        # long-lived or multi-process value-moving deployment would silently
        # re-open the replay / free-option window. ``durable`` defaults False for
        # any store that does not declare itself durable (fail-closed).
        store_durable = bool(getattr(seen_store, "durable", False))
        value_bearing = _leg_is_value_bearing(leg) or _leg_is_value_bearing(radiant_leg)
        if value_bearing and not store_durable and not config.accept_nondurable_seen:
            raise ValidationError(
                "seen-store is NON-durable (in-process only) but the coordinator is wired to a "
                "value-bearing network: a restart or a second process resurrects the H-replay / "
                "free-option window (SEEN-1). Use a durable SeenStore (durable=True), or pass "
                "CoordinatorConfig(accept_nondurable_seen=True) to consciously accept "
                "non-durability for a single-process, single-shot, fresh-H-per-run runbook."
            )
        # VALUE-SCALED BURIAL (red-team 2026-06-12 HIGH): the taker's Radiant asset-claim is
        # deemed reorg-safe at a FLAT burial that is never scaled to value. On a low-cap PoW
        # chain a swap worth more than the marginal cost to reorg a few Radiant blocks is
        # economically reversible. Fail-closed at setup, mirroring MEDIUM-1: a value-bearing
        # RADIANT asset (mainnet) MUST supply the economic inputs the gate value-scales from
        # (a measured per-block reorg cost + an assessed value-at-risk) OR consciously opt into a
        # flat burial via MarginPolicy(accept_flat_burial=True) for a dust run.
        if (
            _leg_is_value_bearing(radiant_leg)
            and not config.margin_policy.accept_flat_burial
            and (
                config.margin_policy.rxd_reorg_cost_per_block is None
                or config.margin_policy.value_at_risk_photons is None
            )
        ):
            raise ValidationError(
                "value-bearing Radiant asset swap without value-scaled claim burial: a flat "
                "rxd_claim_burial bounds reorg probability, not reorg COST vs. value, so a swap worth "
                "more than the marginal Radiant reorg cost is economically reversible (red-team HIGH). "
                "Set MarginPolicy.rxd_reorg_cost_per_block (measured, photons/block) AND "
                "value_at_risk_photons (the assessed economic value), or pass "
                "MarginPolicy(accept_flat_burial=True) to consciously accept a flat burial on a dust run."
            )
        # Value integrity (audit follow-up LOW): for an RXD asset, radiant_amount IS the photon
        # value at stake, so value_at_risk_photons must not be UNDER-stated below it (an
        # under-statement silently shrinks the value-scaled burial — the one scalar that defends
        # the whole HIGH fix). FT/NFT are exempt: their radiant_amount is a token amount / NFT
        # carrier dust, a different unit from the operator-assessed economic value.
        if (
            _leg_is_value_bearing(radiant_leg)
            and record.terms.asset_variant == "rxd"
            and config.margin_policy.value_at_risk_photons is not None
            and config.margin_policy.value_at_risk_photons < record.terms.radiant_amount
        ):
            raise ValidationError(
                f"value_at_risk_photons ({config.margin_policy.value_at_risk_photons}) < the RXD swap's "
                f"radiant_amount ({record.terms.radiant_amount}): an under-stated value-at-risk shrinks the "
                "value-scaled claim burial below what this swap's own on-chain value demands. Set "
                "value_at_risk_photons >= radiant_amount for an RXD swap."
            )
        # MEDIUM-1 (whole-stack audit): a VALUE-BEARING ETH counter-leg swap on an ESTIMATED
        # policy silently runs in the weak mode of two defenses — the verify->lock 'finalized'
        # reorg pin (_assert_eth_counter_funding_verified re-verifies at 'latest' when
        # is_measured=False) and the proactive-refund N-floor (both gated on is_measured).
        # Unlike the BTC path, nothing else couples value↔measured for ETH, and a 'latest'
        # re-verify cannot catch a reorg re-deploying a different contract at the same CREATE
        # address in the verify->lock window → one-sided maker loss. Refuse it unless the
        # operator consciously accepts estimated margins (dust runs); fail-closed at setup so a
        # future value-bearing ETH run cannot inherit is_measured=False by accident.
        if (
            value_bearing
            and record.terms.counter_chain != "btc"
            and not config.margin_policy.is_measured
            and not config.accept_estimated_eth_margins
        ):
            raise ValidationError(
                "value-bearing ETH counter-leg swap with an ESTIMATED margin policy "
                "(is_measured=False): the verify->lock 'finalized' reorg pin AND the "
                "proactive-refund N-floor are both disabled (MEDIUM-1). Use MarginPolicy.measured(...), "
                "or pass CoordinatorConfig(accept_estimated_eth_margins=True) to consciously accept "
                "estimated-margin risk on an operator-gated dust run."
            )
        # ETH (finalized-checkpoint) counter leg requires a finalization window on the policy
        # (audit finality/fsm fail-closed-at-setup): the reorg gate's no-depth WAIT-branch
        # reserve is derived from eth_finalization_window_s. Without it the gate can only fail
        # at claim time — the worst moment. The counter chain is known here, so refuse now.
        if record.terms.counter_chain != "btc" and config.margin_policy.eth_finalization_window_s is None:
            raise ValidationError(
                f"counter_chain={record.terms.counter_chain!r} (finalized-checkpoint leg) requires "
                "MarginPolicy.eth_finalization_window_s to be set; the reorg gate's finalization reserve "
                "depends on it — refusing to construct a coordinator that can only fail at claim time"
            )
        # ETH proactive-refund window must DOMINATE the finality+burial reserve (red-team HIGH: a maker
        # can time its reveal into a SQUEEZE window the taker cannot safely act in if the C1 window N is
        # decoupled from the ETH finality reserve). N must give the taker enough RXD blocks to (a) wait
        # out ETH finalization AND (b) bury its own RXD claim reorg-deep before t_rxd matures — else the
        # proactive-refund decision and the reorg-gate squeeze disagree. Enforced fail-closed for a
        # REAL-VALUE config (is_measured); an estimated/test config (is_measured=False) is an explicit
        # placeholder whose margin magnitudes are operator-accepted-risk (same discipline as the margin
        # itself), so the floor is advisory there — a real-value swap MUST be is_measured=True.
        if record.terms.counter_chain != "btc" and config.margin_policy.is_measured:
            mp = config.margin_policy
            fin_reserve_blocks = math.ceil(mp.eth_finalization_window_s / mp.rxd_block_interval_s)
            # Use the SAME burial reserve the reorg gate uses (assess_claim_finality:
            # _reserve_to_blocks(policy.rxd_claim_burial, ...)) — NOT the hardcoded estimate (red-team
            # LOW): an operator who measures a burial != 6 would otherwise get a floor that blesses an
            # N the gate's actual (larger) squeeze reserve makes insufficient — false assurance.
            burial_blocks = _reserve_to_blocks(mp.rxd_claim_burial, mp.block_interval_s)
            min_n = fin_reserve_blocks + burial_blocks - 1
            if config.maker_stall_safety_window_blocks < min_n:
                raise ValidationError(
                    f"maker_stall_safety_window_blocks={config.maker_stall_safety_window_blocks} is below the "
                    f"ETH finality+burial reserve floor {min_n} (= ceil(eth_finalization_window_s "
                    f"{mp.eth_finalization_window_s}/rxd_block_interval_s {mp.rxd_block_interval_s})={fin_reserve_blocks} "
                    f"+ burial {burial_blocks} - 1); a maker could time its reveal into a "
                    "SQUEEZE window the taker cannot safely act in — raise N or shrink the window"
                )
        # One coordinator instance = one swap. This lock serializes the FSM-advancing
        # steps (see @_serialized_step) so a future concurrent driver cannot interleave
        # a check-then-advance across an await on a single instance.
        self._step_lock = asyncio.Lock()
        self.record = record
        self.counter_leg = leg
        self.radiant_leg = radiant_leg
        self.indexer = indexer
        self.seen_store = seen_store
        self.config = config
        self._persist = persist
        # Optional credential-gating resolver (duck-typed CredentialResolver). Required
        # only when a swap sets terms.credential_ref; its absence then fails closed.
        self._credential_resolver = credential_resolver

    @property
    def btc_leg(self):
        """Transitional alias for ``counter_leg`` (the chain-neutral counter leg)."""
        return self.counter_leg

    # -- internal: advance + persist-shape ----------------------------------
    def _advance(self, event: SwapEvent) -> SwapState:
        """Validate the transition via the pure FSM and update ``self.record`` (pure)."""
        new_state = advance(self.record.state, event)
        self.record = self.record.with_state(new_state)
        return new_state

    async def _persist_record(self, record: SwapRecord, *, shield: bool = False) -> None:
        """Durably write ``record`` via the injected hook (no-op if none).

        Set ``shield=True`` for the post-broadcast persist so a cancellation
        between an on-chain broadcast and the durable write cannot tear it: losing
        that write strands/duplicates funds. The pre-broadcast intent persist is
        NOT shielded — cancelling before the broadcast is safe (nothing happened).
        """
        if self._persist is None:
            return
        if shield:
            await asyncio.shield(self._persist(record))
        else:
            await self._persist(record)

    # -- pre-BTC-lock gate (H4 a) -------------------------------------------
    async def pre_btc_lock_check(self, terms: NegotiatedTerms, *, now_unix_s: int | None = None) -> PreBtcLockGate:
        """Validate everything the taker can check BEFORE funding the counter leg (fail-closed).

        Checks, in order (any failure => do NOT fund):
          1. REF authenticity via ``verify_ref_authenticity`` — the resolved reveal
             must bind to the ADVERTISED asset (genesis-outpoint==ref, `gly` marker,
             optional payload hash, ≥ ``min_ref_confirmations``). Indexer
             unavailable / shallow genesis / wrong asset => fail-closed.
          2. H freshness — a read-only advisory probe of the seen-store (reused H
             => reject early). The authoritative atomic reserve happens later, in
             :meth:`taker_funds_btc`, immediately before the broadcast.
          3. The cross-chain timelock ordering. BTC: the same-clock margin
             ``t_btc - t_rxd >= margin``. ETH: the cross-clock gate that validates the
             ABSOLUTE ``eth_timeout_unix_s`` leaves room for the RELATIVE ``t_rxd`` window
             (needs ``now_unix_s``; audit HIGH-1). The orphaned bridge is wired here.
          4. Maker-*promised* params match the locally re-derived BTC funding SPK
             (the on-chain re-validation happens later in
             :meth:`post_asset_lock_revalidate`).

        ``now_unix_s`` is the caller's wall-clock (the ``now_rxd_height`` precedent: the
        coordinator takes clocks as params, never reads them) — REQUIRED for an ETH swap,
        ignored for BTC. Async because binding (1) awaits the async indexer adapter (a sync
        gate would leak a truthy un-awaited coroutine = fail-OPEN, T7 plan D2).
        """
        if not isinstance(terms, NegotiatedTerms):
            raise ValidationError("pre_btc_lock_check requires NegotiatedTerms")

        # 1. REF authenticity bound to the ADVERTISED asset (FT/NFT carry a ref;
        #    rxd is a no-op inside the gate). verify_ref_authenticity RAISES on any
        #    uncertain outcome (None / missing field / shallow / indexer error) —
        #    we convert that to a fail-closed gate result, never an optimistic pass.
        try:
            await verify_ref_authenticity(
                self.indexer,
                terms.genesis_ref,
                asset_variant=terms.asset_variant,
                min_confirmations=self.config.min_ref_confirmations,
            )
        except ValidationError as exc:
            return PreBtcLockGate(ok=False, reason=f"REF authenticity failed; fail-closed ({exc})")

        # 1b. Credential binding (only when the swap is credential-gated). Confirms the
        #     taker holds a GENUINE consensus-soulbound credential (not a metadata flag)
        #     AND that the swap's pinned payout (taker_dest_hash) pays the credential's
        #     owner. Soulbound permanence => owner is immutable, so binding the payout to
        #     it defeats both resale and rental without co-spending. Fail-closed.
        if terms.credential_ref:
            if self._credential_resolver is None:
                return PreBtcLockGate(
                    ok=False, reason="swap is credential-gated but no credential_resolver is wired; fail-closed"
                )
            try:
                cred = await self._credential_resolver.resolve_credential(terms.credential_ref)
                if cred is None:
                    return PreBtcLockGate(
                        ok=False, reason="credential ref did not resolve (unknown/spent); fail-closed"
                    )
                owner = assert_soulbound_credential(
                    cred,
                    min_confirmations=self.config.min_credential_confirmations,
                    expected_credential_ref=terms.credential_ref,
                )
                expected = holder_hash(owner, variant=terms.asset_variant, genesis_ref=terms.genesis_ref)
                if expected != terms.taker_dest_hash:
                    return PreBtcLockGate(
                        ok=False,
                        reason="credential owner is not the swap payout recipient (taker_dest_hash); rental would pass — fail-closed",
                    )
            except (CredentialBindingError, ValidationError) as exc:
                return PreBtcLockGate(ok=False, reason=f"credential binding failed; fail-closed ({exc})")
            except Exception as exc:
                return PreBtcLockGate(ok=False, reason=f"credential resolver unavailable; fail-closed ({exc})")

        # 2. H freshness — advisory read-only probe for a clean early reject; the
        #    authoritative atomic reserve is in taker_funds_btc, pre-broadcast.
        try:
            if self.seen_store.has_seen(terms.hashlock):
                return PreBtcLockGate(ok=False, reason="hashlock H reused (free-option / preimage-replay risk)")
        except Exception as exc:
            return PreBtcLockGate(ok=False, reason=f"seen-store unavailable; fail-closed ({exc})")

        # 3. Cross-chain timelock ordering (fail-closed). BTC: same-clock margin. ETH: the
        #    cross-clock gate against the ABSOLUTE eth_timeout_unix_s (audit HIGH-1).
        try:
            if terms.counter_chain == "btc":
                assert_timelock_margin(terms.t_btc, terms.t_rxd, self.config.margin_policy)
            else:
                self._assert_eth_timelock_ordering(terms, now_unix_s=now_unix_s)
        except ValidationError as exc:
            return PreBtcLockGate(ok=False, reason=f"margin check failed: {exc}")

        # 4. Maker-promised BTC params match locally re-derived funding SPK.
        try:
            expected_spk = self.counter_leg.derive_funding_scriptpubkey(terms)
            promised_spk = self.counter_leg.promised_funding_scriptpubkey(terms)
        except Exception as exc:
            return PreBtcLockGate(ok=False, reason=f"could not derive BTC funding SPK; fail-closed ({exc})")
        if expected_spk != promised_spk:
            return PreBtcLockGate(ok=False, reason="maker-promised BTC params do not match re-derived funding SPK")

        return PreBtcLockGate(ok=True)

    def _assert_eth_timelock_ordering(self, terms: NegotiatedTerms, *, now_unix_s: int | None) -> None:
        """ETH cross-clock ordering gate (audit HIGH-1) — wires the previously-orphaned
        :mod:`pyrxd.gravity.eth_rxd_timelock` bridge into the live pre-fund path.

        The HTLC ordering invariant requires the counter-leg (ETH) refund to open strictly
        AFTER the asset (RXD) refund, minus the cross-clock margin. For ETH the real deadline
        is the ABSOLUTE ``terms.eth_timeout_unix_s`` (a contract immutable), NOT the relative
        ``t_btc`` placeholder — so the BTC-shaped ``assert_timelock_margin(t_btc, t_rxd)`` is
        the WRONG gate here. We instead project where the RXD CSV refund opens (covenant mines
        ~``now + max_covenant_confirm_wait`` then counts ``t_rxd`` blocks) and refuse unless it
        lands before ``eth_timeout - margin``. This also closes the now-vs-timeout grief: an
        already-expired or near-expiry ``eth_timeout_unix_s`` makes the projected open exceed
        the deadline, so the gate refuses to fund. Fail-closed on any missing input.
        """
        policy = self.config.margin_policy
        if now_unix_s is None:
            raise ValidationError("an ETH swap requires now_unix_s (wall-clock) to validate cross-clock ordering")
        if terms.eth_timeout_unix_s is None:
            raise ValidationError("ETH swap missing eth_timeout_unix_s (the absolute refund deadline)")
        if policy.cross_clock_margin is None or policy.max_covenant_confirm_wait_s is None:
            raise ValidationError(
                "ETH swap requires MarginPolicy.cross_clock_margin and max_covenant_confirm_wait_s "
                "for the cross-clock ordering gate"
            )
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=now_unix_s,
            eth_timeout_unix_s=terms.eth_timeout_unix_s,
            margin=policy.cross_clock_margin,
            t_rxd=terms.t_rxd,
            rxd_block_interval_s=policy.rxd_block_interval_s,
            max_covenant_confirm_wait_s=policy.max_covenant_confirm_wait_s,
        )

    # -- taker funds the counter leg first (the role invariant's step 2) ----------------
    @_serialized_step
    async def taker_funds_btc(self, terms: NegotiatedTerms, *, now_unix_s: int | None = None) -> SwapRecord:
        """Run the pre-lock gate, fund the counter-leg HTLC, record the locator, advance.

        Refuses (raises) if the pre-lock gate fails — the taker NEVER funds against a
        failed gate. H is ATOMICALLY reserved in the seen-store PRE-broadcast (so a
        concurrent or repeat funder of the same H is refused before any value moves;
        TOCTOU-1), and the durable record carries the full counter-leg locator.

        ``now_unix_s`` is the caller's wall-clock — REQUIRED for an ETH swap (the cross-clock
        timelock-ordering gate, audit HIGH-1), ignored for BTC (byte-equivalent).

        Atomicity (kieran-python HIGH): ``counter_leg.fund`` broadcasts on-chain, so a
        cancellation between the broadcast and the in-memory state advance would
        leave value locked but the record at NEGOTIATED → a retry double-funds. We
        persist an INTENT record (terms + derived funding SPK, enough to recover the
        address) BEFORE the awaited fund, and ``asyncio.shield()`` the post-broadcast
        persist of the funded record. ``fund`` itself must be idempotent (treat
        "already in mempool" as success) so a retry after an intent-only crash does
        not lock twice. Persistence is a no-op when no ``persist`` hook is injected.
        """
        if self.record.state is not SwapState.NEGOTIATED:
            raise ValidationError(f"taker_funds_btc only valid from NEGOTIATED, not {self.record.state.value}")
        gate = await self.pre_btc_lock_check(terms, now_unix_s=now_unix_s)
        if not gate.ok:
            raise ValidationError(f"pre-BTC-lock gate refused funding: {gate.reason}")

        # Persist intent BEFORE broadcasting: the SPK is derivable pre-fund, so a
        # crash after this write but before/within the broadcast leaves a record
        # that knows WHERE the HTLC address is (recoverable), not a silent gap.
        await self._persist_record(self.record)

        # Reserve H ATOMICALLY and PRE-broadcast (TOCTOU-1 fix). The check-and-mark
        # is one indivisible step strictly before the only on-chain effect below, so
        # two concurrent funders of the same H race here and exactly one wins — the
        # other is refused with nothing broadcast. A raising store fails CLOSED
        # (refuse to fund), never open. H is consumed at this COMMIT point, not after
        # fund() succeeds: an on-chain-locked HTLC has used its H, and a transient
        # post-fund failure must not re-open the free-option / preimage-replay window.
        try:
            reserved = self.seen_store.reserve(terms.hashlock)
        except Exception as exc:
            raise ValidationError(f"seen-store unavailable; fail-closed ({exc})") from exc
        if not reserved:
            raise ValidationError("hashlock H already reserved; refusing to fund (free-option / preimage-replay)")

        locator = await self.counter_leg.fund(terms)
        if not isinstance(locator, (BtcHtlcLocator, EthHtlcLocator)):
            raise ValidationError("counter_leg.fund must return a Btc/Eth HtlcLocator (full durable retained state)")
        # Bind the funded amount to the negotiated price. A P2TR scriptPubKey commits to
        # the taptree, NOT the output value (and an ETH HTLC contract address commits to
        # immutables, not the funded balance), so the funding-target check in
        # pre_btc_lock_check (step 4) cannot catch a wrong amount — this is the only layer
        # that can. An OVER-funded HTLC is a one-sided taker loss: the maker claims the
        # whole output via the preimage (the claim leaf does not cap value). Under-funding
        # is self-correcting (the maker won't reveal), but we reject both so a mutated
        # `terms` or a buggy leg fails closed before the counter leg is locked. The leg
        # reports the funded amount in its own unit (sats / wei) via ``locked_amount``.
        funded = self.counter_leg.locked_amount(locator)
        if funded != terms.value_amount:
            raise ValidationError(
                f"funded counter-leg amount {funded} != negotiated value_amount {terms.value_amount}; "
                "refusing to lock a mis-valued HTLC"
            )
        # (H was already reserved atomically pre-broadcast above — no post-fund mark.)
        self.record = self.record.with_counter_lock(locator)
        self._advance(SwapEvent.TAKER_FUNDS_BTC)
        # Shielded: the BTC is locked on-chain now; losing this write would
        # double-fund on retry, so it must complete even under cancellation.
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- post-asset-lock re-validation (H4 b) -------------------------------
    def _assert_eth_lock_timing_still_safe(self, *, now_unix_s: int | None) -> None:
        """Post-confirm cross-clock recheck (audit re-verify HIGH) — the bridge's prescribed
        SECOND run (:func:`assert_covenant_confirms_before_eth_deadline` docstring).

        The pre-fund ordering gate (:meth:`_assert_eth_timelock_ordering`) projects where the
        RXD CSV refund opens from the TAKER's fund time. But the MAKER locks the covenant at a
        maker-controlled time and can STALL the broadcast — pushing the ACTUAL rxd-refund-open
        (covenant_mining_time + t_rxd) past that projection and collapsing the cross-clock
        margin. We re-run the gate here at the ACTUAL lock time with
        ``max_covenant_confirm_wait_s = 0`` (the covenant is confirmed now). If the margin no
        longer holds we refuse to advance to BOTH_LOCKED — the taker must refund the counter
        leg rather than proceed into the reopened one-sided-loss window. Fail-closed.
        """
        policy = self.config.margin_policy
        terms = self.record.terms
        if now_unix_s is None:
            raise ValidationError(
                "an ETH swap requires now_unix_s at covenant-lock revalidation (post-confirm cross-clock recheck)"
            )
        if terms.eth_timeout_unix_s is None:
            raise ValidationError("ETH swap missing eth_timeout_unix_s (the absolute refund deadline)")
        if policy.cross_clock_margin is None:
            raise ValidationError("ETH swap requires MarginPolicy.cross_clock_margin for the post-confirm recheck")
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=now_unix_s,
            eth_timeout_unix_s=terms.eth_timeout_unix_s,
            margin=policy.cross_clock_margin,
            t_rxd=terms.t_rxd,
            rxd_block_interval_s=policy.rxd_block_interval_s,
            max_covenant_confirm_wait_s=0,  # the covenant is CONFIRMED now — no future wait budget
        )

    @_serialized_step
    async def post_asset_lock_revalidate(
        self, observed_covenant_spk: bytes, *, now_unix_s: int | None = None
    ) -> SwapRecord:
        """Re-check the on-chain covenant SPK == expected-from-terms+H.

        Called when the maker locks the asset. The expected SPK is recomputed from
        the negotiated terms + H (the constructor params bind hashlock/refundCsv/
        amount/dest-hashes/REF into the covenant bytecode). On match => BOTH_LOCKED.
        On mismatch => PARAMS_MISMATCH; the caller then refunds the BTC via the
        timelock leg (see :meth:`taker_refund_btc`).

        ``now_unix_s`` is the caller's wall-clock at the moment the covenant lock is observed —
        REQUIRED for an ETH swap (the post-confirm cross-clock recheck against a stalled maker
        lock; audit re-verify HIGH), ignored for BTC. On an ETH timing failure this refuses to
        advance to BOTH_LOCKED (raises) so the taker refunds the counter leg.

        Async because the Radiant leg reads chain state (expected-SPK derivation +
        covenant outpoint lookup) over the async indexer/node.
        """
        if self.record.state is not SwapState.BTC_LOCKED:
            raise ValidationError(
                f"post_asset_lock_revalidate only valid from BTC_LOCKED, not {self.record.state.value}"
            )
        observed = bytes(observed_covenant_spk)
        try:
            expected = await self.radiant_leg.expected_covenant_scriptpubkey(self.record.terms)
        except Exception as exc:
            # Cannot recompute the expected SPK => treat as mismatch (fail-closed):
            # the taker has BTC locked and must be able to recover.
            self.record = self.record.with_radiant_lock("<unverifiable>", observed.hex())
            self._advance(SwapEvent.MAKER_LOCKS_WRONG_PARAMS)
            await self._persist_record(self.record, shield=True)
            raise ValidationError(f"could not recompute expected covenant SPK; PARAMS_MISMATCH ({exc})") from exc

        outpoint = await self.radiant_leg.covenant_outpoint(self.record.terms)
        self.record = self.record.with_radiant_lock(outpoint, observed.hex())
        if observed != bytes(expected):
            self._advance(SwapEvent.MAKER_LOCKS_WRONG_PARAMS)
            await self._persist_record(self.record, shield=True)
            return self.record
        # ETH post-confirm gate (audit re-verify HIGH + red-team HIGH): the SPK is right, but for an
        # ETH counter leg two more things must hold before BOTH_LOCKED — which is the precondition
        # for maker_claims_btc (the p-reveal). (1) The maker's counter-funding verification MUST have
        # run and must STILL hold, re-checked here pinned to finality so a reorg cannot have replaced
        # the taker's deploy after it was verified (the TOCTOU). (2) A maker who DELAYED the covenant
        # broadcast may have collapsed the cross-clock margin the pre-fund gate projected. Either
        # failure refuses BOTH_LOCKED (persist for recovery + raise) so the maker never reveals p
        # against an unverified/reorg-replaced or timing-collapsed counter leg — it refunds the
        # covenant via CSV instead of entering the one-sided-loss window.
        if self.record.terms.counter_chain != "btc":
            await self._assert_eth_counter_funding_verified(now_unix_s=now_unix_s)
        self._advance(SwapEvent.MAKER_LOCKS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    async def _assert_eth_counter_funding_verified(self, *, now_unix_s: int | None) -> None:
        """ETH-leg precondition for BOTH_LOCKED (red-team HIGH): the maker-side counter-funding gate
        must be enforced, not optional. We REQUIRE a verified EthHtlcLocator on the record (so
        ``maker_verify_counter_funding`` cannot be skipped on the two-party maker path — advancing to
        the reveal-enabling BOTH_LOCKED without it is impossible) and RE-RUN the verification here,
        pinned to the ``finalized`` checkpoint for a real-value (``is_measured``) swap, so a reorg
        cannot have re-deployed a DIFFERENT contract at the same CREATE address between the maker's
        verify and this RXD lock (the verify->lock TOCTOU; an estimated/test config re-binds at
        'latest', same is_measured discipline as the N-floor + cross-clock margin). Finally re-check
        the cross-clock timing. Any failure persists for recovery and raises (fail-closed)."""
        locator = self.record.counterchain_locator
        if not isinstance(locator, EthHtlcLocator):
            await self._persist_record(self.record, shield=True)
            raise ValidationError(
                "ETH counter-funding was never verified (no EthHtlcLocator on record); "
                "maker_verify_counter_funding MUST run before locking RXD — refusing BOTH_LOCKED "
                "(the maker should refund the covenant via CSV)"
            )
        verify = getattr(self.counter_leg, "verify_counterparty_funded", None)
        if verify is None:
            await self._persist_record(self.record, shield=True)
            raise ValidationError("counter_leg does not implement verify_counterparty_funded; fail-closed")
        block_id = "finalized" if self.config.margin_policy.is_measured else None
        try:
            reverified = await verify(locator.contract_address, self.record.terms, block_identifier=block_id)
            self.record = self.record.with_counter_lock(reverified)
            self._assert_eth_lock_timing_still_safe(now_unix_s=now_unix_s)
        except ValidationError:
            await self._persist_record(self.record, shield=True)
            raise

    # -- maker verifies the taker's counter-leg HTLC before locking the asset (red-team CRITICAL) --
    @_serialized_step
    async def maker_verify_counter_funding(self, counter_contract_address: str) -> SwapRecord:
        """MAKER-side fail-closed gate (red-team CRITICAL fix): the maker MUST verify the
        TAKER-deployed counter-leg HTLC binds to the negotiated terms + the maker's own payout
        config BEFORE the maker locks the asset (funds the RXD covenant). Returns on success
        (recording the verified locator on the record so :meth:`maker_claims_btc` can claim it);
        RAISES on any mismatch — the maker MUST NOT lock the asset if this raises.

        WHY THIS EXISTS: the runbook is TAKER-funds-counter-FIRST, MAKER-locks-asset-SECOND. For a
        BTC counter leg the funding target is a pure function of terms, so the coordinator's
        ``derive==promised`` pre-fund gate + the funding reader already bind it. For an ETH counter
        leg there is NO pre-fund commitment — the contract does not exist until the taker deploys it
        — so ``EthHtlcContractLeg.verify_funded`` is the ONLY thing binding the taker's contract to
        terms, and it previously ran ONLY inside the taker's own ``fund()``. Without this maker-side
        call a hostile taker deploys ``claimant=self`` (or underfunds / sets a bad timeout) and the
        honest maker locks the asset for nothing — a one-sided maker loss reachable in the intended
        two-party flow. The maker passes ONLY the contract ADDRESS (the one untrusted input from the
        taker); the leg builds the EXPECTED locator from the maker's own config and verifies the
        chain matches it.

        ``counter_contract_address`` is the address the taker advertises for its deployed HTLC."""
        terms = self.record.terms
        if terms.counter_chain != "eth":
            raise ValidationError(
                "maker_verify_counter_funding is for an ETH counter leg; a BTC counter leg's funding "
                "target is pre-derivable and bound by the derive==promised gate"
            )
        verify = getattr(self.counter_leg, "verify_counterparty_funded", None)
        if verify is None:
            raise ValidationError("counter_leg does not implement verify_counterparty_funded; fail-closed")
        # Raises on any mismatch (wrong claimant/refundee/H/timeout/amount/logic). The maker MUST NOT
        # lock the asset if this raises.
        locator = await verify(counter_contract_address, terms)
        self.record = self.record.with_counter_lock(locator)
        await self._persist_record(self.record, shield=True)
        return self.record

    @_serialized_step
    async def maker_claims_btc(self, preimage: SecretBytes) -> SwapRecord:
        """Maker spends the BTC claim leaf with ``p`` (revealing it), then zeroizes p.

        Re-verifies ``sha256(p) == H`` before broadcasting (defends a swapped/garbled
        secret). The maker holds ``p`` only as :class:`SecretBytes`; it is zeroized
        immediately after the claim is handed to the BTC leg.

        ``p`` zeroization in ``finally`` runs on the cancel path too. If the awaited
        claim raises AFTER the tx hit the mempool, ``p`` is wiped from memory but is
        now public on-chain — recovery re-scrapes it from the chain, never memory.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"maker_claims_btc only valid from BOTH_LOCKED, not {self.record.state.value}")
        if not isinstance(preimage, SecretBytes):
            raise ValidationError("preimage must be SecretBytes (in-memory only; never persisted)")
        if self.record.counterchain_locator is None:
            raise ValidationError("no BTC locator on record; cannot claim")
        raw = preimage.unsafe_raw_bytes()
        if hashlib.sha256(raw).digest() != self.record.terms.hashlock:
            raise ValidationError("preimage does not hash to the negotiated H; refusing to broadcast")
        try:
            await self.counter_leg.claim(self.record.counterchain_locator, raw)
        finally:
            preimage.zeroize()
        self._advance(SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)
        await self._persist_record(self.record, shield=True)
        return self.record

    def _assert_claim_tx_spends_our_htlc(self, maker_claim_tx_bytes: bytes) -> None:
        """Provenance gate: the supplied claim tx MUST spend OUR BTC HTLC funding outpoint.

        ``scrape_secret`` matches ``p`` by ``sha256(p)==H`` over the witness pushes — it
        trusts that the caller-supplied tx belongs to THIS swap. We verify that here: a
        counterparty-supplied claim tx for a DIFFERENT swap (even one that shares ``H``)
        does not spend our funding outpoint, so we refuse to scrape/claim from it. This
        is the witness-side cross-swap-replay defence that complements the admission-side
        seen-store. Fail-closed on a missing locator or an unparseable tx.
        """
        locator = self.record.counterchain_locator
        if locator is None:
            raise ValidationError("no BTC locator on record; cannot verify claim-tx provenance")
        expected = locator.funding_outpoint.prevout_bytes()
        try:
            prevouts = btc_input_outpoints_from_raw(maker_claim_tx_bytes)
        except ValidationError as exc:
            raise ValidationError(f"could not parse claim tx inputs; fail-closed ({exc})") from exc
        if expected not in prevouts:
            raise ValidationError(
                "supplied claim tx does not spend this swap's BTC HTLC funding outpoint; "
                "refusing to scrape p (wrong or cross-swap claim tx)"
            )

    # -- taker scrapes p from the claim tx and claims the asset (step 5) ----
    @_serialized_step
    async def taker_scrape_and_claim_asset(
        self,
        maker_claim_tx_bytes: bytes,
        *,
        now_rxd_height: int,
        asset_locked_at_height: int,
    ) -> SwapRecord:
        """Scrape ``p`` and claim the asset — gated on the maker's BTC-claim finality.

        Scraping is by ``sha256(candidate) == H`` over the witness pushes (never by
        offset); the coordinator RE-verifies ``sha256(p) == H`` first — a scraped
        value that does not open H is rejected.

        **Reorg gate (security-HIGH, plan 2026-05-26).** The taker must NOT claim the
        asset off a not-yet-final BTC claim: a reorg of that claim after ``p`` is
        public reintroduces one-sided loss. Before firing the Radiant claim we read
        the maker's BTC-claim confirmation depth and run the ``t_rxd``-squeeze
        assessment (:func:`assess_claim_finality`). Three outcomes:

        * **SAFE** — claim now; advance to COMPLETED (the happy path).
        * **WAIT** — the BTC claim is too shallow but the window has room: do NOT
          claim, do NOT advance; the record stays SECRET_REVEALED and the caller
          retries later. (No state is stranded — the gate is before any advance.)
        * **SQUEEZED** — shallow claim AND the ``t_rxd`` window is closing: advance to
          ASSET_VULNERABLE (logged loudly) and STOP. The caller's policy then decides
          a best-effort winner-take-all claim via
          :meth:`taker_claim_asset_from_vulnerable` vs abandoning — never a silent
          claim off a shallow reveal.

        ``now_rxd_height`` / ``asset_locked_at_height`` feed the squeeze (the Radiant
        clock; ``asset_locked_at_height`` is where the maker locked the covenant).
        ``scrape_secret`` is sync; the depth read + Radiant claim are awaited.

        **ETH counter leg.** For an ETH↔RXD swap the maker's claim is referenced by a tx
        HASH (carried in ``maker_claim_tx_bytes``), not raw witness bytes: the flow
        dispatches to :meth:`_taker_scrape_and_claim_eth`, which fetches calldata+logs,
        scrapes ``p``, runs the ETH provenance gate (R6) and the finalized-checkpoint reorg
        gate. The BTC body below is unchanged and byte-for-byte identical to its proven form.
        """
        if self.record.terms.counter_chain != "btc":
            return await self._taker_scrape_and_claim_eth(
                maker_claim_tx_bytes, now_rxd_height=now_rxd_height, asset_locked_at_height=asset_locked_at_height
            )
        if self.record.state is not SwapState.SECRET_REVEALED:
            raise ValidationError(
                f"taker_scrape_and_claim_asset only valid from SECRET_REVEALED, not {self.record.state.value}"
            )
        # Cheap, no-network checks first: a tx that doesn't even contain p is rejected
        # before any RPC round-trip.
        p = self.counter_leg.scrape_secret(maker_claim_tx_bytes, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")
        # Provenance: the tx we scraped p from must spend OUR funding outpoint (defends
        # cross-swap replay even if H is reused via a path the seen-store does not cover).
        self._assert_claim_tx_spends_our_htlc(maker_claim_tx_bytes)

        # Reorg gate: read the maker's BTC-claim depth (fail-closed on any error) and
        # assess against the t_rxd window.
        btc_confs = await self.counter_leg.confirmations_of_claim(maker_claim_tx_bytes)
        policy = self.config.margin_policy
        required_depth = policy.btc_claim_reorg_depth.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s
        ).value
        verdict = CounterClaimFinality.from_btc_depth(btc_confs, required_depth)
        finality = assess_claim_finality(
            counter_claim_finality=verdict,
            now_rxd_height=now_rxd_height,
            asset_locked_at_height=asset_locked_at_height,
            t_rxd=self.record.terms.t_rxd,
            policy=policy,
        )
        if finality is ClaimFinality.WAIT:
            logger.info(
                "reorg gate WAIT: maker BTC claim at %d confs (< required reorg depth); "
                "window still has room — not claiming yet, retry later",
                btc_confs,
            )
            return self.record  # unchanged; stays SECRET_REVEALED
        if finality is ClaimFinality.SQUEEZED:
            logger.warning(
                "reorg gate SQUEEZED: maker BTC claim at %d confs and t_rxd window closing — "
                "advancing to ASSET_VULNERABLE; a winner-take-all claim is now a deliberate "
                "policy decision (taker_claim_asset_from_vulnerable), not automatic",
                btc_confs,
            )
            self._advance(SwapEvent.TAKER_OFFLINE_OR_PINNED)
            await self._persist_record(self.record, shield=True)
            return self.record

        # SAFE: the BTC claim is reorg-deep and our own burial still fits the window.
        await self.radiant_leg.claim_asset(self.record, bytes(p))
        self._advance(SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    async def _taker_scrape_and_claim_eth(
        self, claim_tx_hash, *, now_rxd_height: int, asset_locked_at_height: int
    ) -> SwapRecord:
        """ETH variant of :meth:`taker_scrape_and_claim_asset` (called within the held step
        lock, so NOT itself ``@_serialized_step``). The maker's claim is an on-chain ETH tx
        referenced by ``claim_tx_hash``; the secret lives in its calldata/logs, its finality is
        the post-Merge ``finalized`` checkpoint (no confirmation depth), and provenance is the
        per-swap-unique HTLC contract address (R6), the ETH analogue of the BTC funding outpoint.

        Same gate ORDER and SAFE/WAIT/SQUEEZED semantics as the BTC path: scrape ``p`` and
        RE-verify ``sha256(p)==H``; run the provenance gate; then the ``t_rxd``-squeeze
        assessment over the ETH finality verdict. The Radiant claim only fires on SAFE.
        """
        if self.record.state is not SwapState.SECRET_REVEALED:
            raise ValidationError(
                f"taker_scrape_and_claim_asset only valid from SECRET_REVEALED, not {self.record.state.value}"
            )
        locator = self.record.counterchain_locator
        if not isinstance(locator, EthHtlcLocator):
            raise ValidationError("ETH claim flow requires an EthHtlcLocator on the record")
        # Fetch the candidate blobs (calldata + log data) and scrape p by sha256==H (never by
        # offset); the coordinator RE-verifies sha256(p)==H — a value that does not open H is rejected.
        artifacts = await self.counter_leg.fetch_claim_artifacts(claim_tx_hash)
        p = self.counter_leg.scrape_secret(artifacts, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")
        # Provenance (R6): the claim tx must target OUR HTLC contract instance and emit the
        # revealed secret p (the Claimed(p) event) from it — defends cross-swap replay even if
        # H is reused via a path the seen-store does not cover (the ETH analogue of
        # _assert_claim_tx_spends_our_htlc). Binds the SECRET p, not the public H.
        await self.counter_leg.assert_claim_provenance(
            claim_tx_hash, contract_address=locator.contract_address, preimage=bytes(p)
        )
        # Reorg gate: the ETH finalized-checkpoint verdict (no depth) feeds the t_rxd squeeze.
        # NOTE (RF-06): this point-in-time producer only ever returns FINAL or NOT_YET_FINAL_LIVE
        # — never COUNTER_CHAIN_NOT_FINALIZING — so an actual ETH finalization STALL degrades to
        # WAIT-until-the-window-closes (still SAFE: never claims off a non-final reveal), not an
        # early SQUEEZE. Timely stall handling needs the deferred polling driver to inject the
        # stall verdict; the assess_claim_finality stall branch is unreachable via this path alone.
        verdict = await self.counter_leg.claim_finality_verdict(claim_tx_hash)
        finality = assess_claim_finality(
            counter_claim_finality=verdict,
            now_rxd_height=now_rxd_height,
            asset_locked_at_height=asset_locked_at_height,
            t_rxd=self.record.terms.t_rxd,
            policy=self.config.margin_policy,
        )
        if finality is ClaimFinality.WAIT:
            logger.info(
                "reorg gate WAIT: maker ETH claim not yet finalized but t_rxd window has room — "
                "not claiming yet, retry later"
            )
            return self.record  # unchanged; stays SECRET_REVEALED
        if finality is ClaimFinality.SQUEEZED:
            logger.warning(
                "reorg gate SQUEEZED: maker ETH claim not finalized and t_rxd window closing — "
                "advancing to ASSET_VULNERABLE; a winner-take-all claim is now a deliberate "
                "policy decision (taker_claim_asset_from_vulnerable), not automatic"
            )
            self._advance(SwapEvent.TAKER_OFFLINE_OR_PINNED)
            await self._persist_record(self.record, shield=True)
            return self.record

        # SAFE: the ETH claim is finalized and our own RXD burial still fits the window.
        await self.radiant_leg.claim_asset(self.record, bytes(p))
        self._advance(SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- deliberate winner-take-all claim from the SQUEEZED/ASSET_VULNERABLE state --
    @_serialized_step
    async def taker_claim_asset_from_vulnerable(self, maker_claim_tx_bytes: bytes) -> SwapRecord:
        """Best-effort asset claim from ASSET_VULNERABLE — an EXPLICIT policy decision.

        Only valid from ASSET_VULNERABLE (reached when the reorg gate found the swap
        SQUEEZED). This is winner-take-all: the taker races to claim the asset before
        the maker's ``t_rxd`` CSV refund lands, accepting the residual reorg risk that
        the gate flagged. It is a CONSCIOUS choice the caller makes after the gate
        refused the automatic SAFE claim — never invoked silently.

        For an ETH counter leg ``maker_claim_tx_bytes`` carries the maker's ETH claim tx
        hash; the scrape + provenance gate dispatch to the ETH path. The BTC body below is
        byte-for-byte unchanged.
        """
        if self.record.terms.counter_chain != "btc":
            return await self._taker_claim_eth_from_vulnerable(maker_claim_tx_bytes)
        if self.record.state is not SwapState.ASSET_VULNERABLE:
            raise ValidationError(
                f"taker_claim_asset_from_vulnerable only valid from ASSET_VULNERABLE, not {self.record.state.value}"
            )
        p = self.counter_leg.scrape_secret(maker_claim_tx_bytes, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")
        self._assert_claim_tx_spends_our_htlc(maker_claim_tx_bytes)
        await self.radiant_leg.claim_asset(self.record, bytes(p))
        self._advance(SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    async def _taker_claim_eth_from_vulnerable(self, claim_tx_hash) -> SwapRecord:
        """ETH variant of the deliberate winner-take-all claim (within the held step lock).
        Same explicit ASSET_VULNERABLE-only gate; fetch+scrape p, provenance gate (R6), claim."""
        if self.record.state is not SwapState.ASSET_VULNERABLE:
            raise ValidationError(
                f"taker_claim_asset_from_vulnerable only valid from ASSET_VULNERABLE, not {self.record.state.value}"
            )
        locator = self.record.counterchain_locator
        if not isinstance(locator, EthHtlcLocator):
            raise ValidationError("ETH claim flow requires an EthHtlcLocator on the record")
        artifacts = await self.counter_leg.fetch_claim_artifacts(claim_tx_hash)
        p = self.counter_leg.scrape_secret(artifacts, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")
        await self.counter_leg.assert_claim_provenance(
            claim_tx_hash, contract_address=locator.contract_address, preimage=bytes(p)
        )
        await self.radiant_leg.claim_asset(self.record, bytes(p))
        self._advance(SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- maker-stall proactive asset refund (C1) ----------------------------
    @_serialized_step
    async def maybe_refund_asset_on_maker_stall(
        self, *, now_block_height: int, asset_locked_at_height: int, maker_has_claimed_btc: bool
    ) -> SwapRecord:
        """If the maker is stalling near ``t_RXD - N``, refund the asset proactively.

        Drives BOTH_LOCKED -> MAKER_STALLS -> ASSET_REFUNDED_TAKER_ACTS. A no-op
        (returns the unchanged record) when the trigger has not fired yet. Async
        because the asset refund broadcasts a Radiant covenant spend.

        RUNBOOK SCOPE (FSM finding #2, 2026-06-09 — VERIFIED on regtest): this refunds ONLY the RXD
        covenant, whose CSV refund pays the MAKER in BOTH directions (the maker owns the asset leg; p
        is not yet public) — it is NOT a "taker reclaims the covenant" action (an earlier note wrongly
        said the taker owns it; the covenant CLAIM pays the taker, the CSV REFUND pays the maker, same
        as eth_rxd_timelock.py).

        This is a MAKER-side primitive (the maker recovering its own asset) and MUST NOT be wired into
        a TAKER recovery path on EITHER counter-chain. A taker driven to run it strands itself: it
        gifts the asset back to the maker AND destroys its only recourse (the claimable covenant) while
        its own counter-leg stays locked, after which the maker — still holding p — claims the
        counter-leg and takes both (proven by tests/test_xchain_swap_regtest_e2e.py::
        TestMakerStallAssetOnlyRefundIsTakerLoss). The correct TAKER stall recovery on BOTH the BTC
        and ETH runbooks is :meth:`mutual_refund` (refunds BOTH legs after both timeouts). The
        watchtower (gravity.watch.decide) routes neither counter-chain's taker here.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(
                f"maybe_refund_asset_on_maker_stall only valid from BOTH_LOCKED, not {self.record.state.value}"
            )
        trigger = taker_refund_window_open(
            now_block_height=now_block_height,
            asset_locked_at_height=asset_locked_at_height,
            t_rxd=self.record.terms.t_rxd,
            safety_window_blocks=self.config.maker_stall_safety_window_blocks,
            maker_has_claimed_btc=maker_has_claimed_btc,
            block_interval_s=self.config.margin_policy.block_interval_s,
        )
        if not trigger:
            return self.record
        # BROADCAST-THEN-ADVANCE (red-team LOW): advancing to MAKER_STALLS before the on-chain
        # refund broadcast wedges the swap there (maybe_refund is only valid from BOTH_LOCKED) if
        # the broadcast transiently fails. Broadcast FIRST — a raising refund leaves the record at
        # BOTH_LOCKED and the call is safely retryable — then advance both FSM steps + persist once
        # (matches taker_refund_btc / mutual_refund). The taker refunds rather than wait (NEVER waits).
        await self.radiant_leg.refund_asset(self.record)
        self._advance(SwapEvent.MAKER_STALL_DETECTED)
        self._advance(SwapEvent.TAKER_REFUNDS_ASSET_PROACTIVELY)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- taker refunds BTC (ABORT paths: maker never locks, or PARAMS_MISMATCH)
    @_serialized_step
    async def taker_refund_btc(self) -> SwapRecord:
        """Refund the BTC via the timelock leg, ending in ABORTED.

        Valid from BTC_LOCKED (maker never locked, t_btc elapsed) or PARAMS_MISMATCH
        (maker locked the wrong covenant). The refund needs the FULL locator
        (Tapscript tree + control block) — recovered from the durable record. Async
        because the refund broadcasts the BTC timelock spend.
        """
        state = self.record.state
        if state not in (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH):
            raise ValidationError(f"taker_refund_btc not valid from {state.value}")
        if self.record.counterchain_locator is None:
            raise ValidationError("no BTC locator on record; cannot refund (state was lost)")
        await self.counter_leg.refund(self.record.counterchain_locator, self.record.terms.t_btc)
        if state is SwapState.BTC_LOCKED:
            self._advance(SwapEvent.MAKER_NEVER_LOCKS_BTC_TIMEOUT)
        else:
            self._advance(SwapEvent.TAKER_REFUNDS_BTC)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- safe failure: both timeouts elapse, both refund (MUTUAL_REFUND) -----
    @_serialized_step
    async def mutual_refund(self) -> SwapRecord:
        """Both legs refund after both timeouts elapse — the guaranteed-safe failure.

        Valid from BOTH_LOCKED. The taker refunds BTC, the maker refunds the asset;
        neither suffers one-sided loss. Requires the full locator be retained. Async
        because both refunds broadcast on their chains.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"mutual_refund only valid from BOTH_LOCKED, not {self.record.state.value}")
        if self.record.counterchain_locator is None:
            raise ValidationError("no BTC locator on record; BTC would strand (state was lost)")
        await self.counter_leg.refund(self.record.counterchain_locator, self.record.terms.t_btc)
        await self.radiant_leg.refund_asset(self.record)
        self._advance(SwapEvent.BOTH_TIMEOUTS_ELAPSE)
        await self._persist_record(self.record, shield=True)
        return self.record

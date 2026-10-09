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
import contextlib
import dataclasses
import functools
import hashlib
import logging
import math
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from fractions import Fraction
from typing import Any

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import (
    BtcHtlcLocator,
    Timelock,
    TimeUnit,
    btc_input_outpoints_from_raw,
)
from pyrxd.eth_wallet.chains import ETH_FINALIZATION_WINDOW_FLOOR_S
from pyrxd.eth_wallet.locator import EthHtlcLocator, PendingDeploy
from pyrxd.glyph.credential_binding import CredentialBindingError, assert_soulbound_credential
from pyrxd.gravity.htlc_covenant import holder_hash
from pyrxd.gravity.reorg_cost import PHOTONS_PER_RXD, ReorgCostMeasurement
from pyrxd.security.errors import NetworkError, PreRevealAbort, ValidationError
from pyrxd.security.reveal import reveal_boundary
from pyrxd.security.secrets import SecretBytes

from .eth_rxd_timelock import (
    CrossClockMargin,
    assert_covenant_confirms_before_eth_deadline,
    assert_eth_deadline_is_claimable,
)
from .finality import CounterClaimFinality, CounterClaimState
from .funding_spv import (
    DEFAULT_ELAPSED_BOUND_POLICY,
    MIN_FUNDING_CONFIRMATIONS,
    EarlyElapsedBound,
    ElapsedBoundPolicy,
    MakerFundingNotVerified,
    RadiantChain,
    VerifiedMakerFunding,
    checkpoint_horizon_failure,
    counted_operators,
    early_elapsed_blocks_upper,
    erlang_upper_quantile_s,
    funding_header_ranges,
    radiant_chain_for_leg,
    verify_maker_funding,
)
from .ref_authenticity import verify_ref_authenticity
from .swap_state import (
    NegotiatedTerms,
    SwapEvent,
    SwapRecord,
    SwapRole,
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
    "ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS",
    "MAINNET_ETH_FINALITY_STALL_FLOOR_S",
    "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST",
    "ClaimFinality",
    "DefinitiveFundRefusal",
    "MarginPolicy",
    "SwapCoordinator",
    "assert_timelock_margin",
    "assess_claim_finality",
    "generate_secret",
    "measure_margin_from_btc_block_times",
    "should_taker_refund_proactively",  # deprecated alias of taker_refund_window_open
    "taker_gate_early_bound",
    "taker_refund_window_open",
]

logger = logging.getLogger(__name__)

#: The MONOTONIC clock the taker gate measures its own reads with (never the wall clock: the
#: caller's ``now_unix_s`` stays the only wall-clock reading). A module attribute so a test can
#: advance it without touching the event loop's clock.
_monotonic = time.monotonic


# ---------------------------------------------------------------------------
# The hard role invariant (the safety hinge — NOT an implementer choice)
# ---------------------------------------------------------------------------

MAKER_SECRET_TAKER_LOCKS_BTC_FIRST = (  # nosec B105 — a role-invariant doc string, not a secret/password
    "MAKER_SECRET_TAKER_LOCKS_BTC_FIRST: "
    "the maker holds the Glyph asset and wants BTC; the taker holds BTC and wants "
    "the asset. (1) The MAKER generates the secret p (32 bytes CSPRNG, fresh per "
    "swap) and publishes H = SHA256(p). (2) The MAKER locks the asset FIRST "
    "(Radiant covenant). (3) The TAKER locks BTC SECOND (funds the P2TR HTLC) — "
    "`taker_funds_btc` will not proceed until `pre_btc_lock_check` step 5 has read "
    "the covenant off the Radiant chain (HZ-1, #392). (4) The "
    "MAKER claims the BTC FIRST, revealing p in the Bitcoin witness. (5) The TAKER "
    "scrapes p from Bitcoin and claims the Radiant asset before its refund opens. "
    "Invariant, IN WALL CLOCK (#567): t_RXD * i_RXD >= t_BTC * i_BTC + margin * i_BTC — the "
    "maker holds p and LOCKS the Radiant leg, so THAT leg carries the LONGER refund and the "
    "leg the maker CLAIMS (BTC) the shorter (Herlihy 1801.09515 §1: the secret generator "
    "locks at 6-delta and claims a 4-delta leg). The raw-block form t_RXD > t_BTC + margin "
    "is NOT sufficient: a Radiant block is ~300 s against Bitcoin's ~600 s, so it passes "
    "layouts whose real margin is negative. The taker's client MUST verify the wall-clock "
    "relation before funding, or refuse. "
    "NB the NAME predates HZ-1 (#392), which inverted the lock order in (2)/(3); it is "
    "kept because it is exported, asserted in tests and quoted in a ValidationError, and "
    "because the half of it that names the timelock invariant is still exactly right."
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

#: Blocks reserved for the taker's own claim to be MINED, before its burial starts counting (#511).
#:
#: TWO blocks, and each one is a separate reason. The first is arithmetic and unavoidable: a claim
#: broadcast at height H cannot be mined at H, so its burial can only start at H+1. The second is
#: slack for a block that does not include it — Radiant has no RBF and no CPFP, so a claim that
#: misses cannot be accelerated, and mempool eviction (~8h expiry) then hands the maker its refund.
#:
#: MEASURE IT for a real-value run. This is a BLOCK count, not a wall-clock budget, so the block
#: interval does not enter it — what matters is how many blocks can pass without including a
#: correctly-fee'd tx. 2 is an estimate, not a measurement.
ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS = 2

#: Minimum ``eth_finality_stall_tolerance_s`` a REAL-VALUE ETH-leg policy must carry, in seconds.
#: Grounded in the May-2023 Ethereum mainnet finality incident (~9 epochs, roughly an hour) that
#: `CrossClockMargin` cites as the case this budget exists for; the Sepolia 2026-06-01 stall this
#: project observed directly ran ~20 min. An inactivity-leak worst case is unbounded, so this is a
#: floor and not a sufficient value — larger is safer, and the cost of a larger value is only the
#: maker's asset staying locked longer, which is liveness, never safety.
MAINNET_ETH_FINALITY_STALL_FLOOR_S = 3600

# Hard safety floor (in BLOCKS) for any reorg depth, enforced at MarginPolicy
# construction. A 1-block depth is materially unsafe on a real chain (natural
# single-block reorgs happen; "dust" bounds the loss, not the reorg probability), so
# even a dust run must use >= 2. NOT a configurable knob — it is the fail-closed floor.
_MIN_REORG_DEPTH_BLOCKS = 2

#: Every ``Timelock`` field on :class:`MarginPolicy` and its minimum, in BLOCKS. Iterated by
#: ``__post_init__``; cross-checked against the dataclass's real field set, both directions, by
#: ``tests/test_margin_policy_validates_every_timelock_field.py``.
#:
#: The floors differ ON PURPOSE. A reorg depth of 0 or 1 defeats the gate it guards, so those sit at
#: ``_MIN_REORG_DEPTH_BLOCKS``. ``rxd_claim_inclusion`` is not a reorg depth — it is the blocks a
#: claim needs to be MINED before its burial can start, and 1 is the arithmetic minimum.
#: ``margin`` is deliberately absent: it is a policy quantity with no protocol-imposed floor (a
#: dust run legitimately uses 3), and the wall-clock gate is what bounds it.
_TIMELOCK_FLOORS: dict[str, int] = {
    "btc_claim_reorg_depth": _MIN_REORG_DEPTH_BLOCKS,
    "rxd_claim_burial": _MIN_REORG_DEPTH_BLOCKS,
    "rxd_claim_inclusion": 1,
}

# Hard safety floor (SECONDS) for the ETH/PoS finalization window. A smaller window collapses
# the reorg-gate's finalization reserve toward zero. Enforced at MarginPolicy construction
# whenever eth_finalization_window_s is set (the ETH-swap PRESENCE of the field is enforced
# fail-closed at SwapCoordinator construction, where the counter chain is known).
#
# IMPORTED, not restated. This was a second literal 768 kept beside a "Keep in sync with"
# comment in eth_wallet.chains; the same rule is enforced at both boundaries, so the two
# copies had to agree and nothing made them.
_MIN_ETH_FINALIZATION_WINDOW_S = ETH_FINALIZATION_WINDOW_FLOOR_S


@functools.cache
def _float_field_names(cls: type) -> tuple[str, ...]:
    """The ``float``-typed field names of a dataclass, read off the dataclass itself.

    The twin of ``_TIMELOCK_FLOORS``' derived cross-check, for the knobs that carry a NUMBER
    rather than a Timelock. Kept a derivation because the alternative — a tuple of names beside
    the validator — is the shape that let ``rxd_claim_inclusion`` ship with no floor at all.

    ``from __future__ import annotations`` makes ``field.type`` the ANNOTATION STRING, so the
    match is on text; the class object is accepted too so the derivation does not silently return
    nothing if that import is ever dropped. ``tests/test_margin_policy_rejects_non_finite_floats``
    asserts the result against the fields both ways, so an empty or partial answer fails loudly
    rather than passing vacuously.
    """
    return tuple(f.name for f in dataclasses.fields(cls) if f.type in ("float", "float | None", float))


@dataclass(frozen=True)
class MarginPolicy:
    """How the cross-chain timelock margin is computed and enforced.

    Attributes
    ----------
    margin:
        The required minimum ``t_rxd - t_btc``, as a unit-tagged
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
    # The FAST-tail counterpart, for conversions that DIVIDE by the interval. Dividing wants a
    # SMALL interval (more blocks = more cover); multiplying wants a large one. Reusing one value
    # across an inverse pair is what made #484's filed fix refuse every configuration.
    #
    # Defaults to None = "use rxd_block_interval_s", preserving today's behaviour exactly. A
    # REAL-VALUE policy must supply a measured one: at a measured p10 of 36s, a reserve computed
    # with the 300s default covers about an eighth of the window it is meant to protect.
    #
    # MEASURE IT PER RUN — the figure drifts and it drifts in the unsafe direction. Radiant mainnet
    # p10 was 43s on 2026-06-02 and 36s on 2026-08-26 (720 intervals over 58.6h, blocks read off a
    # mainnet node). Reserves DIVIDE by this, so a stale-high value under-counts: sizing with 43s
    # against a real 36s gives 16% fewer blocks than the window actually holds. The same sample:
    # median 222s, mean 293s, p90 669s, p99 1199s, max 2325s — a single 39-minute gap inside two
    # and a half days.
    # See docs/solutions/design-decisions/sizing-t-rxd-the-two-directions-rule.md.
    rxd_block_interval_fast_s: float | None = None
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
    #: Blocks allowed for the taker's claim to be MINED before its burial starts counting (#511).
    #: See :data:`ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS`. Kept a policy knob rather than a constant
    #: because it is the one term here an operator can measure on their own node.
    rxd_claim_inclusion: Timelock = field(
        default_factory=lambda: Timelock(ESTIMATED_RXD_CLAIM_INCLUSION_BLOCKS, TimeUnit.BLOCKS)
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
    #
    # STALENESS HAS A DANGEROUS DIRECTION, and it is the one a falling hashrate produces. The burial
    # formula DIVIDES by this, so a value carried over from a period of HIGHER hashrate yields FEWER
    # required blocks than the chain now warrants — under-burial, silently, in the unsafe direction.
    # A too-LOW figure merely over-buries, which costs time and not funds. So when in doubt, round
    # DOWN. Measured 2026-08-29 off the mainnet node: difficulty 25,892,399 at the 300 s target is
    # ~371 TH/s, roughly 5x below a figure recorded a few months earlier — this is not hypothetical
    # drift. `rxd_block_interval_s` carries the identical divide-by-a-stale-measurement trap and
    # says so; this parameter had the refresh instruction without the direction.
    rxd_reorg_cost_per_block: int | None = None
    # reorg_cost: the same quantity WITH ITS PROVENANCE — the hashrate and price it assumed, and
    # when it was taken (see `pyrxd.gravity.reorg_cost`). Prefer this over the bare int: an int
    # cannot express "this assumed 1.88 PH/s in May", so nothing can notice when the chain moves,
    # and Radiant's hashrate fell ~5x between measurements with no signal (#533). When supplied it
    # POPULATES `rxd_reorg_cost_per_block` below, so every existing consumer is unchanged, and the
    # coordinator refuses a swap whose measurement is past its `max_age_s`.
    reorg_cost: ReorgCostMeasurement | None = None
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
        # A measurement and a bare int are the SAME quantity from two sources. Refuse rather than
        # pick a winner: silently preferring one would make the other look effective while doing
        # nothing, which is how a stale figure survives in the first place.
        if self.reorg_cost is not None:
            if not isinstance(self.reorg_cost, ReorgCostMeasurement):
                raise ValidationError("MarginPolicy.reorg_cost must be a ReorgCostMeasurement")
            if self.rxd_reorg_cost_per_block is not None:
                raise ValidationError(
                    "MarginPolicy got BOTH reorg_cost and rxd_reorg_cost_per_block. They are the same "
                    "quantity; supply the measurement alone so its provenance travels with it."
                )
            # Populate the plain field so every existing consumer (`_value_scaled_burial_blocks`,
            # the setup gate, the watchtower) reads it unchanged.
            object.__setattr__(self, "rxd_reorg_cost_per_block", self.reorg_cost.photons_per_block)
        # EVERY float knob here must be FINITE, and the `> 0` / `>= 1.0` bounds below do not say
        # so: IEEE-754 makes every comparison with NaN False, so `nan <= 0` and `nan < 1.0` are
        # both False and NaN passes the bound written to exclude it — vacuously, which is
        # indistinguishable in the output from passing because the value is sound. `inf` passes
        # for the honest reason that it genuinely is >= the bound. `argparse(type=float)` accepts
        # both spellings, so `--burial-safety-factor nan` reached this dataclass from the shipped
        # watchtower CLI. `ClaimExecutor.__init__` and `max_protected_value` already carry
        # `math.isfinite` for their own factors and say this is why; MarginPolicy was the one
        # factor site without it.
        #
        # It is a REFUSAL, not a clamp, and it costs nothing honest: every finite positive float
        # is unaffected. What it prevents is the far side — a non-finite factor does not crash,
        # it reaches `Fraction(...)` inside the reorg gate, raises ValueError/OverflowError, gets
        # rewrapped as "could not normalise reorg depths to blocks", and comes out of the
        # watchtower as PAGE_SQUEEZED "verify finality manually" on EVERY tick of EVERY rxd swap.
        # Fail-closed (never a false SAFE), but a guard that pages a healthy swap as a squeeze and
        # pushes its operator to act by hand under time pressure is refusing valid work.
        # DERIVED FROM THE DATACLASS, not a tuple of names typed out here. A hand-kept list of the
        # fields a validator covers is how `rxd_claim_inclusion` went unchecked when #511 added it
        # (see `_TIMELOCK_FLOORS` below, fixed the same way); the float knobs would have gone the
        # same way on the next one. `tests/test_margin_policy_rejects_non_finite_floats.py` pins
        # the derivation in both directions, so it cannot silently start returning nothing.
        for _label in _float_field_names(type(self)):
            _val = getattr(self, _label)
            if isinstance(_val, (int, float)) and not isinstance(_val, bool) and not math.isfinite(_val):
                raise ValidationError(
                    f"MarginPolicy.{_label} = {_val} is not finite. NaN/inf pass every numeric bound "
                    "on this dataclass by construction (NaN compares False to everything) and then "
                    "raise deep inside the reorg gate, where the failure surfaces as an "
                    "un-assessable finality verdict on every swap."
                )
        if not isinstance(self.block_interval_s, (int, float)) or self.block_interval_s <= 0:
            raise ValidationError("MarginPolicy.block_interval_s must be > 0")
        if not isinstance(self.rxd_block_interval_s, (int, float)) or self.rxd_block_interval_s <= 0:
            raise ValidationError("MarginPolicy.rxd_block_interval_s must be > 0")
        fast = self.rxd_block_interval_fast_s
        if fast is not None:
            if not isinstance(fast, (int, float)) or fast <= 0:
                raise ValidationError("MarginPolicy.rxd_block_interval_fast_s must be > 0")
            if fast > self.rxd_block_interval_s:
                raise ValidationError(
                    f"MarginPolicy.rxd_block_interval_fast_s ({fast}s) exceeds rxd_block_interval_s "
                    f"({self.rxd_block_interval_s}s) — a fast-tail percentile cannot be slower than "
                    "the nominal one; the two are swapped"
                )
        if self.require_measured and fast is None:
            raise ValidationError(
                "real-value mode (require_measured=True) requires a MEASURED "
                "rxd_block_interval_fast_s: a reserve computed by DIVIDING by the interval needs a "
                "fast-tail percentile, and the nominal value under-counts it. At a measured p10 "
                "of 36s (Radiant mainnet, 2026-08-26), a reserve computed with a 300s interval "
                "covers about an eighth of the window it protects. Measure it for YOUR run rather "
                "than copying this number: it was 43s in June and 36s in August."
            )
        if not isinstance(self.is_measured, bool):
            raise ValidationError("MarginPolicy.is_measured must be bool")
        if not isinstance(self.require_measured, bool):
            raise ValidationError("MarginPolicy.require_measured must be bool")
        # EVERY Timelock FIELD IS CHECKED, DERIVED FROM THE DATACLASS — not from a hand-kept list.
        #
        # The list was hand-kept, and `rxd_claim_inclusion` was simply left off it when #511 added
        # the field: `Timelock(0)` was accepted and silently restored the pre-#511 floor the field
        # exists to raise, and a bare `int` was accepted at construction to fail much later with an
        # AttributeError instead of a fail-closed ValidationError. The first fix hand-typed a
        # fourth check beside the other three — the same shape, one instance later.
        #
        # `_TIMELOCK_FLOORS` is checked against the dataclass's own fields in both directions by
        # `tests/test_margin_policy_validates_every_timelock_field.py`, so a field added without a
        # floor, or a floor naming a field that no longer exists, is a failing test rather than a
        # gap nobody notices.
        for label, floor in _TIMELOCK_FLOORS.items():
            value = getattr(self, label)
            if not isinstance(value, Timelock):
                raise ValidationError(f"MarginPolicy.{label} must be a Timelock")
            # RADIANT fields convert with RADIANT's interval (#579); btc_claim_reorg_depth
            # is a Bitcoin quantity and keeps the Bitcoin one.
            interval = self.block_interval_s if label == "btc_claim_reorg_depth" else self.rxd_block_interval_s
            blocks = value.normalize_to(TimeUnit.BLOCKS, block_interval_s=interval).value
            if blocks < floor:
                raise ValidationError(
                    f"MarginPolicy.{label} = {blocks} blk < safety floor {floor}. "
                    + (
                        "A 0/1-block reorg depth defeats the gate (single-block reorgs occur on real chains)."
                        if floor >= _MIN_REORG_DEPTH_BLOCKS
                        else "A claim cannot be mined in the block it is broadcast in, so zero reserves nothing."
                    )
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
        # `eth_finality_stall_tolerance_s` defaults to 0, and its own docstring calls it "the single
        # most important safety addition" while citing an hour-long mainnet stall. A default of zero
        # sizes the margin against HAPPY-PATH finality, which is precisely the bug a stall triggers,
        # and nothing in this tree ever constructed a CrossClockMargin to override it — the value was
        # entirely operator-supplied with no floor, unlike every other knob here. Enforced in
        # real-value mode only, so tests and dust runs are unaffected.
        if self.require_measured and self.cross_clock_margin is not None:
            tol = self.cross_clock_margin.eth_finality_stall_tolerance_s
            if tol < MAINNET_ETH_FINALITY_STALL_FLOOR_S:
                raise ValidationError(
                    f"real-value mode (require_measured=True) requires "
                    f"CrossClockMargin.eth_finality_stall_tolerance_s >= "
                    f"{MAINNET_ETH_FINALITY_STALL_FLOOR_S}s, got {tol}s. The taker waits for ETH "
                    "FINALITY before claiming RXD, so the RXD refund must not open until the taker "
                    "has had a stall-tolerant window; the May-2023 mainnet stall ran about an hour. "
                    "Sizing this against happy-path finality is the exact bug a stall triggers."
                )
        if self.max_covenant_confirm_wait_s is not None and (
            not isinstance(self.max_covenant_confirm_wait_s, int)
            or isinstance(self.max_covenant_confirm_wait_s, bool)
            or self.max_covenant_confirm_wait_s < 0
        ):
            raise ValidationError("MarginPolicy.max_covenant_confirm_wait_s must be a non-negative int or None")

    @classmethod
    def estimated(
        cls,
        *,
        block_interval_s: float = 600.0,
        require_measured: bool = False,
        accept_flat_burial: bool = False,
        eth_finalization_window_s: int | None = None,
    ) -> MarginPolicy:
        """The ESTIMATED, test-only policy. Refuses to construct in real-value mode.

        ``accept_flat_burial`` is the dust opt-out from the value-scaled-burial setup gate —
        set it for a deliberate dust run whose value is below the Radiant reorg cost.

        ``eth_finalization_window_s`` is NOT an estimate this class ships — it is a per-chain
        FACT (``pyrxd.eth_wallet.chains``), and it is here because the finality gate RAISES
        without it on any finalized-checkpoint counter leg. An alert-only watchtower watching an
        ETH swap builds its policy through this constructor, and with the window unset every tick
        of a healthy swap came out as ``PAGE_SQUEEZED`` "verify finality manually". None keeps the
        BTC (depth-based) behaviour exactly.
        """
        return cls(
            margin=Timelock(ESTIMATED_DEFAULT_MARGIN_BLOCKS, TimeUnit.BLOCKS),
            block_interval_s=block_interval_s,
            is_measured=False,
            require_measured=require_measured,
            accept_flat_burial=accept_flat_burial,
            eth_finalization_window_s=eth_finalization_window_s,
        )

    @classmethod
    def measured(
        cls,
        *,
        margin: Timelock,
        block_interval_s: float,
        btc_claim_reorg_depth: Timelock | None = None,
        rxd_claim_burial: Timelock | None = None,
        rxd_claim_inclusion: Timelock | None = None,
        rxd_block_interval_s: float | None = None,
        rxd_block_interval_fast_s: float | None = None,
        rxd_reorg_cost_per_block: int | None = None,
        reorg_cost: ReorgCostMeasurement | None = None,
        value_at_risk_photons: int | None = None,
        burial_safety_factor: float = 1.0,
        accept_flat_burial: bool = False,
        eth_finalization_window_s: int | None = None,
    ) -> MarginPolicy:
        """A measured policy for real-value mainnet swaps.

        ``btc_claim_reorg_depth`` / ``rxd_claim_burial`` are the reorg gate's measured
        inputs; if omitted they fall back to the ESTIMATED defaults (acceptable only
        because a measured policy still carries the estimated reorg depths — supply
        measured values for a real mainnet swap).

        ``rxd_block_interval_fast_s`` is the FAST-tail (p10) inter-block measurement, REQUIRED
        here: every reserve computed by dividing a time span by the interval needs it, and the
        nominal value under-counts them. Measured Radiant mainnet 2026-08-26: p10 36s against a
        mean of 293s — a reserve sized with the mean covers about an eighth of its window. (It was
        p10 43s on 2026-06-02; the drift is downward, which is the direction that under-counts, so
        re-measure rather than inheriting either figure.) When it is
        genuinely unknown, pass the same value as ``rxd_block_interval_s`` and know that the
        reserves are then nominal rather than conservative.

        ``rxd_reorg_cost_per_block`` (measured, photons/block) + ``value_at_risk_photons``
        (the assessed economic value) drive the VALUE-SCALED claim burial (red-team HIGH):
        supply both for a value-bearing Radiant swap, or set ``accept_flat_burial=True`` for
        a dust run — the coordinator refuses a value-bearing swap that leaves them unset.

        ``eth_finalization_window_s`` is REQUIRED (non-None) for a finalized-checkpoint (ETH)
        counter leg and must stay None for a depth-based (BTC) one; take it from
        ``pyrxd.eth_wallet.chains.evm_chain_by_id`` rather than guessing. Its absence here was
        the reason the watchtower could not set it at all: a field this constructor does not
        accept is invisible to the reachability guards derived from this signature, and the
        finality gate then raised on every tick of a healthy ETH swap.
        """
        kwargs: dict = {
            "margin": margin,
            "block_interval_s": block_interval_s,
            "is_measured": True,
            "require_measured": True,
            "burial_safety_factor": burial_safety_factor,
            "accept_flat_burial": accept_flat_burial,
        }
        # DO NOT default the fast tail. This used to fill it with `rxd_block_interval_s or 300.0`,
        # reasoning that "the __post_init__ requirement then surfaces as an explicit choice at the
        # call site" — but it cannot, because this line had already satisfied it. `measured()` sets
        # `require_measured=True` unconditionally, so the guard at __post_init__ ("real-value mode
        # requires a MEASURED rxd_block_interval_fast_s") was UNREACHABLE through the constructor
        # operators are told to use.
        #
        # Reproduced on the shipped entry point before this change: `pyrxd-watchtower --measured`
        # yielded require_measured=True with rxd_block_interval_fast_s=300.0, so the ETH 768s
        # finality reserve was ceil(768/300)=3 RXD blocks where the repo's own measured p10 of 36s
        # needs 22 — a 7x under-reserve on exactly the path the guard protects.
        #
        # Left None, the guard fires and the caller must choose. The docstring above already told
        # them how: when the fast tail is genuinely unknown, pass the nominal value explicitly and
        # accept that the reserves are nominal rather than conservative.
        if rxd_block_interval_fast_s is not None:
            kwargs["rxd_block_interval_fast_s"] = rxd_block_interval_fast_s
        if btc_claim_reorg_depth is not None:
            kwargs["btc_claim_reorg_depth"] = btc_claim_reorg_depth
        if rxd_claim_burial is not None:
            kwargs["rxd_claim_burial"] = rxd_claim_burial
        # #511: a REAL-VALUE policy should measure how many blocks a correctly-fee'd claim can
        # wait for inclusion. Reachable here because `measured()` is the constructor such an
        # operator is told to use — a knob only settable through the raw dataclass is not a knob.
        if rxd_claim_inclusion is not None:
            kwargs["rxd_claim_inclusion"] = rxd_claim_inclusion
        if rxd_block_interval_s is not None:
            kwargs["rxd_block_interval_s"] = rxd_block_interval_s
        if rxd_reorg_cost_per_block is not None:
            kwargs["rxd_reorg_cost_per_block"] = rxd_reorg_cost_per_block
        if reorg_cost is not None:
            kwargs["reorg_cost"] = reorg_cost
        if value_at_risk_photons is not None:
            kwargs["value_at_risk_photons"] = value_at_risk_photons
        if eth_finalization_window_s is not None:
            kwargs["eth_finalization_window_s"] = eth_finalization_window_s
        return cls(**kwargs)


def measure_margin_from_btc_block_times(
    *,
    btc_block_timestamps: list[int],
    btc_tail_percentile: float,
    btc_claim_reorg_depth_blocks: int,
    rxd_claim_burial_blocks: int,
    rxd_block_interval_s: float,
    rxd_block_interval_fast_s: float | None = None,
    accept_flat_burial: bool = False,
    value_at_risk_photons: int | None = None,
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
        # REQUIRED by measured() since the silent nominal substitution was removed. This is the
        # documented real-value policy builder, so it is exactly the path that must not quietly
        # reserve at the nominal interval; omitting it now raises rather than under-reserving.
        rxd_block_interval_fast_s=rxd_block_interval_fast_s,
        # Dust runs opt out of value-scaled burial (the value is below the Radiant reorg cost);
        # a real-value run leaves this False and supplies rxd_reorg_cost_per_block + value_at_risk.
        accept_flat_burial=accept_flat_burial,
        # The swap's value in photons, when the caller states one (the taker gate sizes the depth it
        # requires of the maker's funding from it; an NFT/FT swap has no other value source).
        value_at_risk_photons=value_at_risk_photons,
    )
    provenance = {
        "measured": {
            "rxd_block_interval_fast_s": rxd_block_interval_fast_s,
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
            "value_at_risk_photons": value_at_risk_photons,
        },
        "note": (
            "margin + block_interval_s are MEASURED from observed BTC block timestamps; "
            "reorg depths are CHOSEN operator policy. The squeeze normalises all via "
            "block_interval_s — a single-clock approximation across BTC/RXD; the depths "
            "carry slack to absorb it (reorg-gate plan)."
        ),
    }
    return policy, provenance


def _stablecoin_value_floor_photons(terms: NegotiatedTerms, policy: MarginPolicy, counter_leg: Any) -> int | None:
    """Photons implied by a stablecoin counter leg's declared value, or None when there is no basis.

    Against BTC, a leg's economic value was never knowable in-protocol. Against a stablecoin it is:
    ``terms.value_amount`` is a 6-decimal dollar figure sitting on the record, so the swap states
    its own worth (#489).

    That matters because the RXD floor beside this one is exempt for ``ft``/``nft`` — their
    ``radiant_amount`` is a token count or carrier dust, not an economic value — so ANY nonzero
    ``value_at_risk_photons`` satisfied the setup gate for those variants and the value-scaled
    burial collapsed to the flat floor. Downstream is fail-closed for ft/nft today, which makes
    this the setup gate lagging the runtime gate rather than an open hole; it becomes one the
    moment someone passes the opt-out.

    Returns None — no check — unless every input is present and pinned:

    * a ``token_address`` on the terms, so the amount's unit is knowable;
    * a token the leg actually holds, matching that address, whose ``decimals`` are PINNED (the
      registry holds only USD-pegged USDC/USDT and refuses look-alikes by address, which is what
      makes "base units -> dollars" sound here and not a guess);
    * a **provenanced** ``rxd_price_usd`` from :class:`ReorgCostMeasurement`.

    The last is deliberate. Converting dollars to photons needs an RXD/USD rate, and a rate with no
    declared source and no expiry is exactly the stale-constant hazard of #533 in a new place — so
    this reuses the measurement's price, which carries both, rather than inventing one. An operator
    on the bare ``rxd_reorg_cost_per_block`` path gets no check, not a check built on a number
    nobody can date.

    Exact over ``Fraction`` and rounded UP: understating the floor is the unsafe direction.
    """
    if not getattr(terms, "token_address", ""):
        return None
    measurement = policy.reorg_cost
    if measurement is None:
        return None
    token = getattr(counter_leg, "token", None)
    if token is None:
        token = getattr(getattr(counter_leg, "_leg", None), "token", None)
    address = getattr(token, "address", None)
    decimals = getattr(token, "decimals", None)
    if not address or not isinstance(decimals, int) or address.lower() != terms.token_address.lower():
        return None
    if int(terms.value_amount) <= 0:
        return None
    usd = Fraction(int(terms.value_amount), 10**decimals)
    photons = usd / Fraction(measurement.rxd_price_usd) * PHOTONS_PER_RXD
    return -((-photons.numerator) // photons.denominator)


def assert_timelock_margin(t_btc: Timelock, t_rxd: Timelock, policy: MarginPolicy, *, elapsed_blocks: int = 0) -> None:
    """Assert ``t_rxd - t_btc >= margin`` — fail-closed, cross-unit normalised.

    INVERTED 2026-08-31 (#482 finding 1). This asserted ``t_btc - t_rxd >= margin``, which is the
    wrong way round. Herlihy (arXiv:1801.09515) §1: Alice GENERATES the secret and locks at ``6∆``;
    Bob locks at ``5∆``; Carol at ``4∆``; **Alice claims Carol's 4∆ leg**. The secret-holder's
    LOCKED leg carries the LONGEST timeout and the leg they CLAIM the shortest, with Lemma 4.13
    giving the gap: "the timeout on each arc (u, v) is later by at least ∆ than the timeout on each
    arc (v, w)".

    Our maker generates ``p``, LOCKS the Radiant covenant and CLAIMS the counter leg, so ``t_rxd``
    must be the longer one. Under the old relation the window ``[rxd_refund_opens, counter_deadline]``
    — at least ``margin`` wide BY CONSTRUCTION — let the maker refund the covenant while ``p`` was
    still secret and then claim the counter leg. Both legs, deterministically, with the taker unable
    to claim (no ``p``) or refund (its deadline is later). The safety buffer WAS the attack window.


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

    # Convert in one place, and per TERM — because WHICH SIDE OF THE COMPARISON a term lands on,
    # not whether it is a "deadline" or a "reserve", is what decides whether rounding is safe.
    #
    # The gate below is `maker_refund_opens_s < taker_refund_opens_s + margin_s: raise`.
    #
    #   t_rxd   -> LHS.  Rounding DOWN shrinks the left side  -> STRICTER  -> conservative.
    #   t_btc   -> RHS.  Rounding DOWN shrinks the bar        -> PERMISSIVE -> the unsafe side.
    #   margin  -> RHS.  Same as t_btc.
    #
    # #624 derived exactly that for `margin` and fixed it to ceil — and then wrote, right here,
    # that "`t_btc`/`t_rxd` above are DEADLINES and floor correctly (flooring only shrinks the
    # window their holder gets)". That grouped `t_btc` with `t_rxd` when it shares a side with
    # `margin`. The sentence was a CLAIM, no test evaluated it, and the SAME premise was recorded
    # as the reason `t_btc` was safe to leave out of the guard test's derived field set — so the
    # guard for the class carried the error of the instance.
    #
    # `t_btc` is not fixed by ceiling it, though: it is a DEADLINE, and its maturity is not a
    # rounding of anything. BIP68 quantises a SECONDS lock to 512 s, while `normalize_to(BLOCKS)`
    # quantised it to `block_interval_s`. Measured over every encodable value at 600 s/block, the
    # old expression put the taker's refund up to 592 s EARLY (V=20992 -> gate said 20400 s, the
    # chain says 20992 s: a maker-chosen 592 s off a margin the policy demanded in full) and up to
    # 504 s LATE (V=17400 -> gate said 17400 s, the chain says 16896 s: honest terms refused).
    # `consensus_maturity_s` is derived from `to_nsequence()`, so it is the chain's own number in
    # both units and there is nothing left to round. Reachable because `NegotiatedTerms` does NOT
    # pin `t_btc` to BLOCKS — `from_dict` takes the unit tag off the wire and both of that class's
    # own guards are unit-scoped (see `swap_state.py`, "SCOPE, HONESTLY"). No-op for every
    # BLOCKS-tagged `t_btc`, which is everything this tree constructs.
    try:
        taker_refund_opens_s = t_btc.consensus_maturity_s(block_interval_s=policy.block_interval_s)
        # Display + the cheap ordering pre-check only, derived FROM the exact seconds so the
        # message cannot quote a block count the inequality did not use. A BLOCKS lock takes its
        # own value rather than dividing back out: `int(v * iv // iv)` is a block LOW for some v
        # at sub-second intervals, and while nothing real runs one, a pre-check that quietly
        # disagrees with its own input is how the next reader loses an hour.
        btc_blocks = (
            t_btc.value if t_btc.unit is TimeUnit.BLOCKS else int(taker_refund_opens_s // policy.block_interval_s)
        )
        # floor-is-deliberate: t_rxd is the LHS above — flooring shrinks it and makes the gate
        # stricter. (No-op in practice: `NegotiatedTerms` pins t_rxd to BLOCKS.)
        rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        # `margin` is a REQUIREMENT on the RHS, so it ceils. No-op today: every policy the
        # codebase builds tags margin in BLOCKS.
        margin_blocks = _reserve_to_blocks(policy.margin, policy.block_interval_s)
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - normalize_to only raises ValidationError
        raise ValidationError(f"could not normalise timelocks to a common unit: {exc}") from exc

    # ELAPSED COVENANT DEPTH IS SUBTRACTED FROM t_rxd. `t_rxd` is a RELATIVE CSV counted from the
    # covenant's MINING, so once the covenant has confirmations the Radiant refund opens that much
    # sooner and the REAL gap is `(t_rxd - elapsed) - t_btc`. Comparing the negotiated `t_rxd`
    # overstates the gap by exactly `elapsed_blocks`.
    #
    # THE MAKER CHOOSES THAT NUMBER: it locks its covenant, waits, and only then presents the swap.
    # Left uncorrected this is the #482 theft resurrected — negotiated terms that clear the margin,
    # a real gap that does not, and a maker that can refund the Radiant leg while `p` is still
    # secret and then claim the counter leg. Demonstrated at t_rxd=80/t_btc=40/margin=36: a covenant
    # 44 blocks deep left an effective gap of -4 and the pre-fund gate accepted it.
    #
    # The ETH path got this at #482 (the cross-clock gate takes the same parameter) and the BURIAL
    # floor got it at #531; this gate — the one the BTC path relies on — was the third instance of
    # the same conflation and the only one left. Callers that have not read the chain pass 0, which
    # is the negotiated-terms check and still correct for what it is.
    if not isinstance(elapsed_blocks, int) or isinstance(elapsed_blocks, bool) or elapsed_blocks < 0:
        raise ValidationError("assert_timelock_margin elapsed_blocks must be a non-negative int (fail-closed)")
    rxd_blocks -= elapsed_blocks

    # ── WALL CLOCK, NOT RAW BLOCK COUNTS (#567) ──────────────────────────────────────────────
    #
    # `t_btc` counts BITCOIN blocks (~600 s). `t_rxd` counts RADIANT blocks (~300 s nominal, 222 s
    # measured median). Comparing the two counts one-for-one is a unit conflation, and
    # `normalize_to(BLOCKS)` is the IDENTITY for a BLOCKS-tagged Timelock, so
    # `policy.rxd_block_interval_s` never entered this function at all:
    #
    #     t_btc=144 blk (24.0 h)   t_rxd=180 blk (15.0 h)   raw gap 36  ->  the old gate ACCEPTED
    #
    # The Radiant refund opens NINE HOURS BEFORE the counter-leg deadline: the maker refunds the leg
    # it locked while `p` is still secret, then claims the counter leg with `p`. Both legs.
    #
    # THE CONFLATION IS PRE-EXISTING AND WAS FAIL-SAFE UNTIL #482. Requiring `t_btc > t_rxd` in raw
    # counts meant BTC wall-clock exceeded Radiant's by more than 2x, so the bug made this check
    # STRICTER than the protocol needed. Inverting the direction turned it fail-open — the units
    # were only ever safe BECAUSE of the direction, which is why neither the inversion nor the six
    # rounds after it noticed.
    #
    # `margin` stays a BTC-block Timelock: its measured derivation (`ceil(tail_gap / median)`) is
    # "one slow BTC block", a counter-chain quantity, and nothing persisted carries the policy.
    maker_refund_opens_s = rxd_blocks * policy.rxd_block_interval_s
    # `taker_refund_opens_s` is BIP68's own number, computed in the conversion block above — not
    # `btc_blocks * block_interval_s`, which re-quantised it onto the wrong grid.
    margin_s = margin_blocks * policy.block_interval_s

    def _h(seconds: float) -> str:
        return f"{seconds / 3600:.2f} h"

    # Say WHERE the counter-leg number came from, in t_btc's own unit. Printing
    # "{btc_blocks} blk x {block_interval_s}s" beside `taker_refund_opens_s` made the message
    # contradict the inequality it was explaining whenever the two grids disagreed.
    t_btc_desc = (
        f"{t_btc.value} blk x {policy.block_interval_s:g}s"
        if t_btc.unit is TimeUnit.BLOCKS
        else f"{t_btc.value}s, which BIP68 quantises to {taker_refund_opens_s:g}s"
    )

    # The cheap ordering check stays as a NECESSARY condition with a clearer message. It is implied
    # by the inequality below whenever the Radiant interval is the shorter one, so it never refuses
    # anything the wall-clock check would accept — it just fails first, and more legibly.
    if rxd_blocks <= btc_blocks:
        raise ValidationError(
            f"timelock ordering violated: t_rxd ({rxd_blocks} blk"
            f"{f' remaining of {rxd_blocks + elapsed_blocks} after {elapsed_blocks} elapsed' if elapsed_blocks else ''}) "
            f"must exceed t_btc ({btc_blocks} blk) — "
            "the maker holds p and LOCKS the Radiant leg, so that leg carries the LONGER timeout "
            "(Herlihy 1801.09515 §1). The reverse lets the maker refund the covenant while p is "
            "still secret and then claim the counter leg."
        )
    if maker_refund_opens_s < taker_refund_opens_s + margin_s:
        raise ValidationError(
            f"insufficient margin in WALL CLOCK: the maker's Radiant refund opens at "
            f"{_h(maker_refund_opens_s)} ({rxd_blocks} blk"
            f"{f' remaining of {rxd_blocks + elapsed_blocks}' if elapsed_blocks else ''} "
            f"x {policy.rxd_block_interval_s:g}s), but the taker's counter-leg refund opens at "
            f"{_h(taker_refund_opens_s)} ({t_btc_desc}) and the "
            f"margin needs {_h(margin_s)} on top — a shortfall of "
            f"{_h(taker_refund_opens_s + margin_s - maker_refund_opens_s)} "
            f"({'measured' if policy.is_measured else 'ESTIMATED'}). "
            "The two legs count DIFFERENT chains' blocks; a raw block-count comparison accepted "
            "this (#567)."
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
    while the predicate only describes this window — deferred from PR #189.)

    THE RISK THIS WAS WRITTEN FOR IS NOW CLOSED AT THE SOURCE, and it is worth recording that
    this docstring DESCRIBED the defect for months while the ordering that enabled it stood. It
    read: "because ``t_BTC > t_RXD``, a malicious maker can withhold the BTC claim until after
    ``t_RXD`` opens, then claim BTC (revealing ``p``) AND CSV-refund the asset, taking both."

    That is #482 finding 1, stated exactly, and mitigated with a timing predicate that asks the
    taker to bail out early rather than by fixing the relation. With ``t_RXD > t_BTC + margin``
    (see :func:`assert_timelock_margin`) the maker's own refund now opens LAST, so withholding
    buys nothing: the counter leg expires first and the taker refunds it.

    The predicate is KEPT because it still detects a stalled maker — a liveness signal, not a
    theft one — and because a swap negotiated under the old relation is still out there. Treat the
    trigger as "stop waiting", never "keep waiting".

    IMPORTANT — what the taker DOES when this fires is :meth:`mutual_refund` (on ETH a TAKER-role
    coordinator refunds only its counter leg, #850), NOT an asset-only refund. The asset CSV refund
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
    # floor-is-deliberate: this builds `maturity`, and the predicate is `now >= maturity - N`.
    # A SMALLER maturity makes the taker stop waiting SOONER — the conservative direction for a
    # "stop waiting" trigger. (No-op in practice: `NegotiatedTerms` pins t_rxd to BLOCKS.)
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


def _dividing_interval_s(policy: MarginPolicy) -> float:
    """The interval to use when CONVERTING A TIME SPAN INTO A BLOCK COUNT.

    Dividing by a small interval yields MORE blocks, which is more cover — so a reserve wants the
    fast tail. Every `ceil(seconds / interval)` in this module goes through here so a site cannot
    quietly pick the nominal value; the projections that MULTIPLY by an interval deliberately do
    not, and want the slow tail instead.
    """
    return float(policy.rxd_block_interval_fast_s or policy.rxd_block_interval_s)


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


# CHOSEN (not measured): the autonomous claim executor's pre-broadcast value ceiling defaults to
# requiring the cost to reorg the burial to exceed the value at risk by this multiple. An attacker
# is ~indifferent at 1.0, so a margin above 1 is prudent; 2.0 means "reorging the burial must cost
# at least twice the theft gain". The MarginPolicy's own ``burial_safety_factor`` (default 1.0)
# governs the coordinator's burial-RAISING; this is the executor's independent ceiling default.
_DEFAULT_REORG_SAFETY_FACTOR = 2.0


def max_protected_value(
    *,
    rxd_claim_burial_blocks: int,
    reorg_cost_per_block: int,
    safety_factor: float = _DEFAULT_REORG_SAFETY_FACTOR,
) -> int:
    """Max value-at-risk a Radiant claim buried ``rxd_claim_burial_blocks`` deep defends.

    The exact INVERSE of ``_value_scaled_burial_blocks`` (which raises the burial to cover a
    value); this caps the value a given burial defends. Used by the autonomous claim executor as a
    defense-in-depth pre-broadcast gate, independent of the coordinator's value-scaled-burial setup.

    An attacker who reorgs the burial to undo the taker's asset claim (and take the maker's CSV
    refund instead) must spend ~``rxd_claim_burial_blocks * reorg_cost_per_block``; their gain is the
    asset's value. Require ``value * safety_factor <= burial * cost``, so the protected-value ceiling
    is ``floor(burial * cost / safety_factor)``.

    Units: ``reorg_cost_per_block`` and the returned ceiling are in the SAME unit as the declared
    value-at-risk — RXD photons for an ``rxd`` swap, where the value at risk IS ``radiant_amount``;
    for ``ft``/``nft`` the operator declares the asset's market value explicitly. ``reorg_cost_per_block``
    is the attacker's NET marginal cost to add one Radiant block on the reorg chain. Both inputs are
    OPERATOR-SUPPLIED (no live hashrate/price feed in the stack). Pure and fail-closed: raises
    ``ValidationError`` on a non-positive depth/cost or a ``safety_factor`` not a finite float ``>= 1``.
    """
    if (
        not isinstance(rxd_claim_burial_blocks, int)
        or isinstance(rxd_claim_burial_blocks, bool)
        or rxd_claim_burial_blocks <= 0
    ):
        raise ValidationError("rxd_claim_burial_blocks must be a positive int")
    if not isinstance(reorg_cost_per_block, int) or isinstance(reorg_cost_per_block, bool) or reorg_cost_per_block <= 0:
        raise ValidationError(
            "reorg_cost_per_block must be a positive int (operator-MEASURED net marginal cost, "
            "same unit as the declared value-at-risk)"
        )
    if (
        not isinstance(safety_factor, (int, float))
        or isinstance(safety_factor, bool)
        or not math.isfinite(safety_factor)
        or safety_factor < 1.0
    ):
        raise ValidationError(
            "safety_factor must be a finite float >= 1.0 (a factor < 1 would bless theft-profitable swaps)"
        )
    # Integer-exact floor (review INFO): RXD's full supply in photons (~1.6e18) exceeds 2^53, where
    # ``burial*cost/safety_factor`` as a float can drift — even UPWARD, violating the "always round
    # DOWN" safety guarantee. Use the float's exact rational so the ceiling is never larger than true.
    ratio = Fraction(safety_factor)
    return (rxd_claim_burial_blocks * reorg_cost_per_block * ratio.denominator) // ratio.numerator


def _reserve_to_blocks(reserve: Timelock, block_interval_s: float) -> int:
    """Convert a REQUIREMENT/reserve Timelock to BLOCKS, rounding UP for a seconds-tagged value.

    A reserve (claim burial, reorg depth) must round UP: flooring it under-counts the reserve —
    the UNSAFE direction (audit finality INFO). Identity for a BLOCKS-tagged value. Contrast a
    DEADLINE like ``t_rxd``, where flooring is safe because it only shrinks the available window.
    """
    if reserve.unit is TimeUnit.BLOCKS:
        return reserve.value
    return math.ceil(reserve.value / block_interval_s)


def _radiant_reserve_blocks(policy: MarginPolicy, reserve: Timelock) -> int:
    """Convert a RADIANT-chain reserve to blocks, using RADIANT's interval.

    `rxd_claim_burial` and `rxd_claim_inclusion` count RADIANT blocks. They were
    converted with `policy.block_interval_s` — the BITCOIN interval — at seven
    sites, and `policy.rxd_block_interval_s` was used for them nowhere (#579).

    Inert while every constructor tags them BLOCKS, because the conversion is then
    the identity and the interval is never read. That is exactly why it survived:
    a wrong argument that is never used looks like a working one. A SECONDS-tagged
    value makes it live in BOTH directions — measured at 600/300, an 1800 s burial
    (6 Radiant blocks) was used as 3, half the intended depth; and a 900 s burial
    (3 honest Radiant blocks) was REFUSED at construction as "1 blk < floor 2".

    Exists so the choice is made once rather than at each call site. Enforced by
    `tests/test_radiant_reserves_use_the_radiant_interval.py`, which fails if any
    site converts one of these fields with the Bitcoin interval again.
    """
    return _reserve_to_blocks(reserve, policy.rxd_block_interval_s)


def _claim_floor_blocks(policy: MarginPolicy, *, burial: int, counter_reserve: int) -> int:
    """Blocks that must remain before the maker's refund opens for a claim started NOW to be buried
    in time. THE SINGLE DEFINITION — both the fund-time gate and the claim-time assessor call it.

    They disagreed before #511, by exactly one block and on the permissive side. The fund gate
    required `burial + counter_reserve + 1`, its comment naming the extra block as "one block for
    the claim itself to be mined"; `assess_claim_finality` required only `burial + counter_reserve`.
    So a swap could be funded against the stricter floor and then certified SAFE by the looser one
    at a height where the claim provably could not bury in time — measured at burial=6, t_rxd=72:
    `blocks_left == 6` returned SAFE while a claim mined in the very NEXT block reaches depth 6
    exactly AT the refund height, where the maker's refund is simultaneously valid.

    Two gates computing the same quantity from separate expressions is the shape that produced
    #531 and the runner's empty-feasible-set class. Derived once here instead.
    """
    return burial + counter_reserve + _radiant_reserve_blocks(policy, policy.rxd_claim_inclusion)


def _funding_value_at_stake(terms: NegotiatedTerms, policy: MarginPolicy, counter_leg: Any) -> int | None:
    """The swap's value in photons, for the taker gate's ``k`` (see
    :meth:`SwapCoordinator._funding_value_at_stake_photons`, which this is)."""
    candidates: list[int] = []
    if policy.value_at_risk_photons is not None:
        candidates.append(int(policy.value_at_risk_photons))
    if terms.asset_variant == "rxd":
        candidates.append(int(terms.radiant_amount))
    implied = _stablecoin_value_floor_photons(terms, policy, counter_leg)
    if implied is not None:
        candidates.append(int(implied))
    return max(candidates) if candidates else None


def _funding_burial(
    policy: MarginPolicy, chain: RadiantChain, value_at_stake: int | None, *, radiant_min_confirmations: int
) -> int:
    """The ``burial`` term of the taker gate's ``k`` (see :meth:`SwapCoordinator._funding_burial_blocks`,
    which this is): the measured claim burial, else the Radiant leg's ``min_confirmations``, raised on a
    value-bearing network by the value-scaled burial."""
    depth = (
        _radiant_reserve_blocks(policy, policy.rxd_claim_burial)
        if policy.is_measured
        else int(radiant_min_confirmations)
    )
    if not chain.value_bearing:
        return depth
    return max(depth, _value_scaled_burial_blocks(policy, value_at_stake))


#: The refusal for an ETH or ERC-20 counter leg judged without a clock (see
#: :meth:`SwapCoordinator._timelock_ordering_failure`).
_NO_CLOCK_FOR_AN_ABSOLUTE_DEADLINE = (
    "the counter leg's deadline (counter_chain {chain!r}) is an absolute time, so its ordering against t_rxd "
    "is judged from the wall clock and none was supplied; pass now_unix_s (the coordinator never reads the "
    "clock itself)"
)


def taker_gate_early_bound(
    *,
    chain: RadiantChain,
    policy: MarginPolicy,
    value_at_stake_photons: int | None,
    funding_bound: ElapsedBoundPolicy = DEFAULT_ELAPSED_BOUND_POLICY,
    radiant_min_confirmations: int = 1,
) -> EarlyElapsedBound:
    """The elapsed-depth bound the taker gate's negotiation-time check models for steps 6 and 7 —
    :func:`~pyrxd.gravity.funding_spv.early_elapsed_blocks_upper` with the SAME burial the coordinator
    computes (:meth:`SwapCoordinator._funding_proof_room_failure` calls this), for a runner choosing
    terms BEFORE a coordinator exists.

    A runner that derives ``t_btc`` from ``t_rxd`` must reserve ``elapsed_blocks_upper`` Radiant blocks
    of ``t_rxd`` for it: the gate subtracts that bound from ``t_rxd`` before it judges the ordering, so
    a derivation that reserves less produces terms the coordinator refuses at construction.
    ``value_at_stake_photons`` is the value the coordinator will assess (the largest of
    ``value_at_risk_photons``, ``radiant_amount`` for an RXD swap, and a stablecoin counter leg's
    floor). Raises :class:`~pyrxd.gravity.funding_spv.MakerFundingNotVerified` where the gate cannot be
    modelled (no value on a value-bearing network; no shipped checkpoint work).
    """
    burial = _funding_burial(policy, chain, value_at_stake_photons, radiant_min_confirmations=radiant_min_confirmations)
    return early_elapsed_blocks_upper(
        chain=chain, value_at_stake_photons=value_at_stake_photons, burial_blocks=burial, policy=funding_bound
    )


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

    Raises ``ValidationError`` on any un-evaluable input (never assumes "plenty of time").

    Every quantity here ends up in RADIANT blocks, but they do NOT all divide by the same
    interval, and this line used to say they did — "All depths normalised to Radiant BLOCKS
    via ``policy.block_interval_s``", which stated #579's conflation as the rule and is the
    sentence that would send the next reviewer away from the sites that had it. What is
    actually true:

    * the Radiant RESERVES (``rxd_claim_burial``, ``rxd_claim_inclusion``) go through
      ``_radiant_reserve_blocks``, i.e. ``policy.rxd_block_interval_s`` — fixed by #579;
    * the BITCOIN reserve ``btc_claim_reorg_depth`` divides by ``policy.block_interval_s``,
      correctly, and the F-007 step below rescales it into Radiant blocks by the ratio;
    * ``t_rxd`` is a RADIANT deadline and STILL divides by ``policy.block_interval_s`` below —
      the same conflation #579 fixed for the reserves, on a field #579 did not enumerate and
      that ``tests/test_radiant_reserves_use_the_radiant_interval.py`` cannot see (it derives
      its field set from ``MarginPolicy`` names PREFIXED with a chain; ``t_rxd`` lives on
      ``NegotiatedTerms`` and is SUFFIXED). Inert today for the same reason the reserves were —
      every constructor tags it BLOCKS — and stated here rather than quietly left out.
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
        # floor-is-deliberate: this builds `refund_opens_at`, and `blocks_left` counts DOWN from
        # it. A SMALLER deadline leaves FEWER blocks, so the gate squeezes sooner rather than
        # certifying SAFE on a window it does not have. (No-op: t_rxd is pinned to BLOCKS.)
        rxd_blocks = t_rxd.normalize_to(TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s).value
        # Reserves round UP when seconds-tagged (flooring under-counts a reserve — unsafe);
        # t_rxd above floors, which is safe HERE for the reason stated on it — not because it is
        # a deadline. `t_btc` is a deadline too and floors on the PERMISSIVE side of the margin
        # gate, which is how #624's comment came to certify the opposite of the truth.
        flat_burial = _radiant_reserve_blocks(policy, policy.rxd_claim_burial)
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
        # Counter-leg claim is final/reorg-safe. Claim iff our own burial still fits — INCLUDING
        # the blocks the claim needs to be mined (#511), which this compared without until it
        # certified SAFE one block past the point a claim could bury in time.
        if blocks_left >= _claim_floor_blocks(policy, burial=rxd_burial, counter_reserve=0):
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
        counter_reserve_rxd = math.ceil(required_depth_blocks * policy.block_interval_s / _dividing_interval_s(policy))
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
        counter_reserve_rxd = math.ceil(policy.eth_finalization_window_s / _dividing_interval_s(policy))
    if (
        blocks_left >= _claim_floor_blocks(policy, burial=rxd_burial, counter_reserve=counter_reserve_rxd)
        and counter_claim_finality.remaining_positive
    ):
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
    """Result of the pre-BTC-lock validation gate (plan H4(a)).

    ``definitive``: no retry can pass this refusal. It rests only on the agreed terms, local state,
    the clock, or a depth this gate PROVED — and the clock and the proved depth only grow, which
    never loosens one of these checks. False for anything a retry may pass: a chain read, a proof or
    a store that failed; a bound set by one source's REPORT or by the TIME term (a stale header makes
    that larger than the chain is); a missing or too-small configuration (adding a source or a
    setting can undo it). Each classification site says which. :meth:`SwapCoordinator.resume_interrupted_fund`
    acts on it.
    """

    ok: bool
    reason: str = ""
    definitive: bool = False


class _Refusal(str):
    """A refusal reason that also says whether it is definitive (see :class:`PreBtcLockGate`)."""

    definitive: bool = False

    def __new__(cls, text: str, *, definitive: bool) -> _Refusal:
        made = super().__new__(cls, text)
        made.definitive = definitive
        return made


class DefinitiveFundRefusal(ValidationError):
    """The taker gate refused funding for a reason a retry cannot change (``PreBtcLockGate.definitive``)."""


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
    # A zero-argument callable returning a context manager that holds EXCLUSIVE, host-local
    # mutual exclusion over funding this swap (see `record_sink.FileFundLock`). REQUIRED to
    # resume an interrupted ETH fund: `reserve(H)` is what stopped two funders proceeding, the
    # resume deliberately skips it because the record already holds that reservation, and without
    # a replacement two resumers each read the same pre-push balance and each send the shortfall —
    # leaving twice the negotiated amount in an HTLC whose claim sweeps the whole balance to the
    # counterparty. A fresh fund is still covered by the reserve itself.
    fund_lock: Any = None
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
    # Which side this coordinator drives (P3 role guard). ``None`` = the legacy
    # single-operator flow where one coordinator drives both legs; a genuine
    # two-party deployment sets the honest party's role so role-scoped recovery
    # guards (e.g. the taker-stranding asset-only refund) fail closed in code, not
    # merely in a docstring.
    role: SwapRole | None = None
    # The taker gate's elapsed-depth bound policy (surge factor, confidence, the negotiation-time
    # check's slack and work margin): :class:`pyrxd.gravity.funding_spv.ElapsedBoundPolicy`. The
    # maintainer signed off on its defaults on 2026-09-30, except ``early_work_margin``.
    funding_bound: ElapsedBoundPolicy = DEFAULT_ELAPSED_BOUND_POLICY

    def __post_init__(self) -> None:
        if not isinstance(self.margin_policy, MarginPolicy):
            raise ValidationError("margin_policy must be a MarginPolicy")
        if not isinstance(self.funding_bound, ElapsedBoundPolicy):
            raise ValidationError("funding_bound must be an ElapsedBoundPolicy")
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
        if self.role is not None and not isinstance(self.role, SwapRole):
            raise ValidationError("role must be a SwapRole or None")


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
    now_unix_s:
        The caller's wall clock at construction (the coordinator never reads it itself). Used only
        by the negotiation-time check on a NEGOTIATED record on a value-bearing Radiant network,
        where an ETH or ERC-20 counter leg's timelock ordering is judged against the absolute
        ``eth_timeout_unix_s`` from ``now`` — so such a coordinator is refused without it.
    maker_funding_confirmations:
        The confirmations of the maker's covenant funding the CALLER has already observed at
        ``now_unix_s``, or ``None`` (the default: not observed, e.g. a coordinator built before the
        maker funds). Read only by the construction-time projection of when the taker's gate can first
        accept the funding (:meth:`_taker_gate_first_acceptance_wait`): ``k`` minus this many blocks
        remain to wait for. A runner resuming a swap whose funding is already on chain passes the depth
        it read. It can only shorten that projection; steps 3, 5, 6 and 7 read the chain themselves.
        Passing a depth for a funding that does not exist removes the one check that keeps the maker
        from locking into terms whose deadline the taker's gate cannot meet.
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
        now_unix_s: int | None = None,
        maker_funding_confirmations: int | None = None,
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
        # The same floor, from the OTHER leg, and for EVERY asset variant. The RXD check above is
        # exempt for ft/nft, so before this any nonzero value-at-risk satisfied the gate for them
        # and the value-scaled burial fell back to the flat floor (#489).
        if _leg_is_value_bearing(radiant_leg) and config.margin_policy.value_at_risk_photons is not None:
            implied = _stablecoin_value_floor_photons(record.terms, config.margin_policy, leg)
            if implied is not None and config.margin_policy.value_at_risk_photons < implied:
                raise ValidationError(
                    f"value_at_risk_photons ({config.margin_policy.value_at_risk_photons}) is below the "
                    f"{implied} photons this swap's own counter leg declares it is worth "
                    f"({record.terms.value_amount} base units of {record.terms.token_address} at "
                    f"${config.margin_policy.reorg_cost.rxd_price_usd}/RXD). An under-stated "
                    "value-at-risk shrinks the value-scaled claim burial below what the swap is worth. "
                    "Raise value_at_risk_photons, or re-measure the reorg cost if the rate has moved."
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
            fin_reserve_blocks = math.ceil(mp.eth_finalization_window_s / _dividing_interval_s(mp))
            # Use the SAME burial reserve the reorg gate uses (assess_claim_finality:
            # _reserve_to_blocks(policy.rxd_claim_burial, ...)) — NOT the hardcoded estimate (red-team
            # LOW): an operator who measures a burial != 6 would otherwise get a floor that blesses an
            # N the gate's actual (larger) squeeze reserve makes insufficient — false assurance.
            burial_blocks = _radiant_reserve_blocks(mp, mp.rxd_claim_burial)
            min_n = fin_reserve_blocks + burial_blocks - 1
            if config.maker_stall_safety_window_blocks < min_n:
                raise ValidationError(
                    f"maker_stall_safety_window_blocks={config.maker_stall_safety_window_blocks} is below the "
                    f"ETH finality+burial reserve floor {min_n} (= ceil(eth_finalization_window_s "
                    f"{mp.eth_finalization_window_s}/{_dividing_interval_s(mp)}s fast-tail interval)={fin_reserve_blocks} "
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
        #: What the taker gate last PROVED about the maker's funding (k, C, depths), or None.
        self.last_maker_funding: VerifiedMakerFunding | None = None
        # THE NEGOTIATION-TIME CHECK (before anyone locks). A swap whose t_rxd cannot hold the
        # elapsed-depth bound the taker gate will judge (plus the margins steps 6 and 7 add) is
        # refused at step 6 — after the maker has already locked its covenant; and a value-bearing
        # policy without the measured fast tail sizes every timelock reserve at the nominal interval.
        # The terms, the value and the policy are all known here, so refuse now. Only for a
        # NEGOTIATED record: a coordinator built to recover an in-flight swap must construct whatever
        # its terms were.
        if now_unix_s is not None and (not isinstance(now_unix_s, int) or isinstance(now_unix_s, bool)):
            raise ValidationError("now_unix_s must be an int or None")
        if maker_funding_confirmations is not None and (
            not isinstance(maker_funding_confirmations, int)
            or isinstance(maker_funding_confirmations, bool)
            or maker_funding_confirmations < 0
        ):
            raise ValidationError("maker_funding_confirmations must be a non-negative int or None")
        self._maker_funding_confirmations = maker_funding_confirmations
        if record.state is SwapState.NEGOTIATED:
            room = self._funding_proof_room_failure(record.terms, now_unix_s=now_unix_s, at_construction=True)
            if room is not None:
                raise ValidationError(room)

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
    async def pre_btc_lock_check(
        self, terms: NegotiatedTerms, *, now_unix_s: int | None = None, now_sampled_monotonic: float | None = None
    ) -> PreBtcLockGate:
        """Validate everything the taker can check BEFORE funding the counter leg (fail-closed).

        Checks, in order (any failure => do NOT fund):
          1. REF authenticity via ``verify_ref_authenticity`` — the resolved reveal
             must bind to the ADVERTISED asset (genesis-outpoint==ref, `gly` marker,
             optional payload hash, ≥ ``min_ref_confirmations``). Indexer
             unavailable / shallow genesis / wrong asset => fail-closed.
          2. H freshness — a read-only advisory probe of the seen-store (reused H
             => reject early). The authoritative atomic reserve happens later, in
             :meth:`taker_funds_btc`, immediately before the broadcast.
          3. The cross-chain timelock ordering. BTC: the WALL-CLOCK margin
             ``t_rxd * i_rxd >= t_btc * i_btc + margin * i_btc`` (this docstring said
             ``t_btc - t_rxd >= margin`` until 2026-09-02 — the pre-#482 direction, in the
             pre-#567 units, in the gate's own description of itself). ETH: the cross-clock gate that validates the
             ABSOLUTE ``eth_timeout_unix_s`` leaves room for the RELATIVE ``t_rxd`` window
             (needs ``now_unix_s``; audit HIGH-1). The orphaned bridge is wired here.
          4. Maker-*promised* params match the locally re-derived BTC funding SPK
             (the on-chain re-validation happens later in
             :meth:`post_asset_lock_revalidate`).
          5. The MAKER'S ASSET IS REALLY LOCKED (hazard HZ-1 / threat-model S24) —
             :meth:`taker_verify_asset_funding`. Checks 1-4 are all re-derivations of what
             the swap SHOULD look like; this is the only one that reads the Radiant chain,
             and without it the taker locks its counter leg against a maker that locked
             nothing (which then sweeps it with the ``p`` it has held since the envelope).
             Unfunded / mis-valued / shallow / unreadable => fail-closed.

        ``now_unix_s`` is the caller's wall-clock (the ``now_rxd_height`` precedent: the
        coordinator takes the wall clock as a param, never reads it). REQUIRED for an ETH swap (step 3's
        cross-clock gate), for any swap whose Radiant leg is on mainnet (step 5 bounds the elapsed
        depth with it and refuses without it), and whenever the policy carries a reorg-cost
        measurement (step 0). Only a BTC swap on test networks may omit it; step 5 then omits the
        time term of its bound. ``now_sampled_monotonic`` is the :func:`time.monotonic` reading
        taken when ``now_unix_s`` was (default: this call's entry); step 5 advances ``now_unix_s``
        by the monotonic time elapsed since then, measured AFTER its reads (see
        :meth:`taker_verify_asset_funding`). Async because binding (1) awaits the async indexer adapter (a sync
        gate would leak a truthy un-awaited coroutine = fail-OPEN, T7 plan D2).
        """
        if now_sampled_monotonic is None:
            now_sampled_monotonic = _monotonic()
        if not isinstance(terms, NegotiatedTerms):
            raise ValidationError("pre_btc_lock_check requires NegotiatedTerms")

        # 0. The reorg-cost measurement must still hold. Cheapest possible check and it gates a
        #    number that DIVIDES into the burial depth, so a stale one under-buries silently
        #    (#533). Only applies when the operator opted into provenance by supplying a
        #    ReorgCostMeasurement; a bare `rxd_reorg_cost_per_block` has nothing to check, which
        #    is the whole argument for the measurement.
        measurement = self.config.margin_policy.reorg_cost
        if measurement is not None:
            if now_unix_s is None:
                return PreBtcLockGate(
                    ok=False,
                    reason=(
                        "the policy carries a reorg-cost measurement but no now_unix_s was supplied, "
                        "so its freshness cannot be checked. Pass the caller's wall-clock (the "
                        "coordinator never reads the wall clock itself), or drop to a bare "
                        "rxd_reorg_cost_per_block and accept that nothing can tell when it went stale."
                    ),
                )
            try:
                measurement.assert_fresh(now_unix_s)
            except ValidationError as exc:
                return PreBtcLockGate(ok=False, reason=f"reorg-cost measurement is not usable: {exc}")

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

        # 1b. Credential binding (only when the swap is credential-gated). The rule
        #     itself lives in _credential_binding_failure, because it is also a
        #     precondition for BOTH_LOCKED on the MAKER's path — see there for why.
        credential_failure = await self._credential_binding_failure(terms)
        if credential_failure is not None:
            return PreBtcLockGate(ok=False, reason=credential_failure)

        # 2. H freshness — advisory read-only probe for a clean early reject; the
        #    authoritative atomic reserve is in taker_funds_btc, pre-broadcast.
        try:
            # A record carrying a pending deploy means THIS swap already reserved H and put a
            # contract on chain before being interrupted, so seeing H here is expected rather than
            # suspicious — refusing would make a crashed fund permanently unresumable, which is the
            # state this whole handle exists to escape. The authoritative atomic reserve below is
            # skipped on that same evidence; a resume completes the existing contract rather than
            # creating a second one, so the property this probe defends is untouched.
            #
            # SCOPED TO THIS RECORD'S OWN H (#502 item 3). The skip used to fire on a pending
            # deploy for WHATEVER hashlock was passed, so one record left pending disabled the
            # reuse probe for every unrelated H indefinitely — the evidence is "this swap already
            # reserved THIS H", and it says nothing about another one.
            resuming_this_h = bool(self.record.pending_counter_contract or self.record.pending_btc_funding_tx) and (
                bytes(terms.hashlock) == bytes(self.record.terms.hashlock)
            )
            if not resuming_this_h and self.seen_store.has_seen(terms.hashlock):
                # DEFINITIVE: local state. No source is read, and a reservation never expires.
                return PreBtcLockGate(
                    ok=False, reason="hashlock H reused (free-option / preimage-replay risk)", definitive=True
                )
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
            # DEFINITIVE: the terms and the clock only, nothing elapsed. No source is read, and a
            # later `now` only brings the ETH deadline nearer.
            return PreBtcLockGate(ok=False, reason=f"margin check failed: {exc}", definitive=True)

        # 3b. The same timelocks against the SMALLEST depth the taker gate can require of the maker's
        #     funding (see `_funding_proof_room_failure`) — before the chain is read. The constructor
        #     ran it on the record's terms; these are the terms this call was handed.
        room = self._funding_proof_room_failure(terms, now_unix_s=now_unix_s)
        if room is not None:
            # Definitive only where `_funding_proof_room_failure` marks it: the ordering on the terms,
            # and the room in t_rxd on the bound modelled from pyrxd's SHIPPED table and this
            # policy (no source; a later `now` only tightens it). A missing setting, a value, or too
            # few configured operators is a configuration a retry can change.
            return PreBtcLockGate(ok=False, reason=room, definitive=getattr(room, "definitive", False))

        # 4. Maker-promised BTC params match locally re-derived funding SPK.
        try:
            expected_spk = self.counter_leg.derive_funding_scriptpubkey(terms)
            promised_spk = self.counter_leg.promised_funding_scriptpubkey(terms)
        except Exception as exc:
            # DEFINITIVE: a local derivation from the terms; no source, no clock.
            return PreBtcLockGate(
                ok=False, reason=f"could not derive BTC funding SPK; fail-closed ({exc})", definitive=True
            )
        if expected_spk != promised_spk:
            # DEFINITIVE: the maker's own promise against the terms; no source, no clock.
            return PreBtcLockGate(
                ok=False, reason="maker-promised BTC params do not match re-derived funding SPK", definitive=True
            )

        # 5. The MAKER'S ASSET IS REALLY LOCKED (HZ-1). Everything above is a re-derivation of what
        #    the swap SHOULD look like; only this reads the Radiant chain. See
        #    :meth:`taker_verify_asset_funding`.
        #
        #    `cov_confs` is the funding's elapsed depth as an UPPER bound (see
        #    `taker_verify_asset_funding`), because steps 6 and 7 subtract it from t_rxd: SPV proves
        #    only a LOWER bound, and an under-count is the direction that makes the CSV window look
        #    longer than it is.
        try:
            _cov_outpoint, _cov_value, cov_confs = await self.taker_verify_asset_funding(
                terms, now_unix_s=now_unix_s, now_sampled_monotonic=now_sampled_monotonic
            )
        except (ValidationError, NetworkError) as exc:
            # RETRYABLE, every case: a chain read or a proof that failed. Even the checkpoint horizon:
            # the height it is judged at is first the SERVER'S report, and a source's tip headers can
            # raise k, so one source can trip it.
            return PreBtcLockGate(
                ok=False, reason=f"maker's Radiant covenant not verified; fail-closed ({exc})", definitive=False
            )
        except Exception as exc:
            return PreBtcLockGate(
                ok=False, reason=f"could not verify the maker's Radiant covenant; fail-closed ({exc})"
            )

        # 6 and 7. The timelocks judged against the window that ACTUALLY REMAINS once `cov_confs`
        #    blocks of t_rxd have elapsed — see `_judge_remaining_window`, which the lock-time
        #    re-run in `taker_funds_btc` calls again with the re-run's own bound.
        remaining = self._judge_remaining_window(terms, cov_confs=cov_confs, now_unix_s=now_unix_s)
        if remaining is not None:
            return remaining

        return PreBtcLockGate(ok=True)

    def _judge_remaining_window(
        self, terms: NegotiatedTerms, *, cov_confs: int, now_unix_s: int | None
    ) -> PreBtcLockGate | None:
        """Steps 6 and 7 (:meth:`_remaining_window_failure`), with the refusal CLASSIFIED.

        DEFINITIVE only when what this gate PROVED already trips it. ``cov_confs`` is the elapsed
        UPPER bound, set by whichever term is largest: the proved depth, the TIME term, or one
        source's REPORT. A report can be one over-reporting source (even an unidentified one), and
        the time term grows when the proof's newest header is stale — so a refusal they cause may
        pass on a retry with that source removed or a fresh header. The proved depth is backed by the
        proof and only grows, as the clock does, and neither ever loosens steps 6 or 7: a refusal at
        the proved depth stands. Without this run's proof to read the proved depth from, the refusal
        is retryable.
        """
        gate = self._remaining_window_failure(terms, cov_confs=cov_confs, now_unix_s=now_unix_s)
        if gate is None:
            return None
        f = self.last_maker_funding
        if f is None or f.elapsed_blocks_upper != cov_confs:
            return dataclasses.replace(gate, definitive=False)
        if f.proved_depth >= cov_confs:
            return gate
        at_proved = self._remaining_window_failure(terms, cov_confs=f.proved_depth, now_unix_s=now_unix_s)
        return dataclasses.replace(gate, definitive=at_proved is not None and at_proved.definitive)

    def _remaining_window_failure(
        self, terms: NegotiatedTerms, *, cov_confs: int, now_unix_s: int | None
    ) -> PreBtcLockGate | None:
        """Steps 6 and 7 of :meth:`pre_btc_lock_check`: None when the timelocks still hold with
        ``cov_confs`` blocks of ``t_rxd`` already elapsed; a refusing gate otherwise.

        ``cov_confs`` is an elapsed-depth UPPER bound from :meth:`taker_verify_asset_funding`. Every
        run of that method that a lock relies on must be judged here ON ITS OWN BOUND: the
        lock-time re-run in :meth:`taker_funds_btc` reads the chain later than the gate did, so its
        bound can be larger, and a window that held on the gate's bound need not hold on it.
        """
        # 6. The burial-vs-t_rxd floor, using the window that ACTUALLY REMAINS.
        #
        # This ran as step 3b, before the chain read, against the NEGOTIATED t_rxd. But `t_rxd` is a
        # RELATIVE CSV measured from the covenant's confirmation, so by the time the taker funds,
        # `cov_confs` blocks of it are already spent. `assess_claim_finality` knows this — it grants
        # SAFE on `blocks_left - counter_reserve >= burial` where `blocks_left = t_rxd - cov_confs`
        # — and the old check's own comment said so two lines above comparing against the
        # undecremented value.
        #
        # The shortfall is not incidental: step 5 REQUIRES the covenant be `_asset_funding_depth()`
        # deep before the taker funds, which on a measured policy is exactly `rxd_claim_burial`. So
        # `cov_confs >= burial` always holds on the real-value path and the old floor understated
        # the requirement by at least a full burial, on every swap.
        #
        # It moved here rather than reading the chain earlier so the cheap local checks still fail
        # fast; this is the first point where the elapsed depth is known.
        reported_by = self._elapsed_set_by_a_report(cov_confs)
        gate = self._assert_t_rxd_can_reach_a_safe_claim(terms, cov_confs=cov_confs, reported_by=reported_by)
        if gate is not None:
            return gate

        # 7. THE CROSS-CLOCK ORDERING GATE, RE-RUN AGAINST THE WINDOW THAT ACTUALLY REMAINS.
        #
        # Step 3 ran it against the NEGOTIATED t_rxd, anchored at `now`. But t_rxd is a relative
        # CSV from the covenant's mining, so `cov_confs` blocks of it are already spent and the
        # refund opens that much sooner than step 3 computed. Under the OLD relation an overstated
        # window was the conservative direction; inverted (#482), it is the direction that lets the
        # maker refund its Radiant leg while still holding `p` for the ETH leg.
        #
        # THE GAP IS MAKER-CONTROLLED, which is what makes it an attack rather than an inaccuracy:
        # the maker locks its covenant, waits, and only then presents the swap. Step 3 cannot see
        # that — `cov_confs` is not known until the chain read at step 5. Exactly the #531 shape,
        # which fixed this same conflation for the burial floor and left the ordering gate on the
        # negotiated value.
        #
        # BOTH COUNTER CHAINS, mirroring step 3's own branch. This ran for ETH only when it landed,
        # and the BTC path — the flagship BTC<->RXD corridor — was left comparing the NEGOTIATED
        # t_rxd at step 3 and nothing else. Its only elapsed-aware check was step 6's claim floor
        # (burial + reserve + inclusion, ~8 blocks), which is far below a 36-block margin, so a
        # maker could age its covenant and walk the real gap to zero and past it. Fixing the ETH
        # instance and not the class is the failure this codebase keeps repeating; a security panel
        # found it here within an hour of the ETH fix merging.
        try:
            if terms.counter_chain == "btc":
                assert_timelock_margin(terms.t_btc, terms.t_rxd, self.config.margin_policy, elapsed_blocks=cov_confs)
            else:
                self._assert_eth_timelock_ordering(terms, now_unix_s=now_unix_s, elapsed_blocks=cov_confs)
        except ValidationError as exc:
            why = f"margin check failed against the REMAINING window: {exc}"
            if reported_by is not None:
                why += f". The elapsed figure there ({cov_confs}) {reported_by}"
            # Definitive AT THIS DEPTH; `_judge_remaining_window` decides by the proved depth.
            return PreBtcLockGate(ok=False, reason=why, definitive=True)
        return None

    def _asset_funding_depth(self) -> int | None:
        """How deep the MAKER's Radiant covenant funding must be buried before the taker locks.

        The RXD mirror of :meth:`_btc_counter_funding_depth`, and it reuses the policy's EXISTING
        RXD reorg knob rather than inventing a second notion of Radiant finality: a real-value
        (``is_measured``) swap must bury the covenant funding ``rxd_claim_burial`` deep — the same
        depth the claim-finality gate requires of the taker's own Radiant claim. ``None`` (an
        estimated/test policy) defers to the leg's configured ``min_confirmations``, the same
        ``is_measured`` discipline the ETH ``'finalized'`` pin, the N-floor and the cross-clock
        margin already use.
        """
        policy = self.config.margin_policy
        if not policy.is_measured:
            return None
        return _radiant_reserve_blocks(policy, policy.rxd_claim_burial)

    def _elapsed_set_by_a_report(self, cov_confs: int) -> str | None:
        """When the taker gate's last result put the elapsed-depth bound at ``cov_confs`` because a
        configured source REPORTED that depth (``bound_term == "reported"``: above both what was
        proved and the time term), the clause naming that source and what was proved; else None.

        THE RULE, and why it is attribution rather than a cap. A report can only RAISE the bound
        (:func:`~pyrxd.gravity.funding_spv.elapsed_blocks_upper_bound`), from any configured source,
        including one that never counts as an operator. Capping it would let the bound fall below a
        depth a source the taker chose to ask has seen — an UNDER-count of the blocks elapsed, the
        direction that makes the maker's refund look further away than it is. So one source
        over-reporting can still refuse a swap after the maker has locked (the taker configured that
        source, and could equally walk away). What it must not do is have the refusal state that
        figure as the covenant's depth, or point the user at the maker's timing: the refusal says
        whose report it is and what was proved, so the user can check that source.
        """
        f = self.last_maker_funding
        if f is None or f.bound_term != "reported" or f.elapsed_blocks_upper != cov_confs:
            return None
        time_total = None if f.time_blocks is None else f.reference_height - f.height + 1 + f.time_blocks
        # A report EQUAL to the proved depth (or the time term) changed nothing: "reported" names a
        # tie there, and the figure is as good as proved. Only a report above both is attributed.
        if f.reported_depth is None or f.reported_depth <= max(f.proved_depth, time_total or 0):
            return None
        who = [k for k, d in f.reported_by_operator if d == f.reported_depth] or ["a configured source"]
        time_part = "there was no time term" if time_total is None else f"its time term {time_total}"
        return (
            f"is not a proved depth: it is the largest depth a configured source REPORTED ({', '.join(who)}: "
            f"{f.reported_depth}), above what this gate proved ({f.proved_depth} deep) and {time_part}. A report "
            "can only raise this bound, so one source reporting too high refuses the swap here; if that source is "
            "wrong, fix or remove it and retry"
        )

    def _assert_t_rxd_can_reach_a_safe_claim(
        self, terms: NegotiatedTerms, *, cov_confs: int, reported_by: str | None = None
    ) -> PreBtcLockGate | None:
        """None when the swap can still reach a SAFE claim; a refusing gate otherwise.

        *reported_by* (:meth:`_elapsed_set_by_a_report`): ``cov_confs`` came from a source's report,
        not a proof — the refusal then says so and names it instead of calling it the covenant's depth.

        `assess_claim_finality` returns SAFE only when `blocks_left - counter_reserve >= burial`,
        and `blocks_left` is `t_rxd` MINUS the covenant confirmations already elapsed. Checking the
        NEGOTIATED `t_rxd` instead — which this did until #531 — understates the floor by exactly
        `cov_confs`, and step 5 forces `cov_confs >= burial` on a measured policy, so the gap was
        never zero on the path that matters.

        The MAKER chooses `t_rxd`, and shrinking it makes the ordering check pass MORE easily
        (`t_btc - t_rxd` grows) — so the one gate that looked at `t_rxd` rewarded exactly the
        direction that nullifies the burial.
        """
        mp = self.config.margin_policy
        try:
            burial, counter_reserve, required = self._safe_claim_terms(terms)
            elapsed = max(0, int(cov_confs))
            remaining = int(terms.t_rxd.value) - elapsed
            # Both refusals below are definitive AT THIS DEPTH; `_judge_remaining_window` decides by
            # the proved depth whether a retry could pass them.
            if remaining < required and reported_by is not None:
                leaving = f"leaving {remaining}" if remaining > 0 else "leaving none"
                return PreBtcLockGate(
                    ok=False,
                    definitive=True,
                    reason=(
                        f"t_rxd is {int(terms.t_rxd.value)} blocks, and this gate's upper bound on the blocks "
                        f"elapsed since the maker's covenant was mined is {elapsed}, {leaving}; a safe claim needs "
                        f"{required} (burial {burial} + counter-leg reserve {counter_reserve} + "
                        f"{_radiant_reserve_blocks(mp, mp.rxd_claim_inclusion)} to be mined). That {elapsed} "
                        f"{reported_by}."
                    ),
                )
            if remaining < required:
                leaving = f"leaving {remaining}" if remaining > 0 else "leaving none"
                return PreBtcLockGate(
                    ok=False,
                    definitive=True,
                    reason=(
                        f"t_rxd is {int(terms.t_rxd.value)} blocks and the maker's covenant is already "
                        f"{elapsed} deep, {leaving}; a safe claim needs {required} "
                        f"(burial {burial} + counter-leg reserve {counter_reserve} + "
                        f"{_radiant_reserve_blocks(mp, mp.rxd_claim_inclusion)} to be mined), so t_rxd is "
                        f"{required - remaining} blocks short. "
                        "This swap can NEVER reach a safe claim: the taker would reveal, find every "
                        "claim SQUEEZED, and be left choosing between a reorg-reversible claim and "
                        "walking away from a funded counter leg. Negotiate a longer t_rxd, fund "
                        "sooner after the covenant confirms, or lower the value-at-risk."
                    ),
                )
        except ValidationError as exc:
            # RETRYABLE: the policy's burial terms could not be computed — a configuration a retry
            # can change, not a judgement on the swap.
            return PreBtcLockGate(
                ok=False, reason=f"burial-vs-t_rxd check failed; fail-closed ({exc})", definitive=False
            )
        return None

    def _safe_claim_terms(self, terms: NegotiatedTerms) -> tuple[int, int, int]:
        """``(burial, counter_reserve, required)``: the blocks of ``t_rxd`` a safe claim still needs once
        the covenant is on chain — step 6's floor, :func:`_claim_floor_blocks` on the burial and the
        counter-leg reserve."""
        mp = self.config.margin_policy
        flat_burial = _radiant_reserve_blocks(mp, mp.rxd_claim_burial)
        burial = max(flat_burial, _value_scaled_burial_blocks(mp, mp.value_at_risk_photons))
        # max(flat, value-scaled) — the SAME term the claim-time gate uses. Checking only the
        # value-scaled component let the FLAT burial dominate unnoticed, and made this inert
        # whenever `rxd_reorg_cost_per_block` was unset, since that term is 0 there.
        counter_reserve = 0
        if terms.counter_chain != "btc" and mp.eth_finalization_window_s is not None:
            counter_reserve = math.ceil(mp.eth_finalization_window_s / _dividing_interval_s(mp))
        # The SHARED floor (#511) — the claim-time assessor computes it from the same
        # function, so this gate and that one cannot drift apart again.
        return burial, counter_reserve, _claim_floor_blocks(mp, burial=burial, counter_reserve=counter_reserve)

    def _safe_claim_blocks(self, terms: NegotiatedTerms) -> int:
        """Step 6's floor: the blocks of ``t_rxd`` a safe claim needs after the elapsed depth."""
        return self._safe_claim_terms(terms)[2]

    def _funding_value_at_stake_photons(self, terms: NegotiatedTerms) -> int | None:
        """The swap's value in photons, for the taker gate's ``k`` — the coordinator's own assessment.

        The largest of what the policy and the terms already say it is worth: the operator's
        ``value_at_risk_photons``; for an ``rxd`` swap, ``radiant_amount`` (its photons ARE the
        asset, so it is a floor); and for a stablecoin counter leg, the photons its declared value
        implies at the measured price (:func:`_stablecoin_value_floor_photons`). ``ft``/``nft`` have
        no in-protocol value, so they carry the operator's figure or nothing — and nothing refuses
        on a value-bearing network (:func:`pyrxd.gravity.funding_spv.required_funding_confirmations`).
        """
        return _funding_value_at_stake(terms, self.config.margin_policy, self.counter_leg)

    def _funding_burial_blocks(self, chain: RadiantChain, value_at_stake: int | None) -> int:
        """The ``burial`` term of the taker gate's ``k`` — the swap's existing reorg burial.

        On a value-bearing network that is the configured depth raised by the VALUE-SCALED burial —
        a reorg that removes the maker's funding after the taker locks is the same economic attack as
        one that removes the taker's claim, so it is priced the same way. A test network has no value
        to scale by, so its configured depth stands.
        """
        return _funding_burial(
            self.config.margin_policy,
            chain,
            value_at_stake,
            radiant_min_confirmations=int(getattr(self.radiant_leg, "min_confirmations", 1)),
        )

    def _timelock_ordering_failure(
        self, terms: NegotiatedTerms, *, now_unix_s: int | None, elapsed_blocks: int
    ) -> str | None:
        """The cross-chain timelock ordering :meth:`pre_btc_lock_check` judges at step 3
        (``elapsed_blocks=0``) and step 7 (the elapsed-depth bound), for EVERY counter leg: why it
        fails with *elapsed_blocks* of ``t_rxd`` spent, or None.

        BTC: :func:`assert_timelock_margin`. ETH and ERC-20: :meth:`_assert_eth_timelock_ordering`,
        which judges the absolute ``eth_timeout_unix_s`` from *now_unix_s* and so cannot be judged
        without it — that is a failure here, never a skip."""
        try:
            if terms.counter_chain == "btc":
                assert_timelock_margin(
                    terms.t_btc, terms.t_rxd, self.config.margin_policy, elapsed_blocks=elapsed_blocks
                )
            else:
                if now_unix_s is None:
                    return _NO_CLOCK_FOR_AN_ABSOLUTE_DEADLINE.format(chain=terms.counter_chain)
                self._assert_eth_timelock_ordering(terms, now_unix_s=now_unix_s, elapsed_blocks=elapsed_blocks)
        except ValidationError as exc:
            return str(exc)
        return None

    def _funding_proof_room_failure(
        self, terms: NegotiatedTerms, *, now_unix_s: int | None = None, at_construction: bool = False
    ) -> str | None:
        """Why *terms* are refused BEFORE ANYONE LOCKS on a value-bearing Radiant network, or None.

        Run when the coordinator is built for a NEGOTIATED record (with the ``now_unix_s`` it was
        built with) and again at :meth:`pre_btc_lock_check` step 3b (with that call's), before the
        chain is read. The maker locks its covenant BEFORE the taker's gate runs steps 3, 6 and 7, so
        anything those steps would refuse on an honest chain has to be refused here instead, or the
        maker's asset sits locked for ``t_rxd`` behind a swap that cannot proceed. Six checks:

        1. THE MEASURED FAST TAIL (every role). ``MarginPolicy.rxd_block_interval_fast_s`` is what
           time spans are converted into Radiant blocks by (:func:`_dividing_interval_s`); unset,
           that falls back to the nominal interval. WHERE IT IS READ differs by corridor. ETH/ERC-20:
           at fund time, step 6's finalization reserve and step 7's projection of where the maker's
           refund opens (:meth:`_assert_eth_timelock_ordering`). BTC: NOT at fund time — step 6's
           counter reserve is 0 and step 7 (:func:`assert_timelock_margin`) projects the refund at
           the nominal ``rxd_block_interval_s`` — only at claim time, in
           :func:`assess_claim_finality`'s counter-leg reserve. Either way it is read independently of
           the taker gate's elapsed-depth bound, so a value-bearing swap is refused without it.
        2. A VALUE AT STAKE (a coordinator that runs the taker gate — any role but
           ``SwapRole.MAKER``). The gate sizes the depth it requires of the maker's funding from it
           and refuses without one at step 5, after the maker has locked.
        3. TWO OPERATORS ABOVE DUST (a coordinator that runs the taker gate). Above
           ``funding_bound.single_operator_threshold_photons`` (``dust_threshold_photons`` unless the
           user override ``accept_single_operator_up_to_photons`` is set) the gate refuses unless at
           least two distinct operators report the funding transaction's depth (:data:`~pyrxd.gravity.funding_spv.MIN_REPORTING_OPERATORS`);
           a Radiant leg configured to ask fewer operator groups (``configured_depth_operators``,
           derived from each source's ``source_key``) is refused here, naming them.
        4. ROOM IN ``t_rxd``. Step 6 subtracts the gate's elapsed-depth UPPER bound from ``t_rxd``, and
           step 7 re-runs the timelock ordering against what remains. This models that bound with
           :func:`~pyrxd.gravity.funding_spv.early_elapsed_blocks_upper` — built from pyrxd's shipped
           checkpoint data only, to be AT LEAST what step 6 computes on an honest chain (blocks at the
           nominal spacing, the newest header up to ``funding_bound.early_slack_s`` old, no header
           above the newest checkpoint harder than ``funding_bound.early_work_margin`` times the
           shipped last interval's hardest) — and runs steps 6 and 7 on it with this coordinator's
           policy, for EVERY counter leg (:meth:`_timelock_ordering_failure`). So a swap this accepts
           is not refused at step 6 or 7 on such a chain at a ``now`` no earlier than this one; what
           the model does not cover is listed on that function, and steps 6 and 7 on the proved bound
           stay authoritative.
        5. STEP 3 ITSELF (every role, every counter leg): the timelock ordering with nothing elapsed.
           An ETH or ERC-20 counter leg's deadline is absolute, so it is judged from ``now_unix_s``
           and refused without one. A later ``now`` only moves the projected Radiant refund later, so
           the ordering judged here still holds at the taker's steps 3 and 7. The deadline's own
           liveness floor (:func:`assert_eth_deadline_is_claimable`) runs the other way — a later
           ``now`` is nearer the deadline — so AT CONSTRUCTION (``at_construction``) it is also judged
           at the time the taker's gate can first accept the funding on the modelled honest chain
           (:meth:`_taker_gate_first_acceptance_wait`): the blocks the funding still lacks of ``k``
           (all ``k`` before the maker funds; fewer, or none, when the caller observed it on chain)
           plus ``funding_bound.early_slack_s`` (the newest header up to that old). Not for a record
           carrying a pending counter-leg deploy (a resumed fund: the taker already passed its gate).
           At step 3b the funding already exists and step 3 has just judged it at the real ``now``,
           so nothing is added there.
        6. THE CHECKPOINT HORIZON (a coordinator that runs the taker gate, AT CONSTRUCTION only, not
           for a resumed fund). Step 5 refuses a funding whose ``k``-th block lies more than
           :data:`~pyrxd.gravity.funding_spv.MAX_HEADERS_FROM_CHECKPOINT_SDK` blocks past this pyrxd's
           newest checkpoint; :func:`~pyrxd.gravity.funding_spv.checkpoint_horizon_failure` projects
           that height from the newest checkpoint's timestamp and ``now`` (``now_unix_s``, or the
           system clock when the coordinator was built without one — a BTC counter leg needs no
           clock otherwise), and refuses with "upgrade pyrxd". At step 3b the funding exists and
           step 5 judges its real height a moment later, so it is not projected there.

        None — no check — on a test network, where there is no value term; and when the
        configuration has no Radiant chain, which the gate itself refuses.
        """
        try:
            chain = radiant_chain_for_leg(self.radiant_leg, counter_leg=self.counter_leg)
        except MakerFundingNotVerified:
            return None
        if not chain.value_bearing:
            return None
        mp = self.config.margin_policy
        before = f"refused before anyone locks, on Radiant {chain.name}: "
        if mp.rxd_block_interval_fast_s is None:
            return before + (
                "a value-bearing swap needs MarginPolicy.rxd_block_interval_fast_s, the MEASURED fast-tail (p10) "
                "Radiant inter-block interval in seconds. The timelock reserves convert time spans into Radiant "
                f"blocks by dividing by it, and the nominal {mp.rxd_block_interval_s:g}s they fall back to counts "
                "far fewer blocks than a measured p10. Measure it for this run and set it "
                "(MarginPolicy.measured(rxd_block_interval_fast_s=...))"
            )
        if terms.counter_chain != "btc" and now_unix_s is None:
            return before + _NO_CLOCK_FOR_AN_ABSOLUTE_DEADLINE.format(chain=terms.counter_chain)
        # 5. Step 3 itself — the ordering with nothing elapsed. At step 3b it already passed; at
        #    construction nothing else has run it, and the maker locks before the taker's step 3 does.
        #    Reported only when nothing below has a more specific reason (step 6 or 7 on the bound).
        ordering = self._timelock_ordering_failure(terms, now_unix_s=now_unix_s, elapsed_blocks=0)
        step3 = (
            None
            if ordering is None
            else _Refusal(
                before + f"the timelock ordering fails (pre_btc_lock_check step 3): {ordering}", definitive=True
            )
        )
        runs_taker_gate = self.config.role is not SwapRole.MAKER
        value = self._funding_value_at_stake_photons(terms)
        if value is None or value <= 0:
            if not runs_taker_gate:
                return step3
            return before + (
                "the taker gate this coordinator runs needs a value at stake to size the confirmations it "
                "requires of the maker's funding, and refuses without one at step 5 — after the maker has "
                "locked; set MarginPolicy.value_at_risk_photons to the swap's value in photons (a coordinator "
                "that drives only the maker side, config.role=SwapRole.MAKER, is not refused for this)"
            )
        fb = self.config.funding_bound
        needed = fb.requires_operators(chain, value) if runs_taker_gate else 0
        if needed:
            fetch_ops = getattr(self.radiant_leg, "configured_depth_operators", None)
            configured = tuple(str(o) for o in fetch_ops()) if callable(fetch_ops) else ()
            counted = counted_operators(configured)
            if len(counted) < needed:
                named = ", ".join(configured) if configured else "none (this Radiant leg does not say which it asks)"
                return before + (
                    f"the value at stake ({value} photons) is above the taker gate's dust threshold "
                    f"({fb.single_operator_threshold_photons} photons), so the gate requires the maker's funding depth "
                    f"reported by at least {needed} distinct operators (grouped by source_key), and this Radiant "
                    f"leg is configured to ask {len(counted)}: {named}. Add a depth source run by another operator "
                    "(RadiantChainIO(..., depth_sources=...) — pyrxd's shipped mainnet endpoints, or your own node)"
                    + fb.single_operator_refusal_hint()
                )
        burial = self._funding_burial_blocks(chain, value)
        try:
            early = taker_gate_early_bound(
                chain=chain,
                policy=mp,
                value_at_stake_photons=value,
                funding_bound=self.config.funding_bound,
                radiant_min_confirmations=int(getattr(self.radiant_leg, "min_confirmations", 1)),
            )
        except MakerFundingNotVerified as exc:
            return before + f"the taker gate's elapsed-depth bound cannot be modelled: {exc}"
        if runs_taker_gate and at_construction and not self.record.pending_counter_contract:
            horizon = checkpoint_horizon_failure(
                chain=chain,
                now_unix_s=int(time.time()) if now_unix_s is None else now_unix_s,
                required_confirmations=early.required_confirmations,
                observed_confirmations=self._maker_funding_confirmations,
                slack_s=int(fb.early_slack_s),
            )
            if horizon is not None:
                return before + horizon
        elapsed = early.elapsed_blocks_upper
        why = None
        remedy = "Negotiate a longer t_rxd or a smaller value"
        floor = self._assert_t_rxd_can_reach_a_safe_claim(terms, cov_confs=elapsed)
        if floor is not None:
            t_rxd = int(terms.t_rxd.value)
            try:
                need = elapsed + self._safe_claim_blocks(terms)
            except ValidationError:
                why = f"pre_btc_lock_check step 6 refuses on it: {floor.reason}"
            else:
                n_left = t_rxd - elapsed
                left = (
                    f"only {n_left} block{'s' if n_left != 1 else ''} of it {'are' if n_left != 1 else 'is'} left"
                    if n_left > 0
                    else "none of it is left"
                )
                why = (
                    f"{left} once {elapsed} have elapsed, and a safe claim needs {need - elapsed} "
                    f"(pre_btc_lock_check step 6): t_rxd is {need - t_rxd} blocks short of the {need} this needs"
                )
        else:
            # Step 7, for EVERY counter leg. This ran for a BTC counter leg only, so an ETH or ERC-20
            # swap whose t_rxd could not outlast its deadline once the bound had elapsed constructed,
            # the maker locked, and the taker's step 3 or 7 refused.
            step7 = (
                None
                if step3 is not None  # nothing elapsed already fails: step 3's reason is the one to give
                else self._timelock_ordering_failure(terms, now_unix_s=now_unix_s, elapsed_blocks=elapsed)
            )
            if step7 is not None:
                why = f"with {elapsed} elapsed the timelock ordering fails (pre_btc_lock_check step 7): {step7}"
            elif step3 is None and at_construction and terms.counter_chain != "btc" and now_unix_s is not None:
                projected = self._taker_gate_first_acceptance_wait(chain, early)
                if projected is not None:
                    wait_s, basis = projected
                    try:
                        assert_eth_deadline_is_claimable(
                            now_unix_s=now_unix_s + wait_s,
                            eth_timeout_unix_s=terms.eth_timeout_unix_s,
                            margin=mp.cross_clock_margin,
                        )
                    except ValidationError as exc:
                        why = (
                            f"the taker's gate can first accept the funding about {wait_s} s from now ({basis}), and "
                            f"by then the counter leg's deadline is too near (pre_btc_lock_check steps 3 and 7): {exc}"
                        )
                        remedy = "Negotiate a later counter-leg deadline, and a t_rxd that outlasts it"
        if why is None:
            return step3
        return _Refusal(
            before
            + f"with this coordinator's policy the taker gate can require the maker's funding up to {early.required_confirmations} "
            f"blocks deep (k = max({MIN_FUNDING_CONFIRMATIONS}, burial {burial}, ceil(2 × value {value} photons ÷ C) "
            f"= {early.value_term}), with C at least {early.cost_floor_photons} photons by pyrxd's shipped checkpoints); "
            f"its upper bound on the blocks elapsed since the funding can then be {elapsed} on an honest chain "
            f"(blocks every {int(chain.target_spacing_s)} s, the newest up to {fb.early_slack_s} s old; the blocks after "
            f"the reference header {early.reference_depth} deep counted at {fb.surge_factor:g}× that rate, "
            f"ε = {early.epsilon:.3g}); and t_rxd is {int(terms.t_rxd.value)} blocks: {why.rstrip('.')}. {remedy}",
            definitive=True,
        )

    def _taker_gate_first_acceptance_wait(
        self, chain: RadiantChain, early: EarlyElapsedBound
    ) -> tuple[int, str] | None:
        """How long after construction the taker's gate can first accept the maker's funding, as
        ``(seconds, how it was projected)`` — or ``None`` where nothing is waited for.

        The gate accepts the funding once it is ``k`` deep (``early.required_confirmations``, the
        largest ``k`` it can require). A coordinator built BEFORE the maker funds waits for all ``k``:
        the funding mined one block after the maker broadcasts, ``k - 1`` more after it. One built
        after the funding is already on chain waits only for the blocks it still lacks — none once
        it is ``k`` deep — so the caller passes the depth it observed
        (``maker_funding_confirmations``).

        HOW LONG THOSE BLOCKS TAKE is not their count times the nominal spacing: that is the MEAN of
        the time ``n`` blocks take, and an honest chain at the nominal rate is slower than its mean
        about half the time — after the maker has locked, when the taker's step 3 then refuses. The
        wait is the upper ``ε`` quantile of that time instead (:func:`~pyrxd.gravity.funding_spv.erlang_upper_quantile_s`:
        ``n`` blocks arriving as a Poisson process at one per nominal spacing), with the same ``ε`` as
        the elapsed-depth bound (``early.epsilon``: ``ElapsedBoundPolicy.epsilon`` of the swap's
        value), plus ``funding_bound.early_slack_s`` (the newest header up to that old). A chain slower
        than that quantile is the case the model leaves to step 3, which judges the real clock before
        the taker locks.

        ``None`` for a record carrying a pending counter-leg deploy: the taker has already passed its
        gate and started funding, so there is no first acceptance ahead to project. The lock-time
        judgement (steps 3, 6 and 7 on the bound) still runs on it.
        """
        if self.record.pending_counter_contract:  # a resumed fund: the taker already passed its gate
            return None
        k = early.required_confirmations
        seen = self._maker_funding_confirmations
        remaining = k if seen is None else max(0, k - seen)
        if remaining == 0:
            return (
                0,
                f"the maker's funding was observed {seen} deep when the coordinator was built, at least the {k} the gate can require",
            )
        spacing = int(chain.target_spacing_s)
        slack = int(self.config.funding_bound.early_slack_s)
        blocks_s = erlang_upper_quantile_s(remaining, spacing_s=spacing, epsilon=early.epsilon)
        start = "" if seen is None else f"the funding observed {seen} deep, "
        return (
            blocks_s + slack,
            f"{start}{remaining} more block{'s' if remaining != 1 else ''} at {spacing} s on average take up to "
            f"{blocks_s} s at ε = {early.epsilon:.3g}, and the newest header may be up to {slack} s old",
        )

    async def taker_verify_asset_funding(
        self, terms: NegotiatedTerms, *, now_unix_s: int | None = None, now_sampled_monotonic: float | None = None
    ) -> tuple[str, int, int]:
        """Fail-closed: the MAKER's asset must be PROVED locked on chain before the taker locks anything.

        Returns ``(outpoint, value_photons, elapsed_blocks_upper)``; RAISES on anything else. The
        third value is an UPPER bound on the blocks mined since the funding (for the timelock gates
        that subtract it from ``t_rxd``); the full record of what was proved — ``k``, ``C``, the
        proved depth — is left on :attr:`last_maker_funding`.

        THE FUNNEL. Every path that locks the taker's counter leg crosses this method before
        ``counter_leg.fund`` runs: :meth:`pre_btc_lock_check` step 5, and the re-run inside
        :meth:`taker_funds_btc` immediately before the broadcast (which closes the verify->lock
        TOCTOU: a maker double-spending its covenant funding away between check and lock), on the
        BTC and the ETH/ERC-20 branch alike; :meth:`resume_interrupted_fund` completes a crashed
        fund through :meth:`taker_funds_btc`, so it crosses both. ``tests/test_taker_funding_spv_gate.py``
        derives the set of ``fund`` call sites from this module and checks each is preceded by it.

        WHY. HZ-1 in ``docs/htlc-handshake-wire-format.md`` states it as a normative MUST: the maker
        holds ``p`` and the counter-leg claim key from the moment the envelope is published, and
        the BTC claim leaf carries no precondition that the asset was ever locked, so a taker that
        locks against a covenant that does not exist loses the whole counter leg. Until this gate,
        "exists" meant one ElectrumX server's ``listunspent`` said so — and a server that invented
        the covenant made this coordinator lock.

        WHAT IT DOES NOW. The Radiant leg fetches EVIDENCE (``maker_funding_evidence``: the raw
        funding tx, its merkle and coinbase branches, and the header ranges
        :func:`~pyrxd.gravity.funding_spv.funding_header_ranges` plans), and this method PROVES it
        with :func:`~pyrxd.gravity.funding_spv.verify_maker_funding`: the covenant scriptPubKey —
        re-derived here from the taker's OWN terms via the leg — and the value are read from the
        funding transaction's raw bytes, inclusion is proved against a header linked to a shipped
        checkpoint, and the depth must reach ``k = max(6, burial, ceil(2 × value ÷ C))`` (the
        maintainer's rule; ``C`` is the photon cost of one forged confirmation, from Radiant's own
        subsidy schedule and the proved headers). On regtest the same proof runs against the
        network's genesis, with no value term. A leg that cannot supply evidence refuses — there is
        no path that proceeds on the server's word.

        What remains the server's word: that the covenant output is still UNSPENT (SPV cannot show
        a non-spend). The elapsed-depth upper bound is statistical — a confidence scaled by the value,
        at ``funding_bound.surge_factor`` times the nominal block rate — as
        :mod:`pyrxd.gravity.funding_spv` states.

        THE REFERENCE TIME IS TAKEN AFTER THE READS. The gate's time term counts the blocks mined
        between the reference header's median time past and "now"; a "now" read before a slow fetch
        is earlier than the moment the bound is used, and would count fewer. So the ``now`` the gate
        judges is ``now_unix_s`` ADVANCED by the monotonic time elapsed from ``now_sampled_monotonic``
        (when ``now_unix_s`` was taken; default: this call's entry) to the end of the reads, rounded
        up to a whole second. The wall clock is still only the caller's; a slow read can only make
        the bound larger.
        """
        if now_sampled_monotonic is None:
            now_sampled_monotonic = _monotonic()
        if now_unix_s is not None and (not isinstance(now_unix_s, int) or isinstance(now_unix_s, bool)):
            raise ValidationError("now_unix_s must be an int or None")
        fetch = getattr(self.radiant_leg, "maker_funding_evidence", None)
        if not callable(fetch):
            raise ValidationError(
                "radiant_leg does not implement maker_funding_evidence, so the maker's asset lock cannot "
                "be PROVED on chain; fail-closed (refuse to fund the counter leg). Wire a "
                "RadiantCovenantLeg, or a leg exposing that read."
            )
        chain = radiant_chain_for_leg(self.radiant_leg, counter_leg=self.counter_leg)
        expected_spk = bytes(await self.radiant_leg.expected_covenant_scriptpubkey(terms))
        value_at_stake = self._funding_value_at_stake_photons(terms)
        burial = self._funding_burial_blocks(chain, value_at_stake)
        # The depth known BEFORE the headers are read (the value term needs them): lets the leg
        # refuse a funding its own server calls shallower without fetching thousands of headers.
        known_floor = max(burial, MIN_FUNDING_CONFIRMATIONS) if chain.value_bearing else max(burial, 1)
        evidence = await fetch(
            terms,
            header_ranges=functools.partial(funding_header_ranges, chain),
            min_confirmations=known_floor,
        )
        # Re-sampled AFTER the reads (see the docstring): never earlier than the caller's clock.
        now_after_reads = (
            None if now_unix_s is None else now_unix_s + math.ceil(max(0.0, _monotonic() - now_sampled_monotonic))
        )
        result = verify_maker_funding(
            evidence,
            chain=chain,
            expected_spk=expected_spk,
            expected_value=int(terms.radiant_amount),
            value_at_stake_photons=value_at_stake,
            burial_blocks=burial,
            now_unix_s=now_after_reads,
            bound_policy=self.config.funding_bound,
        )
        self.last_maker_funding = result
        # The user override of the single-operator threshold goes into the DURABLE record, so the
        # swap's own record says it was run under it. Carried by every later copy of the record
        # (they use dataclasses.replace) and written by the intent persist before any lock. Never
        # CLEARED: a later run without the override (a resume) must not erase that an earlier gate
        # run - possibly the one the lock went through - accepted one operator by user override.
        override = result.single_operator_override
        if override is not None and override != self.record.single_operator_override:
            self.record = dataclasses.replace(self.record, single_operator_override=override)
        return result.outpoint, result.value_photons, result.elapsed_blocks_upper

    def _assert_eth_timelock_ordering(
        self, terms: NegotiatedTerms, *, now_unix_s: int | None, elapsed_blocks: int = 0
    ) -> None:
        """ETH cross-clock ordering gate (audit HIGH-1) — wires the previously-orphaned
        :mod:`pyrxd.gravity.eth_rxd_timelock` bridge into the live pre-fund path.

        The HTLC ordering invariant requires the ASSET (RXD) refund to open strictly AFTER the
        counter-leg (ETH) refund, plus the cross-clock margin. The maker holds ``p`` and LOCKS the
        Radiant leg, so that leg carries the LONGER timeout and the maker claims the SHORTER one
        (Herlihy 1801.09515 §1). For ETH the real deadline is the ABSOLUTE
        ``terms.eth_timeout_unix_s`` (a contract immutable), NOT the relative ``t_btc``
        placeholder — so the BTC-shaped ``assert_timelock_margin(t_btc, t_rxd)`` is the WRONG gate
        here. We project where the RXD CSV refund opens and refuse unless it lands AFTER
        ``eth_timeout + margin``.

        THIS DOCSTRING DESCRIBED THE OPPOSITE RELATION until #482 — it said the gate refuses
        "unless it lands before ``eth_timeout - margin``", the inverted rule stated with full
        confidence one scroll above the code. Prose that asserts an invariant becomes evidence to
        the next reader; when it is wrong it is manufactured corroboration, so it is corrected
        here rather than left to be cited.

        TWO SEPARATE CHECKS RUN, because ordering does not imply liveness.
        :func:`assert_eth_deadline_is_claimable` asks whether the party who must act still can;
        :func:`assert_covenant_confirms_before_eth_deadline` asks whether either party can be
        robbed if both do. Under the old relation the first fell out of the second's arithmetic
        and had no check of its own; under this one it does not follow, so it is asserted
        directly. Fail-closed on any missing input.
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
        # LIVENESS FIRST, and ONLY HERE. A dead or near-dead deadline is refused on its own
        # terms rather than as a by-product of the ordering arithmetic (#482). Deliberately NOT
        # run in the post-confirm recheck: this floor asks "should the taker fund at all", and
        # once it HAS funded the deadline is legitimately closer every second — applying it there
        # would refuse honest swaps for the crime of being underway.
        assert_eth_deadline_is_claimable(
            now_unix_s=now_unix_s,
            eth_timeout_unix_s=terms.eth_timeout_unix_s,
            margin=policy.cross_clock_margin,
        )
        assert_covenant_confirms_before_eth_deadline(
            now_unix_s=now_unix_s,
            eth_timeout_unix_s=terms.eth_timeout_unix_s,
            margin=policy.cross_clock_margin,
            t_rxd=terms.t_rxd,
            # THE FAST TAIL, matching the interval the sizer divides by. This was passed the
            # NOMINAL while `eth_absolute_to_rxd_relative_blocks` divides by the fast tail, an
            # 8.3x mismatch: under the pre-#482 upper-bound gate that REFUSED exactly the t_rxd
            # the sizer produces, and a runner-side cap was added to satisfy it, shortening t_rxd
            # ~8x and widening the ASSET_VULNERABLE window from ~2h to ~21h at the fast tail —
            # the window in which the maker holds the refunded asset AND can still claim the
            # counter leg with p. THE MISMATCH NOW FAILS THE OTHER WAY: the gate is a LOWER bound,
            # so a slower interval over-projects where the refund opens and ACCEPTS a t_rxd ~8x
            # too short (measured: 312 blk accepted at 300 s where the 36 s tail requires 2,597).
            # Same defect, opposite arrangement. This comment used to justify the fast tail by
            # citing the gate docstring's "the interval is a no-op input" — a claim that docstring
            # no longer makes, because it is only ever true of a t_rxd the sizer itself produced.
            rxd_block_interval_s=_dividing_interval_s(policy),
            max_covenant_confirm_wait_s=policy.max_covenant_confirm_wait_s,
            elapsed_blocks=elapsed_blocks,
        )

    # -- taker funds the counter leg first (the role invariant's step 2) ----------------
    @_serialized_step
    async def taker_funds_btc(self, terms: NegotiatedTerms, *, now_unix_s: int | None = None) -> SwapRecord:
        """Run the pre-lock gate, fund the counter-leg HTLC, record the locator, advance.

        Refuses (raises) if the pre-lock gate fails — the taker NEVER funds against a
        failed gate. The gate's on-chain asset check (:meth:`taker_verify_asset_funding`) is
        RE-RUN here, immediately before the broadcast, which is what closes the verify->lock
        TOCTOU: a maker can double-spend its covenant funding away in the window between the
        taker's check and the taker's lock. H is ATOMICALLY reserved in the seen-store PRE-broadcast (so a
        concurrent or repeat funder of the same H is refused before any value moves;
        TOCTOU-1), and the durable record carries the full counter-leg locator.

        ``now_unix_s`` is the caller's wall-clock, passed to :meth:`pre_btc_lock_check` and to the
        lock-time re-run of :meth:`taker_verify_asset_funding` — REQUIRED for an ETH swap (the
        cross-clock timelock-ordering gate, audit HIGH-1) and for any swap whose Radiant leg is on
        mainnet (the taker gate's elapsed-depth bound); see :meth:`pre_btc_lock_check`.

        Atomicity (kieran-python HIGH): ``counter_leg.fund`` broadcasts on-chain, so a
        cancellation between the broadcast and the in-memory state advance would
        leave value locked but the record at NEGOTIATED → a retry double-funds. We
        persist an INTENT record (terms + derived funding SPK, enough to recover the
        address) BEFORE the awaited fund, and ``asyncio.shield()`` the post-broadcast
        persist of the funded record. ``fund`` itself must be idempotent (treat
        "already in mempool" as success). Persistence is a no-op when no ``persist`` hook is
        injected — which is refused for a value-bearing BTC fund (below).

        A BTC fund records its signed funding transaction (``pending_btc_funding_tx``) BEFORE the
        broadcast. ``fund`` broadcasts and then reads the amount back, and that read can fail after
        the broadcast succeeded; without the bytes the record stayed NEGOTIATED with no locator and
        H reserved, so a retry was refused as "H reused" and nothing in-band could reach the BTC.
        A call on a record carrying them is a RESUME: if the recorded output is already confirmed it
        is recorded as the lock with no gate (the funds already moved — refusing would only hide
        them); otherwise the full gate runs as for a fresh fund and, if it passes, the SAME bytes are
        re-sent (they spend one specific UTXO, so they cannot fund twice).
        """
        # When the caller's clock was read (as near as this method can know): the lock-time re-run
        # below judges `now_unix_s` advanced by everything since, reads included.
        now_sampled_monotonic = _monotonic()
        if self.record.state is not SwapState.NEGOTIATED:
            raise ValidationError(f"taker_funds_btc only valid from NEGOTIATED, not {self.record.state.value}")
        btc_resume_tx = self._btc_resume_tx(terms)
        if btc_resume_tx is not None:
            landed = await self.counter_leg.read_confirmed_funding(terms, btc_resume_tx)
            if landed is not None:
                # The interrupted fund already landed: record the truth. No gate and no reservation
                # check run — recording an output already on chain sends nothing, and refusing would
                # only leave the funds untracked (the stranding this path exists to end).
                rec = await self._record_counter_lock(terms, landed)
                # Best effort: a seen-store that lost H (restored backup, rotated store) would accept a
                # later swap under it. The lock is already recorded; a failing store must not undo that.
                try:
                    if not self.seen_store.has_seen(terms.hashlock):
                        self.seen_store.reserve(terms.hashlock)
                except Exception as exc:  # the lock is recorded; say so rather than undo it
                    logger.warning(
                        "recorded the BTC lock but could not re-reserve its hashlock in the seen-store (%s); "
                        "a later swap under the same H would not be refused until it is reserved",
                        exc,
                    )
                return rec
            # Not proven on chain: what follows may RE-SEND the bytes, so the reservation this record
            # claims must still hold.
            self._check_resume_reservation(terms)
        gate = await self.pre_btc_lock_check(terms, now_unix_s=now_unix_s, now_sampled_monotonic=now_sampled_monotonic)
        if not gate.ok:
            refused = DefinitiveFundRefusal if gate.definitive else ValidationError
            raise refused(f"pre-BTC-lock gate refused funding: {gate.reason}")

        # Persist intent BEFORE broadcasting: the SPK is derivable pre-fund, so a
        # crash after this write but before/within the broadcast leaves a record
        # that knows WHERE the HTLC address is (recoverable), not a silent gap.
        await self._persist_record(self.record)

        # RE-VERIFY the maker's asset lock at LOCK TIME (HZ-1). The gate above ran before this
        # method's own persist, and a maker can double-spend its covenant funding away inside that
        # window — a one-shot check would never see it, and the taker would lock BTC against a
        # covenant that no longer exists while the maker still claims with p. Placed here, not
        # after the H reserve, so the reserve keeps its "last step before the only broadcast"
        # property (TOCTOU-1) and a refusal does not burn H for nothing. Fail-closed: this raises
        # and nothing is broadcast.
        _rerun_outpoint, _rerun_value, rerun_upper = await self.taker_verify_asset_funding(
            terms, now_unix_s=now_unix_s, now_sampled_monotonic=now_sampled_monotonic
        )
        # ...AND JUDGE THE TIMELOCKS ON THE RE-RUN'S OWN BOUND. The re-run reads the chain later than
        # the gate did, so its elapsed-depth upper bound can be larger (more blocks, or a slow read
        # pushing `now` further from the reference time); steps 6 and 7 held on the gate's bound,
        # which says nothing about this one. Discarding it — as this did when the re-run landed —
        # funded on a window the gate itself would now refuse. The ETH ordering is judged at a
        # `now` taken after the re-run's reads, never earlier than the one the bound used.
        rerun_now = (
            None if now_unix_s is None else now_unix_s + math.ceil(max(0.0, _monotonic() - now_sampled_monotonic))
        )
        again = self._judge_remaining_window(terms, cov_confs=rerun_upper, now_unix_s=rerun_now)
        if again is not None:
            raise (DefinitiveFundRefusal if again.definitive else ValidationError)(
                f"lock-time re-run refused funding (elapsed-depth upper bound {rerun_upper}): {again.reason}"
            )

        # Reserve H ATOMICALLY and PRE-broadcast (TOCTOU-1 fix). The check-and-mark
        # is one indivisible step strictly before the only on-chain effect below, so
        # two concurrent funders of the same H race here and exactly one wins — the
        # other is refused with nothing broadcast. A raising store fails CLOSED
        # (refuse to fund), never open. H is consumed at this COMMIT point, not after
        # fund() succeeds: an on-chain-locked HTLC has used its H, and a transient
        # post-fund failure must not re-open the free-option / preimage-replay window.
        # RESUME, or reserve. A record carrying a pending deploy is proof that THIS swap already
        # won the reservation race and got as far as putting a contract on chain — so re-reserving
        # would refuse us our own H, permanently, which is exactly the state a mid-fund crash used
        # to leave behind. Skipping the reserve here does not weaken the guarantee it provides:
        # the resume completes the EXISTING contract rather than creating a second one, the leg
        # verifies that contract carries this swap's immutables before sending anything to it, and
        # it re-reads the balance so a lost receipt cannot double-fund.
        # An ETH counter-leg address is not derivable from terms, so the ONLY thing that can make
        # a mid-fund crash recoverable is a record written to durable storage. Without a persist
        # hook `_persist_record` is a silent no-op and every guarantee below is a lie — which is
        # exactly what shipped: not one runner injected one, so the durable handle never reached
        # disk and the resume it enables could never trigger. Refuse rather than document it.
        if terms.counter_chain == "eth" and self._persist is None:
            raise ValidationError(
                "an ETH counter-leg requires a durable persist hook: its contract address depends "
                "on the deployer's nonce and exists nowhere until the deploy receipt returns, so "
                "without one a crash between deploy and funding leaves real value on chain that "
                "nothing references. Pass persist= (see gravity.record_sink.JsonFileRecordSink)."
            )

        # Beside the ETH rule above, after the gate (whose refusals are more specific) and before
        # the reservation and the broadcast — the point every BTC fund, fresh or resumed, crosses.
        if (
            terms.counter_chain == "btc"
            and self._persist is None
            and (_leg_is_value_bearing(self.counter_leg) or _leg_is_value_bearing(self.radiant_leg))
        ):
            raise ValidationError(
                "a value-bearing BTC counter-leg fund requires a durable persist hook: the funding "
                "transaction is recorded BEFORE it is broadcast, and the amount is read back AFTER, so "
                "a readback that fails or a process that dies in between leaves real BTC locked that "
                "only the record can lead you back to. Pass persist= (see "
                "gravity.record_sink.JsonFileRecordSink)."
            )
        resume_from = None
        if btc_resume_tx is not None:
            pass  # the reservation was checked above (`_check_resume_reservation`); this H is ours
        elif self.record.pending_counter_contract:
            # CHECK the assumption instead of trusting it. "A pending deploy proves this swap won
            # the reservation" holds only while the seen-store and the record-store agree. They can
            # diverge — a restored backup, a rotated or deleted store, or a non-durable SeenStore
            # configured alongside durable records — and then a pending record survives with NO live
            # reservation. Skipping both the probe and the reserve on that record would let a second
            # swap under the same H fund a second HTLC, where one revealed p drains both.
            try:
                still_reserved = self.seen_store.has_seen(terms.hashlock)
            except Exception as exc:
                raise ValidationError(f"seen-store unavailable; fail-closed ({exc})") from exc
            if not still_reserved:
                raise ValidationError(
                    "record carries a pending counter-leg deploy but its hashlock is NOT reserved "
                    "in the seen-store: the two stores have diverged, so this record cannot prove "
                    "it won the reservation. Refusing to resume — resolve the divergence (or "
                    "refund the deployed contract after the timeout) rather than funding against "
                    "an H another swap may also be using."
                )
            if self.config.fund_lock is None:
                raise ValidationError(
                    "resuming an interrupted fund requires CoordinatorConfig.fund_lock: this path "
                    "skips the seen-store reserve (the record already holds that reservation), and "
                    "the reserve was also the only mutual exclusion in the funding path. Two "
                    "resumers without a lock each read the same pre-push balance and each send the "
                    "shortfall, leaving twice the negotiated amount in an HTLC whose claim sweeps "
                    "the whole balance to the counterparty. See gravity.record_sink.FileFundLock."
                )
            resume_from = PendingDeploy(
                address=self.record.pending_counter_contract,
                deploy_tx_hash=str(self.record.pending_counter_deploy_tx),
            )
        else:
            try:
                reserved = self.seen_store.reserve(terms.hashlock)
            except Exception as exc:
                raise ValidationError(f"seen-store unavailable; fail-closed ({exc})") from exc
            if not reserved:
                raise ValidationError("hashlock H already reserved; refusing to fund (free-option / preimage-replay)")

        # An ETH-side contract address is not derivable from terms — it depends on the deployer's
        # nonce — so unlike the BTC path there is nothing to persist BEFORE the broadcast. The next
        # best thing is to persist it the instant the deploy confirms and, for the token leg,
        # strictly before the tokens are pushed into it. Without this the intent record above knows
        # the swap exists but not WHERE its value went, and a crash mid-fund leaves real value in a
        # contract referenced only by an exception string.
        async def _remember_push_nonce(nonce: int) -> None:
            # Durable BEFORE the push is broadcast. The pin is only worth anything on a retry, and a
            # retry only happens after a crash — so a pin recorded after the send is the one thing
            # that crash destroys. Measured 2026-08-24: a re-send at a recorded nonce REPLACES
            # rather than adds, which is what makes funding idempotent without a distributed lock,
            # and unlike `flock` that property holds across hosts.
            self.record = dataclasses.replace(self.record, pending_push_nonce=int(nonce))
            await self._persist_record(self.record, shield=True)

        async def _remember_deploy(address: str, deploy_tx_hash: str) -> None:
            self.record = dataclasses.replace(
                self.record,
                pending_counter_contract=address,
                pending_counter_deploy_tx=deploy_tx_hash,
            )
            await self._persist_record(self.record, shield=True)

        if terms.counter_chain == "eth":
            lock = self.config.fund_lock
            # Held across deploy AND push: the window the lock exists to close is between reading
            # the balance and sending the shortfall, which spans both.
            with lock() if lock is not None else contextlib.nullcontext():
                locator = await self.counter_leg.fund(
                    terms,
                    on_deploy=_remember_deploy,
                    resume_from=resume_from,
                    push_nonce=self.record.pending_push_nonce,
                    on_push_nonce=_remember_push_nonce,
                )
        else:

            async def _remember_btc_funding(raw_tx_hex: str) -> None:
                # Durable BEFORE the broadcast: the only moment the bytes are certain to be ours
                # and not yet on chain. Shielded so a cancellation cannot drop the one write that
                # makes the broadcast after it recoverable.
                staged = dataclasses.replace(self.record, pending_btc_funding_tx=raw_tx_hex)
                # Adopted only once the write returns: if it raises, the leg never broadcasts, and the
                # in-memory record must not claim the transaction. (A hook that writes and THEN raises
                # leaves it on disk only; a resume from disk recovers that — nothing was sent.)
                await self._persist_record(staged, shield=True)
                self.record = staged

            try:
                locator = await self.counter_leg.fund(
                    terms, on_built=_remember_btc_funding, resume_tx_hex=btc_resume_tx
                )
            except Exception as exc:
                txid = self.record.pending_btc_funding_txid
                if txid is None:
                    raise  # failed before the bytes existed: nothing was sent
                try:
                    where = self.counter_leg.htlc_address(terms)
                except Exception:  # the message must never mask the failure it reports
                    where = None
                msg = (
                    f"BTC fund interrupted after funding transaction {txid} was recorded "
                    f"(and may have been broadcast){f' to the HTLC at {where}' if where else ''}: {exc}. "
                    "The record still carries the transaction and the reservation: call taker_funds_btc "
                    "(or resume_interrupted_fund) again to record it once it confirms, or re-send it if "
                    f"it never left. If it confirms and the swap does not proceed, it refunds after t_btc."
                )
                if isinstance(exc, NetworkError):
                    raise NetworkError(msg) from exc
                raise ValidationError(msg) from exc
        return await self._record_counter_lock(terms, locator)

    def _btc_resume_tx(self, terms: NegotiatedTerms) -> str | None:
        """The recorded BTC funding bytes when THIS call resumes an interrupted fund of THIS swap."""
        raw = self.record.pending_btc_funding_tx
        if raw is None or terms.counter_chain != "btc":
            return None
        if bytes(terms.hashlock) != bytes(self.record.terms.hashlock):
            raise ValidationError(
                "the record carries an interrupted BTC fund for a different hashlock: resuming would "
                "act on one swap's funding with another swap's terms"
            )
        return raw

    def _check_resume_reservation(self, terms: NegotiatedTerms) -> None:
        """A resume skips the seen-store reserve on the evidence that THIS record won it. Check that
        evidence instead of trusting it: a restored backup or a rotated store can leave a pending
        record whose H is no longer reserved, and then another swap could be using it."""
        try:
            still_reserved = self.seen_store.has_seen(terms.hashlock)
        except Exception as exc:
            raise ValidationError(f"seen-store unavailable; fail-closed ({exc})") from exc
        if not still_reserved:
            raise ValidationError(
                "record carries an interrupted BTC fund but its hashlock is NOT reserved in the "
                "seen-store: the two stores have diverged, so this record cannot prove it won the "
                "reservation, and the recorded transaction is not proven on chain. Refusing to re-send it. "
                "If it does confirm, resuming again records it (that path needs no reservation); if it "
                "never left, resolve the divergence before funding."
            )

    async def _record_counter_lock(self, terms: NegotiatedTerms, locator: Any) -> SwapRecord:
        """Bind a funded counter-leg locator to the negotiated price, attach it, advance, persist —
        the one place a fund (fresh, resumed, or found already confirmed) becomes BTC_LOCKED."""
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
    def _assert_eth_lock_timing_still_safe(self, *, now_unix_s: int | None, elapsed_blocks: int) -> None:
        """Post-confirm cross-clock recheck (audit re-verify HIGH) — the bridge's prescribed
        SECOND run (:func:`assert_covenant_confirms_before_eth_deadline` docstring).

        The pre-fund ordering gate (:meth:`_assert_eth_timelock_ordering`) projects where the RXD
        CSV refund opens from the TAKER's fund time. We re-run it here at the ACTUAL lock time with
        ``max_covenant_confirm_wait_s = 0`` (the covenant is confirmed now), and refuse to advance
        to BOTH_LOCKED if the ordering no longer holds. Fail-closed.

        WHO THIS PROTECTS, AND WHO RUNS IT — the previous sentence said a failure means "the
        taker refunds the counter leg rather than proceed", and that names a party this code
        cannot speak for. In the two-host flow the only caller of
        :meth:`post_asset_lock_revalidate` is the MAKER's process
        (``scripts/eth_swap_two_host.py`` ``maker_phase_lock_claim``, which enters the flow at
        BTC_LOCKED because "the maker never ran taker_funds_btc — that happened in the TAKER's
        process"); the taker phase never calls it. So refusing here stops the MAKER advancing
        and revealing ``p``, and the maker's recovery is the CSV refund of its own covenant. It
        is maker SELF-RESTRAINT, not a control the taker holds over a hostile maker — a maker
        who wants to skip it simply does not call it.

        The taker's own post-fund defences are elsewhere and are the party-correct ones:
        :func:`assess_claim_finality` and :meth:`taker_refund_window_open`, both of which read
        real Radiant heights rather than projecting from an interval estimate.

        THIS DOCSTRING DESCRIBED THE OPPOSITE HAZARD until now, and #482 corrected its sibling
        while leaving this one. It said the danger was a maker who STALLS the broadcast, "pushing
        the ACTUAL rxd-refund-open past that projection and collapsing the cross-clock margin".
        Under the corrected relation the Radiant leg must OUTLAST the counter leg, so a late lock
        opens the refund LATER and is strictly SAFER — it costs the maker lock time and takes
        nothing from the taker. What robs the taker is a covenant that mined EARLY.

        THE COVENANT'S REAL DEPTH IS WHAT MAKES IT DISCRIMINATE (#564). Anchored on the caller's
        revalidation clock with NO elapsed depth — which is how it shipped — a later anchor only
        makes the inverted invariant easier to satisfy, and the run was not merely weak but
        VACUOUS: brute-forced against the real gate over 12,010 points (covenant depth 0..1200 x
        ten realised Radiant intervals from 1 s to 2,325 s) it refused on ZERO of them.
        ``elapsed_blocks`` is REQUIRED rather than defaulted precisely so no caller can reproduce
        that by omission; :meth:`_covenant_elapsed_blocks` reads it off the chain, the same
        quantity step 7 of :meth:`pre_btc_lock_check` takes from the taker's funding verification.

        WHAT IT REFUSES, measured against the real gate at the sizer's own output (``t_rxd`` 2,597
        blocks at the 36 s measured p10, ``eth_timeout`` 24 h out, margin 7,068 s): only a realised
        interval below 12.00 s/blk at depth 1, 32.00 at depth 6, 34.00 at depth 12, 35.52 at depth
        50, 35.92 at depth 300 and 35.99 at depth 2,596 — converging on the fast tail from below
        and never reaching it. At the p10 itself (36 s), the measured median (221 s), the mean
        (296 s) and the p90 (671 s) it refuses at NO depth in 1..2,596, so it does not refuse
        honest work: it refuses only when Radiant ran FASTER than the tail the terms were sized
        with, which is the direction that eats the taker's window. At 18 s/blk it refuses from
        depth 10 up, where the shipped form passes at every depth.

        THIS HAS NO BTC TWIN, and the asymmetry is deliberate rather than an oversight — see
        :meth:`_assert_btc_counter_funding_verified` for the measurement, and
        ``tests/test_post_confirm_ordering_recheck.py`` for the executable form of the reason.
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
            # THE FAST TAIL, matching the interval the sizer divides by. This was passed the
            # NOMINAL while `eth_absolute_to_rxd_relative_blocks` divides by the fast tail, an
            # 8.3x mismatch: under the pre-#482 upper-bound gate that REFUSED exactly the t_rxd
            # the sizer produces, and a runner-side cap was added to satisfy it, shortening t_rxd
            # ~8x and widening the ASSET_VULNERABLE window from ~2h to ~21h at the fast tail —
            # the window in which the maker holds the refunded asset AND can still claim the
            # counter leg with p. THE MISMATCH NOW FAILS THE OTHER WAY: the gate is a LOWER bound,
            # so a slower interval over-projects where the refund opens and ACCEPTS a t_rxd ~8x
            # too short (measured: 312 blk accepted at 300 s where the 36 s tail requires 2,597).
            # Same defect, opposite arrangement. This comment used to justify the fast tail by
            # citing the gate docstring's "the interval is a no-op input" — a claim that docstring
            # no longer makes, because it is only ever true of a t_rxd the sizer itself produced.
            rxd_block_interval_s=_dividing_interval_s(policy),
            max_covenant_confirm_wait_s=0,  # the covenant is CONFIRMED now — no future wait budget
            # THE COVENANT'S REAL DEPTH. `t_rxd` is a relative CSV counted from MINING, so the
            # refund opens `t_rxd - elapsed` blocks from this anchor; passing the negotiated value
            # is what made this run vacuous (see the docstring's grid).
            elapsed_blocks=elapsed_blocks,
        )

    async def _covenant_elapsed_blocks(self) -> int:
        """How many blocks of the covenant's RELATIVE CSV have ALREADY elapsed, read from chain.

        ``t_rxd`` counts from the covenant's MINING, so any gate judging the ordering AFTER the
        covenant is on chain must subtract this. :meth:`pre_btc_lock_check` step 7 takes it from
        :meth:`taker_verify_asset_funding`'s third return value; the post-confirm recheck cannot,
        because in the two-host flow the only caller of :meth:`post_asset_lock_revalidate` is the
        MAKER's process and that process never ran the taker's pre-fund gate.

        ``min_confirmations=0`` because this is a MEASUREMENT, not a depth gate. The burial
        requirement belongs to the taker and is enforced before it funds
        (:meth:`_asset_funding_depth`); re-imposing it on the transition into BOTH_LOCKED would
        add an unrelated refusal to a fund-safety path, and refusing honest work is a defect in
        its own right. The read itself still fails closed — an unfunded or mis-valued covenant, or
        a depth the node cannot report, raises rather than reading as zero elapsed, which is the
        PERMISSIVE direction for every gate that consumes this number.

        Deliberately NOT routed through :meth:`taker_verify_asset_funding`: that method's contract
        includes the taker's depth requirement, and the two differ in exactly the parameter that
        would make this refuse. The leg call and its fail-closed guard are the same.
        """
        verify = getattr(self.radiant_leg, "verify_maker_asset_funded", None)
        if not callable(verify):
            raise ValidationError(
                "radiant_leg does not implement verify_maker_asset_funded, so the covenant's "
                "elapsed CSV depth cannot be read and the post-confirm ordering recheck would be "
                "judging the NEGOTIATED window rather than the one that remains; fail-closed "
                "(refuse BOTH_LOCKED). Wire a RadiantCovenantLeg, or a leg exposing that read."
            )
        _outpoint, _value, confs = await verify(self.record.terms, min_confirmations=0)
        if not isinstance(confs, int) or isinstance(confs, bool) or confs < 0:
            raise ValidationError(
                f"the Radiant leg reported {confs!r} as the covenant's confirmation depth, which is "
                "not a non-negative int; fail-closed"
            )
        return int(confs)

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
        REQUIRED for an ETH swap (the post-confirm cross-clock recheck; audit re-verify HIGH),
        ignored for BTC. On an ETH timing failure this refuses to advance to BOTH_LOCKED (raises).

        THAT SENTENCE USED TO NAME BOTH THE WRONG HAZARD AND THE WRONG PARTY — "against a stalled
        maker lock ... so the taker refunds the counter leg". #482 inverted the relation, so a
        LATE covenant lock is now strictly safer, and #628 corrected the same two claims on
        :meth:`_assert_eth_lock_timing_still_safe` while this copy kept them. The caller here is
        the MAKER's process (the taker phase never calls this method), so a refusal stops the
        MAKER advancing and its recovery is the CSV refund of its own covenant.

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
        # Post-confirm counter-funding gate (audit re-verify HIGH + red-team HIGH): the SPK is
        # right, but the counter leg must ALSO be verified before BOTH_LOCKED — which is the
        # precondition for maker_claims_btc (the p-reveal). On BOTH chains the maker's
        # counter-funding verification MUST have run and must STILL hold, re-checked here pinned to
        # finality so a reorg cannot have replaced the taker's funding after it was verified (the
        # verify->lock TOCTOU). An ETH leg additionally re-checks the cross-clock timing (a maker
        # who DELAYED the covenant broadcast may have collapsed the margin the pre-fund gate
        # projected). Any failure refuses BOTH_LOCKED (persist for recovery + raise) so the maker
        # never reveals p against an unverified / reorg-replaced / mis-funded / timing-collapsed
        # counter leg — it refunds the covenant via CSV instead of entering the one-sided-loss
        # window.
        if self.record.terms.counter_chain == "btc":
            await self._assert_btc_counter_funding_verified()
        else:
            await self._assert_eth_counter_funding_verified(now_unix_s=now_unix_s)
        # The credential gate is a precondition for the reveal too, and for the same
        # structural reason: its only enforcement lived inside the TAKER's own
        # pre-fund method, which the party it protects never calls.
        await self._assert_credential_binding_verified()
        self._advance(SwapEvent.MAKER_LOCKS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    async def _credential_binding_failure(self, terms: NegotiatedTerms) -> str | None:
        """The credential rule, in one place. Returns a fail-closed reason, or ``None``.

        Confirms the payee holds a GENUINE consensus-soulbound credential (not a
        metadata flag) AND that the swap's pinned payout (``taker_dest_hash``) pays
        that credential's owner. Soulbound permanence => the owner is immutable, so
        binding the payout to it defeats both resale and rental without co-spending.
        A no-op when ``terms.credential_ref`` is empty, which is every swap this
        repo's CLI, scripts and examples can currently construct.

        Returned rather than raised because it has two callers that need different
        shapes: the taker's pre-fund gate reports it as a
        :class:`PreBtcLockGate`, and :meth:`_assert_credential_binding_verified`
        raises it. What must NOT differ between them is the rule — the
        counter-funding checks beside this one were each written out twice before
        being folded into one assertion, and a second copy is where drift starts.
        """
        if not terms.credential_ref:
            return None
        if self._credential_resolver is None:
            return "swap is credential-gated but no credential_resolver is wired; fail-closed"
        try:
            cred = await self._credential_resolver.resolve_credential(terms.credential_ref)
            if cred is None:
                return "credential ref did not resolve (unknown/spent); fail-closed"
            owner = assert_soulbound_credential(
                cred,
                min_confirmations=self.config.min_credential_confirmations,
                expected_credential_ref=terms.credential_ref,
            )
            expected = holder_hash(owner, variant=terms.asset_variant, genesis_ref=terms.genesis_ref)
            if expected != terms.taker_dest_hash:
                return (
                    "credential owner is not the swap payout recipient (taker_dest_hash); "
                    "rental would pass — fail-closed"
                )
        except (CredentialBindingError, ValidationError) as exc:
            return f"credential binding failed; fail-closed ({exc})"
        except Exception as exc:
            return f"credential resolver unavailable; fail-closed ({exc})"
        return None

    async def _assert_credential_binding_verified(self) -> None:
        """Credential precondition for BOTH_LOCKED — the third gate in this group,
        and the third instance of one defect class.

        Enforcement used to exist ONLY inside :meth:`pre_btc_lock_check`, called
        from exactly one place: ``taker_funds_btc``. That is the TAKER's own
        method, and the party the gate protects is the MAKER — ``credential_binding``
        names the asset-locker as the one who runs it, and "only credentialed
        counterparties may take my asset" is the maker's policy. So an
        uncredentialed taker declined to call the method holding the check, funded
        the freely-derivable HTLC address directly, and an honest MAKER-role
        coordinator — with a correct ``credential_resolver`` wired — walked
        BTC_LOCKED -> BOTH_LOCKED -> ``maker_claims_btc`` and revealed ``p`` with
        the resolver call count still at zero. Measured, not argued.

        This is exactly the shape of :meth:`_assert_btc_counter_funding_verified`
        and its ETH twin, and it is fixed the same way: the check belongs on the
        transition into BOTH_LOCKED, which is the precondition for the reveal, not
        on whichever method the honest party happens to pass through. Refusing here
        leaves the maker at BTC_LOCKED with its CSV asset refund still open, so the
        fail-closed direction costs a swap, never an asset.
        """
        reason = await self._credential_binding_failure(self.record.terms)
        if reason is None:
            return
        await self._persist_record(self.record, shield=True)
        raise ValidationError(
            f"credential-gated swap failed its binding at lock time — refusing BOTH_LOCKED "
            f"(the maker should refund the covenant via CSV): {reason}"
        )

    def _counter_verify_callable(self):
        """The counter leg's maker-side verification entry point, or fail-closed.

        A leg that cannot verify the counterparty's funding cannot be verified AT ALL, so the
        maker must refuse to lock rather than silently skip the gate."""
        verify = getattr(self.counter_leg, "verify_counterparty_funded", None)
        if verify is None:
            raise ValidationError("counter_leg does not implement verify_counterparty_funded; fail-closed")
        return verify

    def _btc_counter_funding_depth(self) -> int | None:
        """How deep the taker's BTC HTLC funding must be buried before the maker reveals p.

        BTC's "finalized" is a confirmation DEPTH, not a checkpoint (see
        :class:`pyrxd.gravity.finality.CounterClaimFinality.from_btc_depth`), so this is the BTC
        analogue of the ETH gate's ``block_identifier='finalized'`` pin — and it reuses the policy's
        EXISTING reorg-depth knob rather than inventing a second notion of BTC finality: a real-value
        (``is_measured``) swap must bury the funding ``btc_claim_reorg_depth`` deep, the same depth
        the claim-finality gate requires of the maker's own claim. ``None`` (an estimated/test
        policy) defers to the leg's configured ``min_confirmations`` — the same ``is_measured``
        discipline the ETH pin, the N-floor and the cross-clock margin already use.
        """
        policy = self.config.margin_policy
        if not policy.is_measured:
            return None
        return _reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s)

    async def _assert_btc_counter_funding_verified(self) -> None:
        """BTC-leg precondition for BOTH_LOCKED — the twin of
        :meth:`_assert_eth_counter_funding_verified`, closing the same hole on the BTC arm.

        We REQUIRE a ``BtcHtlcLocator`` on the record (so the maker knows WHICH outpoint the taker
        claims to have funded — advancing to the reveal-enabling BOTH_LOCKED without one is
        impossible) and RE-RUN the on-chain verification here, at lock time, pinned to
        :meth:`_btc_counter_funding_depth`. Re-running is what closes the verify->lock TOCTOU: a
        reorg (or a taker who funded only after the maker looked) can replace the funding output
        between the maker's verify and its own asset lock, and a one-shot verify would never see it.
        The record's locator is then REPLACED with the leg's own re-derivation, so nothing
        counterparty-supplied survives into ``maker_claims_btc``. Any failure persists for recovery
        and raises (fail-closed) — the maker refunds the covenant via CSV rather than revealing p.

        THERE IS DELIBERATELY NO POST-CONFIRM ORDERING RECHECK HERE, and the reason is a
        MEASUREMENT, not a preference. #564 proposed the ETH recheck's BTC twin — re-run
        :func:`assert_timelock_margin` with the covenant's real depth — on the argument that
        fixing the ETH instance and not the class is the failure this repo keeps recording. Both
        shapes of that twin were swept against the real gate and the real production derivation
        (``scripts/_dust_swap_shared.derive_counter_timelock``), and both refuse honest swaps:

        * ``t_btc`` is a RELATIVE CSV counted from the TAKER's BTC funding, not an absolute
          deadline like ``eth_timeout_unix_s``. Subtracting only the covenant's elapsed depth
          shrinks the maker's side of the comparison while leaving the taker's side anchored at a
          funding that has itself aged, so the check tightens by roughly a second per second of
          wall clock. At the runner's own defaults (``t_rxd`` 120, margin 36, 300/600 s, elapsed
          reserve 12 -> derived ``t_btc`` 18) it accepts elapsed <= 12 and refuses from 13, while
          an honest maker that funds at the reserve depth and then waits its
          ``btc_claim_reorg_depth`` of 6 BTC blocks arrives at depth 24-28. Refused, on every
          parameter set swept.
        * Subtracting BOTH legs' elapsed depths is the arithmetically correct form, and it still
          refuses 64 of 126 honest timelines over the realistic band (covenant depth at funding
          from the burial to the reserve, 0-30 min of mempool wait, 1/2/6 BTC blocks of maker
          wait, realised Radiant 221 s median and 296 s mean). The cause is upstream:
          ``derive_counter_timelock`` solves the gate to EQUALITY at ``elapsed = reserve``, so
          production terms carry ZERO headroom for any post-fund drift.

        The ETH corridor escapes this because its counter deadline is absolute AND its gate
        divides by the measured FAST TAIL (36 s) while the chain runs at ~221 s, which is a ~6x
        cushion; the BTC gate prices Radiant at the 300 s nominal with no cushion at all. So the
        honest sentence is that the BTC corridor's post-fund ordering coverage ends at step 7 of
        :meth:`pre_btc_lock_check`, and giving it a second run is blocked on
        ``derive_counter_timelock`` growing a drift reserve — a change to the TERMS, not to a
        gate. ``tests/test_post_confirm_ordering_recheck.py`` derives that zero-headroom property
        from the production code rather than restating it here, so this paragraph cannot go stale
        in silence."""
        locator = self.record.counterchain_locator
        if not isinstance(locator, BtcHtlcLocator):
            await self._persist_record(self.record, shield=True)
            raise ValidationError(
                "BTC counter-funding was never verified (no BtcHtlcLocator on record); "
                "maker_verify_counter_funding MUST run before locking the asset — refusing BOTH_LOCKED "
                "(the maker should refund the covenant via CSV)"
            )
        verify = self._counter_verify_callable()
        try:
            reverified = await verify(
                locator.funding_outpoint, self.record.terms, min_confirmations=self._btc_counter_funding_depth()
            )
            self.record = self.record.with_counter_lock(reverified)
        except (ValidationError, NetworkError):
            await self._persist_record(self.record, shield=True)
            raise
        except Exception as exc:
            await self._persist_record(self.record, shield=True)
            raise ValidationError(
                f"could not verify the BTC counter-funding at lock time; fail-closed ({exc})"
            ) from exc

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
        try:
            verify = self._counter_verify_callable()
        except ValidationError:
            await self._persist_record(self.record, shield=True)
            raise
        block_id = "finalized" if self.config.margin_policy.is_measured else None
        try:
            reverified = await verify(locator.contract_address, self.record.terms, block_identifier=block_id)
            self.record = self.record.with_counter_lock(reverified)
            # THE COVENANT'S REAL DEPTH, read here rather than assumed (#564). NetworkError joins
            # the caught set because this read touches the chain and a failure must persist for
            # recovery before it propagates — the same discipline as the BTC twin below.
            self._assert_eth_lock_timing_still_safe(
                now_unix_s=now_unix_s, elapsed_blocks=await self._covenant_elapsed_blocks()
            )
        except (ValidationError, NetworkError):
            await self._persist_record(self.record, shield=True)
            raise

    # -- maker verifies the taker's counter-leg HTLC before locking the asset (red-team CRITICAL) --
    @_serialized_step
    async def maker_verify_counter_funding(self, counter_funding_ref) -> SwapRecord:
        """MAKER-side fail-closed gate (red-team CRITICAL fix): the maker MUST verify the
        TAKER-funded counter-leg HTLC binds to the negotiated terms + the maker's own payout
        config AFTER the maker has locked the asset and BEFORE the maker reveals p. Returns on success
        (recording the verified locator on the record so :meth:`maker_claims_btc` can claim it);
        RAISES on any mismatch — the maker MUST NOT reveal p if this raises, and recovers the
        already-locked covenant through its CSV refund. Refusing here costs a swap, never an asset.

        WHY THIS EXISTS: the maker commits its own value against a leg the COUNTERPARTY built. The
        runbook is MAKER-locks-asset-FIRST (the taker will not fund until `pre_btc_lock_check`
        step 5 has read the covenant off the Radiant chain), then TAKER-funds-counter, then this.
        Nothing else in the handshake binds that leg: every other check the maker can run is a re-derivation of what the
        counter leg SHOULD look like, and re-deriving a target says nothing about what the taker
        actually funded. This is the only place the maker compares the two against the chain.

        Both chains need it, for the same reason and by different mechanics:

        * **ETH** — there is no pre-fund commitment at all (the contract does not exist until the
          taker deploys it), so a hostile taker can deploy ``claimant=self``, underfund, or set a
          bad timeout. ``EthHtlcContractLeg.verify_funded`` is the only binding, and it previously
          ran ONLY inside the taker's own ``fund()``.
        * **BTC** — the funding ADDRESS is a pure function of terms, but a P2TR scriptPubKey commits
          to the TAPTREE, **not to the output value**. So a hostile taker funds the correct,
          freely-derivable HTLC address with LESS than ``value_amount`` and every SPK check still
          passes. (This method used to REFUSE a BTC counter leg on the grounds that the pre-fund
          ``derive==promised`` gate already bound it. That was wrong twice over: that gate is a
          self-consistency check between two derivations of the maker's own terms, and it runs
          inside the TAKER's ``taker_funds_btc``, which a hostile taker simply does not call. The
          amount bind in the same method is likewise the honest taker's own. Documented as hazard
          HZ-3 in ``docs/htlc-handshake-wire-format.md``.)

        The maker passes ONLY the one untrusted datum the counterparty must supply — the ETH
        contract ADDRESS, or the BTC funding OUTPOINT (a ``BtcOutpoint``, a ``BtcHtlcLocator`` whose
        outpoint is read and whose other fields are ignored, or ``"<txid>:<vout>"``). The leg builds
        the EXPECTED leg from the maker's own config + terms and verifies the chain matches it.

        This gate is NOT optional: :meth:`post_asset_lock_revalidate` requires a verified locator on
        the record and RE-RUNS the verification at lock time (closing the verify->lock TOCTOU) before
        it will advance to BOTH_LOCKED, on both chains."""
        terms = self.record.terms
        verify = self._counter_verify_callable()
        # Raises on any mismatch (BTC: wrong scriptPubKey / amount / depth / spent; ETH: wrong
        # claimant/refundee/H/timeout/amount/logic). The maker MUST NOT lock the asset if it raises.
        if terms.counter_chain == "btc":
            locator = await verify(counter_funding_ref, terms, min_confirmations=self._btc_counter_funding_depth())
        else:
            locator = await verify(counter_funding_ref, terms)
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
        # `unsafe_raw_bytes()` returns a COPY, and `bytes` is immutable, so this local cannot be
        # scrubbed and `preimage.zeroize()` below does not reach it (#480). What the zeroize
        # actually buys is real but narrower than "the secret is gone": it clears the LONG-LIVED
        # holder, the one that outlives this frame and could be persisted, logged or reused. This
        # copy dies with the frame, and downstream callers copy it again regardless — web3 does,
        # building the calldata. Describing the zeroize as erasing the secret from memory would be
        # a promise CPython cannot keep; `SecretBytes.zeroize` is honest about this and the call
        # sites should be too.
        raw = preimage.unsafe_raw_bytes()
        if hashlib.sha256(raw).digest() != self.record.terms.hashlock:
            raise ValidationError("preimage does not hash to the negotiated H; refusing to broadcast")
        # Zeroize once a claim has been ATTEMPTED, not on every exit. Past the submit boundary p
        # may be public — on the public path the preflight eth_call carries the calldata, on the
        # private path the submit does — so holding a copy buys nothing and discarding it is right.
        #
        # Before that boundary nothing has left this process, and zeroizing the holder of a
        # still-secret p strands a swap that a retry would have completed: a transient RPC blip
        # becoming a dead swap (#479). The legs mark that boundary by raising PreRevealAbort, which
        # is a promise about WHERE the failure happened, not why.
        #
        # THE EXAMPLE THIS COMMENT USED TO GIVE IS NOW BACKWARDS, so it is corrected rather than
        # trimmed. It read: "A gate refusal that is NOT a PreRevealAbort — an address really is
        # frozen — still zeroizes." A frozen address is now exactly a PreRevealAbort (see
        # `Erc20HtlcLeg.claim`), so that lane does NOT zeroize, and the sentence described the
        # opposite of the code directly beneath it (#485).
        #
        # What survives is the rule: anything that is not a PreRevealAbort may have carried `p` to
        # a provider, so it zeroizes. The pre-reveal gates are not in that set — including the
        # freeze refusal, where keeping `p` costs nothing because a genuinely frozen counterparty
        # means the swap cannot complete anyway and both sides refund.
        # The leg RECORDS whether anything carrying `p` left the process; this no longer infers it
        # from the exception class. `asyncio.CancelledError` is a BaseException, so a cancellation
        # during the pre-broadcast reads used to land in the zeroize branch and destroy a secret
        # that was still safe — #479 arriving through the cancel channel (#480). A boundary the leg
        # sets cannot be got wrong by a future check landing on the wrong side of it.
        with reveal_boundary() as boundary:
            try:
                await self.counter_leg.claim(self.record.counterchain_locator, raw)
            except PreRevealAbort:
                # Kept as its own branch even though the boundary would say the same: this is the
                # leg's explicit promise that nothing was sent, and it must hold for a leg that
                # does not report a boundary at all. "Keep it" means the holder above stays
                # readable for a retry — see the note on `raw` for what zeroize does and does not
                # reach.
                raise
            except BaseException:
                # UNWATCHED (a leg that does not report) reads as may_be_public, so a
                # non-participating leg keeps today's behaviour. Only an explicit "I got nowhere"
                # keeps the preimage.
                if boundary.may_be_public:
                    preimage.zeroize()
                raise
            else:
                preimage.zeroize()
        self._advance(SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)
        await self._persist_record(self.record, shield=True)
        return self.record

    async def resume_interrupted_fund(self, terms: NegotiatedTerms, *, sink: Any, now_unix_s: int) -> SwapRecord:
        """Reload a crashed fund from durable storage and complete it.

        THE READ SIDE. Without this the durable record was written and never read: every guard the
        resume path carries — the nonce pin, the fund lock, the seen-store divergence check, the
        immutable re-bind — was unreachable in production because `pending_counter_contract` could
        only ever be set by a test that hand-built a record. A mechanism with no reader is half a
        mechanism, and this is the missing half.

        Fails closed on every disagreement, because the alternative to refusing here is funding a
        second HTLC while the first holds real value:

        * No record on disk → refuse. A resume with nothing to resume from is a fresh fund, and a
          fresh fund is `taker_funds_btc`'s job; silently falling through to it would deploy again.
        * A record with no pending handle → refuse. Either the fund completed (the locator is on
          the record) or it never started; neither is a resume.
        * Terms for a different swap (another hashlock) → refuse. For the same swap the RECORD's
          terms are used, not the supplied ones: `taker_funds_btc` acts on the `terms` it is given and
          a runner rebuilds them from its arguments each run, so a drifted argument must neither fund
          one thing while the record describes another nor refuse a legitimate resume.
        """
        rec = sink.load_record()
        if rec is None:
            raise ValidationError(
                "no swap record found: there is nothing to resume. If the fund never started, run "
                "the forward path instead — resuming into a fresh fund would deploy a second HTLC."
            )
        if not rec.pending_counter_contract and not rec.pending_btc_funding_tx:
            state = rec.state.value if isinstance(rec.state, SwapState) else rec.state
            raise ValidationError(
                f"the swap record carries no pending counter-leg deploy (state {state}), so there "
                "is no interrupted fund to complete. If the counter leg is already funded its "
                "locator is on the record and the swap should continue from there."
            )
        if rec.terms.hashlock != terms.hashlock:
            raise ValidationError(
                "the supplied terms do not match the persisted record (different hashlock): "
                "resuming would fund the contract from one swap using the parameters of another."
            )
        # The RECORD's terms are authoritative from here on: they describe the contract that was
        # deployed or the transaction that was signed. A runner rebuilds its terms from its arguments
        # on every run (eth_swap_run re-derives t_btc from a re-measured block interval), so demanding
        # the supplied terms match field-for-field refused legitimate resumes; acting on the supplied
        # ones instead would complete one fund under parameters the record does not describe.
        terms = rec.terms
        self.record = rec
        try:
            return await self.taker_funds_btc(terms, now_unix_s=now_unix_s)
        except ValidationError as exc:
            if self.record.state is SwapState.NEGOTIATED and self.record.pending_btc_funding_tx:
                txid = self.record.pending_btc_funding_txid
                if isinstance(exc, DefinitiveFundRefusal):
                    raise DefinitiveFundRefusal(
                        f"BTC resume refused definitively: {exc}. The recorded funding transaction {txid} is "
                        "NOT re-sent. If it was already broadcast it may still confirm — a resume then records "
                        "it as the lock with no gate. If it never left, the taker's UTXO is unspent, and the "
                        "gate will keep refusing the re-send unless what it refused on changes."
                    ) from exc
                raise ValidationError(
                    f"BTC resume did not complete: {exc}. The record still carries funding transaction {txid} "
                    "(negotiated). Only those same bytes are ever sent, so it cannot fund twice; it may "
                    "already be on chain. Resume again once the cause clears: if it has confirmed it is "
                    "recorded as the lock with no gate, and it is re-sent only when the gate passes."
                ) from exc
            if self.record.state is not SwapState.NEGOTIATED or not self.record.pending_counter_contract:
                raise
            if isinstance(exc, DefinitiveFundRefusal):
                raise DefinitiveFundRefusal(await self._track_refused_resume(terms, str(exc), sink=sink)) from exc
            # A chain read or a store that failed, a proof that did not go through: a retry may pass.
            # Nothing was sent and nothing is changed, so the record stays resumable.
            address = self.record.pending_counter_contract
            raise ValidationError(
                f"resume refused, and it can be retried: {exc}. Nothing was sent and the record is unchanged "
                f"(negotiated, with the pending counter-leg contract {address}): resume again once the cause "
                f"clears. Until a resume completes the watchtower does not track {address}, which may already "
                "hold value; if the cause never clears, refund it by its address after its deadline"
            ) from exc

    async def _save_tracked(self, sink: Any) -> bool:
        """Persist ``self.record`` through the coordinator's persist hook, or else through the *sink*
        the resume loaded it from when that sink can write; whether it was saved."""
        if self._persist is not None:
            await self._persist_record(self.record, shield=True)
            return True
        if callable(sink):
            await asyncio.shield(sink(self.record))
            return True
        return False

    async def _track_refused_resume(self, terms: NegotiatedTerms, why: str, *, sink: Any = None) -> str:
        """Record a REFUSED resume so the watchtower sees what it left on chain; returns the message.

        A resume re-runs the whole taker gate before completing the fund, and a refusal leaves the
        counter-leg contract this swap already DEPLOYED. A native-ETH contract took its value in
        the deploy (the payable constructor); a token contract holds tokens only if the push was
        sent, and the push nonce is recorded before that send. Left NEGOTIATED, the record read as
        "nothing locked" to the watchtower, which observes a counter leg only through its locator:
        no refund page at the deadline, and no alert if the maker claimed the value with ``p``.

        So where the contract MAY hold value the record moves to ``BTC_LOCKED`` with the locator of
        that contract — rebuilt from this swap's own terms and leg (``expected_locator``), the same
        immutables the deploy used — and ``fund_refusal`` says why. Nothing is broadcast; the
        refusal still stands (no push is sent). From there ``taker_refund_btc`` refunds it after the
        deadline, and the watchtower pages for that, or for a claim if the maker reveals ``p``. A
        token contract whose push was never sent holds nothing: the record stays NEGOTIATED (still
        resumable) with the reason recorded.

        Only a DEFINITIVE refusal comes here (:class:`DefinitiveFundRefusal`): one about the terms or
        the time left, which a retry cannot pass. The returned message says what was SAVED: through
        the persist hook, or the sink the resume read the record from; when neither can write, it
        says the change is in memory only.
        """
        rec = self.record
        address, deploy_tx = rec.pending_counter_contract, rec.pending_counter_deploy_tx
        may_hold_value = not terms.token_address or rec.pending_push_nonce is not None
        build = getattr(self.counter_leg, "expected_locator", None)
        if may_hold_value and callable(build):
            locator = build(terms, contract_address=address, deploy_tx_hash=deploy_tx)
            self.record = dataclasses.replace(rec.with_counter_lock(locator), fund_refusal=why)
            self._advance(SwapEvent.TAKER_FUNDS_BTC)
            if not await self._save_tracked(sink):
                return (
                    f"resume refused: {why}. The counter-leg contract {address} was already deployed for this swap "
                    "and may hold value; nothing more was sent. This coordinator has no persist hook and the record "
                    "sink cannot write, so the move to btc_locked is IN MEMORY ONLY: the record on disk still says "
                    f"negotiated and the watchtower does not track {address}. Save coordinator.record, or refund "
                    "the contract by its address after its deadline"
                )
            return (
                f"resume refused: {why}. The counter-leg contract {address} was already deployed for this swap "
                + (
                    "and took its value in the deploy"
                    if not terms.token_address
                    else "and the token push may have been sent"
                )
                + "; nothing more was sent. The record is now btc_locked with that contract's locator and this reason, "
                "so the watchtower tracks it: refund it after its deadline (taker_refund_btc), or claim the covenant "
                "if the maker reveals p"
            )
        self.record = dataclasses.replace(rec, fund_refusal=why)
        saved = await self._save_tracked(sink)
        recorded = "with the reason recorded" if saved else "(the reason is in memory only: nothing could save it)"
        if may_hold_value:
            return (
                f"resume refused: {why}. The counter-leg contract {address} was already deployed for this swap and "
                "may hold value, and this counter leg cannot rebuild its locator, so the record stays negotiated "
                f"{recorded}. Recover it by its address ({address}) after its deadline"
            )
        return (
            f"resume refused: {why}. The token contract {address} was deployed but no token push was sent, so it "
            f"holds nothing; the record stays negotiated {recorded}"
        )

    async def _assert_claim_reached_the_mempool(self) -> None:
        """Confirm the claim actually landed before treating the swap as claimed.

        `claim_asset` returns once the node ACCEPTED the transaction, which is not the same as the
        covenant being spent. Advancing on a broadcast alone meant a claim that never entered — or
        was immediately dropped — left the record saying the asset was claimed while the covenant
        sat there waiting for the maker's CSV refund.

        ABSTAIN is not failure: a source that cannot answer must not fail a claim that probably
        succeeded, on a chain where there is no second chance to send it.
        """
        outpoint = self.record.radiant_covenant_outpoint
        if outpoint is None:
            return
        probe = getattr(getattr(self.radiant_leg, "chain_io", None), "covenant_unspent_incl_mempool", None)
        if probe is None:
            return  # the leg cannot answer; absence of the capability is not evidence of failure
        try:
            unspent = await probe(outpoint)
        except Exception as exc:
            logger.warning("could not confirm the claim reached the mempool for %s: %s", outpoint, exc)
            return
        if unspent is True:
            raise NetworkError(
                f"the claim was broadcast but covenant {outpoint} is still unspent, so it did not "
                "reach the mempool. Radiant has no RBF and no CPFP, and the maker's refund becomes "
                "valid at CSV maturity — retry the claim now rather than treating this as done."
            )

    async def taker_rebroadcast_claim_if_evicted(self, p: bytes) -> str | None:
        """Re-broadcast the taker's claim if it has fallen out of the mempool. Returns the new txid.

        The production entry point for the eviction case. A claim only wins the race with the CSV
        refund by BEING in the mempool when maturity arrives, and Radiant's mempool expiry is about
        eight hours with no RBF to bump it back in. Drive this on whatever tick the operator or the
        watchtower already runs, between the claim and the covenant's maturity.
        """
        if not isinstance(p, (bytes, bytearray)) or len(p) != 32:
            raise ValidationError("preimage must be 32 bytes")
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("preimage does not hash to the negotiated H; refusing to re-broadcast")
        return await self.radiant_leg.rebroadcast_claim_if_evicted(self.record, bytes(p))

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

    # -- taker OBSERVES the maker's on-chain reveal (two-party step 4.5) ----
    @_serialized_step
    async def taker_observed_reveal(self, maker_claim_ref) -> SwapRecord:
        """Advance BOTH_LOCKED -> SECRET_REVEALED on OBSERVING the maker's on-chain claim.

        The honest TAKER never executes the maker's claim (that is the maker's key/action, on a
        different host); it OBSERVES the reveal on-chain and must then enter the claim flow. The only
        other path to SECRET_REVEALED is :meth:`maker_claims_btc` — a MAKER action — so two-party
        callers previously FABRICATED a SECRET_REVEALED record as a resume seam
        (``scripts/eth_swap_two_host.py``) or advanced the FSM directly in tests. This is the
        first-class taker-side transition that replaces both seams.

        It VERIFIES the observed claim is a genuine reveal of THIS swap's ``p`` before advancing —
        ``sha256(p) == H`` scraped from the claim AND the per-swap provenance gate (BTC: the claim
        spends OUR funding outpoint; ETH: it targets OUR HTLC contract and emits ``Claimed(p)``). A
        fabricated or cross-swap "reveal" fails closed and does NOT move the FSM.

        It deliberately does NOT claim the asset and does NOT run the reorg/finality gate — those stay
        in :meth:`taker_scrape_and_claim_asset`, which the caller invokes NEXT (that gate decides
        SAFE/WAIT/SQUEEZED off the same reveal). ``maker_claim_ref`` is the ETH claim tx HASH (str) or
        the raw BTC claim tx bytes — exactly what :meth:`taker_scrape_and_claim_asset` takes.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"taker_observed_reveal only valid from BOTH_LOCKED, not {self.record.state.value}")
        # Prove the observed claim genuinely reveals THIS swap's p (fail-closed) BEFORE advancing —
        # the SAME scrape + provenance the claim step re-runs, minus the finality gate + broadcast.
        if self.record.terms.counter_chain == "btc":
            p = self.counter_leg.scrape_secret(maker_claim_ref, self.record.terms.hashlock)
            if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
                raise ValidationError("observed claim does not reveal a p that opens H; refusing to advance")
            self._assert_claim_tx_spends_our_htlc(maker_claim_ref)
        else:
            locator = self.record.counterchain_locator
            if not isinstance(locator, EthHtlcLocator):
                raise ValidationError("ETH reveal-observation requires an EthHtlcLocator on the record")
            artifacts = await self.counter_leg.fetch_claim_artifacts(maker_claim_ref)
            p = self.counter_leg.scrape_secret(artifacts, self.record.terms.hashlock)
            if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
                raise ValidationError("observed claim does not reveal a p that opens H; refusing to advance")
            await self.counter_leg.assert_claim_provenance(
                maker_claim_ref, contract_address=locator.contract_address, preimage=bytes(p)
            )
        self._advance(SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)
        await self._persist_record(self.record, shield=True)
        return self.record

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
        # ONE CONVERSION, the gate's. `_reserve_to_blocks` CEILS a seconds-tagged reserve;
        # `normalize_to` FLOORS it, which under-counts the reserve — the direction
        # `_reserve_to_blocks` documents as unsafe. Both numbers feed the SAME
        # `from_btc_depth` gate, so flooring here declares the maker's BTC claim final one
        # block early. #607 fixed the third site (`_required_btc_depth_blocks`) and its guard
        # was scoped to `decide.py`, leaving this one and the executor's behind.
        required_depth = _reserve_to_blocks(policy.btc_claim_reorg_depth, policy.block_interval_s)
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
        await self._assert_claim_reached_the_mempool()
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
        and ETH runbooks is :meth:`mutual_refund` (TAKER role on ETH: counter leg only, #850). The
        watchtower (gravity.watch.decide) routes neither counter-chain's taker here.
        """
        # ROLE GUARD (P3): this primitive's CSV refund pays the MAKER in BOTH directions, so a TAKER
        # that runs it gifts the asset back AND destroys its only recourse (the claimable covenant)
        # while its own counter-leg stays locked — the maker, still holding p, then takes both legs
        # (proven by tests/test_xchain_swap_regtest_e2e.py::TestMakerStallAssetOnlyRefundIsTakerLoss).
        # The docstring has always said "MAKER-side only"; a TAKER-role coordinator now cannot call it
        # at all. The taker's stall recovery is mutual_refund (on ETH its own counter leg only, #850).
        if self.config.role is SwapRole.TAKER:
            raise ValidationError(
                "maybe_refund_asset_on_maker_stall is a MAKER-side primitive and is forbidden for a "
                "TAKER-role coordinator: its CSV refund pays the MAKER, so a taker that runs it strands "
                "itself. The taker's maker-stall recovery is mutual_refund (P3 role guard)."
            )
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
        # MATURITY PRE-CHECK (P3): the trigger fires N blocks BEFORE t_rxd maturity ("stop waiting"),
        # but the covenant's CSV refund cannot be MINED until it is buried t_rxd deep. Broadcasting at
        # trigger time (t_rxd - N) is non-final — a real node rejects it, and under deadline pressure a
        # hostile mempool (deadline-pinning) makes "rely on node rejection" fragile. Refuse to broadcast
        # before maturity with an exact "matures at height N, now M" message; a block-based poller
        # retries at maturity. (Uses the SAME normalize_to(BLOCKS) as the trigger so the two agree.)
        #
        # floor-is-deliberate: it MUST match `taker_refund_window_open`'s conversion, or the
        # trigger and the pre-check disagree about the same height and the refund wedges. This
        # gate is also consensus-backstopped — the node rejects a non-final CSV spend — so the
        # floor cannot admit anything the chain would accept. (No-op: t_rxd is pinned to BLOCKS.)
        rxd_blocks = self.record.terms.t_rxd.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=self.config.margin_policy.block_interval_s
        ).value
        maturity_height = asset_locked_at_height + rxd_blocks
        if now_block_height < maturity_height:
            # NetworkError (not ValidationError): "not yet mature" is a TRANSIENT, retryable condition — the
            # same convention the RadiantLeg/BtcLeg refund maturity self-checks use. A block-based poller
            # keys on NetworkError to retry at maturity; raising ValidationError here (a permanent/input
            # error) would make that poller give up on a swap that only needs to wait, risking a missed
            # proactive refund.
            raise NetworkError(
                f"covenant CSV refund is not yet mature: it matures at height {maturity_height}, now "
                f"{now_block_height} ({maturity_height - now_block_height} block(s) to go). Refusing to "
                "broadcast a non-final refund (P3 maturity pre-check) — poll and retry at maturity "
                "rather than relying on node rejection under deadline pressure."
            )
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

    async def _explain_failed_taker_eth_refund(self, locator: Any, refund_error: Exception) -> None:
        """Turn a failed taker ETH refund into what actually happened on chain, when that is knowable.

        A real leg reports both "the maker claimed this contract" and "your own refund already
        landed" as the same preflight ``ValidationError`` ("tx would revert"), usually carrying a
        bare revert code. The two call for opposite actions — claim the covenant with ``p`` before
        ``t_rxd``, or do nothing — so this reads the chain instead of the error text:

        (a) a claim tx in the contract's logs that VERIFIES (``p`` scraped with ``sha256 == H``, and
            the provenance gate: a successful tx emitting ``p`` from this swap's contract) →
            :class:`CounterLegClaimedByCounterparty`, naming the claim tx and the next step;
        (b) the contract's ``settled`` flag set and NO verified claim →
            :class:`CounterLegSettledUnverified`. Deliberately not "refunded": a claim and a refund
            both emit an event, so an honest log source always shows one, and "no verified claim"
            can equally be a log source that is incomplete or lying (read from ONE endpoint). It
            tells the operator to check the contract's events elsewhere before ``t_rxd``;
        (c) anything else (not settled, or the settled flag cannot be read) → returns, and the
            caller re-raises the original error.

        A claim log that does NOT verify, or a log read that fails, falls through to (b) when the
        contract is settled: neither may be reported as the maker's claim, and neither is evidence
        of a refund.

        Read-only. Needs the leg's optional ``observed_claim_tx`` / ``is_settled`` (the shipped
        :class:`pyrxd.gravity.eth_leg.EthLeg` has both); a leg without them gets (c).
        """
        # Local import: keeps this module's import block (and the doc citations into it) unchanged.
        from pyrxd.security.errors import CounterLegClaimedByCounterparty, CounterLegSettledUnverified

        find_claim = getattr(self.counter_leg, "observed_claim_tx", None)
        is_settled = getattr(self.counter_leg, "is_settled", None)
        if find_claim is None or is_settled is None:
            return
        contract = getattr(locator, "contract_address", None)
        try:
            claim_tx = await find_claim(locator)
        except Exception as exc:
            # No verified claim — which, on a settled contract, is exactly case (b), not (c).
            logger.warning("could not read the ETH HTLC %s's logs to explain a failed refund: %s", contract, exc)
            claim_tx = None
        if claim_tx is not None:
            hashlock = self.record.terms.hashlock
            try:
                artifacts = await self.counter_leg.fetch_claim_artifacts(claim_tx)
                p = self.counter_leg.scrape_secret(artifacts, hashlock)
                if hashlib.sha256(bytes(p)).digest() != hashlock:
                    raise ValidationError("the scraped value does not hash to H")
                await self.counter_leg.assert_claim_provenance(claim_tx, contract_address=contract, preimage=bytes(p))
            except Exception as exc:
                logger.warning(
                    "a log on the ETH HTLC %s named tx %s, but it did not verify as a claim of this swap: %s",
                    contract,
                    claim_tx,
                    exc,
                )
                claim_tx = None
        if claim_tx is not None:
            raise CounterLegClaimedByCounterparty(
                f"the ETH refund failed because the MAKER CLAIMED the HTLC {contract} in tx {claim_tx}, "
                "revealing p (verified: sha256(p) == H, and the claim emits p from this swap's contract). "
                "The refund can never succeed now. The RXD covenant "
                f"{self.record.radiant_covenant_outpoint} was NOT touched and is yours to claim with p: run "
                f"taker_observed_reveal({claim_tx!r}) and then taker_scrape_and_claim_asset (two-host "
                f"runner: --phase claim). Do it before the covenant's CSV refund to the maker opens, "
                f"t_rxd = {self.record.terms.t_rxd.value} {self.record.terms.t_rxd.unit.value} after the "
                "covenant was mined; the record is still BOTH_LOCKED.",
                tx_hash=claim_tx,
                contract_address=contract,
            ) from refund_error
        try:
            settled = await is_settled(locator)
        except Exception as exc:
            logger.warning(
                "could not read the ETH HTLC %s's settled flag to explain a failed refund: %s", contract, exc
            )
            return
        if settled:
            t_rxd = self.record.terms.t_rxd
            raise CounterLegSettledUnverified(
                f"the ETH refund failed: the HTLC {contract} is ALREADY SETTLED (claimed or refunded), and "
                "this endpoint showed NO VERIFIED CLAIM. That does not mean it was refunded: a claim and a "
                "refund both emit an event, so an honest node always shows one of them, and the logs here "
                "come from one endpoint that may be incomplete (pruned, range-limited) or not telling the "
                f"truth. CHECK the events of {contract} on another RPC or a block explorer NOW. If the maker "
                "CLAIMED it, p is public and the RXD covenant "
                f"{self.record.radiant_covenant_outpoint} is yours to claim before its CSV refund to the "
                f"maker opens, t_rxd = {t_rxd.value} {t_rxd.unit.value} after the covenant was mined: run "
                "taker_observed_reveal(<claim tx hash>) then taker_scrape_and_claim_asset (two-host runner: "
                'put {"eth_claim_tx_hash": "<claim tx hash>"} in maker_claim.json and run --phase claim). '
                "If it shows only a refund to your address, nothing more is needed on the ETH side.",
                contract_address=contract,
            ) from refund_error

    # -- safe failure: both timeouts elapse, both refund (MUTUAL_REFUND) -----
    @_serialized_step
    async def mutual_refund(self) -> SwapRecord:
        """Both legs refund after both timeouts elapse — the guaranteed-safe failure.

        Valid from BOTH_LOCKED. The taker refunds BTC, the maker refunds the asset;
        neither suffers one-sided loss. Requires the full locator be retained. Async
        because both refunds broadcast on their chains.

        **ETH counter leg, TAKER role: the counter leg ONLY** (#850). The covenant's CSV refund
        pays the MAKER and needs no key, so the taker's process can broadcast it — and "attempt
        both, always" did, even when the counter refund failed because the maker had already
        claimed the ETH HTLC (revealing ``p``). The taker's own tool then sent the covenant back
        to the maker while the taker could still have claimed it with ``p``. So for
        ``role=SwapRole.TAKER`` on an ETH counter leg this broadcasts the counter-leg refund
        only, leaves the covenant for the maker to refund (:meth:`maybe_refund_asset_on_maker_stall`
        in the maker's process), and leaves the record at BOTH_LOCKED: one of the two refunds has
        happened, and the record must stay where :meth:`taker_observed_reveal` can follow a maker
        claim. Recording MUTUAL_REFUND would say both legs were refunded and make that path
        unreachable. When the counter refund fails nothing else is broadcast, and the failure is
        explained from the chain (:meth:`_explain_failed_taker_eth_refund`):
        :class:`~pyrxd.security.errors.CounterLegClaimedByCounterparty` if the maker's claim is
        found and verifies (claim the covenant next), :class:`~pyrxd.security.errors.CounterLegSettledUnverified`
        if the contract is settled with no verified claim (check its events elsewhere; never read as
        "refunded"), else the original error.
        ``EthHtlc``/``Erc20Htlc`` refuse a claim at or after the timeout, so once the refund has
        landed the maker can no longer claim.

        **BTC counter leg: unchanged in this release, for every role** (#850, interim). The BTC
        claim leaf has no timelock, so a maker can still claim with ``p`` while the taker's
        refund is unconfirmed, and the taker's covenant refund forecloses its claim in that
        race — the same defect. It is not closed here because a non-terminal BTC record is
        misread by the watchtower: ``OutspendBtcClaimSource`` reports ANY spend of the BTC HTLC
        as the maker's claim, so the taker's own refund would page a claim race on every tick.
        Fixing BTC needs that spender classification first (#850 plan, PR 9).

        ``role=None`` (one operator driving both legs) and ``role=SwapRole.MAKER`` keep the
        behaviour below on both counter chains: attempt both refunds, advance to MUTUAL_REFUND
        only if both returned. A maker's process holds no BTC refund key, so on BTC its counter
        refund fails and the record stays BOTH_LOCKED; the maker's own recovery is
        :meth:`maybe_refund_asset_on_maker_stall`.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"mutual_refund only valid from BOTH_LOCKED, not {self.record.state.value}")
        if self.record.counterchain_locator is None:
            raise ValidationError("no BTC locator on record; BTC would strand (state was lost)")
        if self.config.role is SwapRole.TAKER and self.record.terms.counter_chain == "eth":
            # The taker's own leg only. No FSM advance and nothing new to persist: the record
            # already says BOTH_LOCKED, which is still true of the covenant. A failed refund is
            # explained from the chain only when a claim VERIFIES; settled with no verified claim
            # is reported as unverified (never as refunded); otherwise the error propagates.
            locator = self.record.counterchain_locator
            try:
                await self.counter_leg.refund(locator, self.record.terms.t_btc)
            except Exception as refund_error:
                await self._explain_failed_taker_eth_refund(locator, refund_error)
                raise
            logger.info(
                "mutual_refund (TAKER role, ETH): counter-leg refund sent; the covenant is left for the "
                "maker to refund and the record stays BOTH_LOCKED."
            )
            return self.record
        # ATTEMPT BOTH, ALWAYS. These two refunds are independent — neither is a precondition for
        # the other — so a failure in the first must not skip the second. Sequencing them with a
        # bare `await; await` made a crash between the broadcasts unrecoverable: the record stays
        # BOTH_LOCKED with the counter leg already refunded, and on retry the counter leg's
        # preflight reverts against the settled contract and raises BEFORE the Radiant refund ever
        # runs. The leg that still holds value could then never be refunded in-band, which is the
        # opposite of what "the guaranteed-safe failure" promises.
        failures: list[tuple[str, Exception]] = []
        try:
            await self.counter_leg.refund(self.record.counterchain_locator, self.record.terms.t_btc)
        except Exception as exc:
            failures.append(("counter leg", exc))
        try:
            await self.radiant_leg.refund_asset(self.record)
        except Exception as exc:
            failures.append(("radiant leg", exc))
        if failures:
            # State deliberately NOT advanced: still BOTH_LOCKED, so a retry re-attempts both. A
            # leg that already refunded fails harmlessly the second time; a leg that did not gets
            # its chance.
            raise NetworkError(
                "mutual refund incomplete — "
                + "; ".join(f"{leg}: {exc}" for leg, exc in failures)
                + ". The other leg was attempted regardless. The swap stays BOTH_LOCKED so a "
                "retry re-attempts both; refunds are independent and re-attempting a settled leg "
                "is harmless."
            )
        self._advance(SwapEvent.BOTH_TIMEOUTS_ELAPSE)
        await self._persist_record(self.record, shield=True)
        return self.record

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
import hashlib
import logging
import math
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum

from pyrxd.btc_wallet.htlc_leg import AUDIT_CLEARED_NETWORKS
from pyrxd.btc_wallet.taproot import (
    BtcHtlcLocator,
    Timelock,
    TimeUnit,
)
from pyrxd.security.errors import ValidationError
from pyrxd.security.secrets import SecretBytes

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
    "should_taker_refund_proactively",
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

    @classmethod
    def estimated(cls, *, block_interval_s: float = 600.0, require_measured: bool = False) -> MarginPolicy:
        """The ESTIMATED, test-only policy. Refuses to construct in real-value mode."""
        return cls(
            margin=Timelock(ESTIMATED_DEFAULT_MARGIN_BLOCKS, TimeUnit.BLOCKS),
            block_interval_s=block_interval_s,
            is_measured=False,
            require_measured=require_measured,
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
    ) -> MarginPolicy:
        """A measured policy for real-value mainnet swaps.

        ``btc_claim_reorg_depth`` / ``rxd_claim_burial`` are the reorg gate's measured
        inputs; if omitted they fall back to the ESTIMATED defaults (acceptable only
        because a measured policy still carries the estimated reorg depths — supply
        measured values for a real mainnet swap).
        """
        kwargs: dict = {
            "margin": margin,
            "block_interval_s": block_interval_s,
            "is_measured": True,
            "require_measured": True,
        }
        if btc_claim_reorg_depth is not None:
            kwargs["btc_claim_reorg_depth"] = btc_claim_reorg_depth
        if rxd_claim_burial is not None:
            kwargs["rxd_claim_burial"] = rxd_claim_burial
        if rxd_block_interval_s is not None:
            kwargs["rxd_block_interval_s"] = rxd_block_interval_s
        return cls(**kwargs)


def measure_margin_from_btc_block_times(
    *,
    btc_block_timestamps: list[int],
    btc_tail_percentile: float,
    btc_claim_reorg_depth_blocks: int,
    rxd_claim_burial_blocks: int,
    rxd_block_interval_s: float,
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


def should_taker_refund_proactively(
    *,
    now_block_height: int,
    asset_locked_at_height: int,
    t_rxd: Timelock,
    safety_window_blocks: int,
    maker_has_claimed_btc: bool,
    block_interval_s: float = 600.0,
) -> bool:
    """Return True once the taker MUST refund the asset rather than keep waiting.

    The dominant adversarial risk: because ``t_BTC > t_RXD``, a malicious maker can
    withhold their BTC claim until *after* ``t_RXD`` opens, then claim BTC (revealing
    ``p``) AND refund the asset — the taker loses both. The defense (C1): treat
    "maker has not claimed and ``t_RXD - N`` is approaching" as a trigger to refund
    the asset proactively, NEVER a reason to keep waiting.

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


def assess_claim_finality(
    *,
    btc_claim_confirmations: int,
    now_rxd_height: int,
    asset_locked_at_height: int,
    t_rxd: Timelock,
    policy: MarginPolicy,
) -> ClaimFinality:
    """Decide SAFE / WAIT / SQUEEZED for the taker's asset claim — fail-closed, pure.

    Two serial finality requirements share the ``t_rxd`` deadline (security review):
      1. the maker's BTC claim must reach ``policy.btc_claim_reorg_depth`` (so ``p`` is
         reorg-safe), THEN
      2. the taker's own Radiant claim must bury ``policy.rxd_claim_burial`` deep,
      both BEFORE ``t_rxd`` (the maker's CSV refund) opens at
      ``asset_locked_at_height + t_rxd``.

    A bare depth gate without the deadline check is a NET REGRESSION: it can force the
    taker to choose between an unsafe early claim and losing the asset to the maker's
    refund. So this returns WAIT only while there is genuinely room to wait, and
    SQUEEZED (→ ASSET_VULNERABLE) once there is not.

    Raises ``ValidationError`` on any un-evaluable input (never assumes "plenty of
    time"). All depths normalised to Radiant BLOCKS via ``policy.block_interval_s``.
    """
    if not isinstance(policy, MarginPolicy):
        raise ValidationError("assess_claim_finality requires a MarginPolicy")
    for label, val in (
        ("btc_claim_confirmations", btc_claim_confirmations),
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
        rxd_burial = policy.rxd_claim_burial.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s
        ).value
        btc_depth_confs = policy.btc_claim_reorg_depth.normalize_to(
            TimeUnit.BLOCKS, block_interval_s=policy.block_interval_s
        ).value
    except ValidationError:
        raise
    except Exception as exc:  # pragma: no cover - normalize_to only raises ValidationError
        raise ValidationError(f"could not normalise reorg depths to blocks: {exc}") from exc

    # The maker's CSV refund opens here (Radiant blocks).
    refund_opens_at = asset_locked_at_height + rxd_blocks
    # To claim SAFELY from now we still need: bury our own claim rxd_burial deep,
    # which (if the BTC claim weren't yet deep) would also require waiting out the
    # remaining BTC depth first. The binding deadline is refund_opens_at.
    blocks_left = refund_opens_at - now_rxd_height

    if btc_claim_confirmations >= btc_depth_confs:
        # BTC claim is reorg-safe. We may claim iff our own burial still fits the window.
        if blocks_left >= rxd_burial:
            return ClaimFinality.SAFE
        return ClaimFinality.SQUEEZED
    # BTC claim still shallow. We can WAIT only if, after the BTC depth elapses, there
    # is STILL room to bury our claim before the refund opens.
    # F-007: the BTC reorg depth is in BTC blocks; convert the wall-clock it represents
    # into RXD blocks (the unit of blocks_left) before subtracting. BTC and RXD block
    # rates differ, so treating BTC blocks 1:1 as RXD blocks under-counts the RXD window
    # the BTC burial consumes and biases WAIT optimistic. Round UP (conservative).
    btc_blocks_remaining = btc_depth_confs - btc_claim_confirmations
    btc_depth_in_rxd = math.ceil(btc_depth_confs * policy.block_interval_s / policy.rxd_block_interval_s)
    if blocks_left - btc_depth_in_rxd >= rxd_burial and btc_blocks_remaining > 0:
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

    def __post_init__(self) -> None:
        if not isinstance(self.margin_policy, MarginPolicy):
            raise ValidationError("margin_policy must be a MarginPolicy")
        w = self.maker_stall_safety_window_blocks
        if not isinstance(w, int) or isinstance(w, bool) or w < 0:
            raise ValidationError("maker_stall_safety_window_blocks must be a non-negative int")
        c = self.min_ref_confirmations
        if not isinstance(c, int) or isinstance(c, bool) or c < 0:
            raise ValidationError("min_ref_confirmations must be a non-negative int")
        if not isinstance(self.accept_nondurable_seen, bool):
            raise ValidationError("accept_nondurable_seen must be a bool")


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
        btc_leg,
        radiant_leg,
        indexer,
        seen_store,
        config: CoordinatorConfig,
        persist: PersistHook | None = None,
    ) -> None:
        if not isinstance(record, SwapRecord):
            raise ValidationError("record must be a SwapRecord")
        if not isinstance(config, CoordinatorConfig):
            raise ValidationError("config must be a CoordinatorConfig")
        if persist is not None and not callable(persist):
            raise ValidationError("persist must be an async callable or None")
        # SEEN-1 guard: refuse a NON-durable (in-process) seen-store on a
        # value-bearing network unless the operator explicitly accepts it. A
        # non-durable store loses H-freshness on a restart / second process, so a
        # long-lived or multi-process value-moving deployment would silently
        # re-open the replay / free-option window. ``durable`` defaults False for
        # any store that does not declare itself durable (fail-closed).
        store_durable = bool(getattr(seen_store, "durable", False))
        value_bearing = _leg_is_value_bearing(btc_leg) or _leg_is_value_bearing(radiant_leg)
        if value_bearing and not store_durable and not config.accept_nondurable_seen:
            raise ValidationError(
                "seen-store is NON-durable (in-process only) but the coordinator is wired to a "
                "value-bearing network: a restart or a second process resurrects the H-replay / "
                "free-option window (SEEN-1). Use a durable SeenStore (durable=True), or pass "
                "CoordinatorConfig(accept_nondurable_seen=True) to consciously accept "
                "non-durability for a single-process, single-shot, fresh-H-per-run runbook."
            )
        self.record = record
        self.btc_leg = btc_leg
        self.radiant_leg = radiant_leg
        self.indexer = indexer
        self.seen_store = seen_store
        self.config = config
        self._persist = persist

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
    async def pre_btc_lock_check(self, terms: NegotiatedTerms) -> PreBtcLockGate:
        """Validate everything the taker can check BEFORE funding BTC (fail-closed).

        Checks, in order (any failure => do NOT fund):
          1. REF authenticity via ``verify_ref_authenticity`` — the resolved reveal
             must bind to the ADVERTISED asset (genesis-outpoint==ref, `gly` marker,
             optional payload hash, ≥ ``min_ref_confirmations``). Indexer
             unavailable / shallow genesis / wrong asset => fail-closed.
          2. H freshness — a read-only advisory probe of the seen-store (reused H
             => reject early). The authoritative atomic reserve happens later, in
             :meth:`taker_funds_btc`, immediately before the broadcast.
          3. The cross-chain margin ordering (``t_btc - t_rxd >= margin``).
          4. Maker-*promised* params match the locally re-derived BTC funding SPK
             (the on-chain re-validation happens later in
             :meth:`post_asset_lock_revalidate`).

        Async because binding (1) awaits the async indexer adapter (a sync gate
        would leak a truthy un-awaited coroutine = fail-OPEN, T7 plan D2).
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

        # 2. H freshness — advisory read-only probe for a clean early reject; the
        #    authoritative atomic reserve is in taker_funds_btc, pre-broadcast.
        try:
            if self.seen_store.has_seen(terms.hashlock):
                return PreBtcLockGate(ok=False, reason="hashlock H reused (free-option / preimage-replay risk)")
        except Exception as exc:
            return PreBtcLockGate(ok=False, reason=f"seen-store unavailable; fail-closed ({exc})")

        # 3. Margin / ordering (fail-closed; raises on un-normalisable units).
        try:
            assert_timelock_margin(terms.t_btc, terms.t_rxd, self.config.margin_policy)
        except ValidationError as exc:
            return PreBtcLockGate(ok=False, reason=f"margin check failed: {exc}")

        # 4. Maker-promised BTC params match locally re-derived funding SPK.
        try:
            expected_spk = self.btc_leg.derive_funding_scriptpubkey(terms)
            promised_spk = self.btc_leg.promised_funding_scriptpubkey(terms)
        except Exception as exc:
            return PreBtcLockGate(ok=False, reason=f"could not derive BTC funding SPK; fail-closed ({exc})")
        if expected_spk != promised_spk:
            return PreBtcLockGate(ok=False, reason="maker-promised BTC params do not match re-derived funding SPK")

        return PreBtcLockGate(ok=True)

    # -- taker funds BTC first (the role invariant's step 2) ----------------
    async def taker_funds_btc(self, terms: NegotiatedTerms) -> SwapRecord:
        """Run the pre-lock gate, fund the BTC HTLC, record the locator, advance.

        Refuses (raises) if the pre-lock gate fails — the taker NEVER funds against a
        failed gate. H is ATOMICALLY reserved in the seen-store PRE-broadcast (so a
        concurrent or repeat funder of the same H is refused before any BTC moves;
        TOCTOU-1), and the durable record carries the full :class:`BtcHtlcLocator`.

        Atomicity (kieran-python HIGH): ``btc_leg.fund`` broadcasts on-chain, so a
        cancellation between the broadcast and the in-memory state advance would
        leave BTC locked but the record at NEGOTIATED → a retry double-funds. We
        persist an INTENT record (terms + derived funding SPK, enough to recover the
        address) BEFORE the awaited fund, and ``asyncio.shield()`` the post-broadcast
        persist of the funded record. ``fund`` itself must be idempotent (treat
        "already in mempool" as success) so a retry after an intent-only crash does
        not lock twice. Persistence is a no-op when no ``persist`` hook is injected.
        """
        if self.record.state is not SwapState.NEGOTIATED:
            raise ValidationError(f"taker_funds_btc only valid from NEGOTIATED, not {self.record.state.value}")
        gate = await self.pre_btc_lock_check(terms)
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

        locator = await self.btc_leg.fund(terms)
        if not isinstance(locator, BtcHtlcLocator):
            raise ValidationError("btc_leg.fund must return a BtcHtlcLocator (full durable retained state)")
        # Bind the funded amount to the negotiated price. A P2TR scriptPubKey commits
        # to the taptree, NOT the output value, so the funding SPK check in
        # pre_btc_lock_check (step 4) cannot catch a wrong amount — this is the only
        # layer that can. An OVER-funded HTLC is a one-sided taker loss: the maker
        # claims the whole output via the preimage (the claim leaf does not cap value).
        # Under-funding is self-correcting (the maker won't reveal), but we reject both
        # so a mutated `terms` or a buggy leg fails closed before the BTC is locked.
        if locator.amount_sats != terms.btc_sats:
            raise ValidationError(
                f"funded BTC amount {locator.amount_sats} != negotiated btc_sats {terms.btc_sats}; "
                "refusing to lock a mis-valued HTLC"
            )
        # (H was already reserved atomically pre-broadcast above — no post-fund mark.)
        self.record = self.record.with_btc_lock(locator)
        self._advance(SwapEvent.TAKER_FUNDS_BTC)
        # Shielded: the BTC is locked on-chain now; losing this write would
        # double-fund on retry, so it must complete even under cancellation.
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- post-asset-lock re-validation (H4 b) -------------------------------
    async def post_asset_lock_revalidate(self, observed_covenant_spk: bytes) -> SwapRecord:
        """Re-check the on-chain covenant SPK == expected-from-terms+H.

        Called when the maker locks the asset. The expected SPK is recomputed from
        the negotiated terms + H (the constructor params bind hashlock/refundCsv/
        amount/dest-hashes/REF into the covenant bytecode). On match => BOTH_LOCKED.
        On mismatch => PARAMS_MISMATCH; the caller then refunds the BTC via the
        timelock leg (see :meth:`taker_refund_btc`).

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
        self._advance(SwapEvent.MAKER_LOCKS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- maker claims BTC, revealing p (role invariant step 4) --------------
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
        if self.record.btc_locator is None:
            raise ValidationError("no BTC locator on record; cannot claim")
        raw = preimage.unsafe_raw_bytes()
        if hashlib.sha256(raw).digest() != self.record.terms.hashlock:
            raise ValidationError("preimage does not hash to the negotiated H; refusing to broadcast")
        try:
            await self.btc_leg.claim(self.record.btc_locator, raw)
        finally:
            preimage.zeroize()
        self._advance(SwapEvent.MAKER_CLAIMS_BTC_REVEALS_P)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- taker scrapes p from the claim tx and claims the asset (step 5) ----
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
        """
        if self.record.state is not SwapState.SECRET_REVEALED:
            raise ValidationError(
                f"taker_scrape_and_claim_asset only valid from SECRET_REVEALED, not {self.record.state.value}"
            )
        # Cheap, no-network checks first: a tx that doesn't even contain p is rejected
        # before any RPC round-trip.
        p = self.btc_leg.scrape_secret(maker_claim_tx_bytes, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")

        # Reorg gate: read the maker's BTC-claim depth (fail-closed on any error) and
        # assess against the t_rxd window.
        btc_confs = await self.btc_leg.confirmations_of_claim(maker_claim_tx_bytes)
        finality = assess_claim_finality(
            btc_claim_confirmations=btc_confs,
            now_rxd_height=now_rxd_height,
            asset_locked_at_height=asset_locked_at_height,
            t_rxd=self.record.terms.t_rxd,
            policy=self.config.margin_policy,
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

    # -- deliberate winner-take-all claim from the SQUEEZED/ASSET_VULNERABLE state --
    async def taker_claim_asset_from_vulnerable(self, maker_claim_tx_bytes: bytes) -> SwapRecord:
        """Best-effort asset claim from ASSET_VULNERABLE — an EXPLICIT policy decision.

        Only valid from ASSET_VULNERABLE (reached when the reorg gate found the swap
        SQUEEZED). This is winner-take-all: the taker races to claim the asset before
        the maker's ``t_rxd`` CSV refund lands, accepting the residual reorg risk that
        the gate flagged. It is a CONSCIOUS choice the caller makes after the gate
        refused the automatic SAFE claim — never invoked silently.
        """
        if self.record.state is not SwapState.ASSET_VULNERABLE:
            raise ValidationError(
                f"taker_claim_asset_from_vulnerable only valid from ASSET_VULNERABLE, not {self.record.state.value}"
            )
        p = self.btc_leg.scrape_secret(maker_claim_tx_bytes, self.record.terms.hashlock)
        if hashlib.sha256(bytes(p)).digest() != self.record.terms.hashlock:
            raise ValidationError("scraped preimage does not hash to H; refusing Radiant claim")
        await self.radiant_leg.claim_asset(self.record, bytes(p))
        self._advance(SwapEvent.TAKER_SCRAPES_P_CLAIMS_ASSET)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- maker-stall proactive asset refund (C1) ----------------------------
    async def maybe_refund_asset_on_maker_stall(
        self, *, now_block_height: int, asset_locked_at_height: int, maker_has_claimed_btc: bool
    ) -> SwapRecord:
        """If the maker is stalling near ``t_RXD - N``, refund the asset proactively.

        Drives BOTH_LOCKED -> MAKER_STALLS -> ASSET_REFUNDED_TAKER_ACTS. A no-op
        (returns the unchanged record) when the trigger has not fired yet. Async
        because the asset refund broadcasts a Radiant covenant spend.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(
                f"maybe_refund_asset_on_maker_stall only valid from BOTH_LOCKED, not {self.record.state.value}"
            )
        trigger = should_taker_refund_proactively(
            now_block_height=now_block_height,
            asset_locked_at_height=asset_locked_at_height,
            t_rxd=self.record.terms.t_rxd,
            safety_window_blocks=self.config.maker_stall_safety_window_blocks,
            maker_has_claimed_btc=maker_has_claimed_btc,
            block_interval_s=self.config.margin_policy.block_interval_s,
        )
        if not trigger:
            return self.record
        self._advance(SwapEvent.MAKER_STALL_DETECTED)
        await self._persist_record(self.record, shield=True)
        # The taker refunds the asset rather than wait (NEVER waits).
        await self.radiant_leg.refund_asset(self.record)
        self._advance(SwapEvent.TAKER_REFUNDS_ASSET_PROACTIVELY)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- taker refunds BTC (ABORT paths: maker never locks, or PARAMS_MISMATCH)
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
        if self.record.btc_locator is None:
            raise ValidationError("no BTC locator on record; cannot refund (state was lost)")
        await self.btc_leg.refund(self.record.btc_locator, self.record.terms.t_btc)
        if state is SwapState.BTC_LOCKED:
            self._advance(SwapEvent.MAKER_NEVER_LOCKS_BTC_TIMEOUT)
        else:
            self._advance(SwapEvent.TAKER_REFUNDS_BTC)
        await self._persist_record(self.record, shield=True)
        return self.record

    # -- safe failure: both timeouts elapse, both refund (MUTUAL_REFUND) -----
    async def mutual_refund(self) -> SwapRecord:
        """Both legs refund after both timeouts elapse — the guaranteed-safe failure.

        Valid from BOTH_LOCKED. The taker refunds BTC, the maker refunds the asset;
        neither suffers one-sided loss. Requires the full locator be retained. Async
        because both refunds broadcast on their chains.
        """
        if self.record.state is not SwapState.BOTH_LOCKED:
            raise ValidationError(f"mutual_refund only valid from BOTH_LOCKED, not {self.record.state.value}")
        if self.record.btc_locator is None:
            raise ValidationError("no BTC locator on record; BTC would strand (state was lost)")
        await self.btc_leg.refund(self.record.btc_locator, self.record.terms.t_btc)
        await self.radiant_leg.refund_asset(self.record)
        self._advance(SwapEvent.BOTH_TIMEOUTS_ELAPSE)
        await self._persist_record(self.record, shield=True)
        return self.record

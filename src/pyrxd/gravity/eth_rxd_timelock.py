"""Cross-clock (ETH absolute-seconds ↔ RXD relative-blocks) timelock bridge.

The BTC↔RXD swap keeps both legs in the same relative-CSV/BLOCKS clock, so the mature
``assert_timelock_margin`` can normalize them through one block interval. The ETH leg
breaks that symmetry: an ETH HTLC refund is an ABSOLUTE unix-second ``block.timestamp``
deadline, while the Radiant covenant refund is a RELATIVE CSV/BIP68 count in BLOCKS that
only starts counting once the covenant is MINED. This module bridges the two:

* :func:`eth_absolute_to_rxd_relative_blocks` converts the absolute ETH deadline into the
  relative RXD-block window the maker should lock the covenant for, with conservative
  (floor) rounding + a fail-closed safety floor, so the canonical HTLC ordering invariant
  holds across the unit + anchor boundary: the asset/RXD leg (claimed SECOND, by the taker)
  opens its refund strictly BEFORE the counter/ETH leg's deadline by at least the margin —
  i.e. the counter/ETH leg, claimed FIRST by the maker, holds the LONGER deadline (the
  cross-clock analog of the BTC ``t_BTC > t_RXD`` invariant). The inherent risk this ordering
  creates (a maker withholding its claim until past the RXD refund, then claiming AND
  refunding) is defended by the proactive asset-refund, not by the timelock alone — see
  :func:`pyrxd.gravity.swap_coordinator.should_taker_refund_proactively`.

* :func:`assert_covenant_confirms_before_eth_deadline` is the funding-confirmation gate
  that closes the NEW mixed-clock race (re-audit SC-3/TLK-1): because the RXD CSV clock
  does not start until the covenant confirms, a delay between agreeing terms and the
  covenant being mined pushes the real RXD refund later in wall-clock against the FIXED ETH
  deadline. The gate refuses to lock RXD unless the covenant can plausibly confirm with
  enough margin still left.

Pure (no chain I/O) and fail-closed (``ValidationError``, never ``assert``). On mainnet
``rxd_block_interval_s`` MUST be a MEASURED value — estimates are test-only — the same
provenance discipline as ``MarginPolicy`` / ``Timelock.normalize_to``.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.security.errors import ValidationError

__all__ = [
    "CrossClockMargin",
    "assert_covenant_confirms_before_eth_deadline",
    "eth_absolute_to_rxd_relative_blocks",
]

# BIP68 relative-block fields are 16 bits; mirrors Timelock's own guard so the converter
# fails with a domain-specific message instead of a generic encoding error.
_MAX_RXD_CSV_BLOCKS = 0xFFFF


@dataclass(frozen=True)
class CrossClockMargin:
    """The safety budget (seconds) carved out of the ETH→RXD deadline gap.

    Each component is a deliberate, documented seconds budget; the converter subtracts
    their sum from the ETH deadline before sizing the RXD window, so the RXD refund opens
    strictly BEFORE the ETH deadline by at least this much wall-clock (the RXD/asset leg,
    claimed second, holds the SHORTER deadline; the ETH/counter leg the longer).

    ``eth_reorg_finality_s`` is CHOSEN/ESTIMATED (post-Merge ETH has variable finalization
    lag, ~2 epochs ≈ 12.8 min in the steady state); ``rounding_slack_s`` MUST be at least
    one ``rxd_block_interval_s`` to absorb the converter's floor rounding plus a cross-chain
    clock-skew budget.
    """

    eth_reorg_finality_s: int  # ETH finalized-checkpoint lag (CHOSEN/ESTIMATED)
    rxd_claim_burial_s: int  # time for the taker's RXD claim to bury reorg-deep
    rxd_confirm_slack_s: int  # slack for the RXD claim tx to propagate + confirm
    rounding_slack_s: int  # block-rounding (>= one block) + cross-chain clock-skew budget

    def __post_init__(self) -> None:
        for name in (
            "eth_reorg_finality_s",
            "rxd_claim_burial_s",
            "rxd_confirm_slack_s",
            "rounding_slack_s",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValidationError(f"CrossClockMargin.{name} must be int seconds")
            if value < 0:
                raise ValidationError(f"CrossClockMargin.{name} must be >= 0")

    def total_s(self) -> int:
        return self.eth_reorg_finality_s + self.rxd_claim_burial_s + self.rxd_confirm_slack_s + self.rounding_slack_s


def eth_absolute_to_rxd_relative_blocks(
    *,
    eth_timeout_unix_s: int,
    expected_rxd_lock_time_unix_s: int,
    margin: CrossClockMargin,
    rxd_block_interval_s: float,
    floor_blocks: int = 12,
) -> Timelock:
    """Size the RXD covenant's RELATIVE CSV window (in BLOCKS) from the ETH ABSOLUTE deadline.

    The RXD refund — relative, anchored at covenant mining ≈ ``expected_rxd_lock_time_unix_s``
    — must open strictly BEFORE the ETH deadline minus the full margin (the RXD/asset leg
    holds the SHORTER deadline; the ETH/counter leg the longer). The window is sized as large
    as that allows (rxd-refund pushed up to, but not past, ``eth_timeout - margin``, maximising
    the taker's claim window). So the available wall-clock budget for the RXD window is::

        budget_s = eth_timeout_unix_s - margin.total_s() - expected_rxd_lock_time_unix_s

    converted to blocks by FLOOR. Flooring can only SHORTEN the RXD window, which lets the
    maker reclaim the asset no later than computed (never longer); the sub-block remainder
    is covered by ``margin.rounding_slack_s``. Fail-closed ``ValidationError`` if the budget
    is non-positive, below the safety floor, or beyond the BIP68 16-bit cap.
    """
    _require_int(eth_timeout_unix_s, "eth_timeout_unix_s")
    _require_int(expected_rxd_lock_time_unix_s, "expected_rxd_lock_time_unix_s")
    if not isinstance(floor_blocks, int) or isinstance(floor_blocks, bool) or floor_blocks < 1:
        raise ValidationError("floor_blocks must be a positive int")
    if rxd_block_interval_s <= 0:
        raise ValidationError("rxd_block_interval_s must be > 0 (use a MEASURED value on mainnet)")

    budget_s = eth_timeout_unix_s - margin.total_s() - expected_rxd_lock_time_unix_s
    if budget_s <= 0:
        raise ValidationError(
            f"no RXD timelock budget: eth_timeout - margin - rxd_lock_time = {budget_s}s "
            "(ETH deadline too close / margin too large to safely lock RXD)"
        )
    t_rxd_blocks = math.floor(budget_s / rxd_block_interval_s)
    if t_rxd_blocks < floor_blocks:
        raise ValidationError(
            f"RXD timelock {t_rxd_blocks} blocks below safety floor {floor_blocks} "
            f"(budget {budget_s}s at {rxd_block_interval_s}s/block)"
        )
    if t_rxd_blocks > _MAX_RXD_CSV_BLOCKS:
        raise ValidationError(
            f"RXD timelock {t_rxd_blocks} blocks exceeds the BIP68 16-bit cap "
            f"{_MAX_RXD_CSV_BLOCKS} (ETH deadline too far in the future to map to a "
            "relative CSV window)"
        )
    return Timelock(t_rxd_blocks, TimeUnit.BLOCKS)


def assert_covenant_confirms_before_eth_deadline(
    *,
    now_unix_s: int,
    eth_timeout_unix_s: int,
    margin: CrossClockMargin,
    t_rxd: Timelock,
    rxd_block_interval_s: float,
    max_covenant_confirm_wait_s: int,
) -> None:
    """Mixed-clock funding-confirmation gate (re-audit SC-3/TLK-1).

    Because the RXD CSV clock starts at covenant MINING, the real RXD refund opens at
    roughly::

        now_unix_s + max_covenant_confirm_wait_s + t_rxd.value * rxd_block_interval_s

    which must stay strictly before ``eth_timeout_unix_s - margin.total_s()``. The projected
    open is rounded UP (``ceil``) so the gate errs toward refusing. Run this TWICE: (1)
    pre-lock with the worst-case ``max_covenant_confirm_wait_s`` (a projection before
    broadcasting the covenant), and (2) post-confirm with ``now_unix_s = actual mining time``
    and ``max_covenant_confirm_wait_s = 0``; if (2) fails the maker must refund the covenant
    proactively rather than proceed. Raises ``ValidationError`` when the covenant would
    confirm too late to lock RXD safely.
    """
    if not isinstance(t_rxd, Timelock) or t_rxd.unit is not TimeUnit.BLOCKS:
        raise ValidationError("t_rxd must be a BLOCKS Timelock")
    _require_int(now_unix_s, "now_unix_s")
    _require_int(eth_timeout_unix_s, "eth_timeout_unix_s")
    if rxd_block_interval_s <= 0:
        raise ValidationError("rxd_block_interval_s must be > 0")
    if not isinstance(max_covenant_confirm_wait_s, int) or isinstance(max_covenant_confirm_wait_s, bool):
        raise ValidationError("max_covenant_confirm_wait_s must be int")
    if max_covenant_confirm_wait_s < 0:
        raise ValidationError("max_covenant_confirm_wait_s must be >= 0")

    deadline_s = eth_timeout_unix_s - margin.total_s()
    projected_rxd_open_s = now_unix_s + max_covenant_confirm_wait_s + math.ceil(t_rxd.value * rxd_block_interval_s)
    if projected_rxd_open_s >= deadline_s:
        raise ValidationError(
            f"covenant would confirm too late: projected RXD refund opens at "
            f"{projected_rxd_open_s} >= ETH-deadline-minus-margin {deadline_s} — refusing to "
            "lock RXD (SC-3/TLK-1 mixed-clock race)"
        )


def _require_int(value: object, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{name} must be int seconds")

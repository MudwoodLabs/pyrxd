"""Observation / quorum layer for the watchtower (v1 alert-only, BTC).

Turns chain reads into the :class:`Observations` that :func:`decide` consumes. The
safety-critical input — the maker's BTC-claim *depth* — must be quorum-agreed
(conservative ``min`` across independent sources, fail-closed below quorum); the
shell backs :class:`BtcClaimSource.confirmations` with
``network.bitcoin.MultiSourceBtcFundingReader`` (already built: ``min(depth)``,
2-of-3, fail-closed). The RXD side is **single-source** in v1 (no Radiant
multi-source primitive exists — Phase-0 finding), so every RXD-derived reading is
flagged ``low_corroboration`` — a false RXD read causes a false *page*, never a
false broadcast. Full RXD quorum is a v2 (autonomous) blocker.

This module defines the ports and the composing :class:`ChainObserver`; the
concrete transports (mempool.space outspend for claim detection,
``MultiSourceBtcFundingReader`` for depth, ssh-tr / ElectrumX for RXD) are wired by
the daemon shell so the brain stays unit-testable with fakes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pyrxd.gravity.swap_state import SwapRecord
from pyrxd.gravity.watch.decide import Observations
from pyrxd.gravity.watch.reconciler import Observer
from pyrxd.security.errors import ValidationError

__all__ = ["BtcClaimSource", "BtcClaimStatus", "ChainObserver", "RxdChainSource"]


@dataclass(frozen=True)
class BtcClaimStatus:
    """Whether the maker's BTC HTLC funding outpoint has been spent by a claim, and
    the spending txid (for the depth read). ``claimed=False`` means the outpoint is
    still unspent (maker has not revealed ``p``)."""

    claimed: bool
    claim_txid: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.claimed, bool):
            raise ValidationError("BtcClaimStatus.claimed must be bool")
        if self.claim_txid is not None and (not isinstance(self.claim_txid, str) or len(self.claim_txid) != 64):
            raise ValidationError("BtcClaimStatus.claim_txid must be 64-char hex or None")
        if self.claimed and self.claim_txid is None:
            raise ValidationError("a claimed BtcClaimStatus must carry the claim_txid")


@runtime_checkable
class BtcClaimSource(Protocol):
    """Detects the maker's counter-leg claim and reads its quorum-agreed depth.

    ``confirmations`` MUST be quorum-backed (conservative ``min`` across independent
    sources) — it is the reorg-safety input to the gate. The shell satisfies it with
    ``MultiSourceBtcFundingReader``.
    """

    async def claim_status(self, funding_txid: str, funding_vout: int) -> BtcClaimStatus:
        """Has the HTLC funding outpoint been spent (the maker's claim)? If so, by what tx?"""
        ...

    async def confirmations(self, claim_txid: str) -> int:
        """Quorum-agreed confirmation depth of the maker's claim tx."""
        ...


@runtime_checkable
class RxdChainSource(Protocol):
    """Radiant chain reads. Single-source in v1 (flagged low-corroboration)."""

    async def tip_height(self) -> int:
        """Current RXD tip height (``getblockcount``)."""
        ...

    async def covenant_confirmations(self, outpoint: str) -> int | None:
        """Confirmations of the funded covenant UTXO, or ``None`` if not found/unmined.

        Used to derive ``asset_locked_at_height = tip - confirmations + 1`` (the height
        the covenant was mined), mirroring the dust driver."""
        ...


class ChainObserver(Observer):
    """Composes a :class:`BtcClaimSource` + a :class:`RxdChainSource` into the
    :class:`Observations` that :func:`decide` consumes.

    ``rxd_corroborated`` is False in v1 (single RXD source) → every observation is
    flagged ``low_corroboration``. Pass True only once a real ≥2-source RXD quorum
    exists (a v2 deliverable).
    """

    def __init__(self, *, btc: BtcClaimSource, rxd: RxdChainSource, rxd_corroborated: bool = False) -> None:
        if not isinstance(rxd_corroborated, bool):
            raise ValidationError("ChainObserver.rxd_corroborated must be bool")
        self._btc = btc
        self._rxd = rxd
        self._rxd_corroborated = rxd_corroborated

    async def observe(self, swap_id: str, record: SwapRecord) -> Observations:
        tip = await self._rxd.tip_height()

        # Maker claim detection (BTC counter-leg). record.btc_locator is None until
        # the BTC leg is funded, and for an ETH swap (decide() short-circuits ETH to
        # NOOP, so a benign all-False observation is fine there).
        maker_claimed = False
        btc_confs: int | None = None
        locator = record.btc_locator
        if locator is not None:
            status = await self._btc.claim_status(locator.funding_outpoint.txid, locator.funding_outpoint.vout)
            maker_claimed = status.claimed
            if maker_claimed and status.claim_txid is not None:
                btc_confs = await self._btc.confirmations(status.claim_txid)

        # Asset-lock height from the covenant's confirmation depth: tip - confs + 1.
        # Out-of-range (bogus/lying source) → None so the gate sees "un-assessable" and
        # decide() fails closed, rather than feeding a nonsensical height to the gate.
        asset_locked: int | None = None
        if record.radiant_covenant_outpoint is not None:
            cov_confs = await self._rxd.covenant_confirmations(record.radiant_covenant_outpoint)
            if cov_confs is not None and cov_confs >= 1:
                candidate = tip - cov_confs + 1
                if 0 <= candidate <= tip:
                    asset_locked = candidate

        return Observations(
            maker_has_claimed_btc=maker_claimed,
            now_rxd_height=tip,
            asset_locked_at_height=asset_locked,
            btc_claim_confirmations=btc_confs,
            low_corroboration=not self._rxd_corroborated,
        )

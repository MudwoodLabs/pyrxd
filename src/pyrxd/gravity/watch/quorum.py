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

from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.swap_state import SwapRecord, SwapState
from pyrxd.gravity.watch.decide import Observations
from pyrxd.gravity.watch.reconciler import Observer
from pyrxd.security.errors import ValidationError

__all__ = [
    "BtcClaimSource",
    "BtcClaimStatus",
    "ChainObserver",
    "EthChainSource",
    "EthClaimStatus",
    "RxdChainSource",
]


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

    async def funding_confirmations(self, funding_txid: str) -> int | None:
        """Quorum-agreed confirmation depth of the taker's BTC FUNDING tx — the relative-CSV refund
        maturity input — or ``None`` if unread/unmined. Same conservative-``min`` quorum as
        :meth:`confirmations` (a forged over-report still fails consensus BIP68; an under-report only
        delays the refund)."""
        ...


@dataclass(frozen=True)
class EthClaimStatus:
    """Whether the maker's ETH HTLC has been claimed (revealing ``p``), and the claim tx hash
    (needed for the finalized-checkpoint verdict). ``claimed=False`` means no claim observed yet."""

    claimed: bool
    claim_tx_hash: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.claimed, bool):
            raise ValidationError("EthClaimStatus.claimed must be bool")
        if self.claim_tx_hash is not None and (
            not isinstance(self.claim_tx_hash, str) or not self.claim_tx_hash.startswith("0x")
        ):
            raise ValidationError("EthClaimStatus.claim_tx_hash must be a 0x-prefixed hex hash or None")
        if self.claimed and self.claim_tx_hash is None:
            raise ValidationError("a claimed EthClaimStatus must carry the claim_tx_hash")


@runtime_checkable
class EthChainSource(Protocol):
    """Detects the maker's ETH counter-leg claim and reads its finalized-checkpoint finality verdict.

    Unlike BTC (a PoW confirmation DEPTH), ETH finality is the post-Merge ``finalized`` CHECKPOINT:
    ``claim_finality_verdict`` returns a *depth-less* :class:`CounterClaimFinality`
    (``confirmations``/``required_depth`` both ``None``). The shell satisfies it with the audited
    ``EthHtlcContractLeg.claim_finality_verdict`` (which binds the receipt to the canonical chain and
    rejects a ``finalized > head`` over-report). Single-source RPC in v1 — flagged low-corroboration
    via the RXD flag; a false read causes a false *page*, never a false broadcast (multi-source ETH
    finality quorum is an audit-gated, real-value requirement)."""

    async def claim_status(self, contract_address: str, deploy_tx_hash: str) -> EthClaimStatus:
        """Has the maker claimed this per-swap HTLC instance (revealing ``p``)? If so, by what tx?"""
        ...

    async def claim_finality_verdict(self, claim_tx_hash: str) -> CounterClaimFinality:
        """The point-in-time finalized-checkpoint verdict for the maker's ETH claim tx."""
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
    """Composes the counter-leg source (:class:`BtcClaimSource` and/or :class:`EthChainSource`) with
    a :class:`RxdChainSource` into the :class:`Observations` that :func:`decide` consumes, routing by
    ``record.terms.counter_chain``. The RXD asset-lock derivation is shared across both directions.

    ``rxd_corroborated`` is False in v1 (single RXD source) → every observation is flagged
    ``low_corroboration``. Pass True only once a real ≥2-source RXD quorum exists (a v2 deliverable).
    A swap is observed only if the source for its counter-chain was injected; otherwise ``observe``
    fails closed (the reconciler turns the error into a decision-required page, never a silent miss).
    """

    def __init__(
        self,
        *,
        rxd: RxdChainSource,
        btc: BtcClaimSource | None = None,
        eth: EthChainSource | None = None,
        rxd_corroborated: bool = False,
    ) -> None:
        if not isinstance(rxd_corroborated, bool):
            raise ValidationError("ChainObserver.rxd_corroborated must be bool")
        # LOW-R2: bind corroboration to STRUCTURE, not just a free bool. Asserting
        # rxd_corroborated=True clears low_corroboration on every observation (which lets the
        # autonomous refund act on a single RXD read), so it must be backed by an actual
        # multi-source quorum. Require the rxd source to declare itself corroborated (a genuine
        # >= 2-source quorum, see MultiSourceRxdChainSource.corroborated); a single source cannot
        # assert it however the flag is passed. (accept_single_source remains the explicit,
        # logged dust opt-in on the executor for the deliberate single-source case.)
        if rxd_corroborated and not bool(getattr(rxd, "corroborated", False)):
            raise ValidationError(
                "rxd_corroborated=True requires a multi-source RXD quorum (the source must expose "
                "corroborated=True, e.g. MultiSourceRxdChainSource with quorum>=2); a single source "
                "cannot assert corroboration. Use a real quorum, or leave rxd_corroborated=False."
            )
        if btc is None and eth is None:
            raise ValidationError("ChainObserver requires at least one counter-leg source (btc and/or eth)")
        self._btc = btc
        self._eth = eth
        self._rxd = rxd
        self._rxd_corroborated = rxd_corroborated

    async def observe(self, swap_id: str, record: SwapRecord) -> Observations:
        tip = await self._rxd.tip_height()
        # Asset-lock height from the covenant's confirmation depth: tip - confs + 1. Shared by both
        # directions. Out-of-range (bogus/lying source) → None so the gate sees "un-assessable" and
        # decide() fails closed, rather than feeding a nonsensical height to the gate.
        asset_locked: int | None = None
        if record.radiant_covenant_outpoint is not None:
            cov_confs = await self._rxd.covenant_confirmations(record.radiant_covenant_outpoint)
            if cov_confs is not None and cov_confs >= 1:
                candidate = tip - cov_confs + 1
                if 0 <= candidate <= tip:
                    asset_locked = candidate
        low_corr = not self._rxd_corroborated

        if record.terms.counter_chain == "eth":
            eth_detected, eth_finality = await self._observe_eth_claim(record)
            return Observations(
                maker_has_claimed_btc=False,
                now_rxd_height=tip,
                asset_locked_at_height=asset_locked,
                eth_claim_detected=eth_detected,
                eth_claim_finality=eth_finality,
                low_corroboration=low_corr,
            )

        # BTC counter-leg (default). record.btc_locator is None until the BTC leg is funded.
        if self._btc is None:
            raise ValidationError("ChainObserver has no BtcClaimSource for a BTC swap")
        maker_claimed = False
        btc_confs: int | None = None
        funding_confs: int | None = None
        locator = record.btc_locator
        if locator is not None:
            status = await self._btc.claim_status(locator.funding_outpoint.txid, locator.funding_outpoint.vout)
            maker_claimed = status.claimed
            if maker_claimed and status.claim_txid is not None:
                btc_confs = await self._btc.confirmations(status.claim_txid)
            # BTC-refund maturity: read the FUNDING outpoint depth ONLY when heading toward a BTC refund
            # (avoids a per-tick quorum round-trip for every swap on every tick). decide() gates the
            # autonomous refund on funding >= t_btc; a None here keeps decide() fail-closed.
            if record.state in (SwapState.BTC_LOCKED, SwapState.PARAMS_MISMATCH):
                funding_confs = await self._btc.funding_confirmations(locator.funding_outpoint.txid)
        return Observations(
            maker_has_claimed_btc=maker_claimed,
            now_rxd_height=tip,
            asset_locked_at_height=asset_locked,
            btc_claim_confirmations=btc_confs,
            btc_funding_confirmations=funding_confs,
            low_corroboration=low_corr,
        )

    async def _observe_eth_claim(self, record: SwapRecord) -> tuple[bool, CounterClaimState | None]:
        """Detect the maker's ETH claim + its finalized-checkpoint verdict STATE. Returns
        ``(detected, finality_state)``. ``(False, None)`` when no ETH locator is present yet
        (pre-fund) or the contract is unclaimed; fails closed (raises) if no ETH source was injected
        — the reconciler turns that into a decision-required page rather than a silent all-clear."""
        if self._eth is None:
            raise ValidationError("ChainObserver has no EthChainSource for an ETH swap")
        locator = record.counterchain_locator
        if not isinstance(locator, EthHtlcLocator):
            return False, None  # ETH swap not yet funded → nothing claimed
        status = await self._eth.claim_status(locator.contract_address, locator.deploy_tx_hash)
        if not status.claimed or status.claim_tx_hash is None:
            return False, None
        verdict = await self._eth.claim_finality_verdict(status.claim_tx_hash)
        return True, verdict.state

"""Observation / quorum layer for the watchtower (v1 alert-only, BTC).

Turns chain reads into the :class:`Observations` that :func:`decide` consumes. The
safety-critical input — the maker's BTC-claim *depth* — must be quorum-agreed
(conservative ``min`` across independent sources, fail-closed below quorum); the
shell backs :class:`BtcClaimSource.confirmations` with
``network.bitcoin.MultiSourceBtcFundingReader`` (already built: ``min(depth)``,
2-of-3, fail-closed). The RXD side is now **multi-source** too:
:class:`pyrxd.gravity.watch.adapters.MultiSourceRxdChainSource` composes >= 2 independent
Radiant readers (the operator's node + public ElectrumX), and the daemon shell wires it by
default (``scripts/watchtower_run.py``, 2-of-2 public ElectrumX) — passing
``rxd_corroborated=True`` clears the ``low_corroboration`` flag. A single-source RXD config
is still permitted as a fallback and stays flagged ``low_corroboration`` (a false RXD read
causes a false *page*, never a false broadcast). Corroboration clears the alert-path flag; it
does **not** lift the executor's dust cap or the mainnet ``audit_cleared`` gate.

This module defines the ports and the composing :class:`ChainObserver`; the
concrete transports (mempool.space outspend for claim detection,
``MultiSourceBtcFundingReader`` for depth, ssh-tr / ElectrumX for RXD) are wired by
the daemon shell so the brain stays unit-testable with fakes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState, FinalityStallTracker
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

    # OPTIONAL across-time capability (duck-typed; the observer probes for it via ``hasattr``, like
    # the RXD source's ``corroborated`` attribute): a source MAY expose ``finality_checkpoint()`` ->
    # ``(head_block, finalized_block)`` so the observer can feed a per-swap FinalityStallTracker and
    # upgrade ``NOT_YET_FINAL_LIVE`` -> ``COUNTER_CHAIN_NOT_FINALIZING`` on a sustained PoS stall (the
    # point-in-time verdict alone never can — a single non-advance of ``finalized`` is normal). A
    # source WITHOUT it keeps the point-in-time fast path unchanged; a missing checkpoint never
    # INVENTS a stall. ``RpcEthChainSource`` provides it; it is intentionally NOT a required Protocol
    # method so a minimal point-in-time-only source stays a valid EthChainSource.


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

    ``rxd_corroborated`` clears the per-observation ``low_corroboration`` flag. Pass True only with a
    real ≥2-source RXD quorum (:class:`MultiSourceRxdChainSource`, ``corroborated=True``) — the
    LOW-R2 guard below refuses it over a single source. A single-source RXD config leaves it False and
    every observation flagged ``low_corroboration`` (a false read → a false page, never a broadcast).
    A swap is observed only if the source for its counter-chain was injected; otherwise ``observe``
    fails closed (the reconciler turns the error into a decision-required page, never a silent miss).

    STATEFUL across ticks for ETH only: it holds ONE :class:`FinalityStallTracker` per ``swap_id``
    (A8 / RF-06). The point-in-time ``claim_finality_verdict`` cannot see a *sustained* PoS finality
    stall (``finalized`` frozen while the head climbs) because a single non-advance of ``finalized`` is
    normal epoch lag; the tracker judges it across observations and upgrades a ``NOT_YET_FINAL_LIVE``
    verdict to ``COUNTER_CHAIN_NOT_FINALIZING`` once the stall is sustained (``decide()`` then routes
    that to an earlier SQUEEZE page). Per-swap-id isolation: one swap's stall run never bleeds into
    another's. ALERT-ONLY — the only effect is a sharper/earlier page; no broadcast, no autonomy. The
    upgrade requires the ETH source to expose the optional ``finality_checkpoint()`` capability; a
    source without it keeps the unchanged point-in-time fast path.
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
        # Per-swap-id RF-06 finality-stall trackers (ETH only), created lazily on first observation of
        # each swap. STATEFUL across ticks; isolated per swap_id so one stall run cannot bleed into
        # another. Only consulted when the ETH source exposes finality_checkpoint() (see below).
        self._eth_stall_trackers: dict[str, FinalityStallTracker] = {}

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
            eth_detected, eth_finality = await self._observe_eth_claim(swap_id, record)
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

    async def _observe_eth_claim(self, swap_id: str, record: SwapRecord) -> tuple[bool, CounterClaimState | None]:
        """Detect the maker's ETH claim + its finalized-checkpoint verdict STATE. Returns
        ``(detected, finality_state)``. ``(False, None)`` when no ETH locator is present yet
        (pre-fund) or the contract is unclaimed; fails closed (raises) if no ETH source was injected
        — the reconciler turns that into a decision-required page rather than a silent all-clear.

        A8 / RF-06 across-time stall: the point-in-time ``verdict`` is the fast path and unchanged;
        when the source exposes the optional ``finality_checkpoint()`` capability, the per-``swap_id``
        :class:`FinalityStallTracker` may UPGRADE a ``NOT_YET_FINAL_LIVE`` to
        ``COUNTER_CHAIN_NOT_FINALIZING`` once a sustained stall is judged across ticks (a ``FINAL``
        verdict is never touched; a single non-advance never trips). Alert-only — the only effect is
        that ``decide()`` SQUEEZES earlier; nothing is broadcast."""
        if self._eth is None:
            raise ValidationError("ChainObserver has no EthChainSource for an ETH swap")
        locator = record.counterchain_locator
        if not isinstance(locator, EthHtlcLocator):
            return False, None  # ETH swap not yet funded → nothing claimed
        status = await self._eth.claim_status(locator.contract_address, locator.deploy_tx_hash)
        if not status.claimed or status.claim_tx_hash is None:
            return False, None
        verdict = await self._eth.claim_finality_verdict(status.claim_tx_hash)
        verdict = await self._upgrade_eth_stall(swap_id, verdict)
        return True, verdict.state

    async def _upgrade_eth_stall(self, swap_id: str, verdict: CounterClaimFinality) -> CounterClaimFinality:
        """Feed the per-``swap_id`` :class:`FinalityStallTracker` this tick's ``(head, finalized)`` and
        return the (possibly upgraded) verdict. A ``FINAL`` verdict short-circuits BEFORE any chain
        read — a final claim is final regardless of a counter-chain stall. The upgrade is skipped (the
        point-in-time verdict returned unchanged) when the ETH source does not expose the optional
        ``finality_checkpoint()`` capability, so a minimal source keeps the unchanged fast path and a
        missing checkpoint never INVENTS a stall. The tracker itself only ever upgrades
        ``NOT_YET_FINAL_LIVE`` and resets on a fresh ``finalized`` (live again)."""
        if verdict.state is CounterClaimState.FINAL:
            return verdict
        checkpoint = getattr(self._eth, "finality_checkpoint", None)
        if checkpoint is None:
            return verdict  # point-in-time-only source: no across-time judgment available
        head_block, finalized_block = await checkpoint()
        tracker = self._eth_stall_trackers.get(swap_id)
        if tracker is None:
            tracker = FinalityStallTracker()
            self._eth_stall_trackers[swap_id] = tracker
        return tracker.verdict(verdict, head_block=head_block, finalized_block=finalized_block)

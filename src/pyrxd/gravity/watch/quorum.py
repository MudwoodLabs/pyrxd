"""Observation / quorum layer for the watchtower (v1 alert-only, BTC).

Turns chain reads into the :class:`Observations` that :func:`decide` consumes. The
safety-critical input — the maker's BTC-claim *depth* — must be quorum-agreed
(conservative ``min`` across sources of distinct operators, fail-closed below quorum); the
shell backs :class:`BtcClaimSource.confirmations` with
``network.bitcoin.MultiSourceBtcFundingReader`` (already built: ``min(depth)``,
2-of-3, fail-closed). The RXD side is now **multi-source** too:
:class:`pyrxd.gravity.watch.adapters.MultiSourceRxdChainSource` composes >= 2 distinct-operator
Radiant readers (the operator's node + public ElectrumX), and the daemon shell wires it by
default (``pyrxd.gravity.watch.run``, 2-of-2 public ElectrumX) — passing
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

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pyrxd.btc_wallet.disposition import BtcCounterDisposition, BtcDispositionKind
from pyrxd.btc_wallet.taproot import BtcHtlcLocator
from pyrxd.eth_wallet.disposition import CounterDisposition, DispositionKind
from pyrxd.eth_wallet.locator import EthHtlcLocator
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState, FinalityStallTracker
from pyrxd.gravity.swap_state import SwapRecord, SwapState
from pyrxd.gravity.watch.decide import Observations
from pyrxd.gravity.watch.reconciler import Observer
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.units import ChainHeight, Confirmations, Seconds

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

    ``confirmations`` MUST be quorum-backed (conservative ``min`` across sources on distinct
    hosts) — it is the reorg-safety input to the gate. The shell satisfies it with
    ``MultiSourceBtcFundingReader``.
    """

    async def claim_status(self, funding_txid: str, funding_vout: int) -> BtcClaimStatus:
        """Has the HTLC funding outpoint been spent (the maker's claim)? If so, by what tx?"""
        ...

    async def confirmations(self, claim_txid: str) -> Confirmations:
        """Quorum-agreed confirmation depth of the maker's claim tx."""
        ...

    async def funding_confirmations(self, funding_txid: str) -> Confirmations | None:
        """Quorum-agreed confirmation depth of the taker's BTC FUNDING tx — the relative-CSV refund
        maturity input — or ``None`` if unread/unmined. Same conservative-``min`` quorum as
        :meth:`confirmations` (a forged over-report still fails consensus BIP68; an under-report only
        delays the refund)."""
        ...

    # OPTIONAL capability (duck-typed, probed like the ETH source's ``finality_checkpoint``): a source
    # MAY expose ``spend_disposition(locator, *, hashlock, burial_blocks) -> BtcCounterDisposition``,
    # the shared disposition reader (``pyrxd.btc_wallet.disposition``) over its sources (#850 PR 9b).
    # With it the observer tells our refund from a claim by the leaf each spends; without it every
    # spend is a claim, as before, and autonomy stays off while the covenant is observed.


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

    async def tip_height(self) -> ChainHeight:
        """Current RXD tip height (``getblockcount``) — a HEIGHT, never a depth."""
        ...

    async def covenant_confirmations(self, outpoint: str) -> Confirmations | None:
        """Confirmations of the funded covenant UTXO, or ``None`` if not found/unmined.

        Used to derive ``asset_locked_at_height = tip - confirmations + 1`` (the height
        the covenant was mined), mirroring the dust driver."""
        ...


def _refund_txid(disposition: BtcCounterDisposition) -> str | None:
    """The refund the page names: the buried one when the read is REFUNDED (its evidence), else the
    deepest refund-leaf spend seen, ties by txid. Not the smallest txid: a replaced refund one source
    still serves would be named in place of the bump that was mined (Mythos F5)."""
    refunds = disposition.refunds_seen
    evidence = disposition.evidence
    if (
        disposition.kind is BtcDispositionKind.REFUNDED
        and evidence is not None
        and any(r.txid == evidence.txid for r in refunds)
    ):
        return evidence.txid
    if not refunds:
        return None
    return min(refunds, key=lambda r: (-(r.deepest if r.deepest is not None else -1), r.txid)).txid


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
        clock: Callable[[], float] | None = None,
        btc_burial_blocks: int | None = None,
    ) -> None:
        if not isinstance(rxd_corroborated, bool):
            raise ValidationError("ChainObserver.rxd_corroborated must be bool")
        if clock is not None and not callable(clock):
            raise ValidationError("ChainObserver.clock must be a callable returning unix seconds, or None")
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
        # The depth a BTC spender must be buried before a classified read calls it REFUNDED/CLAIMED
        # (#850 PR 9b). Required whenever the BTC source classifies: a default here would be a
        # second, silent policy for when our refund counts as final.
        classifies = callable(getattr(btc, "spend_disposition", None))
        if btc_burial_blocks is not None and (
            not isinstance(btc_burial_blocks, int) or isinstance(btc_burial_blocks, bool) or btc_burial_blocks < 1
        ):
            raise ValidationError("ChainObserver.btc_burial_blocks must be a positive int or None")
        if classifies and btc_burial_blocks is None:
            raise ValidationError(
                "ChainObserver: the BTC source classifies spenders (spend_disposition), so btc_burial_blocks is "
                "required (the policy's BTC reorg depth)"
            )
        self._btc_burial_blocks = btc_burial_blocks if classifies else None
        self._btc = btc
        self._eth = eth
        self._rxd = rxd
        self._rxd_corroborated = rxd_corroborated
        # Wall clock for the ETH counter leg only, whose refund deadline is the ABSOLUTE
        # eth_timeout_unix_s rather than a confirmation depth. Injectable so a test can drive the
        # deadline without sleeping; the local clock is adequate because it is compared against a
        # deadline measured in HOURS and only ever decides whether to PAGE (never to broadcast).
        self._clock = clock if clock is not None else time.time
        # Per-swap-id RF-06 finality-stall trackers (ETH only), created lazily on first observation of
        # each swap. STATEFUL across ticks; isolated per swap_id so one stall run cannot bleed into
        # another. Only consulted when the ETH source exposes finality_checkpoint() (see below).
        self._eth_stall_trackers: dict[str, FinalityStallTracker] = {}

    async def observe(self, swap_id: str, record: SwapRecord) -> Observations:
        tip = await self._rxd.tip_height()
        # Asset-lock height from the covenant's confirmation depth: tip - confs + 1. Shared by both
        # directions. Out-of-range (bogus/lying source) → None so the gate sees "un-assessable" and
        # decide() fails closed, rather than feeding a nonsensical height to the gate.
        # THE depth->height conversion, and the only one on this path. It is written out rather
        # than implied because the reverse mistake (storing the depth) is the defect this whole
        # unit-tagging exists for: `Confirmations` in, `ChainHeight` out, with the arithmetic
        # that justifies the re-tag visible on one line.
        asset_locked: ChainHeight | None = None
        # Not for a NEGOTIATED record: a taker's fund now writes the pin before its broadcast, so a
        # crash leaves a NEGOTIATED record pinned, and decide() only WATCHes that state. Reading the
        # covenant there turned an RXD source below quorum into a "reconcile error" page every tick
        # for nothing it could use (Mythos review of #891, F3).
        if record.radiant_covenant_outpoint is not None and record.state is not SwapState.NEGOTIATED:
            cov_confs = await self._rxd.covenant_confirmations(record.radiant_covenant_outpoint)
            if cov_confs is not None and cov_confs >= 1:
                candidate = ChainHeight(int(tip) - int(cov_confs) + 1)
                if 0 <= candidate <= tip:
                    asset_locked = candidate
        low_corr = not self._rxd_corroborated

        if record.terms.counter_chain == "eth":
            eth_fields = await self._observe_eth(swap_id, record)
            return Observations(
                maker_has_claimed_btc=False,
                now_rxd_height=tip,
                asset_locked_at_height=asset_locked,
                # The ETH analogue of btc_funding_confirmations: what lets decide()'s
                # maker-never-locks branch prove the taker's counter-leg refund is due. Read only
                # on the ETH path; the BTC arm's deadline is a depth and needs no clock.
                now_unix_s=Seconds(int(self._clock())),
                low_corroboration=low_corr,
                **eth_fields,
            )

        # BTC counter-leg (default). record.btc_locator is None until the BTC leg is funded.
        if self._btc is None:
            raise ValidationError("ChainObserver has no BtcClaimSource for a BTC swap")
        maker_claimed = False
        btc_confs: Confirmations | None = None
        funding_confs: Confirmations | None = None
        spend: dict[str, Any] = {}
        locator = record.btc_locator
        if locator is not None:
            status = await self._btc.claim_status(locator.funding_outpoint.txid, locator.funding_outpoint.vout)
            maker_claimed = status.claimed
            claim_txid = status.claim_txid
            if self._btc_burial_blocks is not None:
                maker_claimed, claim_txid, spend = await self._classify_btc_spend(record, locator, status)
            # Not when our refund is buried: a claim seen beside it lost and is never mined, so its depth
            # read only fails (an honest source has no such tx) and turned a D14 page into a "reconcile
            # error" (review of PR 9b, M1). decide() pages the covenant claim from the read instead.
            if (
                maker_claimed
                and claim_txid is not None
                and not (
                    spend.get("btc_disposition") is BtcDispositionKind.REFUNDED and not spend.get("btc_single_source")
                )
            ):
                btc_confs = await self._btc.confirmations(claim_txid)
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
            **spend,
        )

    async def _classify_btc_spend(
        self, record: SwapRecord, locator: BtcHtlcLocator, status: BtcClaimStatus
    ) -> tuple[bool, str | None, dict[str, Any]]:
        """``(maker_claimed, claim_txid, Observations fields)`` from the shared disposition read (#850
        PR 9b, design §6).

        A spend leaves the claim trigger only on proof: the discovery read (``claim_status``, any
        source naming a spender) stays the trigger, and a spender it names is taken out of it only
        when the disposition read classifies that txid as a refund-leaf spend (whose signature
        verifies: ``_check_served``). Any claim the disposition read saw (verified or not, buried or
        not, on every kind of answer) is a claim even when discovery missed it; any other spend the
        read cannot account for stays one too, so a source that serves no bytes cannot turn a claim
        into silence."""
        disposition = await self._btc.spend_disposition(  # type: ignore[union-attr]  # probed in __init__
            locator, hashlock=record.terms.hashlock, burial_blocks=self._btc_burial_blocks
        )
        claims = disposition.claims_seen
        refunds = {s.txid for s in disposition.refunds_seen}
        if claims:
            verified = [c for c in claims if c.verified]
            claimed, claim_txid = True, (verified or list(claims))[0].txid
        elif status.claimed and status.claim_txid not in refunds:
            claimed, claim_txid = True, status.claim_txid  # a spend the read could not prove is ours
        else:
            claimed, claim_txid = False, None
        fields = {
            "btc_spend_classified": True,
            "btc_disposition": disposition.kind,
            "btc_refund_txid": _refund_txid(disposition),
            "btc_disposition_reason": disposition.reason,
            "btc_spenders_named": bool(disposition.spenders),
            "btc_claim_witness_seen": bool(claims),
            "btc_single_source": disposition.single_source,
        }
        return claimed, claim_txid, fields

    async def _observe_eth(self, swap_id: str, record: SwapRecord) -> dict[str, Any]:
        """The ETH ``Observations`` fields: the maker's claim and its finalized-checkpoint verdict STATE
        (``eth_claim_detected``, ``eth_claim_finality``), and, when the source reads one, the contract's
        disposition from the shared reader (#850 PR 10, design §5.1). Empty when no ETH locator is
        present yet (pre-fund); fails closed (raises) if no ETH source was injected — the reconciler
        turns that into a decision-required page rather than a silent all-clear.

        The detection scan (``claim_status``, selector-agnostic, over every endpoint) stays the claim
        trigger. The disposition read adds to it, never takes from it: a ``Claimed`` log that opens H
        that the read collected, or a CLAIMED answer, is a claim even when the scan missed it. A claim
        the record kept (``counter_claim_tx``) is a claim on every tick, read or no read: the reader
        can return UNKNOWN before it collects any claim when one endpoint disagrees on an identity read,
        and that must not clear it. The verdict is read for the claim the reader verified first, else
        the scan's, else the first one the read collected, else the one on record. A CLAIMED answer from more than one endpoint is FINAL as it stands: it was verified at
        the agreed finalized block. Gap B (CLAIMED with no transaction) has no other verdict to read.

        A8 / RF-06 across-time stall: the point-in-time verdict is the fast path and unchanged; when the
        source exposes the optional ``finality_checkpoint()`` capability, the per-``swap_id``
        :class:`FinalityStallTracker` may UPGRADE a ``NOT_YET_FINAL_LIVE`` to
        ``COUNTER_CHAIN_NOT_FINALIZING`` once a sustained stall is judged across ticks (a ``FINAL``
        verdict is never touched; a single non-advance never trips). Alert-only — the only effect is
        that ``decide()`` SQUEEZES earlier; nothing is broadcast."""
        if self._eth is None:
            raise ValidationError("ChainObserver has no EthChainSource for an ETH swap")
        locator = record.counterchain_locator
        if not isinstance(locator, EthHtlcLocator):
            return {}  # ETH swap not yet funded → nothing claimed
        status = await self._eth.claim_status(locator.contract_address, locator.deploy_tx_hash)
        scanned = status.claim_tx_hash if status.claimed else None
        fields: dict[str, Any] = {}
        claim_tx = scanned
        read = getattr(self._eth, "counter_disposition", None)
        if callable(read):
            # The coordinator's own arguments for this record (one builder), so both read one thing.
            from pyrxd.gravity.eth_counter_disposition import eth_counter_disposition_kwargs

            disposition: CounterDisposition = await read(locator, **eth_counter_disposition_kwargs(record))
            claims = disposition.claims_seen
            evidence = disposition.evidence
            fields = {
                "eth_disposition": disposition.kind,
                "eth_disposition_reason": disposition.reason,
                "eth_disposition_tx": evidence.tx_hash if evidence is not None else None,
                "eth_claim_seen": bool(claims),
                "eth_single_source": disposition.single_source,
                "eth_settled_at_finalized": disposition.kind is DispositionKind.UNKNOWN
                and disposition.settled_at_finalized,
                "eth_nonce_at_finalized": disposition.nonce_at_finalized,
            }
            claimed = disposition.kind is DispositionKind.CLAIMED
            verified = [c.tx_hash for c in claims if c.verified]
            if claimed and evidence is not None and evidence.tx_hash is not None:
                verified.insert(0, evidence.tx_hash)
            if verified:
                claim_tx = verified[0]
            elif scanned is None and claims:
                claim_tx = claims[0].tx_hash
            if claimed and not disposition.single_source:
                return {"eth_claim_detected": True, "eth_claim_finality": CounterClaimState.FINAL, **fields}
            if claimed and claim_tx is None:
                # Gap B from one endpoint: no transaction to read a verdict for, and one endpoint's
                # CLAIMED is not final on its own. The gate then fails closed (finality un-assessable).
                return {"eth_claim_detected": True, "eth_claim_finality": None, **fields}
        # A claim the record kept stays a claim when this tick names none: a read that failed before
        # it looked at any claim (one endpoint's disagreement) clears nothing (review F1).
        claim_tx = claim_tx or record.counter_claim_tx
        if claim_tx is None:
            return {"eth_claim_detected": False, "eth_claim_finality": None, **fields}
        try:
            verdict = await self._eth.claim_finality_verdict(claim_tx)
        except NetworkError:
            # Endpoints that disagree on the claim's block (one forked or lying) leave its finality
            # un-assessable. The claim is still detected, so decide() pages the claim race fail-closed
            # rather than a generic reconcile error that names no claim (review F1).
            return {"eth_claim_detected": True, "eth_claim_finality": None, **fields}
        verdict = await self._upgrade_eth_stall(swap_id, verdict)
        return {"eth_claim_detected": True, "eth_claim_finality": verdict.state, **fields}

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

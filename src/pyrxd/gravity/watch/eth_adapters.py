"""Production ETH counter-leg transport for the watchtower — keyless, read-only (alert-only v3).

:class:`RpcEthChainSource` satisfies the :class:`~pyrxd.gravity.watch.quorum.EthChainSource`
port against a live Ethereum RPC, built on the **keyless** :class:`~pyrxd.eth_wallet.rpc.EthRpc`
(which holds no signing key). It is the ETH analogue of ``OutspendBtcClaimSource`` and keeps the
same alert-only invariant the rest of the tower does: it broadcasts nothing, holds no key, and
**never reads the preimage ``p``** — the operator scrapes ``p`` from the maker's claim after a page.

Two reads back the port:

* ``claim_status`` — detects the maker's claim from the on-chain event log on the per-swap-unique
  HTLC contract. Because each swap deploys a FRESH contract at a unique address, ANY log from that
  address is swap activity (``p`` sits in a ``Claimed`` event's data — the tower never touches it).
  Detection is SELECTOR-AGNOSTIC and FAILS TOWARD PAGING, mirroring the audited path
  (``assert_claim_provenance`` scans every log from the contract, not one pinned selector): a
  ``Claimed(bytes32)`` log is the canonical claim; a contract emitting ONLY ``Refunded()`` is not a
  claim (the maker never revealed ``p``); any OTHER/unrecognised log on our per-swap contract is
  treated as a claim so a differently-shaped event can never SILENTLY MISS one — over-paging on an
  odd event is a false alarm (LOW for an alert-only tower), a missed claim is the forbidden failure.
  The scan is bounded to the contract's lifetime (deploy block → chain head) and reads to ``latest``
  so a just-mined claim is not missed; reorg-safety lives in the finality verdict, not detection.
  KNOWN LIMITATION: a non-canonical contract that emits NO event at all on ``claim()`` cannot be
  detected from logs (the canonical ``EthHtlc.sol`` DOES emit ``Claimed(bytes32)`` — deploy a
  Claimed-emitting model). DETECTION is also single-source in v1, exactly like the verdict below —
  a lagging/withholding sole RPC can DELAY a page (the per-tick re-scan recovers it); a multi-source
  ETH detection+finality quorum is an audit-gated v2 requirement.

* ``claim_finality_verdict`` — the post-Merge ``finalized``-checkpoint verdict. Its VERDICT LOGIC
  (status → canonical-chain binding (fail-closed) → ``finalized`` checkpoint) is **identical** to the
  audited ``EthHtlcContractLeg.claim_finality_verdict`` (``eth_wallet/htlc_leg.py``), reproduced here
  ONLY so the alert-only tower needs no key (that leg's constructor mandates ``PrivateKeyMaterial``).
  A differential parity test (``test_watch_eth_adapter.py::test_finality_verdict_parity_with_audited_leg``)
  pins the two to agree on the verdict for any given receipt, so the LOGIC cannot silently drift. The
  one deliberate difference is the receipt FETCH: the tower polls on its own interval, so it uses a
  NON-BLOCKING ``get_transaction_receipt`` (a reorg-orphaned/not-yet-mined claim → ``NOT_YET_FINAL_LIVE``
  → re-detect next tick) instead of the leg's blocking ``wait_receipt`` — a single read must never
  sleep a whole reconcile tick. Single-source RPC in v1: a false read causes a false PAGE, never a
  false broadcast (a multi-source ETH finality quorum is the audit-gated v2 requirement). A
  multi-chain records dir watched by a single ``--eth-rpc-url`` fails CLOSED, not open: the deploy tx
  is not found on the wrong chain → ``NetworkError`` → the reconciler pages a decision-required.
"""

from __future__ import annotations

from typing import Any

from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.watch.quorum import EthClaimStatus
from pyrxd.security.errors import NetworkError

__all__ = ["CLAIMED_TOPIC0", "REFUNDED_TOPIC0", "RpcEthChainSource"]

# Pinned EthHtlc.sol event selectors (verified against web3 keccak by test_event_selectors_match_keccak):
#   keccak256("Claimed(bytes32)")  — the canonical claim event; p is in the (non-indexed) log data.
#   keccak256("Refunded()")        — the refund event; emitted when the maker did NOT reveal p.
# Detection is selector-AGNOSTIC (see the module docstring) — these only refine which logs are a claim
# vs a refund so a refund does not over-page, while an unrecognised event still fails toward paging.
CLAIMED_TOPIC0 = "0xeddf608ef698454af2fb41c1df7b7e5154ff0d46969f895e0f39c7dfe7e6380a"
REFUNDED_TOPIC0 = "0x8616bbbbad963e4e65b1366f1d75dfb63f9e9704bbbf91fb01bec70849906cf7"


def _to_0x_hash(value: object) -> str:
    """Normalise a web3 tx-hash to a 0x-prefixed hex string (what :class:`EthClaimStatus` requires).
    web3 returns hashes as ``HexBytes`` (a ``bytes`` subclass) or, for raw-JSON RPCs, as a ``str``;
    both are handled. Any other type raises here rather than being coerced into a non-0x string that
    would only fail far downstream."""
    if isinstance(value, str):
        return value if value.startswith("0x") else "0x" + value
    if isinstance(value, (bytes, bytearray)):  # web3 HexBytes is a bytes subclass
        return "0x" + bytes(value).hex()
    raise NetworkError(f"cannot normalise tx-hash of type {type(value).__name__!r} to a 0x-hex string")


def _topic0(log: dict[str, Any]) -> str | None:
    """The 0x-hex of a log's first topic (event selector), or ``None`` if it has no topics."""
    topics = log.get("topics") or []
    if not topics:
        return None
    return _to_0x_hash(topics[0]).lower()


class RpcEthChainSource:
    """``EthChainSource`` over a keyless :class:`EthRpc` (read-only, no key, never touches ``p``)."""

    def __init__(self, rpc: EthRpc) -> None:
        self._rpc = rpc

    async def claim_status(self, contract_address: str, deploy_tx_hash: str) -> EthClaimStatus:
        # Bound the log scan to the contract's lifetime. A pending/unmined deploy (no blockNumber)
        # means the HTLC contract is not on-chain yet, so nothing can have claimed it → unclaimed.
        # On the WRONG chain the deploy tx is not found → get_transaction raises → fail-closed page.
        deploy = await self._rpc.get_transaction(deploy_tx_hash)
        deploy_block = deploy.get("blockNumber")
        if deploy_block is None:
            return EthClaimStatus(claimed=False)
        # Selector-AGNOSTIC scan of every log from this per-swap-unique contract (NO topic filter),
        # bounded [deploy_block, latest]. A claim can only occur at/after the contract exists, so
        # from_block can never exclude the claim; reading to latest catches a just-mined claim.
        logs = await self._rpc.get_logs(address=contract_address, from_block=int(deploy_block), to_block="latest")
        if not logs:
            return EthClaimStatus(claimed=False)
        claimed_logs = [lg for lg in logs if _topic0(lg) == CLAIMED_TOPIC0]
        if claimed_logs:
            chosen = claimed_logs[-1]  # canonical Claimed(bytes32) — the precise claim tx
        elif all(_topic0(lg) == REFUNDED_TOPIC0 for lg in logs):
            return EthClaimStatus(claimed=False)  # only Refunded() — the maker did NOT reveal p
        else:
            # An unrecognised event from OUR per-swap contract. Fail TOWARD paging: a differently
            # shaped claim event must never be silently missed (over-paging is a false alarm only).
            chosen = logs[-1]
        tx_hash = chosen.get("transactionHash")
        if tx_hash is None:
            raise NetworkError("a log from the HTLC contract is missing transactionHash; cannot identify the claim")
        return EthClaimStatus(claimed=True, claim_tx_hash=_to_0x_hash(tx_hash))

    async def finality_checkpoint(self) -> tuple[int, int]:
        """The current ``(head_block, finalized_block)`` checkpoint — the across-time stall input.

        The point-in-time :meth:`claim_finality_verdict` only sees one ``finalized`` reading; a
        genuine PoS finality STALL (``finalized`` frozen while the head climbs) can only be judged
        across ticks. The watchtower observer feeds this pair to a per-swap
        :class:`~pyrxd.gravity.finality.FinalityStallTracker` so a sustained stall upgrades
        ``NOT_YET_FINAL_LIVE`` → ``COUNTER_CHAIN_NOT_FINALIZING`` (the gate then SQUEEZES). This is an
        OPTIONAL capability (duck-typed; the observer probes for it) so a minimal source without it
        keeps the point-in-time fast path unchanged — a missing checkpoint never INVENTS a stall.

        ``finalized_block_number`` already rejects an incoherent ``finalized > head`` over-report
        (fail-closed) and returns the same head it bounded against, so ``finalized <= head`` holds for
        the tracker by construction."""
        finalized = await self._rpc.finalized_block_number()  # rejects finalized > head (fail-closed)
        head = await self._rpc.block_number()
        # Defend the tracker's finalized <= head precondition against a head that regressed between the
        # two reads (a reorg/lagging-replica race): clamp head up to finalized rather than feed an
        # incoherent pair. A frozen finalized with head==finalized is simply "no stall" (gap 0).
        return max(head, finalized), finalized

    async def claim_finality_verdict(self, claim_tx_hash: str) -> CounterClaimFinality:
        # VERDICT LOGIC identical to EthHtlcContractLeg.claim_finality_verdict (htlc_leg.py:438-460),
        # pinned by test_finality_verdict_parity_with_audited_leg. The ONE deliberate difference: a
        # NON-BLOCKING receipt read (the tower polls; it must never sleep a whole tick) — a not-yet-
        # mined / reorg-orphaned claim → NOT_YET_FINAL_LIVE (re-detect next tick), not a 300s block.
        receipt = await self._rpc.get_transaction_receipt(claim_tx_hash)
        if receipt is None:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        if int(receipt.get("status", 0)) != 1:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        tx_block = int(receipt["blockNumber"])
        # Bind the receipt to the canonical chain, FAIL-CLOSED: a lying receipt blockNumber is caught
        # when its blockHash != the canonical hash at that height; a MISSING receipt blockHash or an
        # EMPTY canonical hash means "cannot prove canonicality" → NOT_YET_FINAL_LIVE, never FINAL.
        receipt_hash = receipt.get("blockHash")
        if receipt_hash is None:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        canonical = await self._rpc.canonical_block_hash(tx_block)
        if not canonical or bytes(receipt_hash) != canonical:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        finalized = await self._rpc.finalized_block_number()  # rejects finalized > head (fail-closed)
        if tx_block <= finalized:
            return CounterClaimFinality(state=CounterClaimState.FINAL)
        return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)

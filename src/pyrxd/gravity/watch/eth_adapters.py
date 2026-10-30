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
  Claimed-emitting model). With one ``--eth-rpc-url`` DETECTION is single-source, like the verdict
  below: a lagging/withholding sole RPC can DELAY a page (the per-tick re-scan recovers it). With
  several, every endpoint is scanned and a claim any one serves is a claim (#850 PR 10).

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

import hashlib
import logging
from typing import Any

from pyrxd.eth_wallet.disposition import CounterDisposition, created_contract, read_counter_disposition
from pyrxd.eth_wallet.events import CLAIMED_TOPIC0, REFUNDED_TOPIC0
from pyrxd.eth_wallet.locator import Erc20HtlcLocator, EthHtlcLocator
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc, quorum_combiner
from pyrxd.eth_wallet.rpc import EthRpc
from pyrxd.gravity.finality import CounterClaimFinality, CounterClaimState
from pyrxd.gravity.watch.quorum import EthClaimStatus
from pyrxd.security.errors import NetworkError

__all__ = ["CLAIMED_TOPIC0", "REFUNDED_TOPIC0", "RpcEthChainSource"]

logger = logging.getLogger(__name__)

# EthHtlc.sol / Erc20Htlc.sol event topic0s, DERIVED in pyrxd.eth_wallet.events as keccak256 of the
# signature (one source, shared with scripts/swap_run_verify.py) and re-exported here:
#   CLAIMED_TOPIC0  = keccak256("Claimed(bytes32)")  — the claim event; p is in the (non-indexed) log data.
#   REFUNDED_TOPIC0 = keccak256("Refunded()")        — the refund event; emitted when the maker did NOT reveal p.
# Detection is selector-AGNOSTIC (see the module docstring) — these only refine which logs are a claim
# vs a refund so a refund does not over-page, while an unrecognised event still fails toward paging.


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


class DeployNotCreationError(NetworkError):
    """An endpoint says the record's deploy transaction did not create the HTLC contract. Unlike an
    endpoint's ordinary failure, this is raised whichever endpoint says it: the scan's start is then
    in doubt, and a lying primary must not be able to pass the check while it drops the others."""


async def _scan_for_claim(rpc: EthRpc, contract_address: str, deploy_tx_hash: str) -> tuple[EthClaimStatus, bool]:
    """One endpoint's selector-agnostic scan: ``(status, canonical)``, ``canonical`` True when the claim
    is a ``Claimed(bytes32)`` log rather than an unrecognised one."""
    # Bound the log scan to the contract's lifetime. A pending/unmined deploy (no blockNumber)
    # means the HTLC contract is not on-chain yet, so nothing can have claimed it → unclaimed.
    # On the WRONG chain the deploy tx is not found → get_transaction raises → fail-closed page.
    deploy = await rpc.get_transaction(deploy_tx_hash)
    # The scan starts at this transaction's block, so a later transaction named as the deploy would
    # start it past a claim. It must be the one that created the contract, derived from its sender
    # and nonce, never read from a receipt's contractAddress.
    if not created_contract(deploy, contract_address):
        raise DeployNotCreationError(
            "the recorded deploy transaction did not create the HTLC contract; cannot bound the claim scan"
        )
    deploy_block = deploy.get("blockNumber")
    if deploy_block is None:
        return EthClaimStatus(claimed=False), False
    # Selector-AGNOSTIC scan of every log from this per-swap-unique contract (NO topic filter),
    # bounded [deploy_block, latest]. A claim can only occur at/after the contract exists, so
    # from_block can never exclude the claim; reading to latest catches a just-mined claim.
    logs = await rpc.get_logs(address=contract_address, from_block=int(deploy_block), to_block="latest")
    if not logs:
        return EthClaimStatus(claimed=False), False
    claimed_logs = [lg for lg in logs if _topic0(lg) == CLAIMED_TOPIC0]
    if claimed_logs:
        chosen = claimed_logs[-1]  # canonical Claimed(bytes32) — the precise claim tx
    elif all(_topic0(lg) == REFUNDED_TOPIC0 for lg in logs):
        return EthClaimStatus(claimed=False), False  # only Refunded() — the maker did NOT reveal p
    else:
        # An unrecognised event from OUR per-swap contract. Fail TOWARD paging: a differently
        # shaped claim event must never be silently missed (over-paging is a false alarm only).
        chosen = logs[-1]
    tx_hash = chosen.get("transactionHash")
    if tx_hash is None:
        raise NetworkError("a log from the HTLC contract is missing transactionHash; cannot identify the claim")
    return EthClaimStatus(claimed=True, claim_tx_hash=_to_0x_hash(tx_hash)), bool(claimed_logs)


async def _tower_finalized_block(rpc: EthRpc | MultiSourceEthRpc) -> int:
    """The ``finalized`` block the tower judges a claim's finality and a stall by: the value a quorum of
    endpoints stand at or above (:func:`~pyrxd.eth_wallet.multi_rpc.quorum_combiner`), each endpoint's
    own answer already bounded by its head.

    Deliberately not ``MultiSourceEthRpc.finalized_block_number``, the MIN the coordinator's reader and
    gate use (erring low there only delays a value-moving step). For an alert-only tower the MIN let one
    lagging endpoint, at any index, hold a final claim at "not yet final", so the tower WATCHed where it
    should page the claim race, and reset the stall tracker whenever its own value moved (0.27 release
    review, A-2; the BTC twin was register R13, fixed with the quorum-vouched depth). With more
    endpoints than the quorum (three at the default 2-of-3), one endpoint can no longer move this value
    either way. When the quorum is every endpoint (two endpoints at the default), the quorum-th value
    is the MIN and one lagging endpoint still holds it, as before; so does a quorum that lags. A single
    endpoint is read as it is."""
    return await _tower_quorum_block(rpc, "finalized_block_number")


async def _tower_quorum_block(rpc: EthRpc | MultiSourceEthRpc, method: str) -> int:
    """``finalized_block_number`` or ``block_number`` as a quorum of endpoints stand at or above it."""
    if not isinstance(rpc, MultiSourceEthRpc):
        return int(await getattr(rpc, method)())
    return int(await rpc.eth_call_quorum(lambda s: getattr(s, method)(), label=method, combine=quorum_combiner(rpc)))


class RpcEthChainSource:
    """``EthChainSource`` over a keyless :class:`EthRpc`, or a :class:`MultiSourceEthRpc` of several
    (read-only, no key, never touches ``p``)."""

    def __init__(self, rpc: EthRpc | MultiSourceEthRpc) -> None:
        self._rpc = rpc

    async def counter_disposition(
        self,
        locator: EthHtlcLocator,
        *,
        recorded_refund_hashes: tuple[str, ...] = (),
        expiry_anchor: tuple[int, str] | None = None,
        recorded_claim_hashes: tuple[str, ...] = (),
        push_nonce_bound: int | None = None,
        push_signer: str | None = None,
        nonce_less: bool = False,
    ) -> CounterDisposition:
        """What the chain says about this swap's HTLC: the coordinator's reader and arguments
        (``EthCounterLeg.counter_disposition``, built by
        :func:`pyrxd.gravity.eth_counter_disposition.eth_counter_disposition_kwargs`), read-only. Never raises
        for a chain read (an unreadable chain is ``UNKNOWN``).

        One deliberate difference: this source holds no key, so a token record that does not name its
        push key (``push_signer``, written before 0.27) is read without a nonce, and its empty contract
        can read ``EXPIRED_EMPTY_OPEN`` but never ``EXPIRED_EMPTY_CLOSED``. The coordinator would read
        its own key's nonce when that key deployed the contract."""
        token = locator.token_address if isinstance(locator, Erc20HtlcLocator) else None
        return await read_counter_disposition(
            self._rpc,
            locator,
            recorded_refund_hashes=recorded_refund_hashes,
            expiry_anchor=expiry_anchor,
            recorded_claim_hashes=recorded_claim_hashes,
            token_address=token,
            funding_account=push_signer if token is not None else None,
            push_nonce_bound=push_nonce_bound if token is not None else None,
            nonce_less=nonce_less if token is not None else False,
        )

    async def claim_status(self, contract_address: str, deploy_tx_hash: str) -> EthClaimStatus:
        """The detection scan, over EVERY endpoint when the source holds several (#850 PR 10, review F1).

        ``MultiSourceEthRpc.get_logs`` reads the primary alone, so a primary that hides the claim's log
        would hide it from the tower however many endpoints were configured. Each endpoint is scanned
        on its own instead, and a claim any one of them serves is the answer: a ``Claimed`` log first,
        else an unrecognised log (fail toward paging).

        A claim another endpoint serves wins over every endpoint's failure, the primary's included. The
        primary's failure used to raise before the others were scanned, so a primary that failed every
        tick (one rate-limited public RPC) turned the swap's every page into one ``reconcile_error``,
        and once the operator ACKed it a final claim the others served paged nothing (0.27 release
        review, A-1; the primary's :class:`DeployNotCreationError` was register R17's case of it). With
        no claim served, the primary's failure still raises, and so does any endpoint's
        :class:`DeployNotCreationError`; another endpoint's ordinary failure only drops it."""
        endpoints = self._rpc.sources if isinstance(self._rpc, MultiSourceEthRpc) else [self._rpc]
        results: list[tuple[EthClaimStatus, bool]] = []
        not_creation: DeployNotCreationError | None = None
        primary_failure: Exception | None = None
        for index, endpoint in enumerate(endpoints):
            try:
                results.append(await _scan_for_claim(endpoint, contract_address, deploy_tx_hash))
            except DeployNotCreationError as exc:
                not_creation = not_creation or exc  # any endpoint's: kept, never dropped like a failure
            except Exception as exc:
                if index == 0:
                    primary_failure = exc  # the primary was required before the union, and still is
                    continue  # unless another endpoint serves a claim
                logger.warning(
                    "ETH claim scan: endpoint %d of %d failed; scanned without it", index + 1, len(endpoints)
                )
        for wanted_canonical in (True, False):
            for status, canonical in results:
                if status.claimed and canonical is wanted_canonical:
                    if primary_failure is not None or not_creation is not None:
                        logger.warning(
                            "ETH claim scan: a claim served beside a failed or refused read (%s); paging the claim",
                            type(not_creation or primary_failure).__name__,
                        )
                    return status
        if not_creation is not None:
            raise not_creation
        if primary_failure is not None:
            raise primary_failure
        return EthClaimStatus(claimed=False)

    async def claim_receipt_opens_h(self, locator: EthHtlcLocator, claim_tx_hash: str) -> bool | None:
        """Whether *claim_tx_hash* is a claim of this contract, read on EVERY endpoint (#850 PR 10, the
        re-review of Mythos F1): ``True`` when every endpoint returns the same receipt (status, block
        and logs, normalised) and it is a success carrying OUR contract's ``Claimed`` event whose data
        opens H; ``False`` when they agree on a receipt that does not; ``None`` when every endpoint
        agrees there is no receipt. Raises :class:`NetworkError` when one fails, answers with a malformed
        receipt, or they disagree.

        A finality verdict says only where a transaction is, not what it did, and
        ``MultiSourceEthRpc.get_transaction_receipt`` leaves the logs out of its agreement, so the
        claim itself is checked here before a candidate's verdict may count."""
        from pyrxd.eth_wallet.htlc_leg import _addr, _b, _receipt_facts

        endpoints = self._rpc.sources if isinstance(self._rpc, MultiSourceEthRpc) else [self._rpc]
        facts = []
        for index, endpoint in enumerate(endpoints):
            try:
                facts.append(_receipt_facts(await endpoint.get_transaction_receipt(claim_tx_hash)))
            except NetworkError:
                raise
            except Exception as exc:
                # One endpoint's malformed answer is that endpoint's failure, typed: an untyped error
                # escaped observe() and replaced the claim race with a generic reconcile-error page
                # (sandbox review N-D). The disposition reader's ``_identity`` treats it the same way.
                raise NetworkError(
                    f"receipt({claim_tx_hash}): endpoint {index + 1} of {len(endpoints)} gave an unreadable "
                    f"answer ({type(exc).__name__})"
                ) from exc
        if any(f != facts[0] for f in facts[1:]):
            raise NetworkError(f"receipt({claim_tx_hash}): endpoints disagree")
        agreed = facts[0]
        if agreed is None:
            return None
        status, _block_hash, _block_number, logs = agreed
        if status != 1:
            return False
        contract, topic0, hashlock = _addr(locator.contract_address), _b(CLAIMED_TOPIC0), locator.hashlock_bytes
        return any(
            address == contract
            and topics
            and topics[0] == topic0
            and len(data) == 32
            and hashlib.sha256(data).digest() == hashlock
            for address, topics, data in logs
        )

    async def finality_checkpoint(self) -> tuple[int, int]:
        """The current ``(head_block, finalized_block)`` checkpoint — the across-time stall input.

        The point-in-time :meth:`claim_finality_verdict` only sees one ``finalized`` reading; a
        genuine PoS finality STALL (``finalized`` frozen while the head climbs) can only be judged
        across ticks. The watchtower observer feeds this pair to a per-swap
        :class:`~pyrxd.gravity.finality.FinalityStallTracker` so a sustained stall upgrades
        ``NOT_YET_FINAL_LIVE`` → ``COUNTER_CHAIN_NOT_FINALIZING`` (the gate then SQUEEZES). This is an
        OPTIONAL capability (duck-typed; the observer probes for it) so a minimal source without it
        keeps the point-in-time fast path unchanged — a missing checkpoint never INVENTS a stall.

        The ``finalized`` and head reads are quorum-th values (:func:`_tower_finalized_block`), so with
        more endpoints than the quorum one endpoint can neither reset the tracker by moving its
        ``finalized`` nor hold it off with a frozen head. Each endpoint's ``finalized_block_number`` rejects
        an incoherent ``finalized > head`` over-report (fail-closed); the head is clamped below."""
        finalized = await _tower_finalized_block(self._rpc)  # each endpoint rejects finalized > head
        # The head by quorum too: with the MIN, one endpoint answering a frozen head kept the head's
        # progress at 0, so the tracker never declared a stall (re-review of the A-2 fix).
        head = await _tower_quorum_block(self._rpc, "block_number")
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
        try:
            status = int(receipt.get("status", 0))
            tx_block = int(receipt["blockNumber"]) if status == 1 else 0
        except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as exc:
            # A malformed receipt (one endpoint's, with a single --eth-rpc-url) is a typed read
            # failure, never an untyped error out of observe() (sandbox review N-D).
            raise NetworkError(f"receipt({claim_tx_hash}) is malformed ({type(exc).__name__})") from exc
        if status != 1:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        # Bind the receipt to the canonical chain, FAIL-CLOSED: a lying receipt blockNumber is caught
        # when its blockHash != the canonical hash at that height; a MISSING receipt blockHash or an
        # EMPTY canonical hash means "cannot prove canonicality" → NOT_YET_FINAL_LIVE, never FINAL.
        receipt_hash = receipt.get("blockHash")
        if receipt_hash is None:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        if not isinstance(receipt_hash, (bytes, bytearray)):
            # web3 returns HexBytes (a bytes subclass); anything else is one endpoint's malformed answer,
            # and bytes(int) would raise OverflowError or allocate that many zero bytes.
            raise NetworkError(f"receipt({claim_tx_hash}) has a malformed blockHash ({type(receipt_hash).__name__})")
        receipt_hash_bytes = bytes(receipt_hash)
        canonical = await self._rpc.canonical_block_hash(tx_block)
        if not canonical or receipt_hash_bytes != canonical:
            return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)
        finalized = await _tower_finalized_block(self._rpc)  # each endpoint rejects finalized > head
        if tx_block <= finalized:
            return CounterClaimFinality(state=CounterClaimState.FINAL)
        return CounterClaimFinality(state=CounterClaimState.NOT_YET_FINAL_LIVE)

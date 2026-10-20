"""Read-only disposition of an ETH counter-leg HTLC, from chain observation (#850 PR 4).

What this answers: has this swap's counter-leg contract been REFUNDED, CLAIMED, or neither yet, and
on what evidence. The coordinator used to decide that from what it had BROADCAST; this reads it from
the chain instead (design ``docs/plans/2026-10-09-counter-leg-disposition-from-chain-design.md`` §2).
Nothing here sends anything, and in this PR nothing calls it yet: PR 5a wires it into the
coordinator, PR 10 into the watchtower.

Three kinds of read, each allowed to decide only what it can prove (§2.1):

* **Nominate**: the union of ``eth_getLogs`` across every endpoint (:func:`union_logs`), or a hash we
  recorded ourselves. A nomination only names a transaction to verify. A missing log decides nothing.
* **Verify**: the transaction's receipt, agreed across endpoints with its logs normalised, has
  ``status == 1``, sits at a block ``<= F``, its block hash is the canonical hash at that height (also
  agreed), and it carries ``Refunded()`` (or ``Claimed(p)`` with ``sha256(p) == H``) from OUR contract.
* **Invariant at F**: ``settled`` (storage slot 0) and the block timestamp, read at the one pinned
  block ``F`` (the quorum MIN of ``finalized``), whose hash every endpoint agrees on.

Precedence when evidence contradicts (§2.4): invariants at ``F`` outrank receipts, and receipts
outrank nominations. A verified refund and a verified claim together, a verified refund beside "Gap B"
(settled at ``F`` while ``timestamp(F) < timeout``), or a verified receipt beside ``settled_F == 0``
are all :attr:`DispositionKind.UNKNOWN`. So is any failed or below-quorum read among the inputs to a
terminal answer: an unreadable input never becomes a terminal one.

Single source: with one endpoint every answer is recorded ``single_source=True``. Whether that may
change a record's state is the CONSUMER's rule (§2.5: never on a value-bearing chain), not this
module's; this module only reports it.

Not in this PR (each lands with the PR that produces its input, design §8): ``REFUND_PENDING`` and
``PAYOUT_REVERTS`` (PR 5b), the expiry-anchor and historic-storage proofs of a refund (§2.3 (a), (b)),
and ``EXPIRED_EMPTY_*`` (PR 7a).
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..network.source_identity import require_distinct_sources
from ..security.errors import ValidationError
from .events import CLAIMED_TOPIC0, REFUNDED_TOPIC0
from .htlc_leg import SETTLED_SLOT, _addr, _b, _int_or_none, _receipt_facts
from .locator import UNKNOWN_DEPLOY_TX_HASH, EthHtlcLocator

__all__ = [
    "LOG_CHUNK_BLOCKS",
    "ClaimSeen",
    "CounterDisposition",
    "DispositionEvidence",
    "DispositionKind",
    "LogUnion",
    "read_counter_disposition",
    "union_logs",
]

#: Blocks per ``eth_getLogs`` request before halving. CHOSEN, not measured against any provider's
#: cap: a range-limit refusal halves the chunk for that endpoint, down to one block.
LOG_CHUNK_BLOCKS = 10_000

#: Error text that means "this range is too large for me", as providers word it. Matched lower-cased.
#: A miss here only costs the halving: the request is then recorded as a failure, never as "no logs".
_RANGE_LIMIT_MARKERS = ("range", "limit", "too many", "exceed", "query returned more than", "-32005", "10000")


class DispositionKind(Enum):
    """What the chain says about the counter-leg contract (design §2.3, the subset this PR reads)."""

    OPEN = "open"  # not settled at the tip, and the tip is before the timeout
    TIP_EXPIRED = "tip_expired"  # not settled at the tip, tip (MIN) at or past the timeout: a refund may be sent
    F_EXPIRED = "f_expired"  # not settled at F, and F itself is at or past the timeout
    SETTLED_UNFINAL = "settled_unfinal"  # settled at the tip, not yet at F: wait
    REFUNDED = "refunded"  # settled at F, and a refund verified (§2.3 (d))
    CLAIMED = "claimed"  # settled at F, and a claim verified, or Gap B
    UNKNOWN = "unknown"  # a read failed, fell below quorum, or the evidence contradicts itself


@dataclass(frozen=True)
class DispositionEvidence:
    """The proof behind a terminal answer: which transaction, at which finalized block, from whom."""

    kind: DispositionKind
    block_number: int
    block_hash: str
    tx_hash: str | None  # None for Gap B (CLAIMED proven by the invariants alone)
    sources: tuple[str, ...]
    single_source: bool


@dataclass(frozen=True)
class ClaimSeen:
    """A ``Claimed(p)`` log from our contract whose data opens ``H``, nominated by at least one
    endpoint. LIVENESS ONLY (§2.3 CLAIM_SEEN): ``p`` is public wherever this transaction is, so the
    covenant claim is due, but it proves nothing about the contract's state."""

    tx_hash: str
    block_number: int | None
    nominated_by: tuple[str, ...]
    verified: bool


@dataclass(frozen=True)
class LogUnion:
    """The union of one log query across endpoints, and what answered (§2.6). ``from_block`` to
    ``to_block`` is the chunked range every answering endpoint covered; each one was then also
    asked from ``to_block + 1`` to its own ``latest``."""

    logs: tuple[dict[str, Any], ...]
    answered: frozenset[str]
    failed: dict[str, str] = field(default_factory=dict)
    from_block: int = 0
    to_block: int = 0


@dataclass(frozen=True)
class CounterDisposition:
    kind: DispositionKind
    reason: str
    finalized_block: int | None
    evidence: DispositionEvidence | None = None
    claims_seen: tuple[ClaimSeen, ...] = ()
    logs_answered: frozenset[str] = frozenset()
    logs_failed: dict[str, str] = field(default_factory=dict)
    single_source: bool = False


# --------------------------------------------------------------------------- fan-out helpers


@dataclass(frozen=True)
class _Panel:
    """The endpoints a read is asked of, and how many must answer. Built only by :func:`_panel_of`,
    so every count in this module is a count over a set already held to one source per operator."""

    sources: tuple[Any, ...]
    need: int


def _panel_of(rpc: Any) -> _Panel:
    """The endpoints behind *rpc* and how many must answer: a multi-source rpc's own sources and
    ``min_agreeing``, or the one endpoint. Two sources of one operator are refused here even though
    ``MultiSourceEthRpc`` already refuses them, because this module counts the answers itself."""
    sources = getattr(rpc, "sources", None)
    if isinstance(sources, list) and len(sources) > 1:
        require_distinct_sources(sources, what="the counter-leg disposition reader")
        return _Panel(tuple(sources), int(rpc.min_agreeing))
    if isinstance(sources, list) and len(sources) == 1:
        return _Panel((sources[0],), 1)
    return _Panel((rpc,), 1)


def _key(source: Any) -> str:
    return str(getattr(source, "source_key", None) or f"source-{id(source)}")


class _BelowQuorum(Exception):
    """A read the decision needs could not be made with enough sources, or they disagreed."""


async def _ask_all(sources: Sequence[Any], call: Callable[[Any], Awaitable[Any]]) -> list[tuple[Any, Any]]:
    results = await asyncio.gather(*(call(s) for s in sources), return_exceptions=True)
    return list(zip(sources, results, strict=True))


async def _identity(panel: _Panel, call: Callable[[Any], Awaitable[Any]], what: str) -> Any:
    """Every answering source must say the same, and at least ``panel.need`` must answer."""
    answers = [r for _s, r in await _ask_all(panel.sources, call) if not isinstance(r, BaseException)]
    if len(answers) < panel.need:
        raise _BelowQuorum(f"{what}: {len(answers)} of {len(panel.sources)} endpoints answered, need {panel.need}")
    if any(a != answers[0] for a in answers[1:]):
        raise _BelowQuorum(f"{what}: endpoints disagree")
    return answers[0]


async def _magnitude(
    panel: _Panel,
    call: Callable[[Any], Awaitable[Any]],
    what: str,
    combine: Callable[[list[Any]], Any],
) -> Any:
    answers = [r for _s, r in await _ask_all(panel.sources, call) if not isinstance(r, BaseException)]
    if len(answers) < panel.need:
        raise _BelowQuorum(f"{what}: {len(answers)} of {len(panel.sources)} endpoints answered, need {panel.need}")
    return combine(answers)


# --------------------------------------------------------------------------- the union log read


def _is_range_limit(exc: BaseException) -> bool:
    text = str(exc).lower()
    return any(marker in text for marker in _RANGE_LIMIT_MARKERS)


async def _logs_from_one(
    source: Any, address: str, topics: list[Any], from_block: int, to_block: int
) -> list[tuple[Any, ...]]:
    """Every log in ``[from_block, to_block]`` from ONE endpoint, chunked, then one last request
    from ``to_block + 1`` to ``"latest"`` so a log newer than the agreed head is still nominated. A
    range-limit refusal halves the chunk. Any other failure (a 429, a timeout, a pruned range, a
    malformed field) raises: it is never "no logs". Returned normalised, so a malformed answer
    fails THIS endpoint rather than the whole read."""
    raw: list[dict[str, Any]] = []
    start, chunk = from_block, LOG_CHUNK_BLOCKS
    while start <= to_block:
        end = min(to_block, start + chunk - 1)
        try:
            raw.extend(await source.get_logs(address=address, topics=topics, from_block=start, to_block=end))
        except Exception as exc:
            if _is_range_limit(exc) and chunk > 1:
                chunk = max(1, chunk // 2)
                continue
            raise
        start = end + 1
    raw.extend(await source.get_logs(address=address, topics=topics, from_block=to_block + 1, to_block="latest"))
    return [(_log_key(log), log) for log in raw]


def _log_key(log: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _addr(log.get("address")),
        tuple(_b(t) for t in (log.get("topics") or [])),
        _b(log.get("data")),
        "0x" + _b(log.get("transactionHash")).hex(),
        _int_or_none(log.get("blockNumber")),
        "0x" + _b(log.get("blockHash")).hex(),
    )


async def union_logs(rpc: Any, *, address: str, topics: list[Any], from_block: int, to_block: int) -> LogUnion:
    """Ask EVERY endpoint behind *rpc* for the logs, and return their union plus who answered (§2.6).

    For NOMINATION only: every log returned names a transaction to verify, and nothing here is
    evidence on its own. An endpoint that fails is recorded in ``failed``, never read as empty.
    Each returned log is the normalised address (lower-cased), topics and data (bytes), tx hash,
    block number and block hash, with a ``nominated_by`` tuple of the endpoints that returned it.
    ``EthRpc.get_logs_union`` and ``MultiSourceEthRpc.get_logs_union`` are this, as methods.
    """
    results = await _ask_all(_panel_of(rpc).sources, lambda s: _logs_from_one(s, address, topics, from_block, to_block))
    nominated_by: dict[tuple[Any, ...], set[str]] = {}
    answered: set[str] = set()
    failed: dict[str, str] = {}
    for source, result in results:
        if isinstance(result, BaseException):
            failed[_key(source)] = f"{type(result).__name__}: {str(result)[:160]}"
            continue
        answered.add(_key(source))
        for k, _log in result:
            nominated_by.setdefault(k, set()).add(_key(source))
    logs = tuple(
        {
            "address": k[0],
            "topics": k[1],
            "data": k[2],
            "transactionHash": k[3],
            "blockNumber": k[4],
            "blockHash": k[5],
            "nominated_by": tuple(sorted(who)),
        }
        for k, who in sorted(nominated_by.items(), key=lambda kv: (kv[0][3], kv[0][4] or 0))
    )
    return LogUnion(logs=logs, answered=frozenset(answered), failed=failed, from_block=from_block, to_block=to_block)


# --------------------------------------------------------------------------- verify


def _our_event(receipt_facts: Any, contract: str, topic0: bytes, *, hashlock: bytes | None) -> bool:
    """Whether the agreed receipt logs carry *topic0* from OUR contract (and, for a claim, data
    opening ``H``)."""
    _status, _bh, _bn, logs = receipt_facts
    for address, topics, data in logs:
        if address != contract or not topics or topics[0] != topic0:
            continue
        if hashlock is None:
            return True
        if _opens(data, hashlock):
            return True
    return False


def _opens(data: bytes, hashlock: bytes) -> bool:
    """Whether ``Claimed(bytes32 p)`` log data is exactly one word ``p`` with ``sha256(p) == H``."""
    return len(data) == 32 and hashlib.sha256(data).digest() == hashlock


async def _verify(
    panel: _Panel,
    tx_hash: str,
    *,
    contract: str,
    topic0: bytes,
    hashlock: bytes | None,
    finalized: int,
) -> tuple[bool, int | None, str]:
    """``(verified, block_number, why)``. Raises :class:`_BelowQuorum` when the reads cannot be made
    or disagree: a nominated transaction that cannot be checked is an unknown, not a no."""

    async def _facts(s: Any) -> Any:
        return _receipt_facts(await s.get_transaction_receipt(tx_hash))

    facts = await _identity(panel, _facts, f"receipt({tx_hash})")
    if facts is None:
        return False, None, "not mined"
    status, block_hash, block_number, _logs = facts
    if status != 1:
        return False, block_number, f"status {status}"
    if block_number is None or block_number > finalized:
        return False, block_number, "not at or below the finalized block"
    canonical = await _identity(
        panel, lambda s: s.canonical_block_hash(block_number), f"canonical_block_hash({block_number})"
    )
    if bytes(canonical) != block_hash:
        return False, block_number, "its block is not canonical"
    if not _our_event(facts, contract, topic0, hashlock=hashlock):
        return False, block_number, "no matching event from this contract"
    return True, block_number, "verified"


# --------------------------------------------------------------------------- the reader


async def read_counter_disposition(
    rpc: Any,
    locator: EthHtlcLocator,
    *,
    from_block: int | None = None,
    recorded_refund_hashes: Sequence[str] = (),
) -> CounterDisposition:
    """The disposition of the counter-leg contract *locator* describes.

    Never raises for a chain read: a read that fails, falls below quorum or disagrees is reported as
    :attr:`DispositionKind.UNKNOWN` with the reason. Raises :class:`ValidationError` for bad inputs.

    ``from_block`` bounds the log scan (the deploy block). When ``None`` it is read from the deploy
    transaction's receipt, which needs a real ``locator.deploy_tx_hash``. ``recorded_refund_hashes``
    are refund transactions we sent ourselves, nominated alongside the logs and verified like them.

    A LIVENESS LIMIT, by design: one endpoint that nominates a transaction (a forged log) and then
    disagrees with the others about its receipt makes every answer for a SETTLED contract UNKNOWN for
    as long as it keeps doing so. UNKNOWN pages and moves nothing, so this costs time, never funds; the
    alternative, letting a majority overrule a disagreeing endpoint, is a majority read the design
    forbids for identity facts (§2.2).
    """
    if not isinstance(locator, EthHtlcLocator):
        raise ValidationError("read_counter_disposition requires an EthHtlcLocator")
    if from_block is not None and (not isinstance(from_block, int) or isinstance(from_block, bool) or from_block < 0):
        raise ValidationError("from_block must be a non-negative int")
    for h in recorded_refund_hashes:
        if not isinstance(h, str) or not h.startswith("0x") or len(h) != 66:
            raise ValidationError("recorded_refund_hashes must be 0x-prefixed 32-byte hex hashes")
    panel = _panel_of(rpc)
    single = len(panel.sources) == 1
    keys = tuple(sorted(_key(s) for s in panel.sources))
    contract = _addr(locator.contract_address)
    hashlock = locator.hashlock_bytes
    timeout = int(locator.timeout)

    def unknown(why: str, finalized: int | None = None, **kw: Any) -> CounterDisposition:
        return CounterDisposition(DispositionKind.UNKNOWN, why, finalized, single_source=single, **kw)

    try:
        finalized = await _magnitude(panel, lambda s: s.finalized_block_number(), "finalized", min)
        f_hash, f_ts = await _identity(panel, lambda s: s.block_hash_and_timestamp(finalized), f"block({finalized})")
        settled_f = any(
            await _identity(
                panel,
                lambda s: s.get_storage_at(locator.contract_address, SETTLED_SLOT, finalized),
                f"settled at {finalized}",
            )
        )
        # Any endpoint seeing it settled at its tip is enough to WAIT: the cost of believing a
        # liar here is a delay, and the cost of disbelieving an honest one is a refund that reverts.
        settled_tip = any(
            await _magnitude(
                panel,
                lambda s: s.get_storage_at(locator.contract_address, SETTLED_SLOT, "latest"),
                "settled at tip",
                lambda words: max(words, key=any),
            )
        )
        tip_ts = await _magnitude(panel, lambda s: s.latest_block_timestamp(), "tip timestamp", min)
        head = await _magnitude(panel, lambda s: s.block_number(), "head", min)
        if from_block is None:
            if str(locator.deploy_tx_hash).lower() == UNKNOWN_DEPLOY_TX_HASH:
                return unknown("no deploy transaction is known, so the log scan has no start; pass from_block")
            deploy = await _identity(panel, lambda s: _deploy_block(s, locator.deploy_tx_hash), "deploy receipt")
            if deploy is None:
                return unknown("the deploy transaction's receipt is not available", finalized)
            from_block = deploy
    except _BelowQuorum as exc:
        return unknown(f"a required read failed: {exc}")

    union = await union_logs(
        rpc,
        address=locator.contract_address,
        topics=[[CLAIMED_TOPIC0, REFUNDED_TOPIC0]],
        from_block=int(from_block),
        to_block=max(int(from_block), int(head)),
    )
    common: dict[str, Any] = {"logs_answered": union.answered, "logs_failed": union.failed}
    if not union.answered:
        # §2.6: a union with zero answers is UNKNOWN. Nothing could be nominated, so a claim
        # whose ``p`` is already public would go unseen, whatever the invariants say.
        return unknown(
            "no endpoint answered the log scan: " + "; ".join(f"{k}: {v}" for k, v in sorted(union.failed.items())),
            finalized,
            **common,
        )

    refunded_topic, claimed_topic = _b(REFUNDED_TOPIC0), _b(CLAIMED_TOPIC0)
    refunds = {h.lower() for h in recorded_refund_hashes}
    claims: dict[str, dict[str, Any]] = {}
    for log in union.logs:
        if log["address"] != contract or not log["topics"]:
            continue
        if log["topics"][0] == refunded_topic:
            refunds.add(log["transactionHash"])
        elif log["topics"][0] == claimed_topic and _opens(log["data"], hashlock):
            claims.setdefault(log["transactionHash"], log)

    incomplete: list[str] = []
    verified_refund: str | None = None
    for tx in sorted(refunds):
        try:
            ok, _bn, _why = await _verify(
                panel, tx, contract=contract, topic0=refunded_topic, hashlock=None, finalized=finalized
            )
        except _BelowQuorum as exc:
            incomplete.append(f"refund {tx}: {exc}")
            continue
        if ok and verified_refund is None:
            verified_refund = tx
    verified_claim: str | None = None
    seen: list[ClaimSeen] = []
    for tx, log in sorted(claims.items()):
        ok, bn = False, log["blockNumber"]
        try:
            ok, vbn, _why = await _verify(
                panel, tx, contract=contract, topic0=claimed_topic, hashlock=hashlock, finalized=finalized
            )
            bn = vbn if vbn is not None else bn
        except _BelowQuorum as exc:
            incomplete.append(f"claim {tx}: {exc}")
        seen.append(ClaimSeen(tx_hash=tx, block_number=bn, nominated_by=tuple(log["nominated_by"]), verified=ok))
        if ok and verified_claim is None:
            verified_claim = tx
    common["claims_seen"] = tuple(seen)

    def evidence(kind: DispositionKind, tx: str | None) -> DispositionEvidence:
        return DispositionEvidence(
            kind=kind,
            block_number=finalized,
            block_hash="0x" + bytes(f_hash).hex(),
            tx_hash=tx,
            sources=keys,
            single_source=single,
        )

    def done(kind: DispositionKind, why: str, tx: str | None = None, *, terminal: bool = False) -> CounterDisposition:
        ev = evidence(kind, tx) if terminal else None
        return CounterDisposition(kind, why, finalized, ev, single_source=single, **common)

    if settled_f:
        if verified_refund and verified_claim:
            return unknown("both a refund and a claim verify for one contract (rule 2)", finalized, **common)
        if incomplete:
            return unknown(
                "settled, but a nominated transaction could not be checked: " + "; ".join(incomplete),
                finalized,
                **common,
            )
        if f_ts < timeout:
            # Gap B: settled by a block at or before F, every one of them before the timeout. The
            # contract refuses refund() before the timeout, so only a claim can have settled it.
            if verified_refund:
                return unknown("a verified refund beside a settlement before the timeout (rule 3)", finalized, **common)
            return done(
                DispositionKind.CLAIMED,
                "settled at the finalized block, whose timestamp is before the timeout",
                verified_claim,
                terminal=True,
            )
        if verified_claim:
            return done(DispositionKind.CLAIMED, "a claim verifies", verified_claim, terminal=True)
        if verified_refund:
            return done(DispositionKind.REFUNDED, "a refund verifies", verified_refund, terminal=True)
        return unknown(
            "settled at the finalized block with neither a verified refund nor a verified claim", finalized, **common
        )

    # Not settled at F. A receipt that verifies at a block <= F contradicts that (rule 5).
    if verified_refund or verified_claim:
        return unknown(
            "a transaction verifies at or below the finalized block, but the contract is not settled there (rule 5)",
            finalized,
            **common,
        )
    if settled_tip:
        return done(DispositionKind.SETTLED_UNFINAL, "settled at the tip, not yet at the finalized block")
    if f_ts >= timeout:
        return done(DispositionKind.F_EXPIRED, "not settled, and the finalized block is at or past the timeout")
    if tip_ts >= timeout:
        return done(DispositionKind.TIP_EXPIRED, "not settled, and the tip is at or past the timeout")
    return done(DispositionKind.OPEN, "not settled, and before the timeout")


async def _deploy_block(source: Any, deploy_tx_hash: str) -> int | None:
    receipt = await source.get_transaction_receipt(deploy_tx_hash)
    if receipt is None:
        return None
    return _int_or_none(receipt.get("blockNumber"))

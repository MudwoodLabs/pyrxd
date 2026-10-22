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
  block ``F`` (the quorum MIN of ``finalized``), whose hash and timestamp every answering endpoint
  agrees on.

"Agreed" throughout means what ``MultiSourceEthRpc`` means by it: at least ``min_agreeing`` endpoints
answered, and every one that answered gave the same value. A disagreement is UNKNOWN, never a vote.
The storage read "at F" is pinned by block NUMBER, so the binding of that read to ``F``'s hash rests
on that agreement, not on an EIP-1898 block-hash pin.

Precedence when evidence contradicts (§2.4): invariants at ``F`` outrank receipts, and receipts
outrank nominations. A verified refund and a verified claim together, a verified refund beside "Gap B"
(settled at ``F`` while ``timestamp(F) < timeout``), or a verified receipt beside ``settled_F == 0``
are all :attr:`DispositionKind.UNKNOWN`. So is any failed or below-quorum read among the inputs to a
terminal answer: an unreadable input never becomes a terminal one.

Single source: with one endpoint every answer is recorded ``single_source=True``. Whether that may
change a record's state is the CONSUMER's rule (§2.5: never on a value-bearing chain), not this
module's; this module only reports it.

The expiry anchor (§2.3 (a), #850 PR 5b): an :attr:`DispositionKind.F_EXPIRED` answer carries
``(F, hash(F))`` for the caller to persist. Passed back in, it proves a later settlement was a
refund, because the contract was unsettled at a canonical block already at or past the timeout, and
``claim()`` reverts from then on. Its hash is rechecked canonical, agreed, at every use.

An empty token contract (§2.3 ``EXPIRED_EMPTY_*``, §2.7, #850 PR 7a): given the token, an
:attr:`DispositionKind.F_EXPIRED` contract whose token balance is 0 at ``F`` (identity across EVERY
endpoint) and at the tip (every endpoint answering 0) is :attr:`DispositionKind.EXPIRED_EMPTY_OPEN`.
It is :attr:`DispositionKind.EXPIRED_EMPTY_CLOSED`, a terminal answer, when the funding key's
transaction count at ``F`` (identity across every endpoint) is above the push-nonce bound: every
push that key signed for this contract had a nonce at or below the bound, so none can land. Without
a bound, or with a count that is not above it or cannot be read, it stays OPEN. A balance read that
fails leaves the answer :attr:`DispositionKind.F_EXPIRED`, which says nothing about the balance.

Not here: ``REFUND_PENDING`` and ``PAYOUT_REVERTS`` are the coordinator's reading of its OWN refund
transaction (``SwapCoordinator.taker_refund_btc``, PR 5b), not of the contract; and the
historic-storage proof of a refund (§2.3 (b)).
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import re
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

#: How far past the agreed head one endpoint's log scan follows its OWN head. CHOSEN, not measured.
#: Bounded so an endpoint reporting an absurd head cannot make its own scan endless; a log beyond it
#: is above every finalized block anyway, so it could only have been a liveness nomination.
LOG_TAIL_BLOCKS = LOG_CHUNK_BLOCKS

#: Error text that means "this range is too large for me", as providers word it. Matched lower-cased.
#: A miss here only costs the halving: the request is then recorded as a failure, never as "no logs".
#: Not measured against live providers; the wording is from their documentation and error reports.
#: A bare "limit exceeded" is left out on purpose: Infura words its RATE limit that way.
_RANGE_LIMIT_MARKERS = ("range", "query returned more than", "too large", "too wide")
#: ...and text that means "slow down", which must NOT be retried as a smaller range: halving on a 429
#: sends a rate-limited endpoint a dozen more requests before it is recorded as failed.
#: A regex, not substrings: a bare "429" matched inside block numbers such as 0x1429ab.
_RATE_LIMIT = re.compile(r"\b429\b|too many requests|rate[ -]?limit")


class DispositionKind(Enum):
    """What the chain says about the counter-leg contract (design §2.3, the subset this PR reads)."""

    OPEN = "open"  # not settled at the tip, and the tip is before the timeout
    TIP_EXPIRED = "tip_expired"  # not settled at the tip, tip (MIN) at or past the timeout: a refund may be sent
    F_EXPIRED = "f_expired"  # not settled at F, and F itself is at or past the timeout
    SETTLED_UNFINAL = "settled_unfinal"  # settled at the tip, not yet at F: wait
    REFUNDED = "refunded"  # settled at F, and a refund verified (§2.3 (d)) or the expiry anchor holds (a)
    CLAIMED = "claimed"  # settled at F, and a claim verified, or Gap B
    EXPIRED_EMPTY_OPEN = "expired_empty_open"  # F_EXPIRED, token balance 0 at F and tip; a push may still land
    EXPIRED_EMPTY_CLOSED = "expired_empty_closed"  # ...and the funding key's nonce at F is past every push
    UNKNOWN = "unknown"  # a read failed, fell below quorum, or the evidence contradicts itself


@dataclass(frozen=True)
class DispositionEvidence:
    """The proof behind a terminal answer: which transaction, at which finalized block, from whom."""

    kind: DispositionKind
    block_number: int
    block_hash: str
    tx_hash: str | None  # None for Gap B (CLAIMED proven by the invariants alone)
    sources: tuple[str, ...]  # every endpoint the reader was given, not only those that answered
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
    ``to_block`` is the range every answering endpoint covered; each one also went on to its own
    head, at most :data:`LOG_TAIL_BLOCKS` further."""

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
    #: ``(F, "0x" + hash(F))`` on an :attr:`DispositionKind.F_EXPIRED` answer: the expiry anchor to
    #: persist (§2.3 (a)). ``None`` on every other answer.
    expiry_anchor: tuple[int, str] | None = None
    #: ``True`` on an :attr:`DispositionKind.UNKNOWN` answer that read the contract SETTLED at the
    #: finalized block (it settled, and the evidence cannot say how), except where a transaction could
    #: not be checked and a nominated claim was verified (``claims_seen`` already surfaces it). ``False`` on every
    #: other answer, including an UNKNOWN from a failed or below-quorum read.
    settled_at_finalized: bool = False
    #: The funding key's transaction count at ``F``, agreed by every endpoint, on an
    #: ``EXPIRED_EMPTY_*`` answer that could read it; ``None`` otherwise. The nonce a push-closing
    #: transaction consumes (design §2.7).
    nonce_at_finalized: int | None = None
    #: For a record with no push nonce (``nonce_less``): whether every endpoint reads the funding
    #: key's pending count, latest count and count at ``F`` as one number, i.e. nothing of this key
    #: is in flight (design §2.7). ``None`` when not asked or not read.
    funding_key_idle: bool | None = None
    #: ``"0x" + hash(F)`` and every endpoint the reader was given, on an answer that got as far as
    #: the log scan (#850 PR 7b): what an operator's abandon records as the read it rests on, also
    #: for an answer with no ``evidence``. ``None`` and ``()`` on an answer that stopped earlier.
    finalized_hash: str | None = None
    sources: tuple[str, ...] = ()
    #: ``True`` only on the one UNKNOWN answer that read every gate and found no contradiction: the
    #: contract is settled at ``F``, ``F`` is at or past the timeout, every nominated transaction was
    #: checked, and neither a refund nor a claim verifies (#850 PR 7b, the abandon's
    #: ``SETTLED_UNVERIFIABLE``). ``settled_at_finalized`` is also set on answers that DO contradict.
    settled_unexplained: bool = False


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
    async def one(s: Any) -> Any:
        # Inside a coroutine, so a source that cannot even START the call (a missing method)
        # fails as that source, not as the whole read.
        return await call(s)

    results = await asyncio.gather(*(one(s) for s in sources), return_exceptions=True)
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


async def _every(panel: _Panel, call: Callable[[Any], Awaitable[Any]], what: str) -> list[Any]:
    """EVERY source must answer (not only a quorum). For a conclusion a negative reading supports
    ("the contract holds nothing"): the endpoint that does not answer may be the one that would have
    said otherwise, so a missing answer is unknown, never a vote."""
    results = await _ask_all(panel.sources, call)
    failed = [r for _s, r in results if isinstance(r, BaseException)]
    if failed:
        raise _BelowQuorum(f"{what}: {len(failed)} of {len(panel.sources)} endpoints did not answer ({failed[0]})")
    return [r for _s, r in results]


# --------------------------------------------------------------------------- the union log read


class _ShortScan(Exception):
    """An endpoint that could not cover the range it was asked for."""


def _is_range_limit(exc: BaseException) -> bool:
    text = str(exc).lower()
    if _RATE_LIMIT.search(text):
        return False
    return any(marker in text for marker in _RANGE_LIMIT_MARKERS)


async def _logs_from_one(
    source: Any, address: str, topics: list[Any], from_block: int, to_block: int
) -> list[tuple[Any, ...]]:
    """Every log in ``[from_block, to_block]`` from ONE endpoint, then on to that endpoint's OWN head
    (at most :data:`LOG_TAIL_BLOCKS` past ``to_block``), so a log newer than the agreed head is still
    nominated. An endpoint whose own head is below ``to_block`` has not covered the range and FAILS:
    counting it as answered would let a short scan pass for a complete one.

    Every request names integer blocks the endpoint has reached. Asking past its head is refused
    by real nodes (anvil: ``BlockOutOfRangeError``), and an open ``"latest"`` tail would dodge the
    chunking. A range-limit refusal halves the chunk. Any other failure (a 429, a timeout, a pruned
    range, a malformed field) raises: it is never "no logs". Returned normalised, so a malformed
    answer fails THIS endpoint rather than the whole read."""
    own_head = int(await source.block_number())
    if own_head < to_block:
        raise _ShortScan(f"its head {own_head} is below the agreed head {to_block}, so it cannot cover the range")
    end_at = min(own_head, to_block + LOG_TAIL_BLOCKS)
    raw: list[dict[str, Any]] = []
    start, chunk = from_block, LOG_CHUNK_BLOCKS
    while start <= end_at:
        end = min(end_at, start + chunk - 1)
        try:
            raw.extend(await source.get_logs(address=address, topics=topics, from_block=start, to_block=end))
        except Exception as exc:
            if _is_range_limit(exc) and chunk > 1:
                chunk = max(1, chunk // 2)
                continue
            raise
        start = end + 1
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
    expiry_anchor: tuple[int, str] | None = None,
    token_address: str | None = None,
    funding_account: str | None = None,
    push_nonce_bound: int | None = None,
    nonce_less: bool = False,
) -> CounterDisposition:
    """The disposition of the counter-leg contract *locator* describes.

    Never raises for a chain read: a read that fails, falls below quorum or disagrees is reported as
    :attr:`DispositionKind.UNKNOWN` with the reason. Raises :class:`ValidationError` for bad inputs.

    ``from_block`` bounds the log scan (the deploy block). When ``None`` it is read from the deploy
    transaction's receipt, which needs a real ``locator.deploy_tx_hash``. ``recorded_refund_hashes``
    are refund transactions we sent ourselves, nominated alongside the logs and verified like them.
    ``expiry_anchor`` is a ``(number, hash)`` this reader returned on an earlier ``F_EXPIRED`` answer
    (§2.3 (a)); with the contract settled at ``F``, an anchor whose hash is still canonical proves a
    refund even when no refund transaction can be verified.

    ``token_address`` makes an expired, unsettled contract's token balance part of the answer
    (``EXPIRED_EMPTY_*``, PR 7a). ``funding_account`` is the key that signed the token push, and
    ``push_nonce_bound`` the highest nonce at which it signed a push for this contract (or a
    transaction that closed that nonce); with both, a count at ``F`` above the bound is
    ``EXPIRED_EMPTY_CLOSED``. ``nonce_less`` says no push nonce is recorded (the bound, if any, is
    our own close's nonce): then CLOSED also needs ``pending == latest == count-at-F`` at every
    endpoint (design §2.7), so a push still in flight above our close is not read as closed.

    LIVENESS LIMITS, by design. One endpoint that nominates a transaction (a forged log) and then
    disagrees with the others about its receipt makes every answer for a SETTLED contract UNKNOWN for
    as long as it keeps doing so. So does one endpoint that has pruned an old receipt (geth's
    transaction-history limit, say) beside one that has not. UNKNOWN pages and moves nothing, so this costs time, never funds; the
    alternative, letting a majority overrule a disagreeing endpoint, is a majority read the design
    forbids for identity facts (§2.2).
    """
    if not isinstance(locator, EthHtlcLocator):
        raise ValidationError("read_counter_disposition requires an EthHtlcLocator")
    if from_block is not None and (not isinstance(from_block, int) or isinstance(from_block, bool) or from_block < 0):
        raise ValidationError("from_block must be a non-negative int")
    for h in recorded_refund_hashes:
        if not isinstance(h, str) or not h.startswith("0x") or len(h) != 66 or not _is_hex(h[2:]):
            raise ValidationError("recorded_refund_hashes must be 0x-prefixed 32-byte hex hashes")
    if expiry_anchor is not None:
        a_num, a_hash = expiry_anchor if isinstance(expiry_anchor, tuple) and len(expiry_anchor) == 2 else (None, None)
        if (
            not isinstance(a_num, int)
            or isinstance(a_num, bool)
            or a_num < 0
            or not isinstance(a_hash, str)
            or not a_hash.startswith("0x")
            or len(a_hash) != 66
            or not _is_hex(a_hash[2:])
        ):
            raise ValidationError("expiry_anchor must be (block number, 0x-prefixed 32-byte hex hash)")
    for name, value in (("token_address", token_address), ("funding_account", funding_account)):
        if value is not None and (
            not isinstance(value, str) or not value.startswith("0x") or len(value) != 42 or not _is_hex(value[2:])
        ):
            raise ValidationError(f"{name} must be a 0x-prefixed 20-byte hex address")
    if push_nonce_bound is not None and (
        not isinstance(push_nonce_bound, int) or isinstance(push_nonce_bound, bool) or push_nonce_bound < 0
    ):
        raise ValidationError("push_nonce_bound must be a non-negative int")
    if not isinstance(nonce_less, bool):
        raise ValidationError("nonce_less must be a bool")
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
        # The QUORUM-th highest head, not the MIN: the scan's agreed range ends here, and one endpoint
        # reporting a tiny head must not cap every honest endpoint's scan (review round 2). At least
        # `need` endpoints vouch for a head this high; one that is below it fails its own scan.
        head = await _magnitude(
            panel, lambda s: s.block_number(), "head", lambda hs: sorted(hs, reverse=True)[panel.need - 1]
        )
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
    common: dict[str, Any] = {
        "logs_answered": union.answered,
        "logs_failed": union.failed,
        "finalized_hash": "0x" + bytes(f_hash).hex(),
        "sources": keys,
    }
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
            return unknown(
                "both a refund and a claim verify for one contract (rule 2)",
                finalized,
                settled_at_finalized=True,
                **common,
            )
        if expiry_anchor is not None and await _anchor_holds(panel, expiry_anchor, finalized):
            # §2.3 (a). Unsettled at a canonical block already at or past the timeout: claim() has
            # reverted ever since, so whatever settled the contract later was a refund. The anchor
            # outranks nominations (an unverifiable one cannot make this UNKNOWN), not invariants.
            # An anchor that no longer holds is simply not used (design §7.2 scenario 10).
            if verified_claim:
                return unknown(
                    "a verified claim beside an expiry anchor (a claim after the timeout)",
                    finalized,
                    settled_at_finalized=True,
                    **common,
                )
            if f_ts < timeout:
                return unknown(
                    "an expiry anchor beside a finalized block before the timeout",
                    finalized,
                    settled_at_finalized=True,
                    **common,
                )
            return done(
                DispositionKind.REFUNDED,
                "settled at the finalized block after the expiry anchor, so by a refund",
                verified_refund,
                terminal=True,
            )
        if incomplete:
            # Tagged unless a nominated claim was verified: a verified claim is surfaced to the operator
            # (``claims_seen``). An unverified nomination does not count, or one endpoint could clear
            # the tag with a forged Claimed log for a transaction that does not exist (re-review of PR 6).
            return unknown(
                "settled, but a nominated transaction could not be checked: " + "; ".join(incomplete),
                finalized,
                settled_at_finalized=not any(c.verified for c in seen),
                **common,
            )
        if f_ts < timeout:
            # Gap B: settled by a block at or before F, every one of them before the timeout. The
            # contract refuses refund() before the timeout, so only a claim can have settled it.
            if verified_refund:
                return unknown(
                    "a verified refund beside a settlement before the timeout (rule 3)",
                    finalized,
                    settled_at_finalized=True,
                    **common,
                )
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
            "settled at the finalized block with neither a verified refund nor a verified claim",
            finalized,
            settled_at_finalized=True,
            settled_unexplained=True,
            **common,
        )

    # Not settled at F. A receipt that verifies at a block <= F contradicts that (rule 5).
    if verified_refund or verified_claim:
        return unknown(
            "a transaction verifies at or below the finalized block, but the contract is not settled there (rule 5)",
            finalized,
            **common,
        )
    # The tip reads are inputs only to these non-terminal answers, so they are made only here: a
    # failed tip read must not turn a verified REFUNDED or CLAIMED into UNKNOWN (rule 7's scope).
    try:
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
    except _BelowQuorum as exc:
        return unknown(f"a required read failed: {exc}", finalized, **common)
    if settled_tip:
        return done(DispositionKind.SETTLED_UNFINAL, "settled at the tip, not yet at the finalized block")
    if f_ts >= timeout:
        anchor = (finalized, "0x" + bytes(f_hash).hex())
        expired = dataclasses.replace(
            done(DispositionKind.F_EXPIRED, "not settled, and the finalized block is at or past the timeout"),
            expiry_anchor=anchor,
        )
        if token_address is None:
            return expired
        return await _expired_empty(
            panel,
            expired,
            contract=locator.contract_address,
            token=token_address,
            finalized=finalized,
            funding_account=funding_account,
            push_nonce_bound=push_nonce_bound,
            nonce_less=nonce_less,
            evidence=lambda: evidence(DispositionKind.EXPIRED_EMPTY_CLOSED, None),
        )
    if tip_ts >= timeout:
        return done(DispositionKind.TIP_EXPIRED, "not settled, and the tip is at or past the timeout")
    return done(DispositionKind.OPEN, "not settled, and before the timeout")


async def _expired_empty(
    panel: _Panel,
    expired: CounterDisposition,
    *,
    contract: str,
    token: str,
    finalized: int,
    funding_account: str | None,
    push_nonce_bound: int | None,
    nonce_less: bool,
    evidence: Callable[[], DispositionEvidence],
) -> CounterDisposition:
    """Refine an ``F_EXPIRED`` answer for a token contract (§2.3 ``EXPIRED_EMPTY_*``, §2.7).

    Empty means 0 at ``F`` (every endpoint answering, all agreeing) AND 0 at the tip (every endpoint
    answering 0): tokens at the tip still make a refund worth sending. A balance read that fails or
    disagrees leaves *expired* as it is. Closed needs the funding key's count at ``F``, every endpoint
    agreeing, above the bound; anything less is OPEN. Both reads are at the one block ``F``, so a
    push cannot land between them (design §7.2 scenario 11)."""
    try:
        at_f = await _every(panel, lambda s: s.erc20_balance_of(token, contract, finalized), f"balance at {finalized}")
        if any(b != at_f[0] for b in at_f[1:]):
            raise _BelowQuorum(f"balance at {finalized}: endpoints disagree")
        at_tip = await _every(panel, lambda s: s.erc20_balance_of(token, contract, "latest"), "balance at tip")
    except _BelowQuorum as exc:
        return dataclasses.replace(expired, reason=f"{expired.reason}; the token balance is unknown: {exc}")
    if int(at_f[0]) != 0 or any(int(b) != 0 for b in at_tip):
        return expired
    empty = dataclasses.replace(
        expired, kind=DispositionKind.EXPIRED_EMPTY_OPEN, reason="expired, and the contract holds no tokens"
    )
    if funding_account is None:
        return dataclasses.replace(
            empty, reason=f"{empty.reason}; the key that signed the push is not known, so its nonce was not read"
        )
    try:
        counts = await _every(
            panel, lambda s: s.get_transaction_count(funding_account, finalized), f"nonce at {finalized}"
        )
        if any(c != counts[0] for c in counts[1:]):
            raise _BelowQuorum(f"nonce at {finalized}: endpoints disagree")
    except _BelowQuorum as exc:
        return dataclasses.replace(empty, reason=f"{empty.reason}; the funding key's nonce at F is unknown: {exc}")
    count = int(counts[0])
    empty = dataclasses.replace(empty, nonce_at_finalized=count)
    if nonce_less:
        # Design §2.7: with no push nonce recorded, a push may sit at any nonce of this key. Nothing
        # in flight anywhere we can see (pending == latest == count at F at every endpoint) is the
        # condition for closing count-at-F, and for reading our own close as the end. It does not
        # see a privately submitted or evicted push (§2.7, D5), nor a push queued above a gap in
        # these endpoints' own pools (geth's pending count stops at the first gap), nor anything at
        # an endpoint that answers "pending" with its latest count. Those residuals are the design's.
        try:
            pending = await _every(
                panel, lambda s: s.get_transaction_count(funding_account, "pending"), "pending nonce"
            )
            latest = await _every(panel, lambda s: s.get_transaction_count(funding_account, "latest"), "latest nonce")
        except _BelowQuorum as exc:
            return dataclasses.replace(
                empty,
                funding_key_idle=False,
                reason=f"{empty.reason}; whether the funding key has transactions in flight is unknown: {exc}",
            )
        idle = all(int(n) == count for n in (*pending, *latest))
        empty = dataclasses.replace(empty, funding_key_idle=idle)
        if not idle:
            return dataclasses.replace(
                empty,
                reason=(
                    f"{empty.reason}; no push nonce is recorded and the funding key has transactions in flight "
                    f"(nonce at F {count}, pending {sorted(set(pending))}, latest {sorted(set(latest))})"
                ),
            )
    if push_nonce_bound is None:
        return dataclasses.replace(
            empty, reason=f"{empty.reason}; no push nonce is recorded, so a push may still land (design §2.7)"
        )
    if count <= push_nonce_bound:
        return dataclasses.replace(
            empty,
            reason=f"{empty.reason}; the funding key's nonce at F is {count}, not past the push nonce {push_nonce_bound}",
        )
    return dataclasses.replace(
        empty,
        kind=DispositionKind.EXPIRED_EMPTY_CLOSED,
        reason=(
            f"expired and empty at the finalized block, and the funding key's nonce there ({count}) is past "
            f"every push it signed (at most {push_nonce_bound}), so none can land"
        ),
        evidence=evidence(),
    )


async def _anchor_holds(panel: _Panel, anchor: tuple[int, str], finalized: int) -> bool:
    """Whether the expiry anchor's block is at or below ``F`` and its hash is still the canonical
    hash at that height, agreed. A read that fails or disagrees is "does not hold": the anchor is
    then not used, and the answer rests on the other evidence alone."""
    number, block_hash = anchor
    if number > finalized:
        return False
    try:
        canonical = await _identity(panel, lambda s: s.canonical_block_hash(number), f"canonical_block_hash({number})")
    except _BelowQuorum:
        return False
    return "0x" + bytes(canonical).hex() == block_hash.lower()


def _is_hex(text: str) -> bool:
    return re.fullmatch(r"[0-9a-fA-F]+", text) is not None


async def _deploy_block(source: Any, deploy_tx_hash: str) -> int | None:
    receipt = await source.get_transaction_receipt(deploy_tx_hash)
    if receipt is None:
        return None
    return _int_or_none(receipt.get("blockNumber"))

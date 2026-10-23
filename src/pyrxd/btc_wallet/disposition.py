"""Read-only disposition of a BTC counter-leg HTLC, from chain observation (#850 PR 9a).

The BTC sibling of :mod:`pyrxd.eth_wallet.disposition`. What this answers: has this swap's BTC HTLC
funding outpoint been spent, by which leaf, and is that spend buried deep enough to act on (design
``docs/plans/2026-10-09-counter-leg-disposition-from-chain-design.md`` §6). Nothing here sends
anything, and in this PR nothing in the coordinator calls it yet.

* **Discovery** is broad: every source is asked who spends the outpoint, and ANY source naming a
  spender nominates it (§6, "any source reports spent with a txid"). A source's spender is accepted
  only when its bytes hash to the txid it is filed under and it spends OUR outpoint; a source that
  serves anything else counts as failed, never as an answer.
* **Classification is by script path, never by txid** (§6, M1). The input spending our outpoint
  reveals its tapscript leaf: the claim leaf with a witness push that opens ``H`` is a claim; the
  refund leaf is a refund. The refund leaf needs the taker's key, so every refund-leaf spend is the
  taker's own refund, whoever broadcast it (the operator, or the tower's pre-signed refund).
  Anything else is not a spend this HTLC can have, and reads :attr:`BtcDispositionKind.UNKNOWN`.
* **Burial decides.** A spender changes nothing until it is ``burial_blocks`` deep at the quorum
  MINIMUM of its depth, with at least ``quorum`` sources answering the depth and every source that
  places it in a block placing it in the SAME block. Below that a claim is
  :attr:`BtcDispositionKind.CLAIM_SEEN` (liveness: ``p`` is public wherever the claim is, so the
  covenant claim is due) and a refund is :attr:`BtcDispositionKind.REFUND_PENDING`: the claim leaf
  has no timelock and the refund signals BIP125, so an unburied refund can still be replaced by a
  claim, and either can be reorged out.
* **Unspent** needs ``quorum`` sources saying so and none naming a spender: a source that cannot
  answer is never a vote for "unspent".

Precedence when evidence contradicts (the §2.4 rules, on BTC): two different spenders both buried
is impossible on an honest chain and reads UNKNOWN. A buried refund beside an unburied claim seen
elsewhere reads :attr:`BtcDispositionKind.REFUNDED`, and the claim stays in ``spenders``: ``p`` is
public, so the consumer keeps the covenant claim paged (D14).

Single source: with one source every answer is ``single_source=True``. Whether that may change a
record's state is the CONSUMER's rule (design §2.5), not this module's.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..network.source_identity import require_distinct_sources
from ..security.errors import ValidationError
from . import taproot as t

__all__ = [
    "BtcCounterDisposition",
    "BtcDispositionEvidence",
    "BtcDispositionKind",
    "BtcSpender",
    "SpendPath",
    "read_btc_counter_disposition",
    "spend_path_of",
]


class SpendPath(Enum):
    """Which of the HTLC's two leaves a transaction spends our outpoint through."""

    CLAIM = "claim"  # the claim leaf, with a witness push that opens H: reveals p
    REFUND = "refund"  # the refund leaf (the taker's CSV exit)
    UNRECOGNISED = "unrecognised"  # neither: not a spend this HTLC can have


class BtcDispositionKind(Enum):
    """What the chain says about the BTC HTLC funding outpoint (design §6)."""

    UNSPENT = "unspent"  # quorum sources hold it unspent, and none names a spender
    REFUND_PENDING = "refund_pending"  # a refund-leaf spend is nominated, not yet buried
    REFUNDED = "refunded"  # a refund-leaf spend is buried at the quorum depth
    CLAIM_SEEN = "claim_seen"  # a claim-leaf spend that opens H is nominated, not yet buried: liveness
    CLAIMED = "claimed"  # a claim-leaf spend is buried at the quorum depth
    UNKNOWN = "unknown"  # a read failed, fell below quorum, or the evidence contradicts itself


@dataclass(frozen=True)
class BtcSpender:
    """One transaction some source names as spending the outpoint, checked and classified.

    ``confirmations`` is the MINIMUM depth across the sources that answered, or ``None`` when fewer
    than the quorum did. ``block`` is ``(height, block hash)`` when every source that places the
    transaction in a block agrees on it and at least the quorum do, else ``None``."""

    txid: str
    path: SpendPath
    raw: bytes
    nominated_by: tuple[str, ...]
    confirmations: int | None
    block: tuple[int, str] | None

    def __repr__(self) -> str:  # the raw bytes are long; a claim's carry p, which is public but noisy
        return (
            f"BtcSpender(txid={self.txid}, path={self.path.value}, nominated_by={self.nominated_by}, "
            f"confirmations={self.confirmations}, block={self.block})"
        )


@dataclass(frozen=True)
class BtcDispositionEvidence:
    """The proof behind a terminal answer: which spender, in which block, how deep, from whom."""

    kind: BtcDispositionKind
    block_number: int
    block_hash: str
    txid: str
    confirmations: int
    sources: tuple[str, ...]  # every source the reader was given, not only those that answered
    single_source: bool


@dataclass(frozen=True)
class BtcCounterDisposition:
    kind: BtcDispositionKind
    reason: str
    evidence: BtcDispositionEvidence | None = None
    spenders: tuple[BtcSpender, ...] = ()
    sources: tuple[str, ...] = ()
    failed: tuple[tuple[str, str], ...] = ()
    single_source: bool = False

    @property
    def claims_seen(self) -> tuple[BtcSpender, ...]:
        """Every nominated claim-leaf spend, buried or not: ``p`` is public wherever one is."""
        return tuple(s for s in self.spenders if s.path is SpendPath.CLAIM)

    @property
    def refunds_seen(self) -> tuple[BtcSpender, ...]:
        return tuple(s for s in self.spenders if s.path is SpendPath.REFUND)


# --------------------------------------------------------------------------- classification


def _input_witness(raw: bytes, prevout: bytes) -> list[bytes] | None:
    """The witness stack of the input of *raw* that spends *prevout*, or ``None``."""
    prevouts = t.btc_input_outpoints_from_raw(raw)
    if prevout not in prevouts:
        return None
    stacks = t._iter_witness_stack(raw)
    index = prevouts.index(prevout)
    return stacks[index] if index < len(stacks) else []


def spend_path_of(raw_tx: bytes, locator: t.BtcHtlcLocator, hashlock: bytes) -> SpendPath:
    """Which leaf *raw_tx* spends ``locator``'s funding outpoint through (design §6, M1).

    Read from the spending input's own witness: its tapscript is the item before the control block
    (BIP341, after dropping an annex). The claim leaf counts only with a witness push whose sha256 is
    *hashlock*, so a claim here always reveals ``p``. Raises :class:`ValidationError` when *raw_tx*
    does not spend the outpoint at all, or does not parse."""
    raw = bytes(raw_tx)
    h = t._as_bytes(hashlock, name="hashlock", length=32)
    stack = _input_witness(raw, locator.funding_outpoint.prevout_bytes())
    if stack is None:
        raise ValidationError("the transaction does not spend this HTLC's funding outpoint")
    items = list(stack)
    if len(items) >= 2 and items[-1][:1] == b"\x50":
        items = items[:-1]  # BIP341 annex
    if len(items) < 2:
        return SpendPath.UNRECOGNISED  # a key-path spend; the NUMS internal key has no private key
    script = items[-2]
    tree = locator.script_tree
    if script == tree.claim_script:
        if any(len(item) == 32 and hashlib.sha256(item).digest() == h for item in items[:-2]):
            return SpendPath.CLAIM
        return SpendPath.UNRECOGNISED
    if script == tree.refund_script:
        return SpendPath.REFUND
    return SpendPath.UNRECOGNISED


# --------------------------------------------------------------------------- the read


def _key(reader: Any) -> str:
    key = getattr(reader, "source_key", None)
    return str(key) if key is not None else f"unnamed-{id(reader):x}"


def _short(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {str(exc)[:160]}"


async def _ask(reader: Any, method: str, *args: Any) -> Any:
    # The lookup is inside the coroutine, so a reader without the method fails as that source's
    # answer (gathered below), not as the whole read.
    return await getattr(reader, method)(*args)


async def _settle(readers: Sequence[Any], method: str, *args: Any) -> list[Any]:
    return list(await asyncio.gather(*(_ask(r, method, *args) for r in readers), return_exceptions=True))


def _depth_or_none(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return int(value)


def _block_or_none(value: Any) -> tuple[int, str] | bool | None:
    """``(height, hash)``; ``None`` for "not in a block"; ``False`` for an unusable answer."""
    if value is None:
        return None
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], int)
        and not isinstance(value[0], bool)
        and value[0] >= 0
        and isinstance(value[1], str)
        and len(value[1]) == 64
        and all(c in "0123456789abcdef" for c in value[1].lower())
    ):
        return (int(value[0]), value[1].lower())
    return False


async def read_btc_counter_disposition(
    readers: Sequence[Any],
    locator: t.BtcHtlcLocator,
    *,
    hashlock: bytes,
    burial_blocks: int,
    quorum: int,
) -> BtcCounterDisposition:
    """Read what the chain shows about ``locator``'s funding outpoint (module docstring).

    Each reader needs ``outpoint_spender(txid, vout) -> bytes | None`` (``None`` only for "unspent",
    raising when it cannot tell), ``confirmations(txid) -> int`` and ``tx_block(txid) -> (height,
    hash) | None``. Readers are counted one per source (:func:`require_distinct_sources`), and
    *quorum* of them must answer each read a decision rests on. Never raises for an unreadable chain:
    that is :attr:`BtcDispositionKind.UNKNOWN` with the reason."""
    readers = list(readers)
    if not readers:
        raise ValidationError("read_btc_counter_disposition needs at least one reader")
    if len(readers) > 1:
        require_distinct_sources(readers, what="read_btc_counter_disposition")
    if isinstance(quorum, bool) or not isinstance(quorum, int) or not 1 <= quorum <= len(readers):
        raise ValidationError(f"quorum must be an int in 1..{len(readers)}, not {quorum!r}")
    if isinstance(burial_blocks, bool) or not isinstance(burial_blocks, int) or burial_blocks < 1:
        raise ValidationError("burial_blocks must be a positive int")
    if not isinstance(locator, t.BtcHtlcLocator):
        raise ValidationError("locator must be a BtcHtlcLocator")
    keys = tuple(_key(r) for r in readers)
    single = len(readers) == 1
    op = locator.funding_outpoint
    prevout = op.prevout_bytes()

    def answer(kind: BtcDispositionKind, reason: str, **kw: Any) -> BtcCounterDisposition:
        return BtcCounterDisposition(kind=kind, reason=reason, sources=keys, single_source=single, **kw)

    failed: dict[str, str] = {}
    unspent_by: list[str] = []
    nominated: dict[str, tuple[bytes, list[str]]] = {}
    for key, result in zip(keys, await _settle(readers, "outpoint_spender", op.txid, op.vout), strict=True):
        if isinstance(result, BaseException):
            failed[key] = _short(result)
            continue
        if result is None:
            unspent_by.append(key)
            continue
        if not isinstance(result, (bytes, bytearray)) or not result:
            failed[key] = f"served a spender that is not raw transaction bytes ({type(result).__name__})"
            continue
        raw = bytes(result)
        try:
            txid = t.btc_txid_from_raw(raw)
            spends = prevout in t.btc_input_outpoints_from_raw(raw)
        except ValidationError as exc:
            failed[key] = f"served a spender that does not parse ({exc})"
            continue
        if not spends:
            failed[key] = f"served tx {txid} as the spender, but it does not spend {op.txid}:{op.vout}"
            continue
        nominated.setdefault(txid, (raw, []))[1].append(key)

    if not nominated:
        if len(unspent_by) >= quorum:
            return answer(
                BtcDispositionKind.UNSPENT,
                f"{len(unspent_by)} of {len(readers)} source(s) hold {op.txid}:{op.vout} unspent and none names a spender",
                failed=tuple(failed.items()),
            )
        return answer(
            BtcDispositionKind.UNKNOWN,
            f"only {len(unspent_by)} source(s) answered that {op.txid}:{op.vout} is unspent, below the quorum of "
            f"{quorum}; {len(failed)} failed",
            failed=tuple(failed.items()),
        )

    spenders: list[BtcSpender] = []
    for txid, (raw, by) in nominated.items():
        path = spend_path_of(raw, locator, hashlock)
        depths = await _settle(readers, "confirmations", txid)
        blocks = await _settle(readers, "tx_block", txid)
        good_depths = [
            d for d in (_depth_or_none(x) for x in depths if not isinstance(x, BaseException)) if d is not None
        ]
        confirmations = min(good_depths) if len(good_depths) >= quorum else None
        placed = [_block_or_none(b) for b in blocks if not isinstance(b, BaseException)]
        in_blocks = {b for b in placed if isinstance(b, tuple)}
        block = (
            next(iter(in_blocks))
            if len(in_blocks) == 1 and sum(isinstance(b, tuple) for b in placed) >= quorum
            else None
        )
        spenders.append(
            BtcSpender(txid=txid, path=path, raw=raw, nominated_by=tuple(by), confirmations=confirmations, block=block)
        )
    spenders.sort(key=lambda s: (s.path.value, s.txid))
    common: dict[str, Any] = {"spenders": tuple(spenders), "failed": tuple(failed.items())}

    strange = [s for s in spenders if s.path is SpendPath.UNRECOGNISED]
    if strange:
        return answer(
            BtcDispositionKind.UNKNOWN,
            f"tx {strange[0].txid} (named by {', '.join(strange[0].nominated_by)}) spends the outpoint through "
            "neither the claim leaf with H nor the refund leaf",
            **common,
        )
    buried = [s for s in spenders if s.confirmations is not None and s.confirmations >= burial_blocks and s.block]
    if len(buried) > 1:
        return answer(
            BtcDispositionKind.UNKNOWN,
            f"{len(buried)} different transactions are each reported buried as the spender of one outpoint "
            f"({', '.join(s.txid for s in buried)}); the sources contradict each other",
            **common,
        )
    if buried:
        s = buried[0]
        block, depth = s.block, s.confirmations
        if block is not None and depth is not None:  # always, by the filter above; said for the type checker
            kind = BtcDispositionKind.CLAIMED if s.path is SpendPath.CLAIM else BtcDispositionKind.REFUNDED
            evidence = BtcDispositionEvidence(
                kind=kind,
                block_number=block[0],
                block_hash=block[1],
                txid=s.txid,
                confirmations=depth,
                sources=keys,
                single_source=single,
            )
            return answer(
                kind,
                f"tx {s.txid} spends the outpoint by the {s.path.value} leaf and is {depth} deep "
                f"(burial {burial_blocks}) in block {block[0]}",
                evidence=evidence,
                **common,
            )
    claims = [s for s in spenders if s.path is SpendPath.CLAIM]
    if claims:
        return answer(
            BtcDispositionKind.CLAIM_SEEN,
            f"tx {claims[0].txid} claims the outpoint (its witness opens H) and is not yet buried "
            f"({claims[0].confirmations} of {burial_blocks})",
            **common,
        )
    refund = spenders[0]
    return answer(
        BtcDispositionKind.REFUND_PENDING,
        f"tx {refund.txid} refunds the outpoint and is not yet buried ({refund.confirmations} of {burial_blocks})",
        **common,
    )

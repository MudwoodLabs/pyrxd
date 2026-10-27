"""Read-only disposition of a BTC counter-leg HTLC, from chain observation (#850 PR 9a).

The BTC sibling of :mod:`pyrxd.eth_wallet.disposition`. What this answers: has this swap's BTC HTLC
funding outpoint been spent, by which leaf, and is that spend buried deep enough to act on (design
``docs/plans/2026-10-09-counter-leg-disposition-from-chain-design.md`` §6). Nothing here sends
anything, and in this PR nothing in the coordinator calls it yet.

* **Discovery** is broad: every source is asked who spends the outpoint, and ANY source naming a
  spender nominates it (§6, "any source reports spent with a txid"), once the spender passes the
  checks below. A source that serves anything else counts as failed, never as an answer.
* **What a served spender must pass.** Its bytes hash to the txid it is filed under and it spends
  OUR outpoint. That binds the witness-stripped bytes only: a source can serve a real transaction's
  txid with a witness it made up. So the witness is checked too. The input spending our outpoint
  must spend one of the HTLC's two leaves, and its BIP340 signature must verify, for that leaf's own
  key, over the transaction as served (``taproot_sighash``). A refund-leaf witness therefore needs
  the taker's key and a claim-leaf witness the maker's, and neither can be made up by a source.
  The one exception is a claim whose signature cannot be checked here (a spender with more than one
  input, whose other spent outputs this reader does not know) or does not verify: its witness still
  carries a preimage of ``H``, which only a holder of ``p`` can write, so it is kept, unverified, as
  liveness (``p`` is public wherever it is), and it is never terminal.
* **Classification is by script path, never by txid** (§6, M1): the claim leaf with a witness push
  that opens ``H`` is a claim; the refund leaf is a refund, whoever broadcast it (the operator, or
  the tower's pre-signed refund). Sources serving one txid with a refund and a claim whose
  signatures both verify read :attr:`BtcDispositionKind.UNKNOWN`. A claim witness that does not
  verify beside a verified refund does not hold the refund off (anyone who knows ``p`` can write
  one over our refund's txid); it is still reported in ``claims_seen``.
* **Burial decides.** A spender changes nothing until it is ``burial_blocks`` deep at the depth a
  quorum of sources vouches for (:func:`~pyrxd.network.quorum_depth.depth_vouched_by_quorum`), with
  at least ``quorum`` sources answering the depth and every source that places it in a block placing
  it in the SAME block. Below that a claim is
  :attr:`BtcDispositionKind.CLAIM_SEEN` and a refund :attr:`BtcDispositionKind.REFUND_PENDING`: the
  claim leaf has no timelock and the refund signals BIP125, so an unburied refund can still be
  replaced by a claim, and either can be reorged out. One source that over-reports cannot raise
  that depth, and one that under-reports cannot hold it down while a quorum of others answers (it
  was the minimum until register R13). One source that places the spender in another block still
  holds every terminal answer back.
* **Unspent** needs ``quorum`` sources saying so and none naming a spender that passes the checks:
  a source that cannot answer is never a vote for "unspent". ``unspent_by`` lists who said so on
  every answer, so a consumer can see a refund of ours that one source holds and the rest do not.

**Claims are liveness on every answer.** ``claims_seen`` is filled whatever the kind, UNKNOWN
included: a consumer pages the covenant claim on any non-empty ``claims_seen``, not only on
:attr:`BtcDispositionKind.CLAIM_SEEN`.

Precedence when evidence contradicts (the §2.4 rules, on BTC): two different spenders both buried
is impossible on an honest chain and reads UNKNOWN. A buried refund beside an unburied claim seen
elsewhere reads :attr:`BtcDispositionKind.REFUNDED`, and the claim stays in ``spenders`` (D14).

Single source: with one source, or with a quorum of one (any one source then decides alone),
every answer is ``single_source=True``. Whether that may change a record's state is the
CONSUMER's rule (design §2.5), not this module's.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..network.quorum_depth import depth_vouched_by_quorum
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
    "spend_signature_verifies",
]


class SpendPath(Enum):
    """Which of the HTLC's two leaves a transaction spends our outpoint through."""

    CLAIM = "claim"  # the claim leaf, with a witness push that opens H: reveals p
    REFUND = "refund"  # the refund leaf (the taker's CSV exit)
    UNRECOGNISED = "unrecognised"  # neither: not a spend this HTLC can have


class BtcDispositionKind(Enum):
    """What the chain says about the BTC HTLC funding outpoint (design §6)."""

    UNSPENT = "unspent"  # quorum sources hold it unspent, and none names a spender that passes the checks
    REFUND_PENDING = "refund_pending"  # a refund-leaf spend is nominated, not yet buried
    REFUNDED = "refunded"  # a refund-leaf spend is buried at the quorum depth
    CLAIM_SEEN = "claim_seen"  # a claim-leaf spend that opens H is nominated, not buried (or unverified)
    CLAIMED = "claimed"  # a verified claim-leaf spend is buried at the quorum depth
    UNKNOWN = "unknown"  # a read failed, fell below quorum, or the evidence contradicts itself


@dataclass(frozen=True)
class BtcSpender:
    """One transaction some source names as spending the outpoint, checked and classified.

    ``verified``: its leaf signature verifies over the bytes served (always, for a refund).
    ``confirmations`` is the depth a quorum of the sources that answered vouches for
    (:func:`~pyrxd.network.quorum_depth.depth_vouched_by_quorum`), or ``None`` when fewer than the
    quorum did; ``deepest`` is the MAXIMUM any source answered (``None`` when none did), so
    a caller can tell "mined, depth below quorum" from "no source has it mined". ``block`` is ``(height, block hash)`` when every source that places the
    transaction in a block agrees on it and at least the quorum do, else ``None``. ``contested``:
    sources served this txid with witnesses that classify differently; ``raw`` is then a claim's
    bytes when any was served, so ``p`` can be read from it."""

    txid: str
    path: SpendPath
    raw: bytes
    nominated_by: tuple[str, ...]
    confirmations: int | None
    block: tuple[int, str] | None
    verified: bool = True
    deepest: int | None = None
    contested: bool = False
    #: On a verified refund: a claim witness (unverified, carrying p) that a source served for the
    #: same txid. Reported through :attr:`BtcCounterDisposition.claims_seen`.
    claim_raw: bytes | None = None

    def __repr__(self) -> str:  # the raw bytes are long; a claim's carry p, which is public but noisy
        return (
            f"BtcSpender(txid={self.txid}, path={self.path.value}, nominated_by={self.nominated_by}, "
            f"confirmations={self.confirmations}, block={self.block}, verified={self.verified}, "
            f"contested={self.contested})"
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
    #: The sources that answered "unspent", on every answer.
    unspent_by: tuple[str, ...] = ()
    single_source: bool = False
    #: How many sources each read a decision rests on needed (the reader's ``quorum``).
    quorum: int = 1

    @property
    def claims_seen(self) -> tuple[BtcSpender, ...]:
        """Every nominated claim-leaf spend, buried or not, verified or not, on every kind of
        answer: ``p`` is public wherever one is."""
        seen = [s for s in self.spenders if s.path is SpendPath.CLAIM]
        seen += [
            dataclasses.replace(s, path=SpendPath.CLAIM, raw=s.claim_raw, verified=False, claim_raw=None)
            for s in self.spenders
            if s.claim_raw is not None
        ]
        return tuple(seen)

    @property
    def refunds_seen(self) -> tuple[BtcSpender, ...]:
        return tuple(s for s in self.spenders if s.path is SpendPath.REFUND)

    @property
    def refund_outvoted(self) -> bool:
        """A :attr:`BtcDispositionKind.REFUND_PENDING` read whose refunds a quorum does not hold: every
        refund-leaf spend is named by fewer than ``quorum`` sources, at least ``quorum`` sources hold
        the outpoint unspent, and no claim is seen. One stale source still serving a refund that was
        dropped or never relayed reads this way, and so does a refund that has reached only one
        source's mempool so far. The kind stays REFUND_PENDING (the coordinator follows that refund);
        a consumer that would stand down on a pending refund of ours reads this as unspent instead,
        since sending our refund again costs nothing (the watchtower, register R12)."""
        return (
            self.kind is BtcDispositionKind.REFUND_PENDING
            and len(self.unspent_by) >= self.quorum
            and not self.claims_seen
            and all(len(set(r.nominated_by)) < self.quorum for r in self.refunds_seen)
        )


# --------------------------------------------------------------------------- classification


def _input_witness(raw: bytes, prevout: bytes) -> tuple[int, list[bytes]] | None:
    """``(input index, witness stack)`` of the input of *raw* that spends *prevout*, or ``None``."""
    prevouts = t.btc_input_outpoints_from_raw(raw)
    if prevout not in prevouts:
        return None
    stacks = t._iter_witness_stack(raw)
    index = prevouts.index(prevout)
    return index, (stacks[index] if index < len(stacks) else [])


def _split_annex(stack: list[bytes]) -> tuple[list[bytes], bytes | None]:
    items = list(stack)
    if len(items) >= 2 and items[-1][:1] == b"\x50":
        return items[:-1], items[-1]  # BIP341 annex
    return items, None


def spend_path_of(raw_tx: bytes, locator: t.BtcHtlcLocator, hashlock: bytes) -> SpendPath:
    """Which leaf *raw_tx* spends ``locator``'s funding outpoint through (design §6, M1).

    Read from the spending input's own witness: its tapscript is the item before the control block
    (BIP341, after dropping an annex). The claim leaf counts only with a witness push whose sha256 is
    *hashlock*, so a claim here always reveals ``p``. This reads the witness only; whether its
    signature verifies is :func:`spend_signature_verifies`. Raises :class:`ValidationError` when
    *raw_tx* does not spend the outpoint at all, or does not parse."""
    raw = bytes(raw_tx)
    h = t._as_bytes(hashlock, name="hashlock", length=32)
    found = _input_witness(raw, locator.funding_outpoint.prevout_bytes())
    if found is None:
        raise ValidationError("the transaction does not spend this HTLC's funding outpoint")
    items, _annex = _split_annex(found[1])
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


#: The sighash types BIP341 allows in a 65-byte signature (0x00 only as the implicit 64-byte form).
_BIP341_HASH_TYPES = frozenset({0x01, 0x02, 0x03, 0x81, 0x82, 0x83})


def spend_signature_verifies(raw_tx: bytes, locator: t.BtcHtlcLocator) -> bool | None:
    """Whether the BIP340 signature in *raw_tx*'s spend of ``locator``'s outpoint verifies for the
    key of the leaf it spends, over *raw_tx* itself (BIP341 script-path sighash).

    ``None`` when this cannot be checked here: a spender with more than one input whose signature
    is not ANYONECANPAY (its sighash commits to every input's spent output, and only ours is known).
    Our own refunds are single-input (``taproot.build_refund_tx``), so a refund is always checked. ``False`` for a leaf this HTLC
    does not have, a malformed signature, or one that does not verify. Each leaf ends
    ``<32-byte x-only key> OP_CHECKSIG`` (``taproot.claim_leaf_script``, ``refund_leaf_script``),
    and that key is the one checked."""
    import coincurve

    raw = bytes(raw_tx)
    found = _input_witness(raw, locator.funding_outpoint.prevout_bytes())
    if found is None:
        return False
    index, stack = found
    items, annex = _split_annex(stack)
    tree = locator.script_tree
    if len(items) < 3 or items[-2] not in (tree.claim_script, tree.refund_script):
        return False
    script = items[-2]
    fields = t.btc_spend_fields_from_raw(raw)
    sig = items[0]
    if len(sig) == 64:
        hash_type = t.SIGHASH_DEFAULT
    elif len(sig) == 65 and sig[64] in _BIP341_HASH_TYPES:
        hash_type, sig = sig[64], sig[:64]
    else:
        return False  # BIP341: a 65-byte signature never carries 0x00, nor a type outside the list
    anyonecanpay = bool(hash_type & t.SIGHASH_ANYONECANPAY)
    n_in = len(fields.input_prevouts)
    if n_in != 1 and not anyonecanpay:
        return None
    if script[-34:-33] != b"\x20" or script[-1:] != b"\xac":
        return False
    # With ANYONECANPAY the sighash commits to this input's own spent output only, so the other
    # inputs' spent outputs (unknown here) are placeholders the hash never reads.
    spent = [(0, b"")] * n_in
    spent[index] = (locator.amount_sats, locator.scriptpubkey)
    try:
        msg = t.taproot_sighash(
            tx_version=int.from_bytes(raw[:4], "little", signed=True),
            locktime=int.from_bytes(raw[-4:], "little"),
            inputs=list(zip(fields.input_prevouts, fields.input_sequences, strict=True)),
            input_index=index,
            spent_outputs=spent,
            outputs=list(fields.outputs),
            hash_type=hash_type,
            tapleaf_hash_value=t.tapleaf_hash(script, tree.leaf_version),
            annex=annex,
        )
        return bool(coincurve.PublicKeyXOnly(script[-33:-1]).verify(sig, msg))
    except (ValidationError, ValueError):
        return False


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


@dataclass
class _Nomination:
    """Every witness served for one txid, each with its path and whether its signature verifies."""

    served: list[tuple[bytes, SpendPath, bool]]
    by: list[str]


def _check_served(raw: bytes, locator: t.BtcHtlcLocator, hashlock: bytes) -> tuple[str, SpendPath, bool] | str:
    """``(txid, path, verified)`` for a spender a source served, or why that source failed."""
    op = locator.funding_outpoint
    try:
        txid = t.btc_txid_from_raw(raw)
        if op.prevout_bytes() not in t.btc_input_outpoints_from_raw(raw):
            return f"served tx {txid} as the spender, but it does not spend {op.txid}:{op.vout}"
        path = spend_path_of(raw, locator, hashlock)
        verifies = spend_signature_verifies(raw, locator)
    except ValidationError as exc:
        return f"served a spender that does not parse ({exc})"
    if path is SpendPath.UNRECOGNISED:
        return f"served tx {txid}, which spends the outpoint through neither the claim leaf with H nor the refund leaf"
    if path is SpendPath.REFUND and verifies is not True:
        # Needs the taker's key: a refund witness whose signature does not verify was made up.
        return f"served tx {txid} with a refund-leaf witness whose signature does not verify"
    return txid, path, verifies is True


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
    hashlock = t._as_bytes(hashlock, name="hashlock", length=32)
    keys = tuple(_key(r) for r in readers)
    # A quorum of one lets any one source decide, however many are asked (review of part 2, F1).
    single = len(readers) == 1 or quorum < 2
    op = locator.funding_outpoint

    failed: dict[str, str] = {}
    unspent_by: list[str] = []
    nominated: dict[str, _Nomination] = {}

    def answer(kind: BtcDispositionKind, reason: str, **kw: Any) -> BtcCounterDisposition:
        return BtcCounterDisposition(
            kind=kind,
            reason=reason,
            sources=keys,
            single_source=single,
            failed=tuple(failed.items()),
            unspent_by=tuple(unspent_by),
            quorum=quorum,
            **kw,
        )

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
        checked = _check_served(raw, locator, hashlock)
        if isinstance(checked, str):
            failed[key] = checked
            continue
        txid, path, verified = checked
        entry = nominated.setdefault(txid, _Nomination(served=[], by=[]))
        if all(raw != r for r, _p, _v in entry.served):
            entry.served.append((raw, path, verified))
        entry.by.append(key)

    if not nominated:
        if len(unspent_by) >= quorum:
            return answer(
                BtcDispositionKind.UNSPENT,
                f"{len(unspent_by)} of {len(readers)} source(s) hold {op.txid}:{op.vout} unspent and none names a "
                "spender that passes the checks",
            )
        return answer(
            BtcDispositionKind.UNKNOWN,
            f"only {len(unspent_by)} source(s) answered that {op.txid}:{op.vout} is unspent, below the quorum of "
            f"{quorum}; {len(failed)} failed",
        )

    spenders: list[BtcSpender] = []
    for txid, entry in nominated.items():
        claims = [(r, v) for r, p, v in entry.served if p is SpendPath.CLAIM]
        refunds = [r for r, p, _v in entry.served if p is SpendPath.REFUND]  # all verified (_check_served)
        claim_raw: bytes | None = None
        contested = False
        if refunds and not any(v for _r, v in claims):
            # A verified refund beside claim witnesses that do not verify: anyone who knows p can write
            # those over our refund's txid, so they must not hold the refund off (re-review N1). Each is
            # still kept, as liveness: it carries p.
            raw, path, verified = refunds[0], SpendPath.REFUND, True
            claim_raw = claims[0][0] if claims else None
        elif claims:
            # A claim is kept whatever else was served for this txid: it carries p. Prefer one whose
            # signature verifies. Beside a verified refund too, both are signed over one txid: UNKNOWN.
            raw, verified = max(claims, key=lambda c: c[1])
            path = SpendPath.CLAIM
            contested = bool(refunds)
        else:
            raw, path, verified = entry.served[0]
        depths = await _settle(readers, "confirmations", txid)
        blocks = await _settle(readers, "tx_block", txid)
        good_depths = [
            d for d in (_depth_or_none(x) for x in depths if not isinstance(x, BaseException)) if d is not None
        ]
        confirmations = depth_vouched_by_quorum(good_depths, quorum) if len(good_depths) >= quorum else None
        placed = [_block_or_none(b) for b in blocks if not isinstance(b, BaseException)]
        in_blocks = {b for b in placed if isinstance(b, tuple)}
        block = (
            next(iter(in_blocks))
            if len(in_blocks) == 1 and sum(isinstance(b, tuple) for b in placed) >= quorum
            else None
        )
        spenders.append(
            BtcSpender(
                txid=txid,
                path=path,
                raw=raw,
                nominated_by=tuple(entry.by),
                confirmations=confirmations,
                block=block,
                verified=verified,
                deepest=max(good_depths) if good_depths else None,
                contested=contested,
                claim_raw=claim_raw,
            )
        )
    spenders.sort(key=lambda s: (s.path.value, s.txid))
    common: dict[str, Any] = {"spenders": tuple(spenders)}

    disputed = [s for s in spenders if s.contested]
    if disputed:
        return answer(
            BtcDispositionKind.UNKNOWN,
            f"sources served tx {disputed[0].txid} with witnesses that spend different leaves; the txid binds "
            "only the witness-stripped bytes, so which one is on chain is not known",
            **common,
        )
    buried = [
        s
        for s in spenders
        if s.verified and s.confirmations is not None and s.confirmations >= burial_blocks and s.block
    ]
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
    claims_seen = [s for s in spenders if s.path is SpendPath.CLAIM]
    if claims_seen:
        c = claims_seen[0]
        why = "its signature cannot be verified here" if not c.verified else f"{c.confirmations} of {burial_blocks}"
        return answer(
            BtcDispositionKind.CLAIM_SEEN,
            f"tx {c.txid} claims the outpoint (its witness opens H) and is not terminal ({why})",
            **common,
        )
    refund = spenders[0]
    return answer(
        BtcDispositionKind.REFUND_PENDING,
        f"tx {refund.txid} refunds the outpoint and is not yet buried ({refund.confirmations} of {burial_blocks})",
        **common,
    )

"""Verify the block a HashMark sits in, instead of taking the height on the endpoint's word.

:mod:`pyrxd.glyph.mark_anchor` reports where an endpoint SAYS a transaction is, bound only to that
endpoint's own header. This module checks it, from data any endpoint can serve, against something
pyrxd ships: the checkpoint table in :mod:`pyrxd.spv.radiant_checkpoints`. Merkle verification needs
no independent source (HashMark §2.3.2), so one endpoint's data is enough — the trust sits in the
checkpoint, not in who served the proof.

CALLERS (tracked in #799). ``pyrxd verify`` calls it, on by default, through
:func:`pyrxd.cli.glyph_inspect.verify_anchor_block`, for ONE anchor: the mark's own (``mark_anchor``
in its JSON, and the ``block`` check), which crosses it on both of the paths that build it — its
own lookup, and with ``--wave-name`` the form-2 lookup, which verifies the anchor it fetched before
the name judgement reads its depth and hands that same anchor, verified, to the ``block`` check
(``records[i].name_at_mark.anchor`` is that anchor). VERIFIED prints this module's claim; any other
outcome falls back to the endpoint's-word wording with the reason; CONTRADICTED exits 2 with its
reason, as a binding failure does. What form 2 reads from its SECOND endpoint (the mark's height
again, and every chain step's) is not verified, and ``glyph inspect`` does not call it. The
``/verify/`` and ``/inspect/`` pages do, for their one anchor, through ``glue.verify_mark_block``,
which drives :func:`verify_with_fetched` — the sequence and decision the CLI's helper uses too.

WHAT ``VERIFIED`` CLAIMS, per level. Both levels first require that the transaction's raw bytes
(more than 64 of them) hash to its txid and that its merkle branch (SHA-256d, like Bitcoin's) leads
to the merkle root in the header served for its height — and that the branch is exactly as deep
as the block's tree, which the COINBASE's branch (position 0, checked against the same root)
states. Radiant accepts 64-byte transactions (``MIN_TX_SIZE = 32``,
``tests/vendor/radiant_core/consensus.h:19``), and the bytes of one can double as an inner node's
two children, so a branch one level longer than the tree can "prove" a transaction the block does
not contain (CVE-2017-12842); the more-than-64-bytes rule closes only the shorter direction.
Pinning the depth to the coinbase's closes the longer one too, unless the block's coinbase is
itself 64 bytes, which only that block's miner can arrange: the coinbase's raw bytes are not
fetched or checked.

* **checkpoint** — the height ``H`` is at or below the newest checkpoint. The header at ``H`` is
  linked hash by hash (each header's previous-block field equals the double-SHA-512/256 hash of the
  one below) up to the first checkpoint at or above ``H``, whose hash must equal the shipped one.
  The height then rests on that checkpoint: forging it would take a SHA-512/256d second preimage.
  No proof-of-work is checked or needed at this level.
* **work** — ``H`` is above the newest checkpoint ``C``. The headers ``C+1 .. H`` (and above, for
  burial) are linked hash by hash to ``C``'s header, whose hash must equal the shipped one, and
  EACH must (a) hash at or below the target its own nBits states and (b) state a target whose work
  is at least :data:`FLOOR_WORK_DIVISOR`-th of ``C``'s.

  WHAT THAT COSTS A LIAR — not the work of every header since ``C``. A server placing the
  transaction at a false height ``H`` can serve the REAL headers ``C+1 .. H-1`` unchanged; it has
  to mine only the header at ``H`` (whose merkle root commits to the transaction) and one on top of
  it for each further confirmation checked: ``min_confirmations`` headers from ``H`` up, each at
  or above the floor. The cost is set by ``min_confirmations`` and the floor, not by how far ``H``
  sits above ``C``. (The low-work test in ``tests/test_mark_block_verification.py`` builds exactly
  this forgery: real headers to 460,580, one mined header on top.)

  FOR A CALLER THAT GATES FUNDS on this (the planned swap taker gate, "phase 2b"): a single
  forged confirmation costs one floor-level header, so the required ``min_confirmations`` MUST
  scale with the value at risk, and the refusal must say what it required. The default of this
  module is the mark path's, where a wrong answer misleads but moves nothing.

REQUIRED DEPTH AND TARGET DEPTH ARE TWO NUMBERS. ``min_confirmations`` is REQUIRED: a proof that
cannot reach it is NOT VERIFIED. ``target_confirmations`` (optional, never below the required
depth in effect) is how deep to TRY: the headers up to it are fetched and checked like the rest,
but one that is missing, malformed, unlinked, below its own target or below the floor only ends
the proved run there — it is past what was required, so it is not a finding either way — and
``verified_depth`` (with the claim's header count) is the depth actually proved. ``pyrxd verify``
passes none, so its required depth is the only one; the browser pages require 1 and aim for
more, so a server whose tip is short still VERIFIES to the depth it can prove.

WHAT IS NOT CLAIMED, at any level: that the chain is Radiant's most-work chain; that any header's
nBits is the value Radiant's difficulty rules require (Radiant retargets EVERY block, its algorithm
is not vendored here, so only each header's own target and the floor are checked); that the
block's timestamp is accurate; that the transaction's scripts are valid. And the checkpoint table
is only as good as its sources — see its docstring for who vouched for it.

THE CONTRACT: :func:`verify_mark_block` is synchronous (the browser bridge drives it without an
event loop) and TOTAL over server data — every malformed, missing, truncated or contradictory reply
becomes a :class:`BlockVerification` with a reason, never an exception. It raises only for a
caller's programming error: a bad ``min_confirmations`` or a malformed ``checkpoints`` table.

Three states, and why three: ``VERIFIED`` (every check passed); ``CONTRADICTED`` (the data the
server served is well-formed and fails a check — its own proof disagrees with its claim; a block
hash it named that is not the header it served is not, on its own, a failed check: see
:func:`verify_mark_block`); ``NOT VERIFIED`` (nothing was proved either way: data missing or
unreadable, no checkpoint for this network, the chain above the checkpoint too long for this
pyrxd, or a difficulty below the floor — an honest low-difficulty stretch is not a lie). Neither
non-VERIFIED state says the mark is invalid; both mean the height remains the endpoint's word.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pyrxd.hash import radiant_block_hash
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.security.types import BlockHeight
from pyrxd.spv.merkle import build_branch, compute_root, extract_merkle_root, verify_tx_in_block
from pyrxd.spv.radiant import (
    TxMerkleBranch,
    radiant_header_prev_hash,
    radiant_header_work,
    verify_radiant_header_pow,
)
from pyrxd.spv.radiant_checkpoints import CHECKPOINTS

__all__ = [
    "CONTRADICTED",
    "FLOOR_WORK_DIVISOR",
    "MAX_HEADERS_FROM_CHECKPOINT",
    "MAX_HEADERS_PER_REQUEST",
    "NOTHING_AGAINST_THE_MARK",
    "NOT_VERIFIED",
    "VERIFIED",
    "BlockFetch",
    "BlockFetchPlan",
    "BlockVerification",
    "block_fetches",
    "contradicted_sentence",
    "could_not_fetch",
    "plan_block_verification",
    "verify_mark_block",
    "verify_with_fetched",
]

VERIFIED = "VERIFIED"
NOT_VERIFIED = "NOT VERIFIED"
CONTRADICTED = "CONTRADICTED"

# ── PARAMETERS — approved by the maintainer 2026-09-29 (plan Q2/Q3). ────────────────────────────
# Changing either changes what VERIFIED means above the newest checkpoint, so each change needs the
# maintainer's sign-off again and a CHANGELOG entry.

#: Each header above the newest checkpoint must carry at least ``checkpoint work // 16``. Radiant
#: difficulty fell about 2.5x over ~8,000 blocks between the two fixture marks (460,572 and
#: 468,521), so 16 leaves honest headroom; a tighter floor degrades honest marks to NOT VERIFIED,
#: a looser one makes a forged chain cheaper.
FLOOR_WORK_DIVISOR = 16

#: The most headers linked from a checkpoint in one verification: past it, the answer is "this
#: pyrxd's checkpoints are too old", not an unbounded walk. Two checkpoint intervals.
MAX_HEADERS_FROM_CHECKPOINT = 4032

# ─────────────────────────────────────────────────────────────────────────────────────────────

#: ElectrumX's ``blockchain.block.headers`` serves at most 2016 headers per call.
MAX_HEADERS_PER_REQUEST = 2016

_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
_INTERNAL = "verification could not complete (internal error"


@dataclass(frozen=True)
class BlockFetchPlan:
    """What a caller must fetch before :func:`verify_mark_block` can reach VERIFIED.

    ``header_ranges`` are ``(start_height, count)`` pairs, each ``count <= MAX_HEADERS_PER_REQUEST``
    (a ``blockchain.block.headers`` call each), plus two merkle branches in the block at ``height``:
    the mark's (``blockchain.transaction.get_merkle``) and the coinbase's
    (``blockchain.transaction.id_from_pos(height, 0, true)``), which pins the tree's depth. When ``reason`` is set, nothing fetched can verify this block and the ranges are
    empty: say why instead of fetching.
    """

    height: int | None
    header_ranges: tuple[tuple[int, int], ...]
    level: str | None
    reason: str | None


@dataclass(frozen=True)
class BlockVerification:
    """The outcome, with the one sentence a surface may print when it is VERIFIED."""

    state: str
    #: The exact claim, for VERIFIED only; ``None`` otherwise.
    claim: str | None
    #: Why it is not VERIFIED; ``None`` when it is.
    reason: str | None
    height: int | None
    #: The mark's block hash, display hex, once the header at ``height`` has been read: the hash of
    #: the header SERVED at that height, which is the block proved when the state is VERIFIED.
    blockhash: str | None = None
    #: The block hash the endpoint had NAMED for the transaction, when it is not ``blockhash`` (the
    #: ``blockhash`` step is then ``"differs"``); ``None`` when it matched, was not given, or was not
    #: 64 hex characters. A different name is not a contradiction by itself — a chain
    #: reorganisation between the endpoint's two replies produces one honestly — so it is reported,
    #: and the rest of the checks decide the state.
    named_blockhash: str | None = None
    #: ``"checkpoint"`` (at or below the newest checkpoint) or ``"work"`` (above it).
    level: str | None = None
    checkpoint_height: int | None = None
    checkpoint_hash: str | None = None
    #: Distinct headers whose hash linkage was checked.
    linked_headers: int = 0
    #: For ``work``: floor(log2) of the minimum work each header above the checkpoint had to carry.
    floor_work_log2: int | None = None
    #: Blocks from the mark's block up to the highest one linked to it — the mark's block counts
    #: as 1 — once the height is established. At the checkpoint level this includes the blocks up
    #: to the newest checkpoint, which the table places on one chain.
    verified_depth: int | None = None
    #: ``((step, "passed" | "failed" | "not run"), ...)`` in the order they run; the ``blockhash``
    #: step is ``"passed"``, ``"differs"`` (see ``named_blockhash``) or ``"not run"``, never
    #: ``"failed"``.
    steps: tuple[tuple[str, str], ...] = ()


_STEPS = ("tree_depth", "merkle", "blockhash", "linkage", "proof_of_work", "floor", "burial")


class _Stop(Exception):
    """Internal: ends verification with a state and reason."""

    def __init__(self, state: str, reason: str) -> None:
        super().__init__(reason)
        self.state = state
        self.reason = reason


def _table(network: Any, checkpoints: Sequence[tuple[int, str]] | None) -> tuple[tuple[int, str], ...]:
    """The checkpoint table to use. A caller-supplied one is validated (a programming error raises)."""
    if checkpoints is None:
        return CHECKPOINTS.get(network, ()) if isinstance(network, str) else ()
    out = tuple(checkpoints)
    last = -1
    for entry in out:
        if not (isinstance(entry, tuple) and len(entry) == 2):
            raise ValidationError("each checkpoint must be a (height, hash) pair")
        h, bh = entry
        if not isinstance(h, int) or isinstance(h, bool) or h <= last:
            raise ValidationError("checkpoint heights must be ints in strictly ascending order")
        if not isinstance(bh, str) or not _HEX64.match(bh):
            raise ValidationError("checkpoint hashes must be 64 lowercase hex characters")
        last = h
    return out


def _require_min_confirmations(min_confirmations: Any) -> int:
    if not isinstance(min_confirmations, int) or isinstance(min_confirmations, bool) or min_confirmations < 1:
        raise ValidationError("min_confirmations must be an int >= 1 (the block itself counts as 1); it has no default")
    return min_confirmations


def _is_height(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= BlockHeight.MAX


def _chunks(start: int, stop_inclusive: int) -> list[tuple[int, int]]:
    out = []
    h = start
    while h <= stop_inclusive:
        n = min(MAX_HEADERS_PER_REQUEST, stop_inclusive - h + 1)
        out.append((h, n))
        h += n
    return out


def _require_target(target_confirmations: Any) -> int | None:
    if target_confirmations is None:
        return None
    if not isinstance(target_confirmations, int) or isinstance(target_confirmations, bool) or target_confirmations < 1:
        raise ValidationError("target_confirmations must be None or an int >= 1 (the block itself counts as 1)")
    return target_confirmations


def _top(height: int, min_confirmations: int, target: int | None, newest_h: int) -> int:
    """The highest block to fetch and check: the REQUIRED top (``height + min_confirmations - 1``),
    raised toward the target's — but never past :data:`MAX_HEADERS_FROM_CHECKPOINT` above the newest
    checkpoint, so an optional target can never turn a verifiable block into "needs a newer
    pyrxd". With no target (the CLI) it is the required top, exactly as before targets existed."""
    required = height + min_confirmations - 1
    if target is None or target <= min_confirmations:
        return required
    return max(required, min(height + target - 1, newest_h + MAX_HEADERS_FROM_CHECKPOINT))


def _plan(
    height: Any, min_confirmations: int, table: tuple[tuple[int, str], ...], target: int | None = None
) -> BlockFetchPlan:
    if not _is_height(height):
        return BlockFetchPlan(None, (), None, f"no usable block height to verify (got {type(height).__name__})")
    if not table:
        return BlockFetchPlan(height, (), None, "this pyrxd ships no checkpoints for this network")
    newest_h = table[-1][0]
    # The REQUIRED top decides "needs a newer pyrxd"; the fetch then reaches toward the target.
    top = height + min_confirmations - 1
    ranges: list[tuple[int, int]] = []
    if height <= newest_h:
        level = "checkpoint"
        idx = bisect.bisect_left([h for h, _ in table], height)
        above_h = table[idx][0]
        if above_h - height > MAX_HEADERS_FROM_CHECKPOINT:
            return BlockFetchPlan(
                height, (), None, f"no checkpoint within {MAX_HEADERS_FROM_CHECKPOINT} blocks above block {height}"
            )
        ranges += _chunks(height, above_h)
    else:
        level = "work"
    if top - newest_h > MAX_HEADERS_FROM_CHECKPOINT:
        return BlockFetchPlan(
            height,
            (),
            None,
            f"block {top} is {top - newest_h} blocks past this pyrxd's newest checkpoint ({newest_h}); "
            f"it links at most {MAX_HEADERS_FROM_CHECKPOINT} — needs a newer pyrxd",
        )
    top = _top(height, min_confirmations, target, newest_h)
    if top > newest_h:
        ranges += _chunks(newest_h, top)
    return BlockFetchPlan(height, tuple(ranges), level, None)


def plan_block_verification(
    *,
    height: Any,
    min_confirmations: int,
    target_confirmations: int | None = None,
    network: str = "mainnet",
    checkpoints: Sequence[tuple[int, str]] | None = None,
) -> BlockFetchPlan:
    """Which headers to fetch to verify the block at *height* — decided here, not by the caller.

    Total over *height* (it is the endpoint's claim). ``checkpoints`` defaults to the shipped table
    for *network*; tests pass their own. ``target_confirmations``: how deep to try beyond the
    REQUIRED ``min_confirmations`` (see the module docstring); ``None`` asks for the required depth
    only.
    """
    return _plan(
        height,
        _require_min_confirmations(min_confirmations),
        _table(network, checkpoints),
        _require_target(target_confirmations),
    )


def _header(headers: Mapping[Any, Any], h: int) -> bytes:
    got = headers.get(h)
    if got is None:
        raise _Stop(NOT_VERIFIED, f"the header at height {h} was not available")
    if not isinstance(got, (bytes, bytearray)) or len(got) != 80:
        raise _Stop(NOT_VERIFIED, f"the reply for the header at height {h} is not an 80-byte header")
    return bytes(got)


def _hashes_to(header: Any, want: str) -> bool:
    """Whether *header* is an 80-byte header whose hash is *want*."""
    return isinstance(header, (bytes, bytearray)) and len(header) == 80 and radiant_block_hash(bytes(header)) == want


def _extends(header: Any, below: str, floor: int) -> bool:
    """Whether *header* passes every check a header above the newest checkpoint must: 80 bytes,
    naming *below* as its previous block, meeting its own target, carrying the floor's work.

    Asked only of a header PAST the required depth (``target_confirmations``), before the checks
    that would fail the proof: there, a header that does not pass ends the proved run instead."""
    if not isinstance(header, (bytes, bytearray)) or len(header) != 80:
        return False
    header = bytes(header)
    if radiant_header_prev_hash(header) != below:
        return False
    try:
        verify_radiant_header_pow(header)
    except (SpvVerificationError, ValidationError):
        return False
    return radiant_header_work(header) >= floor


def _coinbase_branch(reply: Any, height: int) -> tuple[str, tuple[str, ...]]:
    """``(coinbase txid, branch)`` from an ``id_from_pos(height, 0, true)`` reply, shape-checked only."""
    if reply is None:
        raise _Stop(NOT_VERIFIED, "no coinbase merkle branch was supplied, so the tree's depth is unknown")
    if not isinstance(reply, Mapping):
        raise _Stop(NOT_VERIFIED, "the coinbase merkle reply is malformed: not an object")
    tx_hash, branch = reply.get("tx_hash"), reply.get("merkle")
    if not isinstance(tx_hash, str) or not _HEX64.match(tx_hash.lower()):
        raise _Stop(NOT_VERIFIED, "the coinbase merkle reply is malformed: no usable tx_hash")
    try:
        parsed = TxMerkleBranch.from_electrumx({"block_height": height, "merkle": branch, "pos": 0})
    except ValidationError as exc:
        raise _Stop(NOT_VERIFIED, f"the coinbase merkle reply is malformed: {exc}") from None
    return tx_hash.lower(), parsed.branch


def verify_mark_block(
    *,
    txid: Any,
    raw_tx: Any,
    height: Any,
    merkle: TxMerkleBranch | Mapping[str, Any] | None,
    coinbase_merkle: Mapping[str, Any] | None,
    headers: Mapping[int, bytes],
    min_confirmations: int,
    blockhash: Any = None,
    network: str = "mainnet",
    checkpoints: Sequence[tuple[int, str]] | None = None,
    target_confirmations: int | None = None,
) -> BlockVerification:
    """Verify that *txid* is in the block at *height*, anchored to a shipped checkpoint.

    *raw_tx* is the transaction's bytes; *merkle* is a :class:`~pyrxd.spv.radiant.TxMerkleBranch`
    or the raw ``blockchain.transaction.get_merkle`` dict; *coinbase_merkle* is the raw
    ``blockchain.transaction.id_from_pos(height, 0, true)`` dict (``tx_hash`` and ``merkle``) for
    the same block, which pins the tree's depth — it has no default, so no caller can skip it;
    *headers* maps height to raw 80-byte
    header, covering :func:`plan_block_verification`'s ranges; *blockhash*, when given, is the
    block hash the endpoint named for the transaction (verbose ``blockhash``). When it is not the
    hash of the header served at *height*, that alone decides nothing: the header served is
    checked like any other (inclusion, linkage to a checkpoint), and VERIFIED then reports the
    header served as the block proved, with ``named_blockhash`` and a sentence in the claim saying
    the endpoint had named another. If that header fails a check, the state is whatever the check
    says, and the reason notes the different name too.

    *min_confirmations* is REQUIRED; *target_confirmations* is how deep to try past it, and never
    turns a proof that reached the required depth into anything but VERIFIED (module docstring).

    Never raises on server data — see the module docstring for the states and what each claims.
    """
    table = _table(network, checkpoints)
    min_conf = _require_min_confirmations(min_confirmations)
    target = _require_target(target_confirmations)
    steps = dict.fromkeys(_STEPS, "not run")
    facts: dict[str, Any] = {"height": height if _is_height(height) else None}

    def done(state: str, reason: str | None = None, claim: str | None = None) -> BlockVerification:
        return BlockVerification(
            state=state, claim=claim, reason=reason, steps=tuple((s, steps[s]) for s in _STEPS), **facts
        )

    try:
        claim = _verify(
            txid=txid,
            raw_tx=raw_tx,
            height=height,
            merkle=merkle,
            coinbase_merkle=coinbase_merkle,
            headers=headers,
            min_conf=min_conf,
            target=target,
            blockhash=blockhash,
            table=table,
            steps=steps,
            facts=facts,
        )
    except _Stop as stop:
        reason = stop.reason
        if steps["blockhash"] == "differs":
            reason += "; the endpoint had also named a different block for the transaction than the header served"
        return done(stop.state, reason)
    except Exception as exc:  # the totality net; the property tests assert it never fires
        return done(NOT_VERIFIED, f"{_INTERNAL}: {type(exc).__name__})")
    return done(VERIFIED, claim=claim)


def _verify(
    *,
    txid: Any,
    raw_tx: Any,
    height: Any,
    merkle: Any,
    coinbase_merkle: Any,
    headers: Any,
    min_conf: int,
    target: int | None,
    blockhash: Any,
    table: tuple[tuple[int, str], ...],
    steps: dict[str, str],
    facts: dict[str, Any],
) -> str:
    """Run every check; return the VERIFIED claim, or raise :class:`_Stop` with the outcome."""
    plan = _plan(height, min_conf, table, target)
    if plan.reason is not None:
        raise _Stop(NOT_VERIFIED, plan.reason)
    facts["level"] = plan.level
    if not isinstance(headers, Mapping):
        raise _Stop(NOT_VERIFIED, "no headers were supplied")
    if not isinstance(txid, str) or not _HEX64.match(txid.lower()):
        raise _Stop(NOT_VERIFIED, "no usable txid")
    txid = txid.lower()

    # 1. inclusion: the raw tx hashes to the txid, and its branch leads to header[H]'s merkle root.
    if merkle is None:
        raise _Stop(NOT_VERIFIED, "no merkle branch was supplied")
    if not isinstance(merkle, TxMerkleBranch):
        try:
            merkle = TxMerkleBranch.from_electrumx(merkle)
        except ValidationError as exc:
            raise _Stop(NOT_VERIFIED, f"the merkle reply is malformed: {exc}") from None
    if merkle.block_height != height:
        steps["merkle"] = "failed"
        raise _Stop(CONTRADICTED, f"the merkle branch is for block {merkle.block_height}, not block {height}")
    if merkle.pos == 0:
        raise _Stop(NOT_VERIFIED, "the transaction is at position 0 (a coinbase), which this check does not accept")
    if not isinstance(raw_tx, (bytes, bytearray)):
        raise _Stop(NOT_VERIFIED, "no raw transaction bytes were supplied")
    header_h = _header(headers, height)

    # 1a. the tree's depth, from the coinbase's branch in the same block (see the module docstring).
    cb_txid, cb_branch = _coinbase_branch(coinbase_merkle, height)
    if compute_root(cb_txid, build_branch(list(cb_branch), 0)) != extract_merkle_root(header_h):
        steps["tree_depth"] = "failed"
        raise _Stop(CONTRADICTED, f"the coinbase's merkle branch does not lead to block {height}'s merkle root")
    if len(merkle.branch) != len(cb_branch):
        steps["tree_depth"] = "failed"
        raise _Stop(
            CONTRADICTED,
            f"the transaction's merkle branch is {len(merkle.branch)} level(s) deep, but block {height}'s "
            f"tree is {len(cb_branch)} deep (its coinbase's branch)",
        )
    steps["tree_depth"] = "passed"

    # NOT refused here: a sibling equal to the running hash. ElectrumX's honest branch for the last
    # transaction of an odd-width level duplicates it (the merkle duplicate-last rule), so refusing
    # it would refuse real marks. CVE-2012-2459 cannot prove a transaction that is absent here:
    # the root is pinned by a header that must also link to a checkpoint.
    try:
        verify_tx_in_block(
            bytes(raw_tx),
            txid,
            build_branch(list(merkle.branch), merkle.pos),
            merkle.pos,
            header_h,
            expected_depth=len(cb_branch),
        )
    except SpvVerificationError as exc:
        steps["merkle"] = "failed"
        raise _Stop(CONTRADICTED, f"merkle inclusion failed: {exc}") from None
    steps["merkle"] = "passed"

    # 2. the endpoint's named block, when it named one. A DIFFERENT name is recorded, not refused:
    # the name and the header come from different replies, and a reorganisation between them (the
    # transaction re-mined at the same height in a replacement block) makes them differ with no
    # one lying. Nothing below trusts the name — the header served is checked on its own, and it
    # is that header, never the name, that VERIFIED reports — so a stale name cannot make a false
    # VERIFIED, and refusing on it alone would refuse an honest mark.
    mark_hash = radiant_block_hash(header_h)
    facts["blockhash"] = mark_hash
    if blockhash is not None:
        named = blockhash.lower() if isinstance(blockhash, str) else None
        if named == mark_hash:
            steps["blockhash"] = "passed"
        else:
            steps["blockhash"] = "differs"
            facts["named_blockhash"] = named if named is not None and _HEX64.match(named) else None

    # 3. linkage to a checkpoint.
    heights = [h for h, _ in table]
    newest_h, newest_hash = table[-1]
    required_top = height + min_conf - 1
    top = _top(height, min_conf, target, newest_h)
    linked: set[int] = set()

    def link(lo: int, hi: int) -> None:
        """headers lo..hi each name the one below as their previous block."""
        below = radiant_block_hash(_header(headers, lo))
        linked.add(lo)
        for h in range(lo + 1, hi + 1):
            hdr = _header(headers, h)
            if radiant_header_prev_hash(hdr) != below:
                steps["linkage"] = "failed"
                raise _Stop(CONTRADICTED, f"the header at {h} does not link to the header served at {h - 1}")
            below = radiant_block_hash(hdr)
            linked.add(h)

    def anchor(h: int, want: str) -> None:
        if radiant_block_hash(_header(headers, h)) != want:
            steps["linkage"] = "failed"
            raise _Stop(CONTRADICTED, f"the header served at {h} is not pyrxd's checkpoint for that height")

    if plan.level == "checkpoint":
        cp_h, cp_hash = table[bisect.bisect_left(heights, height)]
        facts.update(checkpoint_height=cp_h, checkpoint_hash=cp_hash)
        link(height, cp_h)
        anchor(cp_h, cp_hash)
        steps["linkage"] = "passed"
        facts["linked_headers"] = len(linked)
        facts["verified_depth"] = newest_h - height + 1
    else:
        facts.update(checkpoint_height=newest_h, checkpoint_hash=newest_hash)

    # 4. above the newest checkpoint: linkage from it, each header's own PoW, and the floor. When
    # only the TARGET reaches above it (a block just below the newest checkpoint), this is extra
    # depth, and nothing here can fail the proof: it runs only from the checkpoint's own header,
    # and records these steps only if it linked a header above it.
    required_above = required_top > newest_h
    if top > newest_h and (required_above or _hashes_to(headers.get(newest_h), newest_hash)):
        anchor(newest_h, newest_hash)
        floor = radiant_header_work(_header(headers, newest_h)) // FLOOR_WORK_DIVISOR
        below = newest_hash
        linked.add(newest_h)
        reached = newest_h
        for h in range(newest_h + 1, top + 1):
            got = headers.get(h)
            if got is None and h > height:
                break  # burial shortfall, judged below
            if h > required_top and not _extends(got, below, floor):
                break  # past the REQUIRED depth: the proved run ends here, and that is no finding
            hdr = _header(headers, h)
            if radiant_header_prev_hash(hdr) != below:
                steps["linkage"] = "failed"
                raise _Stop(CONTRADICTED, f"the header at {h} does not link to the header served at {h - 1}")
            try:
                below = verify_radiant_header_pow(hdr)
            except (SpvVerificationError, ValidationError) as exc:
                steps["proof_of_work"] = "failed"
                raise _Stop(CONTRADICTED, f"the header at {h} fails its own proof-of-work: {exc}") from None
            steps["proof_of_work"] = "passed"  # so far: every header up to this one
            if radiant_header_work(hdr) < floor:
                steps["floor"] = "failed"
                raise _Stop(
                    NOT_VERIFIED,
                    f"the header at {h} carries less work than the floor (1/{FLOOR_WORK_DIVISOR} of "
                    f"checkpoint {newest_h}'s); its difficulty may be honest, but it does not verify here",
                )
            linked.add(h)
            reached = h
        if required_above or reached > newest_h:
            facts["floor_work_log2"] = floor.bit_length() - 1
            steps["linkage"] = "passed"
            steps["proof_of_work"] = "passed"
            steps["floor"] = "passed"
            facts["linked_headers"] = len(linked)
            depth = reached - height + 1
            if plan.level == "checkpoint":
                depth = max(depth, newest_h - height + 1)
            facts["verified_depth"] = depth

    # 5. burial.
    if facts["verified_depth"] < min_conf:
        steps["burial"] = "failed"
        raise _Stop(
            NOT_VERIFIED,
            f"only {facts['verified_depth']} of the {min_conf} required blocks could be verified",
        )
    steps["burial"] = "passed"

    if plan.level == "checkpoint":
        claim = (
            f"The transaction is in block {height}: its merkle branch leads to that block's header, and "
            f"that header is linked hash by hash to block {facts['checkpoint_height']}, a checkpoint "
            f"shipped with pyrxd. The height rests on that checkpoint, not on any server."
        )
    else:
        claim = (
            f"The transaction is in block {height}: its merkle branch leads to that block's header, and "
            f"that header is linked hash by hash to block {newest_h}, a checkpoint shipped with pyrxd, "
            f"through {height - newest_h} header(s), each meeting its own proof-of-work target and carrying "
            f"at least 2^{facts['floor_work_log2']} expected hash evaluations. A server lying about this "
            f"height could reuse the real headers below it; it would have had to mine the "
            f"{facts['verified_depth']} header(s) from block {height} up, at that work or more. pyrxd does "
            f"not check that they are Radiant's most-work chain, or that each difficulty is the one "
            f"Radiant's rules require."
        )
    if steps["blockhash"] == "differs":
        named = facts.get("named_blockhash")
        claim += (
            f" The endpoint had named a different block for the transaction"
            f"{f' ({named})' if named else ''}; the block proved is {facts['blockhash']}, the header served "
            f"for block {height} when the proof was fetched, as a chain reorganisation between the two "
            f"replies would leave it."
        )
    return claim


# ── ONE FETCH ORDER, ONE SET OF SENTENCES, for every surface ────────────────────────────────────
#
# ``pyrxd verify`` fetches with an async client; the browser pages fetch with a WebSocket in
# JavaScript and hand the answers to a SYNCHRONOUS Python bridge. Both walk the same sequence
# (:func:`block_fetches`) and decide through the same function (:func:`verify_with_fetched`), so
# the order, what counts as "could not be fetched", and every sentence a reader sees come from
# here once — the CLI and the pages cannot word the same outcome two ways.

#: What each fetch is called in a "could not be fetched" reason.
MERKLE_FETCH = "the transaction's merkle branch"
COINBASE_FETCH = "the block's coinbase merkle branch"


def _headers_fetch(start: int, count: int) -> str:
    return f"the block headers {start}-{start + count - 1}"


@dataclass(frozen=True)
class BlockFetch:
    """One ElectrumX request :func:`verify_with_fetched` still needs, and how to name it.

    ``key`` is ``"merkle"``, ``"coinbase"`` or ``"headers:<start>:<count>"``: the name the answer
    is handed back under. ``method`` and ``params`` are the JSON-RPC call, exactly — the caller
    only sends it. ``what`` names it in a reason.
    """

    key: str
    method: str
    params: tuple[Any, ...]
    what: str


def block_fetches(plan: BlockFetchPlan, txid: str) -> tuple[BlockFetch, ...]:
    """Every request *plan* needs, in the order they are made: the transaction's merkle branch,
    the block's coinbase branch (which pins the tree's depth), then each header range in the
    plan's order. Empty when the plan has a reason (nothing fetched could verify)."""
    if plan.reason is not None or plan.height is None:
        return ()
    h = plan.height
    out = [
        BlockFetch("merkle", "blockchain.transaction.get_merkle", (txid, h), MERKLE_FETCH),
        BlockFetch("coinbase", "blockchain.transaction.id_from_pos", (h, 0, True), COINBASE_FETCH),
    ]
    for start, count in plan.header_ranges:
        out.append(
            BlockFetch(
                f"headers:{start}:{count}", "blockchain.block.headers", (start, count), _headers_fetch(start, count)
            )
        )
    return tuple(out)


def could_not_fetch(what: str, *, source: Any, detail: Any, height: Any) -> BlockVerification:
    """NOT VERIFIED because *what* could not be fetched from *source* — a server that lacks the
    method, a request that timed out, a reply refused as malformed. Never a finding against the
    mark: the height falls back to the endpoint's word, with this reason. *source* and *detail*
    are sanitised here, for every surface."""
    from ._inspect_core import _sanitize_display_string  # lazy: this module stays import-light

    return BlockVerification(
        state=NOT_VERIFIED,
        claim=None,
        reason=f"{what} could not be fetched from {_sanitize_display_string(str(source))}: "
        f"{_sanitize_display_string(str(detail))}",
        height=height if _is_height(height) else None,
    )


def verify_with_fetched(
    *,
    txid: Any,
    raw_tx: Any,
    height: Any,
    blockhash: Any,
    min_confirmations: int,
    source: Any,
    fetched: Mapping[str, Any],
    failed: Mapping[str, Any],
    network: str = "mainnet",
    checkpoints: Sequence[tuple[int, str]] | None = None,
    target_confirmations: int | None = None,
) -> BlockVerification | BlockFetch:
    """The next :class:`BlockFetch` still needed, or the outcome once nothing is.

    SYNCHRONOUS AND NEVER SUSPENDS: the browser bridge calls it without an event loop, once per
    answer, and the CLI calls it in a loop around its own awaited fetches.

    *fetched* maps a :attr:`BlockFetch.key` to the PARSED answer — a
    :class:`~pyrxd.spv.radiant.TxMerkleBranch` for ``merkle``, the dict
    :func:`~pyrxd.spv.radiant.coinbase_branch_from_reply` returns for ``coinbase``, the list of
    80-byte headers :func:`~pyrxd.spv.radiant.block_headers_from_reply` returns for a range.
    *failed* maps a key to why that fetch failed. The requests are walked in
    :func:`block_fetches` order and the FIRST that failed ends it: :func:`could_not_fetch`, naming
    *source*. When the plan says nothing can verify (no checkpoints, too far past the newest one),
    or there is no txid, nothing is asked for and the verifier states the reason.

    *min_confirmations* is required and *target_confirmations* only aimed for, as in
    :func:`verify_mark_block`; ``pyrxd verify`` passes no target, the pages pass one.
    """

    def outcome(merkle: Any = None, coinbase: Any = None, headers: Any = None) -> BlockVerification:
        return verify_mark_block(
            txid=txid,
            raw_tx=raw_tx,
            height=height,
            merkle=merkle,
            coinbase_merkle=coinbase,
            headers=headers or {},
            min_confirmations=min_confirmations,
            blockhash=blockhash,
            network=network,
            checkpoints=checkpoints,
            target_confirmations=target_confirmations,
        )

    plan = plan_block_verification(
        height=height,
        min_confirmations=min_confirmations,
        target_confirmations=target_confirmations,
        network=network,
        checkpoints=checkpoints,
    )
    if plan.reason is not None or not txid:
        return outcome()
    merkle = coinbase = None
    headers: dict[int, bytes] = {}
    for step in block_fetches(plan, str(txid)):
        if step.key in failed:
            return could_not_fetch(step.what, source=source, detail=failed[step.key], height=height)
        if step.key not in fetched:
            return step
        got = fetched[step.key]
        if step.key == "merkle":
            merkle = got
        elif step.key == "coinbase":
            coinbase = got
        else:
            start = step.params[0]
            for i, header in enumerate(got or ()):
                headers.setdefault(start + i, header)
    return outcome(merkle, coinbase, headers)


#: Said beside every CONTRADICTED outcome, on every surface: an honest mark served by a confused or
#: lying server gets one too.
NOTHING_AGAINST_THE_MARK = (
    "this says nothing against the mark itself, only that the server's own proof does not support "
    "the height it reported"
)


def contradicted_sentence(height: Any, source: Any, reason: Any) -> str:
    """Why no block is reported for a CONTRADICTED outcome — one sentence for the CLI and the pages."""
    return f"the block proof {source or 'the endpoint'} served contradicts the height reported for the mark (block {height}): {reason}"

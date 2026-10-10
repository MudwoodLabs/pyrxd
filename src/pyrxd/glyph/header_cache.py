"""A cache of verified Radiant headers, extending a shipped checkpoint forward (#826, phase 1).

WHY. :mod:`pyrxd.glyph.mark_block` links a mark's block at most
:data:`~pyrxd.glyph.mark_block.MAX_HEADERS_FROM_CHECKPOINT` headers past its anchor. With only the
shipped checkpoints as anchors, a release stops verifying new marks about two weeks after its
newest checkpoint. This cache holds headers this machine has already linked to that checkpoint,
so verification can link forward from the newest cached header instead, with the same cap.

NOTHING NEW IS TRUSTED. Every cached header is linked hash by hash to the newest checkpoint shipped
with pyrxd, meets its own proof-of-work target, and carries at least the floor (below). The two
rules that decide what may ENTER the cache are applied by :func:`agreed_headers` and the caller's
depth bound (``pyrxd headers sync``): a header is cached only when at least
:data:`MIN_OPERATORS` distinct operators served it byte for byte alike, and only when it sits at
least :data:`CACHE_MIN_DEPTH` blocks below the lowest tip any of them reported.

THE FLOOR. Each cached header, and each header :mod:`~pyrxd.glyph.mark_block` links above a cached
anchor, must carry at least ``W // FLOOR_WORK_DIVISOR`` expected hash evaluations, where:

* while syncing (:func:`sync_floor`), ``W`` is the GREATER of the newest shipped checkpoint's work
  and the median work of the newest :data:`RECENT_WINDOW` headers ALREADY in the cache when the
  sync starts. It is computed once per sync, so the headers being added in that sync neither raise
  nor lower their own bar, and a median rather than a maximum, so one high-work header cannot
  strand an honest sync;
* when the cache is read back, ``W`` is the newest shipped checkpoint's work: the invariant every
  cached header must keep, whatever bar it was admitted under;
* while verifying from a cached anchor, ``W`` is the GREATER of that checkpoint's work and the
  anchor's own.

So no floor is ever below 1/16 of the newest shipped checkpoint's work. Cached headers can hold
it above that, and as they change from one sync to the next the sync floor moves up or down with
them, but never below that bound.

THE HONEST-PATH LIMIT, plainly. ``pyrxd headers sync`` stops at the first header whose work is below
the sync floor; it caches the agreed headers under it, reports ``stopped``, and says what gets past
that header, as :func:`floor_stop_advice` COMPUTES it from the cache it left: a plain re-run, when
the headers it added moved the floor to or below that header's work; ``pyrxd headers sync
--reset``, when the shipped checkpoint's floor admits the header; otherwise only a newer pyrxd
release. Until then, marks above that header verify only from the shipped checkpoint, within its
4,032 headers. Within one verification walk (at most 4,032 headers above a cached anchor) the floor
rests on the anchor's work when that is higher, as it rests on a checkpoint's; and when a server
disagrees with the cache, the fallback walk from the checkpoint keeps that floor for EVERY header
above the checkpoint, including those below the cached anchor, which neither the agreeing walk nor
a walk with no cache holds to it.

HOW CLOSE HONEST HEADERS COME (``scripts/measure_header_floor_margins.py``, which states its method;
run 2026-10-07, read-only from a default public server, over the 370,601 linked mainnet headers
from block 100,000 to 470,600). Each figure is the worst, over the range, of ``W / (the least work
of a header the rule would have to pass)``, taking the worst case over whatever the script does not
model; 16 or more would mean an honest header was held back. Every floor is ``max(W_C, X) // 16``.
The fallback row computes exactly that; the sync and verify rows measure the ``X`` part alone, and
the checkpoint rows the ``W_C`` part, so a full rule's worst is at most the larger of its row and the
checkpoint row over the release's life.

* sync, ``X`` = the median of the 2,016 cached headers before a span starting at every height:
  3.64 over spans of 4,032 blocks, 3.48 over spans of 8,640 that fit in the range;
* verify, ``X`` = the anchor's work, every height as the anchor, over the 4,032 headers above it: 3.91;
* the fallback after a disagreement, ``max(W_C, the worst cached anchor within 4,032 headers of the
  checkpoint)`` against every header in that walk: 3.84 for every checkpoint height, 4.57 for every
  height;
* the shipped checkpoint's work against the headers after it, for every checkpoint height: 3.48
  over 8,640 blocks, and 7.94 over 25,920 blocks (about three months).

So the per-sync, per-anchor and fallback rules kept more than three times their margin over this
range, while the checkpoint bound, which every floor keeps, used half of it within three months: a
release whose checkpoint is months old can come within reach of its limit if difficulty keeps
falling, and then needs a newer pyrxd.

PURE. Nothing here touches a file or the network: the CLI's store
(:mod:`pyrxd.cli.header_store`) reads and writes the bytes :func:`encode_store` produces, and the
browser pages can keep the same bytes in IndexedDB.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any

from pyrxd.hash import radiant_block_hash
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.radiant import radiant_header_prev_hash, radiant_header_work, verify_radiant_header_pow
from pyrxd.spv.radiant_checkpoints import MIN_DEPTH_BELOW_TIP

# The floor divisor has ONE source, ``mark_block.FLOOR_WORK_DIVISOR``, read at call time (never
# imported by value), so the cache and the verifier cannot hold different divisors.
from . import mark_block as _mark_block

__all__ = [
    "CACHE_MIN_DEPTH",
    "MIN_OPERATORS",
    "RECENT_WINDOW",
    "HeaderCacheRefusal",
    "HeaderStoreCorrupt",
    "VerifiedHeaders",
    "agreed_headers",
    "decode_store",
    "encode_store",
    "extend_verified_headers",
    "floor_stop_advice",
    "start_verified_headers",
    "sync_floor",
    "verify_header_chain",
]

#: How far below the LOWEST tip any source reported a header must sit before it is cached: the
#: checkpoint refresh's own minimum depth (``scripts/refresh_radiant_checkpoints.py``), the same
#: number, so a cached header is held to the depth a shipped checkpoint is.
CACHE_MIN_DEPTH = MIN_DEPTH_BELOW_TIP

#: How many of the newest cached headers :func:`sync_floor` takes the median work of.
RECENT_WINDOW = 2016

#: Distinct OPERATORS (:func:`pyrxd.network.source_identity.source_key`; two hosts of one operator
#: are one) that must serve a header byte for byte alike before it is cached.
MIN_OPERATORS = 2

_MAGIC = b"pyrxd-header-cache\n"
_VERSION = 1
#: Sync records kept in the store's metadata (the newest ones). Provenance only: nothing reads
#: them to decide anything.
_MAX_SYNC_RECORDS = 64

#: Seals issued by the verifying functions and not yet used. Each seal admits exactly ONE
#: construction: ``dataclasses.replace`` (which re-runs ``__init__`` with the same seal) is refused.
_UNUSED_SEALS: set[object] = set()


def _issue_seal() -> object:
    seal = object()
    _UNUSED_SEALS.add(seal)
    return seal


class HeaderCacheRefusal(Exception):
    """Sources disagreed, too few operators answered, or a served header is a lie (a broken link,
    a failed proof-of-work). Nothing is cached when this is raised."""


class HeaderStoreCorrupt(Exception):
    """The stored bytes are not a header store this pyrxd wrote. The store is then treated as EMPTY."""


@dataclass(frozen=True)
class VerifiedHeaders:
    """Headers linked hash by hash from the newest shipped checkpoint, each above it checked.

    ``headers[0]`` is the checkpoint's own header (``base_height == checkpoint_height``); every
    later header names the one before it, meets its own proof-of-work target and carries at least
    :attr:`floor_work`. Built ONLY by :func:`verify_header_chain`, :func:`extend_verified_headers`
    and :func:`start_verified_headers`: constructing one directly, or deriving one with
    ``dataclasses.replace``, raises (each seal admits one construction), so a :class:`VerifiedHeaders`
    is always a checked one.
    """

    network: str
    checkpoint_height: int
    checkpoint_hash: str
    headers: tuple[bytes, ...]
    hashes: tuple[str, ...]
    #: ``work(checkpoint header) // FLOOR_WORK_DIVISOR``: the floor every cached header met.
    floor_work: int
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            _UNUSED_SEALS.remove(self._seal)
        except KeyError:
            raise ValidationError(
                "VerifiedHeaders is built only by verify_header_chain() or extend_verified_headers()"
            ) from None

    @property
    def base_height(self) -> int:
        return self.checkpoint_height

    @property
    def top(self) -> int:
        """The height of the newest cached header."""
        return self.checkpoint_height + len(self.headers) - 1

    @property
    def checkpoint_header(self) -> bytes:
        return self.headers[0]

    def header_at(self, height: int) -> bytes:
        return self.headers[height - self.checkpoint_height]

    def hash_at(self, height: int) -> str:
        return self.hashes[height - self.checkpoint_height]

    def covers(self, height: int) -> bool:
        return self.checkpoint_height <= height <= self.top


def _require_table(table: Sequence[tuple[int, str]]) -> tuple[tuple[int, str], ...]:
    out = tuple(table)
    if not out:
        raise ValidationError("a header cache needs a shipped checkpoint table for its network")
    return out


def _floor_of(work: int) -> int:
    """``work // mark_block.FLOOR_WORK_DIVISOR``, EXACTLY. The divisor ships as the int 16; a test
    may set an exact :class:`~fractions.Fraction` to emulate a work ratio real headers cannot show. A
    float is refused: ``int(W // 16.0)`` rounds real work (about 2**56) and can come out one too high."""
    d = _mark_block.FLOOR_WORK_DIVISOR
    if isinstance(d, bool) or not isinstance(d, (int, Fraction)) or d <= 0:
        raise ValidationError(f"FLOOR_WORK_DIVISOR must be a positive int (or an exact Fraction), not {d!r}")
    return int(work // d)


def _walk(
    below_hash: str,
    start: int,
    headers: Sequence[Any],
    floor: int,
    *,
    pow_limit: int | None,
    floor_of: str = "the newest shipped checkpoint's",
) -> tuple[list[str], str | None, str | None]:
    """Check *headers* (heights ``start``, ``start+1``, ...) above a header hashing to *below_hash*.

    Returns ``(hashes of the accepted prefix, kind, reason)``. ``kind`` is ``None`` when every
    header passed; ``"lie"`` for a header that is not 80 bytes, does not link to the one below it,
    or fails its own proof-of-work (no honest source serves one); ``"floor"`` for a header below
    the floor, where the accepted prefix ends (an honest difficulty drop can do that).
    """
    hashes: list[str] = []
    below = below_hash
    for i, hdr in enumerate(headers):
        h = start + i
        if not isinstance(hdr, (bytes, bytearray)) or len(hdr) != 80:
            return hashes, "lie", f"the header at {h} is not an 80-byte header"
        hdr = bytes(hdr)
        if radiant_header_prev_hash(hdr) != below:
            return hashes, "lie", f"the header at {h} does not link to the header at {h - 1}"
        try:
            got = verify_radiant_header_pow(hdr, pow_limit=pow_limit)
        except (SpvVerificationError, ValidationError) as exc:
            return hashes, "lie", f"the header at {h} fails its own proof-of-work: {exc}"
        if radiant_header_work(hdr, pow_limit=pow_limit) < floor:
            return (
                hashes,
                "floor",
                f"the header at {h} carries less work than the floor (1/{_mark_block.FLOOR_WORK_DIVISOR} of "
                f"{floor_of}); its difficulty may be honest, but it is not cached",
            )
        hashes.append(got)
        below = got
    return hashes, None, None


def verify_header_chain(
    network: str,
    base_height: int,
    headers: Sequence[Any],
    *,
    table: Sequence[tuple[int, str]],
    pow_limit: int | None = None,
) -> tuple[VerifiedHeaders | None, str | None]:
    """Re-check stored headers against the shipped *table*: ``(verified, why not all of them)``.

    *headers* start at *base_height*, which must be a checkpoint in *table* whose hash the first
    header has. Every header links to the one below it; every checkpoint of *table* the headers
    reach must match; every header above the NEWEST checkpoint meets its own proof-of-work and the
    floor. The result is rebased onto the newest checkpoint (headers below it are dropped: the
    shipped table covers them).

    ``(None, reason)`` when the headers cannot be trusted at all (they do not start at a
    checkpoint, a link or a checkpoint does not match, a proof-of-work fails) or add nothing (they
    end at or below the newest checkpoint). A header below the floor ends the verified run there
    and is reported as the second element; the headers under it are kept.
    """
    table = _require_table(table)
    cp_h, cp_hash = table[-1]
    by_height = dict(table)
    if not headers:
        return None, "the store holds no headers"
    if base_height not in by_height:
        return None, f"the store starts at block {base_height}, which is not a checkpoint this pyrxd ships"
    first = headers[0]
    if (
        not isinstance(first, (bytes, bytearray))
        or len(first) != 80
        or radiant_block_hash(bytes(first)) != by_height[base_height]
    ):
        return None, f"the store's first header is not checkpoint {base_height}"
    top = base_height + len(headers) - 1
    if top < cp_h:
        return None, f"the store ends at block {top}, below this pyrxd's newest checkpoint ({cp_h})"
    # Below the newest checkpoint: linkage alone, pinned at every checkpoint (no proof-of-work is
    # needed there, as at mark_block's checkpoint level).
    below = by_height[base_height]
    for h in range(base_height + 1, cp_h + 1):
        hdr = headers[h - base_height]
        if not isinstance(hdr, (bytes, bytearray)) or len(hdr) != 80 or radiant_header_prev_hash(bytes(hdr)) != below:
            return None, f"the stored header at {h} does not link to the one below it"
        below = radiant_block_hash(bytes(hdr))
        if h in by_height and below != by_height[h]:
            return None, f"the stored header at {h} is not the checkpoint this pyrxd ships for that height"
    base = bytes(headers[cp_h - base_height])
    floor = _floor_of(radiant_header_work(base, pow_limit=pow_limit))
    above = headers[cp_h - base_height + 1 :]
    hashes, kind, reason = _walk(cp_hash, cp_h + 1, above, floor, pow_limit=pow_limit)
    if kind == "lie":
        return None, f"the store is not a verified chain: {reason}"
    kept = (base, *(bytes(x) for x in above[: len(hashes)]))
    return (
        VerifiedHeaders(
            network=network,
            checkpoint_height=cp_h,
            checkpoint_hash=cp_hash,
            headers=kept,
            hashes=(cp_hash, *hashes),
            floor_work=floor,
            _seal=_issue_seal(),
        ),
        reason,
    )


def sync_floor(chain: VerifiedHeaders) -> int:
    """The floor a sync from *chain* holds every new header to: never below the shipped checkpoint's.

    ``max(checkpoint work, median work of the newest RECENT_WINDOW cached headers) //
    FLOOR_WORK_DIVISOR``, from headers ALREADY verified into the cache. Compute it once, before the
    sync adds anything, and pass it to every :func:`extend_verified_headers` call of that sync.
    """
    recent = statistics.median_low(radiant_header_work(h) for h in chain.headers[-RECENT_WINDOW:])
    return _floor_of(max(radiant_header_work(chain.checkpoint_header), recent))


#: What gets a stopped sync past the header it stopped at, as :func:`floor_stop_advice` computes it.
ADVICE_RERUN, ADVICE_RESET, ADVICE_UPGRADE = "rerun", "reset", "upgrade"


def floor_stop_advice(chain: VerifiedHeaders, stopped_work: int) -> tuple[str, int]:
    """``(advice, next sync floor)`` for a sync that stopped at a header carrying *stopped_work*,
    *chain* being the cache as that sync left it. Computed, never assumed:

    * ``"rerun"`` when the floor a plain re-run would use (:func:`sync_floor` of *chain*: the headers
      the stopped sync added move the median) is at or below *stopped_work*;
    * else ``"reset"`` when a rebuild's first-sync floor, the shipped checkpoint's
      (:attr:`VerifiedHeaders.floor_work`), is at or below it. Every cached header above the
      checkpoint already meets that floor (the store invariant), so a rebuild reaches the header;
    * else ``"upgrade"``: no floor this release can use admits the header.
    """
    next_floor = sync_floor(chain)
    if stopped_work >= next_floor:
        return ADVICE_RERUN, next_floor
    if stopped_work >= chain.floor_work:
        return ADVICE_RESET, next_floor
    return ADVICE_UPGRADE, next_floor


def extend_verified_headers(
    chain: VerifiedHeaders, new: Sequence[Any], *, floor: int | None = None, pow_limit: int | None = None
) -> tuple[VerifiedHeaders, str | None]:
    """*chain* with *new* (heights ``chain.top + 1`` up) appended: ``(extended, why it stopped)``.

    Every new header must link to the one below it and meet its own proof-of-work, or this raises
    :class:`HeaderCacheRefusal` and nothing is added. One below the floor ends the extension there:
    the headers under it are added and the reason is returned. *floor* is the sync's
    (:func:`sync_floor`, computed before the sync added anything); it may never be below
    :attr:`~VerifiedHeaders.floor_work`, the shipped checkpoint's, which is the default.
    """
    if floor is None:
        floor, floor_of = chain.floor_work, "the newest shipped checkpoint's"
    elif floor < chain.floor_work:
        raise ValidationError("a sync floor may never be below the shipped checkpoint's (VerifiedHeaders.floor_work)")
    else:
        floor_of = "the greater of the newest shipped checkpoint's and the recent cached median"
    hashes, kind, reason = _walk(chain.hashes[-1], chain.top + 1, new, floor, pow_limit=pow_limit, floor_of=floor_of)
    if kind == "lie":
        raise HeaderCacheRefusal(str(reason))
    added = tuple(bytes(x) for x in new[: len(hashes)])
    # Copies the whole tuple per call, so a sync of N headers in batches of 2,016 copies about
    # N**2 / 4,032 references in all. Kept: measured 2026-10-10 (a plain tuple-concatenation loop of
    # that shape, this machine), 105,000 headers took 0.01 s and 525,000 took 0.25 s, small beside
    # the per-header proof-of-work check. A buffer shared between a chain and its extensions would
    # make it linear, but two extensions of one chain would then write into the same buffer, and
    # keeping each VerifiedHeaders immutable under that is more code than this cost justifies.
    return (
        VerifiedHeaders(
            network=chain.network,
            checkpoint_height=chain.checkpoint_height,
            checkpoint_hash=chain.checkpoint_hash,
            headers=chain.headers + added,
            hashes=chain.hashes + tuple(hashes),
            floor_work=chain.floor_work,
            _seal=_issue_seal(),
        ),
        reason,
    )


def start_verified_headers(
    network: str, checkpoint_header: Any, *, table: Sequence[tuple[int, str]], pow_limit: int | None = None
) -> VerifiedHeaders:
    """An empty cache: just the newest shipped checkpoint's header, which must hash to it."""
    table = _require_table(table)
    chain, why = verify_header_chain(network, table[-1][0], [checkpoint_header], table=table, pow_limit=pow_limit)
    if chain is None:
        raise HeaderCacheRefusal(f"the header served for checkpoint {table[-1][0]} is not that checkpoint ({why})")
    return chain


def agreed_headers(replies: Mapping[str, Sequence[Any]], start: int, count: int) -> list[bytes]:
    """The headers ``start .. start+count-1`` every operator in *replies* served, byte for byte.

    *replies* maps an OPERATOR key (:func:`pyrxd.network.source_identity.source_key`, one entry
    per operator, however many hosts it runs) to the headers it served from *start*. Raises
    :class:`HeaderCacheRefusal` when fewer than :data:`MIN_OPERATORS` operators answered, when an
    operator served a different number of headers than asked, or when any two disagree at any
    height. Every operator that answered must agree; a disagreeing one is never outvoted.
    """
    if len(replies) < MIN_OPERATORS:
        raise HeaderCacheRefusal(
            f"need headers from at least {MIN_OPERATORS} different operators, got {len(replies)}"
            + (f" ({', '.join(replies)})" if replies else "")
        )
    for op, got in replies.items():
        if len(got) != count:
            raise HeaderCacheRefusal(f"{op} served {len(got)} of the {count} headers from block {start}")
    out: list[bytes] = []
    for i in range(count):
        seen = {op: bytes(got[i]) if isinstance(got[i], (bytes, bytearray)) else None for op, got in replies.items()}
        values = set(seen.values())
        if None in values or len(values) != 1:
            raise HeaderCacheRefusal(
                f"operators disagree on the header at block {start + i} ({', '.join(seen)}); nothing was cached"
            )
        out.append(next(iter(values)))  # type: ignore[arg-type]
    return out


# ── The store's bytes ──────────────────────────────────────────────────────────────────────────
#
#   b"pyrxd-header-cache\n"
#   4 bytes, big-endian: length L of the metadata
#   L bytes: UTF-8 JSON {"version", "network", "base_height", "count", "syncs"}
#   count * 80 bytes: the headers, base_height upward
#   32 bytes: SHA-256 of everything above
#
# The checksum catches a damaged file; the chain is re-verified on every read regardless
# (:func:`verify_header_chain`), so the checksum is never what makes a header trusted.


def encode_store(chain: VerifiedHeaders, *, syncs: Sequence[Mapping[str, Any]] = ()) -> bytes:
    """The bytes of a store holding *chain*, with the newest *syncs* records as provenance."""
    meta = {
        "version": _VERSION,
        "network": chain.network,
        "base_height": chain.base_height,
        "count": len(chain.headers),
        "syncs": [dict(s) for s in list(syncs)[-_MAX_SYNC_RECORDS:]],
    }
    blob = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body = _MAGIC + len(blob).to_bytes(4, "big") + blob + b"".join(chain.headers)
    return body + hashlib.sha256(body).digest()


#: The deepest metadata :func:`decode_store` accepts. What :func:`encode_store` writes is at most 4
#: deep (the metadata, its ``syncs`` list, a record, a record's ``operators`` list).
_MAX_META_DEPTH = 8


def _nesting_depth(value: Any) -> int:
    """How deeply *value*'s lists and dicts nest (a scalar is 0), without recursing."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        deepest = max(deepest, depth)
        stack.extend((child, depth + 1) for child in children)
    return deepest


def decode_store(data: Any) -> tuple[dict[str, Any], list[bytes]]:
    """``(metadata, headers)`` from store bytes, or :class:`HeaderStoreCorrupt`. Shape only: what
    the headers SAY is checked by :func:`verify_header_chain`, never here."""
    if not isinstance(data, (bytes, bytearray)):
        raise HeaderStoreCorrupt("the store is not bytes")
    data = bytes(data)
    if len(data) < len(_MAGIC) + 4 + 32 or not data.startswith(_MAGIC):
        raise HeaderStoreCorrupt("the store does not start with pyrxd's header-cache marker")
    body, digest = data[:-32], data[-32:]
    if hashlib.sha256(body).digest() != digest:
        raise HeaderStoreCorrupt("the store's checksum does not match its contents")
    at = len(_MAGIC)
    n = int.from_bytes(body[at : at + 4], "big")
    at += 4
    try:
        meta = json.loads(body[at : at + n].decode("utf-8"))
    except Exception as exc:  # total over file contents: RecursionError on deep nesting, not only ValueError
        raise HeaderStoreCorrupt(f"the store's metadata could not be parsed as JSON ({type(exc).__name__})") from None
    at += n
    if _nesting_depth(meta) > _MAX_META_DEPTH:
        # Deeper than anything encode_store writes; refused here so that nothing downstream (a
        # re-encode on save, a JSON report of the sync records) recurses through it.
        raise HeaderStoreCorrupt(f"the store's metadata is nested deeper than {_MAX_META_DEPTH} levels")
    if not isinstance(meta, dict) or meta.get("version") != _VERSION:
        raise HeaderStoreCorrupt(f"the store's metadata is not version {_VERSION}")
    count, base = meta.get("count"), meta.get("base_height")
    if not all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in (count, base)):
        raise HeaderStoreCorrupt("the store's metadata has no usable count or base height")
    raw = body[at:]
    if len(raw) != 80 * count:
        raise HeaderStoreCorrupt(f"the store holds {len(raw)} bytes of headers, not {count} headers")
    if not isinstance(meta.get("network"), str) or not isinstance(meta.get("syncs"), list):
        raise HeaderStoreCorrupt("the store's metadata has no network or sync records")
    return meta, [raw[i * 80 : (i + 1) * 80] for i in range(count)]

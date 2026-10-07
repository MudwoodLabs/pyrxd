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

* while caching (and when the cache is read back), ``W`` is the work of the NEWEST SHIPPED
  checkpoint's header, fixed for the whole cache;
* while verifying from a cached anchor, ``W`` is the GREATER of that checkpoint's work and the
  anchor's own.

So the floor is never lowered by headers the cache supplied: a cached header can only raise the bar
later headers are held to, never move it below the one the shipped checkpoint sets. The floor
does not drift with the cache's own contents, however many headers it holds.

THE HONEST-PATH LIMIT, plainly. If Radiant's difficulty falls below 1/16 of the newest shipped
checkpoint's, ``pyrxd headers sync`` stops caching at the first header below that (it caches the
agreed headers under it and says why), and marks past that point do not verify with this release:
the answer is NOT VERIFIED and a newer pyrxd, with a newer checkpoint, is needed. Within one
verification walk (at most 4,032 headers above a cached anchor) the same limit applies relative
to the anchor's difficulty when that is higher, exactly as it applies to a checkpoint today. The
cache removes the TIME limit on a release; it does not remove this one.

PURE. Nothing here touches a file or the network: the CLI's store
(:mod:`pyrxd.cli.header_store`) reads and writes the bytes :func:`encode_store` produces, and the
browser pages can keep the same bytes in IndexedDB.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pyrxd.hash import radiant_block_hash
from pyrxd.security.errors import SpvVerificationError, ValidationError
from pyrxd.spv.radiant import radiant_header_prev_hash, radiant_header_work, verify_radiant_header_pow
from pyrxd.spv.radiant_checkpoints import MIN_DEPTH_BELOW_TIP

from .mark_block import FLOOR_WORK_DIVISOR

__all__ = [
    "CACHE_MIN_DEPTH",
    "MIN_OPERATORS",
    "HeaderCacheRefusal",
    "HeaderStoreCorrupt",
    "VerifiedHeaders",
    "agreed_headers",
    "decode_store",
    "encode_store",
    "extend_verified_headers",
    "start_verified_headers",
    "verify_header_chain",
]

#: How far below the LOWEST tip any source reported a header must sit before it is cached: the
#: checkpoint refresh's own minimum depth (``scripts/refresh_radiant_checkpoints.py``), the same
#: number, so a cached header is held to the depth a shipped checkpoint is.
CACHE_MIN_DEPTH = MIN_DEPTH_BELOW_TIP

#: Distinct OPERATORS (:func:`pyrxd.network.source_identity.source_key`; two hosts of one operator
#: are one) that must serve a header byte for byte alike before it is cached.
MIN_OPERATORS = 2

_MAGIC = b"pyrxd-header-cache\n"
_VERSION = 1
#: Sync records kept in the store's metadata (the newest ones). Provenance only: nothing reads
#: them to decide anything.
_MAX_SYNC_RECORDS = 64

_SEAL = object()


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
    :attr:`floor_work`. Built ONLY by :func:`verify_header_chain` and :func:`extend_verified_headers`:
    constructing one directly raises, so a :class:`VerifiedHeaders` is always a checked one.
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
        if self._seal is not _SEAL:
            raise ValidationError("VerifiedHeaders is built only by verify_header_chain() or extend_verified_headers()")

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


def _walk(
    below_hash: str, start: int, headers: Sequence[Any], floor: int, *, pow_limit: int | None
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
                f"the header at {h} carries less work than the floor (1/{FLOOR_WORK_DIVISOR} of the newest "
                f"shipped checkpoint's); its difficulty may be honest, but a newer pyrxd is needed to cache past it",
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
    floor = radiant_header_work(base, pow_limit=pow_limit) // FLOOR_WORK_DIVISOR
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
            _seal=_SEAL,
        ),
        reason,
    )


def extend_verified_headers(
    chain: VerifiedHeaders, new: Sequence[Any], *, pow_limit: int | None = None
) -> tuple[VerifiedHeaders, str | None]:
    """*chain* with *new* (heights ``chain.top + 1`` up) appended: ``(extended, why it stopped)``.

    Every new header must link to the one below it and meet its own proof-of-work, or this raises
    :class:`HeaderCacheRefusal` and nothing is added. One below the floor (:attr:`~VerifiedHeaders.floor_work`,
    fixed by the shipped checkpoint, never by a cached header) ends the extension there: the headers
    under it are added and the reason is returned.
    """
    hashes, kind, reason = _walk(chain.hashes[-1], chain.top + 1, new, chain.floor_work, pow_limit=pow_limit)
    if kind == "lie":
        raise HeaderCacheRefusal(str(reason))
    added = tuple(bytes(x) for x in new[: len(hashes)])
    return (
        VerifiedHeaders(
            network=chain.network,
            checkpoint_height=chain.checkpoint_height,
            checkpoint_hash=chain.checkpoint_hash,
            headers=chain.headers + added,
            hashes=chain.hashes + tuple(hashes),
            floor_work=chain.floor_work,
            _seal=_SEAL,
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
    except (UnicodeDecodeError, ValueError):
        raise HeaderStoreCorrupt("the store's metadata is not JSON") from None
    at += n
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

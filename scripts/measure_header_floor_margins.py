#!/usr/bin/env python3
"""Measure how close honest Radiant headers come to the header-cache floors (#826).

READ-ONLY. It asks one ElectrumX server for block headers (or reads them from a file this script
saved earlier), checks that they link hash by hash and meet their own proof-of-work, and reports
the worst ratio, over the range, for each rule that holds a header to ``W // 16``. A ratio is
``W / (the work of the header that would have to pass)``: a ratio of 16 or more means an honest
header in that range would have been held back by that rule.

    # from the first default mainnet server
    PYTHONPATH=src python scripts/measure_header_floor_margins.py --from 100000 --to 470000

    # keep the headers, and re-run later from the file
    PYTHONPATH=src python scripts/measure_header_floor_margins.py --from 100000 --to 470000 --save h.bin
    PYTHONPATH=src python scripts/measure_header_floor_margins.py --from 100000 --load h.bin

What is measured, for each rule. Each figure is the worst over the range; where the code's rule
depends on something the script does not model (which anchor a mark gets, where a fallback walk
ends), the script takes the worst case over it, so the figure is an UPPER BOUND on what that rule
did to honest headers in the range, never an underestimate:

* **sync** (:func:`pyrxd.glyph.header_cache.sync_floor`): a sync fixes ONE floor from the median
  work of the newest 2,016 headers already cached, and holds every header it adds to it. For every
  height ``s`` the span would start at, the ratio is ``median_low(work[s-2016 : s]) / min(work[s :
  s+L])`` for spans of ``L`` = 4,032 and 8,640 blocks (two and four weeks between syncs). The
  shipped checkpoint's work also enters that floor (``max``); it is measured separately below.
* **verify** (:mod:`pyrxd.glyph.mark_block` from a cached anchor): the floor comes from one anchor
  for up to 4,032 headers above it. For every height ``a`` as the anchor, the ratio is
  ``work[a] / min(work[a+1 : a+4033])``.
* **fallback** (:func:`pyrxd.glyph.mark_block.verify_with_fetched` after a server disagrees with the
  cache): the walk runs from the shipped checkpoint ``C`` and holds EVERY header above it, those
  below the cached anchor ``A`` included, to ``work[A] // 16``, with ``A`` anywhere in the 4,032
  headers above ``C``. The ratio is ``max(work[C+1 : C+4033]) / min(work[C+1 : C+4033])`` (the worst
  ``A`` against the worst header), for every checkpoint height ``C`` and, separately, for every height.
* **checkpoint**: the shipped checkpoint's work is the least any floor can be. For every checkpoint
  height (a multiple of 2,016), the ratio is ``work[cp] / min(work[cp+1 : cp+1+L])`` for ``L`` =
  8,640 and 25,920 blocks (about one and three months of a release's life).

This is not a test: it needs the network (or a saved file) and minutes of CPU.
"""

from __future__ import annotations

import argparse
import asyncio
import bisect
import json
import sys
from collections import deque
from collections.abc import Sequence
from pathlib import Path

WINDOW = 2016
SYNC_SPANS = (4032, 8640)
VERIFY_SPAN = 4032
FALLBACK_SPAN = 4032
CHECKPOINT_SPANS = (8640, 25920)
INTERVAL = 2016


async def fetch(url: str, lo: int, hi: int) -> list[bytes]:
    from pyrxd.network.electrumx import ElectrumXClient

    out: list[bytes] = []
    async with ElectrumXClient([url]) as client:
        h = lo
        while h <= hi:
            n = min(2016, hi - h + 1)
            got = await client.get_block_headers(h, n)
            if len(got) != n:
                raise SystemExit(f"{url} served {len(got)} of {n} headers from {h}")
            out += got
            h += n
    return out


def check_chain(headers: Sequence[bytes]) -> list[int]:
    """The work of each header, after checking linkage and each header's own proof-of-work."""
    from pyrxd.hash import radiant_block_hash
    from pyrxd.spv.radiant import radiant_header_prev_hash, radiant_header_work, verify_radiant_header_pow

    work = []
    below = None
    for i, hdr in enumerate(headers):
        got = verify_radiant_header_pow(hdr)
        if below is not None and radiant_header_prev_hash(hdr) != below:
            raise SystemExit(f"header #{i} does not link to the one below it")
        below = got if got else radiant_block_hash(hdr)
        work.append(radiant_header_work(hdr))
    return work


def sliding_min(values: Sequence[int], span: int) -> list[tuple[int, int]]:
    """``out[i] = (min(values[i : i+span]), its index)`` for every full window."""
    out: list[tuple[int, int]] = []
    q: deque[int] = deque()
    for j, v in enumerate(values):
        while q and values[q[-1]] >= v:
            q.pop()
        q.append(j)
        if q[0] <= j - span:
            q.popleft()
        if j >= span - 1:
            out.append((values[q[0]], q[0]))
    return out


def trailing_median_low(values: Sequence[int], window: int) -> list[int]:
    """``out[s] = median_low(values[s-window : s])`` for every ``s >= window`` (index ``s - window``)."""
    out: list[int] = []
    win = sorted(values[:window])
    for s in range(window, len(values) + 1):
        out.append(win[(window - 1) // 2])
        if s == len(values):
            break
        win.pop(bisect.bisect_left(win, values[s - window]))
        bisect.insort(win, values[s])
    return out


def sliding_max(values: Sequence[int], span: int) -> list[tuple[int, int]]:
    """``out[i] = (max(values[i : i+span]), its index)`` for every full window."""
    neg = [-v for v in values]
    return [(-m, at) for m, at in sliding_min(neg, span)]


def measure(work: Sequence[int], lo: int) -> dict:
    n = len(work)
    result: dict = {"from": lo, "to": lo + n - 1, "headers": n}
    medians = trailing_median_low(work, WINDOW)  # medians[s - WINDOW] is for a span starting at s
    for span in SYNC_SPANS:
        mins = sliding_min(work, span)  # mins[s] = min(work[s : s+span])
        best = (0.0, None, None)
        for s in range(WINDOW, n - span + 1):
            m, at = mins[s]
            r = medians[s - WINDOW] / m
            if r > best[0]:
                best = (r, lo + s, lo + at)
        result[f"sync_span_{span}"] = {"worst_ratio": round(best[0], 3), "span_start": best[1], "at": best[2]}
    mins = sliding_min(work, VERIFY_SPAN)
    best = (0.0, None, None)
    for a in range(0, n - VERIFY_SPAN - 1):
        m, at = mins[a + 1]
        r = work[a] / m
        if r > best[0]:
            best = (r, lo + a, lo + at)
    result[f"verify_span_{VERIFY_SPAN}"] = {"worst_ratio": round(best[0], 3), "anchor": best[1], "at": best[2]}
    mins = sliding_min(work, FALLBACK_SPAN)
    maxs = sliding_max(work, FALLBACK_SPAN)
    for label, step in (("every_checkpoint", INTERVAL), ("every_height", 1)):
        best = (0.0, None, None, None)
        first = (-lo) % INTERVAL if step == INTERVAL else 0
        for c in range(first, n - FALLBACK_SPAN - 1, step):
            (m, at), (mx, a) = mins[c + 1], maxs[c + 1]
            r = mx / m
            if r > best[0]:
                best = (r, lo + c, lo + a, lo + at)
        result[f"fallback_span_{FALLBACK_SPAN}_{label}"] = {
            "worst_ratio": round(best[0], 3),
            "checkpoint": best[1],
            "anchor": best[2],
            "at": best[3],
        }
    for span in CHECKPOINT_SPANS:
        mins = sliding_min(work, span)
        best = (0.0, None, None)
        first = (-lo) % INTERVAL
        for cp in range(first, n - span - 1, INTERVAL):
            m, at = mins[cp + 1]
            r = work[cp] / m
            if r > best[0]:
                best = (r, lo + cp, lo + at)
        result[f"checkpoint_span_{span}"] = {"worst_ratio": round(best[0], 3), "checkpoint": best[1], "at": best[2]}
    return result


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from", dest="lo", type=int, required=True, help="first height")
    ap.add_argument("--to", dest="hi", type=int, help="last height (needed unless --load)")
    ap.add_argument("--server", help="ElectrumX URL (default: the first default mainnet server)")
    ap.add_argument("--save", type=Path, help="write the fetched raw headers to this file")
    ap.add_argument("--load", type=Path, help="read raw headers (starting at --from) from this file")
    args = ap.parse_args(argv)
    if args.load:
        raw = args.load.read_bytes()
        if len(raw) % 80:
            raise SystemExit(f"{args.load} is not a whole number of 80-byte headers")
        headers = [raw[i : i + 80] for i in range(0, len(raw), 80)]
        if args.hi is not None:
            headers = headers[: args.hi - args.lo + 1]
    else:
        if args.hi is None:
            ap.error("--to is required without --load")
        from pyrxd.network.registry import DEFAULT_ENDPOINTS

        url = args.server or DEFAULT_ENDPOINTS["mainnet"][0]
        headers = asyncio.run(fetch(url, args.lo, args.hi))
        if args.save:
            args.save.write_bytes(b"".join(headers))
    work = check_chain(headers)
    print(json.dumps(measure(work, args.lo), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

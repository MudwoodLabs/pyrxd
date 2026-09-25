#!/usr/bin/env python3
"""Append pypistats' daily download window to a file that keeps it forever.

pypistats.org serves roughly the last **180 days** of PyPI downloads per package,
and a day that falls out of that window is gone from the API. pyrxd's first
downloads (2026-04-29) were already ~150 days back when this was written, so the
only way to keep the whole history is to save it as it goes by, the same way
`collect_traffic.py` saves GitHub's 14-day traffic window.

WHAT IS STORED. Both of the categories pypistats' ``overall`` endpoint returns, as
it returns them:

    {"with_mirrors": {"YYYY-MM-DD": n, ...}, "without_mirrors": {...}}

``without_mirrors`` is the more useful figure and is still not people: it counts
CI jobs and other automated installs, including the clean-environment install the
release runbook runs after every publish. pypistats returns no row for a day with
no downloads, and none is invented here — a missing date means "no row", and a
reader decides whether to draw it as zero.

FAILURE IS LOUD, deliberately, for the same reason as the traffic collector: a
failed fetch and a genuinely quiet period both produce "no new rows", and the
first must never be written into the history as the second. This script raises
rather than writing a partial or empty merge, and the caller must not commit on a
non-zero exit. No token is needed; the API is public and rate-limited.

THE WRITE IS ATOMIC, for the same reason as the traffic collector's: the merged
history goes to a temporary file and replaces the target with ``os.replace``, so an
interrupted run leaves the previous file intact rather than a truncated one.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

_PACKAGE = os.environ.get("PYPI_PACKAGE", "pyrxd")
_OUT = pathlib.Path(os.environ.get("PYPI_DOWNLOADS_FILE", "pypi.json"))

#: The two categories pypistats' ``overall`` endpoint returns when ``mirrors`` is not
#: passed. Anything else in the answer means the shape changed.
_CATEGORIES = ("with_mirrors", "without_mirrors")

#: pypistats answers an over-eager client with HTTP 429. A daily job should never hit
#: it, but one retry after a pause costs nothing; a second 429 is a failure.
_RETRY_AFTER_429_S = 30


class DownloadsError(RuntimeError):
    """The fetch could not complete. NOT the same as 'no downloads'."""


def _get(package: str) -> dict:
    # The scheme is an inline literal, not a constant, so it is statically provable —
    # `urlopen` honours `file:` and would read a local path without complaint. Same
    # shape as scripts/collect_traffic.py.
    req = urllib.request.Request(
        f"https://pypistats.org/api/packages/{package}/overall",
        headers={"Accept": "application/json", "User-Agent": "pyrxd-download-collector"},
    )
    for attempt in (1, 2):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - scheme checked above
                if resp.status != 200:
                    raise DownloadsError(f"pypistats returned HTTP {resp.status}")
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                if attempt == 1:
                    time.sleep(_RETRY_AFTER_429_S)
                    continue
                raise DownloadsError("pypistats is rate limiting (HTTP 429), still after one retry") from exc
            if exc.code == 404:
                raise DownloadsError(
                    f"pypistats has no package named {package!r} (HTTP 404) — check PYPI_PACKAGE"
                ) from exc
            raise DownloadsError(f"pypistats returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise DownloadsError(f"pypistats could not be reached: {exc.reason}") from exc
    raise DownloadsError(
        "pypistats kept answering HTTP 429 (rate limited)"
    )  # pragma: no cover - loop always returns or raises


def _is_iso_day(value: object) -> bool:
    """A canonical ``YYYY-MM-DD`` string: the form the history is keyed and sorted by."""
    if not isinstance(value, str):
        return False
    try:
        return datetime.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def fetch(package: str) -> dict[str, dict[str, int]]:
    """{'with_mirrors': {'2026-09-01': n, ...}, 'without_mirrors': {...}}"""
    payload = _get(package)
    rows = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise DownloadsError("pypistats' answer had no 'data' list — shape changed?")
    if not rows:
        # A package with a release history always has rows in a 180-day window. An
        # empty list means something failed upstream; say so rather than merge nothing.
        raise DownloadsError(
            "pypistats returned zero rows. That is not 'no downloads' for a published "
            "package — treating it as an error so it cannot be written into the history "
            "as a quiet period."
        )
    out: dict[str, dict[str, int]] = {c: {} for c in _CATEGORIES}
    for row in rows:
        category = row.get("category") if isinstance(row, dict) else None
        if category not in out:
            raise DownloadsError(f"pypistats returned an unknown category {category!r} — shape changed?")
        date, downloads = row.get("date"), row.get("downloads")
        if not (_is_iso_day(date) and isinstance(downloads, int) and not isinstance(downloads, bool)):
            raise DownloadsError(f"pypistats returned a malformed row: {row!r}")
        if downloads < 0:
            raise DownloadsError(f"pypistats returned a negative count: {row!r}")
        out[category][date] = downloads
    if not out["without_mirrors"]:
        raise DownloadsError("pypistats returned no 'without_mirrors' rows — shape changed?")
    return out


def _write_atomic(path: pathlib.Path, text: str) -> None:
    """Replace *path* with *text* so that no reader, and no later step, can see a partial file.

    Written to a temporary file in the same directory (so ``os.replace`` is a rename on one
    filesystem, which is atomic) and then swapped in. An interruption before the swap leaves
    the old file untouched and removes the temporary one. The workflow's commit step would
    otherwise commit whatever bytes a cancelled write had got to.
    """
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def merge(existing: dict, fresh: dict) -> tuple[dict, int]:
    """Newest wins, and return how many day-entries actually changed.

    Overwriting, not max(): the most recent day pypistats reports can be partial,
    and a later, fuller copy of the same date must replace it. Past days are
    immutable in practice, so rewriting them is a no-op. Days that have aged out of
    pypistats' window are simply not in `fresh`, so they are kept — which is the
    point of the file.
    """
    merged = {k: dict(v) for k, v in existing.items()}
    changed = 0
    for category, days in fresh.items():
        series = merged.setdefault(category, {})
        for day, n in days.items():
            if series.get(day) != n:
                series[day] = n
                changed += 1
    for category in merged:
        merged[category] = dict(sorted(merged[category].items()))
    return merged, changed


def main() -> int:
    try:
        fresh = fetch(_PACKAGE)
    except DownloadsError as exc:
        # Exit 2, never 0 and never a write: the file keeps whatever it had.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Anything unforeseen is still "could not run"; the caller branches on 2.
        print(f"error: unexpected failure fetching downloads: {exc!r}", file=sys.stderr)
        return 2

    existing: dict = {}
    if _OUT.exists():
        try:
            existing = json.loads(_OUT.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"error: {_OUT} is not valid JSON ({exc}) — refusing to overwrite it", file=sys.stderr)
            return 2

    merged, changed = merge(existing, fresh)
    _write_atomic(_OUT, json.dumps(merged, indent=2, sort_keys=True) + "\n")

    days = merged.get("without_mirrors", {})
    span = f"{min(days)}..{max(days)}" if days else "(none)"
    print(f"{_OUT}: {len(days)} days held ({span}); {changed} day-entries written this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Append GitHub's 14-day traffic window to a file that keeps it forever.

GitHub's traffic API returns **at most 14 days** and is NOT retroactive: a day
that falls off the window is gone permanently, from the API and from the
Insights page alike. There is no parameter that widens it. So the only way to
have a year of view/clone history is to have been saving it all year.

Measured on this repo 2026-09-15: the window held exactly 14 entries,
2026-09-01..2026-09-14.

WHAT THIS IS NOT. Clones are not people. The same 14 days showed 4,278 clones
against 160 views — a ratio that is CI, mirrors and package bots, including this
repository's own workflows. `uniques` is the less-bad figure and is still
inflated. Nothing here de-duplicates automation, and a chart built from it will
flatter you if you let it. The honest read is trend, not magnitude.

TOKEN. The Actions `GITHUB_TOKEN` cannot read these endpoints. They need
repository *Administration* access, which is not among the permissions grantable
to `GITHUB_TOKEN` (`actions`, `attestations`, `checks`, `contents`,
`deployments`, `discussions`, `id-token`, `issues`, `packages`, `pages`,
`pull-requests`, `security-events`, `statuses` and friends — no
`administration`). A PAT is required, so the workflow passes one in.

FAILURE IS LOUD, deliberately. An auth failure, a network blip and a genuinely
quiet fortnight all produce "no new rows", and the first two must never be
written into the history as if they were the third. This script raises rather
than writing a partial or empty merge, and the caller must not commit on a
non-zero exit.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

_REPO = os.environ.get("TRAFFIC_REPO", "MudwoodLabs/pyrxd")
_OUT = pathlib.Path(os.environ.get("TRAFFIC_FILE", "traffic.json"))

#: (endpoint, the key its per-day list is stored under in the response)
_SERIES = (("views", "views"), ("clones", "clones"))


class TrafficError(RuntimeError):
    """The fetch could not complete. NOT the same as 'no traffic'."""


def _get(path: str, token: str) -> dict:
    # The scheme is an inline literal, not a constant, so it is statically provable
    # rather than asserted at runtime — `urlopen` honours `file:` and would read a
    # local path without complaint. Same shape as scripts/check_photonic_drift.py.
    req = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {token}",
            "User-Agent": "pyrxd-traffic-collector",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - scheme checked above
            if resp.status != 200:
                raise TrafficError(f"{path} returned HTTP {resp.status}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404):
            # 401 = the PAT is expired or revoked, which is how this breaks after it
            # has been working for months. 403 = valid token, wrong scope. Both get
            # the remediation, because both look identical from the run log otherwise.
            raise TrafficError(
                f"{path} returned HTTP {exc.code}. These endpoints need repository "
                "Administration (read) access, which the Actions GITHUB_TOKEN cannot be "
                "granted. Set a TRAFFIC_TOKEN secret to a PAT with that permission "
                "(classic: `repo`; fine-grained: Administration -> Read-only)."
            ) from exc
        raise TrafficError(f"{path} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise TrafficError(f"{path} could not be reached: {exc.reason}") from exc


def fetch(token: str) -> dict[str, dict[str, dict[str, int]]]:
    """{'views': {'2026-09-01': {'count': n, 'uniques': n}, ...}, 'clones': {...}}"""
    out: dict[str, dict[str, dict[str, int]]] = {}
    for endpoint, list_key in _SERIES:
        payload = _get(f"repos/{_REPO}/traffic/{endpoint}", token)
        rows = payload.get(list_key)
        if not isinstance(rows, list):
            raise TrafficError(f"traffic/{endpoint} had no '{list_key}' list — shape changed?")
        # An empty list is possible for a genuinely untouched repo, but on a repo
        # with any history it means something went wrong upstream. Say so rather
        # than silently merging nothing.
        if not rows:
            raise TrafficError(
                f"traffic/{endpoint} returned zero days. That is not 'no traffic' — the "
                "window always holds 14 entries for a repo with any activity. Treating "
                "this as an error so it cannot be written into the history as a quiet week."
            )
        out[endpoint] = {
            str(r["timestamp"])[:10]: {"count": int(r["count"]), "uniques": int(r["uniques"])} for r in rows
        }
    return out


def merge(existing: dict, fresh: dict) -> tuple[dict, int]:
    """Newest wins, and return how many day-entries actually changed.

    Overwriting is correct, not lossy: the current day is always PARTIAL — it
    accumulates until UTC midnight — so today's row must be replaced by
    tomorrow's fuller copy of the same date. Merging by max() would freeze a
    half-day. Past days are immutable in practice, so overwriting them is a
    no-op that costs nothing and self-heals a row written during an outage.
    """
    merged = {k: dict(v) for k, v in existing.items()}
    changed = 0
    for endpoint, days in fresh.items():
        series = merged.setdefault(endpoint, {})
        for day, row in days.items():
            if series.get(day) != row:
                series[day] = row
                changed += 1
    for endpoint in merged:
        merged[endpoint] = dict(sorted(merged[endpoint].items()))
    return merged, changed


def main() -> int:
    token = os.environ.get("TRAFFIC_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        print("error: no TRAFFIC_TOKEN or GITHUB_TOKEN in the environment", file=sys.stderr)
        return 2

    try:
        fresh = fetch(token)
    except TrafficError as exc:
        # Exit 2, never 0 and never a write. The file on disk keeps whatever it
        # already had; a failed run must leave the history untouched rather than
        # shortened.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Anything unforeseen — a malformed row, a urllib subclass we did not name
        # — is still "could not run", and the caller branches on 2 to say so. A
        # bare traceback would exit 1 and read as an ordinary failure.
        print(f"error: unexpected failure fetching traffic: {exc!r}", file=sys.stderr)
        return 2

    existing: dict = {}
    if _OUT.exists():
        try:
            existing = json.loads(_OUT.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"error: {_OUT} is not valid JSON ({exc}) — refusing to overwrite it", file=sys.stderr)
            return 2

    merged, changed = merge(existing, fresh)
    _OUT.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    days = merged.get("views", {})
    span = f"{min(days)}..{max(days)}" if days else "(none)"
    print(f"{_OUT}: {len(days)} days held ({span}); {changed} day-entries written this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

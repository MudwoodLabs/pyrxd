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
`administration`). A PAT is required, so the workflow passes one in: a
FINE-GRAINED token scoped to this repository only, with Repository permissions ->
Administration: Read-only and nothing else, stored as a secret of the `traffic`
environment (see the header of .github/workflows/traffic.yml). NOT a classic PAT:
the `repo` scope a classic one needs grants full control of every repository its
owner can access, for a job that only reads a view count.

THE WRITE IS ATOMIC. The merged history goes to a temporary file beside the target
and replaces it with ``os.replace``, so a run interrupted mid-write (a cancelled
workflow signals the process) leaves the previous file intact, not a truncated one.

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

#: What to set, printed by BOTH failure paths (no token at all; a 401/403/404). A classic
#: PAT with `repo` would work, and would grant write access to every repository its owner
#: can reach, so it is deliberately not offered.
_TOKEN_REMEDIATION = (
    "Set TRAFFIC_TOKEN as a secret of the `traffic` environment (Settings -> Environments -> "
    "traffic), holding a FINE-GRAINED personal access token with Repository access: only this "
    "repository, and Repository permissions -> Administration: Read-only, nothing else."
)


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
                f"granted. {_TOKEN_REMEDIATION}"
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
        # This is how the job fails FIRST in production — before any HTTP call —
        # so the remediation has to live here, not only on the 401/403 branch.
        # Observed 2026-09-16: the first dispatched run printed only "no token"
        # and left the operator to find the fix in a comment.
        print(
            "error: no TRAFFIC_TOKEN in the environment. The traffic endpoints need "
            "repository Administration (read) access, which the Actions GITHUB_TOKEN "
            f"cannot be granted. {_TOKEN_REMEDIATION}",
            file=sys.stderr,
        )
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
    _write_atomic(_OUT, json.dumps(merged, indent=2, sort_keys=True) + "\n")

    days = merged.get("views", {})
    span = f"{min(days)}..{max(days)}" if days else "(none)"
    print(f"{_OUT}: {len(days)} days held ({span}); {changed} day-entries written this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

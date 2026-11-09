#!/usr/bin/env python3
"""Append Cloudflare Web Analytics page views for the docs site to a file that keeps them.

The docs site (``mudwoodlabs.github.io/pyrxd``) reports page views to Cloudflare Web
Analytics: the Sphinx pages load the beacon directly, and ``/inspect/``, ``/verify/`` and
``/playground/`` each count through a frame from ``count.mudwoodlabs.com``
(``tools/visit-counter/``), which is a second Web Analytics site. This script reads
the last few days of those page views from Cloudflare's GraphQL Analytics API and merges
them into ``web.json`` on the ``traffic-data`` branch, beside ``traffic.json`` and
``pypi.json``, for the adoption dashboard.

WHAT IS STORED. Page loads and visits per day per path, as Cloudflare reports them:

    {"pageviews": {"YYYY-MM-DD": {"/playground": n, "/pyrxd/": n, ...}},
     "visits":    {"YYYY-MM-DD": {...}}}

A tool page shows up as ``/<tool>`` (the counter page the beacon runs in; Pages drops ``.html``); the
docs pages show up under ``/pyrxd/...``. A page view is a browser loading a page, not a person, and Cloudflare
samples ("adaptive") at high volume. The honest read is trend, not magnitude.

AN EMPTY ANSWER IS NOT AN ERROR here, unlike the PyPI collector: a site this size can
have a day with no visits. What separates a failure from a quiet day is the API itself:
a non-200, a GraphQL ``errors`` list, or a changed shape raises, and nothing is written.

TOKEN. ``CF_ANALYTICS_TOKEN`` is a Cloudflare API token with Account -> Account Analytics
-> Read and nothing else. ``CF_ACCOUNT_ID`` names the account and ``CF_SITE_TAG`` the Web
Analytics sites, comma-separated; neither is secret. The script never prints the token.

THE WRITE IS ATOMIC, for the same reason as the other collectors: the merged history
goes to a temporary file and replaces the target with ``os.replace``.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

_OUT = pathlib.Path(os.environ.get("WEB_ANALYTICS_FILE", "web.json"))

#: The day the docs site started reporting to Cloudflare (PR #957, deployed 2026-11-09).
#: Earlier days in the lookback window are not written, so they cannot read as zero views.
_FIRST_DAY = "2026-11-09"

#: Days re-read on every run. Overlap is free (newest wins), and it lets a run that was
#: missed, or a day that was still partial, be filled in by the next one.
_LOOKBACK_DAYS = 7

#: One row per (day, path). A week of a small docs site is far below this; reaching it
#: would mean rows were cut off, so it is treated as an error rather than a full answer.
_LIMIT = 5000

_QUERY = """
query PageViews($account: String!, $sites: [String!]!, $start: Date!, $end: Date!) {
  viewer {
    accounts(filter: { accountTag: $account }) {
      rumPageloadEventsAdaptiveGroups(
        limit: __LIMIT__
        filter: { siteTag_in: $sites, date_geq: $start, date_leq: $end }
      ) {
        count
        sum { visits }
        dimensions { date requestPath }
      }
    }
  }
}
""".replace("__LIMIT__", str(_LIMIT))


class WebAnalyticsError(RuntimeError):
    """The fetch could not complete. NOT the same as 'no page views'."""


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise WebAnalyticsError(f"{name} is not set — see the header of scripts/collect_web_analytics.py")
    return value


def _site_tags() -> list[str]:
    """CF_SITE_TAG, comma-separated: the docs site and the tool-page counter site."""
    tags = [t.strip() for t in _env("CF_SITE_TAG").split(",") if t.strip()]
    if len(set(tags)) != len(tags):
        raise WebAnalyticsError("CF_SITE_TAG names the same site twice")
    return tags


def _post(token: str, variables: dict) -> dict:
    # The scheme is an inline literal so it is statically provable; `urlopen` honours `file:`.
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/graphql",
        data=json.dumps({"query": _QUERY, "variables": variables}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "pyrxd-web-analytics-collector",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - scheme is a literal
            if resp.status != 200:
                raise WebAnalyticsError(f"Cloudflare returned HTTP {resp.status}")
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        hint = " — check CF_ANALYTICS_TOKEN (Account Analytics: Read)" if exc.code in (401, 403) else ""
        raise WebAnalyticsError(f"Cloudflare returned HTTP {exc.code}{hint}") from exc
    except urllib.error.URLError as exc:
        raise WebAnalyticsError(f"Cloudflare could not be reached: {exc.reason}") from exc


def _is_iso_day(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return datetime.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _count(value: object, row: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise WebAnalyticsError(f"Cloudflare returned a malformed count: {row!r}")
    return value


def parse(payload: object) -> dict[str, dict[str, dict[str, int]]]:
    """{'pageviews': {day: {path: n}}, 'visits': {day: {path: n}}} from one GraphQL answer."""
    if not isinstance(payload, dict):
        raise WebAnalyticsError("Cloudflare's answer was not a JSON object — shape changed?")
    if payload.get("errors"):
        messages = "; ".join(str(e.get("message", e)) if isinstance(e, dict) else str(e) for e in payload["errors"])
        raise WebAnalyticsError(f"Cloudflare returned GraphQL errors: {messages}")
    try:
        accounts = payload["data"]["viewer"]["accounts"]
    except (KeyError, TypeError) as exc:
        raise WebAnalyticsError("Cloudflare's answer had no data.viewer.accounts — shape changed?") from exc
    if not isinstance(accounts, list) or len(accounts) != 1:
        raise WebAnalyticsError(f"expected exactly one account in the answer, got {accounts!r} — check CF_ACCOUNT_ID")
    rows = accounts[0].get("rumPageloadEventsAdaptiveGroups") if isinstance(accounts[0], dict) else None
    if not isinstance(rows, list):
        raise WebAnalyticsError("the answer had no rumPageloadEventsAdaptiveGroups list — shape changed?")
    if len(rows) >= _LIMIT:
        raise WebAnalyticsError(f"the answer hit the {_LIMIT}-row limit, so rows may be missing")
    out: dict[str, dict[str, dict[str, int]]] = {"pageviews": {}, "visits": {}}
    for row in rows:
        dims = row.get("dimensions") if isinstance(row, dict) else None
        if not isinstance(dims, dict):
            raise WebAnalyticsError(f"Cloudflare returned a row without dimensions: {row!r}")
        day, path = dims.get("date"), dims.get("requestPath")
        if not (_is_iso_day(day) and isinstance(path, str)):
            raise WebAnalyticsError(f"Cloudflare returned a malformed row: {row!r}")
        visits = (row.get("sum") or {}).get("visits") if isinstance(row.get("sum"), dict) else None
        out["pageviews"].setdefault(day, {})
        out["visits"].setdefault(day, {})
        out["pageviews"][day][path] = out["pageviews"][day].get(path, 0) + _count(row.get("count"), row)
        out["visits"][day][path] = out["visits"][day].get(path, 0) + _count(visits, row)
    return out


def fetch(today: datetime.date | None = None) -> tuple[dict, list[str]]:
    """The parsed answer and the days it covers (every day asked for, answered or not)."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    start = today - datetime.timedelta(days=_LOOKBACK_DAYS - 1)
    days = [(start + datetime.timedelta(days=i)).isoformat() for i in range(_LOOKBACK_DAYS)]
    days = [d for d in days if d >= _FIRST_DAY] or [today.isoformat()]
    payload = _post(
        _env("CF_ANALYTICS_TOKEN"),
        {"account": _env("CF_ACCOUNT_ID"), "sites": _site_tags(), "start": days[0], "end": days[-1]},
    )
    return parse(payload), days


def merge(existing: dict, fresh: dict, days: list[str]) -> tuple[dict, int]:
    """Replace every day the fetch covered with what it returned, and keep all older days.

    A day inside the window that came back with no rows is written as ``{}``: the API
    answered for it, and it had no page views. A day outside the window is untouched, so
    nothing that has aged out of Cloudflare's retention is lost.
    """
    merged = {k: {d: dict(p) for d, p in v.items()} for k, v in existing.items()}
    changed = 0
    for metric in ("pageviews", "visits"):
        series = merged.setdefault(metric, {})
        for day in days:
            new = dict(sorted(fresh.get(metric, {}).get(day, {}).items()))
            if series.get(day) != new:
                series[day] = new
                changed += 1
        merged[metric] = dict(sorted(series.items()))
    return merged, changed


def _write_atomic(path: pathlib.Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def main() -> int:
    try:
        fresh, days = fetch()
    except WebAnalyticsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: unexpected failure fetching page views: {type(exc).__name__}", file=sys.stderr)
        return 2

    existing: dict = {}
    if _OUT.exists():
        try:
            existing = json.loads(_OUT.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"error: {_OUT} is not valid JSON ({exc}) — refusing to overwrite it", file=sys.stderr)
            return 2

    merged, changed = merge(existing, fresh, days)
    _write_atomic(_OUT, json.dumps(merged, indent=2, sort_keys=True) + "\n")
    held = merged.get("pageviews", {})
    total = sum(sum(p.values()) for p in held.values())
    print(f"{_OUT}: {len(held)} days held, {total} page views; {changed} day-entries written this run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

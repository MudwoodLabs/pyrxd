# traffic-data

Orphan branch. Holds `traffic.json`, the accumulated GitHub traffic history for
this repository, written daily by `.github/workflows/traffic.yml` on `main`.

**Why this exists.** GitHub's traffic API returns at most **14 days** and is not
retroactive — a day that falls off is gone from the API and the Insights page
alike, and no parameter widens it. The only way to have a year of history is to
have been saving it all year.

**Do not read the magnitudes as people.** The 14 days seeded here showed 4,278
clones against 160 views. That ratio is CI, mirrors and package bots, including
this repository's own workflows. `uniques` is the less-bad figure and is still
inflated. Nothing here de-duplicates automation. The honest read is trend, not
magnitude — and for a published library, PyPI download stats (~180 days via
pypistats, unlimited via the BigQuery public dataset) are the better signal.

**Shape.** `{"views": {"YYYY-MM-DD": {"count": n, "uniques": n}}, "clones": {...}}`

Same-date rows are overwritten, not maxed: today's row is partial until UTC
midnight, so a later fuller copy must replace it.

A failed fetch writes nothing at all — see `scripts/collect_traffic.py` on
`main` and the guards in `tests/test_traffic_history_is_never_silently_shortened.py`.

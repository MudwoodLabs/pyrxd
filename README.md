# traffic-data

Orphan branch. Holds two histories, both written daily by
`.github/workflows/traffic.yml` on `main`:

- `traffic.json`: GitHub traffic (page views and clones) for this repository.
- `pypi.json`: PyPI downloads of the `pyrxd` package, from pypistats.org.

**Why this exists.** Both sources forget. GitHub's traffic API returns at most
**14 days** and is not retroactive: a day that falls off is gone from the API and
the Insights page alike, and no parameter widens it. pypistats keeps about **180
days**. The only way to have a longer history is to have been saving it all along.
`pypi.json` was added on 2026-09-25, when pyrxd's first downloads (2026-04-29) were
about 150 days back, and its first run captured everything pypistats still held.

**Do not read the magnitudes as people.**
- **Clones.** The 14 days seeded in `traffic.json` showed 4,278 clones against 160
  views. That ratio is CI, mirrors and package bots, including this repository's
  own workflows. `uniques` is the less-bad figure and is still inflated.
- **Downloads.** `without_mirrors` still counts CI jobs and other automated
  installs, including the clean-environment install the release runbook runs after
  every publish.

Nothing here de-duplicates automation. The honest read is trend, not magnitude.

**Shapes.**

- `traffic.json`: `{"views": {"YYYY-MM-DD": {"count": n, "uniques": n}}, "clones": {...}}`
- `pypi.json`: `{"with_mirrors": {"YYYY-MM-DD": n}, "without_mirrors": {...}}`

  pypistats returns no row for a day with no downloads, and none is invented here.
  A missing date means "no row"; a reader decides whether to draw it as zero.

Same-date rows are overwritten, not maxed. The newest day is partial until it
closes, so a later, fuller copy must replace it.

A failed fetch writes nothing at all. See `scripts/collect_traffic.py` and
`scripts/collect_pypi_downloads.py` on `main`, and their guards in
`tests/test_traffic_history_is_never_silently_shortened.py` and
`tests/test_pypi_download_history_is_never_silently_shortened.py`.

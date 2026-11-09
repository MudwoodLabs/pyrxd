"""A failed Cloudflare page-view fetch must never be written into the history as a quiet period.

`scripts/collect_web_analytics.py` keeps the docs site's daily page views in `web.json`
on the traffic-data branch. Unlike pypistats, Cloudflare can honestly answer "no rows"
for a quiet week, so emptiness cannot be the failure signal. These tests pin what is:
a non-200, a GraphQL ``errors`` list, a changed shape or a truncated answer writes
nothing, while an honest empty answer records the covered days as ``{}``.

The answer shape below is written from Cloudflare's documented GraphQL layout
(``viewer.accounts[].rumPageloadEventsAdaptiveGroups``), NOT captured from the live API:
no Analytics token was available when this was written. The first scheduled run is the
check against the real service; a shape change there fails it loudly.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import pathlib
import sys
import urllib.error

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "collect_web_analytics.py"
_WORKFLOW = _ROOT / ".github" / "workflows" / "traffic.yml"
_TODAY = datetime.date(2026, 11, 20)
_TOKEN = "test-token-not-a-secret"
_REAL_FETCH: dict = {}


def _load(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("WEB_ANALYTICS_FILE", str(tmp_path / "web.json"))
    monkeypatch.setenv("CF_ANALYTICS_TOKEN", _TOKEN)
    monkeypatch.setenv("CF_ACCOUNT_ID", "acct")
    monkeypatch.setenv("CF_SITE_TAG", "site")
    spec = importlib.util.spec_from_file_location(f"collect_web_{tmp_path.name}", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    real_fetch = module.fetch
    _REAL_FETCH[module] = real_fetch
    monkeypatch.setattr(module, "fetch", lambda today=None: real_fetch(_TODAY))
    return module


def _answer(rows: list[dict]) -> dict:
    return {"data": {"viewer": {"accounts": [{"rumPageloadEventsAdaptiveGroups": rows}]}}, "errors": None}


def _row(day: str, path: str, count: int, visits: int) -> dict:
    return {"count": count, "sum": {"visits": visits}, "dimensions": {"date": day, "requestPath": path}}


class _Resp:
    def __init__(self, body: dict, status: int = 200) -> None:
        self.status, self._body = status, json.dumps(body).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a) -> None:
        return None


def _serve(mod, monkeypatch: pytest.MonkeyPatch, answer) -> list:
    sent: list = []

    def fake(req, timeout=None):
        sent.append(req)
        if isinstance(answer, int):
            raise urllib.error.HTTPError(req.full_url, answer, "err", {}, None)
        return _Resp(answer)

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake)
    return sent


_OLD = {"pageviews": {"2026-10-01": {"/pyrxd/": 3}}, "visits": {"2026-10-01": {"/pyrxd/": 2}}}


def _seed(mod) -> str:
    text = json.dumps(_OLD)
    mod._OUT.write_text(text)
    return text


def test_an_honest_answer_is_merged_and_older_days_are_kept(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch)
    _seed(mod)
    sent = _serve(
        mod,
        monkeypatch,
        _answer(
            [
                _row("2026-11-20", "/pyrxd/playground/count.html", 4, 2),
                _row("2026-11-19", "/pyrxd/", 1, 1),
            ]
        ),
    )
    assert mod.main() == 0
    data = json.loads(mod._OUT.read_text())
    assert data["pageviews"]["2026-10-01"] == {"/pyrxd/": 3}, "a day outside the window was dropped"
    assert data["pageviews"]["2026-11-20"] == {"/pyrxd/playground/count.html": 4}
    assert data["visits"]["2026-11-19"] == {"/pyrxd/": 1}
    assert data["pageviews"]["2026-11-14"] == {}, "an answered day with no rows must read as zero, not missing"
    assert len([d for d in data["pageviews"] if d >= "2026-11-14"]) == mod._LOOKBACK_DAYS
    body = json.loads(sent[0].data)
    assert body["variables"] == {"account": "acct", "site": "site", "start": "2026-11-14", "end": "2026-11-20"}


def test_days_before_counting_started_are_not_written_as_zero(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setattr(mod, "fetch", lambda today=None: _REAL_FETCH[mod](datetime.date(2026, 11, 10)))
    sent = _serve(mod, monkeypatch, _answer([]))
    assert mod.main() == 0
    data = json.loads(mod._OUT.read_text())
    assert sorted(data["pageviews"]) == ["2026-11-09", "2026-11-10"]
    assert json.loads(sent[0].data)["variables"]["start"] == "2026-11-09"


@pytest.mark.parametrize(
    "answer",
    [
        401,
        500,
        {"data": None, "errors": [{"message": "not authorized for that account"}]},
        {**_answer([_row("2026-11-20", "/pyrxd/", 1, 1)]), "errors": [{"message": "partial: quota exceeded"}]},
        {"data": {"viewer": {"accounts": []}}, "errors": None},
        {"data": {"viewer": {"accounts": [{}]}}, "errors": None},
        _answer([{"count": 1, "sum": {"visits": 1}, "dimensions": {"date": "11/09/2026", "requestPath": "/"}}]),
        _answer([_row("2026-11-09", "/", -1, 0)]),
        _answer([{"count": True, "sum": {"visits": 1}, "dimensions": {"date": "2026-11-09", "requestPath": "/"}}]),
    ],
    ids=[
        "http-401",
        "http-500",
        "graphql-errors",
        "errors-with-partial-data",
        "no-account",
        "no-dataset",
        "bad-date",
        "negative",
        "bool-count",
    ],
)
def test_a_failed_or_malformed_answer_writes_nothing(tmp_path, monkeypatch, capsys, answer):
    mod = _load(tmp_path, monkeypatch)
    before = _seed(mod)
    _serve(mod, monkeypatch, answer)
    assert mod.main() == 2
    assert mod._OUT.read_text() == before
    assert _TOKEN not in capsys.readouterr().err


def test_a_truncated_answer_writes_nothing(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch)
    before = _seed(mod)
    _serve(mod, monkeypatch, _answer([_row("2026-11-09", f"/p{i}", 1, 1) for i in range(mod._LIMIT)]))
    assert mod.main() == 2
    assert mod._OUT.read_text() == before


def test_a_missing_setting_fails_without_a_request(tmp_path, monkeypatch):
    mod = _load(tmp_path, monkeypatch)
    before = _seed(mod)
    sent = _serve(mod, monkeypatch, _answer([]))
    monkeypatch.delenv("CF_SITE_TAG")
    assert mod.main() == 2
    assert sent == [] and mod._OUT.read_text() == before


def test_the_workflow_runs_the_collector_and_commits_its_file():
    text = _WORKFLOW.read_text()
    assert "run: python scripts/collect_web_analytics.py" in text
    assert "WEB_ANALYTICS_FILE: data/web.json" in text
    assert "git add web.json" in text
    assert "steps.web.outcome == 'failure'" in text, "a failed page-view fetch must turn the run red"

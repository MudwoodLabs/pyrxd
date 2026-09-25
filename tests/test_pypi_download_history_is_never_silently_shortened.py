"""A failed PyPI-downloads fetch must never be written into the history as a quiet period.

pypistats.org serves about **180 days** of downloads, and pyrxd's first downloads were
already ~150 days back when `scripts/collect_pypi_downloads.py` was written, so the
collected file is the only copy of anything older. The risk is the same as for the
GitHub traffic collector (`test_traffic_history_is_never_silently_shortened.py`): a rate
limit, a network blip and a genuinely idle stretch all arrive as "no new rows", and the
first two must not be recorded as the third.

The fixture is a slice of the REAL pypistats answer (`tests/fixtures/
pypistats_overall_sample.json`), so the parser is tested against the shape pypistats
actually sends, not one written here. Failures are stubbed at `urlopen`, where the
script's own error handling lives.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import urllib.error

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "collect_pypi_downloads.py"
_REAL = json.loads((_ROOT / "tests" / "fixtures" / "pypistats_overall_sample.json").read_text())["response"]
_WORKFLOW = _ROOT / ".github" / "workflows" / "traffic.yml"


def _load(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    """Import the script fresh with PYPI_DOWNLOADS_FILE pointed into a tmpdir (read at import)."""
    monkeypatch.setenv("PYPI_DOWNLOADS_FILE", str(tmp_path / "pypi.json"))
    spec = importlib.util.spec_from_file_location(f"collect_pypi_{tmp_path.name}", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_RETRY_AFTER_429_S", 0)
    return module


class _Resp:
    def __init__(self, body: dict, status: int = 200) -> None:
        self.status = status
        self._body = json.dumps(body).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a) -> None:
        return None


def _serve(mod, monkeypatch: pytest.MonkeyPatch, *answers) -> list[str]:
    """Answer successive urlopen calls in order; an int answer raises that HTTP error."""
    calls: list[str] = []
    queue = list(answers)

    def _urlopen(req, timeout=None):
        calls.append(req.full_url)
        a = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(a, int):
            raise urllib.error.HTTPError(req.full_url, a, "nope", {}, None)  # type: ignore[arg-type]
        return _Resp(a)

    monkeypatch.setattr(mod.urllib.request, "urlopen", _urlopen)
    return calls


def _window(start_day: int, days: int) -> dict:
    """A pypistats-shaped answer covering 2026-08-{start_day}.. for `days` days, both categories."""
    rows = []
    for cat, base in (("with_mirrors", 100), ("without_mirrors", 10)):
        for i in range(days):
            rows.append({"category": cat, "date": f"2026-08-{start_day + i:02d}", "downloads": base + i})
    return {"data": rows, "package": "pyrxd", "type": "overall_downloads"}


# ---------------------------------------------------------------------------
# The honest path
# ---------------------------------------------------------------------------


def test_the_real_pypistats_shape_is_written(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(tmp_path, monkeypatch)
    calls = _serve(mod, monkeypatch, _REAL)

    assert mod.main() == 0
    written = json.loads((tmp_path / "pypi.json").read_text())
    assert set(written) == {"with_mirrors", "without_mirrors"}
    for cat in written:
        expected = {r["date"]: r["downloads"] for r in _REAL["data"] if r["category"] == cat}
        assert written[cat] == expected
    assert calls == ["https://pypistats.org/api/packages/pyrxd/overall"]


def test_a_rerun_changes_nothing(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Idempotence: a daily job that rewrote every row would make the data branch's own
    diff useless for seeing when something actually moved."""
    mod = _load(tmp_path, monkeypatch)
    _serve(mod, monkeypatch, _REAL)
    assert mod.main() == 0
    first = (tmp_path / "pypi.json").read_bytes()
    assert mod.main() == 0
    assert (tmp_path / "pypi.json").read_bytes() == first


def test_older_days_survive_when_the_window_slides(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The point of the file: a day pypistats has stopped serving is still kept."""
    mod = _load(tmp_path, monkeypatch)
    _serve(mod, monkeypatch, _window(1, 10))
    assert mod.main() == 0
    _serve(mod, monkeypatch, _window(6, 10))  # 08-01..08-05 are no longer offered
    assert mod.main() == 0
    written = json.loads((tmp_path / "pypi.json").read_text())
    assert "2026-08-01" in written["without_mirrors"], "a day that aged out of the API was dropped"
    assert "2026-08-15" in written["without_mirrors"], "the newly offered days were not appended"
    assert len(written["without_mirrors"]) == 15


def test_a_later_copy_of_a_day_replaces_it(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The newest day can be partial; a fuller copy must overwrite, not be max()-ed away."""
    mod = _load(tmp_path, monkeypatch)
    merged, changed = mod.merge({"without_mirrors": {"2026-08-10": 3}}, {"without_mirrors": {"2026-08-10": 11}})
    assert merged["without_mirrors"]["2026-08-10"] == 11
    assert changed == 1
    # Newest wins in BOTH directions: a later, lower copy is a correction, not noise, and a
    # max()-merge would keep the stale higher figure forever. (An upward-only case cannot
    # tell "newest wins" from max(); this one can.)
    merged, changed = mod.merge({"without_mirrors": {"2026-08-10": 11}}, {"without_mirrors": {"2026-08-10": 3}})
    assert merged["without_mirrors"]["2026-08-10"] == 3
    assert changed == 1


def test_one_429_is_retried_then_the_fetch_succeeds(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """pypistats rate-limits with 429 (seen while writing this). One retry is the
    honest-path twin of the refusal below: a single 429 must not cost a day."""
    mod = _load(tmp_path, monkeypatch)
    calls = _serve(mod, monkeypatch, 429, _REAL)
    assert mod.main() == 0
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# The failures that must not look like success
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("answers", [(429, 429), (404,), (500,), (503,)])
def test_an_http_failure_exits_nonzero_and_writes_nothing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, answers: tuple
) -> None:
    mod = _load(tmp_path, monkeypatch)
    out = tmp_path / "pypi.json"
    out.write_text(json.dumps({"without_mirrors": {"2026-01-01": 9}}) + "\n")
    before = out.read_bytes()
    _serve(mod, monkeypatch, *answers)
    assert mod.main() == 2
    assert out.read_bytes() == before, "a failed fetch rewrote the history file"


def test_an_unreachable_host_exits_nonzero_and_writes_nothing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _load(tmp_path, monkeypatch)

    def _down(req, timeout=None):
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(mod.urllib.request, "urlopen", _down)
    assert mod.main() == 2
    assert not (tmp_path / "pypi.json").exists()


@pytest.mark.parametrize(
    "body",
    [
        {"data": []},  # empty: not "no downloads" for a published package
        {"rows": []},  # the list key renamed
        {"data": [{"category": "with_mirrors", "date": "2026-08-01", "downloads": 5}]},  # no without_mirrors
        {"data": [{"category": "with_bots", "date": "2026-08-01", "downloads": 5}]},  # unknown category
        {"data": [{"category": "without_mirrors", "date": "2026-08-01", "downloads": "5"}]},  # count as text
        {"data": [{"category": "without_mirrors", "date": "2026-08-01", "downloads": True}]},  # bool is not a count
        {"data": [{"category": "without_mirrors", "date": "2026-08-01", "downloads": -1}]},  # negative
        {"data": [{"category": "without_mirrors", "date": "08/01/2026", "downloads": 5}]},  # date format changed
    ],
)
def test_a_changed_or_empty_answer_is_an_error(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, body: dict
) -> None:
    mod = _load(tmp_path, monkeypatch)
    _serve(mod, monkeypatch, body)
    assert mod.main() == 2
    assert not (tmp_path / "pypi.json").exists()


def test_an_empty_answer_is_named_as_such(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The operator reading the run log must be told the list was EMPTY — the case that
    most resembles a quiet period — not a generic shape complaint."""
    mod = _load(tmp_path, monkeypatch)
    _serve(mod, monkeypatch, {"data": [], "package": "pyrxd", "type": "overall_downloads"})
    assert mod.main() == 2
    assert "zero rows" in capsys.readouterr().err


def test_a_corrupt_existing_file_is_not_overwritten(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(tmp_path, monkeypatch)
    out = tmp_path / "pypi.json"
    out.write_text("{ this is not json")
    _serve(mod, monkeypatch, _REAL)
    assert mod.main() == 2
    assert out.read_text() == "{ this is not json"


# ---------------------------------------------------------------------------
# The workflow actually runs it, commits it, and goes red when it fails
# ---------------------------------------------------------------------------


def test_the_daily_workflow_collects_commits_and_fails_loudly() -> None:
    """A collector nothing runs keeps nothing. And because the two collectors run with
    `continue-on-error` (so one source's outage does not lose the other's day), the job
    must end with a step that turns the run red when either failed — otherwise a broken
    fetch would sit behind a green check forever."""
    import yaml

    wf = yaml.safe_load(_WORKFLOW.read_text())
    steps = wf["jobs"]["collect"]["steps"]
    by_id = {s.get("id"): s for s in steps if s.get("id")}

    assert "python scripts/collect_pypi_downloads.py" in by_id["pypi"]["run"]
    assert by_id["pypi"]["env"]["PYPI_DOWNLOADS_FILE"] == "data/pypi.json"
    assert "python scripts/collect_traffic.py" in by_id["traffic"]["run"]

    commit = next(s for s in steps if s.get("name", "").startswith("Commit"))
    assert "pypi.json" in commit["run"] and "traffic.json" in commit["run"]

    last = steps[-1]
    assert "steps.pypi.outcome" in last["if"] and "steps.traffic.outcome" in last["if"]
    assert "exit 1" in last["run"]

    paths = wf[True]["pull_request"]["paths"] if True in wf else wf["on"]["pull_request"]["paths"]
    assert "scripts/collect_pypi_downloads.py" in paths

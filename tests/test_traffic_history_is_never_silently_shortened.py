"""A failed traffic fetch must never be written into the history as a quiet week.

GitHub's traffic API holds **14 days** and is not retroactive, so the collected file
is the only copy of anything older. That makes the write path the whole risk surface:
an auth failure, a network blip and a genuinely idle fortnight all arrive as "no new
rows", and the first two must not be recorded as the third.

The failure this guards is the one that looks like success. A collector that caught
its own errors and wrote `{}` would exit 0, commit cleanly, and silently truncate
months of history — and nothing downstream could tell that from a real quiet period,
because a shortened series and an idle one are the same shape.

So every non-200, every shape change, and an empty day list are all errors here, and
an error means **no write at all**. The honest-path tests sit beside them: a normal
fetch must still merge, and a re-run must be a no-op rather than churning the file.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "collect_traffic.py"


def _load(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    """Import the script fresh with TRAFFIC_FILE pointed into a tmpdir.

    Module-level `_OUT` reads the env at import, so the env must be set first —
    importing once at module scope would pin every test to the same real path.
    """
    monkeypatch.setenv("TRAFFIC_FILE", str(tmp_path / "traffic.json"))
    spec = importlib.util.spec_from_file_location(f"collect_traffic_{tmp_path.name}", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _payload(endpoint: str, days: int = 14, start: int = 1) -> dict:
    return {
        endpoint: [
            {"timestamp": f"2026-09-{start + i:02d}T00:00:00Z", "count": 10 + i, "uniques": 2 + i} for i in range(days)
        ]
    }


# ---------------------------------------------------------------------------
# The honest path
# ---------------------------------------------------------------------------


def test_a_normal_fetch_is_written(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")
    monkeypatch.setattr(mod, "_get", lambda path, token: _payload("views" if "views" in path else "clones"))

    assert mod.main() == 0
    written = json.loads((tmp_path / "traffic.json").read_text())
    assert len(written["views"]) == 14
    assert len(written["clones"]) == 14


def test_a_rerun_changes_nothing(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Idempotence. A daily job that rewrote every row would make the history's own
    diff useless for seeing when something actually moved."""
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")
    monkeypatch.setattr(mod, "_get", lambda path, token: _payload("views" if "views" in path else "clones"))

    assert mod.main() == 0
    first = (tmp_path / "traffic.json").read_bytes()
    assert mod.main() == 0
    assert (tmp_path / "traffic.json").read_bytes() == first


def test_older_days_survive_when_the_window_slides(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The entire point of the file. Day 1 must still be there once it has aged out
    of GitHub's 14-day window and stopped being returned at all."""
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")

    monkeypatch.setattr(mod, "_get", lambda p, t: _payload("views" if "views" in p else "clones", start=1))
    assert mod.main() == 0
    # The window slides forward; 2026-09-01 is no longer offered by the API.
    monkeypatch.setattr(mod, "_get", lambda p, t: _payload("views" if "views" in p else "clones", start=8))
    assert mod.main() == 0

    written = json.loads((tmp_path / "traffic.json").read_text())
    assert "2026-09-01" in written["views"], "a day that aged out of the API was dropped from the history"
    assert "2026-09-21" in written["views"], "the newly offered days were not appended"
    assert len(written["views"]) == 21


def test_todays_partial_row_is_replaced_not_maxed(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Today's row accumulates until UTC midnight, so a later, fuller copy of the same
    date must overwrite. A max()-style merge would freeze a half-day forever."""
    mod = _load(tmp_path, monkeypatch)
    one = {"views": {"2026-09-14": {"count": 3, "uniques": 1}}}
    two = {"views": {"2026-09-14": {"count": 11, "uniques": 4}}}
    merged, changed = mod.merge(one, two)
    assert merged["views"]["2026-09-14"] == {"count": 11, "uniques": 4}
    assert changed == 1


# ---------------------------------------------------------------------------
# The failures that must not look like success
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", [401, 403, 404, 500])
def test_an_http_failure_exits_nonzero_and_writes_nothing(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    """403 is the expected production failure (GITHUB_TOKEN cannot be granted
    Administration); 401 is how it breaks later, when the PAT expires. Neither may
    truncate the file, and neither may exit 0."""
    import urllib.error

    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")
    out = tmp_path / "traffic.json"
    out.write_text(json.dumps({"views": {"2026-01-01": {"count": 9, "uniques": 9}}}) + "\n")
    before = out.read_bytes()

    def _boom(req, timeout=None):
        raise urllib.error.HTTPError(getattr(req, "full_url", "u"), code, "nope", {}, None)  # type: ignore[arg-type]

    # Stubbed at urlopen, NOT at `_get`: `_get` is where the HTTPError handling
    # lives, so replacing it would test a seam invented by this test rather than
    # the code that actually runs. An earlier draft did exactly that and the
    # exception sailed straight past the handler it was meant to exercise.
    monkeypatch.setattr(mod.urllib.request, "urlopen", _boom)

    assert mod.main() == 2
    assert out.read_bytes() == before, "a failed fetch rewrote the history file"


def test_an_empty_day_list_is_an_error_not_a_quiet_week(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sharp one. Zero days is indistinguishable from real silence in the output,
    so it is refused rather than merged."""
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")
    monkeypatch.setattr(mod, "_get", lambda path, token: {"views": [], "clones": []})

    assert mod.main() == 2
    assert not (tmp_path / "traffic.json").exists()


def test_a_changed_response_shape_is_an_error(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If GitHub renames the list key, every day silently becomes zero. Fail instead."""
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")
    monkeypatch.setattr(mod, "_get", lambda path, token: {"something_else": []})

    assert mod.main() == 2


def test_a_corrupt_existing_file_is_not_overwritten(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refusing here keeps the damaged bytes available to recover by hand. Overwriting
    would turn a recoverable problem into a permanent one."""
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.setenv("TRAFFIC_TOKEN", "t")
    out = tmp_path / "traffic.json"
    out.write_text("{ this is not json")
    monkeypatch.setattr(mod, "_get", lambda path, token: _payload("views" if "views" in path else "clones"))

    assert mod.main() == 2
    assert out.read_text() == "{ this is not json"


def test_no_token_at_all_exits_nonzero(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mod = _load(tmp_path, monkeypatch)
    monkeypatch.delenv("TRAFFIC_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert mod.main() == 2

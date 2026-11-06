"""The playground's "Export as project": the starter kit's project, plus the visitor's code.

The export must hand over exactly what ``pyrxd new`` makes (so the project's own test and CI
are the starter kit's, not a copy), add the code under ``playground/`` without touching any
template file, and refuse the names the starter kit refuses.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import zipfile
from pathlib import Path

import pytest
from pyrxd.starter import ProjectNameError, render_project

_DIR = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "playground"


@pytest.fixture(scope="module")
def pg():
    sys.path.insert(0, str(_DIR))
    try:
        spec = importlib.util.spec_from_file_location("playground", _DIR / "playground.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["playground"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        sys.path.remove(str(_DIR))
        sys.modules.pop("playground", None)
        sys.modules.pop("lessons", None)


def _unzip(blob: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return {n: zf.read(n).decode("utf-8") for n in zf.namelist()}


def test_export_is_the_starter_project_plus_the_code(pg):
    code = "from playground import sandbox\nprint('mine')\n"
    out = pg.export_project("my-radiant-app", "send", code)
    files = _unzip(out["zip"])
    assert out["filename"] == "my-radiant-app.zip"
    assert all(n.startswith("my-radiant-app/") for n in files)
    got = {n.removeprefix("my-radiant-app/"): t for n, t in files.items()}
    assert sorted(got) == out["files"]

    template = render_project("my-radiant-app")
    assert template, "the starter kit rendered nothing"
    # Every template file is there, byte for byte: the export never edits the starter kit.
    for path, text in template.items():
        assert got[path] == text, path
    # And the only additions are the code and its README, under playground/.
    assert set(got) - set(template) == {"playground/send.py", "playground/README.md"}
    assert got["playground/send.py"].endswith(code)
    assert got["playground/send.py"].startswith("# send.py: exported from the Radiant Playground.")
    assert "does not exist outside that page" in got["playground/send.py"]
    assert "src/my_radiant_app/mint.py" in got["playground/README.md"]


def test_export_uses_the_lesson_file_name(pg):
    for lesson in pg.lesson_list():
        files = pg.export_project("demo-app", lesson["id"], lesson["code"])["files"]
        assert f"playground/{lesson['file']}" in files


@pytest.mark.parametrize("name", ["pyrxd", "json", "-bad", "", "../escape"])
def test_export_refuses_names_the_starter_kit_refuses(pg, name):
    with pytest.raises(ProjectNameError):
        pg.export_project(name, "wallet", "print(1)\n")


def test_export_refuses_an_unknown_lesson(pg):
    with pytest.raises(KeyError):
        pg.export_project("demo-app", "no-such-lesson", "print(1)\n")


def test_export_is_offered_only_with_the_starter_kit(pg, monkeypatch):
    assert pg.export_available() is True
    monkeypatch.setitem(sys.modules, "pyrxd.starter", None)  # an import of it now fails
    assert pg.export_available() is False

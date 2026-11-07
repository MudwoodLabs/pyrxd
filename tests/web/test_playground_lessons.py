"""Every playground lesson runs, and every "Try it" edit fails the way its text says.

Two runtimes:

* CPython with the real coincurve, in this process.
* The Pyodide SHAPE, in a subprocess: ``coincurve``, ``aiohttp`` and ``websockets`` cannot be
  imported and ``hashlib.pbkdf2_hmac`` is gone, as in Pyodide 0.26.4 without its OpenSSL
  package. ``playground.prepare_runtime`` must make every lesson work there anyway, through
  ``sandbox_curve`` and its own PBKDF2. This is the import graph and the shims, not Pyodide
  itself; the page's boot in a real browser is checked by hand (see the PR).
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[2] / "docs" / "inspect_static" / "playground"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mods():
    sys.path.insert(0, str(_DIR))
    try:
        yield _load("playground"), _load("lessons")
    finally:
        sys.path.remove(str(_DIR))
        sys.modules.pop("playground", None)
        sys.modules.pop("lessons", None)


def _lessons():
    sys.path.insert(0, str(_DIR))
    try:
        return _load("lessons").lesson_list()
    finally:
        sys.path.remove(str(_DIR))
        sys.modules.pop("lessons", None)


LESSONS = _lessons()
assert LESSONS, "no lessons found"


def _matches(error: dict, expect: str) -> bool:
    return error["rule"] == expect or error["type"] == expect


@pytest.mark.parametrize("lesson", LESSONS, ids=[x["id"] for x in LESSONS])
def test_lesson_runs_as_written(mods, lesson):
    pg, _ = mods
    pg.reset_sandbox()
    r = asyncio.run(pg.run_program(lesson["code"]))
    assert r["error"] is None, r["error"]
    assert r["stdout"].strip()


@pytest.mark.parametrize("lesson", [x for x in LESSONS if x["try_it"]], ids=[x["id"] for x in LESSONS if x["try_it"]])
def test_try_it_breaks_the_way_the_text_says(mods, lesson):
    pg, _ = mods
    t = lesson["try_it"]
    assert lesson["code"].count(t["find"]) == 1, "the edit must name one place in the code"
    edited = lesson["code"].replace(t["find"], t["replace"])
    pg.reset_sandbox()
    r = asyncio.run(pg.run_program(edited))
    if t["expect"] is None:
        assert r["error"] is None, r["error"]
    else:
        assert r["error"] is not None and _matches(r["error"], t["expect"]), r["error"]
        assert r["error"]["line"] is not None


def test_lessons_run_one_after_another_on_one_chain(mods):
    """A visitor does not get a fresh chain per lesson: every lesson must cope with what the ones
    before it left behind (an earlier NFT in the wallet picked by mistake failed lesson 6 this way)."""
    pg, _ = mods
    pg.reset_sandbox()
    for lesson in LESSONS:
        r = asyncio.run(pg.run_program(lesson["code"]))
        assert r["error"] is None, (lesson["id"], r["error"])
    for lesson in LESSONS:  # and a second lap, as after clicking around
        r = asyncio.run(pg.run_program(lesson["code"]))
        assert r["error"] is None, (lesson["id"], r["error"])


def test_lesson_ids_are_unique_and_fields_complete():
    keys = {"id", "title", "meta", "file", "heading", "intro", "steps", "code", "try_it"}
    assert len({x["id"] for x in LESSONS}) == len(LESSONS)
    for x in LESSONS:
        assert set(x) == keys, x["id"]


_PYODIDE_SHAPE = r"""
import asyncio, hashlib, importlib.abc, json, sys
BLOCK = {"coincurve", "aiohttp", "websockets"}
class _Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path, target=None):
        if name.split(".")[0] in BLOCK:
            raise ImportError(f"{name} is not available under Pyodide")
sys.meta_path.insert(0, _Block())
del hashlib.pbkdf2_hmac
sys.path.insert(0, sys.argv[1])
import playground, lessons
changed = playground.prepare_runtime()
out = {"changed": changed, "runs": {}}
for lesson in lessons.lesson_list():
    playground.reset_sandbox()
    r = asyncio.run(playground.run_program(lesson["code"]))
    out["runs"][lesson["id"]] = r["error"]
out["export"] = playground.export_project("demo-app", "wallet", "print(1)\n")["files"]
out["curve"] = type(sys.modules["coincurve"]).__name__, getattr(sys.modules["coincurve"], "_PYRXD_PLAYGROUND_SHIM", False)
print(json.dumps(out))
"""


def test_every_lesson_runs_in_the_pyodide_shape():
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _PYODIDE_SHAPE, str(_DIR)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stderr[-3000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["curve"] == ["module", True]
    assert any(c.startswith("secp256k1: sandbox_curve") for c in out["changed"])
    assert "pbkdf2_hmac: pure Python" in out["changed"]
    assert set(out["runs"]) == {x["id"] for x in LESSONS}
    assert all(err is None for err in out["runs"].values()), out["runs"]
    assert "playground/wallet.py" in out["export"] and "tests/test_mint.py" in out["export"]

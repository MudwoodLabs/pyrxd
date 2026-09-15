"""Every Photonic file pyrxd cites must be watched for drift.

pyrxd makes ~170 claims about Radiant-Core/Photonic-Wallet — docstrings asserting
what its verifiers do, protocol-spec rows, interop fixtures generated from its
actual TypeScript. None of them is evaluated by any test here, because they are
claims about another repository. ``scripts/check_photonic_drift.py`` watches the
cited files for change; this test is what stops that watcher going blind.

It runs OFFLINE and asserts one direction strictly: **anything cited is pinned.**
Cite a new Photonic file without pinning it and this fails, because a watcher
silently not covering a dependency is indistinguishable from one that is — the
failure mode this project keeps rediscovering, most recently in guards that were
structural about the check and hand-kept about the set.

The other direction (pinned, no longer cited) is harmless — a stale entry costs
one HTTP request — so the drift script reports it and this test does not fail on
it. ``also_watch`` covers a file we depend on before its citation lands.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
PIN_PATH = ROOT / "tests/fixtures/photonic_upstream_pin.json"
SCRIPT = ROOT / "scripts/check_photonic_drift.py"


def _drift_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_photonic_drift", SCRIPT)
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cited() -> dict[str, list[str]]:
    paths: dict[str, list[str]] = _drift_module().cited_paths(ROOT)
    return paths


@pytest.fixture(scope="module")
def pin() -> dict[str, Any]:
    assert PIN_PATH.exists(), f"{PIN_PATH} missing — python scripts/check_photonic_drift.py --update-pin"
    data: dict[str, Any] = json.loads(PIN_PATH.read_text(encoding="utf-8"))
    return data


def test_the_scan_finds_citations_at_all(cited: dict[str, list[str]]) -> None:
    """Non-vacuity. Without this the rest passes trivially on an empty set.

    pyrxd cites Photonic in the protocol spec, the Glyph builders and the interop
    fixtures; a scan returning nothing means the citation format moved or the
    walker broke, not that the dependency went away.
    """
    assert cited, (
        "no Photonic citations found anywhere in src/, tests/, docs/ or scripts/. "
        "The scan is broken — every other assertion in this file is now vacuous."
    )
    assert len(cited) >= 10, f"only {len(cited)} cited paths; expected the full surface (was 26)"


def test_the_pin_is_not_empty(pin: dict[str, Any]) -> None:
    assert pin.get("files"), "the pin records no files — the drift watcher checks nothing"
    assert len(pin["commit"]) >= 7, f"pin commit {pin['commit']!r} is not a usable sha"


def test_every_cited_photonic_file_is_pinned(cited: dict[str, list[str]], pin: dict[str, Any]) -> None:
    """The load-bearing one: you cannot depend on a Photonic file unwatched."""
    known = set(pin["files"]) | set(pin.get("not_found_at_this_commit", []))
    unpinned = {path: sorted(set(who)) for path, who in cited.items() if path not in known}
    assert not unpinned, (
        "these Photonic files are cited by pyrxd but not watched for drift:\n"
        + "\n".join(f"  {p}\n      cited by {', '.join(w[:3])}" for p, w in sorted(unpinned.items()))
        + "\n\nRefresh with: python scripts/check_photonic_drift.py --update-pin"
    )


def test_also_watch_entries_are_really_pinned(pin: dict[str, Any]) -> None:
    """``also_watch`` must not become a list of names nothing fetches."""
    missing = [p for p in pin.get("also_watch", []) if p not in pin["files"]]
    assert not missing, f"also_watch names files absent from the pin, so unwatched: {missing}"

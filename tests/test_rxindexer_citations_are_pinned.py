"""Every RXinDexer file pyrxd cites must be watched for drift — the WAVE rule is transcribed from it.

``pyrxd.glyph.wave_rules`` and ``tests/test_wave_claim_registers_with_the_indexer.py`` carry a
transcription of RXinDexer's WAVE claim rule (``validate_wave_name``, the claim path in
``process_tx``, the backfill, the envelope parse). A transcription is a claim about another
repository that no test here can evaluate: if upstream changes the rule, every test in this
repo stays green and pyrxd goes on refusing or accepting names by a rule the indexer no longer
applies. ``scripts/check_photonic_drift.py --target rxindexer`` watches the cited files; this
test runs OFFLINE and stops that watcher going blind, exactly as
``test_photonic_citations_are_pinned.py`` does for Photonic.

It also ties the pin to the transcription: the commit the transcription names must be the
commit the pin records, or the digests describe a different text from the one transcribed.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/check_photonic_drift.py"
TRANSCRIPTIONS = (
    ROOT / "src/pyrxd/glyph/wave_rules.py",
    ROOT / "tests/test_wave_claim_registers_with_the_indexer.py",
)


def _drift_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_upstream_drift", SCRIPT)
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def drift() -> ModuleType:
    return _drift_module()


@pytest.fixture(scope="module")
def cited(drift: ModuleType) -> dict[str, list[str]]:
    paths: dict[str, list[str]] = drift.cited_paths(ROOT, drift.RXINDEXER)
    return paths


@pytest.fixture(scope="module")
def pin(drift: ModuleType) -> dict[str, Any]:
    path = ROOT / drift.RXINDEXER.pin_path
    assert path.exists(), f"{path} missing — python scripts/check_photonic_drift.py --target rxindexer --update-pin"
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def test_the_scan_finds_the_transcribed_files(cited: dict[str, list[str]]) -> None:
    """Non-vacuity: the two files the WAVE rule is transcribed from must be among the cited."""
    assert {"electrumx/server/wave_index.py", "electrumx/lib/glyph.py"} <= set(cited)


def test_every_cited_rxindexer_file_is_pinned(cited: dict[str, list[str]], pin: dict[str, Any]) -> None:
    known = set(pin["files"]) | set(pin.get("not_found_at_this_commit", []))
    unpinned = {path: sorted(set(who)) for path, who in cited.items() if path not in known}
    assert not unpinned, (
        "these RXinDexer files are cited by pyrxd but not watched for drift:\n"
        + "\n".join(f"  {p}\n      cited by {', '.join(w[:3])}" for p, w in sorted(unpinned.items()))
        + "\n\nRefresh with: python scripts/check_photonic_drift.py --target rxindexer --update-pin"
    )


def test_the_transcription_names_the_pinned_commit(pin: dict[str, Any]) -> None:
    """A transcription citing commit X checked against digests taken at commit Y proves nothing."""
    assert pin["repo"] == "Radiant-Core/RXinDexer"
    for path in TRANSCRIPTIONS:
        text = path.read_text(encoding="utf-8")
        named = set(re.findall(r"\bca8a6a4e[0-9a-f]*\b", text))
        assert named, f"{path.name} names no RXinDexer commit"
        assert all(pin["commit"].startswith(c) for c in named), (path.name, named, pin["commit"])


def test_the_photonic_pin_is_not_mistaken_for_this_one(drift: ModuleType) -> None:
    """The two targets scan for disjoint path shapes, so neither pin can satisfy the other."""
    assert drift.RXINDEXER.pin_path != drift.PHOTONIC.pin_path
    assert not drift.RXINDEXER.citation_re.search("packages/lib/src/wave.ts")
    assert not drift.PHOTONIC.citation_re.search("electrumx/server/wave_index.py")

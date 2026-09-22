"""The HashMark spec pyrxd writes against must stay pinned and cited consistently.

pyrxd's HashMark decoder was written from ``HASHMARK_PROTOCOL.md`` alone, without
reading the reference source, and ``encode_hashmark`` was written the same way.
That independence is the whole value of ``test_hashmark_mainnet_vectors.py`` (his
writer, our reader) and ``test_hashmark_encoder.py`` (our writer, his reader) —
without it, both sides are pyrxd agreeing with pyrxd, which is how this repository
once published conformance vectors that accepted an exploitable HTLC ordering.

A spec that moves under a DECODER is a quiet problem: records stop decoding and
someone notices. A spec that moves under an ENCODER puts wrong bytes on chain
under a real signature, permanently, and the writer is the last party to find out.

So this file asserts, offline, that:

* the pin is well-formed and names a real commit;
* every HashMark citation anywhere in ``src/`` or ``tests/`` names the repository
  the pin names — a second, unpinned upstream is exactly the drift this guards.

The second direction (pinned but no longer cited) is harmless and is not asserted:
a stale entry costs one HTTP request. The set of citations is DERIVED by scanning,
never listed here — a hand-kept list of what a guard covers is how a guard comes to
pass vacuously over the case it was written for.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
PIN_PATH = ROOT / "tests/fixtures/hashmark_upstream_pin.json"

#: Any GitHub repo reference whose name mentions hashmark. Deliberately not
#: anchored to the pinned owner: a citation of SOMEONE ELSE'S hashmark fork is
#: precisely what this must catch, and anchoring the pattern to the pinned owner
#: would make it invisible.
_REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]*[Hh]ash[Mm]ark[A-Za-z0-9_.-]*)")
_SHA_RE = re.compile(r"\A[0-9a-f]{40}\Z")
_DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")


@pytest.fixture(scope="module")
def pin() -> dict[str, Any]:
    assert PIN_PATH.exists(), f"{PIN_PATH} missing — the encoder has no pinned spec to have been written against"
    data: dict[str, Any] = json.loads(PIN_PATH.read_text(encoding="utf-8"))
    return data


def _searchable_files() -> list[Path]:
    """Every shipped source and test file that mentions HashMark at all.

    Derived, not listed. ``docs/`` is excluded on purpose: prose there cites the
    protocol by name in passing, and pulling it in would make this guard about
    documentation style rather than about what the code was written against.
    """
    out = []
    for base in (ROOT / "src", ROOT / "tests"):
        for path in base.rglob("*"):
            if path.suffix not in {".py", ".js", ".json"} or not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):  # pragma: no cover - binary or unreadable
                continue
            if "hashmark" in text.lower():
                out.append(path)
    return out


def test_the_scan_finds_hashmark_files_at_all() -> None:
    """Non-vacuity. Without this, every assertion below passes on an empty set.

    pyrxd's HashMark surface is the script module, the inspector, the CLI and
    five test files; a scan returning nothing means the walker broke, not that
    the dependency went away.
    """
    found = _searchable_files()
    assert len(found) >= 5, f"only {len(found)} files mention HashMark; the scan is broken, not the dependency"
    assert any(p.name == "hashmark.py" for p in found), "the scan did not even find src/pyrxd/script/hashmark.py"


def test_the_pin_is_well_formed(pin: dict[str, Any]) -> None:
    assert pin.get("repo"), "the pin names no repository"
    assert pin.get("license") == "MIT", f"license {pin.get('license')!r} — the citation in hashmark.py claims MIT"
    assert _SHA_RE.match(pin.get("commit", "")), f"pin commit {pin.get('commit')!r} is not a full 40-hex sha"
    assert pin.get("spec") in pin.get("files", {}), "the pin names a spec file it does not record a digest for"


def test_every_pinned_digest_is_a_lowercase_sha256(pin: dict[str, Any]) -> None:
    """A digest with a typo in it can never match, so the watcher would report
    drift forever — and a watcher that is always red is one nobody reads."""
    bad = {name: d for name, d in pin["files"].items() if not _DIGEST_RE.match(d)}
    assert not bad, f"these pin entries are not lowercase 64-hex sha256: {bad}"


def test_the_pin_records_the_reference_implementation_not_only_the_spec(pin: dict[str, Any]) -> None:
    """The encoder is verified against his DECODER, so his decoder's source is a
    dependency of the proof even though we must not read it."""
    files = set(pin["files"])
    assert "packages/protocol/src/decode.ts" in files, (
        "the reference decoder is not pinned, so the cross-implementation proof in "
        "test_hashmark_encoder.py is running against an unknown version of it"
    )


def test_every_hashmark_citation_names_the_pinned_repo(pin: dict[str, Any]) -> None:
    """The load-bearing one: no second, unpinned HashMark upstream.

    A fork or a moved repository cited from one file and pinned from another is
    the drift that makes a pin certify nothing.
    """
    expected = pin["repo"]
    wrong: dict[str, set[str]] = {}
    seen = 0
    for path in _searchable_files():
        for repo in _REPO_RE.findall(path.read_text(encoding="utf-8")):
            seen += 1
            if repo.removesuffix(".git") != expected:
                wrong.setdefault(str(path.relative_to(ROOT)), set()).add(repo)
    assert seen, f"no file cites a HashMark repository at all — {PIN_PATH.name} is pinning something nothing uses"
    assert not wrong, f"these cite a HashMark repo other than the pinned {expected}: {wrong}"


def test_the_encoder_module_cites_the_pinned_repo_and_the_pin_itself() -> None:
    """The module the pin exists FOR has to point back at it.

    Without this the pin is reachable only from this test: someone rewriting the
    module docstring drops the citation, every assertion above still passes on the
    other files, and the encoder's provenance quietly stops being recorded where
    the next reader of the encoder will look.
    """
    source = (ROOT / "src/pyrxd/script/hashmark.py").read_text(encoding="utf-8")
    assert _REPO_RE.search(source), "src/pyrxd/script/hashmark.py no longer cites the HashMark repository"
    assert PIN_PATH.name in source, (
        f"src/pyrxd/script/hashmark.py does not mention {PIN_PATH.name}, so a reader of the "
        "encoder has no way to find which upstream commit it was written against"
    )

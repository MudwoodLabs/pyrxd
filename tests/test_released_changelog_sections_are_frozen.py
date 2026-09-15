"""A released CHANGELOG section is a claim about what shipped, and it must stop changing.

SIX entries drifted into `## [0.23.0]` after v0.23.0 was tagged, across five separate PRs — each
one a public statement that the release contained work it did not. Mine, all of them: the section
sits directly below `## [Unreleased]`, both carry a `### Fixed`, and appending to the wrong one
looks identical to appending to the right one in a diff.

WHY A DIGEST AND NOT THE GIT TAG. The obvious check is "compare each released section against
`git show v<version>:CHANGELOG.md`". That check cannot run where it matters: `.github/workflows/
ci.yml` uses `actions/checkout` with no `fetch-depth`, which is a depth-1 clone with no tags, so
the comparison would skip in CI and pass locally — a guard CI declines to run, which is worse than
no guard because it looks green. Digesting the file against a committed manifest needs nothing but
the file.

WHAT THIS DOES AND DOES NOT CLAIM. It prevents RECURRENCE; it did not detect the six. The manifest
is generated from the tree at the moment it is written, so it freezes whatever is there — the six
were moved to `[Unreleased]` first, by hand, and the manifest was generated after. A future entry
appended to a released section changes that section's digest and fails here.

Editing a released section on purpose (a typo, a dead link) also fails, deliberately: regenerate
with `python tests/test_released_changelog_sections_are_frozen.py --regen` and the diff then shows
a reviewer exactly which shipped record changed.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CHANGELOG = _ROOT / "CHANGELOG.md"
_MANIFEST = _ROOT / "tests" / "fixtures" / "changelog_released_sections.json"

#: `## [1.2.3] — 2026-01-01`. `## [Unreleased]` deliberately does not match: it is the one section
#: that is supposed to change, and it is where every new entry belongs.
_RELEASED = re.compile(r"^## \[(\d+\.\d+\.\d+)\]")


def _released_sections() -> dict[str, str]:
    """`{version: sha256 of that section's text}` for every RELEASED section."""
    lines = _CHANGELOG.read_text(encoding="utf-8").split("\n")
    starts: list[tuple[int, str | None]] = []
    for i, line in enumerate(lines):
        if line.startswith("## "):
            m = _RELEASED.match(line)
            starts.append((i, m.group(1) if m else None))

    out: dict[str, str] = {}
    for idx, (start, version) in enumerate(starts):
        if version is None:
            continue
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        body = "\n".join(lines[start:end])
        out[version] = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return out


def test_no_released_section_has_changed() -> None:
    actual = _released_sections()
    assert len(actual) >= 20, (
        f"only {len(actual)} released sections found — the heading pattern has stopped matching, "
        "so this guard would pass over anything"
    )
    expected = json.loads(_MANIFEST.read_text(encoding="utf-8"))

    changed = sorted(v for v in actual if v in expected and actual[v] != expected[v])
    added = sorted(set(actual) - set(expected))
    removed = sorted(set(expected) - set(actual))

    assert not changed, (
        f"released CHANGELOG sections were edited: {changed}. A released section states what that "
        "version SHIPPED — if you are adding a changelog entry it belongs under `## [Unreleased]`, "
        "not here. Six entries reached `[0.23.0]` this way. If the edit is deliberate, run "
        "`python tests/test_released_changelog_sections_are_frozen.py --regen` so the change is "
        "visible in review."
    )
    assert not removed, (
        f"released sections vanished from CHANGELOG.md: {removed}. Rewriting release history needs "
        "a deliberate --regen, not a silent drop."
    )
    assert not added, (
        f"released sections {added} are not in the manifest — a new release was cut without "
        "regenerating it, so those sections are unguarded. Run --regen."
    )


if __name__ == "__main__":  # pragma: no cover - maintenance entry point
    import sys

    if "--regen" not in sys.argv:
        raise SystemExit("pass --regen to rewrite the manifest from the current CHANGELOG.md")
    _MANIFEST.write_text(json.dumps(_released_sections(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {_MANIFEST.relative_to(_ROOT)} ({len(_released_sections())} released sections)")

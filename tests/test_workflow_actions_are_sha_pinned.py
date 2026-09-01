"""Every `uses:` in every GitHub workflow must be pinned to a full commit SHA.

A floating tag (`actions/checkout@v7`) resolves at run time to whatever that tag points at THEN.
Whoever controls the tag controls what executes in CI, with the repository checked out and the
job's secrets in scope. A SHA cannot be moved.

WHY THIS IS A TEST AND NOT A SCRIPT. The repo already learned that a checker wired to nothing is
not a checker: two mutation groups were added to `scripts/mutation_groups.py` and not to the CI
matrix, and a coverage-omission script sat as a taskipy task nothing invoked. `pytest tests/` runs
in CI unconditionally, so a test has no separate wiring to forget — the weakest link in
"detect" is the wiring, and this removes it.

HOW IT WAS FOUND. Dependabot #550 proposed bumping `actions/checkout@v4` -> `@v7` in
`mutation.yml`. Merging it would have been an improvement in version and a regression in posture:
every other checkout in the repo is SHA-pinned, and that PR would have left two floating. Pinning
them to the SHA the rest of the repo already uses achieves the bump AND the consistency. A third
straggler — `setup-python@v7`, the last floating tag in the repository — turned up only because
fixing the two prompted a sweep for the whole set rather than the two the PR named.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_WORKFLOWS = sorted((Path(__file__).resolve().parent.parent / ".github" / "workflows").glob("*.yml"))

#: `uses: owner/repo@ref` or `uses: ./local/path`. Docker refs (`docker://`) are out of scope.
_USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def test_there_are_workflows_to_check() -> None:
    """Guards the guard. A glob that silently matches nothing passes every assertion below."""
    assert len(_WORKFLOWS) >= 5, f"only found {len(_WORKFLOWS)} workflow files; the glob is wrong"


@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_every_action_reference_is_sha_pinned(path: Path) -> None:
    floating: list[tuple[int, str]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        m = _USES.match(line)
        if not m:
            continue
        ref = m.group("ref")
        if ref.startswith("./") or ref.startswith("docker://"):
            continue  # a local composite action is this repo's own code; a docker ref is digest-pinned separately
        _, _, version = ref.partition("@")
        if not _SHA.match(version):
            floating.append((lineno, line.strip()))

    assert not floating, (
        f"{path.name} references actions by a MOVABLE ref, so whoever controls the tag controls "
        f"what runs in CI with this repo checked out:\n"
        + "\n".join(f"  {path.name}:{n}  {text}" for n, text in floating)
        + "\n\nPin to the full commit SHA and keep the version in a trailing comment, e.g.\n"
        "  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1"
    )


def test_the_same_action_is_pinned_to_ONE_sha_everywhere() -> None:
    """Two SHAs for one action means a bump landed in some workflows and not others — the drift
    that leaves a stale, possibly-vulnerable version running in the lane nobody looked at."""
    seen: dict[str, set[str]] = {}
    for path in _WORKFLOWS:
        for line in path.read_text(encoding="utf-8").splitlines():
            m = _USES.match(line)
            if not m:
                continue
            ref = m.group("ref")
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            name, _, version = ref.partition("@")
            if _SHA.match(version):
                seen.setdefault(name, set()).add(version)

    split = {name: shas for name, shas in seen.items() if len(shas) > 1}
    assert not split, f"these actions are pinned to more than one SHA across workflows: {split}"

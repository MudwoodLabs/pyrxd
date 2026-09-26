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

ONE LAYER DOWN. A SHA fixes the action's own files, not what they download. The tests at the
bottom of this file cover an action whose action.yml pulls a container image by an input that
defaults to `latest`, which a SHA pin on `uses:` cannot see.
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
            # A local composite action is this repo's own code. No workflow has a docker:// ref,
            # and nothing here checks one.
            continue
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


# ─────────────────────────────────────────── what the pinned action then DOWNLOADS ──
#
# A SHA pin fixes the action's own files. It does not fix what those files fetch. The required
# "Scan for leaked secrets" check was pinned `trufflesecurity/trufflehog@<sha> # v3.97.5` and ran
# trufflehog 3.97.9: the action is a wrapper whose action.yml runs
# `docker run "${IMAGE}:${VERSION}"` with `version` defaulting to `latest`. Nothing above could
# see it, because the thing that floated was one layer below the `uses:` line these tests read.

#: Actions that pull WHAT RUNS through an input whose default MOVES, each mapped to
#: {input: (the floating default, the pattern an explicit value must match)}. REVIEWED, not
#: derived: CI cannot read another repository's action.yml offline, so each entry says where it
#: was read.
_FLOATING_RUNTIME_INPUTS: dict[str, dict[str, tuple[str, str]]] = {
    # action.yml at f714bf45 (v3.97.5) and 4dd8831c (v3.97.9), byte-identical, read 2026-09-25:
    # `version` defaults to "latest"; the step runs `docker run "${IMAGE}:${VERSION}"`. An image
    # TAG can be re-pushed, so the value must carry a digest; the tag before it is only a label.
    "trufflesecurity/trufflehog": {
        "version": ("latest", r"^(?P<label>\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}$"),
    },
}

#: Every OTHER third-party action a required check's job uses, read for the same property and
#: not put in `_FLOATING_RUNTIME_INPUTS`, with what was read and why. REVIEWED 2026-09-25 against
#: each action.yml at the SHA pinned in the workflows. The set is not hand-kept in the other
#: direction: `test_every_action_a_required_check_uses_has_been_reviewed` derives the actions
#: from the jobs that produce a required check, so a new one fails until someone reads it.
_REVIEWED_ACTIONS: dict[str, str] = {
    "actions/checkout": "node action; no input selects a tool or image version",
    "actions/cache": "node action; no input selects a tool or image version",
    "actions/setup-python": (
        "installs the Python that `python-version` names (every use sets it); the patch release "
        "comes from GitHub's toolcache/manifest, and `check-latest` defaults to false. A "
        "toolchain for the code under test, not the judge of a check"
    ),
    "github/codeql-action/init": (
        "`tools` unset takes the CLI version GitHub's feature flags recommend "
        "(src/feature-flags.ts at 1c5b6756), so it DOES float, but inside GitHub, the party that "
        "already runs the job, not a third-party registry. `tools: linked` would pin it to the "
        "bundle this SHA ships; not done here (see the PR that added this entry)"
    ),
    "github/codeql-action/analyze": "no version input; runs the CLI that init set up",
    "google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml": (
        "reusable workflow; calls osv-scanner-action@7f58dd67, whose action.yml fixes "
        "`docker://ghcr.io/google/osv-scanner-action:v2.6.0`: a version TAG chosen by the action, "
        "not an input this repo could pin, and not `latest`"
    ),
}

_TRAILING_VERSION = re.compile(r"#\s*v?(?P<version>\d+\.\d+\.\d+)\s*$")


def _load_yaml(path: Path) -> dict:
    import yaml

    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name} did not parse to a mapping"
    return doc


def _third_party(ref: str) -> str | None:
    """`owner/repo[/path]` for a remote action ref, None for a local or docker one."""
    if ref.startswith(("./", "docker://")):
        return None
    return ref.partition("@")[0]


def _steps_using(action: str) -> list[tuple[Path, str, dict]]:
    """(workflow, job id, step) for every step, in every workflow, that uses `action`."""
    found = []
    for path in _WORKFLOWS:
        for job_id, job in (_load_yaml(path).get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if _third_party(str(step.get("uses", ""))) == action:
                    found.append((path, job_id, step))
    return found


def test_an_action_that_downloads_a_floating_default_has_it_pinned_by_digest() -> None:
    checked = 0
    for action, inputs in _FLOATING_RUNTIME_INPUTS.items():
        for path, job_id, step in _steps_using(action):
            given = step.get("with") or {}
            for name, (floating, pattern) in inputs.items():
                checked += 1
                value = given.get(name)
                assert value is not None and str(value) != floating, (
                    f"{path.name} job {job_id}: `{action}` gets no `{name}:`, so it runs its default "
                    f"{floating!r} — whatever was pushed last, whatever the SHA pin on `uses:` says. "
                    f"Set `{name}:` explicitly (see the comment in trufflehog.yml for how)."
                )
                assert re.match(pattern, str(value)), (
                    f"{path.name} job {job_id}: `{action}` `{name}: {value}` does not match {pattern}. "
                    f"A bare tag can be re-pushed; pin the digest."
                )
    assert checked, "no step uses an action in _FLOATING_RUNTIME_INPUTS; this test checked nothing"


def test_the_pinned_image_label_matches_the_actions_version_comment() -> None:
    """Dependabot bumps the `uses:` SHA and its `# vX.Y.Z` comment. It cannot see a `version:`
    input, so without this a bump would move the WRAPPER and leave the scanner where it was, under
    a comment claiming otherwise: the defect this section exists for, reintroduced by automation."""
    checked = 0
    for action, inputs in _FLOATING_RUNTIME_INPUTS.items():
        for path, job_id, step in _steps_using(action):
            ref = str(step["uses"])
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if f"uses: {ref}" in ln]
            comments = {m.group("version") for ln in lines if (m := _TRAILING_VERSION.search(ln))}
            assert len(comments) == 1, f"{path.name}: expected one `# vX.Y.Z` comment on `uses: {ref}`, got {lines}"
            (commented,) = comments
            for name, (_floating, pattern) in inputs.items():
                m = re.match(pattern, str((step.get("with") or {}).get(name, "")))
                assert m, f"{path.name} job {job_id}: `{name}` is not pinned; see the test above"
                checked += 1
                assert m.group("label") == commented, (
                    f"{path.name} job {job_id}: `uses: {action}` is commented v{commented} but `{name}:` "
                    f"runs {m.group('label')}. Update `{name}:` to {commented} with that tag's digest."
                )
    assert checked, "nothing was compared; this test checked nothing"


def test_every_action_a_required_check_uses_has_been_reviewed() -> None:
    """The universe is DERIVED: every third-party action in a job that produces a required check
    (`_REQUIRED_CHECKS`, via the same job-name derivation the every-PR-base test uses). The
    verdicts are reviewed. Both directions: an unreviewed action fails, and so does an entry for an
    action no required job uses any more."""
    from tests.test_ci_workflows_check_every_pr_base import _REQUIRED_CHECKS, _producers

    used: dict[str, set[str]] = {}
    for check in _REQUIRED_CHECKS:
        for path, job_id in _producers(check):
            job = _load_yaml(path)["jobs"][job_id]
            refs = [str(job["uses"])] if "uses" in job else [str(s.get("uses", "")) for s in job.get("steps") or []]
            for name in filter(None, map(_third_party, refs)):
                used.setdefault(name, set()).add(f"{path.name}:{job_id}")

    assert "trufflesecurity/trufflehog" in used, f"the derivation missed the known case; it found {sorted(used)}"
    unreviewed = sorted(set(used) - set(_FLOATING_RUNTIME_INPUTS) - set(_REVIEWED_ACTIONS))
    assert not unreviewed, (
        f"required checks use actions nobody has read for a floating runtime input: "
        f"{ {a: sorted(used[a]) for a in unreviewed} }. Read each one's action.yml at the pinned SHA "
        f"and add it to _FLOATING_RUNTIME_INPUTS or _REVIEWED_ACTIONS with what you read."
    )
    stale = sorted(set(_REVIEWED_ACTIONS) - set(used))
    assert not stale, f"_REVIEWED_ACTIONS names actions no required check uses any more: {stale}"
    overlap = sorted(set(_REVIEWED_ACTIONS) & set(_FLOATING_RUNTIME_INPUTS))
    assert not overlap, f"these are in both registries: {overlap}"
    unused = sorted(a for a in _FLOATING_RUNTIME_INPUTS if not _steps_using(a))
    assert not unused, f"_FLOATING_RUNTIME_INPUTS names actions no workflow uses: {unused}"

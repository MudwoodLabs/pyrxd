"""A release tag is not a branch, so branch protection never applied to it.

`publish.yml` triggers on ``release: published``. A release can be cut from ANY tag on ANY
commit — tags are arbitrary refs, `tags/protection` is not configured, and required status
checks protect *main*, not a tag. Before the `verify` job existed the whole workflow was
``build -> publish``: nothing between a tag and PyPI ran a single test.

The `pypi` environment (required reviewer, `v*` tags only, admin bypass disabled) closes
the question of WHO may publish. It cannot answer WHETHER the code works — an approver
sees "approve deployment", not "this commit was never on main".

So the gate is structural: `publish` depends on `build`, `build` depends on `verify`, and
`verify` refuses a commit that is not an ancestor of `origin/main` and then runs the
suite. This test pins that chain. It is the CI half of "a gate protects a PLACE, not a
change" — the place here is main, and a tag is the route around it.
"""

from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML is a dev dependency; this test parses a workflow")

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PUBLISH = _ROOT / ".github" / "workflows" / "publish.yml"


def _workflow() -> dict:
    return yaml.safe_load(_PUBLISH.read_text(encoding="utf-8"))


def _needs(job: dict) -> set[str]:
    n = job.get("needs") or []
    return {n} if isinstance(n, str) else set(n)


def _transitive_needs(jobs: dict, start: str) -> set[str]:
    seen: set[str] = set()
    stack = list(_needs(jobs.get(start, {})))
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(_needs(jobs.get(name, {})))
    return seen


def test_the_workflow_still_triggers_on_a_release() -> None:
    """Non-vacuity. If the trigger changed, every assertion below is about nothing."""
    wf = _workflow()
    on = wf.get("on") or wf.get(True)  # PyYAML parses a bare `on:` key as the bool True
    assert on and "release" in on, (
        "publish.yml no longer triggers on a release — re-read this module's docstring before "
        "editing it; the whole premise here is that a tag bypasses branch protection"
    )


def test_publishing_transitively_requires_the_verify_job() -> None:
    """The chain itself: nothing reaches PyPI without `verify` having run."""
    jobs = _workflow()["jobs"]
    assert "publish" in jobs, "the publish job was renamed or removed — update this guard"
    upstream = _transitive_needs(jobs, "publish")
    assert "verify" in upstream, (
        f"the `publish` job no longer depends (even transitively) on `verify`; it needs "
        f"{sorted(upstream) or 'nothing'}. A release tag could then publish code that was "
        "never on main and never tested, behind an approval click that says nothing about "
        "either."
    )


def test_verify_refuses_a_commit_that_is_not_on_main() -> None:
    """The ancestry check is the half branch protection cannot do for itself."""
    steps = _workflow()["jobs"]["verify"]["steps"]
    body = "\n".join(s.get("run", "") for s in steps)
    assert "merge-base --is-ancestor" in body, (
        "the `verify` job no longer checks that the tagged commit is an ancestor of main. "
        "Without it a tag on an arbitrary commit — one that never crossed a PR, so never "
        "crossed the required status checks — can still be released."
    )
    assert "refs/remotes/origin/main" in body, (
        "the ancestry check no longer uses a FULLY QUALIFIED ref. A bare `origin/main` is "
        "ambiguous: gitrevisions checks refs/tags/<name> BEFORE refs/remotes/<name>, and "
        "actions/checkout with fetch-depth: 0 fetches all tags — so a tag named `origin/main` "
        "shadows the remote-tracking branch and this gate passes for a commit that never "
        "reached main. git only warns; it does not fail. Tags are unprotected here."
    )


def test_the_release_gate_checks_the_same_types_as_the_pr_gate() -> None:
    """A release must not be refused for something no PR gate could have caught.

    `verify` runs `task typecheck` (10 paths). CI's Type check ran mypy over 3 of them, so
    7 were checked only AFTER the tag was cut — and retrying a refused release needs a new
    tag. `poetry.lock` is gitignored, so `verify` also resolves dependencies fresh at release
    time, and the typecheck of `network/electrumx.py` is documented as sensitive to which
    `websockets` major gets resolved. Both now run the same task, so the release gate is a
    no-op rather than a surprise.
    """
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "task typecheck" in ci, (
        "ci.yml no longer runs `task typecheck`, so the release-time typecheck covers paths "
        "no PR gate does — a release can be refused for a regression every PR let through"
    )


def test_verify_actually_runs_the_tests() -> None:
    """An ancestry check alone would prove provenance, not correctness."""
    steps = _workflow()["jobs"]["verify"]["steps"]
    body = "\n".join(s.get("run", "") for s in steps)
    assert "pytest" in body, (
        "the `verify` job no longer runs the test suite, so the artifact about to be uploaded "
        "is only known to come from main — not to work"
    )


def test_the_environment_comment_does_not_overclaim() -> None:
    """This file's own history is why. `publish.yml` asserted "The `pypi` environment is the
    second-factor" while that environment had ZERO protection rules — a confident sentence
    next to a setting nobody had checked. The environment is configured now; the comment must
    not drift back into describing a gate as broader than it is."""
    text = " ".join(_PUBLISH.read_text(encoding="utf-8").split())
    assert "Optional but recommended: configure the `pypi` environment" not in text, (
        "publish.yml has reverted to calling the pypi environment optional; it is configured "
        "(required reviewer, v* tags only, no admin bypass) and the comment should say so"
    )

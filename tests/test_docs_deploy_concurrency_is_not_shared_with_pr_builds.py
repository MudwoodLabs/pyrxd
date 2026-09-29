"""No pull-request run of the docs workflow can cancel a pending deploy from main (#749).

`.github/workflows/docs.yml` used one repository-wide concurrency group, `pages`, for every run.
GitHub keeps at most ONE pending run per group and cancels the older pending run when another
queues, even with `cancel-in-progress: false`. Observed 2026-09-26: a PR's docs build was
cancelled eight seconds after it queued, by another branch's PR build. The same rule lets a PR
build queued behind a pending deploy from main cancel that deploy, leaving the published docs and
the /inspect/ and /verify/ pages stale with nothing red to say so.

The guard renders each job's concurrency group the way GitHub would for a pull_request event and
for a push to main, and requires that no job able to run on a PR lands in the deploy's group.
The sibling guard for the traffic workflow is
`tests/test_pr_code_never_runs_with_the_traffic_write_token.py`.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import yaml

_WORKFLOW = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "docs.yml"
_EXCLUDES_PULL_REQUEST = "github.event_name != 'pull_request'"

#: The contexts a group is rendered in: two different PRs, and a push to main.
_PR_1 = {
    "github.event_name": "pull_request",
    "github.ref": "refs/pull/1/merge",
    "github.event.pull_request.number": "1",
}
_PR_2 = {
    "github.event_name": "pull_request",
    "github.ref": "refs/pull/2/merge",
    "github.event.pull_request.number": "2",
}
_MAIN = {"github.event_name": "push", "github.ref": "refs/heads/main", "github.event.pull_request.number": ""}


def _doc() -> dict[str, Any]:
    doc = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "docs.yml did not parse to a mapping"
    return doc


def _render(group: object, context: dict[str, str]) -> str:
    """The group string for *context*. Only plain ``${{ <context key> }}`` substitutions are
    understood; anything else fails, so an unfamiliar expression cannot pass by being unread."""

    def sub(m: re.Match[str]) -> str:
        key = m.group(1).strip()
        assert key in context, f"cannot render the concurrency expression {m.group(0)!r}; extend this guard"
        return context[key]

    rendered = re.sub(r"\$\{\{(.*?)\}\}", sub, str(group))
    assert "${{" not in rendered, rendered
    return rendered


def _group(block: object) -> object | None:
    if block is None:
        return None
    return block.get("group") if isinstance(block, dict) else block


def _can_run_on_pull_request(job: dict[str, Any]) -> bool:
    """False only when the job's `if:` is a conjunction that includes the PR exclusion."""
    cond = " ".join(str(job.get("if", "")).replace("${{", "").replace("}}", "").split())
    if not cond or "||" in cond:
        return True
    return _EXCLUDES_PULL_REQUEST not in [c.strip() for c in cond.split("&&")]


def _groups(job: dict[str, Any], context: dict[str, str]) -> set[str]:
    """Every concurrency group this job's run joins: the workflow's, and the job's own."""
    found = set()
    for block in (_doc().get("concurrency"), job.get("concurrency")):
        group = _group(block)
        if group is not None:
            found.add(_render(group, context))
    return found


def _deploy_groups() -> set[str]:
    deploy = _doc()["jobs"]["deploy"]
    return _groups(deploy, _MAIN)


def test_the_deploy_is_serialised_in_the_pages_group_and_never_cancelled() -> None:
    """The honest half: the deploy still has its group, so the check below is not vacuous."""
    deploy = _doc()["jobs"]["deploy"]
    assert not _can_run_on_pull_request(deploy), "the deploy job must never run on a pull_request"
    assert deploy["concurrency"]["group"] == "pages"
    assert deploy["concurrency"]["cancel-in-progress"] is False


def test_no_job_a_pull_request_runs_joins_the_deploys_group() -> None:
    deploy_groups = _deploy_groups()
    assert deploy_groups == {"pages"}, deploy_groups
    pr_jobs = {jid: job for jid, job in _doc()["jobs"].items() if _can_run_on_pull_request(job)}
    assert pr_jobs, "no job runs on a pull_request: the build check has gone, or this guard is misreading"
    for jid, job in pr_jobs.items():
        for context in (_PR_1, _PR_2):
            shared = _groups(job, context) & deploy_groups
            assert not shared, f"job {jid!r} joins the deploy's group {shared} on a pull_request"


def test_two_prs_and_main_build_in_different_groups() -> None:
    """Per ref: one PR's build cannot displace another PR's, or main's."""
    build = _doc()["jobs"]["build"]
    rendered = [_groups(build, c) for c in (_PR_1, _PR_2, _MAIN)]
    assert all(rendered), "the build job has no concurrency group"
    assert rendered[0].isdisjoint(rendered[1]) and rendered[0].isdisjoint(rendered[2])
    assert rendered[1].isdisjoint(rendered[2])

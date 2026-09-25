"""A pull request's code must never run holding the traffic job's write token or its PAT.

`.github/workflows/traffic.yml` runs on `pull_request` (for PRs touching the collectors) as well
as daily. Until this file existed it was ONE job, granted `contents: write`, whose PR branch
IMPORTED the PR's copies of both collectors (`spec.loader.exec_module`) after a checkout that left
the token on disk (`persist-credentials` defaults to true). The run log of a PR run showed
`Contents: write` in the token's permissions, then the PR's code executing. For a PR from a branch
in this repository that token can push.

The same review found the rest of what this file pins:

* TRAFFIC_TOKEN was a REPOSITORY secret, readable by any workflow on any branch that names it.
  It now lives in the `traffic` environment, which admits only main, and the job checks that
  restriction before using it, because GitHub silently creates an unrestricted environment the
  first time a workflow names one that does not exist.
* PR runs and scheduled runs shared one concurrency group, so a pending PR run could cancel a
  pending scheduled one: GitHub keeps one PENDING run per group and cancels the older one even
  with `cancel-in-progress: false`.
* The commit step ran on `always()`, so a CANCELLED run went on to commit whatever the collectors
  had written by then.

Everything here reads the workflow YAML, and the environment check's shell step is EXECUTED
against a stand-in `gh` that answers with canned API responses, so the step that runs in CI is
the step that is tested.

WHAT THIS CANNOT SEE. Whether the environment really exists, whether the repository-level
TRAFFIC_TOKEN was deleted, and whether GitHub honours the settings; those live in repository
settings, which CI cannot read with the tokens it has. The environment check covers the first at
run time; the second needs the maintainer (see the PR that introduced this file).
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

import pytest

# A hard import, as in test_leak_scan_covers_what_is_published.py: if PyYAML stops arriving,
# collection fails loudly instead of every check here skipping.
import yaml

_WORKFLOW = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "traffic.yml"
_ENVIRONMENT = "traffic"
_EXCLUDES_PULL_REQUEST = "github.event_name != 'pull_request'"


def _doc() -> dict[str, Any]:
    doc = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "traffic.yml did not parse to a mapping"
    return doc


def _triggers() -> dict[str, Any]:
    doc = _doc()
    # PyYAML reads YAML 1.1, where a bare `on` key is the boolean True.
    return doc[True] if True in doc else doc["on"]


def _jobs() -> dict[str, dict[str, Any]]:
    return _doc()["jobs"]


def _can_run_on_pull_request(job: dict[str, Any]) -> bool:
    """False only when the job's `if:` is a conjunction that includes the PR exclusion. Anything
    this cannot read (an `||`, a negation spelled differently) counts as able to run on a PR,
    so an unfamiliar condition fails the permission test instead of slipping past it."""
    cond = " ".join(str(job.get("if", "")).replace("${{", "").replace("}}", "").split())
    if not cond or "||" in cond:
        return True
    return _EXCLUDES_PULL_REQUEST not in [c.strip() for c in cond.split("&&")]


def _pull_request_jobs() -> dict[str, dict[str, Any]]:
    jobs = {jid: job for jid, job in _jobs().items() if _can_run_on_pull_request(job)}
    assert jobs, "no job in traffic.yml can run on a pull request; this file would check nothing"
    return jobs


def _permissions(job: dict[str, Any]) -> Any:
    """The job's effective token permissions: its own block, else the workflow's."""
    return job["permissions"] if "permissions" in job else _doc().get("permissions")


def _checkouts(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in job.get("steps") or [] if str(s.get("uses", "")).startswith("actions/checkout@")]


def _step(job: dict[str, Any], name: str) -> dict[str, Any]:
    found = [s for s in job.get("steps") or [] if s.get("name") == name]
    assert len(found) == 1, f"expected one step named {name!r}, found {len(found)}"
    return found[0]


# ─────────────────────────────────────────────── the pull-request job ──


def test_the_workflow_still_runs_on_pull_requests_and_never_on_pull_request_target() -> None:
    """Non-vacuity, and the one trigger that would hand a fork's code a write token and secrets."""
    triggers = _triggers()
    assert "pull_request" in triggers, "traffic.yml no longer runs on pull_request; this file checks nothing"
    assert "pull_request_target" not in triggers


def test_every_job_a_pull_request_can_run_holds_no_write_permission() -> None:
    jobs = _pull_request_jobs()
    assert any("exec_module" in str(s.get("run", "")) for job in jobs.values() for s in job.get("steps") or []), (
        "the job that EXECUTES the PR's collectors is not among the PR jobs; this test is looking at the wrong job"
    )
    for job_id, job in jobs.items():
        perms = _permissions(job)
        assert perms not in ("write-all", None), f"job {job_id}: permissions {perms!r} on a pull_request run"
        if isinstance(perms, dict):
            writes = sorted(k for k, v in perms.items() if str(v) == "write")
            assert not writes, f"job {job_id} runs the PR's code with write access to {writes}"
        else:
            assert perms in ("read-all", {}), f"job {job_id}: unrecognised permissions {perms!r}"


def test_no_checkout_in_a_pull_request_job_leaves_credentials_on_disk() -> None:
    """Read-only is the first half. The second: `persist-credentials` defaults to TRUE, which
    writes the job token into the checkout's git config, where the PR's code can read it."""
    for job_id, job in _pull_request_jobs().items():
        checkouts = _checkouts(job)
        assert checkouts, f"job {job_id} has no checkout; this test checked nothing"
        for step in checkouts:
            assert (step.get("with") or {}).get("persist-credentials") is False, (
                f"job {job_id}: a checkout without `persist-credentials: false` leaves the token for the PR's code"
            )


def test_no_pull_request_job_names_a_secret_or_the_environment() -> None:
    for job_id, job in _pull_request_jobs().items():
        assert "environment" not in job, f"job {job_id} runs PR code inside the {job.get('environment')!r} environment"
        assert "secrets." not in json.dumps(job), f"job {job_id} references a secret on a pull_request run"


# ─────────────────────────────────────────────── the writing job ──


def _writer() -> tuple[str, dict[str, Any]]:
    writers = {jid: job for jid, job in _jobs().items() if (_permissions(job) or {}).get("contents") == "write"}
    assert list(writers) == ["collect"], f"expected exactly the `collect` job to write, found {sorted(writers)}"
    return "collect", writers["collect"]


def test_the_writing_job_never_runs_for_a_pull_request_but_still_writes() -> None:
    """The refusal and the honest path together: the daily job keeps `contents: write` (it pushes
    the history branch), and it is the one job a pull request can never start."""
    _job_id, job = _writer()
    assert not _can_run_on_pull_request(job), f"the writing job's condition {job.get('if')!r} admits pull requests"


def test_only_the_checkout_the_commit_step_pushes_from_keeps_credentials() -> None:
    """Write only where it pushes: of the writing job's two checkouts, the collector's keeps no
    token, and the one that does is the data branch the commit step pushes from."""
    _job_id, job = _writer()
    keeping = [s for s in _checkouts(job) if (s.get("with") or {}).get("persist-credentials") is not False]
    assert len(_checkouts(job)) == 2 and len(keeping) == 1, [s.get("name") for s in keeping]
    (data,) = keeping
    commit = _step(job, "Commit if anything changed")
    assert (data.get("with") or {}).get("path") == commit.get("working-directory") == "data"
    assert "git push" in commit["run"]


def test_the_traffic_token_is_read_only_inside_the_traffic_environment() -> None:
    """Every job that names a secret must run in the `traffic` environment, and the token must
    be named somewhere, so a rename cannot make this pass by referencing nothing."""
    referencing = {jid: job for jid, job in _jobs().items() if "secrets." in json.dumps(job)}
    assert "secrets.TRAFFIC_TOKEN" in _WORKFLOW.read_text(encoding="utf-8")
    assert list(referencing) == ["collect"], sorted(referencing)
    for job_id, job in referencing.items():
        env = job.get("environment")
        name = env.get("name") if isinstance(env, dict) else env
        assert name == _ENVIRONMENT, (
            f"job {job_id} reads a secret outside the {_ENVIRONMENT!r} environment ({env!r}): a repository "
            f"secret is readable by a workflow on any branch"
        )


def test_the_environment_is_checked_before_the_token_is_used() -> None:
    _job_id, job = _writer()
    names = [s.get("name") for s in job["steps"]]
    check = names.index("Check the traffic environment admits only main")
    token = next(i for i, s in enumerate(job["steps"]) if "secrets.TRAFFIC_TOKEN" in json.dumps(s))
    assert check < token, "the environment is checked only after the token has been handed to a step"
    step = job["steps"][check]
    assert not step.get("continue-on-error"), "a failed environment check must stop the job, not be recorded"
    assert (_permissions(job) or {}).get("actions") == "read", "the check needs `actions: read` to read environments"


# ─────────────────────────────── the environment check, EXECUTED ──

_POLICY_MAIN = {"branch_policies": [{"name": "main", "type": "branch"}]}


def _run_environment_check(tmp_path: pathlib.Path, responses: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    """Run the step's own shell text with a stand-in `gh` first on PATH. `responses` maps the API
    path after `repos/<repo>/environments/` to a JSON body, or to None for an HTTP 404."""
    _job_id, job = _writer()
    step = _step(job, "Check the traffic environment admits only main")
    answers = tmp_path / "answers"
    answers.mkdir()
    for path, body in responses.items():
        if body is not None:
            (answers / path.replace("/", "__")).write_text(json.dumps(body))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "gh"
    fake.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "assert sys.argv[1] == 'api', sys.argv\n"
        "prefix = 'repos/' + os.environ['REPO'] + '/environments/'\n"
        "assert sys.argv[2].startswith(prefix), sys.argv\n"
        "f = pathlib.Path(os.environ['FAKE_GH_ANSWERS']) / sys.argv[2][len(prefix):].replace('/', '__')\n"
        "if not f.exists():\n"
        "    sys.stderr.write('gh: Not Found (HTTP 404)\\n'); sys.exit(1)\n"
        "sys.stdout.write(f.read_text())\n"
    )
    fake.chmod(0o755)
    env = {
        **os.environ,
        **{k: str(v) for k, v in (step.get("env") or {}).items() if "${{" not in str(v)},
        "REPO": "MudwoodLabs/pyrxd",
        "GH_TOKEN": "unused",
        "FAKE_GH_ANSWERS": str(answers),
        "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
    }
    script = tmp_path / "step.sh"
    script.write_text(step["run"])
    # GitHub runs a `run:` block with `bash -e {0}` when no shell is named.
    return subprocess.run(["bash", "-e", str(script)], env=env, capture_output=True, text=True, timeout=60)


@pytest.mark.parametrize(
    ("responses", "admits"),
    [
        (
            {
                "traffic": {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                "traffic/deployment-branch-policies": _POLICY_MAIN,
            },
            "the branch main",
        ),
        (
            {"traffic": {"deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}},
            "protected branches only",
        ),
    ],
    ids=["selected-branch-main", "protected-branches-only"],
)
def test_the_environment_check_passes_a_correctly_restricted_environment(tmp_path, responses, admits) -> None:
    """The honest path: a guard that refused the environment the setup instructions describe
    would stop the daily collection outright."""
    proc = _run_environment_check(tmp_path, responses)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"deployments restricted to {admits}" in proc.stdout


@pytest.mark.parametrize(
    ("responses", "why"),
    [
        # What GitHub creates, silently, when a workflow names an environment that does not exist.
        ({"traffic": {"name": "traffic", "deployment_branch_policy": None, "protection_rules": []}}, "NO deployment"),
        ({"traffic": None}, "could not read environment"),
        (
            {
                "traffic": {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                "traffic/deployment-branch-policies": {
                    "branch_policies": [*_POLICY_MAIN["branch_policies"], {"name": "dev", "type": "branch"}]
                },
            },
            "must admit exactly the branch main",
        ),
        (
            {
                "traffic": {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                "traffic/deployment-branch-policies": {"branch_policies": [{"name": "main", "type": "tag"}]},
            },
            "must admit exactly the branch main",
        ),
        (
            {
                "traffic": {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}},
                "traffic/deployment-branch-policies": {"branch_policies": []},
            },
            "must admit exactly the branch main",
        ),
    ],
    ids=["auto-created-unrestricted", "missing", "also-admits-dev", "a-tag-named-main", "no-rules"],
)
def test_the_environment_check_fails_loudly_and_names_the_fix(tmp_path, responses, why) -> None:
    proc = _run_environment_check(tmp_path, responses)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "::error::" in proc.stdout and why in proc.stdout, proc.stdout + proc.stderr
    assert "Settings -> Environments -> traffic" in proc.stdout, "the failure must say how to fix it"


# ─────────────────────────────────────────────── concurrency and cancellation ──


def _evaluate(expression: Any, event_name: str, pr_number: int | None) -> Any:
    """Evaluate the small subset of GitHub's expression language the concurrency block uses.

    It is translated to Python and evaluated; anything outside the subset is REFUSED rather than
    guessed at, so a rewrite of the block fails here with a clear message instead of being
    evaluated wrongly. `and`/`or` return an operand, exactly as GitHub's `&&`/`||` do.
    """
    text = str(expression).strip()
    if not (text.startswith("${{") and text.endswith("}}")):
        return text  # a literal
    body = " ".join(text[3:-2].split())
    body = body.replace("&&", " and ").replace("||", " or ")
    body = body.replace("github.event.pull_request.number", "PR").replace("github.event_name", "EVENT")
    body = re.sub(r"\bformat\(\s*('[^']*')\s*,", r"FMT(\1,", body)
    leftover = re.sub(r"'[^']*'|\b(?:and|or|EVENT|PR|FMT)\b|==|!=|[(),\s]", "", body)
    assert not leftover, f"the concurrency expression uses {leftover!r}, which this evaluator does not know"
    names = {"EVENT": event_name, "PR": pr_number, "FMT": lambda f, *a: f.format(*a)}
    # The input is restricted to the subset checked just above.
    return eval(body, {"__builtins__": {}}, names)


def test_a_pull_request_run_never_shares_the_writers_concurrency_group() -> None:
    concurrency = _doc()["concurrency"]
    writers = {e: _evaluate(concurrency["group"], e, None) for e in ("schedule", "workflow_dispatch")}
    assert len(set(writers.values())) == 1, f"the writers must share ONE group, so two never overlap: {writers}"
    (writers_group,) = set(writers.values())
    for pr in (7, 8):
        group = _evaluate(concurrency["group"], "pull_request", pr)
        assert group != writers_group, (
            f"a PR run joins the writers' group {writers_group!r} and can displace a pending one"
        )
    assert _evaluate(concurrency["group"], "pull_request", 7) != _evaluate(concurrency["group"], "pull_request", 8)
    for event in writers:
        assert _evaluate(concurrency["cancel-in-progress"], event, None) is False, (
            f"a {event} run could be cancelled in progress, mid-push"
        )


def test_a_cancelled_run_commits_nothing() -> None:
    """`always()` is true for a cancelled run; `!cancelled()` is not. The commit step, and the
    step that turns a failed collector red, must not run once the run is cancelled."""
    _job_id, job = _writer()
    for step in job["steps"]:
        assert "always()" not in str(step.get("if", "")), f"step {step.get('name')!r} still runs on always()"
    commit = _step(job, "Commit if anything changed")
    assert "!cancelled()" in str(commit.get("if", "")), commit.get("if")
    red = _step(job, "Fail the run if a collector failed")
    assert "!cancelled()" in str(red.get("if", "")) and "steps.traffic.outcome" in str(red["if"])

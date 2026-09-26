"""A pull request into ANY base branch must get the checks a pull request into main gets.

Branch protection requires six status checks on `main` (`_REQUIRED_CHECKS` below; the
count is checked against it). It requires nothing on any other branch. Until this file
existed, seven workflows (ci, lint, codeql, docs, osv-scanner, trufflehog, integration) also
filtered their `pull_request` trigger with `branches: [main]` or `branches: [main, dev]`. So a
stacked PR, one whose base is another feature branch, ran NO checks at all: no tests, lint,
CodeQL, docs build, OSV scan, secret scan or regtest. Measured before the change: this
repository has had four PRs with a non-main base (#141, #231, #498, #664), and the head commit
of each carries zero check runs, while main-based PRs from the same weeks (#140, #142, #230,
#497) carry 10 to 19. #141 was merged into its base that way.

A gate protects a PLACE, not a change: the required checks are scoped to main, and the
stacked PR merges somewhere else. Its change then travels to main inside its base PR, and
the only later chance to catch it is that PR's CI: a different PR from the one that caused
the failure, and only if it runs after the stack lands and nobody bypasses protection
(`enforce_admins` was off when this was written; read as ON 2026-09-25, so an admin merge no
longer skips the checks on main). For #141 that chance did come: #155 took it to main with
11 check runs on a head that contained it. The stacked PR itself was still merged with no
check having run on it.

So the rule is structural: no `pull_request` / `pull_request_target` trigger in any
workflow may filter on the base branch. The `push:` branch filters are untouched on
purpose (a push to main/dev is what those lanes are for). `paths:` filters are allowed
EXCEPT on a workflow that produces a required check: a required check that never reports
leaves a docs-only PR waiting for it forever.

WHAT THIS DOES NOT DO. It makes the checks RUN on a stacked PR. It does not make them
REQUIRED there: branch protection covers main only, so a red check on a stacked PR is
visible but does not block merging into its base.

WHAT THIS CANNOT SEE. It reads the trigger and the `if:` conditions. A job that skips
itself for some other reason (an `if:` on `github.event_name`, a step that exits 0 early)
is invisible to it. The set of required checks lives in branch protection, which CI cannot
read, so `_REQUIRED_CHECKS` below is REVIEWED against the live setting, not derived.
"""

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_WORKFLOWS = sorted([*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")])

_PR_EVENTS = ("pull_request", "pull_request_target")
_BASE_FILTERS = ("branches", "branches-ignore")
_PATH_FILTERS = ("paths", "paths-ignore")

#: Workflows that may keep a base-branch filter on a PR trigger, each with the reason.
#: EMPTY on purpose. An entry must name a workflow that still HAS such a filter;
#: `test_every_base_filter_exemption_is_still_needed` fails the day it stops being true.
_BASE_FILTER_EXEMPTIONS: dict[str, str] = {}

#: The status checks branch protection requires on `main`. REVIEWED, not derived: CI cannot
#: read branch protection. Read 2026-09-22, and again 2026-09-23 after `leak-scan` was added, with
#: `gh api repos/MudwoodLabs/pyrxd/branches/main/protection --jq .required_status_checks.contexts`,
#: and again 2026-09-25: the same six, each now bound to the GitHub Actions app (app_id 15368).
#: The workflow that produces each one is NOT written here; it is derived from the workflows' job
#: names, so a renamed job fails this file rather than silently leaving a check unguarded.
_REQUIRED_CHECKS = (
    "test (3.12)",
    "lint",
    "Scan for leaked secrets",
    "Analyze (Python)",
    "scan-pr / osv-scan",
    "leak-scan",  # added to branch protection 2026-09-23, after #717 brought the workflow
)

#: A required check whose workflow does not exist on this branch yet, with the file that
#: will produce it. Strict: once the file exists, the pending test fails until the name
#: moves into `_REQUIRED_CHECKS`, so it cannot sit here unguarded.
_PENDING_REQUIRED_CHECKS: dict[str, str] = {}

#: Checks guarded exactly like the required ones (every PR base, no path filter) that branch
#: protection does NOT require yet. REVIEWED, like `_REQUIRED_CHECKS`. Empty today; a check that
#: must run on every PR before it is made required belongs here, then moves up.
_GUARDED_NOT_YET_REQUIRED: tuple[str, ...] = ()

#: A condition that reads the PR's base branch can reintroduce the filter one level down.
_BASE_REF_IN_CONDITION = re.compile(r"\bbase_ref\b|pull_request\.base\.ref\b")


def _load(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{path.name} did not parse to a mapping"
    return doc


def _triggers(path: Path) -> dict[str, Any]:
    """The workflow's `on:` block as {event: config-or-None}, whatever shape it was written in."""
    doc = _load(path)
    # PyYAML reads YAML 1.1, where a bare `on` key is the boolean True, not the string "on".
    on = doc[True] if True in doc else doc.get("on")
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return dict.fromkeys(on)
    if isinstance(on, dict):
        return on
    raise AssertionError(f"{path.name}: unrecognised `on:` shape {on!r}")


def _pr_trigger_configs(path: Path) -> dict[str, dict[str, Any]]:
    """Each PR event this workflow triggers on, with its filter mapping ({} when bare)."""
    return {event: (cfg or {}) for event, cfg in _triggers(path).items() if event in _PR_EVENTS}


def _check_names(job_id: str, job: dict[str, Any]) -> tuple[set[str], set[str]]:
    """(exact check-run names, name PREFIXES) this job reports under.

    GitHub names a job's check run after `name:` (else the job id); a matrix job without a
    templated name gets ` (<values>)` appended; a job that calls a reusable workflow reports
    as `<caller> / <called job>`, and the called job lives in another repository, so only the
    caller half is knowable here.
    """
    name = str(job.get("name", job_id))
    if "uses" in job:
        return set(), {f"{name} / "}
    matrix = (job.get("strategy") or {}).get("matrix")
    if isinstance(matrix, dict) and "${{" not in name:
        axes = [v for k, v in matrix.items() if k not in ("include", "exclude") and isinstance(v, list)]
        if axes:
            return {f"{name} ({', '.join(map(str, combo))})" for combo in itertools.product(*axes)}, set()
    return {name}, set()


def _producers(check: str) -> list[tuple[Path, str]]:
    """Every (workflow, job id) that reports a check run named `check`."""
    found = []
    for path in _WORKFLOWS:
        for job_id, job in (_load(path).get("jobs") or {}).items():
            exact, prefixes = _check_names(job_id, job)
            if check in exact or any(check.startswith(p) for p in prefixes):
                found.append((path, job_id))
    return found


def test_the_glob_found_the_workflows_this_guard_exists_for() -> None:
    """Non-vacuity. A glob that matched nothing, or a parser that missed the `on:` key, would
    pass every test below. These seven are the ones that carried a base filter until this file
    existed; each must still be found AND still be read as PR-triggered."""
    names = {p.name for p in _WORKFLOWS}
    formerly_filtered = {
        "ci.yml",
        "lint.yml",
        "codeql.yml",
        "docs.yml",
        "osv-scanner.yml",
        "trufflehog.yml",
        "integration.yml",
    }
    missing = formerly_filtered - names
    assert not missing, f"workflow glob did not find {sorted(missing)} under {_WORKFLOW_DIR}"
    not_pr = sorted(n for n in formerly_filtered if not _pr_trigger_configs(_WORKFLOW_DIR / n))
    assert not not_pr, f"these are no longer read as triggering on pull_request: {not_pr}"


@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_no_pull_request_trigger_filters_on_the_base_branch(path: Path) -> None:
    if path.name in _BASE_FILTER_EXEMPTIONS:
        return
    for event, cfg in _pr_trigger_configs(path).items():
        filters = sorted(k for k in _BASE_FILTERS if k in cfg)
        assert not filters, (
            f"{path.name}: `{event}` carries {filters} = {[cfg[k] for k in filters]}. "
            f"A PR into any other base (a stacked PR) then runs none of this workflow, and its "
            f"change reaches main inside its base PR without it. Remove the filter; if this "
            f"workflow genuinely must not run for other bases, add it to _BASE_FILTER_EXEMPTIONS "
            f"in {Path(__file__).name} with the reason."
        )


def test_every_base_filter_exemption_is_still_needed() -> None:
    """Both directions. An exemption for a workflow that no longer exists, or no longer has a
    base filter, is a stale claim. Vacuous while the dict is empty; it exists so the first
    entry anyone adds is checked from the day it lands."""
    for name, reason in _BASE_FILTER_EXEMPTIONS.items():
        assert reason.strip(), f"exemption for {name} has no reason"
        path = _WORKFLOW_DIR / name
        assert path.exists(), f"_BASE_FILTER_EXEMPTIONS names {name}, which does not exist"
        still = [e for e, cfg in _pr_trigger_configs(path).items() if any(k in cfg for k in _BASE_FILTERS)]
        assert still, f"{name} no longer filters a PR trigger by base branch; delete its exemption"


@pytest.mark.parametrize("path", _WORKFLOWS, ids=lambda p: p.name)
def test_no_job_or_step_condition_filters_on_the_base_branch(path: Path) -> None:
    """The same filter one level down: `if: github.base_ref == 'main'` on a job or step skips
    it for a stacked PR just as surely as a trigger filter, and no trigger check would see it."""
    offending = []
    for job_id, job in (_load(path).get("jobs") or {}).items():
        conditions = [(f"jobs.{job_id}", job.get("if"))]
        conditions += [(f"jobs.{job_id}.steps[{i}]", s.get("if")) for i, s in enumerate(job.get("steps") or [])]
        offending += [(where, cond) for where, cond in conditions if cond and _BASE_REF_IN_CONDITION.search(str(cond))]
    assert not offending, f"{path.name}: conditions that read the PR's base branch: {offending}"


@pytest.mark.parametrize("check", (*_REQUIRED_CHECKS, *_GUARDED_NOT_YET_REQUIRED))
def test_every_required_check_runs_on_every_pull_request(check: str) -> None:
    """A required check must report on every PR: no base filter and no path filter. A path
    filter on a required check's workflow leaves a docs-only PR waiting for a check that will
    never arrive."""
    producers = _producers(check)
    assert producers, (
        f"no job in {_WORKFLOW_DIR.name}/ reports a check named {check!r}, which branch protection "
        f"requires on main. A renamed job leaves the requirement waiting forever; update the job "
        f"or _REQUIRED_CHECKS (after checking branch protection)."
    )
    for path, job_id in producers:
        configs = _pr_trigger_configs(path)
        assert "pull_request" in configs, (
            f"{path.name} (job {job_id}) produces {check!r} but has no pull_request trigger"
        )
        cfg = configs["pull_request"]
        filters = sorted(k for k in (*_BASE_FILTERS, *_PATH_FILTERS) if k in cfg)
        assert not filters, (
            f"{path.name} (job {job_id}) produces the required check {check!r}, and its "
            f"pull_request trigger is filtered by {filters}. Some PRs would then never get it."
        )


def test_pending_required_checks_are_still_pending() -> None:
    """Strict, so the pending list cannot outlive its reason. When the workflow appears, move the
    check into _REQUIRED_CHECKS so the test above guards it."""
    arrived = {check: wf for check, wf in _PENDING_REQUIRED_CHECKS.items() if (_WORKFLOW_DIR / wf).exists()}
    assert not arrived, (
        f"{arrived} now exist. Move each check name from _PENDING_REQUIRED_CHECKS into "
        f"_REQUIRED_CHECKS in {Path(__file__).name} (and confirm branch protection requires it)."
    )


_NUMBER_WORDS = {
    w: n
    for n, w in enumerate(
        ("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve")
    )
}


def test_the_docstring_states_the_same_number_of_required_checks_as_the_tuple() -> None:
    """The docstring said "five status checks" after `leak-scan` had made it six: prose beside a
    reviewed list drifts silently, because nothing reads it. So every count of status checks
    this file's docstring states is checked against `_REQUIRED_CHECKS`. Whitespace is flattened
    first, so a count wrapped onto the next line is still found; and at least one count must be
    found, so rewording it away cannot turn this into a test of nothing."""
    doc = " ".join((__doc__ or "").split())
    words = "|".join(_NUMBER_WORDS)
    counts = re.findall(rf"\b({words}|\d+) (?:required )?status checks\b", doc, re.IGNORECASE)
    assert counts, "the module docstring no longer states how many checks are required; this test found nothing"
    stated = {int(c) if c.isdigit() else _NUMBER_WORDS[c.lower()] for c in counts}
    assert stated == {len(_REQUIRED_CHECKS)}, (
        f"the docstring says {counts} status checks, but _REQUIRED_CHECKS lists {len(_REQUIRED_CHECKS)}"
    )


#: The script that WRITES branch protection. A re-run applies whatever it holds.
_PROTECTION_SCRIPT = _ROOT / "scripts" / "post-public-flip.sh"
#: The GitHub Actions app. A required check bound to it cannot be satisfied by a status that
#: any other integration (or a token with `statuses: write`) posts under the same name.
_GITHUB_ACTIONS_APP_ID = 15368


#: The WHOLE branch-protection document the script PUTs, as it must be to reproduce the live
#: rules exactly. REVIEWED, not derived (CI cannot read branch protection): compared field by
#: field with `gh api repos/MudwoodLabs/pyrxd/branches/main/protection`, read 2026-09-25 after
#: required signatures were switched off. The check list is built from `_REQUIRED_CHECKS`, so the
#: two reviewed copies in this file cannot disagree with each other.
_LIVE_PROTECTION: dict[str, Any] = {
    "required_status_checks": {
        "strict": True,
        "checks": [{"context": c, "app_id": _GITHUB_ACTIONS_APP_ID} for c in _REQUIRED_CHECKS],
    },
    "enforce_admins": True,
    "required_pull_request_reviews": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews": True,
        "require_code_owner_reviews": False,
        "require_last_push_approval": False,
    },
    "restrictions": None,
    "allow_force_pushes": False,
    "allow_deletions": False,
    "block_creations": False,
    "required_linear_history": True,
    "required_conversation_resolution": True,
    "lock_branch": False,
    "allow_fork_syncing": False,
}


def _script_without_comments_or_heredocs() -> str:
    """The script's COMMANDS: comment lines and heredoc bodies removed, continuations joined."""
    text = re.sub(
        r"<<'?(\w+)'?([^\n]*)\n.*?\n\1\n", r"<<\1\2\n", _PROTECTION_SCRIPT.read_text(encoding="utf-8"), flags=re.S
    )
    text = re.sub(r"\\\n", " ", text)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def test_the_protection_script_reproduces_the_live_rules_exactly() -> None:
    """`scripts/post-public-flip.sh` calls itself idempotent and safe to re-run, and it PUTs a
    whole branch-protection document. It held `enforce_admins: false`, one required approval,
    and a `typecheck` check that no workflow produces, while the live rules had moved on to six
    app-bound checks enforced for admins. A re-run would have silently switched the admin bypass
    back on. Pinning only those fields left the rest free to drift (a re-run could have allowed
    force pushes, or dropped linear history), so the WHOLE document is compared."""
    import json

    bodies = re.findall(r"<<'EOF'[^\n]*\n(\{.*?\n\})\nEOF\n", _PROTECTION_SCRIPT.read_text(encoding="utf-8"), re.S)
    assert len(bodies) == 1, (
        f"expected exactly one JSON protection payload in {_PROTECTION_SCRIPT.name}, found {len(bodies)}"
    )
    payload = json.loads(bodies[0])

    def _normalised(doc: dict[str, Any]) -> dict[str, Any]:
        doc = json.loads(json.dumps(doc))
        status = doc.get("required_status_checks") or {}
        if isinstance(status.get("checks"), list):
            status["checks"] = sorted(status["checks"], key=lambda c: json.dumps(c, sort_keys=True))
        return doc

    got, want = _normalised(payload), _normalised(_LIVE_PROTECTION)
    differing = sorted(k for k in set(got) | set(want) if got.get(k, "<absent>") != want.get(k, "<absent>"))
    assert not differing, (
        f"{_PROTECTION_SCRIPT.name} would PUT a protection document that differs from the live rules in "
        f"{differing}: "
        + "; ".join(f"{k}: script {got.get(k, '<absent>')!r}, live {want.get(k, '<absent>')!r}" for k in differing)
    )


def test_the_protection_script_makes_no_other_protection_call() -> None:
    """Required signatures has its own endpoint, outside the PUT document, and the script used to
    POST it. With admins enforced that blocked every PR, whose head commits are unsigned, so the
    maintainer switched it off; a re-run would have switched it back on. Every command that
    touches `branches/` is found here (comments and heredoc text removed first), and it must be
    exactly the one PUT the test above checks."""
    commands = _script_without_comments_or_heredocs()
    api_calls = [line.strip() for line in commands.splitlines() if re.search(r"\bgh\s+api\b", line)]
    assert api_calls, f"found no `gh api` call in {_PROTECTION_SCRIPT.name}; this test checked nothing"
    branch_calls = [c for c in api_calls if "branches/" in c]
    assert len(branch_calls) == 1 and re.search(
        r'-X PUT "repos/\$\{REPO\}/branches/\$\{BRANCH\}/protection"', branch_calls[0]
    ), f"{_PROTECTION_SCRIPT.name} must make exactly one branch-protection call, the PUT; found {branch_calls}"
    assert "required_signatures" not in commands, "the script touches required signatures again"


def test_no_doc_or_script_tells_anyone_to_admin_merge() -> None:
    """The release runbook merged with `gh pr merge ... --admin`. That flag merges a PR that fails
    ANY requirement, required checks included, and with `enforce_admins` on it no longer works at
    all, so an instruction to use it is now wrong twice. Every tracked file except the frozen
    CHANGELOG and the tests is read; backslash-continued command lines are joined first, so the
    flag cannot hide on the next line. The runbook's own (flagless) merge command must be SEEN,
    so a scan that read nothing cannot pass."""
    import subprocess

    listed = subprocess.run(["git", "ls-files", "-z"], cwd=_ROOT, capture_output=True, check=True).stdout
    paths = [p for p in listed.decode().split("\0") if p and p != "CHANGELOG.md" and not p.startswith("tests/")]
    merge = re.compile(r"\bgh\s+pr\s+merge\b[^\n]*")
    seen, admin = [], []
    for rel in paths:
        try:
            text = (_ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for m in merge.finditer(re.sub(r"\\\r?\n", " ", text)):
            seen.append(rel)
            if re.search(r"(?<![\w-])--admin\b", m.group(0)):
                admin.append(f"{rel}: {m.group(0).strip()}")
    assert "docs/runbooks/cutting-a-release.md" in seen, f"the scan did not see the runbook's merge command: {seen}"
    assert not admin, "these tell someone to merge with --admin, past the required checks:\n" + "\n".join(admin)


#: A LOCAL publish to PyPI given as a command: at the start of a line (after an optional `$ `
#: prompt) or after `&&`, `||` or `;`. Prose that names the command, as a warning does, is not a
#: command and does not match.
_LOCAL_PUBLISH_COMMAND = re.compile(
    r"(?:^|&&|\|\||;)[ \t]*(?:\$[ \t]*)?(?:poetry[ \t]+publish|twine[ \t]+upload|uv[ \t]+publish"
    r"|flit[ \t]+publish|hatch[ \t]+publish)\b",
    re.MULTILINE,
)


def test_no_doc_or_script_tells_anyone_to_publish_from_a_laptop() -> None:
    """`scripts/post-public-flip.sh` ended by telling the reader to run `poetry build && poetry
    publish` for pyrxd 0.2.0. A release is published by creating a GitHub Release, which runs
    `publish.yml`: its verify job, the `pypi` environment's reviewer and the PEP 740 attestations.
    A laptop publish skips all three. The same file walk as the test above; the one legitimate
    publisher, `publish.yml`, uses the PyPA action rather than any of these commands. A known-bad
    line is matched first, so a matcher that finds nothing cannot pass."""
    import subprocess

    assert _LOCAL_PUBLISH_COMMAND.search("     poetry build && poetry publish\n"), "the matcher misses the known case"
    assert not _LOCAL_PUBLISH_COMMAND.search("the attestations. `poetry publish` from a laptop would skip them\n")
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=_ROOT, capture_output=True, check=True).stdout
    paths = [p for p in listed.decode().split("\0") if p and p != "CHANGELOG.md" and not p.startswith("tests/")]
    assert "scripts/post-public-flip.sh" in paths, (
        "the file walk no longer reaches the script this test was written for"
    )
    found = []
    for rel in paths:
        try:
            text = (_ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for m in _LOCAL_PUBLISH_COMMAND.finditer(re.sub(r"\\\r?\n", " ", text)):
            line = text.count("\n", 0, m.start()) + 1
            found.append(f"{rel}:{line}: {m.group(0).strip()}")
    assert not found, "these tell someone to publish to PyPI outside publish.yml:\n" + "\n".join(found)

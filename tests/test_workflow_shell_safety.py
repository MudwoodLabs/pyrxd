"""Workflow shell steps that handle text they did not write (#827).

Each step is pulled out of its workflow file and run under real bash with stand-in `gh`, `git` and
`python` commands, so the tests exercise the shipped script rather than a copy of it:

* `photonic-drift.yml`, both jobs: the report quotes text derived from upstream files. While it is
  on stdout, workflow commands are switched off (a line beginning `::` is printed, not obeyed), and
  in the issue body it sits inside a code fence longer than any run of backticks it contains.
* `combine-prs.yml`: the PR numbers `gh pr list` returns are read one per line into an array, each
  checked to be digits, never word-split.

Plus one class guard over every workflow: no `for … in $VAR` loop over an unquoted expansion.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

_WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"
_DRIFT = _WORKFLOWS_DIR / "photonic-drift.yml"
_COMBINE = _WORKFLOWS_DIR / "combine-prs.yml"
_EXPRESSION = re.compile(r"\$\{\{[^}]*\}\}")


def _step(workflow: Path, job: str, name: str) -> str:
    doc = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    steps = [s for s in doc["jobs"][job]["steps"] if s.get("name") == name]
    assert len(steps) == 1, f"{workflow.name}:{job} has {len(steps)} steps named {name!r}"
    assert "shell" not in steps[0], "these tests run the step the way GitHub's default shell does"
    return _EXPRESSION.sub("EXPR", steps[0]["run"])


def _drift_jobs() -> list[str]:
    jobs = list(yaml.safe_load(_DRIFT.read_text(encoding="utf-8"))["jobs"])
    assert len(jobs) >= 2, jobs  # non-vacuity: both the Photonic and the RXinDexer job
    return jobs


def _step_named(job: str, prefix: str) -> str:
    doc = yaml.safe_load(_DRIFT.read_text(encoding="utf-8"))
    names = [s["name"] for s in doc["jobs"][job]["steps"] if s.get("name", "").startswith(prefix)]
    assert len(names) == 1, (job, prefix, names)
    return _step(_DRIFT, job, names[0])


def _run(tmp_path: Path, script: str, stubs: dict[str, str], env: dict[str, str] | None = None):
    """Run *script* as GitHub's default `run:` shell does (`bash -e`), with a PATH holding only the
    given stand-ins plus the coreutils the scripts use."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    for name, body in stubs.items():
        stub = bindir / name
        stub.write_text(body, encoding="utf-8")
        stub.chmod(0o755)
    for tool in ("bash", "awk", "cat", "printf", "tee"):
        if tool in stubs:
            continue
        found = shutil.which(tool)
        assert found, f"`{tool}` is not installed"
        link = bindir / tool
        if not link.exists():
            link.symlink_to(found)
    script_file = tmp_path / "step.sh"
    script_file.write_text(script, encoding="utf-8")
    full_env = {"PATH": str(bindir), "HOME": str(tmp_path), "LC_ALL": "C.UTF-8", **(env or {})}
    return subprocess.run(
        [str(bindir / "bash"), "-e", str(script_file)],
        cwd=tmp_path,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


_HOSTILE_REPORT = "drift in a.ts:\n````\n::error::forged annotation\n```\nend of report\n"


def _fenced_region(body: str) -> str:
    """The text of the first fenced block, closed the way CommonMark closes it: by a line of at
    least as many backticks as opened it, and nothing else."""
    lines = body.split("\n")
    start = next(i for i, line in enumerate(lines) if re.fullmatch(r"`{3,}", line))
    width = len(lines[start])
    end = next(i for i in range(start + 1, len(lines)) if re.fullmatch(rf"`{{{width},}}", lines[i]))
    return "\n".join(lines[start + 1 : end]) + "\n"


_GH_CAPTURE_BODY = f"""#!{sys.executable}
import os, shutil, sys
args = sys.argv[1:]
if args[:2] == ["issue", "list"]:
    sys.exit(0)  # no open issue: the step creates one
shutil.copy(args[args.index("--body-file") + 1], os.environ["BODY_OUT"])
"""


@pytest.mark.parametrize("job", _drift_jobs())
def test_the_drift_issue_fence_outlasts_any_backticks_in_the_report(tmp_path: Path, job: str) -> None:
    """A report line of backticks no longer closes the issue's code block early."""
    (tmp_path / "drift-report.txt").write_text(_HOSTILE_REPORT, encoding="utf-8")
    out = tmp_path / "body-captured.md"
    proc = _run(
        tmp_path, _step_named(job, "Open or update the drift issue"), {"gh": _GH_CAPTURE_BODY}, {"BODY_OUT": str(out)}
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _fenced_region(out.read_text(encoding="utf-8")) == _HOSTILE_REPORT


@pytest.mark.parametrize("job", _drift_jobs())
def test_the_drift_issue_keeps_a_three_backtick_fence_for_a_plain_report(tmp_path: Path, job: str) -> None:
    """Honest path: a report with no backticks is fenced exactly as before."""
    report = "drift in a.ts: lines 10-12 changed\n"
    (tmp_path / "drift-report.txt").write_text(report, encoding="utf-8")
    out = tmp_path / "body-captured.md"
    proc = _run(
        tmp_path, _step_named(job, "Open or update the drift issue"), {"gh": _GH_CAPTURE_BODY}, {"BODY_OUT": str(out)}
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    body = out.read_text(encoding="utf-8")
    assert "\n```\n" + report + "```\n" in body
    assert _fenced_region(body) == report


_PYTHON_STUB = f"""#!/bin/sh
if [ "$1" = "-c" ]; then exec {sys.executable} "$@"; fi
printf '%s' "$REPORT"
exit 1
"""


@pytest.mark.parametrize("job", _drift_jobs())
def test_workflow_commands_are_off_while_the_report_is_on_stdout(tmp_path: Path, job: str) -> None:
    """Every report line sits between `::stop-commands::<token>` and `::<token>::`, the token is
    not guessable from the script, and the checker's exit code still reaches the step output."""
    output = tmp_path / "github_output"
    proc = _run(
        tmp_path,
        _step_named(job, "Check cited"),
        {"python": _PYTHON_STUB},
        {"REPORT": _HOSTILE_REPORT, "GITHUB_OUTPUT": str(output)},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = proc.stdout.split("\n")
    stops = [i for i, line in enumerate(lines) if line.startswith("::stop-commands::")]
    assert len(stops) == 1, proc.stdout
    token = lines[stops[0]].removeprefix("::stop-commands::")
    assert re.fullmatch(r"[0-9a-f]{32}", token), token
    resume = lines.index(f"::{token}::")
    forged = lines.index("::error::forged annotation")
    assert stops[0] < forged < resume
    assert output.read_text(encoding="utf-8") == "code=1\n"


_GIT_STUB = f"""#!{sys.executable}
import json, os, sys
with open(os.environ["GIT_LOG"], "a", encoding="utf-8") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
"""


def _gh_stub(numbers: str) -> str:
    return f"""#!{sys.executable}
import json, sys
args = sys.argv[1:]
if args[:2] == ["pr", "list"]:
    print({numbers!r}, end="")
elif args[:2] == ["pr", "view"]:
    print("head-" + args[2] if "headRefName" in args else "title " + args[2])
"""


def _combine(tmp_path: Path, numbers: str) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    log = tmp_path / "git.jsonl"
    proc = _run(
        tmp_path,
        _step(_COMBINE, "combine", "Combine open PRs"),
        {"gh": _gh_stub(numbers), "git": _GIT_STUB},
        {
            "GIT_LOG": str(log),
            "GITHUB_RUN_ID": "1",
            "BASE": "main",
            "AUTHOR": "app/dependabot",
            "LABEL": "",
            "REQUIRE_GREEN": "true",
        },
    )
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    return proc, calls


def test_combine_prs_merges_each_listed_pr(tmp_path: Path) -> None:
    """Honest path: two PR numbers, one per line, are each fetched and merged."""
    proc, calls = _combine(tmp_path, "12\n34\n")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    merged = [c[-1] for c in calls if c[:1] == ["merge"]]
    assert merged == ["origin/head-12", "origin/head-34"], calls


def test_combine_prs_refuses_a_pr_number_that_is_not_digits(tmp_path: Path) -> None:
    """A line holding anything but digits stops the job before any PR is touched. Word splitting
    used to turn `12 34` into two PRs, and would split whatever else the list held."""
    proc, calls = _combine(tmp_path, "12 34\n")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not all digits" in proc.stdout
    assert [c for c in calls if c[:1] in (["merge"], ["fetch"]) and c[-1] != "main"] == [], calls


def test_combine_prs_exits_cleanly_when_nothing_matches(tmp_path: Path) -> None:
    proc, calls = _combine(tmp_path, "")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "No open PRs match" in proc.stdout
    assert not [c for c in calls if c[:1] == ["merge"]]


_UNQUOTED_FOR = re.compile(r"\bfor\s+\w+\s+in\s+\$(?:\w+|\{\w+\})(?:\s|;|$)", re.M)


def test_no_workflow_loops_over_an_unquoted_expansion() -> None:
    """The class #827 found once: `for n in $numbers` word-splits (and globs) whatever the variable
    holds. Every `run:` script in every workflow is read; a loop over a list belongs in an array."""
    runs = []
    for wf in sorted(_WORKFLOWS_DIR.glob("*.yml")):
        for job_id, job in (yaml.safe_load(wf.read_text(encoding="utf-8")).get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if isinstance(step.get("run"), str):
                    runs.append((f"{wf.name}:{job_id}:{step.get('name')}", step["run"]))
    assert len(runs) > 20, len(runs)  # non-vacuity: the sweep reads the real workflows
    bad = [f"{label}: {m.group(0).strip()}" for label, run in runs for m in _UNQUOTED_FOR.finditer(run)]
    assert not bad, bad


def test_the_unquoted_loop_pattern_matches_the_form_it_exists_for() -> None:
    assert _UNQUOTED_FOR.search("for n in $numbers; do")
    assert _UNQUOTED_FOR.search("  for n in ${numbers}\n")
    assert not _UNQUOTED_FOR.search('for n in "${numbers[@]}"; do')
    assert not _UNQUOTED_FOR.search("for i in 1 2 3; do")

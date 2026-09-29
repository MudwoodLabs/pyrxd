"""An upload step that names a dot-path must say `include-hidden-files: true`, or it uploads nothing there.

`actions/upload-artifact` has excluded hidden files and directories by default since v4.4. The
step still succeeds; the dot-paths are just not in the artifact. Two workflows here did that:

* `mutation.yml` uploaded `.mutation-reports/` and `.mutation-sessions/*.sqlite`. Run
  36521398529's artifacts held only `mutation-<group>.log`, for completed groups too, so the
  survivor list (the job's whole output) never left the runner. The step's comment said partial
  sessions were kept.
* `fuzz.yml` uploaded `tests/.hypothesis-corpus/`, the shrunk reproducers of a failing deep run.
  Run 36417762423's artifact held `logs/` alone.

THE RULE, over every `actions/upload-artifact` step in every file in `.github/workflows/`: if any
line of `with.path` has a path component starting with `.` (other than `.` and `..` themselves),
the step sets `include-hidden-files: true`. The set of steps is derived from the files, so a new
workflow or a new upload is covered the moment it is written.

WHAT THIS CANNOT SEE: a hidden file INSIDE a non-hidden directory (`logs/.last-run`). The path
names only `logs/`, so nothing here says a dot-file will be in it.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_WORKFLOWS = sorted([*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")])


def _upload_steps(doc: dict) -> list[tuple[str, dict]]:
    """(job id / step label, step) for every upload-artifact step in a parsed workflow."""
    out = []
    for job_id, job in (doc.get("jobs") or {}).items():
        for i, step in enumerate(job.get("steps") or []):
            if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                out.append((f"{job_id}/{step.get('name', f'step {i}')}", step))
    return out


def _dot_paths(step: dict) -> list[str]:
    """The `path` lines of an upload step that have a hidden component."""
    raw = str((step.get("with") or {}).get("path", ""))
    hits = []
    for line in raw.splitlines():
        line = line.strip().lstrip("!")  # a `!` line is an exclusion; it can still be hidden
        if any(part.startswith(".") and part not in (".", "..") for part in line.split("/")):
            hits.append(line)
    return hits


def _violations(doc: dict) -> list[str]:
    bad = []
    for label, step in _upload_steps(doc):
        hidden = _dot_paths(step)
        flag = (step.get("with") or {}).get("include-hidden-files")
        if hidden and flag is not True and str(flag).lower() != "true":
            bad.append(f"{label}: {hidden}")
    return bad


def test_every_upload_of_a_dot_path_includes_hidden_files() -> None:
    assert _WORKFLOWS, f"no workflow files under {_WORKFLOW_DIR}; the glob is wrong"
    steps = 0
    dotted = 0
    bad = []
    for wf in _WORKFLOWS:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for _label, step in _upload_steps(doc):
            steps += 1
            dotted += bool(_dot_paths(step))
        bad += [f"{wf.name}: {v}" for v in _violations(doc)]

    # Non-vacuity: the repo has upload steps, and some upload dot-paths. If the parse stops
    # finding them, "no violations" would mean nothing was checked.
    assert steps >= 5, f"only {steps} upload-artifact steps found; the step walk has stopped matching"
    assert dotted >= 2, f"only {dotted} upload steps with a dot-path found; mutation.yml and fuzz.yml each have one"
    assert not bad, (
        "these upload steps name hidden paths without `include-hidden-files: true`, so the "
        "artifact silently leaves those paths out:\n  " + "\n  ".join(bad)
    )


_OLD_MUTATION_STEP = """
jobs:
  mutate:
    steps:
      - name: Upload survivor list and session databases
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: mutation-${{ matrix.group }}
          path: |
            mutation-${{ matrix.group }}.log
            .mutation-reports/
            .mutation-sessions/*.sqlite
          retention-days: 90
"""


def test_the_guard_fires_on_the_step_that_uploaded_only_the_log() -> None:
    """Plant: `mutation.yml`'s upload step as it was before this fix."""
    bad = _violations(yaml.safe_load(_OLD_MUTATION_STEP))
    assert len(bad) == 1
    assert ".mutation-reports/" in bad[0] and ".mutation-sessions/*.sqlite" in bad[0]


def test_the_guard_passes_the_fixed_step_and_a_step_with_no_dot_path() -> None:
    """Honest paths: the same step with the flag, and an upload with no hidden path at all."""
    fixed = _OLD_MUTATION_STEP.replace("retention-days: 90", "include-hidden-files: true\n          retention-days: 90")
    assert _violations(yaml.safe_load(fixed)) == []
    plain = _OLD_MUTATION_STEP.replace(".mutation-reports/", "reports/").replace(
        ".mutation-sessions/*.sqlite", "sessions/*.sqlite"
    )
    assert _violations(yaml.safe_load(plain)) == []
    # `./x` is the current directory, not a hidden one.
    assert _dot_paths({"with": {"path": "./dist/\n../out"}}) == []

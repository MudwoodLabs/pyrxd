"""A workflow step that pipes one command into another must not lose the first one's failure.

With no `shell:`, GitHub runs a Linux `run:` block as `bash -e {0}`. That has no `pipefail`,
so `cmd | tee log` exits with `tee`'s status: success. `.github/workflows/mutation.yml` ran
`scripts/mutation_test.sh "$MATRIX_GROUP" | tee ...` that way, and every fail-closed exit the
script has (a red clean-suite baseline, zero mutants, an incomplete sweep, a kill rate under the
floor) was reported green. Weekly run 35710549260 (2026-09-22): `ethtimelock` logged
"FAIL: total kill rate 81% < threshold 86%" and concluded success; `glyphverify` and
`walletcore` never got past their baselines and concluded success. The same happened in
34953335748. The script was correct. The step threw its answer away.

THE RULE, over every step in every file in `.github/workflows/`: a `run:` block containing a
pipeline must do ONE of

* run under the explicit `shell: bash` (GitHub runs that as `bash --noprofile --norc -eo
  pipefail {0}`; a custom `bash {0}` does NOT get pipefail, so only the bare word counts),
  set on the step or via `defaults.run.shell` on the job or workflow;
* `set -o pipefail` (or `set -euo pipefail` and friends) before its first pipeline; or
* read `PIPESTATUS` in the command right after EACH pipeline, as photonic-drift.yml does to
  keep its exit code 1/2 distinction while still tee-ing a report.

WHAT THIS CANNOT SEE. Pipes inside a double-quoted `"$(a | b)"` are one quoted word to the
lexer and are not checked. A `|` in a `case` pattern (`a|b)`) is counted as a pipe; that errs
toward demanding pipefail, never toward waving a step through. Heredoc bodies are skipped.
"""

from __future__ import annotations

import itertools
import re
import shlex
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_WORKFLOWS = sorted([*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")])

_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_PIPE = re.compile(r"(?<![|>])\|(?!\|)")  # `|` or `|&`; not `||`, not `>|`


def _strip_heredocs(script: str) -> str:
    out: list[str] = []
    end: str | None = None
    for line in script.split("\n"):
        if end is not None:
            if line.strip() == end:
                end = None
            continue
        out.append(line)
        m = _HEREDOC.search(line)
        if m:
            end = m.group(2)
    return "\n".join(out)


def _pipelines(script: str) -> list[tuple[bool, list[str]]]:
    """Split a shell script into pipelines: (contains a pipe, the words in it).

    `\\n` is made a punctuation token and each newline is followed by a `;`, so a newline
    still ends a command after shlex's comment handling has swallowed it along with the
    comment. `&&`, `||`, `;`, `&` and newlines end a pipeline; a newline straight after `|` is
    a continuation, as it is in bash."""
    text = _strip_heredocs(script).replace("\\\n", " ").replace("\n", "\n;")
    lex = shlex.shlex(text, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    out: list[tuple[bool, list[str]]] = []
    words: list[str] = []
    piped = after_pipe = False
    for tok in lex:
        if tok and set(tok) <= set("();<>|&\n"):
            op = tok.replace("\n", "")
            if _PIPE.search(op):
                piped = after_pipe = True
                continue
            ends = "\n" in tok or any(c in op for c in ";&") or op in ("||",)
            if ends and not after_pipe and (words or piped):
                out.append((piped, words))
                words, piped = [], False
            continue
        words.append(tok)
        after_pipe = False
    if words or piped:
        out.append((piped, words))
    return out


def _sets_pipefail(words: list[str]) -> bool | None:
    """True/False if this command is a `set` that turns pipefail on/off, else None."""
    if not words or words[0] != "set":
        return None
    result = None
    for flag, value in itertools.pairwise(words[1:]):
        if value == "pipefail" and flag[:1] in "-+" and "o" in flag:
            result = flag[0] == "-"
    return result


def _unguarded_pipelines(script: str) -> list[str]:
    """Pipelines in `script` whose left-hand failures would be lost, as text for the message."""
    pipefail = False
    bad: list[str] = []
    pls = _pipelines(script)
    for i, (piped, words) in enumerate(pls):
        toggled = _sets_pipefail(words)
        if toggled is not None:
            pipefail = toggled
        if not piped or pipefail:
            continue
        nxt = pls[i + 1][1] if i + 1 < len(pls) else []
        if not any("PIPESTATUS" in w for w in nxt):
            bad.append(" ".join(words)[:120])
    return bad


def _piped_steps() -> list[tuple[str, str, str | None, str]]:
    """(workflow file, step label, effective shell, run script) for every step whose `run:`
    contains a pipeline."""
    found = []
    for wf in _WORKFLOWS:
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        wf_shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell")
        for job_id, job in (doc.get("jobs") or {}).items():
            job_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell", wf_shell)
            for n, step in enumerate(job.get("steps") or []):
                run = step.get("run")
                if not isinstance(run, str) or not any(p for p, _ in _pipelines(run)):
                    continue
                label = f"{wf.name}:{job_id}:{step.get('name') or step.get('id') or n}"
                found.append((wf.name, label, step.get("shell", job_shell), run))
    return found


def _violations(steps: list[tuple[str, str, str | None, str]]) -> list[str]:
    out = []
    for _wf, label, shell, run in steps:
        if shell == "bash":
            continue
        out.extend(f"{label}: {p}" for p in _unguarded_pipelines(run))
    return out


def test_every_piped_workflow_step_keeps_the_left_hand_exit_status() -> None:
    assert _WORKFLOWS, f"no workflows found under {_WORKFLOW_DIR}"
    steps = _piped_steps()
    # Non-vacuity: a lexer that stopped seeing pipes would pass every workflow.
    assert steps, "no piped `run:` step found in any workflow — the scan is broken, not the workflows"
    # Control: photonic-drift.yml pipes into tee in two steps and reads PIPESTATUS after each.
    # If the scan cannot find those, it cannot be trusted to find anything.
    assert sum(wf == "photonic-drift.yml" for wf, *_ in steps) >= 2, [s[1] for s in steps]
    bad = _violations(steps)
    assert not bad, (
        "these steps pipe a command into another under `bash -e` with no pipefail, so the step "
        "reports the LAST command's status and a failure on the left is lost. Add `set -o "
        "pipefail`, declare `shell: bash`, or read `${PIPESTATUS[0]}` right after:\n  " + "\n  ".join(bad)
    )


def test_the_guard_fails_on_the_mutation_step_as_it_shipped() -> None:
    """Plant: the pre-fix mutation.yml step, verbatim."""
    old = (
        'mkdir -p "$MUTATION_SESSION_DIR" "$MUTATION_REPORT_DIR"\n'
        'MUTATION_MIN_KILL_PCT="$MATRIX_MIN_KILL" \\\n'
        '  poetry run bash scripts/mutation_test.sh "$MATRIX_GROUP" | tee "mutation-${MATRIX_GROUP}.log"\n'
    )
    bad = _violations([("mutation.yml", "mutate", None, old)])
    assert len(bad) == 1 and "mutation_test.sh" in bad[0], bad
    # A custom `bash {0}` is not the `bash` shorthand and does not get pipefail.
    assert _violations([("mutation.yml", "mutate", "bash {0}", old)])
    # Each accepted form clears it.
    assert not _violations([("mutation.yml", "mutate", "bash", old)])
    assert not _violations([("mutation.yml", "mutate", None, "set -o pipefail\n" + old)])
    assert not _violations([("mutation.yml", "mutate", None, "set -euo pipefail\n" + old)])
    # ...but not when it comes too late, or is switched back off.
    assert _violations([("mutation.yml", "mutate", None, old + "set -o pipefail\n")])
    assert _violations([("mutation.yml", "mutate", None, "set -o pipefail\nset +o pipefail\n" + old)])


def test_the_guard_passes_photonic_drift_and_reads_PIPESTATUS_placement() -> None:
    """Honest path: photonic-drift.yml's real steps pass. And a PIPESTATUS read only counts
    in the command right after the pipeline; any command in between overwrites it."""
    drift = [s for s in _piped_steps() if s[0] == "photonic-drift.yml"]
    assert len(drift) >= 2
    assert not _violations(drift)
    ok = 'set +e\npython x.py | tee r.txt  # keep the report\necho "code=${PIPESTATUS[0]}" >> "$GITHUB_OUTPUT"\n'
    assert not _violations([("w", "s", None, ok)])
    late = 'python x.py | tee r.txt\necho hi\necho "code=${PIPESTATUS[0]}"\n'
    assert _violations([("w", "s", None, late)])


def test_the_lexer_does_not_see_pipes_that_are_not_there() -> None:
    """`||`, a quoted `|`, a comment and a heredoc body are not pipelines."""
    for script in (
        "a || b\n",
        "grep -E 'x|y' f\n",
        'jq ".[] | .name" f\n',
        "echo hi  # a | b\n",
        "python - <<'EOF'\nprint(1 | 2)\nEOF\n",
        "echo ${{ inputs.a || 'b' }}\n",
    ):
        assert not any(p for p, _ in _pipelines(script)), script
    assert any(p for p, _ in _pipelines("a |\n  b\n")), "a newline after | continues the pipeline"

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
* `set -o pipefail` (or `set -euo pipefail` and friends, or `shopt -so pipefail`) before its
  first pipeline, in the step's own shell. A `set` inside `( ... )` or `$( ... )` changes only
  that subshell, so it covers the pipes inside it and nothing after it; or
* capture `${PIPESTATUS[0]}` in the command right after a single-`|` pipeline, into a variable
  (`rc=${PIPESTATUS[0]}`) or as `key=${PIPESTATUS[0]}` appended to `$GITHUB_OUTPUT`, as
  photonic-drift.yml does to keep its exit code 1/2 distinction while still tee-ing a report.
  Any other mention of PIPESTATUS keeps nothing.

A script run by `bash -c '...'` / `sh -c "..."` is split and held to the same rule. It starts
without pipefail even inside a `shell: bash` step, because a child shell does not inherit it.

WHAT THIS CANNOT SEE. Pipes inside a double-quoted `"$(a | b)"` are one quoted word to the
lexer and are not checked. Nor is a script fed to a shell by a heredoc or a variable
(`bash <<EOF`, `bash -c "$CMD"`). A `|` in a `case` pattern (`a|b)`) is counted as a pipe;
that errs toward demanding pipefail. The `)` of a `case` pattern also closes a subshell frame
early, so inside `( ... )` a `case` can make a later `set` look like the parent's. Heredoc
bodies are skipped, each only up to its own terminator line; a heredoc whose terminator never
appears is not skipped at all.
"""

from __future__ import annotations

import itertools
import re
import shlex
from pathlib import Path
from typing import NamedTuple

import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_DIR = _ROOT / ".github" / "workflows"
_WORKFLOWS = sorted([*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")])

_PUNCT = "();<>|&\n"
# Operators, longest first, so a run shlex glued together (`)|`, `;;`, `>&`) splits correctly.
_OPS = re.compile(r";;&|;;|;&|\|\||\|&|\||&&|&>>|&>|>>|>&|>\||<<<|<<|<>|<&|<|>|&|;|\(|\)|\n")
_SHELLS = frozenset({"bash", "sh", "dash", "zsh", "ksh"})
_ASSIGN_STATUS0 = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\$\{PIPESTATUS\[0\]\}")
_OUTPUT_TARGETS = frozenset({"$GITHUB_OUTPUT", "${GITHUB_OUTPUT}"})


def _heredoc_delimiters(line: str, state: dict) -> list[str]:
    """Delimiters of the REAL heredocs a line opens, in order.

    A character scan, not a regex, because the regex it replaced also matched `echo "use <<EOF"`
    and `$((1<<N))` and switched checking off for the rest of the step. `<<` counts only outside
    quotes, comments and arithmetic, and `<<<` is a here-string, not a heredoc. `state` carries an
    open quote or arithmetic depth across lines."""
    out: list[str] = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if state["q"] == "'":
            if c == "'":
                state["q"] = None
            i += 1
            continue
        if state["q"] == '"':
            if c == "\\":
                i += 2
                continue
            if c == '"':
                state["q"] = None
            i += 1
            continue
        if state["arith"]:
            if c == "(":
                state["arith"] += 1
            elif c == ")":
                state["arith"] -= 1
            i += 1
            continue
        if c == "\\":
            i += 2
        elif c in "'\"":
            state["q"] = c
            i += 1
        elif c == "#" and (i == 0 or line[i - 1] in " \t;&|()"):
            break  # a comment: nothing after it on this line is shell
        elif line.startswith("((", i):
            state["arith"] = 2
            i += 2
        elif line.startswith("<<<", i):
            i += 3
        elif line.startswith("<<", i):
            m = re.compile(r"-?[ \t]*(?:'([^']*)'|\"([^\"]*)\"|\\?([^\s;&|<>()'\"]+))").match(line, i + 2)
            if not m:
                i += 2
                continue
            out.append(next(g for g in m.groups() if g is not None))
            i = m.end()
        else:
            i += 1
    return out


def _strip_heredocs(script: str) -> str:
    """Drop heredoc BODIES, each only up to its own terminator line. A heredoc whose terminator
    never appears is NOT stripped: the lines after it stay checked, so a mistaken opener errs
    toward checking too much rather than switching the check off."""
    lines = script.split("\n")
    out: list[str] = []
    state: dict = {"q": None, "arith": 0}
    i = 0
    while i < len(lines):
        out.append(lines[i])
        pending = _heredoc_delimiters(lines[i], state)
        i += 1
        for end in pending:
            j = next((k for k in range(i, len(lines)) if lines[k].strip() == end), None)
            if j is None:
                break
            i = j + 1
    return "\n".join(out)


class _Cmd(NamedTuple):
    pipes: int  # how many `|` / `|&` join this pipeline's commands
    words: list[str]  # words and redirection operators, in order
    frame: tuple[int, ...]  # the subshells it runs in, outermost first; () is the step's shell


def _pipelines(script: str) -> list[_Cmd]:
    """Split a shell script into pipelines.

    `\\n` is made a punctuation token and each newline is followed by a `;`, so a newline
    still ends a command after shlex's comment handling has swallowed it along with the
    comment. `&&`, `||`, `;`, `&`, `(`, `)` and newlines end a pipeline; a newline straight after
    `|` is a continuation, as it is in bash. `(` opens a subshell frame (so does `$(`) and `)`
    closes it; redirections stay in `words`, so `>> "$GITHUB_OUTPUT"` is visible."""
    text = _strip_heredocs(script).replace("\\\n", " ").replace("\n", "\n;")
    lex = shlex.shlex(text, posix=True, punctuation_chars=_PUNCT)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    out: list[_Cmd] = []
    words: list[str] = []
    pipes = 0
    after_pipe = False
    stack: list[int] = []
    frame: tuple[int, ...] = ()
    serial = 0

    def flush() -> None:
        nonlocal words, pipes
        if words or pipes:
            out.append(_Cmd(pipes, words, frame))
        words, pipes = [], 0

    for tok in lex:
        if not (tok and set(tok) <= set(_PUNCT)):
            if not words and not pipes:
                frame = tuple(stack)
            words.append(tok)
            after_pipe = False
            continue
        for op in _OPS.findall(tok):
            if op in ("|", "|&"):
                pipes += 1
                after_pipe = True
            elif op[0] in "<>" or op in ("&>", "&>>"):
                words.append(op)
            elif after_pipe and op in ("\n", ";"):
                continue  # the newline (and the `;` added after it) continues the pipeline
            else:
                flush()
                after_pipe = False
                if op == "(":
                    serial += 1
                    stack.append(serial)
                elif op == ")" and stack:
                    stack.pop()
    flush()
    return out


def _sets_pipefail(words: list[str]) -> bool | None:
    """True/False if this command turns pipefail on/off (`set -o`/`+o`, `set -euo`,
    `shopt -so`/`-uo`), else None."""
    if not words:
        return None
    if words[0] == "set":
        result = None
        for flag, value in itertools.pairwise(words[1:]):
            if value == "pipefail" and flag[:1] in "-+" and "o" in flag and not flag.startswith("--"):
                result = flag[0] == "-"
        return result
    if words[0] == "shopt" and "pipefail" in words[1:]:
        letters = "".join(w[1:] for w in words[1:] if w.startswith("-") and not w.startswith("--"))
        if "o" in letters and ("s" in letters) != ("u" in letters):
            return "s" in letters
    return None


def _inner_scripts(words: list[str]) -> list[tuple[bool, str]]:
    """(starts with pipefail, script) for each `bash -c '...'` / `sh -c "..."` in a command.

    CHECKED, not refused: the inner string is split and held to the same rule as a step. It
    starts WITHOUT pipefail whatever the outer shell has set, because a child shell does not
    inherit it (only an exported SHELLOPTS would carry it); `bash -o pipefail -c` starts with it."""
    found = []
    for i, w in enumerate(words):
        if w.rsplit("/", 1)[-1] not in _SHELLS:
            continue
        pipefail, has_c, j = False, False, i + 1
        while j < len(words) and words[j][:1] in "-+" and not words[j].startswith("--") and len(words[j]) > 1:
            flag = words[j]
            has_c = has_c or (flag[0] == "-" and "c" in flag)
            if "o" in flag and j + 1 < len(words):
                if words[j + 1] == "pipefail":
                    pipefail = flag[0] == "-"
                j += 1
            j += 1
        if has_c and j < len(words):
            found.append((pipefail, words[j]))
    return found


def _has_pipe(script: str) -> bool:
    return any(c.pipes or any(_has_pipe(s) for _, s in _inner_scripts(c.words)) for c in _pipelines(script))


def _captures_status(pipes: int, nxt: list[str]) -> bool:
    """The command after a pipeline keeps its LEFT-HAND status: one `|`, and `${PIPESTATUS[0]}`
    either assigned to a variable (`rc=${PIPESTATUS[0]}`, optionally under local/declare/...)
    or echoed as `key=${PIPESTATUS[0]}` into `$GITHUB_OUTPUT`, as photonic-drift.yml does.
    Merely MENTIONING PIPESTATUS (`: "${PIPESTATUS[@]}"`, `${PIPESTATUS[1]}`) keeps nothing.
    With more than one `|`, index 0 says nothing about the middle stages, so it does not count."""
    if pipes != 1 or not nxt:
        return False
    body = nxt[1:] if nxt[0] in ("local", "declare", "typeset", "readonly", "export") else nxt
    if body and all("=" in w for w in body) and any(_ASSIGN_STATUS0.fullmatch(w) for w in body):
        return True
    if nxt[0] in ("echo", "printf") and any(_ASSIGN_STATUS0.fullmatch(w) for w in nxt):
        return any(a == ">>" and b in _OUTPUT_TARGETS for a, b in itertools.pairwise(nxt))
    return False


def _unguarded_pipelines(script: str, pipefail: bool = False) -> list[str]:
    """Pipelines in `script` whose left-hand failures would be lost, as text for the message.

    `pipefail` is the state the script STARTS in (`shell: bash` starts with it on). A `set` inside
    a subshell, `( set -o pipefail )` or `$(...)`, changes only that subshell, so the state is
    kept per frame and a frame sees the latest setting made in it or in the frames around it."""
    set_in: dict[tuple[int, ...], bool] = {(): pipefail}
    bad: list[str] = []
    cmds = _pipelines(script)

    def effective(frame: tuple[int, ...]) -> bool:
        for k in range(len(frame), -1, -1):
            if frame[:k] in set_in:
                return set_in[frame[:k]]
        return pipefail

    for i, cmd in enumerate(cmds):
        toggled = _sets_pipefail(cmd.words)
        if toggled is not None:
            set_in[cmd.frame] = toggled
        for inner_pf, inner in _inner_scripts(cmd.words):
            bad.extend(f"[inside {cmd.words[0]} -c] {p}" for p in _unguarded_pipelines(inner, inner_pf))
        if not cmd.pipes or effective(cmd.frame):
            continue
        nxt = cmds[i + 1].words if i + 1 < len(cmds) else []
        if not _captures_status(cmd.pipes, nxt):
            bad.append(" ".join(cmd.words)[:120])
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
                if not isinstance(run, str) or not _has_pipe(run):
                    continue
                label = f"{wf.name}:{job_id}:{step.get('name') or step.get('id') or n}"
                found.append((wf.name, label, step.get("shell", job_shell), run))
    return found


def _violations(steps: list[tuple[str, str, str | None, str]]) -> list[str]:
    out = []
    for _wf, label, shell, run in steps:
        # `shell: bash` starts WITH pipefail, but a `bash -c` inside it still starts without.
        out.extend(f"{label}: {p}" for p in _unguarded_pipelines(run, pipefail=shell == "bash"))
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
        assert not _has_pipe(script), script
    assert _has_pipe("a |\n  b\n"), "a newline after | continues the pipeline"


_LOST = "a | tee log\n"  # an unguarded pipeline; every plant below must still see it


def _flags(script: str, shell: str | None = None) -> bool:
    return bool(_violations([("w", "s", shell, script)]))


def test_only_a_REAL_heredoc_suspends_the_check_and_only_until_its_terminator() -> None:
    """Plant: the old heredoc regex matched `<<EOF` inside quotes and `1<<N` inside arithmetic,
    and with no terminator line to end it, skipped the whole rest of the step."""
    assert _flags(_LOST), "control: the bare pipeline must be flagged"
    for fake in (
        'echo "use <<EOF"\n',
        "echo 'use <<EOF'\n",
        "x=$((1<<N))\n",
        "(( y = 1 << 3 ))\n",
        'cat <<< "$here_string"\n',
        "echo hi  # <<EOF\n",
        "cat <<EOF\n",  # a real opener whose terminator never comes: the rest stays checked
    ):
        assert _flags(fake + _LOST), fake
    # Honest path: a real heredoc's BODY is skipped, quoted or not, `<<-` or not...
    for real in ("python - <<'PY'\nprint(1 | 2)\nPY\n", 'cat <<-"E"\n1 | 2\nE\n', "cat > f <<X\n1|2\nX\n"):
        assert not _flags(real), real
    # ...two on one line are each skipped to their own terminator...
    assert not _flags("paste <<A <<B\n1 | 2\nA\n3 | 4\nB\n")
    # ...and a pipeline AFTER the terminator is checked again.
    assert _flags("python - <<'PY'\nprint(1)\nPY\n" + _LOST)


def test_pipefail_set_in_a_SUBSHELL_does_not_cover_the_step() -> None:
    """Plant: `( set -o pipefail )` counted as setting it for everything after."""
    for sub in ("( set -o pipefail )\n", "x=$(set -o pipefail)\n", "(set -euo pipefail; true)\n"):
        assert _flags(sub + _LOST), sub
    # Honest path: the step's own shell, `shopt -so` included...
    for top in ("set -o pipefail\n", "set -euxo pipefail\n", "shopt -so pipefail\n", "shopt -s -o pipefail\n"):
        assert not _flags(top + _LOST), top
    assert _flags("shopt -so pipefail\nshopt -uo pipefail\n" + _LOST)
    # ...and a subshell sees its parent's setting, and its own for the pipes inside it.
    assert not _flags("set -o pipefail\n( a | tee log )\n")
    assert not _flags("( set -o pipefail; a | tee log )\n")
    assert _flags("( set -o pipefail; true )\n( a | tee log )\n"), "a sibling subshell is a new shell"


def test_a_pipe_inside_bash_c_is_CHECKED() -> None:
    """Plant: the pipe inside `bash -c '...'` was one quoted word, never seen. Chosen: check the
    inner script (not refuse every `bash -c`), starting WITHOUT pipefail, since a child shell
    does not inherit the parent's."""
    for script, shell in (
        ("bash -c 'a | tee log'\n", None),
        ('sh -c "a | tee log"\n', None),
        ("/bin/bash -ec 'a | tee log'\n", None),
        ("set -o pipefail\nbash -c 'a | tee log'\n", None),
        ("bash -c 'a | tee log'\n", "bash"),
    ):
        assert _flags(script, shell), (script, shell)
    assert _has_pipe("bash -c 'a | b'\n"), "a step whose only pipe is inside bash -c must be scanned"
    # Honest path: the inner script guards itself, or the child starts with pipefail.
    for ok in (
        "bash -c 'set -o pipefail; a | tee log'\n",
        "bash -o pipefail -c 'a | tee log'\n",
        "bash -eo pipefail -c 'a | tee log'\n",
        "bash -c 'echo no pipe here'\n",
        "poetry run bash scripts/x.sh\n",
    ):
        assert not _flags(ok), ok


def test_only_a_CAPTURED_PIPESTATUS_0_counts() -> None:
    """Plant: any word containing PIPESTATUS counted, so `${PIPESTATUS[1]}` (the RIGHT-hand
    status) and `: "${PIPESTATUS[@]}"` (read and thrown away) both passed."""
    for nxt in (
        'echo "${PIPESTATUS[1]}"\n',
        ': "${PIPESTATUS[@]}"\n',
        'echo "${PIPESTATUS[0]}"\n',  # printed, not kept
        'echo "code=${PIPESTATUS[0]}" > log.txt\n',  # kept, but not where the workflow reads it
        "rc=${PIPESTATUS[1]}\n",
    ):
        assert _flags(_LOST + nxt), nxt
    # Three stages: index 0 says nothing about the middle one.
    assert _flags("a | b | tee log\nrc=${PIPESTATUS[0]}\n")
    # Honest path: captured into a variable, or into $GITHUB_OUTPUT as photonic-drift.yml does.
    for nxt in (
        "rc=${PIPESTATUS[0]}\n",
        'rc="${PIPESTATUS[0]}"\n',
        'local rc="${PIPESTATUS[0]}"\n',
        'echo "code=${PIPESTATUS[0]}" >> "$GITHUB_OUTPUT"\n',
        'echo "code=${PIPESTATUS[0]}" >> ${GITHUB_OUTPUT}\n',
    ):
        assert not _flags(_LOST + nxt), nxt

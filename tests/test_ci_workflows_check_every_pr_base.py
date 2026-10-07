"""A pull request into ANY base branch must get the checks a pull request into main gets.

Branch protection requires eight status checks on `main` (`_REQUIRED_CHECKS` below; the
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
import json
import re
import shlex
import shutil
import subprocess
import sys
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
#: 2026-10-07: `test (3.11)` and `test (3.10)` added (app_id 15368); eight in all.
#: The workflow that produces each one is NOT written here; it is derived from the workflows' job
#: names, so a renamed job fails this file rather than silently leaving a check unguarded.
_REQUIRED_CHECKS = (
    "test (3.12)",
    "test (3.11)",  # added to branch protection 2026-10-07
    "test (3.10)",  # added to branch protection 2026-10-07
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
#: protection does NOT require yet. REVIEWED, like `_REQUIRED_CHECKS`. A check that must run on
#: every PR before it is made required belongs here, then moves up.
_GUARDED_NOT_YET_REQUIRED: tuple[str, ...] = (
    # counter-leg-artifacts.yml: rebuilds tests/fixtures/{EthHtlc,Erc20Htlc}.json from contracts/
    # and fails on any difference (#846). Whether to require it is the maintainer's call.
    "counter-leg artifacts rebuild",
)

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
#: required signatures were switched off, and again 2026-10-07 after the two test checks were added
#: (every other field unchanged). The check list is built from `_REQUIRED_CHECKS`, so the
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


#: The shell's metacharacters: outside quotes, each one ends a word.
_METACHARACTERS = frozenset(" \t\n;&|()<>")

#: Redirection operators as `shlex` (punctuation mode) returns them. The word after one is its
#: target, not a command.
_REDIRECTIONS = frozenset({"<", ">", ">>", "<<", "<<<", "<&", ">&", "<>", ">|", "&>", "&>>"})

#: Reserved words after which the shell still expects a command word (`if gh ...`, `! gh ...`).
_PREFIX_RESERVED_WORDS = frozenset({"!", "{", "if", "then", "else", "elif", "while", "until", "do", "time"})

#: `NAME=value` (or `NAME+=value`, `NAME[i]=value`) before a command is an assignment, not the command.
_ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")

#: The only heredoc this parser reads: `<<` or `<<-`, then a delimiter in single or double quotes
#: that ends where the shell's word would. Quoting the delimiter is what stops the shell expanding
#: the body, so the body is data.
_QUOTED_HEREDOC = re.compile(r"<<(-?)[ \t]*(?:'(\w+)'|\"(\w+)\")(?=[ \t\n;&|()<>]|$)")

#: `gh api` options that take a value, so the word after them is not the endpoint.
_GH_API_VALUED_OPTIONS = frozenset(
    {"-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field", "--input", "-q", "--jq"}
    | {"-t", "--template", "--hostname", "-p", "--preview", "--cache"}
)

#: EVERY `gh api` invocation the script makes, word for word after `gh api`, in order. REVIEWED:
#: read from the script on 2026-09-25. Any new call, or any change to one, fails
#: `test_the_protection_script_makes_only_the_reviewed_api_calls` until it is added here, which is
#: the point: a call that changes repository settings should not arrive without someone reading it.
_REVIEWED_GH_API_CALLS: list[list[str]] = [
    ["repos/${REPO}", "--jq", ".visibility"],
    [
        "-X",
        "PATCH",
        "repos/${REPO}",
        "-F",
        "security_and_analysis[secret_scanning][status]=enabled",
        "-F",
        "security_and_analysis[secret_scanning_push_protection][status]=enabled",
        "--silent",
    ],
    ["-X", "PUT", "repos/${REPO}/automated-security-fixes", "--silent"],
    ["-X", "PUT", "repos/${REPO}/vulnerability-alerts", "--silent"],
    ["-X", "PUT", "repos/${REPO}/private-vulnerability-reporting", "--silent"],
    ["-X", "PUT", "repos/${REPO}/branches/${BRANCH}/protection", "--input", "-"],
    [
        "repos/${REPO}",
        "--jq",
        "{\n  visibility,\n  default_branch,\n  security_and_analysis: .security_and_analysis\n}",
    ],
]

#: The first word of every simple command the script runs, as `_command_words` reads them.
#: REVIEWED: read from the script on 2026-09-28. `say`, `ok` and `warn` are functions the script
#: defines around `printf`; `{`, `}`, `if`, `then`, `fi` and `[[` are shell syntax. A command word
#: not listed here fails the check until someone adds it, and a listed word the script no longer
#: uses fails it too. Most ways to run text as a command (`bash -c`, `eval`, `python3 -c`, `.`,
#: `xargs`, `trap`, `env`, `exec`) begin with a word that is not on this list.
_REVIEWED_COMMAND_WORDS = frozenset(
    {"set", "say", "ok", "warn", "printf", "{", "}", "gh", "if", "[[", "then", "exit", "fi", "cat"}
)


def _is_operator(word: str) -> bool:
    """A control or redirection operator. `shlex` (punctuation mode) returns a RUN of the characters
    `();<>|&` as one token, so `);`, `()` and `|&` arrive whole."""
    return bool(word) and set(word) <= set("();<>|&")


def _script_commands(text: str) -> str:
    """`text` as the shell would run it, minus what the shell does not run.

    One pass that tracks quoting the way bash does. Outside quotes: a backslash-newline is removed
    (a line continuation, joined with no space), any other backslash keeps the next character from
    being special, a `#` that begins a word drops the rest of the line, and a newline becomes `;`,
    so each command's words end where the shell's do while a quoted multi-line argument stays
    whole. A `<<` outside quotes opens a heredoc, and its body (the lines after this one, up to
    the delimiter) is removed: it is data, because the delimiter must be quoted. Inside double
    quotes a backslash-newline is removed too; inside single quotes nothing is special.

    Rather than guess, it fails on forms it would otherwise read differently from bash: a heredoc
    delimiter that is unquoted or written any other way, a heredoc never closed, `$'…'` quoting
    (in which `\\'` does not end the string), and an unbalanced quote.
    """
    name = _PROTECTION_SCRIPT.name
    out: list[str] = []
    quote = ""
    word_start = True  # the next character would begin a word, so a `#` there begins a comment
    heredocs: list[tuple[str, bool]] = []  # opened on the current line: (delimiter, strip leading tabs)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if quote == "'":
            out.append(c)
            quote = "" if c == "'" else quote
            i += 1
        elif quote == '"':
            if c == "\\" and i + 1 < n:
                if text[i + 1] != "\n":
                    out.append(text[i : i + 2])
                i += 2
                continue
            out.append(c)
            quote = "" if c == '"' else quote
            i += 1
        elif c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                out.append(text[i : i + 2])
                word_start = False
            i += 2
        elif c in "'\"":
            assert not (c == "'" and out and out[-1] == "$"), (
                f"{name} uses `$'…'` (ANSI-C) quoting, in which `\\'` does not end the string; this "
                f"parser would disagree with bash about where the string ends"
            )
            quote = c
            out.append(c)
            word_start = False
            i += 1
        elif c == "#" and word_start:
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("<<<", i):
            out.append(" <<< ")
            word_start = True
            i += 3
        elif text.startswith("<<", i):
            m = _QUOTED_HEREDOC.match(text, i)
            line = text[i:].split("\n", 1)[0]
            assert m, (
                f"{name}: `{line}`: a heredoc must have a quoted delimiter, such as <<'EOF'. With an "
                f"unquoted one the shell expands the body, so a `$(…)` in it runs; other forms this "
                f"parser does not read"
            )
            delimiter = m.group(2) or m.group(3)
            heredocs.append((delimiter, m.group(1) == "-"))
            out.append(f" << {delimiter} ")
            word_start = True
            i = m.end()
        elif c == "\n":
            out.append(" ; ")
            word_start = True
            i += 1
            for delimiter, strip_tabs in heredocs:
                while True:
                    assert i < n, f"{name}: the heredoc ended by {delimiter!r} is never closed"
                    end = text.find("\n", i)
                    end = n if end == -1 else end
                    body_line, i = text[i:end], end + 1
                    if (body_line.lstrip("\t") if strip_tabs else body_line) == delimiter:
                        break
            heredocs.clear()
        else:
            out.append(c)
            word_start = c in _METACHARACTERS
            i += 1
    assert not quote, f"unbalanced {quote} quote in {name}; this parser cannot read it"
    assert not heredocs, f"{name}: heredoc(s) {[d for d, _ in heredocs]} opened on the last line, with no body"
    return "".join(out)


def _script_words(text: str) -> list[str]:
    """`_script_commands(text)` split into shell words (quotes removed, variables NOT expanded)."""
    lex = shlex.shlex(_script_commands(text), posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


def _command_words(words: list[str]) -> list[str]:
    """The first word of every simple command, in order: the word at the start or after a control
    operator, once any `NAME=value` assignments and redirections before it are skipped. After a
    reserved word such as `if`, `then`, `!` or `{`, the next word is a command word as well."""
    found: list[str] = []
    expecting = True
    i = 0
    while i < len(words):
        word = words[i]
        if word in _REDIRECTIONS:
            i += 2
            continue
        if _is_operator(word):
            expecting = True
        elif expecting and not _ASSIGNMENT_WORD.match(word):
            found.append(word)
            expecting = word in _PREFIX_RESERVED_WORDS
        i += 1
    return found


def _gh_api_calls(words: list[str]) -> list[list[str]]:
    """The words after each `gh api`, up to the operator that ends the command."""
    calls = []
    for i, word in enumerate(words):
        if word == "gh" and words[i + 1 : i + 2] == ["api"]:
            argv = []
            for w in words[i + 2 :]:
                if _is_operator(w):
                    break
                argv.append(w)
            calls.append(argv)
    return calls


def _method_and_endpoint(argv: list[str]) -> tuple[str, str]:
    """The HTTP method `gh api` will use, and its endpoint argument. With no `-X`, `gh api` sends
    GET, or POST when any field or input is given."""
    method, positional, i = "", [], 0
    while i < len(argv):
        word = argv[i]
        if word in _GH_API_VALUED_OPTIONS:
            if word in ("-X", "--method"):
                method = argv[i + 1].upper()
            i += 2
            continue
        if not word.startswith("-"):
            positional.append(word)
        i += 1
    assert len(positional) == 1, f"`gh api {' '.join(argv)}` has {len(positional)} endpoint arguments, not 1"
    if not method:
        has_body = any(w in ("-f", "--raw-field", "-F", "--field", "--input") for w in argv)
        method = "POST" if has_body else "GET"
    return method, positional[0]


def test_the_protection_script_reproduces_the_live_rules_exactly() -> None:
    """`scripts/post-public-flip.sh` calls itself idempotent and safe to re-run, and it PUTs a
    whole branch-protection document. It held `enforce_admins: false`, one required approval,
    and a `typecheck` check that no workflow produces, while the live rules had moved on to six
    app-bound checks enforced for admins. A re-run would have silently switched the admin bypass
    back on. Pinning only those fields left the rest free to drift (a re-run could have allowed
    force pushes, or dropped linear history), so the WHOLE document is compared."""
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


def _check_protection_script(text: str) -> None:
    """Every check `test_the_protection_script_makes_only_the_reviewed_api_calls` makes, on `text`."""
    name = _PROTECTION_SCRIPT.name
    words = _script_words(text)
    assert "<<<" not in words, f"{name} uses a `<<<` here-string, which hands text to a command's input"
    for word in words:
        base = word.rsplit("/", 1)[-1]
        assert base not in ("bash", "sh") and not base.startswith("python"), (
            f"{name} runs `{word}`, an interpreter: the commands it is given are text this check cannot see"
        )
        assert "$(" not in word and "`" not in word, (
            f"{name}: {word!r} holds a command substitution this check cannot split into commands "
            f"(one inside quotes, or text that a later arithmetic evaluation could run)"
        )
    for banned in ("eval", "curl", "wget", "source"):
        assert banned not in words, f"{name} runs `{banned}`, which this test cannot see through"
    joined = " ".join(words).lower()
    for mention in ("graphql", "required_signatures"):
        assert mention not in joined, f"{name} mentions {mention!r} outside its comments and heredocs"
    commands = _command_words(words)
    for word in commands:
        assert "$" not in word, f"{name} runs `{word}`, a command named by a variable or substitution"
    for i, word in enumerate(words):
        if word == "gh":
            assert words[i + 1 : i + 2] == ["api"], f"`gh {words[i + 1]}`: the script may use only `gh api`"
        if word == "api":
            assert i > 0 and words[i - 1] == "gh", f"`{words[i - 1]} api`: an API call not spelled `gh api`"
    assignments = {var: [w for w in words if w.startswith(f"{var}=")] for var in ("REPO", "BRANCH")}
    assert assignments == {"REPO": ["REPO=MudwoodLabs/pyrxd"], "BRANCH": ["BRANCH=main"]}, assignments
    unreviewed, unused = (
        sorted(set(commands) - _REVIEWED_COMMAND_WORDS),
        sorted(_REVIEWED_COMMAND_WORDS - set(commands)),
    )
    assert not unreviewed and not unused, (
        f"{name} runs commands not in _REVIEWED_COMMAND_WORDS: {unreviewed}; listed there but no longer "
        f"run: {unused}. Read what the new command can execute before adding it."
    )

    calls = _gh_api_calls(words)
    assert calls, f"found no `gh api` call in {name}; this test checked nothing"
    protection = []
    for argv in calls:
        method, endpoint = _method_and_endpoint(argv)
        literal = endpoint.replace("${REPO}", "").replace("${BRANCH}", "")
        assert re.fullmatch(r"[A-Za-z0-9_./-]+", literal), (
            f"`gh api {' '.join(argv)}`: the endpoint {endpoint!r} is not a literal path "
            f"(only ${{REPO}} and ${{BRANCH}} may appear in it)"
        )
        assert method not in ("DELETE", "POST"), f"`gh api {' '.join(argv)}` is a {method}"
        if "protection" in endpoint:
            protection.append((method, endpoint))
    assert protection == [("PUT", "repos/${REPO}/branches/${BRANCH}/protection")], protection
    assert calls == _REVIEWED_GH_API_CALLS, (
        f"{_PROTECTION_SCRIPT.name} makes API calls that differ from _REVIEWED_GH_API_CALLS:\n"
        + "\n".join(f"  gh api {' '.join(c)}" for c in calls)
    )


def test_the_protection_script_makes_only_the_reviewed_api_calls() -> None:
    """The script used to POST required signatures after its PUT. With admins enforced that
    blocked every PR, so the maintainer switched it off, and a re-run would have switched it back
    on. A first version of this test looked only at `gh api` lines containing `branches/`, and two
    plants got past it: a DELETE of `enforce_admins` through a variable path, and a GraphQL
    `updateBranchProtectionRule(isAdminEnforced: false)`. The next version read a quoted `<<WORD`
    as a heredoc and dropped the real commands after it, and could not see commands run from a
    string or by another interpreter (issue #750); `_BYPASSES` holds each of those.

    What it checks, on the script's text split into shell words (comments dropped; heredoc
    bodies, which a quoted delimiter makes data, removed; variables NOT expanded):

    * none of the forms `_script_commands` would read differently from bash: an unquoted heredoc
      delimiter (the shell expands such a body, so a `$(…)` there would run), a heredoc never
      closed, `$'…'` quoting, an unbalanced quote;
    * no word is `bash`, `sh` or `python…` (with or without a directory), `eval`, `source`,
      `curl` or `wget`; there is no `<<<`; no word holds `$(` or a backtick (a command
      substitution inside quotes, which this parser does not split into commands); no command
      word contains `$`;
    * the first word of every simple command is in `_REVIEWED_COMMAND_WORDS`, and every word
      listed there is still used;
    * every `gh` is `gh api`, every `api` follows `gh`, and nothing mentions `graphql` or
      `required_signatures`;
    * `REPO` and `BRANCH` are each assigned exactly once, to `MudwoodLabs/pyrxd` and `main`;
    * every endpoint is a literal path whose only variables are `${REPO}` and `${BRANCH}`;
    * the method is never DELETE or POST, the only call whose endpoint mentions `protection` is
      the PUT the test above checks, and the calls equal `_REVIEWED_GH_API_CALLS` word for word.

    WHAT IT CANNOT SEE: it reads text, it is not a shell. A command the script builds while it
    runs, out of pieces that are each harmless text, and then has the shell evaluate (arithmetic
    evaluation of an array subscript is one route) is invisible to it; `_ASSEMBLED_AT_RUN_TIME`
    is one, and a test below keeps this sentence true.
    `test_under_bash_the_script_calls_gh_exactly_as_reviewed` runs the script and catches such a
    `gh` call on the path that run takes (every call succeeds and the repository reads as
    public). On any other path, only review of the script catches it."""
    _check_protection_script(_PROTECTION_SCRIPT.read_text(encoding="utf-8"))


#: The call every bypass below makes: switching off `enforce_admins` on main.
_DELETE_ENFORCE_ADMINS = 'gh api -X DELETE "repos/${REPO}/branches/${BRANCH}/protection/enforce_admins" --silent'
#: The same call with the variables written out, for text the script hands to another process.
_DELETE_ENFORCE_ADMINS_LITERAL = (
    "gh api -X DELETE repos/MudwoodLabs/pyrxd/branches/main/protection/enforce_admins --silent"
)
#: Each bypass is inserted after this line of the real script.
_BYPASS_ANCHOR = 'ok "branch protection applied to ${BRANCH}"\n'

#: Ways to hide a protection DELETE from the check, each with the text its failure must contain, so
#: a plant cannot pass by tripping some other rule. The first six came from the review of #748
#: (issue #750); the check then in place passed all six. The next eight were found while fixing
#: it: all but the ANSI-C one passed that check too (the ANSI-C one made `shlex` raise), and
#: `dot-source-from-a-heredoc` is caught by `_REVIEWED_COMMAND_WORDS` alone. The last
#: pins this parser's own order of work: a backslash ending a quoted heredoc's body line is data,
#: and must not join that line to the delimiter below it. The four that end "is a DELETE" use only
#: reviewed command words, so they fail only if the parser now SEES the hidden call.
_BYPASSES: dict[str, tuple[str, str]] = {
    "quoted-heredoc-marker": (f'ok "see <<ok below"\n{_DELETE_ENFORCE_ADMINS}\nok\n', "is a DELETE"),
    "heredoc-piped-to-bash": (f"cat <<'SH' | bash\n{_DELETE_ENFORCE_ADMINS_LITERAL}\nSH\n", "an interpreter"),
    "bash-c": (f"bash -c '{_DELETE_ENFORCE_ADMINS_LITERAL}'\n", "an interpreter"),
    "bash-here-string": (f"bash <<< '{_DELETE_ENFORCE_ADMINS_LITERAL}'\n", "here-string"),
    "command-in-a-variable": (f'c="{_DELETE_ENFORCE_ADMINS_LITERAL}"; $c\n', "named by a variable"),
    "python3-subprocess": (
        f"python3 -c 'import shlex, subprocess; subprocess.run(shlex.split(\"{_DELETE_ENFORCE_ADMINS_LITERAL}\"))'\n",
        "an interpreter",
    ),
    "unquoted-heredoc-body": (f"cat <<NOTES\n$({_DELETE_ENFORCE_ADMINS})\nNOTES\n", "quoted delimiter"),
    "substitution-in-double-quotes": (f'ok "$({_DELETE_ENFORCE_ADMINS_LITERAL})"\n', "command substitution"),
    "substitution-in-single-quotes-arithmetic": (
        f"if [[ -v 'x[$({_DELETE_ENFORCE_ADMINS_LITERAL})]' ]]; then ok; fi\n",
        "command substitution",
    ),
    "backticks-in-double-quotes": (f'ok "`{_DELETE_ENFORCE_ADMINS_LITERAL}`"\n', "command substitution"),
    "ansi-c-quoting": (f"ok $'\\''; {_DELETE_ENFORCE_ADMINS}; ok $'\\''\n", "ANSI-C"),
    "comment-after-line-continuation": (f"ok a\\\n#; {_DELETE_ENFORCE_ADMINS}\n", "is a DELETE"),
    "comment-after-escaped-space": (f"ok a\\ #; {_DELETE_ENFORCE_ADMINS}\n", "is a DELETE"),
    "dot-source-from-a-heredoc": (
        f". /dev/stdin <<'SRC'\n{_DELETE_ENFORCE_ADMINS_LITERAL}\nSRC\n",
        "not in _REVIEWED_COMMAND_WORDS",
    ),
    "backslash-ending-a-heredoc-body-line": (
        f"cat <<'EOF'\na \\\nEOF\n{_DELETE_ENFORCE_ADMINS}\ncat <<'EOF'\nb\nEOF\n",
        "is a DELETE",
    ),
}


#: A DELETE the text check CANNOT see, kept so the docstring's WHAT IT CANNOT SEE stays true: `$`
#: and `(` meet only when the script runs, and `[[ -v ]]` then evaluates the subscript, running it.
_ASSEMBLED_AT_RUN_TIME = f"p='$'; x=\"a[${{p}}({_DELETE_ENFORCE_ADMINS_LITERAL})]\"; [[ -v $x ]] || ok\n"


def _planted(plant: str) -> str:
    text = _PROTECTION_SCRIPT.read_text(encoding="utf-8")
    assert text.count(_BYPASS_ANCHOR) == 1, f"{_PROTECTION_SCRIPT.name} no longer has one {_BYPASS_ANCHOR!r}"
    return text.replace(_BYPASS_ANCHOR, _BYPASS_ANCHOR + plant)


@pytest.mark.parametrize("bypass", _BYPASSES)
def test_each_known_bypass_fails_the_protection_script_check(bypass: str) -> None:
    plant, failure = _BYPASSES[bypass]
    with pytest.raises(AssertionError, match=re.escape(failure)):
        _check_protection_script(_planted(plant))


def _run_with_stub_gh(tmp_path: Path, text: str) -> tuple[subprocess.CompletedProcess[str], list[list[str]]]:
    """Run `text` under real bash with a PATH that holds ONLY a stand-in `gh`, which records its
    arguments and answers the visibility query with `public`, plus `cat`, `bash` and `python3`
    (the bypasses above need the last two). The real `gh` is not on that PATH, the environment
    holds no token, and HOME is the test's own temporary directory."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "gh-calls.jsonl"
    stub = bindir / "gh"
    stub.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['GH_STUB_LOG'], 'a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if '.visibility' in sys.argv[1:]:\n"
        "    print('public')\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    for tool in ("bash", "cat"):
        found = shutil.which(tool)
        assert found, f"`{tool}` is not installed; this test runs the script under it"
        (bindir / tool).symlink_to(found)
    (bindir / "python3").symlink_to(sys.executable)
    assert shutil.which("gh", path=str(bindir)) == str(stub), "the stand-in gh is not the one on PATH"
    script = tmp_path / _PROTECTION_SCRIPT.name
    script.write_text(text, encoding="utf-8")
    env = {"PATH": str(bindir), "HOME": str(tmp_path), "GH_STUB_LOG": str(log), "LC_ALL": "C.UTF-8"}
    proc = subprocess.run(
        [str(bindir / "bash"), str(script)], env=env, capture_output=True, text=True, timeout=60, check=False
    )
    calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    return proc, calls


def test_under_bash_the_script_calls_gh_exactly_as_reviewed(tmp_path: Path) -> None:
    """The honest path, and the check above measured against a real shell. The script runs to the
    end, and the calls bash makes are `_REVIEWED_GH_API_CALLS` with `${REPO}` and `${BRANCH}`
    expanded, argument for argument. A call the text check cannot see (see its WHAT IT CANNOT SEE)
    still fails here, if it is on the path this run takes."""
    proc, calls = _run_with_stub_gh(tmp_path, _PROTECTION_SCRIPT.read_text(encoding="utf-8"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    expanded = [
        ["api", *(w.replace("${REPO}", "MudwoodLabs/pyrxd").replace("${BRANCH}", "main") for w in call)]
        for call in _REVIEWED_GH_API_CALLS
    ]
    assert calls == expanded, f"under bash the script called gh as: {calls}"


@pytest.mark.parametrize("bypass", _BYPASSES)
def test_each_known_bypass_really_runs_the_delete_under_bash(tmp_path: Path, bypass: str) -> None:
    """A plant that bash would not run proves nothing about the check, so each one is run: the
    DELETE must reach the stand-in `gh`."""
    proc, calls = _run_with_stub_gh(tmp_path, _planted(_BYPASSES[bypass][0]))
    delete = _DELETE_ENFORCE_ADMINS_LITERAL.split()[1:]
    assert delete in calls, f"bash did not run the DELETE (exit {proc.returncode}): {calls}\n{proc.stderr}"


def test_a_call_assembled_at_run_time_passes_the_text_check_and_is_caught_under_bash(tmp_path: Path) -> None:
    """Both halves of WHAT IT CANNOT SEE, executed. The text check passes `_ASSEMBLED_AT_RUN_TIME`;
    if it starts failing it, the check has closed this gap, so move the plant into `_BYPASSES`
    and correct that docstring. Under bash the DELETE runs, and the honest-path comparison above
    would not match the calls."""
    text = _planted(_ASSEMBLED_AT_RUN_TIME)
    _check_protection_script(text)
    proc, calls = _run_with_stub_gh(tmp_path, text)
    assert _DELETE_ENFORCE_ADMINS_LITERAL.split()[1:] in calls, f"bash did not run the DELETE: {calls}\n{proc.stderr}"
    assert len(calls) == len(_REVIEWED_GH_API_CALLS) + 1, calls


def test_no_doc_or_script_tells_anyone_to_admin_merge() -> None:
    """The release runbook merged with `gh pr merge ... --admin`. That flag merges a PR that fails
    ANY requirement, required checks included, and with `enforce_admins` on it no longer works at
    all, so an instruction to use it is now wrong twice. Every tracked file except the frozen
    CHANGELOG and the tests is read; backslash-continued command lines are joined first, so the
    flag cannot hide on the next line. The runbook's own (flagless) merge command must be SEEN,
    so a scan that read nothing cannot pass."""
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

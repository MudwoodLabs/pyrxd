"""The published docs make CLAIMS about the code, and nothing evaluates them.

Prose drifts from the code beside it in total silence: tests pin that a sentence is
*emitted*, never that it is *correct*. Two kinds of claim in the how-to guides are
mechanically checkable, and both had failed by the time this file was written:

* **"the code is at this path"** — ``docs/concepts/external-miner-protocol.md`` cited
  ``src/pyrxd/glyph/dmint.py`` in five places. That module became a *package* whose
  ``__init__.py`` only re-exports; the code moved to ``dmint/miner.py``. Every citation
  pointed at a file that does not exist.
* **"run this command"** — ``docs/how-to/create-a-token-collection.md`` opened with
  ``pyrxd glyph init-metadata --type container-nft -o collection.json``. The command
  declares ``--out`` and no ``-o``, so the documented first step of that guide exited
  with ``Error: No such option '-o'``.

Neither is exotic. Both are what a reader hits on line one, and both are a `grep` and a
signature lookup away from being impossible.

**Scope.** ``docs/brainstorms/`` and ``docs/plans/`` are dated working drafts, and
``docs/solutions/`` are dated incident records — a record that names a file as it stood
in May is not stale, it is a record. Only the prescriptive surface is scanned, matching
``tests/test_protocol_lock_ordering_docs_are_current.py``.

**What this cannot do.** It checks that a cited path resolves and that a documented
invocation's *options are declared*. It cannot check that the prose around them is true,
that the arguments are sensible, or that the command would succeed against a real chain.
It is a DETECT-level mechanism for the two claim classes above, not a proof the docs are
right.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import click
import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: The prescriptive, user-facing surface. See the scope note in the module docstring for
#: why brainstorms/plans/solutions are absent.
_SCANNED_DIRS = (
    _ROOT / "docs" / "how-to",
    _ROOT / "docs" / "tutorials",
    _ROOT / "docs" / "concepts",
    _ROOT / "docs" / "reference",
)


def _scanned_docs() -> list[Path]:
    out: list[Path] = []
    for d in _SCANNED_DIRS:
        if d.exists():
            out.extend(d.rglob("*.md"))
    out.extend((_ROOT / "docs").glob("*.md"))  # top-level pages, not the dated subtrees
    return sorted(set(out))


# ---------------------------------------------------------------------------
# 1. Every source path a doc cites must exist
# ---------------------------------------------------------------------------

#: Matches a citation in prose, in a markdown link target, or in a fenced block alike —
#: the drift is the same wherever it appears, and the three spellings of it in
#: external-miner-protocol.md were split across all three.
_SRC_PATH_RE = re.compile(r"src/pyrxd/[A-Za-z0-9_/]+\.py")

#: Floor for the non-vacuity assertion. Measured at 95 distinct paths / 423 occurrences
#: when this test was written; the floor is set well below that so ordinary doc churn
#: does not trip it, and well above zero so a broken regex or an empty scan cannot pass
#: as a clean run. A structural check whose SET is empty is indistinguishable from a
#: passing one in the output, which is precisely how guards go quietly vacuous.
_MIN_CITED_PATHS = 40


def _cited_source_paths() -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for doc in _scanned_docs():
        for match in _SRC_PATH_RE.findall(doc.read_text(encoding="utf-8")):
            hits.setdefault(match, []).append(str(doc.relative_to(_ROOT)))
    return hits


def test_every_source_path_cited_in_the_docs_exists() -> None:
    cited = _cited_source_paths()
    assert len(cited) >= _MIN_CITED_PATHS, (
        f"only {len(cited)} source-path citations found across {len(_scanned_docs())} docs — "
        "the scan found (almost) nothing, so a pass here proves nothing. Check _SRC_PATH_RE "
        "and _SCANNED_DIRS before lowering this floor."
    )
    missing = {path: sorted(set(docs)) for path, docs in cited.items() if not (_ROOT / path).exists()}
    assert not missing, (
        f"docs cite source files that do not exist — a reader following the citation lands nowhere: {missing}"
    )


# ---------------------------------------------------------------------------
# 2. Every documented CLI invocation's options are declared
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^```([A-Za-z0-9_-]*)")

#: Fence languages where a bare (unprompted) line is a command rather than console
#: output. In a ``console`` fence, output and commands are interleaved, so only the
#: ``$ ``-prefixed lines are commands.
_SHELL_LANGS = frozenset({"bash", "sh", "shell", "zsh"})

#: Measured at 65 invocations / 79 option tokens when written. Same non-vacuity
#: reasoning as _MIN_CITED_PATHS: this check is structural about options and
#: hand-fed about which fences it reaches.
_MIN_INVOCATIONS = 30
_MIN_OPTION_TOKENS = 40


def _extract_invocations(text: str, origin: str) -> list[tuple[str, int, str]]:
    """Return ``(origin, line_number, command)`` for each ``pyrxd ...`` line in a fence.

    Backslash continuations are joined, so a multi-line ``deploy-dmint`` invocation is
    checked as the single command it is.
    """
    out: list[tuple[str, int, str]] = []
    lines = text.splitlines()
    lang: str | None = None
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        fence = _FENCE_RE.match(stripped)
        if fence:
            lang = None if lang is not None else (fence.group(1) or "")
            i += 1
            continue
        if lang is not None:
            body: str | None = None
            if stripped.startswith("$ pyrxd"):
                body = stripped[2:]
            elif lang in _SHELL_LANGS and stripped.startswith("pyrxd "):
                body = stripped
            if body is not None:
                start = i + 1
                while body.rstrip().endswith("\\") and i + 1 < len(lines):
                    i += 1
                    body = body.rstrip()[:-1] + " " + lines[i].strip()
                out.append((origin, start, body))
        i += 1
    return out


def _documented_invocations() -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    for doc in _scanned_docs():
        out.extend(_extract_invocations(doc.read_text(encoding="utf-8"), str(doc.relative_to(_ROOT))))
    return out


def _declared_params(cmd: click.Command, into: dict[str, click.Parameter]) -> dict[str, click.Parameter]:
    """Fold *cmd*'s option spellings into *into*.

    Options accumulate down the command path because click resolves a group's options on
    the group, and the docs write them wherever they read best
    (``pyrxd --network testnet glyph deploy-dmint ...``).
    """
    for param in cmd.params:
        for spelling in list(param.opts) + list(param.secondary_opts):
            into[spelling] = param
    return into


def _check_invocation(root: click.Command, command: str) -> list[str]:
    """Return a list of problems with *command*; empty means every option resolves."""
    command = command.split("#", 1)[0].strip()  # trailing "# explanatory comment"
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []  # unbalanced quotes: a prose fragment, not an invocation
    if not tokens or tokens[0] != "pyrxd":
        return []

    problems: list[str] = []
    current: click.Command = root
    path: list[str] = []
    known = _declared_params(root, {})
    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token == "...":
            break  # documented elision; nothing after it is a real token
        if token.startswith("-"):
            name, _, inline_value = token.partition("=")
            param = known.get(name)
            if param is None:
                problems.append(f"`{' '.join(['pyrxd', *path])}` declares no option {name!r}")
                i += 1
                continue
            takes_value = not getattr(param, "is_flag", False) and param.nargs != 0
            i += 1 + (1 if (takes_value and not inline_value) else 0)
            continue
        if isinstance(current, click.Group):
            sub = current.get_command(click.Context(current), token)
            if sub is None:
                problems.append(f"`{' '.join(['pyrxd', *path])}` has no subcommand {token!r}")
                break
            current = sub
            path.append(token)
            known = _declared_params(current, known)
        i += 1
    return problems


@pytest.fixture(scope="module")
def cli_root() -> click.Command:
    from pyrxd.cli.main import cli

    return cli


def test_every_documented_cli_invocation_names_real_options(cli_root: click.Command) -> None:
    invocations = _documented_invocations()
    assert len(invocations) >= _MIN_INVOCATIONS, (
        f"only {len(invocations)} `pyrxd ...` invocations extracted from {len(_scanned_docs())} docs. "
        "The extractor, not the docs, is the thing to check: a fence style it does not "
        "recognise makes this test pass over nothing."
    )
    option_tokens = sum(
        1 for _o, _l, cmd in invocations for tok in shlex.split(cmd.split("#", 1)[0]) if tok.startswith("-")
    )
    assert option_tokens >= _MIN_OPTION_TOKENS, (
        f"only {option_tokens} option tokens across {len(invocations)} invocations — this check is "
        "about options, so with none of them it asserts nothing."
    )

    failures = [
        f"{origin}:{line}: {cmd}\n    {problem}"
        for origin, line, cmd in invocations
        for problem in _check_invocation(cli_root, cmd)
    ]
    assert not failures, "documented commands that the CLI would refuse:\n" + "\n".join(failures)


def test_the_invocation_checker_actually_catches_a_bad_command(cli_root: click.Command) -> None:
    """Run the checker against defects it was NOT built from.

    The `-o` typo it was written for is a *short* option on a *leaf* command. If the
    checker only ever sees that, a version of it that special-cased short options, or
    that stopped walking after the first subcommand, would look identical to a working
    one. So: a long option on a group, a short option on a leaf, and a subcommand that
    does not exist — none of which is the original defect — plus the honest forms of all
    three, because a checker that refuses valid commands is a worse bug than one that
    misses an invalid one.
    """
    should_fail = [
        "pyrxd --netwrok testnet glyph list --type ft",  # long option, on the ROOT group
        "pyrxd glyph init-metadata --type nft -o out.json",  # short option, on a leaf
        "pyrxd glyph inti-metadata --type nft",  # subcommand that does not exist
        "pyrxd wallet export-xpub --descriptors",  # near-miss of a real flag
    ]
    for command in should_fail:
        assert _check_invocation(cli_root, command), f"checker did not object to {command!r}"

    should_pass = [
        "pyrxd --network testnet glyph list --type ft",
        "pyrxd glyph init-metadata --type nft --out out.json",
        "pyrxd wallet export-xpub --descriptor",
        "pyrxd glyph airdrop-ft <REF> --to <ADDR>:<AMOUNT> --recipients holders.csv",
        "pyrxd --network regtest --electrumx ws://127.0.0.1:50022/ ...",
    ]
    for command in should_pass:
        assert not _check_invocation(cli_root, command), f"checker wrongly objected to {command!r}"


def test_the_extractor_reads_both_fence_styles() -> None:
    """``console`` fences prompt with ``$``; ``bash`` fences do not, and the docs use
    both. An extractor that handled one would silently skip every command in the other —
    the vacuous-pass failure mode, from the direction the count floors cannot see."""
    doc = "\n".join(
        [
            "```console",
            "$ pyrxd glyph list --type ft",
            "some console output that is not a command",
            "```",
            "```bash",
            "pyrxd balance --refresh",
            "pyrxd glyph deploy-dmint token.json \\",
            "    --max-height 100",
            "```",
            "```python",
            "pyrxd_is_not_a_command = 1",
            "```",
        ]
    )
    found = [cmd for _o, _l, cmd in _extract_invocations(doc, "synthetic")]
    assert found == [
        "pyrxd glyph list --type ft",
        "pyrxd balance --refresh",
        "pyrxd glyph deploy-dmint token.json  --max-height 100",
    ], found

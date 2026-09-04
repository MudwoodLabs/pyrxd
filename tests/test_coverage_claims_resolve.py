"""A docstring that says "covered by X" is making a CLAIM. Check X exists.

Prose is the one part of a codebase no test evaluates: tests pin that a sentence is
EMITTED, never that it is TRUE. So a comment naming a sibling test as covering some
half of a problem drifts silently the moment that test is renamed, split or deleted
— and the next reader trusts it, decides the half is handled, and moves on.

Not hypothetical here. Two claims of exactly this shape were wrong in one session:
a test docstring saying a consensus rule was "verified against upstream
Radiant-Core at the commit this repo vendors" while the file defining that rule was
NOT among the vendored sources, and a scanner docstring naming a parity sweep as
covering the half it could not see. Both read as diligence. Both were false.

WHAT THIS CATCHES AND WHAT IT DOES NOT. It resolves the NAME: a claim pointing at
something that does not exist is unambiguously false and is caught here mechanically.
It cannot judge whether the named test actually covers what the prose says it covers
— that needs a person, and it is how the parity-sweep claim survived. A guard with a
stated edge beats one presented as complete.
"""

from __future__ import annotations

import ast
import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Prose that points at a named test as evidence.
_CLAIM = re.compile(
    r"(?:covered by|tested by|pinned by|asserted by|proven by|guarded by|verified by|see)"
    r"\s+`?((?:test_|Test)[A-Za-z0-9_]+)",
    re.IGNORECASE,
)


def _defined_names() -> set[str]:
    """Every test module, class and function name that exists, from the AST.

    Derived rather than listed: a hand-kept roster of what exists is the artifact
    this whole class of bug is made of.
    """
    names = {"tests"}  # bare `tests/` directory references
    for path in _ROOT.joinpath("tests").rglob("*.py"):
        names.add(path.stem)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError:  # pragma: no cover - a broken test file fails elsewhere
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                names.add(node.name)
    return names


def _claims() -> list[tuple[str, str, str]]:
    out = []
    for path in list(_ROOT.joinpath("tests").rglob("*.py")) + list(_ROOT.joinpath("src").rglob("*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue  # this module quotes the pattern it searches for
        text = path.read_text(encoding="utf-8")
        for match in _CLAIM.finditer(text):
            line = text[: match.start()].count("\n") + 1
            out.append((f"{path.relative_to(_ROOT)}:{line}", match.group(1), text.split("\n")[line - 1].strip()))
    return out


def test_every_named_coverage_claim_resolves() -> None:
    defined = _defined_names()
    unresolved = [
        f"{loc}: prose names {name!r}, which is not a test module, class or function\n      {ctx[:110]}"
        for loc, name, ctx in _claims()
        if name not in defined
    ]
    assert not unresolved, (
        "a docstring or comment points at a test that does not exist, so a reader is "
        "being told a case is covered when nothing named covers it:\n  " + "\n  ".join(unresolved)
    )


def test_the_scan_is_not_vacuous() -> None:
    """The pass condition and the scanned-nothing condition are the same output, so
    this asserts there was something to check. Measured at 30 claims when written."""
    claims = _claims()
    assert len(claims) > 15, f"only {len(claims)} coverage claims found — has the pattern or the tree moved?"
    defined = _defined_names()
    assert len(defined) > 500, f"only {len(defined)} defined names parsed — the AST walk is not reaching the suite"


def test_the_pattern_actually_matches_the_shape_it_describes() -> None:
    """Non-vacuity for the regex itself: a pattern that matched nothing would make
    the check above pass forever while asserting nothing."""
    assert _CLAIM.search("that half is covered by `test_some_sweep_name`")
    assert _CLAIM.search("Proven by test_a_high_s_signature_is_refused")
    assert not _CLAIM.search("covered by consensus"), "must not fire on prose naming no test"

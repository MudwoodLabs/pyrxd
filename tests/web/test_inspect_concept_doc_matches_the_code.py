"""Keep ``docs/concepts/glyph-inspect-tool.md`` anchored to the code it describes.

That page is the public explanation of what the inspect tool proves and what it
does not, so its wrong sentences are the expensive kind. Three classes of drift
had all shipped in it at once, and all three are mechanically checkable:

1. A cited source path that no longer exists.
2. A symbol attributed to the wrong file — ``inspect_cmd`` and
   ``_render_script_human`` were cited three times against
   ``src/pyrxd/cli/glyph_cmds.py`` after both moved to
   ``src/pyrxd/cli/glyph_inspect.py``. The *path* still existed, so a link
   checker saw nothing; only the pairing was wrong.
3. A stale list of the script ``type`` values the classifier emits. The page
   carried two such lists, a short one and a long one, and the addition of
   ``op_return-msg`` / ``op_return-hashmark-v*`` left both behind.

This is a DETECT-level mechanism. It cannot prove the prose is true — no test
evaluates claims — only that these three specific couplings have not come
apart again.

Every set here is DERIVED, never hand-typed: the link set and the symbol set
come from the document, and the type set is AST-extracted from the classifier.
Each check asserts its own set is non-empty first, because a scanner that runs
over nothing passes exactly like a scanner that runs over everything.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
DOC = _ROOT / "docs" / "concepts" / "glyph-inspect-tool.md"
CLASSIFIER = _ROOT / "src" / "pyrxd" / "glyph" / "_inspect_core.py"
SRC = _ROOT / "src"

#: ``[text](../../some/path)`` — repo-relative links only. In-page anchors,
#: sibling ``.md`` links and ``https://`` URLs are somebody else's problem.
_REPO_LINK_RE = re.compile(r"\]\((\.\./\.\./[^)#\s]+)\)")

#: A backticked BARE Python identifier: no dots (that is a module path), no
#: parens, no ``=``. ``_render_script_human`` matches; ``pyrxd.glyph.inspect``,
#: ``type=ft`` and ``glyph_group.add_command(inspect_cmd)`` do not.
_BACKTICK_IDENT_RE = re.compile(r"`(_?[A-Za-z][A-Za-z0-9_]*)`")

#: Start of a markdown list item — a numbered footgun or a bullet. Blocks are
#: split here as well as on blank lines so a list of source-of-truth bullets
#: does not merge every path in it into one scope.
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*]\s|\d+\.\s)")


def _doc_text() -> str:
    return DOC.read_text(encoding="utf-8")


def _blocks(text: str) -> list[str]:
    """Split *text* into scopes: paragraphs, each list item its own scope."""
    blocks: list[list[str]] = [[]]
    for line in text.splitlines():
        if not line.strip() or _LIST_ITEM_RE.match(line):
            blocks.append([])
        blocks[-1].append(line)
    return ["\n".join(b) for b in blocks if any(x.strip() for x in b)]


def _definitions_under_src() -> dict[str, set[Path]]:
    """Map every ``def``/``class`` name under ``src/`` to the files defining it."""
    index: dict[str, set[Path]] = {}
    for path in SRC.rglob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover — a broken tree is another test's job
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                index.setdefault(node.name, set()).add(path)
    return index


def _emitted_script_types() -> tuple[set[str], set[str]]:
    """AST-extract every value the classifier assigns to a ``"type"`` key.

    Returns ``(exact, prefixes)``. Two of the assignments are f-strings —
    ``f"p2pkh-{kind}"`` and ``f"op_return-hashmark-v{version}"`` — whose full
    value is not a literal, so their constant head is returned as a prefix.
    Deriving the set this way is the point: a hand-kept list is exactly what
    went stale, and would go stale again on the next new shape.
    """
    tree = ast.parse(CLASSIFIER.read_text(encoding="utf-8"))
    exact: set[str] = set()
    prefixes: set[str] = set()

    def record(node: ast.expr) -> None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            exact.add(node.value)
        elif isinstance(node, ast.JoinedStr):
            head = node.values[0] if node.values else None
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                prefixes.add(head.value)

    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "type":
                    record(value)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "type"
                ):
                    record(node.value)
    return exact, prefixes


def test_the_doc_is_where_this_test_thinks_it_is() -> None:
    assert DOC.is_file(), f"{DOC} moved; every check below would silently pass"
    assert CLASSIFIER.is_file(), f"{CLASSIFIER} moved"


class TestCitedPathsResolve:
    def test_every_repo_relative_link_target_exists(self) -> None:
        links = _REPO_LINK_RE.findall(_doc_text())
        assert len(links) >= 8, f"only {len(links)} repo-relative links found — did the syntax change?"
        missing = sorted({rel for rel in links if not (DOC.parent / rel).resolve().exists()})
        assert not missing, f"the doc links to paths that do not exist: {missing}"


class TestSymbolsAreAttributedToTheirRealHome:
    """A backticked symbol next to a ``.py`` link must live in one of those files.

    This is the check the path-existence test above cannot make. Both files in
    the ``inspect_cmd`` mix-up existed; what was wrong was the pairing, and a
    reader following the link found no such function.
    """

    def test_named_symbols_live_in_the_files_cited_beside_them(self) -> None:
        defined = _definitions_under_src()
        checked: list[tuple[str, str]] = []
        wrong: list[str] = []

        for block in _blocks(_doc_text()):
            py_links = [rel for rel in _REPO_LINK_RE.findall(block) if rel.endswith(".py")]
            cited = [(DOC.parent / rel).resolve() for rel in py_links]
            cited = [p for p in cited if SRC in p.parents]
            if not cited:
                continue
            for name in set(_BACKTICK_IDENT_RE.findall(block)):
                homes = defined.get(name)
                # Only unambiguous names: a symbol defined in several modules
                # says nothing about which file the sentence meant.
                if not homes or len(homes) != 1:
                    continue
                home = next(iter(homes))
                checked.append((name, home.relative_to(_ROOT).as_posix()))
                if home not in cited:
                    wrong.append(
                        f"`{name}` is defined in {home.relative_to(_ROOT).as_posix()}, "
                        f"but the doc names it beside "
                        f"{[p.relative_to(_ROOT).as_posix() for p in cited]}"
                    )

        assert len(checked) >= 2, (
            f"only {len(checked)} symbol/path pairings were checked ({checked}) — "
            "this scan has stopped seeing the doc's structure, so a wrong "
            "attribution would pass unnoticed"
        )
        assert not wrong, "\n".join(wrong)


class TestEveryEmittedScriptTypeIsDocumented:
    """The page must name every ``type`` the classifier can hand a reader.

    An undocumented value is not cosmetic: a consumer switching on ``type ==
    "op_return"`` silently misses ``op_return-msg``, and a reader checking the
    page for what they might see is told the wrong set.
    """

    def test_the_extraction_found_a_plausible_set(self) -> None:
        exact, prefixes = _emitted_script_types()
        assert len(exact) >= 12, f"only extracted {sorted(exact)} — the AST shape moved"
        assert prefixes, "expected at least the f-string type assignments"

    @pytest.mark.parametrize("name", sorted(_emitted_script_types()[0]))
    def test_exact_type_appears_in_the_doc(self, name: str) -> None:
        pattern = re.compile(r"`(?:type=)?" + re.escape(name) + r"`")
        assert pattern.search(_doc_text()), (
            f"the classifier can emit type={name!r}, and the concept doc never mentions it"
        )

    @pytest.mark.parametrize("prefix", sorted(_emitted_script_types()[1]))
    def test_fstring_type_family_appears_in_the_doc(self, prefix: str) -> None:
        pattern = re.compile(r"`(?:type=)?" + re.escape(prefix) + r"[A-Za-z0-9_-]+`")
        assert pattern.search(_doc_text()), (
            f"the classifier emits types starting {prefix!r}, and the concept doc names none of them"
        )

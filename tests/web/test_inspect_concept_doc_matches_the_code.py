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


class TestEveryAttestationOutcomeIsDocumented:
    """The same rule, one level down, on the set that actually caught someone out.

    The page listed the attestation outcomes as "``valid``, ``invalid_signature``,
    or ``not_attested``" — a hand-typed set of three, missing ``unverifiable``, which
    is the outcome EVERY v2 record produces in the browser. The sibling check above
    derives the script ``type`` values from the classifier and so could not see this:
    it is structural about one enumeration and was silent about the other.

    So this derives the set from :class:`AttestationOutcome` itself. A future outcome
    that the page does not name fails here rather than leaving a reader with a list
    that quietly stopped being complete — and the omission is not cosmetic, because
    a reader who has never heard of ``unverifiable`` reads a withheld verdict as a
    decided one.
    """

    @staticmethod
    def _outcomes() -> set[str]:
        from pyrxd.script.hashmark import AttestationOutcome

        return {member.value for member in AttestationOutcome}

    def test_the_enumeration_is_not_empty(self) -> None:
        """A scanner that runs over nothing passes exactly like one that runs over
        everything."""
        outcomes = self._outcomes()
        assert len(outcomes) >= 4, f"only derived {sorted(outcomes)} — the enum moved"

    @staticmethod
    def _the_list() -> str:
        """The paragraph that ENUMERATES the outcomes, not the whole page.

        Scoped deliberately. A page-wide search is satisfied by any mention anywhere,
        so once the page gained a paragraph explaining ``unverifiable``, deleting the
        word from the enumeration stopped failing — measured, by planting exactly
        that. The defect being guarded is a reader handed an incomplete LIST, and the
        list is the unit to look in.
        """
        anchor = "`hashmark.attestation` as"
        blocks = [b for b in _doc_text().split("\n\n") if anchor in b]
        assert len(blocks) == 1, (
            f"expected exactly one paragraph containing {anchor!r}, found {len(blocks)}. "
            f"If the enumeration moved or was reworded, point this anchor at it — do NOT "
            f"widen the search back to the whole page, which is what made this vacuous."
        )
        return blocks[0]

    @pytest.mark.parametrize("outcome", sorted(_outcomes.__func__()))
    def test_the_outcome_is_named_in_the_list(self, outcome: str) -> None:
        pattern = re.compile(r"`" + re.escape(outcome) + r"`")
        assert pattern.search(self._the_list()), (
            f"verify_attestation can return {outcome!r} and the concept doc's list of "
            f"outcomes does not include it. That page is the public explanation of what "
            f"this tool proves; a list missing one is a reader told the wrong set.\n"
            f"--- the list ---\n{self._the_list()}"
        )


_STATIC = _ROOT / "docs" / "inspect_static"
_DOCS_WORKFLOW = _ROOT / ".github" / "workflows" / "docs.yml"


def _flat(text: str) -> str:
    """Hard-wrapped prose, searchable: a phrase that wraps is invisible to a line grep."""
    return " ".join(text.split())


def _section(heading: str) -> str:
    """One ``## `` section of the doc, up to the next one."""
    text = _doc_text()
    start = text.index(heading)
    end = text.find("\n## ", start + len(heading))
    return text[start : end if end != -1 else len(text)]


class TestTheIntegrityStoryIsTheOneTheCodeTells:
    """Three sentences about the browser pages' integrity checks had drifted from the code: the
    doc's table of what is SHA-256 checked omitted the two curve files the page checks; the doc
    still said HashMark decoding was CLI-only, after both pages gained a curve; and
    ``shared.js`` claimed its check held "even if the GitHub Pages deploy is compromised",
    which the doc's own section on the manifest says it does not."""

    @staticmethod
    def _page_files_the_manifest_pins() -> set[str]:
        """DERIVED from the docs build: every page file whose digest ``docs.yml`` writes into
        the manifest (``sha256sum ../<file>`` from the wheels directory). The wheels are named
        by variable there and described by name in the table, so they are not in this set."""
        found = set(re.findall(r"sha256sum \.\./([\w./-]+)", _DOCS_WORKFLOW.read_text(encoding="utf-8")))
        return {Path(p).name for p in found}

    def test_the_derivation_finds_the_files_it_must(self) -> None:
        files = self._page_files_the_manifest_pins()
        assert {"glue.py", "secp256k1-bridge.js", "noble-secp256k1.js"} <= files, (
            f"derived only {sorted(files)} from docs.yml — this scan is broken, not the doc"
        )

    def test_every_file_the_manifest_pins_is_in_the_integrity_table(self) -> None:
        table = _section("## Browser variant: install-time integrity")
        missing = sorted(f for f in self._page_files_the_manifest_pins() if f not in table)
        assert not missing, f"the docs build SHA-256 pins {missing} and the integrity table never names them"

    def test_the_doc_does_not_call_hashmark_checking_cli_only_while_the_pages_install_a_curve(self) -> None:
        """A PHRASE PIN, reviewed rather than derived — but gated on the fact that makes it
        false: while some page hands the boot a curve, the doc must not say the browser cannot
        decode or check a HashMark."""
        pages_with_a_curve = [
            p for p in _STATIC.glob("*/*.js") if p.name != "shared.js" and "curveUrl:" in p.read_text(encoding="utf-8")
        ]
        assert pages_with_a_curve, "no page installs a curve — re-read the doc's HashMark section, then this test"
        flat = _flat(_doc_text())
        assert "HashMark decoding is a **CLI-only**" not in flat
        assert "a HashMark OP_RETURN fails to classify there" not in flat

    def test_no_comment_says_the_manifest_check_survives_a_compromised_deploy(self) -> None:
        """The manifest is served by the same deploy as the files it pins, so a compromised
        deploy rewrites both. The doc says so; the code's comments must not say the opposite.

        A PHRASE PIN on the two affirmative forms that shipped ("even if the GitHub Pages deploy
        is compromised", "Defends against a compromised GitHub Pages deploy"). Deliberately NOT
        a negation heuristic: "does NOT defend against a compromised deploy" is the correct
        sentence and says "defend", which neither pattern matches."""
        sources = sorted(_STATIC.glob("*/*.js")) + sorted(_STATIC.glob("*/*.html"))
        assert len(sources) >= 5, f"only {len(sources)} page sources found — this scan is broken"
        claim = re.compile(
            r"\bdefends against (a |the )?compromised (GitHub )?Pages deploy"
            r"|even if the (GitHub )?Pages deploy is compromised",
            re.IGNORECASE,
        )
        wrong = [
            f"{p.relative_to(_ROOT)}: {m.group(0)!r}"
            for p in sources
            for m in claim.finditer(_flat(p.read_text(encoding="utf-8")))
        ]
        assert not wrong, "these comments claim a defence the doc says does not exist:\n" + "\n".join(wrong)
        assert "does **not** defend the deployed origin against itself" in _flat(_doc_text())

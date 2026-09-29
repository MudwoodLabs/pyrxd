"""Every ``path/file.py:NNN`` citation in the published docs must land on real code.

The docs pin normative statements to source with a ``path:line`` citation — the
Glyph spec says so in its own §1 ("Each statement carries a citation of the form
``path:line``"), and the HTLC handshake format says it in its header. **Line
numbers shift on every insertion above them**, so those citations rot in total
silence, and the readers they rot for are second implementers: this project has
already shipped one security release (0.22.0) caused by a published artifact
teaching a stale rule.

Measured when this file was written, over the scanned set below: 347 citations,
282 of which name a file this repository contains. **60 of those landed on a
blank line** (none past end-of-file, and no cited file was missing), and 2 bare
basenames were ambiguous between two real files (``htlc_leg.py`` — ``btc_wallet``
and ``eth_wallet`` both have one; ``wallet.py`` — ``hd/wallet.py`` and
``wallet.py``). All were repaired in the commit that added this file; this test
is what keeps them repaired.

What this test proves
---------------------
For every citation naming a file this repo contains: the file exists, the cited
line numbers are within it, and they are not blank. And for every citation
written NEXT TO A CODE NAME, that the cited lines are that name's (the symbol
rule, below).

**What it does NOT prove — read this before trusting a green run.** It cannot
tell that a cited line says what the doc claims. A citation with no name beside
it that has drifted from ``build_ft_locking_script`` onto some *other* non-blank
line passes here. That failure mode is real and was the majority of the rot
found: of the 29 citations that named a uniquely-defined function or class on
their own doc line, **23 pointed outside that symbol's definition** while landing
on perfectly non-blank lines. The symbol rule closes that gap only where the doc
writes the name beside the citation in one of the forms below. This is a
DETECT-level floor, not a proof the citations are right. The structural fix is to
cite symbols rather than lines; see the note at the bottom of this module.

Scope
-----
Derived, not hand-kept: every tracked ``docs/**/*.md`` **except** the three dated
subtrees. ``docs/brainstorms/`` and ``docs/plans/`` are working drafts and
``docs/solutions/`` are incident records — a record that names a file as it stood
in May is not stale, it is a record. (The same split as
``tests/test_docs_are_current.py`` and
``tests/test_protocol_lock_ordering_docs_are_current.py``, but stated as an
EXCLUDE list so a new docs subdirectory is scanned by default rather than
silently unscanned.) The symbol rule reads ``docs/solutions/`` too; see below.

"Tracked" means what ``git ls-files`` lists, because that is what CI checks out.
Reading the filesystem instead let an untracked local draft fail the gate on one
machine and never in CI. Where there is no git work tree (a ``git archive``
export, an unpacked sdist) the files on disk are read instead; see
``_tracked_files``.

The symbol rule
---------------
A citation written next to a code name says where that name is, so it can be
checked mechanically. ``symbol_named_by`` reads exactly these forms, with
``CITE`` a citation filling its own backtick span:

* ```name` (`CITE`)``, ```name`, `CITE```, ```name` at `CITE```;
* ```CITE` (`name` …)``;
* ```CITE name``` (the name inside the citation's own backticks).

``name`` is an identifier, optionally dotted (``Class.method``) or written with
``()``. A name that ends or starts a LIST of names (```a`, `b` and `c` (`CITE`)``)
is not taken, because the citation then speaks for the list; a backticked file
name (``htlc_spend.py``) is not a symbol. ``check_symbol`` then applies one of
two rules. If the cited file is Python and defines the name (``def``, ``class``,
or a module- or class-level assignment, found with ``ast``), the cited lines must
overlap that definition. Otherwise (the vendored C++, or a name the file only
uses) the name must appear in the cited lines.

"Overlap", not "the ``def`` line is cited", because the docs deliberately cite
lines inside a definition: ``holder_hash``'s ``rxd`` branch, the field lines of
``BtcHtlcLocator``. Measured on the docs as they stood when this rule was added,
requiring the ``def`` line would have refused 5 such citations, each of which
lands on the lines its sentence describes.

The list exception exists for the same reason: 3 citations name a list, and one
of them (``WAVE_TREASURY_ADDRESS_DEFAULT`` and ``wave_name_price``, cited at
``:65`` and ``:73-86``) is correct but fails if read as naming its last member.

``docs/solutions/`` is read by this rule though not by the blank-line gate. A
record may cite a file as it stood in May, but a citation that names its own
subject says where that subject IS, and people and agents read these records as
current guidance. Where the named thing no longer exists, the fix is to say so in
the record, not to point the citation somewhere else.

Measured when the rule was added (the figures further up were measured for the
blank-line gate when it was written): 37 symbol citations resolved to a file
here, 30 in the published docs and 7 in ``docs/solutions/``. Fifteen failed: 9
in the published docs and 6 in ``docs/solutions/``, one of those on a blank line
that the blank-line gate never saw because it does not read that subtree. Another
14 could not be resolved to a file here (Photonic Wallet sources, mostly) and were
not checked. All 15 were fixed in the change that added the rule. Two needed more
than a new line number: ``pre_btc_lock_gate`` is not a function in pyrxd, and
Glyph spec §16.4 described a ``COMMIT_SCRIPT_RE`` that 0.25.0 had changed.

What the symbol rule cannot see: a citation with no name beside it; a citation
for a list of names; a continuation citation with no file
(```REF_OPCODES` (`:1075`)``), whose file is whichever one the prose last named;
a citation sharing its backticks with more ranges (```x.py:10, 40-41```); a C++
citation that lands on a call rather than the definition, since the occurrence
rule accepts both; and a symbol citation in ``docs/solutions/`` naming a file
this repo does not contain, which is not held to the out-of-scope inventory
below. In the other direction, it refuses a citation that deliberately points at
a USE of a name the same Python file defines: cite the definition, or write the
citation so it does not sit directly beside the name.

Resolution, and why bare ``file.py:N`` is checked too
-----------------------------------------------------
A citation resolves when **exactly one** file in the repo has it as a trailing
path suffix. ``src/pyrxd/glyph/script.py``, ``glyph/script.py`` and bare
``script.py`` all resolve to the same file when that file is the only match.

That is a proof of uniqueness, not a guess. The distinction matters: an earlier
ad-hoc pass at this problem resolved bare ``types.py`` by taking the *first*
match under ``src/``, and reported phantom failures against the wrong file.
Here, more than one candidate is a **failure**, not a coin toss — the fix is to
write enough of the path to disambiguate. So a bare basename that becomes
ambiguous later (someone adds a second ``proof.py``) fails loudly instead of
quietly resolving to the wrong file or dropping out of coverage.

Radiant Core citations resolve through the vendored pin
-------------------------------------------------------
``tests/vendor/radiant_core/README.md`` already establishes that every
Radiant-Core line citation in this repo is anchored to the tag in
``MANIFEST.json``, and the vendored files are verbatim copies at that tag. So a
citation like ``src/validation.h:82`` is checked against the vendored copy,
mapped through the manifest's own ``upstream_path`` fields — derived from the
manifest, never a second hand-written table. When
``scripts/refresh_radiant_core_vendor.py`` moves the pin, this test is what
reports the citations the move invalidated.
"""

from __future__ import annotations

import ast
import functools
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: Dated working space. See the Scope note in the module docstring.
_DATED_SUBTREES = frozenset({"brainstorms", "plans", "solutions"})

#: The dated subtree the SYMBOL rule reads anyway. See "The symbol rule" in the module docstring.
_SYMBOL_RULE_ALSO_READS = frozenset({"solutions"})

_VENDOR_ROOT = _ROOT / "tests" / "vendor" / "radiant_core"
_MANIFEST = _VENDOR_ROOT / "MANIFEST.json"
_RXINDEXER_ROOT = _ROOT / "tests" / "vendor" / "rxindexer"
_RXINDEXER_MANIFEST = _RXINDEXER_ROOT / "MANIFEST.json"

#: Directories that hold no repository source. Pruning too FEW of these can only
#: add candidates, i.e. turn a resolvable citation into a loud "ambiguous"
#: failure — it can never make a rotted citation pass. The prune list is
#: therefore safe to be incomplete, which is the opposite of the usual
#: hand-kept-set hazard.
_PRUNED_DIR_NAMES = frozenset({"__pycache__", "node_modules"})
_PRUNED_DIRS = (_ROOT / "docs" / "_build",)

#: A citation: a file name with at least one extension, then ``:line`` or
#: ``:line-line``. The leading lookbehind stops the match from starting in the
#: middle of a longer identifier — without it, ``[a-z_]+\.py`` matched
#: ``_deploy.py`` inside the real filename ``dmint_v1_deploy.py`` and invented a
#: missing file. The extension must start with a letter so a bare IPv4 address
#: (``127.0.0.1:7332``) is not read as a citation to a file called ``0.1``.
_CITE_RE = re.compile(r"(?<![A-Za-z0-9_./-])([A-Za-z0-9_][A-Za-z0-9_./-]*\.([A-Za-z][A-Za-z0-9]*)):(\d+)(?:-(\d+))?")

#: Citations that name a file this repository does not contain, with why.
#:
#: This is the one JUDGEMENT CALL in the test, so it is pinned by MEMBERSHIP
#: rather than trusted as prose: ``test_the_out_of_scope_inventory_is_exact``
#: asserts this set equals exactly the set of unresolvable citations in the docs
#: today, in BOTH directions. A new unresolvable citation fails (that is how a
#: renamed local file gets caught rather than silently leaving scope), and an
#: entry that no doc cites any more fails (that is how a stale exemption gets
#: deleted rather than inherited). The same test also asserts that nothing listed
#: here actually resolves, so an entry can never be used to silence a checkable
#: citation.
#:
#: Reasons are grouped rather than repeated per line; the pin is on the keys.
_OUT_OF_SCOPE: dict[str, str] = {
    # Radiant Core, at paths not vendored under tests/vendor/radiant_core/.
    # Anchored to MANIFEST.json's tag like every other Radiant-Core citation here
    # (tests/vendor/radiant_core/README.md), but with no local copy to check against.
    "Radiant-Core/src/chainparams.cpp": "Radiant Core, not vendored",
    "feature_swap.py": "Radiant Core, not vendored",
    "src/index/swapindex.cpp": "Radiant Core, not vendored",
    "src/miner.cpp": "Radiant Core, not vendored",
    "src/policy/policy.cpp": "Radiant Core, not vendored",
    "src/rpc/swap.cpp": "Radiant Core, not vendored",
    "src/script/sighashtype.h": "Radiant Core, not vendored",
    "swapindex.cpp": "Radiant Core, not vendored",
    "test/functional/feature_swap.py": "Radiant Core, not vendored",
    # Photonic Wallet (TypeScript). A separate repository; nothing here can
    # resolve or check these, and their line numbers are not anchored at all —
    # see the honesty note that goes with them in the research docs.
    "Swap.tsx": "Photonic Wallet",
    "mint.ts": "Photonic Wallet",
    "packages/app/src/electrum/worker/NFT.ts": "Photonic Wallet",
    "packages/app/src/pages/Mint.tsx": "Photonic Wallet",
    "packages/app/src/swapBroadcast.ts": "Photonic Wallet",
    "packages/cli/src/schemas.ts": "Photonic Wallet",
    "packages/lib/src/__tests__/protocols.test.ts": "Photonic Wallet",
    "packages/lib/src/mint.ts": "Photonic Wallet",
    "packages/lib/src/protocols.ts": "Photonic Wallet",
    "packages/lib/src/script.ts": "Photonic Wallet",
    "packages/lib/src/token.ts": "Photonic Wallet",
    "packages/lib/src/transfer.tsx": "Photonic Wallet",
    "packages/lib/src/types.ts": "Photonic Wallet",
    "powmint.rxd": "Photonic Wallet",
    "script.ts": "Photonic Wallet",
    "swapBroadcast.ts": "Photonic Wallet",
    "token.ts": "Photonic Wallet",
    "tx.ts": "Photonic Wallet",
    "types.ts": "Photonic Wallet",
    "packages/lib/src/wave.ts": "Photonic Wallet",
    # The WAVE register page, which pays the registration fee; digest-pinned in
    # tests/fixtures/photonic_upstream_pin.json at becf41a7.
    "packages/app/src/pages/WaveRegister.tsx": "Photonic Wallet",
    # Radiant-Core/RXinDexer, the indexer that registers WAVE claims. glyph_index.py and
    # glyph_api.py are not vendored (wave_index.py and lib/glyph.py are, under
    # tests/vendor/rxindexer/, and resolve through _upstream_index); both are digest-pinned in
    # tests/fixtures/rxindexer_upstream_pin.json and watched by
    # scripts/check_photonic_drift.py --target rxindexer.
    "electrumx/server/glyph_api.py": "Radiant-Core/RXinDexer, pinned by digest",
    "electrumx/server/glyph_index.py": "Radiant-Core/RXinDexer, pinned by digest",
    # Radiant-Core/WAVE-Protocol, the WAVE protocol description (3-63 character names).
    "ANNOUNCEMENT.md": "Radiant-Core/WAVE-Protocol",
    # Not a citation at all: an ElectrumX endpoint, host:port. Listed rather than
    # filtered out by a cleverer regex, because a rule that silently drops things
    # is a rule nobody reviews.
    "electrumx.radiant4people.com": "an ElectrumX host:port, not a file",
}

#: Non-vacuity floors. Measured when this file was written: 95 docs, 347
#: citations, 282 resolved. The floors sit well below those so ordinary doc churn
#: does not trip them, and well above zero so a broken regex, a moved docs tree,
#: or an empty scan cannot pass as a clean run. A structural check whose SET is
#: empty is indistinguishable from a passing one in the output.
_MIN_DOCS = 50
_MIN_CITATIONS = 200
_MIN_RESOLVED = 180


@dataclass(frozen=True)
class Citation:
    """One ``target:start[-end]`` occurrence, and where in the docs it was written."""

    doc: str
    doc_line: int
    text: str
    target: str
    start: int
    end: int | None
    #: The code name written next to this citation, when it is written in one of the forms
    #: ``symbol_named_by`` recognises. ``None`` for a citation that names no symbol.
    symbol: str | None = None

    @property
    def where(self) -> str:
        return f"{self.doc}:{self.doc_line}"


def _tracked_files(root: Path) -> list[str] | None:
    """The files git tracks under *root*, repo-relative; ``None`` if *root* is not a git work tree.

    What CI checks out is the tracked set, so that is what this test reads. Walking the
    filesystem instead let an untracked local draft (a ``docs/design/`` note, a scratch
    ``proof.py``) fail the gate, or make a bare basename ambiguous, on one machine and never in
    CI. ``None`` sends the caller to the filesystem walk: in a ``git archive`` export or an
    unpacked sdist the files on disk ARE the tracked set, and anywhere else the walk sees a
    superset, which can only add citations to check and candidates to disambiguate. Neither
    direction hides a rotted citation.
    """
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:  # no git on PATH
        return None
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != root.resolve():
        return None
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
    return [p for p in listed.decode("utf-8").split("\0") if p]


def _walked_files(root: Path) -> list[str]:
    """Every file under *root*, for when there is no git work tree to ask. See ``_tracked_files``.

    Hidden and ``_PRUNED_DIR_NAMES`` directories are not descended into, so a local
    ``.venv`` costs nothing here; ``_repo_files`` applies the same pruning to either listing.
    """
    out: list[str] = []
    stack = [root]
    while stack:
        directory = stack.pop()
        for entry in directory.iterdir():
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if not (entry.name.startswith(".") or entry.name in _PRUNED_DIR_NAMES):
                    stack.append(entry)
            elif entry.is_file():
                out.append(entry.relative_to(root).as_posix())
    return out


def _repo_files() -> list[str]:
    """Every file in the checkout, as a repo-relative posix path.

    Tracked files when git can say which those are, else every file on disk. Hidden
    directories are pruned either way, which is what keeps a local ``.venv`` (and its
    thousands of same-named modules) out of the candidate set when there is no index to
    consult.
    """
    listed = _tracked_files(_ROOT)
    if listed is None:
        listed = _walked_files(_ROOT)
    pruned = {d.relative_to(_ROOT).as_posix() for d in _PRUNED_DIRS}
    out: list[str] = []
    for rel in listed:
        dirs = rel.split("/")[:-1]
        if any(d.startswith(".") or d in _PRUNED_DIR_NAMES for d in dirs):
            continue
        if any(rel.startswith(p + "/") for p in pruned):
            continue
        path = _ROOT / rel
        if path.is_symlink() or not path.is_file():  # a tracked file deleted locally, or a submodule
            continue
        out.append(rel)
    return out


def _docs(subtrees_also_read: frozenset[str] = frozenset()) -> list[str]:
    """``docs/**/*.md`` minus the dated subtrees, plus any of those named in *subtrees_also_read*."""
    out = []
    for rel in _repo_files():
        parts = rel.split("/")
        if parts[0] != "docs" or len(parts) < 2 or not rel.endswith(".md"):
            continue
        if len(parts) > 2 and parts[1] in _DATED_SUBTREES and parts[1] not in subtrees_also_read:
            continue
        out.append(rel)
    return sorted(out)


def _scanned_docs() -> list[str]:
    return _docs()


def _suffix_index(files: list[str]) -> dict[str, list[str]]:
    """Map every trailing path suffix of every file to the files that carry it."""
    index: dict[str, list[str]] = {}
    for path in files:
        parts = path.split("/")
        for i in range(len(parts)):
            index.setdefault("/".join(parts[i:]), []).append(path)
    return index


def _upstream_index() -> dict[str, str]:
    """Upstream path -> the vendored verbatim copy of it, for every vendored upstream.

    Radiant Core through its manifest's ``upstream_path`` fields; RXinDexer
    (``tests/vendor/rxindexer/``, pinned at the commit its manifest and
    ``tests/fixtures/rxindexer_upstream_pin.json`` name), whose files sit at their upstream
    paths. Derived from the vendor manifests, so a file added to or dropped from either vendor
    set changes this map without anyone editing it.
    """
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    index = {
        meta["upstream_path"]: (_VENDOR_ROOT.relative_to(_ROOT) / local).as_posix()
        for local, meta in manifest["files"].items()
    }
    rxindexer = json.loads(_RXINDEXER_MANIFEST.read_text(encoding="utf-8"))
    for upstream_path in rxindexer["files"]:
        index[upstream_path] = (_RXINDEXER_ROOT.relative_to(_ROOT) / upstream_path).as_posix()
    return index


def citations_in(doc: str, text: str) -> list[Citation]:
    """Every citation in one document's *text*, with the symbol it names where it names one.

    Read over the whole text rather than line by line, so a name and its citation that a
    hard wrap put on different lines are still seen together. ``_CITE_RE`` cannot itself
    span a newline, so it finds exactly what a line-by-line pass would.
    """
    found: list[Citation] = []
    for match in _CITE_RE.finditer(text):
        found.append(
            Citation(
                doc=doc,
                doc_line=text.count("\n", 0, match.start()) + 1,
                text=match.group(0),
                target=match.group(1),
                start=int(match.group(3)),
                end=int(match.group(4)) if match.group(4) else None,
                symbol=symbol_named_by(text, match.start(), match.end()),
            )
        )
    return found


def _citations(docs: list[str] | None = None) -> list[Citation]:
    found: list[Citation] = []
    for rel in _scanned_docs() if docs is None else docs:
        found.extend(citations_in(rel, (_ROOT / rel).read_text(encoding="utf-8")))
    return found


def _candidates(target: str, suffixes: dict[str, list[str]], upstream: dict[str, str]) -> list[str]:
    """Files this citation could mean. Empty = not in this repo; >1 = ambiguous."""
    local = suffixes.get(target)
    if local:
        return sorted(local)
    return sorted({path for up, path in upstream.items() if target == up or target.endswith("/" + up)})


def check_citation(cit: Citation, candidates: list[str], source_lines: list[str] | None) -> str | None:
    """Return a problem description for *cit*, or ``None`` if it lands on real code.

    Split out from the scan so the failure modes can be exercised directly against
    synthetic inputs — see ``TestTheCheckerFires``. A guard whose failure branch is
    never executed is a guard nobody has seen work.
    """
    if len(candidates) > 1:
        return (
            f"{cit.where}: `{cit.text}` is ambiguous — {len(candidates)} files match it "
            f"({', '.join(candidates)}). Write enough of the path to name one."
        )
    assert source_lines is not None, "a resolved citation must be given the file's lines"
    path = candidates[0]
    total = len(source_lines)
    numbers = [cit.start] if cit.end is None else [cit.start, cit.end]
    if cit.end is not None and cit.end < cit.start:
        return f"{cit.where}: `{cit.text}` is a backwards range."
    for number in numbers:
        if number < 1 or number > total:
            return f"{cit.where}: `{cit.text}` points past the end of {path} ({total} lines)."
    for number in numbers:
        if not source_lines[number - 1].strip():
            return (
                f"{cit.where}: `{cit.text}` points at BLANK line {number} of {path}. "
                "The code it named has moved; find it and re-cite it."
            )
    return None


# ---------------------------------------------------------------------------
# The symbol rule: a citation written next to a code name must land on that name
# ---------------------------------------------------------------------------

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_DOTTED = rf"(?P<name>{_IDENT}(?:\.{_IDENT})*)(?:\(\))?"
#: A code name that fills its own backtick span: ``name``, ``Class.method``, ``name()``.
_NAME = rf"`{_DOTTED}`"

#: How far either side of a citation to look for its name. Longer than any name and joiner.
_WINDOW = 200

#: The name comes first, and the citation is a backtick span of its own right after it:
#: ``name`` (``path:N``  |  ``name``, ``path:N``  |  ``name`` at ``path:N``.
#: Matched against the text up to and including the citation's opening backtick.
_NAME_THEN_CITE = re.compile(rf"{_NAME}(?:\s*\(\s*|,\s*|\s+at\s+)`\Z")
#: The citation comes first and opens a parenthetical that starts with the name:
#: ``path:N`` (``name``.  Matched from the citation's closing backtick.
_CITE_THEN_NAME = re.compile(rf"\A`\s*\(\s*{_NAME}")
#: The name shares the citation's backticks: ``path:N name``.  Matched from the citation's end.
_CITE_WITH_NAME = re.compile(rf"\A[ \t]+{_DOTTED}`")

#: The name is the LAST of a list — ``a``, ``b`` and (ETH) ``c`` (``path:N``) — so the
#: citation speaks for the list, not for ``c``. Only a joiner directly after another
#: backtick span counts, with at most one short parenthetical between it and the name, so
#: an ordinary word before the name ("the shared ``c``") never reads as a list.
_LIST_BEFORE = re.compile(r"`\s*(?:,|\band|\bor)\s*(?:\([^()`\n]*\)\s*)?\Z")
#: The mirror, for a name that is the FIRST of a list: ``path:N`` (``a``, ``b``).
_LIST_AFTER = re.compile(r"\A\s*(?:,|and\b|or\b)\s*`")


def symbol_named_by(text: str, start: int, end: int) -> str | None:
    """The code name written next to the citation at ``text[start:end]``, or ``None``.

    These forms, and only these, name a symbol (``CITE`` is the citation):

    * ```name` (`CITE`)``, ```name`, `CITE```, ```name` at `CITE``` — the citation fills a
      backtick span of its own, directly after the name;
    * ```CITE` (`name` …)`` — the citation fills its own span and the parenthetical after it
      opens with the name;
    * ```CITE name``` — the name inside the citation's own backticks.

    A name that ends or starts a list of names is not taken: the citation then belongs to
    the list, and a rule that picked one member would refuse citations that are correct.
    Whitespace between the parts may include a newline, so a hard wrap hides nothing.
    """
    if start == 0 or text[start - 1] != "`":
        return None
    after = text[end : end + _WINDOW]
    within = _CITE_WITH_NAME.match(after)
    if within:
        return within.group("name")
    if not after.startswith("`"):
        return None  # the citation shares its backticks with something other than a name
    before = text[max(0, start - _WINDOW) : start]
    first = _NAME_THEN_CITE.search(before)
    if first:
        name_at = start - len(before) + first.start()
        if _LIST_BEFORE.search(text[max(0, name_at - _WINDOW) : name_at]):
            return None
        return first.group("name")
    second = _CITE_THEN_NAME.match(after)
    if second:
        if _LIST_AFTER.match(after[second.end() :]):
            return None
        return second.group("name")
    return None


@dataclass(frozen=True)
class Definition:
    """One name a Python file binds, and the lines it spans (decorators included)."""

    qualname: str
    first: int
    last: int


@functools.cache
def python_definitions(source: str) -> tuple[Definition, ...]:
    """Every ``def``, ``async def`` and ``class`` in *source*, at any depth, and every ``name =``
    or ``name: T =`` at module or class level (a function's locals are not definitions).

    Qualified by the classes and functions around them, so ``NegotiatedTerms.to_dict`` and
    ``SwapRecord.to_dict`` stay apart. An ``import`` is deliberately NOT a definition: a
    citation to a module that merely uses an imported name is held to the occurrence rule,
    not told that the name "is defined" at its import line.
    """
    out: list[Definition] = []

    def visit(node: ast.AST, prefix: str, in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                first = min([d.lineno for d in child.decorator_list] + [child.lineno])
                out.append(Definition(prefix + child.name, first, child.end_lineno or child.lineno))
                is_function = not isinstance(child, ast.ClassDef)
                visit(child, f"{prefix}{child.name}.", in_function or is_function)
            elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                if in_function:
                    continue
                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                for target in targets:
                    for leaf in ast.walk(target):
                        if isinstance(leaf, ast.Name):
                            out.append(Definition(prefix + leaf.id, child.lineno, child.end_lineno or child.lineno))
            else:
                visit(child, prefix, in_function)

    visit(ast.parse(source), "", False)
    return tuple(out)


def check_symbol(cit: Citation, path: str, source: str) -> tuple[str, str | None]:
    """Return ``(rule, problem)`` for a citation that names ``cit.symbol``; ``problem`` is ``None`` if it holds.

    ``rule`` is which of the two applied:

    * ``"definition"`` — *path* is Python and defines the name (see ``python_definitions``;
      a dotted name must match the trailing parts of the qualified name). The cited lines
      must overlap one of those definitions, decorators through last line. Overlap rather
      than "the ``def`` line is cited" because the docs deliberately cite a branch inside a
      function (``holder_hash``'s ``rxd`` branch), and that is a correct citation.
    * ``"occurrence"`` — *path* is not Python (the vendored C++), or does not define the
      name (a dict key, a string value, an imported name). The name's last part must then
      appear as a whole word in the cited lines. This is weaker: it cannot tell a C++
      definition from a call.

    Split out from the scan so both rules can be exercised against synthetic inputs.
    """
    assert cit.symbol is not None, "only a citation that names a symbol has one to check"
    first, last = cit.start, cit.end if cit.end is not None else cit.start
    parts = cit.symbol.split(".")
    if path.endswith(".py"):
        defined = [d for d in python_definitions(source) if d.qualname.split(".")[-len(parts) :] == parts]
        if defined:
            if any(d.first <= last and first <= d.last for d in defined):
                return "definition", None
            spans = ", ".join(str(d.first) if d.first == d.last else f"{d.first}-{d.last}" for d in defined)
            return "definition", (
                f"{cit.where}: `{cit.symbol}` is cited at `{cit.text}`, but {path} defines it at "
                f"line(s) {spans}, and the cited lines are not inside it. Re-cite it where it is."
            )
    word = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(parts[-1])}(?![A-Za-z0-9_])")
    lines = source.splitlines()
    if any(word.search(line) for line in lines[first - 1 : last]):
        return "occurrence", None
    seen = [n for n, line in enumerate(lines, 1) if word.search(line)]
    if seen:
        where = ", ".join(map(str, seen[:5])) + (" …" if len(seen) > 5 else "")
        elsewhere = f"it does appear at line(s) {where}"
    else:
        elsewhere = (
            "it appears nowhere in that file. If it was removed or renamed, say so in the doc "
            "rather than pointing the citation somewhere else"
        )
    return "occurrence", (f"{cit.where}: `{cit.symbol}` does not appear in `{cit.text}` ({path}); {elsewhere}.")


def _is_symbol(name: str, suffixes: dict[str, list[str]], upstream: dict[str, str]) -> bool:
    """A backticked ``htlc_spend.py`` next to a citation names a FILE, not a symbol."""
    return "." not in name or not _candidates(name, suffixes, upstream)


@dataclass(frozen=True)
class SymbolScan:
    """What the symbol rule saw: the citations it checked, each with the rule applied, and
    the problems found. A citation whose file this repo does not contain is not checked."""

    checked: list[tuple[Citation, str]]
    problems: list[str]


def _symbol_scan() -> SymbolScan:
    suffixes = _suffix_index([f for f in _repo_files() if not f.startswith("tests/vendor/")])
    upstream = _upstream_index()
    sources: dict[str, str] = {}
    checked: list[tuple[Citation, str]] = []
    problems: list[str] = []
    for cit in _citations(_docs(_SYMBOL_RULE_ALSO_READS)):
        if cit.symbol is None or not _is_symbol(cit.symbol, suffixes, upstream):
            continue
        candidates = _candidates(cit.target, suffixes, upstream)
        if not candidates:
            continue
        lines = None
        if len(candidates) == 1:
            path = candidates[0]
            if path not in sources:
                sources[path] = (_ROOT / path).read_text(encoding="utf-8", errors="replace")
            lines = sources[path].splitlines()
        # The mechanical checks first: a docs/solutions/ citation is read ONLY here, and a
        # symbol cannot be looked for past the end of a file or in an ambiguous one.
        problem = check_citation(cit, candidates, lines)
        if problem is None:
            rule, problem = check_symbol(cit, candidates[0], sources[candidates[0]])
            checked.append((cit, rule))
        if problem:
            problems.append(problem)
    return SymbolScan(checked, problems)


def _scan() -> tuple[list[Citation], dict[str, list[str]], list[Citation], list[str]]:
    """Return (all citations, resolved->candidates, unresolved citations, problems)."""
    suffixes = _suffix_index([f for f in _repo_files() if not f.startswith("tests/vendor/")])
    upstream = _upstream_index()

    cits = _citations()
    resolved: dict[str, list[str]] = {}
    unresolved: list[Citation] = []
    problems: list[str] = []
    line_cache: dict[str, list[str]] = {}

    for cit in cits:
        candidates = _candidates(cit.target, suffixes, upstream)
        if not candidates:
            unresolved.append(cit)
            continue
        resolved.setdefault(cit.target, candidates)
        lines = None
        if len(candidates) == 1:
            path = candidates[0]
            if path not in line_cache:
                line_cache[path] = (_ROOT / path).read_text(encoding="utf-8", errors="replace").splitlines()
            lines = line_cache[path]
        problem = check_citation(cit, candidates, lines)
        if problem:
            problems.append(problem)
    return cits, resolved, unresolved, problems


@pytest.fixture(scope="module")
def scan() -> tuple[list[Citation], dict[str, list[str]], list[Citation], list[str]]:
    return _scan()


# ---------------------------------------------------------------------------
# 1. The scan reaches something
# ---------------------------------------------------------------------------


def test_the_scan_is_not_vacuous(scan) -> None:
    """A citation checker that finds no citations passes every check below.

    That is indistinguishable from a real pass in the output, so it is asserted
    against directly rather than left to be noticed.
    """
    cits, resolved, unresolved, _ = scan
    docs = _scanned_docs()
    assert len(docs) >= _MIN_DOCS, (
        f"only {len(docs)} docs scanned — the docs tree moved, or _DATED_SUBTREES now "
        "excludes almost everything. Nothing below proves anything until this is fixed."
    )
    assert len(cits) >= _MIN_CITATIONS, (
        f"only {len(cits)} citations matched across {len(docs)} docs — check _CITE_RE "
        "before lowering this floor; a regex that matches nothing passes silently."
    )
    checked = len(cits) - len(unresolved)
    assert checked >= _MIN_RESOLVED, (
        f"only {checked} citations resolved to a file in this repo (of {len(cits)}). "
        "If resolution broke, every citation drops into the out-of-scope bucket and "
        "the real check below runs over nothing."
    )
    assert resolved, "no citation resolved to any file at all"


def test_the_excluded_dated_subtrees_still_exist() -> None:
    """The exclusion must not go vacuous by renaming.

    If ``docs/plans/`` is renamed and this list is not, the scan silently starts
    reading dated drafts — and their citations legitimately describe the past, so
    the suite would start failing for a reason that is not a defect.
    """
    missing = [name for name in sorted(_DATED_SUBTREES) if not (_ROOT / "docs" / name).is_dir()]
    assert not missing, (
        f"_DATED_SUBTREES names directories that no longer exist: {missing}. "
        "Update the exclusion to match the docs tree."
    )
    assert _SYMBOL_RULE_ALSO_READS <= _DATED_SUBTREES, (
        "_SYMBOL_RULE_ALSO_READS re-admits subtrees the main scan excludes; one it does not "
        f"exclude would re-admit nothing: {sorted(_SYMBOL_RULE_ALSO_READS - _DATED_SUBTREES)}"
    )


def test_only_tracked_files_are_read(tmp_path: Path) -> None:
    """An untracked draft must not fail the gate locally when CI never sees it — and a
    directory git knows nothing about must fall back to reading what is on disk.

    Run against a real throwaway repository, because what is under test is what ``git
    ls-files`` says, and a stub would only repeat what this test told it.
    """
    repo = tmp_path / "repo"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "tracked.md").write_text("`a.py:1`\n", encoding="utf-8")
    (repo / "docs" / "draft.md").write_text("`a.py:99`\n", encoding="utf-8")
    env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", *env, "-C", str(repo), "add", "docs/tracked.md"], check=True)
    assert _tracked_files(repo) == ["docs/tracked.md"]

    plain = tmp_path / "export"
    (plain / "docs").mkdir(parents=True)
    (plain / "docs" / "draft.md").write_text("", encoding="utf-8")
    assert _tracked_files(plain) is None, "a directory outside any git work tree has no index to ask"
    assert _walked_files(plain) == ["docs/draft.md"]

    # A subdirectory of a work tree is not a work tree's root: the listing would be
    # relative to the wrong place, so it too falls back to the walk.
    assert _tracked_files(repo / "docs") is None


# ---------------------------------------------------------------------------
# 2. The gate
# ---------------------------------------------------------------------------


def test_every_cited_line_lands_on_real_code(scan) -> None:
    """The gate. Missing file, past EOF, blank line, or ambiguous name — all fail.

    A citation that lands on a blank line is one whose code has moved; a reader
    following it arrives at whitespace and cannot tell whether the rule it was
    meant to support still holds.
    """
    _, _, _, problems = scan
    assert not problems, "doc citations no longer land on the code they name:\n  " + "\n  ".join(problems)


def test_a_healthy_citation_is_accepted() -> None:
    """The honest path: a correct citation must PASS.

    Paired with the refusal cases below, because a checker that refuses valid work
    is a defect in its own right — and the cheapest way to make this file green
    would be a predicate that rejects nothing, or one that rejects everything and
    gets its floors lowered.
    """
    lines = ["def f():", "", "    return 1", ""]
    single = Citation("d.md", 1, "a.py:1", "a.py", 1, None)
    span = Citation("d.md", 1, "a.py:1-3", "a.py", 1, 3)
    assert check_citation(single, ["a.py"], lines) is None
    assert check_citation(span, ["a.py"], lines) is None


class TestTheCheckerFires:
    """Each failure mode, exercised directly. See ``check_citation``'s docstring."""

    _LINES = ["def f():", "", "    return 1", ""]

    def test_a_blank_start_line_is_refused(self) -> None:
        cit = Citation("d.md", 7, "a.py:2", "a.py", 2, None)
        problem = check_citation(cit, ["a.py"], self._LINES)
        assert problem is not None and "BLANK line 2" in problem and "d.md:7" in problem

    def test_a_blank_end_line_is_refused(self) -> None:
        cit = Citation("d.md", 7, "a.py:1-4", "a.py", 1, 4)
        problem = check_citation(cit, ["a.py"], self._LINES)
        assert problem is not None and "BLANK line 4" in problem

    def test_a_line_past_eof_is_refused(self) -> None:
        cit = Citation("d.md", 7, "a.py:99", "a.py", 99, None)
        problem = check_citation(cit, ["a.py"], self._LINES)
        assert problem is not None and "past the end" in problem

    def test_a_range_ending_past_eof_is_refused(self) -> None:
        cit = Citation("d.md", 7, "a.py:1-99", "a.py", 1, 99)
        problem = check_citation(cit, ["a.py"], self._LINES)
        assert problem is not None and "past the end" in problem

    def test_a_backwards_range_is_refused(self) -> None:
        cit = Citation("d.md", 7, "a.py:3-1", "a.py", 3, 1)
        problem = check_citation(cit, ["a.py"], self._LINES)
        assert problem is not None and "backwards" in problem

    def test_an_ambiguous_name_is_refused_rather_than_guessed(self) -> None:
        """Two matches must fail, not resolve to the first one.

        This is the defect the earlier ad-hoc pass shipped: bare ``types.py``
        resolved to whichever file the walk reached first, and the checker then
        reported confident nonsense against the wrong file.
        """
        cit = Citation("d.md", 7, "wallet.py:1", "wallet.py", 1, None)
        problem = check_citation(cit, ["src/pyrxd/hd/wallet.py", "src/pyrxd/wallet.py"], None)
        assert problem is not None and "ambiguous" in problem

    def test_a_missing_file_is_reported_as_unresolvable(self) -> None:
        """Resolution, not ``check_citation``, is what notices a vanished file.

        ``_candidates`` returns nothing, the citation lands in the unresolved
        bucket, and ``test_the_out_of_scope_inventory_is_exact`` fails it because
        it is not a known external reference.
        """
        suffixes = _suffix_index(["src/pyrxd/glyph/script.py"])
        assert _candidates("src/pyrxd/glyph/gone.py", suffixes, {}) == []
        assert _candidates("src/pyrxd/glyph/script.py", suffixes, {}) == ["src/pyrxd/glyph/script.py"]


# ---------------------------------------------------------------------------
# 2b. The symbol rule
# ---------------------------------------------------------------------------

#: Non-vacuity floor for the symbol rule. See the measurement in the module docstring; the
#: floor sits below it so ordinary doc churn does not trip it, and far above zero so a form
#: regex that stops matching cannot pass as a clean run.
_MIN_SYMBOL_CHECKED = 25


@pytest.fixture(scope="module")
def symbol_scan() -> SymbolScan:
    return _symbol_scan()


def test_every_symbol_citation_lands_on_its_symbol(symbol_scan) -> None:
    """The gate for the half the blank-line check cannot see.

    A citation written next to a code name that lands on some OTHER non-blank line passes
    ``test_every_cited_line_lands_on_real_code`` — the Glyph spec cited ``iter_input_refs``
    at the delegate builder, and ``docs/security-audit-scope.md`` cited ``REF_OPCODES`` at a
    P2PKH byte string for months, both green. See ``check_symbol`` for the two rules.
    """
    assert not symbol_scan.problems, "doc citations do not land on the code they name:\n  " + "\n  ".join(
        symbol_scan.problems
    )


def test_the_symbol_rule_is_not_vacuous(symbol_scan) -> None:
    """A form regex that matches nothing makes the gate above pass over nothing.

    So the rule must have checked a real number of citations, through BOTH rules, and in
    both the published docs and ``docs/solutions/`` — each is a way the scan could quietly
    stop reaching something while every assertion above stays green.
    """
    checked = symbol_scan.checked
    assert len(checked) >= _MIN_SYMBOL_CHECKED, (
        f"the symbol rule checked only {len(checked)} citations — check _NAME_THEN_CITE, "
        "_CITE_THEN_NAME and _CITE_WITH_NAME before lowering this floor."
    )
    rules = {rule for _, rule in checked}
    assert rules == {"definition", "occurrence"}, (
        f"only these rules ran over the real docs: {sorted(rules)}. The definition rule covers "
        "Python targets; the occurrence rule covers the vendored C++."
    )
    subtrees = {cit.doc.split("/")[1] for cit, _ in checked}
    assert subtrees >= _SYMBOL_RULE_ALSO_READS, (
        f"no citation in {sorted(_SYMBOL_RULE_ALSO_READS - subtrees)} was checked, though the rule is meant to read it"
    )
    assert subtrees - _DATED_SUBTREES, "no citation in the published docs was checked"


class TestTheSymbolRule:
    """Both halves of the rule on synthetic inputs: which citations name a symbol, and
    whether the named symbol is where they say. Refusals are paired with honest cases."""

    # Line numbers matter below; the comment on each line is the number.
    _SOURCE = "\n".join(
        [
            "import os",  # 1
            "from x import imported_name",  # 2
            "",  # 3
            "CONSTANT = 1",  # 4
            "annotated: int = 2",  # 5
            "",  # 6
            "",  # 7
            "@decorator",  # 8
            "def decorated():",  # 9
            "    local = 3",  # 10
            "    return local",  # 11
            "",  # 12
            "",  # 13
            "class Outer:",  # 14
            "    attr = 4",  # 15
            "",  # 16
            "    def method(self):",  # 17
            "        if os:",  # 18
            "            return 5",  # 19
            "        return 6  # CONSTANT is read here",  # 20
            "",  # 21
            "",  # 22
            "class Other:",  # 23
            "    def method(self):",  # 24
            "        return imported_name",  # 25
            "",
        ]
    )

    @staticmethod
    def _cite(symbol: str, start: int, end: int | None = None) -> Citation:
        text = f"a.py:{start}" + (f"-{end}" if end is not None else "")
        return Citation("d.md", 7, text, "a.py", start, end, symbol)

    # -- which citations name a symbol ------------------------------------------------

    @pytest.mark.parametrize(
        ("text", "name"),
        [
            ("see `iter_input_refs` (`script.py:12`) here", "iter_input_refs"),
            ("guess (`TruncatedScriptError`,\n`script.py:12`)", "TruncatedScriptError"),
            ("`dMintScript` at `script.py:12`", "dMintScript"),
            ("`swap_state.py:12` (`NegotiatedTerms` and its wire form)", "NegotiatedTerms"),
            ("(`failover.py:12 _holds_tx`)", "_holds_tx"),
            ("`build()` (`proof.py:12`)", "build"),
            ("`NegotiatedTerms.__post_init__` (`swap_state.py:12`)", "NegotiatedTerms.__post_init__"),
            ("the shared `REF_OPCODES`\n(`glyph/script.py:12`), locked", "REF_OPCODES"),
            ("`foo` resolves and `bar` (`x.py:12`)", "bar"),
        ],
    )
    def test_each_written_form_is_read(self, text: str, name: str) -> None:
        (cit,) = citations_in("d.md", text)
        assert cit.symbol == name

    @pytest.mark.parametrize(
        "text",
        [
            "`a` and `b` (`x.py:12`)",
            "`a`, `b` (`x.py:12`)",
            "carries `a`, `b` and (ETH) `c`\n(`x.py:12`)",
            "`x.py:12` (`a`, `b`)",
            "`x.py:12` (`a` and `b`)",
            "`x.py:12, 40-41` (`a`)",
            "`a` (see `x.py:12`)",
            "`a` x.py:12",
            "`a = 1` (`x.py:12`)",
            "`x.py:12 and more`",
        ],
    )
    def test_a_citation_with_no_single_named_subject_names_none(self, text: str) -> None:
        """A list of names, a citation sharing its backticks, or a name not directly beside
        it: the citation's subject is not one symbol, so the rule must not pick one."""
        (cit,) = citations_in("d.md", text)
        assert cit.symbol is None

    def test_a_file_named_beside_a_citation_is_not_a_symbol(self) -> None:
        suffixes = _suffix_index(["src/pyrxd/gravity/htlc_spend.py"])
        assert not _is_symbol("htlc_spend.py", suffixes, {})
        assert _is_symbol("NegotiatedTerms.to_dict", suffixes, {})
        assert _is_symbol("to_dict", suffixes, {})

    # -- whether the symbol is where the citation says --------------------------------

    @pytest.mark.parametrize(
        ("symbol", "start", "end"),
        [
            ("CONSTANT", 4, None),
            ("annotated", 5, None),
            ("decorated", 8, None),  # the decorator line
            ("decorated", 9, None),
            ("decorated", 10, 11),  # a line inside the body
            ("Outer", 14, 20),
            ("Outer.attr", 15, None),
            ("Outer.method", 18, 19),  # a branch inside the method
            ("Other.method", 24, None),
            ("method", 24, 25),  # a bare name matches either class's method
            ("decorated", 1, 8),  # a range that only touches the decorator
        ],
    )
    def test_a_citation_on_its_definition_is_accepted(self, symbol: str, start: int, end: int | None) -> None:
        assert check_symbol(self._cite(symbol, start, end), "a.py", self._SOURCE) == ("definition", None)

    @pytest.mark.parametrize(
        ("symbol", "start", "end", "defined_at"),
        [
            ("decorated", 4, None, "8-11"),
            ("CONSTANT", 5, None, "4"),
            ("CONSTANT", 20, None, "4"),  # MENTIONED on the cited line, defined elsewhere
            ("Other.method", 17, 20, "24-25"),  # the other class's method
            ("Outer", 23, 25, "14-20"),
        ],
    )
    def test_a_citation_beside_its_definition_is_refused(
        self, symbol: str, start: int, end: int | None, defined_at: str
    ) -> None:
        rule, problem = check_symbol(self._cite(symbol, start, end), "a.py", self._SOURCE)
        assert rule == "definition"
        assert problem is not None and f"defines it at line(s) {defined_at}," in problem and "d.md:7" in problem

    @pytest.mark.parametrize(
        ("symbol", "start", "end"),
        [
            ("imported_name", 25, None),  # an import is not a definition, so a use is fine
            ("imported_name", 2, None),
            ("local", 10, None),  # a function's local is not a definition either
        ],
    )
    def test_a_name_the_file_does_not_define_is_accepted_where_it_appears(
        self, symbol: str, start: int, end: int | None
    ) -> None:
        assert check_symbol(self._cite(symbol, start, end), "a.py", self._SOURCE) == ("occurrence", None)

    def test_a_name_the_file_does_not_define_is_refused_where_it_does_not_appear(self) -> None:
        rule, problem = check_symbol(self._cite("local", 4), "a.py", self._SOURCE)
        assert rule == "occurrence"
        assert problem is not None and "does appear at line(s) 10, 11" in problem

    def test_a_name_that_appears_nowhere_says_so(self) -> None:
        """The "no longer exists" case: the fix is to say so in the doc, not to re-point it."""
        rule, problem = check_symbol(self._cite("pre_btc_lock_gate", 9), "a.py", self._SOURCE)
        assert rule == "occurrence"
        assert problem is not None and "appears nowhere in that file" in problem

    def test_a_non_python_file_is_held_to_the_occurrence_rule(self) -> None:
        source = "static bool check(int x) {\n    return helper(x);\n}\n"
        assert check_symbol(self._cite("check", 1), "v.h", source) == ("occurrence", None)
        assert check_symbol(self._cite("helper", 2), "v.h", source) == ("occurrence", None)
        rule, problem = check_symbol(self._cite("check", 2, 3), "v.h", source)
        assert rule == "occurrence" and problem is not None and "does appear at line(s) 1" in problem

    def test_the_citation_from_issue_752_is_refused_against_the_real_file(self) -> None:
        """The defect this rule exists for, through the production path and the real source.

        The Glyph spec cited ``iter_input_refs`` at the delegate builder: every cited line
        real code, none of it the function. Rebuilt here from whatever ``script.py`` holds
        today — the first other definition that does not overlap the real one — so it keeps
        meaning the same thing as lines move. The blank-line rule must PASS it (that is the
        gap) and the symbol rule must refuse it (that is the fix).
        """
        path = "src/pyrxd/glyph/script.py"
        source = (_ROOT / path).read_text(encoding="utf-8")
        definitions = python_definitions(source)
        (real,) = [d for d in definitions if d.qualname == "iter_input_refs"]
        elsewhere = next(
            d
            for d in definitions
            if "." not in d.qualname and d.first < d.last and (d.last < real.first or d.first > real.last)
        )
        (cit,) = citations_in("spec.md", f"walker is `iter_input_refs` (`{path}:{elsewhere.first}-{elsewhere.last}`)")
        assert cit.symbol == "iter_input_refs"
        assert check_citation(cit, [path], source.splitlines()) is None, "the blank-line rule was meant to miss this"
        rule, problem = check_symbol(cit, path, source)
        assert rule == "definition"
        assert problem is not None and f"line(s) {real.first}-{real.last}," in problem


# ---------------------------------------------------------------------------
# 3. The exemption, pinned in both directions
# ---------------------------------------------------------------------------


def test_the_out_of_scope_inventory_is_exact(scan) -> None:
    """The exempt set must equal exactly what is unresolvable today.

    Both directions matter and they catch different things:

    * an unresolvable citation that is NOT listed is the failure this whole file
      exists for — a local file was renamed or deleted and its citations quietly
      stopped being checked, which looks identical to a clean run;
    * a listed target that nothing cites any more is a dead exemption, and an
      exemption nobody re-reads is how a wrong reason survives.
    """
    _, _, unresolved, _ = scan
    seen = {cit.target for cit in unresolved}
    listed = set(_OUT_OF_SCOPE)

    unlisted = sorted(seen - listed)
    where = {t: sorted({c.where for c in unresolved if c.target == t}) for t in unlisted}
    assert not unlisted, (
        "these citations name files this repository does not contain, and are not "
        f"recorded as external references: {where}. If a local file was renamed, re-point "
        "the citation. If it really is another project's file, add it to _OUT_OF_SCOPE "
        "with the project it belongs to."
    )

    stale = sorted(listed - seen)
    assert not stale, (
        f"_OUT_OF_SCOPE lists targets no doc cites any more: {stale}. Delete them rather "
        "than leaving an exemption whose reason nobody has re-read."
    )


def test_no_out_of_scope_entry_masks_a_checkable_file(scan) -> None:
    """An exemption may never name a file this repo actually has.

    Without this, the cheapest way to silence a real failure is to paste the
    failing target into ``_OUT_OF_SCOPE`` — the membership pin above would then
    agree with itself forever. This is the executable half of the exemption's
    reason: "we cannot check it" has to remain TRUE.
    """
    suffixes = _suffix_index([f for f in _repo_files() if not f.startswith("tests/vendor/")])
    upstream = _upstream_index()
    resolvable = {
        target: _candidates(target, suffixes, upstream)
        for target in _OUT_OF_SCOPE
        if _candidates(target, suffixes, upstream)
    }
    assert not resolvable, (
        f"_OUT_OF_SCOPE names targets this repository CAN resolve: {resolvable}. They must be checked, not exempted."
    )


# ---------------------------------------------------------------------------
# Note on line numbers vs symbols
# ---------------------------------------------------------------------------
#
# Line numbers are the wrong unit for these citations and this test cannot fix
# that. It catches the citation that drifted onto whitespace or off the end of
# the file, and — when the doc writes the code name beside it — the one that
# drifted onto a different function. A citation with no name beside it can still
# drift onto a different function unseen; drift of that kind was the larger half of
# the rot measured when this file was written (23 of 29 checkable cases). A
# symbol citation — ``swap_coordinator.py::SwapCoordinator.pre_btc_lock_check`` —
# does not move when a line is inserted above it, and resolves exactly via
# ``ast``, so both halves become checkable at once.
#
# Converting the ~280 citations in these docs is a separate change: the Glyph
# spec declares the ``path:line`` form in its own normative §1, several citations
# name ranges spanning multiple definitions or module-level constants where no
# single symbol applies, and a half-converted corpus is worse than either pure
# form. This test is the floor under the current form, not an argument for
# keeping it.

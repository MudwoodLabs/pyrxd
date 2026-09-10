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
line numbers are within it, and they are not blank.

**What it does NOT prove — read this before trusting a green run.** It cannot
tell that the cited line says what the doc claims. A citation that has drifted
from ``build_ft_locking_script`` onto some *other* non-blank line passes here.
That failure mode is real and was the majority of the rot found: of the 29
citations that named a uniquely-defined function or class on their own doc line,
**23 pointed outside that symbol's definition** while landing on perfectly
non-blank lines. This is a DETECT-level floor for the mechanical half, not a
proof the citations are right. The structural fix for the other half is to cite
symbols rather than lines; see the note at the bottom of this module.

Scope
-----
Derived, not hand-kept: every ``docs/**/*.md`` **except** the three dated
subtrees. ``docs/brainstorms/`` and ``docs/plans/`` are working drafts and
``docs/solutions/`` are incident records — a record that names a file as it stood
in May is not stale, it is a record. (The same split as
``tests/test_docs_are_current.py`` and
``tests/test_protocol_lock_ordering_docs_are_current.py``, but stated as an
EXCLUDE list so a new docs subdirectory is scanned by default rather than
silently unscanned.)

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

import json
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: Dated working space. See the Scope note in the module docstring.
_DATED_SUBTREES = frozenset({"brainstorms", "plans", "solutions"})

_VENDOR_ROOT = _ROOT / "tests" / "vendor" / "radiant_core"
_MANIFEST = _VENDOR_ROOT / "MANIFEST.json"

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

    @property
    def where(self) -> str:
        return f"{self.doc}:{self.doc_line}"


def _scanned_docs() -> list[Path]:
    docs_root = _ROOT / "docs"
    return sorted(p for p in docs_root.rglob("*.md") if p.relative_to(docs_root).parts[0] not in _DATED_SUBTREES)


def _repo_files() -> list[str]:
    """Every file in the checkout, as a repo-relative posix path.

    Hidden directories are pruned, which is what keeps a local ``.venv`` (and its
    thousands of same-named modules) out of the candidate set.
    """
    out: list[str] = []
    stack = [_ROOT]
    while stack:
        directory = stack.pop()
        for entry in directory.iterdir():
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name.startswith(".") or entry.name in _PRUNED_DIR_NAMES or entry in _PRUNED_DIRS:
                    continue
                stack.append(entry)
            elif entry.is_file():
                out.append(entry.relative_to(_ROOT).as_posix())
    return out


def _suffix_index(files: list[str]) -> dict[str, list[str]]:
    """Map every trailing path suffix of every file to the files that carry it."""
    index: dict[str, list[str]] = {}
    for path in files:
        parts = path.split("/")
        for i in range(len(parts)):
            index.setdefault("/".join(parts[i:]), []).append(path)
    return index


def _upstream_index() -> dict[str, str]:
    """Radiant Core ``upstream_path`` -> the vendored verbatim copy of it.

    Derived from the vendor manifest the refresh script writes, so a file added to
    or dropped from the vendor set changes this map without anyone editing it.
    """
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return {
        meta["upstream_path"]: (_VENDOR_ROOT.relative_to(_ROOT) / local).as_posix()
        for local, meta in manifest["files"].items()
    }


def _citations() -> list[Citation]:
    found: list[Citation] = []
    for doc in _scanned_docs():
        rel = doc.relative_to(_ROOT).as_posix()
        for lineno, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            for match in _CITE_RE.finditer(line):
                found.append(
                    Citation(
                        doc=rel,
                        doc_line=lineno,
                        text=match.group(0),
                        target=match.group(1),
                        start=int(match.group(3)),
                        end=int(match.group(4)) if match.group(4) else None,
                    )
                )
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
# the file; it cannot catch the one that drifted onto a different function, which
# was the larger half of the rot measured above (23 of 29 checkable cases). A
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

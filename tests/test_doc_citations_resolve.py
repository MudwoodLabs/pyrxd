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
For every citation naming a file this repo contains, including a bare ``:N``
that follows one: the file exists, the cited line numbers are within it, and
they are not blank. And for every citation
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

``name`` is an identifier, optionally dotted (``Class.method``,
``pyrxd.glyph.script.iter_input_refs``) or written with ``()``. A name that ends
or starts a LIST of names (```a`, `b` and `c` (`CITE`)``) is not taken, because
the citation then speaks for the list; nor is a Python keyword (``None``), a
backticked file name (``htlc_spend.py``), or, in the ```CITE name``` form, a plain
lowercase word (```x.py:14 onwards```). ``check_symbol`` then applies one of two
rules. If the cited file is Python and defines the name (``def``, ``class``, or a
module- or class-level assignment, found with ``ast``; a leading module path is
dropped first), the cited lines must lie inside that definition or contain it
whole, and a bare name the file defines in several places (``to_dict`` on two
classes) must be qualified. Otherwise (the vendored C++, or a name the file only
uses) the name must appear in the cited lines.

"Inside or whole", not "the ``def`` line is cited", because the docs deliberately
cite lines inside a definition: ``holder_hash``'s ``rxd`` branch, the field lines
of ``BtcHtlcLocator``. Measured on the docs as they stood when this rule was added,
requiring the ``def`` line would have refused 5 such citations, each of which
lands on the lines its sentence describes. Not mere overlap either: a range that
straddles one edge of a definition is what a range looks like after the code
moved under it (``iter_input_refs`` at ``:1100-1120`` or ``:1142-1172``, when it is
defined at 1120-1142), and overlap passed both. Requiring qualification of an
ambiguous bare name refused one citation in the docs (``to_dict``, meaning
``NegotiatedTerms.to_dict``); the other two changes refused none.

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

What the symbol rule cannot see: a citation with no name beside it (outside a
keyed table row, below); a citation for a list of names; a citation sharing its
backticks with more ranges (```x.py:10, 40-41```), except through the row rule; a
citation that drifted WITHIN its definition (a line of a long function that now
lands on a different line of the same function); a C++ citation that lands on a
call rather than the definition, since the occurrence rule accepts both; a real
all-lowercase function name written as ```x.py:14 check```, read as prose; and a
symbol citation in ``docs/solutions/`` naming a file this repo does not contain,
which is not held to the out-of-scope inventory below. A cited Python file that
does not parse on the running interpreter is reported, not passed. In the other direction, it refuses a citation that deliberately points at
a USE of a name the same Python file defines: cite the definition, or write the
citation so it does not sit directly beside the name.

Bare ``:N`` citations
---------------------
A doc often cites a second line of the same file as a bare ``:N`` in backticks
(``iter_input_refs`` (``script.py:1144-1166``) over ``REF_OPCODES`` (``:1099``)).
``_CITE_RE`` needs a file name, so those were invisible to this test: two in the
Glyph spec had drifted off their code when #773 was reviewed. A bare ``:N`` reads
the file most recently NAMED before it (in backticks, with or without a line) on
the same line, or else earlier in the same paragraph; a table row does not
inherit from the row above it, whose file is usually a column's, not a row's. Once
attributed, a bare citation is an ordinary one: the blank-line gate reads it, and
so does the symbol rule when a code name is written beside it.

A bare ``:N`` with no file named before it is REFUSED in the published docs
(``test_every_bare_citation_names_its_file``). It used to pass unchecked, and that
is where most of the handshake spec's rot hid: its ``terms`` and finality tables
cited ``:288-289``, ``:1517`` and so on with no file in the row, so no rule read
them, and #815/#817 moved every one onto unrelated code (two past the end of the
file they were meant for). Writing the file costs one word and makes every rule
below apply. ``docs/solutions/`` is not held to this, for the same reason it is
outside the blank-line gate.

Table rows
----------
A row whose first cell is exactly one code name (```rxd_claim_burial```, or
```maker_stall_safety_window_blocks` (`N`)``) is ABOUT that name, so a citation in a
later cell of the row that names no symbol of its own must have the key in its
cited lines (``check_row_key``). It is the occurrence rule, not the definition
rule: a field's row may cite the line that validates it as well as the line that
declares it.

Measured on ``docs/htlc-handshake-wire-format.md`` as it stood at 6f44969e, where
every rule above passed it: the row rule refuses 4 citations, the unattributed-bare
rule 16, and reading further ranges 1 more (``swap_state.py:16-19, 516-517``, whose
second range had drifted onto a blank line) — 21 in all. The spec had more drifted
citations than that, in prose with no name beside them; see the note at the bottom.

Further ranges
--------------
``x.py:10, 40-41`` is two citations. Only ``:10`` used to be read, so ``40-41``
could point anywhere, including past the end of the file. Every range is now a
citation of its own: the blank-line gate reads each, and so does the row rule. None
of them names a symbol (the citation's subject is not one name).

Measured when bare citations were first read (#773, with a symbol check of its
own that the symbol rule above has replaced), on the docs as they stood then: 39
bare citations, 23 attributed and 16 not (table rows that name no file, all in
``docs/htlc-handshake-wire-format.md``). Those checks found 13 citations the
name-and-line check had passed or could not see; all were re-cited in #773.

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
import keyword
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

#: A file NAMED in backticks, with or without a line: what a later bare ``:N`` reads as its file.
#: ``adapters.py`` counts although it carries no line — ``adapters.py`` a ... (``:142``) means
#: adapters.py, not whichever file was last cited WITH a line.
_FILE_MENTION_RE = re.compile(
    r"`((?:[A-Za-z0-9_][A-Za-z0-9_./-]*/)?[A-Za-z0-9_][A-Za-z0-9_-]*\.[A-Za-z][A-Za-z0-9]*)(?::\d+(?:-\d+)?(?:,\s*\d+)*)?`"
)

#: A bare continuation citation, ``:N`` or ``:N-M`` alone in backticks. It names no file.
_BARE_RE = re.compile(r"`:(\d+)(?:-(\d+))?`")

#: A further range of the same citation: the ``, 40-41`` in ``x.py:10, 40-41``. Matched at the
#: end of a ``_CITE_RE`` match, repeatedly; no backtick can intervene, so it never leaves the
#: citation's own code span.
_MORE_RE = re.compile(r",[ \t]*(\d+)(?:-(\d+))?(?![\d.])")

#: A table row's first cell holding exactly one code name, optionally followed by a short
#: parenthetical alias: ``| `rxd_claim_burial` |`` or ``| `maker_stall_safety_window_blocks` (`N`) |``.
_ROW_KEY_RE = re.compile(
    r"\A[ \t]*\|[ \t]*`(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?:\(\))?`[ \t]*(?:\([^|\n]*\))?[ \t]*\|"
)

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
#: Measured: 22 bare citations attributed to a file this repo has when #773 first read them, and
#: 56 when it was reconciled with #766 (847 citations in all by then).
#: A floor, for the same reason as the three above.
_MIN_BARE_RESOLVED = 15


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
    #: Written as a bare ``:N``; ``target`` is the file named before it (see the module docstring).
    bare: bool = False
    #: The code name a table row is ABOUT, when this citation sits in a later cell of a row whose
    #: first cell is that one name (```name``` or ```name` (`alias`)``). See "Table rows" in the
    #: module docstring. ``None`` outside such a row.
    row_key: str | None = None

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
        doc_line = text.count("\n", 0, match.start()) + 1
        key = _row_key_at(text, match.start())
        found.append(
            Citation(
                doc=doc,
                doc_line=doc_line,
                text=match.group(0),
                target=match.group(1),
                start=int(match.group(3)),
                end=int(match.group(4)) if match.group(4) else None,
                symbol=symbol_named_by(text, match.start(), match.end()),
                row_key=key,
            )
        )
        # ``x.py:10, 40-41``: every further range is a citation of the same file. Before these
        # were read, only ``:10`` was checked and ``40-41`` could point anywhere. A multi-range
        # citation names no single symbol (``symbol_named_by``), so these carry none either.
        pos = match.end()
        while more := _MORE_RE.match(text, pos):
            found.append(
                Citation(
                    doc=doc,
                    doc_line=doc_line,
                    text=f"{match.group(1)}:{more.group(0).lstrip(', ')}",
                    target=match.group(1),
                    start=int(more.group(1)),
                    end=int(more.group(2)) if more.group(2) else None,
                    row_key=key,
                )
            )
            pos = more.end()
    found.extend(_bare_citations_in(doc, text))
    return sorted(found, key=lambda c: c.doc_line)


def _row_key_at(text: str, offset: int) -> str | None:
    """The code name the table row holding ``text[offset]`` is about, if the citation is in a
    LATER cell of a row whose first cell is that one name (``_ROW_KEY_RE``); else ``None``."""
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    line = text[line_start : len(text) if line_end == -1 else line_end]
    key = _ROW_KEY_RE.match(line)
    if key is None or offset - line_start < key.end():
        return None  # not a keyed row, or the citation is in the key cell itself
    return _code_name(key.group("name"))


def _bare_citations_in(doc: str, text: str) -> list[Citation]:
    """Every bare ``:N`` in *text* that a file named before it attributes (module docstring).

    The file is the one last named on the same line, or else earlier in the same paragraph; a
    table row does not inherit from the row above. The symbol beside it is read by
    ``symbol_named_by`` over the whole text, as for any other citation.
    """
    found: list[Citation] = []
    paragraph: str | None = None  # the file last named in this paragraph (not in a table)
    offset = 0  # where this line starts in *text*
    for lineno, line in enumerate(text.split("\n"), 1):
        is_row = line.lstrip().startswith("|")
        if not line.strip() or is_row:
            paragraph = None
        on_line: str | None = None  # the file last named earlier on this line
        events = sorted(
            [(m.start(), 0, "named", m) for m in _FILE_MENTION_RE.finditer(line)]
            + [(m.start(), 1, "full", m) for m in _CITE_RE.finditer(line)]
            + [(m.start(), 1, "bare", m) for m in _BARE_RE.finditer(line)],
            key=lambda e: (e[0], e[1]),
        )
        for _, _, kind, match in events:
            if kind != "bare":
                on_line = paragraph = match.group(1)
                continue
            named = on_line or (None if is_row else paragraph)
            if named is None:
                continue  # nothing names its file; see the module docstring
            found.append(
                Citation(
                    doc=doc,
                    doc_line=lineno,
                    text=f"{match.group(0).strip('`')} (read as {named})",
                    target=named,
                    start=int(match.group(1)),
                    end=int(match.group(2)) if match.group(2) else None,
                    # Inside the backticks, as symbol_named_by expects of a citation.
                    symbol=symbol_named_by(text, offset + match.start() + 1, offset + match.end() - 1),
                    bare=True,
                    row_key=_row_key_at(text, offset + match.start()),
                )
            )
        offset += len(line) + 1
    return found


def unattributed_bare_citations(doc: str, text: str) -> list[str]:
    """Every bare ``:N`` in *text* that no file named before it attributes, as ``doc:line `:N```.

    The complement of ``_bare_citations_in``, computed from it rather than by a second copy of
    the attribution rule, so the two cannot disagree about what "attributed" means.
    """
    attributed = {(c.doc_line, c.start, c.end) for c in _bare_citations_in(doc, text)}
    out: list[str] = []
    for lineno, line in enumerate(text.split("\n"), 1):
        for match in _BARE_RE.finditer(line):
            end = int(match.group(2)) if match.group(2) else None
            if (lineno, int(match.group(1)), end) not in attributed:
                out.append(f"{doc}:{lineno} {match.group(0)}")
    return out


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
        return _code_name(within.group("name"), within.group(0).strip(" \t`"))
    if not after.startswith("`"):
        return None  # the citation shares its backticks with something other than a name
    before = text[max(0, start - _WINDOW) : start]
    first = _NAME_THEN_CITE.search(before)
    if first:
        name_at = start - len(before) + first.start()
        if _LIST_BEFORE.search(text[max(0, name_at - _WINDOW) : name_at]):
            return None
        return _code_name(first.group("name"))
    second = _CITE_THEN_NAME.match(after)
    if second:
        if _LIST_AFTER.match(after[second.end() :]):
            return None
        return _code_name(second.group("name"))
    return None


def _code_name(name: str, written: str | None = None) -> str | None:
    """*name*, unless it is a Python keyword (```CITE` (`None` if …)`` names no symbol).

    *written* is given for the ```CITE name``` form, where the name shares the citation's
    backticks with no punctuation to mark it as code. There a plain lowercase word
    (```x.py:14 onwards```) is prose, so only a name that LOOKS like code is taken: one with
    an underscore, a dot, a capital, a digit or ``()``. A real function called ``check``
    written that way is therefore not checked; written in any other form, it is.
    """
    if keyword.iskeyword(name.split(".")[0]):
        return None
    if written is not None and not re.search(r"[_.A-Z0-9(]", written):
        return None
    return name


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
    not told that the name "is defined" at its import line. The exception is an import of a
    name the same scope ALSO assigns (``try: from x import y`` / ``except ImportError: y =
    None``): the import is then one of the name's bindings, and a citation of it is correct.

    Raises ``SyntaxError`` when *source* does not parse on the running Python; ``check_symbol``
    reports that rather than letting it pass or crash the scan.
    """
    out: list[Definition] = []
    imported: list[Definition] = []

    def visit(node: ast.AST, prefix: str, in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                first = min([d.lineno for d in child.decorator_list] + [child.lineno])
                out.append(Definition(prefix + child.name, first, child.end_lineno or child.lineno))
                is_function = not isinstance(child, ast.ClassDef)
                visit(child, f"{prefix}{child.name}.", in_function or is_function)
            elif isinstance(child, (ast.Import, ast.ImportFrom)):
                if in_function:
                    continue
                for alias in child.names:
                    if alias.name != "*":
                        bound = alias.asname or alias.name.split(".")[0]
                        imported.append(Definition(prefix + bound, child.lineno, child.end_lineno or child.lineno))
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
    assigned = {d.qualname for d in out}
    out.extend(d for d in imported if d.qualname in assigned)
    return tuple(out)


def _without_module_prefix(parts: list[str], path: str) -> list[str]:
    """*parts* with a leading module path dropped: ``pyrxd.glyph.script.iter_input_refs``,
    cited in ``src/pyrxd/glyph/script.py``, is ``iter_input_refs``.

    Only a prefix that is a contiguous run of *path*'s own components is dropped (so
    ``pyrxd.glyph``, the re-export path, is too), and at least one part is always kept. A
    prefix that names anything else (``Wrong.method``) is left alone, and ``check_symbol``
    then refuses the name if the file defines ``method`` under some other qualifier.
    """
    module = path.removesuffix(".py").split("/")
    if module[-1] == "__init__":
        module = module[:-1]
    for k in range(len(parts) - 1, 0, -1):
        if any(module[i : i + k] == parts[:k] for i in range(len(module) - k + 1)):
            return parts[k:]
    return parts


#: How many lines a citation of a definition may take in above it (a leading comment and a
#: blank) and below it (the two blank lines PEP 8 leaves after a top-level definition). Only
#: blank and comment lines count. Measured on the real docs when this was set: every one of the
#: 35 citations the definition rule checked lay INSIDE its definition, so honest citations use
#: none of this; it is room for a comment, not for code.
_LEAD_ALLOWANCE = 3
_TRAIL_ALLOWANCE = 2


def _is_filler(line: str) -> bool:
    """A blank or comment-only line: the only kind a citation may take in beside a definition."""
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _lands_on(d: Definition, first: int, last: int, lines: list[str]) -> bool:
    """The cited lines overlap the definition, and any they take in outside it are at most
    ``_LEAD_ALLOWANCE`` lines above it and ``_TRAIL_ALLOWANCE`` below, all blank or comments.

    So a range inside the definition passes, and so does one that adds a leading comment. A
    range that holds the definition among other code does not, however much of it there is:
    ``swap_state.py:1-800`` contains ``NegotiatedTerms.to_dict`` and says nothing about where.
    """
    if last < d.first or first > d.last:
        return False
    if d.first - first > _LEAD_ALLOWANCE or last - d.last > _TRAIL_ALLOWANCE:
        return False
    outside = [*range(first, d.first), *range(d.last + 1, last + 1)]
    return all(0 < n <= len(lines) and _is_filler(lines[n - 1]) for n in outside)


def check_symbol(cit: Citation, path: str, source: str) -> tuple[str, str | None]:
    """Return ``(rule, problem)`` for a citation that names ``cit.symbol``; ``problem`` is ``None`` if it holds.

    ``rule`` is which of the two applied:

    * ``"definition"`` — *path* is Python and defines the name (see ``python_definitions``;
      a dotted name must match the trailing parts of the qualified name, after any leading
      module path is dropped, see ``_without_module_prefix``). If the name matches more than
      one qualified name (bare ``to_dict``, with ``NegotiatedTerms.to_dict`` and
      ``SwapRecord.to_dict`` both defined) and none of them exactly, the citation is refused
      as ambiguous: which one the doc meant cannot be known, the same stance as a bare file
      name two files share. A dotted name the file does not define, when the file DOES define
      its last part (``Wrong.iter_input_refs``, ``X.to_dict``), is refused as naming nothing:
      falling through to the occurrence rule would accept it wherever the last part appears.
      Otherwise the cited lines must land on one of the definitions (decorators through last
      line), see ``_lands_on``: inside it, because the docs deliberately cite a branch inside
      a function (``holder_hash``'s ``rxd`` branch), or over it with at most a few blank or
      comment lines either side. A range that takes in other code — straddling an edge, or
      holding the whole definition among its neighbours — is how a range looks after the
      code moved under it, or one too wide to say where the name is, so it is refused.
    * ``"occurrence"`` — *path* is not Python (the vendored C++), or does not define the
      name (a dict key, a string value, an imported name). The name's last part must then
      appear as a whole word in the cited lines. This is weaker: it cannot tell a C++
      definition from a call.
    * ``"unparsed"`` — *path* is Python that does not parse on the running interpreter (newer
      syntax than it knows), so where it defines the name is unknown. Always a problem: an
      unverifiable citation is reported, not passed.

    Split out from the scan so both rules can be exercised against synthetic inputs.
    """
    assert cit.symbol is not None, "only a citation that names a symbol has one to check"
    first, last = cit.start, cit.end if cit.end is not None else cit.start
    parts = cit.symbol.split(".")
    lines = source.splitlines()
    if path.endswith(".py"):
        try:
            definitions = python_definitions(source)
        except (SyntaxError, ValueError) as exc:
            return "unparsed", (
                f"{cit.where}: `{cit.symbol}` at `{cit.text}` cannot be checked: {path} does not parse "
                f"on this Python ({exc}). Run this test on a Python that parses it."
            )

        def matching(name: list[str]) -> list[Definition]:
            return [d for d in definitions if d.qualname.split(".")[-len(name) :] == name]

        defined = matching(parts)
        if not defined:
            parts = _without_module_prefix(parts, path)
            defined = matching(parts)
        if not defined and len(parts) > 1 and (same_last := matching(parts[-1:])):
            return "definition", (
                f"{cit.where}: `{cit.symbol}` at `{cit.text}` names nothing {path} defines — it "
                f"defines `{parts[-1]}` only as {', '.join(sorted({d.qualname for d in same_last}))}. "
                "Correct the qualified name."
            )
        exact = [d for d in defined if d.qualname == ".".join(parts)]
        defined = exact or defined
        qualnames = sorted({d.qualname for d in defined})
        if len(qualnames) > 1:
            return "definition", (
                f"{cit.where}: `{cit.symbol}` at `{cit.text}` is ambiguous — {path} defines "
                f"{', '.join(qualnames)}. Write the qualified name, so the citation can be checked "
                "against the one it means."
            )
        if defined:
            if any(_lands_on(d, first, last, lines) for d in defined):
                return "definition", None
            spans = ", ".join(
                str(d.first) if d.first == d.last else f"{d.first}-{d.last}"
                for d in sorted(defined, key=lambda d: d.first)
            )
            return "definition", (
                f"{cit.where}: `{cit.symbol}` is cited at `{cit.text}`, but {path} defines it at "
                f"line(s) {spans}, and the cited lines are not on it (inside it, or over it with at "
                f"most {_LEAD_ALLOWANCE} blank or comment lines above and {_TRAIL_ALLOWANCE} below). "
                "Re-cite it where it is."
            )
    word = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(parts[-1])}(?![A-Za-z0-9_])")
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


def check_row_key(cit: Citation, path: str, source: str) -> str | None:
    """Return a problem for a citation in a keyed table row whose cited lines never mention the key.

    The rule is occurrence, never definition: a row about a field legitimately cites the line that
    VALIDATES it (``hashlock`` at ``object.__setattr__(self, "hashlock", _b32(...))``), not only
    the line that declares it. What it refuses is a citation whose lines do not mention the row's
    subject at all, which is what every drifted row in the handshake spec looked like: real,
    non-blank code about something else.
    """
    assert cit.row_key is not None, "only a citation in a keyed row has a key to check"
    last = cit.row_key.split(".")[-1]
    first, final = cit.start, cit.end if cit.end is not None else cit.start
    lines = source.splitlines()
    word = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(last)}(?![A-Za-z0-9_])")
    if any(word.search(line) for line in lines[first - 1 : final]):
        return None
    seen = [n for n, line in enumerate(lines, 1) if word.search(line)]
    where = (
        f"it does appear at line(s) {', '.join(map(str, seen[:5]))}{' …' if len(seen) > 5 else ''}"
        if seen
        else "it appears nowhere in that file"
    )
    return (
        f"{cit.where}: this table row is about `{cit.row_key}`, but `{cit.text}` ({path}) never "
        f"mentions it; {where}. Re-cite the row's lines, or name what the citation is about beside it."
    )


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
        named = cit.symbol is not None and _is_symbol(cit.symbol, suffixes, upstream)
        keyed = cit.symbol is None and cit.row_key is not None and _is_symbol(cit.row_key, suffixes, upstream)
        if not (named or keyed):
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
        if problem is None and named:
            rule, problem = check_symbol(cit, candidates[0], sources[candidates[0]])
            checked.append((cit, rule))
        elif problem is None:
            problem = check_row_key(cit, candidates[0], sources[candidates[0]])
            checked.append((cit, "row"))
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
    bare = sum(1 for cit in cits if cit.bare and cit not in unresolved)
    assert bare >= _MIN_BARE_RESOLVED, (
        f"only {bare} bare `:N` citations were attributed to a file this repo has — check "
        "_BARE_RE and _FILE_MENTION_RE; an attribution rule that finds nothing passes silently."
    )


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


def test_every_bare_citation_names_its_file() -> None:
    """A bare ``:N`` that no file attributes is checked by nothing, so it is refused.

    See "Bare ``:N`` citations" in the module docstring: this is where the handshake spec's
    ``terms`` and finality tables rotted unseen.
    """
    offenders = [
        o for rel in _scanned_docs() for o in unattributed_bare_citations(rel, (_ROOT / rel).read_text("utf-8"))
    ]
    assert not offenders, (
        "these bare `:N` citations name no file before them, so no rule can check them — write the "
        "file (`swap_state.py:N`):\n  " + "\n  ".join(offenders)
    )


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

    def test_a_bare_citation_reads_the_file_named_before_it(self) -> None:
        text = (
            "`script.py:12` over `REF_OPCODES` (`:99`), and\n"  # on the same line
            "`adapters.py` holds `Source` (`:7`)\n"  # named without a line
            "then `:8` on the next line of the paragraph\n"
            "\n"
            "a new paragraph `:9`\n"  # nothing named: not attributed
            "| `swap.py:1` | row |\n"
            "| `:2` | the next row |\n"  # a row does not inherit from the row above
        )
        got = [(c.doc_line, c.target, c.start, c.symbol) for c in citations_in("d.md", text) if c.bare]
        assert got == [
            (1, "script.py", 99, "REF_OPCODES"),
            (2, "adapters.py", 7, "Source"),
            (3, "adapters.py", 8, None),
        ]

    def test_an_unattributed_bare_citation_is_reported(self) -> None:
        """The refusal and its honest pair: the same row, with and without the file written."""
        assert unattributed_bare_citations("d.md", "| `min_ref_confirmations` | 6 | `:1517` |\n") == ["d.md:1 `:1517`"]
        assert unattributed_bare_citations("d.md", "| `min_ref_confirmations` | 6 | `x.py:1`, `:1517` |\n") == []
        assert unattributed_bare_citations("d.md", "`a.py:1` then (`:2`)\n\nnew paragraph (`:3`)\n") == ["d.md:3 `:3`"]

    def test_every_range_of_a_multi_range_citation_is_read(self) -> None:
        """``x.py:10, 40-41`` is two citations; the second used to be invisible to every rule."""
        got = [(c.target, c.start, c.end, c.symbol) for c in citations_in("d.md", "see `x.py:10, 40-41, 7`")]
        assert got == [("x.py", 10, None, None), ("x.py", 40, 41, None), ("x.py", 7, None, None)]
        (late,) = [c for c in citations_in("d.md", "`a.py:1, 9`") if c.start == 9]
        problem = check_citation(late, ["a.py"], ["x = 1", "y = 2"])
        assert problem is not None and "past the end" in problem
        # Not a further range: a closing backtick intervenes, or the number is a version.
        assert [c.start for c in citations_in("d.md", "`x.py:10`, 40 tests")] == [10]
        assert [c.start for c in citations_in("d.md", "`x.py:10, 1.5`")] == [10]

    def test_a_bare_citation_is_held_to_the_blank_line_check(self) -> None:
        """The #773 shape: a bare ``:N`` that drifted onto a blank line, invisible before."""
        (cit,) = [c for c in citations_in("d.md", "`a.py:1` and then (`:2`)") if c.bare]
        assert (cit.target, cit.start) == ("a.py", 2)
        problem = check_citation(cit, ["a.py"], ["x = 1", "", "y = 2"])
        assert problem is not None and "BLANK line 2" in problem
        (honest,) = [c for c in citations_in("d.md", "`a.py:1` and then (`:3`)") if c.bare]
        assert check_citation(honest, ["a.py"], ["x = 1", "", "y = 2"]) is None


# ---------------------------------------------------------------------------
# 2b. The symbol rule
# ---------------------------------------------------------------------------

#: Non-vacuity floor for the symbol rule. See the measurement in the module docstring; the
#: floor sits below it so ordinary doc churn does not trip it, and far above zero so a form
#: regex that stops matching cannot pass as a clean run.
_MIN_SYMBOL_CHECKED = 25
#: The same for the table-row rule. Measured when it was added: 41 row citations checked, 39 of
#: them in the handshake spec.
_MIN_ROW_CHECKED = 20


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
    assert rules == {"definition", "occurrence", "row"}, (
        f"only these rules ran over the real docs: {sorted(rules)}. The definition rule covers "
        "Python targets; the occurrence rule covers the vendored C++; the row rule covers keyed "
        "table rows."
    )
    rows = sum(1 for _, rule in checked if rule == "row")
    assert rows >= _MIN_ROW_CHECKED, (
        f"the row rule checked only {rows} citations — check _ROW_KEY_RE before lowering this floor."
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
            "",  # 26
            "try:",  # 27
            "    from y import fallback_name",  # 28
            "except ImportError:",  # 29
            "    fallback_name = None",  # 30
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
            ("(`x.py:12 Foo`)", "Foo"),
            ("(`x.py:12 build()`)", "build"),
            ("`x.py:12` (`none_left` if absent)", "none_left"),
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
            "`x.py:14 onwards`",  # a word after the line number is prose, not a name
            "`x.py:12` (`None` if absent)",  # a keyword is not a symbol
            "`True` (`x.py:12`)",
        ],
    )
    def test_a_citation_with_no_single_named_subject_names_none(self, text: str) -> None:
        """A list of names, a citation sharing its backticks, or a name not directly beside
        it: the citation's subject is not one symbol, so the rule must not pick one. (Each
        range of a multi-range citation is a citation of its own; none names a symbol.)"""
        cits = citations_in("d.md", text)
        assert cits and all(cit.symbol is None for cit in cits)

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
            ("Other.method", 24, 25),
            ("decorated", 8, 11),  # exactly the definition
            ("decorated", 6, 11),  # with the blank lines above it
            ("decorated", 8, 13),  # with the blank lines below it
            ("Outer", 12, 22),  # both
            ("fallback_name", 28, None),  # the import is a binding: the same scope assigns it
            ("fallback_name", 30, None),
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
            ("decorated", 1, 8, "8-11"),  # a drifted range: ends on the decorator
            ("decorated", 4, 9, "8-11"),  # ends inside the definition
            ("decorated", 10, 14, "8-11"),  # starts inside, runs past the end
            ("Outer.method", 15, 18, "17-20"),  # starts before, ends inside
            ("fallback_name", 25, None, "28, 30"),
            ("decorated", 4, 11, "8-11"),  # holds the whole definition, and code above it
            ("Outer", 4, 25, "14-20"),  # holds it among its neighbours
            ("Outer.method", 1, 30, "17-20"),  # the whole file
            ("Outer.method", 17, 25, "17-20"),  # blank lines and then another class below
        ],
    )
    def test_a_citation_beside_its_definition_is_refused(
        self, symbol: str, start: int, end: int | None, defined_at: str
    ) -> None:
        rule, problem = check_symbol(self._cite(symbol, start, end), "a.py", self._SOURCE)
        assert rule == "definition"
        assert problem is not None and f"defines it at line(s) {defined_at}," in problem and "d.md:7" in problem

    #: A leading comment block above a function, and code after it. Line numbers as above.
    _COMMENTED = "\n".join(
        [
            "# 1",  # 1
            "# 2",  # 2
            "# 3",  # 3
            "# 4",  # 4
            "def foo():",  # 5
            "    a = 1",  # 6
            "    return a",  # 7
            "",  # 8
            "BAR = 2",  # 9
            "",
        ]
    )

    @pytest.mark.parametrize(
        ("start", "end"),
        [
            (3, 6),  # the comment just above it and its first lines
            (2, 7),  # three comment lines and the whole function
            (5, 8),  # the function and the blank line below it
            (4, 5),
        ],
    )
    def test_a_range_may_take_in_a_leading_comment(self, start: int, end: int) -> None:
        """The honest half of the bound: a range starting on the comment that introduces a
        function, and running into it, cites the function. It used to be refused as a
        straddle."""
        assert check_symbol(self._cite("foo", start, end), "a.py", self._COMMENTED) == ("definition", None)

    @pytest.mark.parametrize(
        ("start", "end"),
        [
            (1, 7),  # four comment lines above: past the allowance
            (5, 9),  # runs on to the next line of code, inside the allowance
            (1, 9),  # holds the function among its neighbours
            (4, 4),  # only the comment, not the function
        ],
    )
    def test_a_range_is_bounded_around_the_definition(self, start: int, end: int) -> None:
        """A range that holds the definition is not enough: ``1-800`` holds everything. It
        may take in at most ``_LEAD_ALLOWANCE`` comment or blank lines above and
        ``_TRAIL_ALLOWANCE`` below, and no code."""
        assert (_LEAD_ALLOWANCE, _TRAIL_ALLOWANCE) == (3, 2), "the cases here are sized to these"
        rule, problem = check_symbol(self._cite("foo", start, end), "a.py", self._COMMENTED)
        assert rule == "definition"
        assert problem is not None and "defines it at line(s) 5-7," in problem

    def test_a_range_holding_a_real_method_among_its_neighbours_is_refused(self) -> None:
        """The review's case, through the real file: ``NegotiatedTerms.to_dict`` cited at a
        range that holds it and much else, and at the whole file. Built from wherever the
        method is today, and paired with the method's own lines, which must pass."""
        path = "src/pyrxd/gravity/swap_state.py"
        source = (_ROOT / path).read_text(encoding="utf-8")
        (real,) = [d for d in python_definitions(source) if d.qualname == "NegotiatedTerms.to_dict"]
        lines = source.splitlines()
        whole = len(lines)

        def non_blank(n: int, step: int) -> int:
            # A range's ends must be code (a BLANK end is refused by the plain citation rule), so
            # the "around it" range is widened past any blank line it would otherwise end on —
            # the file's own edits must not decide whether this case is the one under test.
            while not lines[n - 1].strip():
                n += step
            return n

        around = (non_blank(real.first - 100, -1), non_blank(real.last + 100, 1))
        for start, end in (around, (1, whole)):
            (cit,) = citations_in("d.md", f"`NegotiatedTerms.to_dict` (`{path}:{start}-{end}`)")
            assert check_citation(cit, [path], source.splitlines()) is None
            rule, problem = check_symbol(cit, path, source)
            assert rule == "definition" and problem is not None and f"line(s) {real.first}-{real.last}," in problem
        (cit,) = citations_in("d.md", f"`NegotiatedTerms.to_dict` (`{path}:{real.first}-{real.last}`)")
        assert check_symbol(cit, path, source) == ("definition", None)

    @pytest.mark.parametrize(
        ("path", "wrong", "right"),
        [
            ("src/pyrxd/gravity/swap_state.py", "X.to_dict", "SwapRecord.to_dict"),
            ("src/pyrxd/glyph/script.py", "Wrong.iter_input_refs", "iter_input_refs"),
        ],
    )
    def test_a_wrongly_qualified_name_is_refused_where_the_right_one_passes(
        self, path: str, wrong: str, right: str
    ) -> None:
        """The file defines the last part, but not under that qualifier. Cited at the real
        definition's own lines, the correct name passes and the wrong one must not: it names
        nothing, and the occurrence rule would have accepted it anywhere the word appears."""
        source = (_ROOT / path).read_text(encoding="utf-8")
        (real,) = [d for d in python_definitions(source) if d.qualname == right]
        rule, problem = check_symbol(self._cite(wrong, real.first, real.last), path, source)
        assert rule == "definition"
        assert problem is not None and "names nothing" in problem and right in problem
        assert check_symbol(self._cite(right, real.first, real.last), path, source) == ("definition", None)

    def test_a_wrong_qualifier_is_refused_on_synthetic_input(self) -> None:
        rule, problem = check_symbol(self._cite("Wrong.method", 24, 25), "a.py", self._SOURCE)
        assert rule == "definition"
        assert problem is not None and "only as Other.method, Outer.method" in problem
        assert check_symbol(self._cite("Other.method", 24, 25), "a.py", self._SOURCE) == ("definition", None)
        # A dotted name whose last part the file does not define at all is still read by
        # the occurrence rule: ``self.local`` is not a definition anywhere.
        assert check_symbol(self._cite("self.local", 10), "a.py", self._SOURCE) == ("occurrence", None)

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

    def test_a_bare_name_several_things_define_is_refused_as_ambiguous(self) -> None:
        """Bare ``method`` is ``Outer.method`` and ``Other.method`` here. Landing on either
        proves nothing about the one the doc meant, so the doc must say which."""
        for start, end in ((17, 20), (24, 25)):
            rule, problem = check_symbol(self._cite("method", start, end), "a.py", self._SOURCE)
            assert rule == "definition"
            assert problem is not None and "ambiguous" in problem and "Other.method, Outer.method" in problem

    def test_a_bare_name_with_one_exact_definition_is_that_definition(self) -> None:
        """The honest path beside the ambiguity: an unqualified name that IS a module-level
        definition means that one, even where a class also has a member of the name."""
        source = "def run():\n    pass\n\n\nclass C:\n    def run(self):\n        pass\n"
        assert check_symbol(self._cite("run", 1, 2), "a.py", source) == ("definition", None)
        rule, problem = check_symbol(self._cite("run", 6, 7), "a.py", source)
        assert rule == "definition" and problem is not None and "defines it at line(s) 1-2," in problem
        assert check_symbol(self._cite("C.run", 6, 7), "a.py", source) == ("definition", None)

    @pytest.mark.parametrize(
        ("symbol", "start", "problem"),
        [
            ("pkg.a.decorated", 9, None),
            ("a.decorated", 10, None),
            ("pkg.a.Outer.method", 18, None),
            ("pkg.a.CONSTANT", 4, None),
            ("pkg.a.CONSTANT", 20, "defines it at line(s) 4,"),  # mentioned on 20, defined on 4
            ("pkg.a.method", 24, "ambiguous"),
        ],
    )
    def test_a_module_qualified_name_is_held_to_the_definition_rule(
        self, symbol: str, start: int, problem: str | None
    ) -> None:
        rule, found = check_symbol(self._cite(symbol, start), "src/pkg/a.py", self._SOURCE)
        assert rule == "definition"
        assert (found is None) if problem is None else (found is not None and problem in found)

    def test_a_prefix_that_is_not_the_module_is_not_dropped(self) -> None:
        """``Wrong.method`` must not be read as bare ``method``: only the file's own module
        path is dropped, so a wrong class name gets no help from the definition rule."""
        assert _without_module_prefix(["Wrong", "method"], "src/pkg/a.py") == ["Wrong", "method"]
        assert _without_module_prefix(["pkg", "a", "f"], "src/pkg/a.py") == ["f"]
        assert _without_module_prefix(["pkg", "f"], "src/pkg/__init__.py") == ["f"]
        assert _without_module_prefix(["a"], "src/pkg/a.py") == ["a"]

    def test_a_file_that_does_not_parse_is_reported_not_passed(self) -> None:
        """A cited file in syntax newer than the running Python must not crash the scan, and
        must not pass either: nothing is known about where it defines anything."""
        rule, problem = check_symbol(self._cite("f", 1), "a.py", "def f(:\n    pass\n")
        assert rule == "unparsed" and problem is not None and "does not parse" in problem and "d.md:7" in problem
        assert check_symbol(self._cite("f", 1), "a.py", "def f():\n    pass\n") == ("definition", None)

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

    def test_a_bare_citation_beside_a_name_is_held_to_the_symbol_rule(self) -> None:
        """The #773 shape: ``REF_OPCODES`` (``:1075``), a bare citation on a real, non-blank
        line of the wrong code. Read against the file named before it, then refused, with the
        honest citation of the same name accepted."""
        (cit,) = [c for c in citations_in("d.md", "`a.py:1`. Then `CONSTANT` (`:10`)") if c.bare]
        assert (cit.target, cit.start, cit.symbol) == ("a.py", 10, "CONSTANT")
        assert check_citation(cit, ["a.py"], self._SOURCE.splitlines()) is None, "the premise: line 10 is not blank"
        rule, problem = check_symbol(cit, "a.py", self._SOURCE)
        assert rule == "definition" and problem is not None and "defines it at line(s) 4," in problem
        (honest,) = [c for c in citations_in("d.md", "`a.py:1`. Then `CONSTANT` (`:4`)") if c.bare]
        assert check_symbol(honest, "a.py", self._SOURCE) == ("definition", None)

    # -- keyed table rows -----------------------------------------------------------

    @pytest.mark.parametrize(
        ("row", "keys"),
        [
            ("| `btc_sats` | int | **yes** | `> 0` | `a.py:4, 20` |", ["btc_sats", "btc_sats"]),
            ("| `stall_blocks` (`N`) | 6 | policy | `a.py:4` |", ["stall_blocks"]),
            ("| `RadiantCovenantLeg.min_confirmations` | 1 | `a.py:4` |", ["RadiantCovenantLeg.min_confirmations"]),
            ("| `t_rxd` | blocks | `a.py:4`; `_validate` (`a.py:9`) |", ["t_rxd", "t_rxd"]),
            # Not keyed: the first cell is prose, two names, or the citation itself.
            ("| `ft`/`nft` with an empty ref | `a.py:4` |", [None]),
            ("| **reorg floor** | 2 | `a.py:4` |", [None]),
            ("| `a.py:4` | the file |", [None]),
            ("not a row `btc_sats` `a.py:4`", [None]),
        ],
    )
    def test_a_row_key_is_read_only_from_a_first_cell_holding_one_name(self, row: str, keys: list) -> None:
        assert [c.row_key for c in citations_in("d.md", row) if not c.bare] == keys

    def test_a_row_citation_must_mention_the_key(self) -> None:
        """Occurrence, not definition: ``CONSTANT`` is read at line 20 (a use) as well as 4."""
        for start in (4, 20):
            (cit,) = citations_in("d.md", f"| `CONSTANT` | 1 | `a.py:{start}` |")
            assert check_row_key(cit, "a.py", self._SOURCE) is None
        (cit,) = citations_in("d.md", "| `CONSTANT` | 1 | `a.py:9` |")
        problem = check_row_key(cit, "a.py", self._SOURCE)
        assert problem is not None and "about `CONSTANT`" in problem and "does appear at line(s) 4, 20" in problem
        (cit,) = citations_in("d.md", "| `gone` | 1 | `a.py:9` |")
        problem = check_row_key(cit, "a.py", self._SOURCE)
        assert problem is not None and "appears nowhere" in problem

    def test_a_row_citation_naming_its_own_symbol_is_held_to_that_symbol_instead(self) -> None:
        """``_b32`` (``swap_state.py:N``) in the ``hashlock`` row is about ``_b32``: the symbol rule
        reads it, and the row rule must not also demand ``hashlock`` there."""
        (cit,) = citations_in("d.md", "| `hashlock` | 64-hex | `a.py:4`; `decorated` (`a.py:9`) |")[1:]
        assert (cit.symbol, cit.row_key) == ("decorated", "hashlock")
        assert check_symbol(cit, "a.py", self._SOURCE) == ("definition", None)

    def test_the_drift_from_817_is_refused_against_the_real_file(self) -> None:
        """The shape the row rule exists for, through the production path and the real source.

        The finality table cited ``min_ref_confirmations`` at a line that #817 turned into other
        code. Rebuilt from wherever the field is today: cited at the neighbouring field
        ``maker_stall_safety_window_blocks`` (real, non-blank, wrong) it must pass the blank-line
        gate and be refused here; cited at its own line it must pass both.
        """
        path = "src/pyrxd/gravity/swap_coordinator.py"
        source = (_ROOT / path).read_text(encoding="utf-8")
        defs = {d.qualname: d for d in python_definitions(source)}
        real = defs["CoordinatorConfig.min_ref_confirmations"].first
        wrong = defs["CoordinatorConfig.maker_stall_safety_window_blocks"].first
        (cit,) = citations_in("d.md", f"| `min_ref_confirmations` | 6 | policy | `swap_coordinator.py:{wrong}` |")
        assert check_citation(cit, [path], source.splitlines()) is None, "the blank-line rule was meant to miss this"
        problem = check_row_key(cit, path, source)
        assert problem is not None and str(real) in problem
        (honest,) = citations_in("d.md", f"| `min_ref_confirmations` | 6 | policy | `swap_coordinator.py:{real}` |")
        assert check_row_key(honest, path, source) is None


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
#
# Why not a sentence-level rule ("the cited lines must contain some name the sentence
# mentions")? It was tried on the handshake spec when the row rule was added, after every
# citation in it had been re-checked by hand: it flagged 24 of the 125 citations it could
# read, and all 24 were correct — a citation inside a method the sentence names by its class,
# a range covering a list of fields, a sentence naming five methods and citing the state check
# in each. A gate that is wrong one time in five gets exemptions, and an exemption list is
# where a real failure hides. The keyed-row rule is the part of that idea whose subject is
# unambiguous.

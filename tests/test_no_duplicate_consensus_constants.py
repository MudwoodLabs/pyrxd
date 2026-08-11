"""Guard against a consensus rule being spelled in more than one place.

This is the cheapest defence against the specific failure mode that produced
three bugs in a day. The ref-operand rule was written out by hand in four
walkers; two were right and two were wrong, and nothing in the codebase could
say which. The fix was to centralise it — but centralising is not durable on its
own, because the natural way to write the fifth walker is to type the rule again
rather than import it. Nothing stopped that. This does.

The rule enforced: a consensus constant has exactly ONE assignment, in
``pyrxd.constants``. Everywhere else must import or alias it. Re-spelling the
value — as a literal set, as a range comparison, or as a magic number in a walk
— fails here with a pointer to the canonical name.

These are static checks, not import-time checks, and that is deliberate: a
duplicate definition that happens to be *correct today* still needs to fail,
because the failure mode is the two copies drifting apart later.

Why the re-spelling checks are AST-based
----------------------------------------
They used to match source text with regexes, and text matching lost twice:

* ``op in range(0xD0, 0xD9)``, ``0xD0 <= op < 0xD9`` and ``0xD0 <= op and op < 0xD9``
  all sailed through the banned-range pattern. So did
  ``frozenset(range(0xD0, 0xD9))`` — **the original bug's own spelling**. A guard that
  cannot catch the bug that motivated it is worse than no guard, because it certifies
  safety.
* A new walker written as ``_MY_REF_OPS = (0xD0, 0xD8)`` with ``i += 36`` passed all 31
  guard and parity tests: two opcodes sat under the "three or more" literal threshold,
  and ``+= 36`` is not ``+= 37`` so it missed the walk fingerprint.

The AST does not care how the expression is punctuated, so a comparison is a comparison
however it is spaced, split or reordered. What the AST *adds* is a false-positive
problem — it normalises ``0x00D0`` (a Unicode codepoint in ``glyph/_confusables.py``)
and ``210`` (a length bound in ``tests/network/test_electrumx.py``) into the same
integers as ``0xd0`` and ``0xd2``. So every rule below requires the constant to be
**written** as a two-digit hex byte, via :func:`_is_hex_byte_literal`: AST for
structure, source spelling for intent.

Every detector is a pure function of source text, so
:class:`TestTheGuardCatchesTheBugsThatMotivatedIt` can plant each historical defect
verbatim and prove the guard fires — rather than trusting that it would.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from pyrxd.constants import PUSH_REF_OPCODES, REF_OPERAND_OPCODES, REF_OPERAND_WIDTH

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "pyrxd"
TESTS_ROOT = REPO_ROOT / "tests"

# The one module allowed to state each rule.
CANONICAL_MODULE = SRC_ROOT / "constants.py"

# Test-side files allowed to name the raw opcode bytes: the oracle derives them
# from the vendored C++, and the differentials assert against them explicitly.
# Everything else in tests/ must go through pyrxd.constants or the oracle.
_TEST_ALLOWLIST = {
    "consensus_oracle.py",
    "test_consensus_opcode_parity.py",
    "test_ref_walker_differential.py",
    "test_no_duplicate_consensus_constants.py",
    "test_preimage_differential.py",
    "test_preimage.py",
    "test_glyph.py",
}


def _python_files(root: Path):
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def _strip_comments_and_docstrings(text: str) -> str:
    """Crude but adequate: drop ``#`` comments and triple-quoted blocks.

    Documentation is *supposed* to name these opcodes — the point of the guard
    is to catch executable re-definitions, so prose must not trip it.
    """
    text = re.sub(r'"""(?:.|\n)*?"""', "", text)
    text = re.sub(r"'''(?:.|\n)*?'''", "", text)
    return re.sub(r"#[^\n]*", "", text)


def _rel(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))


# ---------------------------------------------------------------------------
# One assignment per consensus constant
# ---------------------------------------------------------------------------

_GUARDED_NAMES = ["REF_OPERAND_OPCODES", "PUSH_REF_OPCODES", "REF_OPERAND_WIDTH", "MAX_OPCODE"]


class TestSingleDefinition:
    @pytest.mark.parametrize("name", _GUARDED_NAMES)
    def test_constant_is_assigned_exactly_once_in_src(self, name):
        """Only ``pyrxd/constants.py`` may assign it; everyone else imports.

        An alias (``REF_OPCODES = REF_OPERAND_OPCODES``) is fine — it binds a
        second name to the same object and cannot drift. A second *literal* is
        not.
        """
        assignment = re.compile(rf"^\s*{name}\s*(?::[^=\n]+)?=\s*(?P<rhs>.+)$", re.MULTILINE)
        offenders = []
        for path in _python_files(SRC_ROOT):
            body = _strip_comments_and_docstrings(path.read_text(encoding="utf-8"))
            for match in assignment.finditer(body):
                rhs = match.group("rhs").strip()
                if path == CANONICAL_MODULE:
                    continue
                # Re-binding to the canonical object is allowed.
                if re.fullmatch(r"[A-Za-z_][\w.]*", rhs):
                    continue
                offenders.append(f"{_rel(path)}: {name} = {rhs}")
        assert not offenders, (
            f"{name} must be defined once, in src/pyrxd/constants.py, and imported elsewhere. "
            f"Re-definitions found:\n  " + "\n  ".join(offenders)
        )

    def test_canonical_module_defines_all_of_them(self):
        body = CANONICAL_MODULE.read_text(encoding="utf-8")
        for name in _GUARDED_NAMES:
            assert re.search(rf"^{name}\s*[:=]", body, re.MULTILINE), (
                f"{name} is guarded but no longer defined in src/pyrxd/constants.py"
            )


# ---------------------------------------------------------------------------
# No re-spelling of the ref-operand set
# ---------------------------------------------------------------------------

#: A ref opcode byte AS WRITTEN: ``0xd0``..``0xd8``, exactly two hex digits.
#: Requiring the spelling is what keeps ``0x00D0`` (a Unicode codepoint) and ``208``
#: (a decimal length bound) from being read as consensus opcodes by the AST rules.
_REF_OPCODE_BYTE = re.compile(r"\A0[xX][dD][0-9a-fA-F]\Z")

#: The byte range a contiguous test over the ref opcodes would name. ``0xd9`` is
#: included because it is the exclusive upper bound of the range spelling —
#: ``range(0xD0, 0xD9)`` and ``op < 0xD9`` are how the bug is written half the time.
_REF_BAND = range(0xD0, 0xDA)

#: Two is the real threshold, not three: ``(0xD0, 0xD8)`` is a complete re-spelling of
#: ``PUSH_REF_OPCODES``, and it is what the walker that defeated the old guard used.
_RESPELL_THRESHOLD = 2

#: A ref walk advances by the opcode plus its 36-byte operand. Both spellings count —
#: ``i += 37`` in one step, or ``i += 1`` then ``i += 36`` — because the registered
#: ``transaction_preimage.py`` already uses the second and the walker that defeated the
#: old guard used ``+= 36`` precisely to miss a fingerprint that only knew ``37``.
_WALK_STRIDES = frozenset({REF_OPERAND_WIDTH, REF_OPERAND_WIDTH + 1})


def _is_hex_byte_literal(node: ast.AST, source: str) -> bool:
    """Is ``node`` an int constant WRITTEN as a ``0xdN`` byte?"""
    if not isinstance(node, ast.Constant) or not isinstance(node.value, int) or isinstance(node.value, bool):
        return False
    segment = ast.get_source_segment(source, node)
    return bool(segment and _REF_OPCODE_BYTE.match(segment.strip()))


def _hex_ref_opcodes(node: ast.AST, source: str) -> set[int]:
    """The ref-OPERAND opcodes (the real five) spelled as hex bytes anywhere under ``node``."""
    return {
        child.value
        for child in ast.walk(node)
        if _is_hex_byte_literal(child, source) and child.value in REF_OPERAND_OPCODES
    }


def _parse(source: str):
    return ast.parse(source)


def respelled_ref_collections(source: str) -> list[str]:
    """Collection literals that hand-copy the ref-operand set.

    A set/list/tuple display, or a call to a set-shaped builtin, holding
    :data:`_RESPELL_THRESHOLD` or more of the five ref-operand opcodes.
    """
    tree = _parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        is_display = isinstance(node, (ast.Set, ast.List, ast.Tuple))
        is_builder = (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"frozenset", "set", "list", "tuple", "range"}
        )
        if not (is_display or is_builder):
            continue
        found = _hex_ref_opcodes(node, source)
        if len(found) >= _RESPELL_THRESHOLD:
            offenders.append(f"line {node.lineno}: {sorted(hex(v) for v in found)}")
    return offenders


def contiguous_ref_range_tests(source: str) -> list[str]:
    """Contiguous-range tests over the ref opcode band, in ANY spelling.

    Two structures, which between them cover every way to write it:

    * an ordering comparison (``<``/``<=``/``>``/``>=``) against a ``0xdN`` byte in the
      band — this is ``0xd0 <= op <= 0xd8``, ``0xD0 <= op < 0xD9``,
      ``op >= 0xD0 and op <= 0xD8``, and ``0xD0 <= op and op < 0xD9`` alike, because
      each ``and`` operand is simply its own comparison node;
    * a ``range(...)`` whose bounds name the band — ``op in range(0xD0, 0xD9)`` and
      ``frozenset(range(0xD0, 0xD9))``.

    Equality (``!=``/``==``) against a single opcode is NOT flagged: a fixed-layout
    reader asserting "byte 0 is 0xd8" is reading a position, not restating the set.
    """
    tree = _parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            if not any(isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in node.ops):
                continue
            for operand in (node.left, *node.comparators):
                if _is_hex_byte_literal(operand, source) and operand.value in _REF_BAND:
                    offenders.append(f"line {node.lineno}: ordering comparison against {hex(operand.value)}")
                    break
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "range":
            for arg in node.args:
                if _is_hex_byte_literal(arg, source) and arg.value in _REF_BAND:
                    offenders.append(f"line {node.lineno}: range() over {hex(arg.value)}")
                    break
    return offenders


def ref_walk_strides(source: str) -> list[str]:
    """Walk-stride fingerprints (``+= 36`` / ``+= 37`` / ``x + 37``) in a ref-aware file.

    The stride alone is not evidence — ``spv/proof.py`` and ``gravity/trade.py`` step
    over 36-byte outpoints and merkle nodes and have nothing to do with refs. The
    fingerprint is a stride **in a file that also names a ref opcode byte**, which is
    what a hand-rolled walker looks like and what the shared-constant users no longer
    look like.
    """
    tree = _parse(source)
    if not _hex_ref_opcodes(tree, source):
        return []
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
            if isinstance(node.value, ast.Constant) and node.value.value in _WALK_STRIDES:
                offenders.append(f"line {node.lineno}: += {node.value.value}")
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            for side in (node.left, node.right):
                if isinstance(side, ast.Constant) and side.value in _WALK_STRIDES:
                    offenders.append(f"line {node.lineno}: + {side.value}")
                    break
    return offenders


class TestNoRespelledRefOperandSet:
    def test_no_literal_ref_opcode_collection_outside_constants(self):
        offenders = []
        for path in _python_files(SRC_ROOT):
            if path == CANONICAL_MODULE:
                continue
            source = path.read_text(encoding="utf-8")
            offenders += [f"{_rel(path)}: {hit}" for hit in respelled_ref_collections(source)]
        assert not offenders, (
            "a literal collection of ref-operand opcodes was found outside "
            "pyrxd.constants. Import REF_OPERAND_OPCODES instead — four hand-written "
            "copies of this set produced three fund-affecting bugs:\n  " + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize("root_name", ["src", "tests"])
    def test_no_contiguous_range_comparison_over_the_ref_opcodes(self, root_name):
        """Ban ``0xd0 <= op <= 0xd8`` and every other spelling of it, outright.

        This expression is the ``glyph/script.py`` bug: it sweeps in 0xd4-0xd7, which
        carry no operand, so the walk consumes 36 bytes that are not there, fabricates a
        ref, and loses the real one. There is no correct use of it, so it is banned
        rather than reviewed.
        """
        root = REPO_ROOT / root_name
        offenders = []
        for path in _python_files(root):
            if root_name == "tests" and path.name in _TEST_ALLOWLIST:
                continue
            source = path.read_text(encoding="utf-8")
            offenders += [f"{_rel(path)}: {hit}" for hit in contiguous_ref_range_tests(source)]
        assert not offenders, (
            "a contiguous-range test over the ref opcode bytes was found. The "
            "operand-carrying opcodes are NOT a contiguous range — 0xd4-0xd7 sit "
            "inside it and take no operand. Use REF_OPERAND_OPCODES:\n  " + "\n  ".join(offenders)
        )


# ---------------------------------------------------------------------------
# Every ref walker uses the shared constant
# ---------------------------------------------------------------------------

# Modules that walk a script and must consume ref operands. Adding a walker
# without adding it here is caught by test_no_unregistered_ref_walkers below.
_REF_WALKERS = {
    "transaction/transaction_preimage.py",
    "glyph/script.py",
    "glyph/credential_binding.py",
    "glyph/soulbound_detect.py",
    "glyph/soulbound_covenant.py",
    "gravity/htlc_covenant.py",
}


class TestWalkersShareTheConstant:
    @pytest.mark.parametrize("rel_path", sorted(_REF_WALKERS))
    def test_walker_references_the_shared_constant(self, rel_path):
        body = _strip_comments_and_docstrings((SRC_ROOT / rel_path).read_text(encoding="utf-8"))
        assert re.search(r"\bREF_OPERAND_OPCODES\b|\bREF_OPCODES\b", body), (
            f"src/pyrxd/{rel_path} walks scripts but does not reference the shared "
            f"ref-operand constant. Import REF_OPERAND_OPCODES (or the REF_OPCODES alias) "
            f"rather than spelling the rule again."
        )

    def test_walker_registry_is_complete(self):
        """Catch a NEW walker that hard-codes the stride without the shared constant.

        Advancing by 37 (1 opcode + 36 operand bytes), or by 36 after consuming the
        opcode, is the fingerprint of a ref walk. Any file that does that AND names a ref
        opcode byte must be registered above and must use the shared constant, so walker
        number seven cannot repeat the history.
        """
        unregistered = []
        for path in _python_files(SRC_ROOT):
            rel = str(path.relative_to(SRC_ROOT))
            if rel in _REF_WALKERS or path == CANONICAL_MODULE:
                continue
            source = path.read_text(encoding="utf-8")
            hits = ref_walk_strides(source)
            if hits:
                unregistered.append(f"{_rel(path)}: {hits[0]}")
        assert not unregistered, (
            "these files look like they walk ref operands (they name a ref opcode byte "
            "and advance by 36/37) but are not registered in _REF_WALKERS:\n  "
            + "\n  ".join(unregistered)
            + "\nRegister them and make them use REF_OPERAND_OPCODES."
        )


# ---------------------------------------------------------------------------
# The guard, proved against the bugs that motivated it
# ---------------------------------------------------------------------------


#: The four walkers' worth of history, as source. Each string is a defect that shipped
#: (or, for the last two, that a reviewer demonstrated slipping past the old guard).
#: Every one of them MUST be flagged by at least one detector above.
_HISTORICAL_BUGS = {
    "the original set, spelled as a range": "REF = frozenset(range(0xD0, 0xD9))\n",
    "the glyph/script.py range comparison": "def w(op):\n    return 0xd0 <= op <= 0xd8\n",
    "the same comparison, split over `and`": "def w(op):\n    return op >= 0xD0 and op <= 0xD8\n",
    "exclusive upper bound": "def w(op):\n    return 0xD0 <= op < 0xD9\n",
    "exclusive upper bound, split": "def w(op):\n    return 0xD0 <= op and op < 0xD9\n",
    "membership in a range": "def w(op):\n    return op in range(0xD0, 0xD9)\n",
    "membership in a lowercase range": "def w(op):\n    return op in range(0xd0, 0xd9)\n",
    "a hand-copied operand set": "OPS = {0xD0, 0xD1, 0xD2, 0xD3, 0xD8}\n",
    "a hand-copied push-ref pair": "OPS = (0xD0, 0xD8)\n",
    "the same pair as a list": "OPS = [0xd0, 0xd8]\n",
}

#: The reviewer's walker: two opcodes (under the old ">= 3" threshold) and a 36-byte
#: stride (not the ``37`` the old fingerprint knew). It passed all 31 guard and parity
#: tests. Kept whole rather than as fragments because the point is the combination.
_UNREGISTERED_WALKER = """
_MY_REF_OPS = (0xD0, 0xD8)


def walk(script):
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op in _MY_REF_OPS:
            i += 36
    return i
"""


def _any_detector_fires(source: str) -> list[str]:
    return respelled_ref_collections(source) + contiguous_ref_range_tests(source) + ref_walk_strides(source)


class TestTheGuardCatchesTheBugsThatMotivatedIt:
    """Plant each historical defect verbatim and require the guard to fire.

    Without this class the guard asserts only that the tree is clean today, which is
    exactly the state it was in while being blind to six of these ten spellings.
    """

    @pytest.mark.parametrize("label", sorted(_HISTORICAL_BUGS))
    def test_a_planted_historical_bug_is_caught(self, label):
        assert _any_detector_fires(_HISTORICAL_BUGS[label]), (
            f"the guard does not catch {label!r} — a defect it exists to prevent:\n{_HISTORICAL_BUGS[label]}"
        )

    def test_the_walker_that_defeated_the_previous_guard_is_caught(self):
        """Both of its evasions are closed, and each independently."""
        assert respelled_ref_collections(_UNREGISTERED_WALKER), "the 2-opcode tuple must be flagged"
        assert ref_walk_strides(_UNREGISTERED_WALKER), "the 36-byte stride must be flagged"

    def test_the_original_bugs_own_spelling_is_caught(self):
        """``frozenset(range(0xD0, 0xD9))`` — the literal source of the whole incident.

        The old banned-range pattern did not match it. A guard that cannot catch the bug
        that motivated it is worse than none, because it certifies safety.
        """
        assert contiguous_ref_range_tests("REF = frozenset(range(0xD0, 0xD9))\n")


class TestTheGuardDoesNotFireOnLegitimateCode:
    """The other half: a guard nobody can satisfy gets deleted or blanket-allowlisted.

    Each of these is a real shape from this tree that the AST rules must leave alone.
    """

    @pytest.mark.parametrize(
        ("label", "source"),
        [
            ("a fixed-layout reader asserting one opcode", "def f(s, p):\n    return s[p] != 0xD8\n"),
            ("...and its partner", "def f(s, p):\n    return s[p] == 0xD0\n"),
            ("a Unicode codepoint that normalises to 0xd0", "TABLE = {0x00D0: 'D', 0x00D7: 'x', 0x00D8: 'O'}\n"),
            ("a decimal length bound inside the band", "def f(x):\n    return len(x) <= 210\n"),
            ("a 36-byte outpoint step with no ref opcode", "def f(p):\n    p += 36\n    return p\n"),
            ("a walker using the shared constant", "from pyrxd.constants import REF_OPERAND_OPCODES\n"),
            ("one ref opcode named alone", "OP = 0xD8\n"),
        ],
    )
    def test_legitimate_shapes_are_not_flagged(self, label, source):
        assert not _any_detector_fires(source), f"false positive on {label}"


# ---------------------------------------------------------------------------
# Sanity: the constants still hold the values the rest of the suite assumes
# ---------------------------------------------------------------------------


def test_guarded_constants_have_expected_shape():
    """Cheap smoke check so a mangled constants.py fails here with a clear
    message rather than as a confusing cascade elsewhere. The authoritative
    check against Radiant Core is test_consensus_opcode_parity.py."""
    assert PUSH_REF_OPCODES < REF_OPERAND_OPCODES
    assert REF_OPERAND_WIDTH == 36
    assert all(isinstance(o, int) for o in REF_OPERAND_OPCODES)

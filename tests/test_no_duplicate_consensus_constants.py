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


#: The ref-operand WIDTH as a walker would hand-spell it: the width itself, or the
#: width plus the opcode byte. Both are the constant, one addition apart.
_HAND_SPELLED_WIDTHS = frozenset({REF_OPERAND_WIDTH, REF_OPERAND_WIDTH + 1})


#: Per-line opt-out for a ``36``/``37`` that genuinely is not the ref width — a byte
#: OFFSET that happens to equal it, most often. Deliberately narrow: it exempts one
#: line and demands a written reason, so the exception is reviewed rather than a
#: blanket file allowlist. Its correctness is tested both ways below.
_NOT_A_REF_WIDTH = re.compile(r"#\s*not-a-ref-width:\s*\S")


def hand_spelled_ref_widths(source: str) -> list[str]:
    """Bare ``36``/``37`` integer literals in a file that walks ref operands.

    Takes RAW source (comments intact) because the per-line opt-out is a comment.
    Comments are not AST nodes and a docstring saying "36-byte ref" is a ``str``,
    not an ``int``, so neither can trip an integer-constant rule.

    The companion to :func:`ref_walk_strides`, and it exists because that one
    could not see this: it fires only on files naming a ref opcode as a HEX BYTE,
    and every walker in this tree correctly imports ``REF_OPERAND_OPCODES``
    instead — so all six sailed past it while hand-spelling the width.

    That left ``REF_OPERAND_WIDTH`` pinned from Radiant Core and read by exactly
    one module. Mutating it to 35 changed no walker's behaviour, which is the
    same as not having pinned it: a constant with no consumer pins nothing.

    Every spelling counts, not just the stride — ``i += 37``, ``script[p:p+37]``,
    ``len(operand) != 36`` and ``script[p:p+37]`` are all the same number written
    by hand, and any one of them can drift.
    """
    tree = _parse(source)
    lines = source.splitlines()
    offenders: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, int)
            and not isinstance(node.value, bool)
            and node.value in _HAND_SPELLED_WIDTHS
        ):
            # Written as a plain decimal? A hex or otherwise-spelled 36 is not
            # what a hand-rolled walk looks like, and demanding the spelling is
            # how the sibling detectors avoid AST false positives.
            segment = ast.get_source_segment(source, node)
            if not segment or segment.strip() != str(node.value):
                continue
            line = lines[node.lineno - 1] if node.lineno <= len(lines) else ""
            if _NOT_A_REF_WIDTH.search(line):
                continue
            offenders.append(f"line {node.lineno}: bare {node.value}")
    return offenders


class TestWalkersShareTheConstant:
    @pytest.mark.parametrize("rel_path", sorted(_REF_WALKERS))
    def test_walker_references_the_shared_constant(self, rel_path):
        body = _strip_comments_and_docstrings((SRC_ROOT / rel_path).read_text(encoding="utf-8"))
        assert re.search(r"\bREF_OPERAND_OPCODES\b|\bREF_OPCODES\b", body), (
            f"src/pyrxd/{rel_path} walks scripts but does not reference the shared "
            f"ref-operand constant. Import REF_OPERAND_OPCODES (or the REF_OPCODES alias) "
            f"rather than spelling the rule again."
        )

    @pytest.mark.parametrize("rel_path", sorted(_REF_WALKERS))
    def test_walker_does_not_hand_spell_the_operand_width(self, rel_path):
        """The width is a consensus fact too, and it was the one nobody imported."""
        offenders = hand_spelled_ref_widths((SRC_ROOT / rel_path).read_text(encoding="utf-8"))
        assert not offenders, (
            f"src/pyrxd/{rel_path} spells the ref-operand width by hand:\n  "
            + "\n  ".join(offenders)
            + f"\nUse REF_OPERAND_WIDTH (currently {REF_OPERAND_WIDTH}) — it is derived from "
            f"Radiant Core's GetScriptOp by tests/consensus_oracle.py, and a hand-written "
            f"copy is a copy that can disagree with it."
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
# One implementation per primitive
# ---------------------------------------------------------------------------
#
# The ref-operand rule was the first consensus rule found in four copies; it was
# not the last. Each detector below covers a primitive that was independently
# re-implemented somewhere in this tree, and each names the module that owns it.
#
# The shape is deliberately the same every time: find the *spelling* a
# hand-rolled copy has, allow-list the module that is allowed to have it, and
# prove the detector fires by planting the duplicate.

#: primitive -> (owning module relative to src/pyrxd, detector, human name)
#: Entries are consumed by :class:`TestOneImplementationPerPrimitive` and by
#: :class:`TestEachNewDetectorFiresOnAPlantedDuplicate`, so a detector cannot be
#: added without a proof that it works.


def double_sha256_spellings(source: str) -> list[str]:
    """Hand-written ``sha256(sha256(x))``, in any of its spellings.

    Matches the nesting structurally — ``hashlib.sha256(hashlib.sha256(x)
    .digest()).digest()``, ``sha256(sha256(x))`` with locally-bound names, and
    the ``.digest()`` / no-``.digest()`` mixtures in between — because the tree
    contained all three.

    Nineteen sites spelled this out. That was survivable only because they all
    happened to agree; the same nesting written for Radiant's **block** hash is
    ``sha512_256(sha512_256(x))``, and the two are indistinguishable at a glance.
    """
    tree = _parse(source)
    offenders: list[str] = []

    def _sha256_call(node: ast.AST) -> bool:
        """Is ``node`` a call to something named ``sha256`` (however qualified)?"""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "digest":
            # ``<call>.digest()`` — unwrap and test the receiver.
            return _sha256_call(func.value)
        if isinstance(func, ast.Attribute):
            return func.attr == "sha256"
        return isinstance(func, ast.Name) and func.id == "sha256"

    for node in ast.walk(tree):
        if not _sha256_call(node) or not isinstance(node, ast.Call):
            continue
        inner = node.func.value if isinstance(node.func, ast.Attribute) and node.func.attr == "digest" else node
        if not isinstance(inner, ast.Call):
            continue
        for arg in inner.args:
            if _sha256_call(arg):
                offenders.append(f"line {node.lineno}: nested sha256(sha256(...))")
                break
    return offenders


def local_hash_definitions(source: str) -> list[str]:
    """``def hash256`` / ``def _hash256`` / ``def sha256d`` / ``def hash160`` and friends.

    A re-DEFINITION, not a re-binding: ``_hash256 = hash256`` is fine (it is the
    same object and cannot drift), ``def _hash256(...)`` is not.

    ``hash160`` matters as much as ``hash256`` here for a reason that is not
    about drift at all: :mod:`pyrxd.hash` falls back to a pure-Python RIPEMD160
    when OpenSSL refuses it, and three modules that defined their own went
    straight to ``hashlib.new("ripemd160", ...)`` — which raises on every
    OpenSSL-3 distro.

    METHODS ARE EXEMPT. ``PublicKey.hash160()`` is an accessor on a key object —
    an API surface that delegates to the shared function — not a second
    implementation. Functions nested inside other FUNCTIONS are NOT exempt:
    ``glyph/dmint/miner.py`` hid a ``sha256d`` there.
    """
    banned = {"hash256", "_hash256", "sha256d", "_sha256d", "double_sha256", "hash160", "_hash160"}
    tree = _parse(source)
    methods = {
        id(child)
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        for child in node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return [
        f"line {node.lineno}: def {node.name}(...)"
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in banned and id(node) not in methods
    ]


def compact_size_width_tables(source: str) -> list[str]:
    """The ``0xFD``/``0xFE``/``0xFF`` prefix dispatch, written out by hand.

    Any construct naming two or more of the three CompactSize prefix bytes is a
    re-statement of :data:`pyrxd.compactsize.PREFIX_WIDTHS`. Four readers and
    four writers each had their own; three readers rejected non-minimal
    encodings and the fourth accepted them, and nothing could tell.

    Requires the two-digit hex spelling for the same reason the ref detectors do
    — ``253``/``254``/``255`` are ordinary numbers everywhere else in the tree.
    """
    prefixes = {0xFD, 0xFE, 0xFF}
    tree = _parse(source)
    offenders: list[str] = []

    def _named_prefix(child: ast.AST) -> int | None:
        """The CompactSize prefix ``child`` names, if it names one AS a prefix.

        Two spellings, because the tree contained both: the int ``0xFD`` (a
        dispatch on the byte just read) and the one-byte literal ``b"\\xfd"``
        (the byte being written). An encoder written as an ``if``/``elif`` chain
        uses the second almost exclusively, which is how the fourth CompactSize
        writer slipped past the first version of this detector.
        """
        if not isinstance(child, ast.Constant):
            return None
        segment = ast.get_source_segment(source, child)
        if segment is None:
            return None
        segment = segment.strip()
        is_int = isinstance(child.value, int) and not isinstance(child.value, bool)
        if is_int and child.value in prefixes and re.fullmatch(r"0[xX][fF][dDeEfF]", segment):
            return child.value
        is_prefix_byte = isinstance(child.value, bytes) and len(child.value) == 1 and child.value[0] in prefixes
        if is_prefix_byte and re.fullmatch(r"b[\"']\\x[fF][dDeEfF][\"']", segment):
            return child.value[0]
        return None

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Dict, ast.Set, ast.List, ast.Tuple, ast.If, ast.Compare, ast.FunctionDef)):
            continue
        found = {v for child in ast.walk(node) if (v := _named_prefix(child)) is not None}
        if len(found) >= 2:
            offenders.append(f"line {node.lineno}: CompactSize prefixes {sorted(hex(v) for v in found)}")
            break  # one report per file is enough; nested nodes would repeat it
    return offenders


def base58_alphabet_literals(source: str) -> list[str]:
    """The base58 alphabet, retyped.

    Two copies existed, and the WIF decoder each one backed could have come to
    disagree about what a given string decodes to. The alphabet is the
    fingerprint of a third: it is 58 characters nobody types by accident.
    """
    tree = _parse(source)
    return [
        f"line {node.lineno}: base58 alphabet literal"
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, (str, bytes))
        and (node.value if isinstance(node.value, str) else node.value.decode("latin-1")).startswith("123456789ABCDEF")
        and len(node.value) == 58
    ]


#: name -> (detector, module allowed to hold the one implementation, why)
_PRIMITIVE_GUARDS = {
    "double SHA-256": (
        double_sha256_spellings,
        {"hash.py"},
        "import hash256 from pyrxd.hash",
    ),
    "hash256/hash160 definitions": (
        local_hash_definitions,
        {"hash.py"},
        "import hash256/hash160 from pyrxd.hash (an ``x = hash256`` alias is fine)",
    ),
    "CompactSize prefix table": (
        compact_size_width_tables,
        {"compactsize.py"},
        "use pyrxd.compactsize.read_compact_size / encode_compact_size",
    ),
    "base58 alphabet": (
        base58_alphabet_literals,
        {"base58.py", "utils.py"},
        "use pyrxd.base58",
    ),
}

#: Files exempt from a specific detector, each with the reason recorded here AND
#: in the code. These are the deliberate non-consolidations: merging them would
#: be wrong, not merely unnecessary.
_PRIMITIVE_EXEMPTIONS = {
    # The dMint proof-of-work grind. These three run ``sha256(sha256(...))``
    # once per nonce — tens of millions of times per mint — with ``sha256``
    # rebound to a local to skip the attribute lookup. Routing them through a
    # shared function adds a Python call per hash, and ``estimate.py`` is worse
    # than slow: it MEASURES hashes/sec, so the indirection would skew every ETA
    # and difficulty quantile the miner reports to the user. The digest is
    # identical either way; ``tests/test_hash_single_source.py`` pins that.
    "double SHA-256": {
        "contrib/miner/parallel.py",
        "glyph/dmint/estimate.py",
        "glyph/dmint/miner.py",
    },
    # ``utils.py`` keeps ``base58chars`` for ``from_base58``/``to_base58``, a
    # separate list-of-ints API used by the BEEF/BRC-style helpers. Folding it
    # into pyrxd.base58's str-based codec is a real refactor with its own risk,
    # not a de-duplication; recorded rather than done.
    "base58 alphabet": set(),
}


class TestOneImplementationPerPrimitive:
    @pytest.mark.parametrize("primitive", sorted(_PRIMITIVE_GUARDS))
    def test_only_the_owning_module_implements_it(self, primitive):
        detector, owners, remedy = _PRIMITIVE_GUARDS[primitive]
        exempt = _PRIMITIVE_EXEMPTIONS.get(primitive, set())
        offenders = []
        for path in _python_files(SRC_ROOT):
            rel = str(path.relative_to(SRC_ROOT))
            if rel in owners or rel in exempt:
                continue
            source = path.read_text(encoding="utf-8")
            offenders += [f"{_rel(path)}: {hit}" for hit in detector(source)]
        assert not offenders, (
            f"{primitive} is implemented outside {sorted(owners)}:\n  "
            + "\n  ".join(offenders)
            + f"\nThere must be exactly one — {remedy}."
        )

    @pytest.mark.parametrize("primitive", sorted(_PRIMITIVE_GUARDS))
    def test_the_owning_module_still_implements_it(self, primitive):
        """The other half. If the canonical implementation is moved or renamed,
        the guard above silently starts passing on an empty tree."""
        detector, owners, _ = _PRIMITIVE_GUARDS[primitive]
        found = any(detector((SRC_ROOT / owner).read_text(encoding="utf-8")) for owner in owners)
        assert found, (
            f"none of {sorted(owners)} contains an implementation of {primitive} any more. "
            f"Either it moved (update _PRIMITIVE_GUARDS) or the guard is now vacuous."
        )

    def test_every_exemption_names_a_file_that_exists(self):
        """An exemption for a deleted file is a hole nobody notices."""
        missing = [
            f"{primitive}: {rel}"
            for primitive, rels in _PRIMITIVE_EXEMPTIONS.items()
            for rel in rels
            if not (SRC_ROOT / rel).is_file()
        ]
        assert not missing, f"stale exemptions in _PRIMITIVE_EXEMPTIONS: {missing}"


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


# ---------------------------------------------------------------------------
# Every NEW detector, proved by planting the duplicate it exists to catch
# ---------------------------------------------------------------------------

#: (detector, label, source) — each source is the duplicate as it actually
#: appeared in this tree before the consolidation, or as the next person would
#: plausibly write it. An entry here is the only evidence a detector works: the
#: previous version of this guard was blind to the very bug it was written for,
#: and passed a clean tree the whole time.
_PLANTED_DUPLICATES = [
    (
        double_sha256_spellings,
        "the hashlib.new-style spelling from network/bitcoin.py",
        "def _hash256(data):\n    return hashlib.sha256(hashlib.sha256(data).digest()).digest()\n",
    ),
    (
        double_sha256_spellings,
        "the locally-bound spelling from glyph/dmint/miner.py",
        "def sha256d(data):\n    return sha256(sha256(data))\n",
    ),
    (
        double_sha256_spellings,
        "a checksum slice, as in btc_wallet/keys.py",
        "checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]\n",
    ),
    (
        double_sha256_spellings,
        "a from-import spelling nobody has written yet",
        "from hashlib import sha256\nd = sha256(sha256(x).digest()).digest()\n",
    ),
    (
        local_hash_definitions,
        "a private hash256 re-definition",
        "def _hash256(b):\n    return other(b)\n",
    ),
    (
        local_hash_definitions,
        "a hash160 re-definition — the one that had no OpenSSL-3 fallback",
        'def hash160(data):\n    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()\n',
    ),
    (
        local_hash_definitions,
        "a nested sha256d helper",
        "def f():\n    def sha256d(x):\n        return x\n    return sha256d\n",
    ),
    (
        compact_size_width_tables,
        "the width dict from utils.py",
        "W = {0xFD: (2, 0xFC), 0xFE: (4, 0xFFFF), 0xFF: (8, 0xFFFFFFFF)}\n",
    ),
    (
        compact_size_width_tables,
        "the if/elif chain from gravity/transactions.py",
        (
            "def _varint(n):\n"
            "    if n < 0xFD:\n"
            "        return bytes([n])\n"
            "    elif n <= 0xFFFF:\n"
            '        return b"\\xfd" + n.to_bytes(2, "little")\n'
            "    elif n <= 0xFFFFFFFF:\n"
            '        return b"\\xfe" + n.to_bytes(4, "little")\n'
            '    return b"\\xff" + n.to_bytes(8, "little")\n'
        ),
    ),
    (
        compact_size_width_tables,
        "the tolerant size map from btc_wallet/taproot.py — the copy that ACCEPTED non-minimal",
        "def read_compact():\n    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[v]\n    return size\n",
    ),
    (
        base58_alphabet_literals,
        "the bytes alphabet from security/secrets.py",
        '_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\n',
    ),
    (
        base58_alphabet_literals,
        "the str alphabet from base58.py",
        'ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"\n',
    ),
]


class TestEachNewDetectorFiresOnAPlantedDuplicate:
    """A detector that has not been SHOWN to fire is worthless.

    Every entry plants the duplicate into a throwaway source string and requires
    the detector to name it. This is the same discipline as
    :class:`TestTheGuardCatchesTheBugsThatMotivatedIt`, applied to the detectors
    added alongside it.
    """

    @pytest.mark.parametrize(
        ("detector", "label", "source"),
        _PLANTED_DUPLICATES,
        ids=[label for _, label, _ in _PLANTED_DUPLICATES],
    )
    def test_planted_duplicate_is_caught(self, detector, label, source):
        assert detector(source), f"{detector.__name__} does not catch {label!r}:\n{source}"

    def test_every_new_detector_has_at_least_one_planted_proof(self):
        """Adding a detector without a proof is the failure mode this prevents."""
        proved = {detector for detector, _, _ in _PLANTED_DUPLICATES}
        unproved = {detector for detector, _, _ in _PRIMITIVE_GUARDS.values()} - proved
        assert not unproved, (
            f"these detectors have no planted-duplicate proof: {sorted(d.__name__ for d in unproved)}. "
            f"Add one to _PLANTED_DUPLICATES — an unproved detector may pass a clean tree while "
            f"being blind to the duplicate it exists to catch."
        )


class TestTheNewDetectorsDoNotFireOnLegitimateCode:
    """The other half, again: a guard nobody can satisfy gets allowlisted away."""

    @pytest.mark.parametrize(
        ("detector", "label", "source"),
        [
            (double_sha256_spellings, "a single sha256", "d = hashlib.sha256(x).digest()\n"),
            (double_sha256_spellings, "sha256 then ripemd160", "d = hashlib.new('ripemd160', sha256(x))\n"),
            (
                double_sha256_spellings,
                "the SHA-512/256 block hash — a DIFFERENT function, and it must stay one",
                "once = hashlib.new('sha512_256', h).digest()\ntwice = hashlib.new('sha512_256', once).digest()\n",
            ),
            (double_sha256_spellings, "sha256 of a concatenation of two digests", "d = sha256(a_digest + b_digest)\n"),
            (local_hash_definitions, "an alias, which cannot drift", "_hash256 = hash256\n"),
            (local_hash_definitions, "an unrelated function", "def hash_payload(b):\n    return hash256(b)\n"),
            (compact_size_width_tables, "one prefix named alone", "if first == 0xFD:\n    pass\n"),
            (compact_size_width_tables, "decimal 253/254/255", "LIMITS = (253, 254, 255)\n"),
            (compact_size_width_tables, "a 0xff byte mask", "masked = value & 0xFF\n"),
            (base58_alphabet_literals, "a 58-char string that is not the alphabet", f'S = "{"a" * 58}"\n'),
            (base58_alphabet_literals, "the alphabet's prefix only", 'S = "123456789ABCDEF"\n'),
        ],
    )
    def test_legitimate_shapes_are_not_flagged(self, detector, label, source):
        assert not detector(source), f"{detector.__name__} false-positives on {label}"


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

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

The three questions each detector has to answer
-----------------------------------------------
The sections below grew as the failure mode was found in new shapes, and each
addition had to answer the same three questions. They are worth stating once,
because a fourth section will have to answer them too.

**What is the OWNER?** Sometimes a constant in ``pyrxd.constants``; sometimes a
*derivation* that lives elsewhere — ``relay_floor_photons_per_byte()``,
``BTC_MAX_SATS`` as ``supply x subunit``, ``SEQUENCE_FINAL - 1``. Where the owner is
a derivation, "does ``constants.py`` still spell this number" cannot be the
not-vacuous check; ``TestDerivedRulesAreNotRetyped.test_the_owning_derivations_still_exist``
asserts each is still *computed from its inputs* instead.

**Is the ban SATISFIABLE, and where?** A blanket ban on ``10_000`` or ``768`` is not
— 10,000 is also a basis-point denominator, 768 a legitimate registry datum — so the
narrow detectors key on the value AND the role the site puts it in. Scope differs per
detector for measured reasons, not by default: the value scan skips ``tests`` (19
legitimate ``500_000_000`` amounts) but covers ``scripts`` and ``examples``, which had
no such collisions and had been excluded only by where the scan happened to start.

**How is it PROVED?** Two ways, and both are required. A detector must fire on a
planted duplicate (:class:`TestEachNewDetectorFiresOnAPlantedDuplicate`) and must NOT
fire on the coincidental shapes (:class:`TestTheNewDetectorsDoNotFireOnLegitimateCode`)
— the second is what stops a guard nobody can satisfy from being allowlisted away, and
it is where the deliberate non-consolidations are recorded as executable claims rather
than as comments. Where a guard uses object identity rather than source text, the
premise that makes identity meaningful is asserted too, not assumed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from pyrxd.constants import (
    DUST_THRESHOLD_PHOTONS,
    LOCKTIME_THRESHOLD,
    MAX_SCRIPT_ELEMENT_SIZE,
    MAX_SCRIPT_ELEMENT_SIZE_LEGACY,
    PUSH_REF_OPCODES,
    REF_OPERAND_OPCODES,
    REF_OPERAND_WIDTH,
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_ENABLED,
)
from pyrxd.eth_wallet.chains import ETH_FINALIZATION_WINDOW_FLOOR_S
from pyrxd.fee_sizing import relay_floor_photons_per_byte
from pyrxd.security.types import BTC_MAX_SATS, RADIANT_MAX_PHOTONS

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "pyrxd"
TESTS_ROOT = REPO_ROOT / "tests"
SCRIPTS_ROOT = REPO_ROOT / "scripts"
EXAMPLES_ROOT = REPO_ROOT / "examples"

#: The roots a VALUE scan covers. ``tests`` is deliberately absent — see
#: :meth:`TestNoRespelledCentralisedValue.test_no_second_literal`. ``scripts`` and
#: ``examples`` are present because they were the tree's remaining blind spot: the
#: value guard was ``src``-only, and five hand-written ``546``s were sitting in
#: shipped examples and mainnet run scripts the whole time it was passing. An example
#: is a file people COPY, so a literal there propagates into code this repo will
#: never see.
_VALUE_SCAN_ROOTS = {"src": SRC_ROOT, "scripts": SCRIPTS_ROOT, "examples": EXAMPLES_ROOT}

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

#: The ref-opcode names the guard was written for, plus the consensus numbers
#: #418 and #419 centralised. Adding a name here is cheap and worth doing — but
#: it is NOT sufficient on its own, and REG-2 is the proof: a second copy of
#: ``LOCKTIME_THRESHOLD`` survived that consolidation spelled
#: ``LOCKTIME_HEIGHT_THRESHOLD``, and this check builds its pattern FROM the
#: name, so it looked straight past it. The value guard below is what closes
#: that; both are needed, and neither subsumes the other.
_GUARDED_NAMES = [
    "REF_OPERAND_OPCODES",
    "PUSH_REF_OPCODES",
    "REF_OPERAND_WIDTH",
    "MAX_OPCODE",
    "LOCKTIME_THRESHOLD",
    "DUST_THRESHOLD_PHOTONS",
    "MAX_SCRIPT_ELEMENT_SIZE",
    "MAX_SCRIPT_ELEMENT_SIZE_LEGACY",
    "MAX_SCRIPT_SIZE",
    "MAX_OPS_PER_SCRIPT",
    "MAX_STACK_SIZE",
    "MAX_OP_RETURN_MSG_BYTES",
    "SEQUENCE_LOCKTIME_ENABLED",
]


class TestSingleDefinition:
    @pytest.mark.parametrize("name", _GUARDED_NAMES)
    @pytest.mark.parametrize("root_name", ["src", "tests"])
    def test_constant_is_assigned_exactly_once(self, name, root_name):
        """Only ``pyrxd/constants.py`` may assign it; everyone else imports.

        An alias (``REF_OPCODES = REF_OPERAND_OPCODES``) is fine — it binds a
        second name to the same object and cannot drift. A second *literal* is
        not.

        ``tests`` is in scope as well as ``src``. It used to be src-only, which
        left the fixtures free to re-type the very numbers the shipped code is
        forbidden to re-type — and a test asserting against its own second copy
        of a constant passes whatever the first copy says. The oracle and
        differential files are allowlisted because deriving the values from the
        vendored C++ is their entire job.
        """
        root = REPO_ROOT / root_name
        assignment = re.compile(rf"^\s*{name}\s*(?::[^=\n]+)?=\s*(?P<rhs>.+)$", re.MULTILINE)
        offenders = []
        for path in _python_files(root):
            if path == CANONICAL_MODULE or (root_name == "tests" and path.name in _TEST_ALLOWLIST):
                continue
            body = _strip_comments_and_docstrings(path.read_text(encoding="utf-8"))
            for match in assignment.finditer(body):
                rhs = match.group("rhs").strip()
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
# No re-spelling of a centralised VALUE, under any name
# ---------------------------------------------------------------------------
#
# The check above builds its pattern from a NAME, so it can only find a copy
# that agreed to be called the same thing. REG-2 is what that misses:
#
#     src/pyrxd/constants.py:543          LOCKTIME_THRESHOLD       = 500_000_000
#     src/pyrxd/swap/rswp/covenant.py:79  LOCKTIME_HEIGHT_THRESHOLD = 500_000_000
#
# Two independent literals — ``LOCKTIME_THRESHOLD is LOCKTIME_HEIGHT_THRESHOLD``
# was False — and adding ``LOCKTIME_HEIGHT_THRESHOLD`` to ``_GUARDED_NAMES``
# would not have helped either, because then the guard looks for THAT spelling
# and the next copy picks a third. The only property both copies share is the
# number, so the number is what this looks for.
#
# The asymmetry that made it worth finding: ``constants.py``'s copy is pinned to
# the vendored ``script.h:90`` by ``test_consensus_opcode_parity.py``, and the
# second copy was pinned to nothing. Drifting it DOWN to 400_000_000 was caught
# by two boundary vectors; drifting it UP to 600_000_000 passed the entire
# offline suite.
#
# Values, not names, and derived from ``pyrxd.constants`` rather than retyped —
# a guard that spells the number itself is one more copy of the number.

#: value -> the canonical name(s) that hold it. Several script limits share
#: 32_000_000, so the label names all of them.
_GUARDED_VALUES: dict[int, str] = {
    LOCKTIME_THRESHOLD: "LOCKTIME_THRESHOLD",
    DUST_THRESHOLD_PHOTONS: "DUST_THRESHOLD_PHOTONS",
    MAX_SCRIPT_ELEMENT_SIZE_LEGACY: "MAX_SCRIPT_ELEMENT_SIZE_LEGACY",
    MAX_SCRIPT_ELEMENT_SIZE: "MAX_SCRIPT_ELEMENT_SIZE / MAX_SCRIPT_SIZE / MAX_OPS_PER_SCRIPT / MAX_STACK_SIZE",
}

#: Files allowed to spell a guarded value, each a deliberate non-consolidation
#: recorded BOTH here and at the site. Merging these would be wrong, not merely
#: unnecessary.
_VALUE_EXEMPTIONS: dict[int, set[str]] = {
    # Bitcoin's dust limit is 546 satoshis and Radiant's policy floor is 546
    # photons; the same number expresses two unrelated rules on two chains, and
    # ``btc_wallet/payment.py`` says so in five lines of comment ending "Two
    # chains, two rules; do not alias them." Aliasing them would make a change
    # to Radiant policy silently move Bitcoin's dust limit.
    DUST_THRESHOLD_PHOTONS: {"btc_wallet/payment.py"},
}

#: A plain decimal integer, with or without ``_`` grouping. Hex and binary are
#: NOT this: ``glyph/_confusables.py`` holds the Unicode codepoint ``0x0222``,
#: which is 546, and a mask written ``0xFF`` is not a length limit. Same
#: "AST for structure, source spelling for intent" rule the ref detectors use.
_DECIMAL_INT = re.compile(r"\d[\d_]*")


def respelled_centralised_value(source: str) -> list[str]:
    """Any guarded consensus value, written out as a decimal literal.

    Deliberately flags the value ANYWHERE, not just on the right-hand side of an
    assignment: ``if height >= 500_000_000:`` is the same rule re-typed, and it
    drifts exactly as easily as a named copy does.
    """
    tree = _parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or isinstance(node.value, bool) or not isinstance(node.value, int):
            continue
        name = _GUARDED_VALUES.get(node.value)
        if name is None:
            continue
        segment = ast.get_source_segment(source, node)
        if segment is None or not _DECIMAL_INT.fullmatch(segment.strip()):
            continue
        offenders.append(f"line {node.lineno}: {segment.strip()} is {name}")
    return offenders


class TestNoRespelledCentralisedValue:
    @pytest.mark.parametrize("value", sorted(_GUARDED_VALUES))
    @pytest.mark.parametrize("root_name", sorted(_VALUE_SCAN_ROOTS))
    def test_no_second_literal(self, value, root_name):
        """``src``, ``scripts`` and ``examples`` — but NOT ``tests``.

        ``tests`` is measured to hold 19 legitimate ``500_000_000`` photon amounts
        (5 RXD is a natural fixture size) plus boundary vectors like
        ``2_100_000_000_000_001``, so a value scan there would be unsatisfiable —
        which is why the NAME check above is the one that covers ``tests``. The two
        guards have different blind spots on purpose.

        ``scripts`` and ``examples`` used to share ``tests``' exemption by accident
        rather than by argument: the scan simply started at ``src`` and stopped
        there. They hold no such legitimate collisions — measured, five hits, all
        five a hand-written dust floor — so there was never a reason to exclude
        them, and every reason not to: ``examples`` is the code readers copy.
        """
        root = _VALUE_SCAN_ROOTS[root_name]
        name = _GUARDED_VALUES[value]
        # Exemptions are recorded relative to ``src``; the other roots have none.
        exempt = _VALUE_EXEMPTIONS.get(value, set()) if root_name == "src" else set()
        offenders = []
        for path in _python_files(root):
            rel = str(path.relative_to(root))
            if path == CANONICAL_MODULE or rel in exempt:
                continue
            source = path.read_text(encoding="utf-8")
            offenders += [f"{_rel(path)}: {hit}" for hit in respelled_centralised_value(source)]
        # Another value's literal in this file is that value's failure, not this one's.
        offenders = [o for o in offenders if o.endswith(name)]
        assert not offenders, (
            f"{name} is spelled out again outside src/pyrxd/constants.py:\n  "
            + "\n  ".join(offenders)
            + f"\nImport it — `from ...constants import {name.split(' / ')[0]}` — and alias if a local "
            "name reads better. A second literal inherits none of the pins the canonical one carries."
        )

    def test_the_canonical_module_still_spells_each_value(self):
        """The other half. If ``constants.py`` stops holding these numbers, the
        scan above starts passing on a tree that lost the constant entirely."""
        source = CANONICAL_MODULE.read_text(encoding="utf-8")
        found = {hit.split(" is ")[1] for hit in respelled_centralised_value(source)}
        missing = sorted(set(_GUARDED_VALUES.values()) - found)
        assert not missing, f"src/pyrxd/constants.py no longer spells: {missing} — the value guard is now vacuous"

    def test_every_value_exemption_names_a_file_that_exists(self):
        missing = [
            f"{value}: {rel}"
            for value, rels in _VALUE_EXEMPTIONS.items()
            for rel in rels
            if not (SRC_ROOT / rel).is_file()
        ]
        assert not missing, f"stale exemptions in _VALUE_EXEMPTIONS: {missing}"

    def test_every_exemption_still_holds_the_value_it_is_exempt_for(self):
        """An exemption that no longer covers anything is a standing hole.

        If ``btc_wallet/payment.py`` ever stops spelling 546, the exemption must
        go with it — otherwise it silently licenses the NEXT copy to appear there.
        """
        stale = [
            f"{value}: {rel}"
            for value, rels in _VALUE_EXEMPTIONS.items()
            for rel in rels
            if not any(
                hit.endswith(_GUARDED_VALUES[value])
                for hit in respelled_centralised_value((SRC_ROOT / rel).read_text(encoding="utf-8"))
            )
        ]
        assert not stale, f"these exemptions no longer cover anything: {stale}"


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


# ---------------------------------------------------------------------------
# Rules that are DERIVED somewhere, and were written out by hand anyway
# ---------------------------------------------------------------------------
#
# The detectors above cover values that live in ``pyrxd.constants``. These four
# cover the other half of the same failure mode: a rule that already has an owner
# — a function that computes it, or a constant in the module that owns the
# subject — and a second copy typed out somewhere the owner was not imported.
#
# Each one exists because the sweep found live copies, and each is deliberately
# NARROW. A blanket ban on the underlying number would be unsatisfiable and would
# be allow-listed away within a release: 10_000 is also a basis-point denominator
# and a dust ceiling, 768 is also a legitimate registry datum. So each detector
# keys on the number AND on the role the site puts it in, which is what separates
# "the rule, restated" from "the same integer, for an unrelated reason".


def _decimal_int_constant(node: ast.AST, source: str, wanted: int) -> bool:
    """Is ``node`` the int ``wanted``, WRITTEN as a plain decimal literal?

    Same "AST for structure, source spelling for intent" rule the ref detectors
    use, for the same reason: ``0x0300`` is 768 and has nothing to do with
    Ethereum finality.
    """
    if not isinstance(node, ast.Constant) or isinstance(node.value, bool) or not isinstance(node.value, int):
        return False
    if node.value != wanted:
        return False
    segment = ast.get_source_segment(source, node)
    return bool(segment and _DECIMAL_INT.fullmatch(segment.strip()))


#: Every node type that BINDS a name to a value. ``NamedExpr`` (the walrus) is in the
#: list because an edge-case sweep found it was the one spelling that slipped past:
#: ``if (fee_rate := 10_000) > 0:`` binds the rule exactly as an assignment does, and a
#: detector that only knew ``Assign``/``AnnAssign`` reported the file clean.
_BINDING_NODES = (ast.Assign, ast.AnnAssign, ast.NamedExpr)


def _binding_name(node: ast.AST) -> str | None:
    """The name a statement binds, for the statement kinds a constant hides in."""
    if isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and isinstance(node.target, ast.Name):
        return node.target.id
    if isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name):
                return t.id
            if isinstance(t, ast.Attribute):
                return t.attr
    return None


def respelled_relay_floor(source: str) -> list[str]:
    """Radiant's per-BYTE relay floor, typed out as a fee rate.

    The owner is :func:`pyrxd.fee_sizing.relay_floor_photons_per_byte`, and
    ``glyph.builder``, ``glyph.ft``, ``glyph.dmint.miner`` and ``wallet`` all bind
    their default to that call. Four sites did not: both CLI config defaults, the
    ``CliContext`` field, and ``build_dmint_mint_tx``'s parameter.

    Why the floor moving is not hypothetical: Radiant ships TWO floors, the legacy
    ``LEGACY_MIN_RELAY_TX_FEE_PER_KB`` and the post-2.0
    ``RADIANT_CORE_2_MIN_RELAY_TX_FEE_PER_KB``, and ``GetEffectiveMinRelayFee``
    already switched between them once — a 10x step. A stale literal on a *default*
    is the worst place for it: nobody passed the value, so nobody reviews it, and
    Radiant has neither RBF nor CPFP, so the resulting transaction cannot be
    bumped. It holds its inputs until mempool expiry.

    NARROW BY DESIGN. It fires only where the number is playing the role of a fee
    rate — a binding, parameter default, or dict entry whose NAME says ``fee_rate``.
    ``_BPS_DENOMINATOR = 10_000`` (basis points) and
    ``MAINNET_DUST_CEILING_PHOTONS = 10_000`` are the same integer for unrelated
    reasons and must not be swept in; both are proved unflagged below.
    """
    floor = relay_floor_photons_per_byte()
    tree = _parse(source)
    offenders: list[str] = []

    def _is_fee_rate(name: str | None) -> bool:
        return bool(name) and "fee_rate" in name.lower()

    for node in ast.walk(tree):
        if isinstance(node, _BINDING_NODES):
            name = _binding_name(node)
            if _is_fee_rate(name) and node.value is not None and _decimal_int_constant(node.value, source, floor):
                offenders.append(f"line {node.lineno}: {name} = {floor}")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            a = node.args
            positional = a.posonlyargs + a.args
            for arg, default in zip(positional[len(positional) - len(a.defaults) :], a.defaults, strict=True):
                if _is_fee_rate(arg.arg) and _decimal_int_constant(default, source, floor):
                    offenders.append(f"line {default.lineno}: parameter {arg.arg}={floor}")
            for arg, default in zip(a.kwonlyargs, a.kw_defaults, strict=True):
                if default is not None and _is_fee_rate(arg.arg) and _decimal_int_constant(default, source, floor):
                    offenders.append(f"line {default.lineno}: parameter {arg.arg}={floor}")
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                is_fee_key = isinstance(key, ast.Constant) and isinstance(key.value, str) and _is_fee_rate(key.value)
                if is_fee_key and _decimal_int_constant(value, source, floor):
                    offenders.append(f'line {value.lineno}: "{key.value}": {floor}')
    return offenders


def respelled_non_final_sequence(source: str) -> list[str]:
    """``0xFFFFFFFE`` — :data:`pyrxd.constants.SEQUENCE_LOCKTIME_ENABLED` — retyped.

    An input is final iff ``nSequence == SEQUENCE_FINAL``, and a transaction whose
    inputs are all final skips ``nLockTime`` altogether. So every CLTV spend and
    every BIP68-evaluated refund in this SDK needs exactly this value, and three
    of them wrote it out: the RSWP refund, the Gravity ``forfeit()`` CLTV input,
    and the HTLC refund's fee input.

    The one-character slip to ``0xFFFFFFFF`` is silent at build time and fatal at
    spend time — the refund branch simply stops being satisfiable, on a chain with
    no RBF and no CPFP, in the path a stalled counterparty makes load-bearing.

    Any spelling counts here, unlike the ref-opcode detectors: there is no
    plausible unrelated 4294967294 in this tree, so requiring the hex form would
    only leave the decimal one as a way through. ``SEQUENCE_FINAL - 1`` is a
    ``BinOp``, not a constant, so the canonical derivation does not trip it.
    """
    tree = _parse(source)
    return [
        f"line {node.lineno}: {ast.get_source_segment(source, node) or node.value} is SEQUENCE_LOCKTIME_ENABLED"
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and not isinstance(node.value, bool)
        and isinstance(node.value, int)
        and node.value == SEQUENCE_LOCKTIME_ENABLED
    ]


def respelled_money_supply_cap(source: str) -> list[str]:
    """A chain's ``MAX_MONEY``, written out instead of imported.

    ``pyrxd.security.types`` owns both, and derives each as ``supply x subunit``
    rather than as a flat literal — so a bare ``2_100_000_000_000_000`` anywhere is
    a second copy by construction.

    This one is not about drift, because a supply cap does not change. It is about
    which CHAIN the number belongs to. ``security/types.py`` records what that
    costs: Bitcoin's cap was applied to Radiant amounts, where the real limit is a
    thousand times larger, and one legitimate UTXO above 21,000,000 RXD then raised
    inside a list comprehension, took every sibling UTXO on the address with it,
    and surfaced as a transport fault that evicted healthy endpoints. An anonymous
    literal is precisely the copy that gets pasted onto the wrong chain, because
    nothing about it says which chain it came from.
    """
    caps = {BTC_MAX_SATS: "BTC_MAX_SATS", RADIANT_MAX_PHOTONS: "RADIANT_MAX_PHOTONS"}
    tree = _parse(source)
    return [
        f"line {node.lineno}: {ast.get_source_segment(source, node)} is {caps[node.value]}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and not isinstance(node.value, bool)
        and isinstance(node.value, int)
        and node.value in caps
        and _decimal_int_constant(node, source, node.value)
    ]


#: A name that declares a LOWER BOUND rather than a measurement: ``_FLOOR_S`` and
#: ``_MIN_ETH_FINALIZATION_WINDOW_S``, the two spellings the duplicate actually used.
_FLOOR_SHAPED_NAME = re.compile(r"floor|min.*final|final.*min", re.IGNORECASE)


def restated_eth_finalization_floor(source: str) -> list[str]:
    """The 2-epoch ETH finality FLOOR, declared a second time under a floor name.

    :data:`pyrxd.eth_wallet.chains.ETH_FINALIZATION_WINDOW_FLOOR_S` owns it. It was
    two literals joined by a ``# Keep in sync with ...`` comment — which is this
    whole failure mode written down in the source: the comment names the obligation
    and supplies nothing that can discharge it. Both copies gate the SAME rule at
    different boundaries (registry construction, ``MarginPolicy`` construction), so
    raising one for a real consensus change and missing the other leaves a
    cross-chain swap claiming against a finalization reserve the chain no longer
    honours — which is the reorg gate's entire purpose.

    Keyed on a FLOOR-shaped name, not on the number. ``EvmChain(...,
    finalization_window_s=768)`` in the registry is Ethereum L1's actual window —
    data, not the rule — and collapsing the two would couple "what this chain does"
    to "what we refuse to go below". Proved unflagged below.

    "Floor-shaped" covers both spellings the two copies actually used: ``_FLOOR_S``
    and ``_MIN_ETH_FINALIZATION_WINDOW_S``. A guard keyed on only the first would
    have missed the second — which is the same mistake ``_GUARDED_NAMES`` made with
    ``LOCKTIME_HEIGHT_THRESHOLD``, one section up.
    """
    tree = _parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, _BINDING_NODES):
            continue
        name = _binding_name(node)
        if not name or not _FLOOR_SHAPED_NAME.search(name):
            continue
        if node.value is not None and _decimal_int_constant(node.value, source, ETH_FINALIZATION_WINDOW_FLOOR_S):
            offenders.append(f"line {node.lineno}: {name} = {ETH_FINALIZATION_WINDOW_FLOOR_S}")
    return offenders


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
# The derived-rule detectors, run over the tree
# ---------------------------------------------------------------------------

#: rule -> (detector, scan roots, the remedy to print). ``tests`` is out of scope for
#: all four for the reason given on
#: :meth:`TestNoRespelledCentralisedValue.test_no_second_literal`: a test that
#: asserts against an INDEPENDENTLY spelled expected value is doing its job, and is
#: the only thing that can catch the canonical constant being mutated.
_DERIVED_RULE_GUARDS = {
    "Radiant's per-byte relay floor": (
        respelled_relay_floor,
        ("src", "scripts", "examples"),
        "bind it to pyrxd.fee_sizing.relay_floor_photons_per_byte() — as glyph.builder, "
        "glyph.ft, glyph.dmint.miner, wallet and cli.config all do",
    ),
    "the non-final nSequence": (
        respelled_non_final_sequence,
        ("src", "scripts", "examples"),
        "import SEQUENCE_LOCKTIME_ENABLED from pyrxd.constants",
    ),
    "a chain's MAX_MONEY": (
        respelled_money_supply_cap,
        ("src", "scripts", "examples"),
        "import BTC_MAX_SATS or RADIANT_MAX_PHOTONS from pyrxd.security.types — and "
        "pick by CHAIN, never by which name reads better",
    ),
    "the ETH 2-epoch finality floor": (
        restated_eth_finalization_floor,
        ("src",),
        "import ETH_FINALIZATION_WINDOW_FLOOR_S from pyrxd.eth_wallet.chains",
    ),
}

#: Files allowed to hold one of these, each a deliberate non-consolidation.
#: Empty today: every site the sweep found was a real duplicate, and every one was
#: consolidated. Kept as the recorded place for the first genuine exception.
_DERIVED_RULE_EXEMPTIONS: dict[str, set[str]] = {}


class TestDerivedRulesAreNotRetyped:
    @pytest.mark.parametrize("rule", sorted(_DERIVED_RULE_GUARDS))
    def test_no_hand_written_copy(self, rule):
        detector, root_names, remedy = _DERIVED_RULE_GUARDS[rule]
        exempt = _DERIVED_RULE_EXEMPTIONS.get(rule, set())
        offenders = []
        for root_name in root_names:
            root = _VALUE_SCAN_ROOTS[root_name]
            for path in _python_files(root):
                if path == CANONICAL_MODULE or str(path.relative_to(root)) in exempt:
                    continue
                source = path.read_text(encoding="utf-8")
                offenders += [f"{_rel(path)}: {hit}" for hit in detector(source)]
        assert not offenders, (
            f"{rule} is written out by hand:\n  " + "\n  ".join(offenders) + f"\nInstead: {remedy}. "
            "A second literal inherits none of the pins the canonical one carries."
        )

    def test_the_owning_derivations_still_exist(self):
        """The other half. Each of these guards is vacuous if the owner is gone,
        and unlike the ``constants.py`` values these owners are DERIVED expressions
        — so 'does the canonical module still spell the number' cannot be the check.
        What must hold is that each is still computed from its inputs."""
        assert relay_floor_photons_per_byte() * 1000 == 10_000_000, (
            "the relay floor is no longer derived from RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB"
        )
        assert SEQUENCE_LOCKTIME_ENABLED == SEQUENCE_FINAL - 1, (
            "SEQUENCE_LOCKTIME_ENABLED must stay derived from SEQUENCE_FINAL, not become its own literal"
        )
        assert ETH_FINALIZATION_WINDOW_FLOOR_S == 2 * 32 * 12, "the ETH floor is no longer 2 epochs x 32 slots x 12 s"
        types_src = (SRC_ROOT / "security" / "types.py").read_text(encoding="utf-8")
        for name in ("BTC_MAX_SATS", "RADIANT_MAX_PHOTONS"):
            assert re.search(rf"^{name}: int = [\d_]+ \* [\d_]+$", types_src, re.MULTILINE), (
                f"{name} must stay a supply x subunit product. Flattening it to one literal makes "
                f"respelled_money_supply_cap unable to tell the definition from a copy."
            )

    def test_the_eth_floor_has_exactly_one_definition(self):
        """``restated_eth_finalization_floor`` keys on a name, so it cannot see a
        copy that picks a third spelling — the same blind spot ``_GUARDED_NAMES``
        has. This closes it from the other side: the coordinator's floor must BE
        the chains module's object, not merely equal to it."""
        from pyrxd.gravity import swap_coordinator

        assert swap_coordinator._MIN_ETH_FINALIZATION_WINDOW_S is ETH_FINALIZATION_WINDOW_FLOOR_S, (
            "MarginPolicy's ETH finalization floor is no longer the same object as "
            "pyrxd.eth_wallet.chains.ETH_FINALIZATION_WINDOW_FLOOR_S — it has been given its own "
            "literal again, and the two can now drift apart silently."
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
    (
        respelled_centralised_value,
        "REG-2 verbatim: the locktime threshold under a DIFFERENT name",
        "LOCKTIME_HEIGHT_THRESHOLD = 500_000_000\n",
    ),
    (
        respelled_centralised_value,
        "the same value with no underscores, which grep for `500_000_000` misses",
        "THRESHOLD = 500000000\n",
    ),
    (
        respelled_centralised_value,
        "no name at all — the rule re-typed inline, which a name-based guard cannot see",
        "def is_height(locktime):\n    return locktime < 500_000_000\n",
    ),
    (
        respelled_centralised_value,
        "a second dust floor",
        "_MIN_CHANGE = 546\n",
    ),
    (
        respelled_centralised_value,
        "a hand-typed script-element cap",
        "MAX_PUSH = 32_000_000\n",
    ),
    # --- the relay floor, in each of the four shapes the sweep actually found ---
    (
        respelled_relay_floor,
        "cli/config.py's _DEFAULTS entry — a dict value under a 'fee_rate' key",
        '_DEFAULTS = {"network": "mainnet", "fee_rate": 10_000, "coin_type": 512}\n',
    ),
    (
        respelled_relay_floor,
        "cli/config.py's dataclass field — the one load() validates against the floor",
        "@dataclass\nclass Config:\n    fee_rate: int = 10_000\n",
    ),
    (
        respelled_relay_floor,
        "cli/context.py's field — the one NOTHING validates, so it fails open",
        "@dataclass\nclass CliContext:\n    fee_rate: int = 10_000\n",
    ),
    (
        respelled_relay_floor,
        "build_dmint_mint_tx's parameter default — a lost PoW grind if it goes stale",
        "def build_dmint_mint_tx(utxo, nonce, pkh, current_time, fee_rate: int = 10_000):\n    return utxo\n",
    ),
    (
        respelled_relay_floor,
        "a keyword-only parameter default, which the positional zip alone would miss",
        "def build(*, fee_rate: int = 10_000):\n    return fee_rate\n",
    ),
    (
        respelled_relay_floor,
        "examples/dmint_v1_deploy_demo.py's module constant, under a DIFFERENT name",
        "MIN_FEE_RATE = 10_000  # photons per byte\n",
    ),
    (
        respelled_relay_floor,
        "the same value with no underscores, which a grep for `10_000` misses",
        "DEFAULT_FEE_RATE = 10000\n",
    ),
    (
        respelled_relay_floor,
        "a walrus binding — found by sweeping the detector's own edge cases, not the tree",
        "if (fee_rate := 10_000) > 0:\n    pass\n",
    ),
    (
        respelled_relay_floor,
        "an attribute target, which a Name-only binding check would miss",
        "class C:\n    def __init__(self):\n        self.fee_rate = 10_000\n",
    ),
    (
        restated_eth_finalization_floor,
        "the same floor bound by a walrus",
        "if (_min_eth_finalization_window := 768) > 0:\n    pass\n",
    ),
    # --- the non-final nSequence, in both spellings ---
    (
        respelled_non_final_sequence,
        "swap/rswp/covenant.py's REFUND_SEQUENCE, verbatim",
        "REFUND_SEQUENCE = 0xFFFFFFFE\n",
    ),
    (
        respelled_non_final_sequence,
        "gravity/transactions.py's inline CLTV sequence",
        'seq = (0xFFFFFFFE).to_bytes(4, "little")\n',
    ),
    (
        respelled_non_final_sequence,
        "gravity/htlc_spend.py's fee-input keyword argument",
        "fee_in = _fee_input(fee, sequence=0xFFFFFFFE)\n",
    ),
    (
        respelled_non_final_sequence,
        "the decimal spelling, which a grep for the hex form misses",
        "SEQ = 4294967294\n",
    ),
    # --- money supply caps ---
    (
        respelled_money_supply_cap,
        "btc_wallet/validate.py's bare BTC cap — the anonymous literal that gets pasted onto the wrong chain",
        "def validate_satoshis(v):\n    return v <= 2_100_000_000_000_000\n",
    ),
    (
        respelled_money_supply_cap,
        "the same cap without underscores",
        "MAX = 2100000000000000\n",
    ),
    (
        respelled_money_supply_cap,
        "Radiant's cap, retyped",
        "RADIANT_MAX = 2_100_000_000_000_000_000\n",
    ),
    # --- the ETH finality floor ---
    (
        restated_eth_finalization_floor,
        "eth_wallet/chains.py's _FLOOR_S, verbatim",
        "_FLOOR_S = 768\n",
    ),
    (
        restated_eth_finalization_floor,
        "swap_coordinator.py's copy, under the OTHER name the pair actually used",
        "_MIN_ETH_FINALIZATION_WINDOW_S = 768\n",
    ),
    (
        restated_eth_finalization_floor,
        "an annotated third spelling nobody has written yet",
        "ETH_FINALITY_FLOOR_SECONDS: int = 768\n",
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
        registered = (
            {detector for detector, _, _ in _PRIMITIVE_GUARDS.values()}
            | {detector for detector, _, _ in _DERIVED_RULE_GUARDS.values()}
            | {respelled_centralised_value}
        )
        unproved = registered - proved
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
            (
                respelled_centralised_value,
                "the Unicode codepoint 0x0222 — 546 as an integer, not as a dust rule",
                "TABLE = {0x0222: 'O', 0x0223: 'o'}\n",
            ),
            (
                respelled_centralised_value,
                "a value one off the threshold: a boundary vector, not a second copy",
                "BOUNDARY = 499_999_999\n",
            ),
            (
                respelled_centralised_value,
                "the constant used by NAME, which is the whole point",
                "from pyrxd.constants import LOCKTIME_THRESHOLD\n\nif t < LOCKTIME_THRESHOLD:\n    pass\n",
            ),
            (
                respelled_centralised_value,
                "an unrelated ordinary number",
                "TIMEOUT_MS = 30_000\n",
            ),
            # --- the COINCIDENTAL 10_000s. Each is the same integer for an
            # --- unrelated reason, and collapsing any of them into the relay floor
            # --- would couple two things that have no business moving together.
            (
                respelled_relay_floor,
                "glyph/royalty.py's basis-point denominator — 10_000 bps is 100%, not a fee rate",
                "_BPS_DENOMINATOR = 10_000\n",
            ),
            (
                respelled_relay_floor,
                "swap/rswp/quoting.py's _BPS, the same denominator under a shorter name",
                "_BPS = 10_000\n",
            ),
            (
                respelled_relay_floor,
                "gravity/watch's dust ceiling — photons of VALUE, not photons per byte",
                "MAINNET_DUST_CEILING_PHOTONS = 10_000\n",
            ),
            (
                respelled_relay_floor,
                "eth_wallet/rpc.py's log cap — a count, and it is not even a currency",
                "_MAX_LOG_ENTRIES = 10_000\n",
            ),
            (
                respelled_relay_floor,
                "a royalty bounds check, where 10_000 is the top of the bps range",
                "def check(bps):\n    return 0 <= bps <= 10_000\n",
            ),
            (
                respelled_relay_floor,
                "a CALL passing the rate — the caller chose it, this is a use not a definition",
                "tx = wallet.build_send_tx(dest, photons=1, fee_rate=10_000)\n",
            ),
            (
                respelled_relay_floor,
                "the rate bound to the owning derivation, which is the whole point",
                "from pyrxd.fee_sizing import relay_floor_photons_per_byte\n\nMIN_FEE_RATE = relay_floor_photons_per_byte()\n",
            ),
            (
                respelled_non_final_sequence,
                "SEQUENCE_FINAL itself — one greater, and a different rule",
                "SEQUENCE_FINAL = 0xFFFFFFFF\n",
            ),
            (
                respelled_non_final_sequence,
                "the canonical derivation, which is a BinOp and not a literal",
                "SEQUENCE_LOCKTIME_ENABLED = SEQUENCE_FINAL - 1\n",
            ),
            (
                respelled_money_supply_cap,
                "a boundary vector one above the cap, which is a test doing its job",
                "OVER = 2_100_000_000_000_001\n",
            ),
            (
                respelled_money_supply_cap,
                "the canonical supply x subunit derivation",
                "BTC_MAX_SATS: int = 21_000_000 * 100_000_000\n",
            ),
            (
                restated_eth_finalization_floor,
                "the registry datum — Ethereum L1's ACTUAL window, not the floor",
                'CHAINS = {"ethereum": EvmChain(name="ethereum", chain_id=1, finalization_window_s=768)}\n',
            ),
            (
                restated_eth_finalization_floor,
                "a floor-named binding holding an unrelated number",
                "_FLOOR_S = 900\n",
            ),
            (
                restated_eth_finalization_floor,
                "the floor bound to the owning constant",
                "_MIN_ETH_FINALIZATION_WINDOW_S = ETH_FINALIZATION_WINDOW_FLOOR_S\n",
            ),
        ],
    )
    def test_legitimate_shapes_are_not_flagged(self, detector, label, source):
        assert not detector(source), f"{detector.__name__} false-positives on {label}"

    def test_a_separately_compiled_literal_is_a_DIFFERENT_int_object(self):
        """The premise ``test_the_eth_floor_has_exactly_one_definition`` rests on.

        That test uses ``is``, so it is worth nothing unless a re-introduced literal
        really does produce a distinct object. Two independently compiled modules,
        one deriving the value and one typing it, are exactly the situation — and
        CPython's small-int cache stops at 256, so 768 is not shared.
        """
        derived: dict = {}
        retyped: dict = {}
        exec(compile("FLOOR = 2 * 32 * 12\n", "<chains>", "exec"), derived)
        exec(compile("MIN_WINDOW = 768\n", "<coordinator>", "exec"), retyped)
        assert derived["FLOOR"] == retyped["MIN_WINDOW"], "premise check: the values must be equal"
        assert derived["FLOOR"] is not retyped["MIN_WINDOW"], (
            "a re-typed 768 is the SAME object as the derived one, so the identity guard cannot fire"
        )
        imported: dict = {"FLOOR": derived["FLOOR"]}
        exec(compile("MIN_WINDOW = FLOOR\n", "<coordinator>", "exec"), imported)
        assert imported["MIN_WINDOW"] is derived["FLOOR"], "an imported name must stay the same object"


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

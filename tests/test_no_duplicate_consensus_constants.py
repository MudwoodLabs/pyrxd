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

These are source-text checks, not import-time checks, and that is deliberate: a
duplicate definition that happens to be *correct today* still needs to fail,
because the failure mode is the two copies drifting apart later.
"""

from __future__ import annotations

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

# A literal collection naming three or more of the five ref opcodes: the shape
# of a hand-rolled copy of the set.
_REF_OPCODE_BYTE = re.compile(r"0[xX][dD][0-9a-fA-F]\b")


class TestNoRespelledRefOperandSet:
    def test_no_literal_ref_opcode_collection_outside_constants(self):
        ref_bytes = {f"0x{o:02x}" for o in REF_OPERAND_OPCODES}
        offenders = []
        for path in _python_files(SRC_ROOT):
            if path == CANONICAL_MODULE:
                continue
            body = _strip_comments_and_docstrings(path.read_text(encoding="utf-8"))
            for literal in re.finditer(r"[\{\(\[]([^\{\}\(\)\[\]\n]*)[\}\)\]]", body):
                found = {m.group(0).lower() for m in _REF_OPCODE_BYTE.finditer(literal.group(1))}
                if len(found & ref_bytes) >= 3:
                    offenders.append(f"{_rel(path)}: {literal.group(0).strip()[:70]}")
        assert not offenders, (
            "a literal collection of ref-operand opcodes was found outside "
            "pyrxd.constants. Import REF_OPERAND_OPCODES instead — four hand-written "
            "copies of this set produced three fund-affecting bugs:\n  " + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize("root_name", ["src", "tests"])
    def test_no_contiguous_range_comparison_over_the_ref_opcodes(self, root_name):
        """Ban ``0xd0 <= op <= 0xd8`` and its variants outright.

        This exact expression is the ``glyph/script.py`` bug: it sweeps in
        0xd4-0xd7, which carry no operand, so the walk consumes 36 bytes that
        are not there, fabricates a ref, and loses the real one. There is no
        correct use of it, so it is banned rather than reviewed.
        """
        root = REPO_ROOT / root_name
        pattern = re.compile(
            r"0[xX][dD]0\s*<=?\s*\w+\s*<=?\s*0[xX][dD][3-8]|"
            r"\w+\s*(?:>=?|in\s+range\()\s*0[xX][dD]0\b[^\n]{0,40}0[xX][dD][3-8]\b"
        )
        offenders = []
        for path in _python_files(root):
            if root_name == "tests" and path.name in _TEST_ALLOWLIST:
                continue
            body = _strip_comments_and_docstrings(path.read_text(encoding="utf-8"))
            for match in pattern.finditer(body):
                offenders.append(f"{_rel(path)}: {match.group(0).strip()}")
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
        """Catch a NEW walker that hard-codes 37 without the shared constant.

        ``pos += 37`` (1 opcode + 36 operand bytes) is the fingerprint of a ref
        walk. Any file containing it must be registered above and must use the
        shared constant, so walker number seven cannot repeat the history.
        """
        fingerprint = re.compile(r"(?:\+=\s*37\b)|(?:pos\s*\+\s*37\b)|(?:i\s*\+\s*37\b)")
        unregistered = []
        for path in _python_files(SRC_ROOT):
            rel = str(path.relative_to(SRC_ROOT))
            if rel in _REF_WALKERS:
                continue
            body = _strip_comments_and_docstrings(path.read_text(encoding="utf-8"))
            if fingerprint.search(body):
                unregistered.append(_rel(path))
        assert not unregistered, (
            "these files look like they walk ref operands (they advance by 37 = 1 opcode "
            "+ 36 operand bytes) but are not registered in _REF_WALKERS:\n  "
            + "\n  ".join(unregistered)
            + "\nRegister them and make them use REF_OPERAND_OPCODES."
        )


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

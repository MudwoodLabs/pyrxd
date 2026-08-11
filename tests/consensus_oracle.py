"""Derive Radiant consensus facts by parsing the vendored C++ sources.

This module is the *oracle* half of the consensus differential tests. It reads
``tests/vendor/radiant_core/script.h`` and ``script.cpp`` — verbatim, pinned
copies of Radiant Core — and extracts the facts pyrxd re-implements in Python.

The point is that **no consensus fact in here is typed by a human.** Every value
is recovered from the C++ that defines it. A hand-maintained Python table of the
same facts is precisely the artifact that failed: four pyrxd walkers each spelled
the ref-operand rule by hand, two spelled it wrong, and the test meant to catch
that spelled it by hand a fifth time — so the test agreed with the bug.

Parsing C++ with regular expressions is normally a bad idea. It is acceptable
here for three reasons: the input is pinned by sha256 so it cannot change under
the parser, the grammar subset involved is a flat enum plus two ``if`` chains,
and every extractor below fails loudly (``OracleParseError``) rather than
returning an empty or partial set. A silent empty result would make the
differential vacuous, which is the one outcome worse than no test at all.
"""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path

VENDOR_DIR = Path(__file__).parent / "vendor" / "radiant_core"
MANIFEST_PATH = VENDOR_DIR / "MANIFEST.json"


class OracleParseError(AssertionError):
    """The vendored C++ did not parse as expected.

    Raised rather than returning a degraded result: an oracle that quietly
    yields ``set()`` turns every differential built on it into a test that
    asserts nothing.
    """


# ---------------------------------------------------------------------------
# Vendored file access
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=4)
def vendored_source(name: str) -> str:
    path = VENDOR_DIR / name
    if not path.is_file():
        raise OracleParseError(
            f"vendored Radiant Core source {name!r} is missing from {VENDOR_DIR}. "
            "Restore it with scripts/refresh_radiant_core_vendor.py — the consensus "
            "differentials cannot run without it."
        )
    return path.read_text(encoding="utf-8")


def vendored_digest(name: str) -> str:
    return hashlib.sha256((VENDOR_DIR / name).read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")


def _strip_comments(src: str) -> str:
    """Remove C/C++ comments, preserving line structure.

    Newlines inside block comments are kept so that any line numbers reported
    in a failure message still refer to the real file.
    """
    src = _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), src)
    return _LINE_COMMENT.sub("", src)


# ---------------------------------------------------------------------------
# Fact 1 — the opcode table (script.h, `enum opcodetype`)
# ---------------------------------------------------------------------------

_ENUM_ENTRY = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z_]\w*)            # enumerator name
    (?:\s*=\s*(?P<value>[^,]+?))?     # optional initialiser
    \s*,
    """,
    re.VERBOSE | re.MULTILINE,
)


@lru_cache(maxsize=1)
def opcode_table() -> dict[str, int]:
    """``{enumerator name: numeric value}`` for every member of ``opcodetype``.

    Handles the three shapes the enum actually uses: an explicit hex
    initialiser (``OP_0 = 0x00``), an alias to an earlier member
    (``OP_FALSE = OP_0``), and an implicit value continuing from the previous
    member (``FIRST_UNDEFINED_OP_VALUE``, which is how ``MAX_OPCODE`` is
    defined and therefore load-bearing).
    """
    src = _strip_comments(vendored_source("script.h"))
    start = src.find("enum opcodetype")
    if start < 0:
        raise OracleParseError("could not locate `enum opcodetype` in vendored script.h")
    brace = src.find("{", start)
    end = src.find("};", brace)
    if brace < 0 or end < 0:
        raise OracleParseError("could not delimit the body of `enum opcodetype` in vendored script.h")
    body = src[brace + 1 : end]

    table: dict[str, int] = {}
    previous = -1
    for match in _ENUM_ENTRY.finditer(body):
        name = match.group("name")
        raw = (match.group("value") or "").strip()
        if not raw:
            value = previous + 1  # C enum implicit increment
        elif re.fullmatch(r"0[xX][0-9a-fA-F]+", raw):
            value = int(raw, 16)
        elif raw.isdigit():
            value = int(raw)
        elif raw in table:
            value = table[raw]  # alias, e.g. OP_TRUE = OP_1
        else:
            raise OracleParseError(
                f"unparsable initialiser for {name!r} in `enum opcodetype`: {raw!r}. "
                "The vendored header changed shape; update tests/consensus_oracle.py."
            )
        table[name] = value
        previous = value

    if len(table) < 100 or "OP_PUSHINPUTREF" not in table:
        raise OracleParseError(
            f"`enum opcodetype` parse produced an implausible table ({len(table)} entries). "
            "Refusing to run the differential against a bad oracle."
        )
    return table


@lru_cache(maxsize=1)
def max_opcode() -> int:
    """``MAX_OPCODE`` — the largest byte Radiant accepts as an opcode.

    Recovered from ``FIRST_UNDEFINED_OP_VALUE - 1`` exactly as ``script.h``
    defines it, rather than from the literal, so that adding an opcode upstream
    moves this automatically. ``CScript::HasValidOps`` rejects any script
    containing a byte above it.
    """
    src = _strip_comments(vendored_source("script.h"))
    if not re.search(r"MAX_OPCODE\s*=\s*FIRST_UNDEFINED_OP_VALUE\s*-\s*1", src):
        raise OracleParseError(
            "MAX_OPCODE is no longer defined as `FIRST_UNDEFINED_OP_VALUE - 1` in the "
            "vendored script.h; re-derive it in tests/consensus_oracle.py."
        )
    table = opcode_table()
    if "FIRST_UNDEFINED_OP_VALUE" not in table:
        raise OracleParseError("FIRST_UNDEFINED_OP_VALUE missing from the parsed opcode table")
    return table["FIRST_UNDEFINED_OP_VALUE"] - 1


# ---------------------------------------------------------------------------
# Fact 2 — which opcodes carry an immediate operand (script.cpp, GetScriptOp)
# ---------------------------------------------------------------------------

_OPCODE_EQ = re.compile(r"opcode\s*==\s*(OP_\w+)")


@lru_cache(maxsize=1)
def ref_operand_opcode_names() -> frozenset[str]:
    """Names of the opcodes ``GetScriptOp`` follows with a fixed 36-byte operand.

    This is *the* rule three pyrxd bugs got wrong. It is deliberately recovered
    from the branch that performs the pointer advance (``pc += 36``) rather than
    from any list of names, so the set can only be wrong if the C++ itself is.

    Note this is NOT the contiguous range 0xd0–0xd8: 0xd4–0xd7 are stack ops
    that carry no operand and sit right in the middle of it.
    """
    src = _strip_comments(vendored_source("script.cpp"))
    body = _get_script_op_body(src)

    # Locate the operand branch by its effect — the 36-byte program-counter
    # advance — then read the condition that guards it.
    advance = re.search(r"pc\s*\+=\s*(\d+)\s*;", body[body.rfind("else if") :])
    branch_start = body.rfind("else if")
    if branch_start < 0:
        raise OracleParseError("no `else if` branch found in GetScriptOp")
    branch = body[branch_start:]
    if not re.search(r"pc\s*\+=\s*36\s*;", branch):
        raise OracleParseError(
            "the final `else if` branch of GetScriptOp no longer advances pc by 36; "
            "the ref-operand encoding changed upstream."
        )
    condition = branch[branch.find("(") : branch.find("{")]
    names = frozenset(_OPCODE_EQ.findall(condition))
    if not names:
        raise OracleParseError("GetScriptOp operand branch parsed to an empty opcode set")
    del advance
    return names


@lru_cache(maxsize=1)
def ref_operand_width() -> int:
    """Operand width in bytes (36) as ``GetScriptOp`` advances the pc."""
    src = _strip_comments(vendored_source("script.cpp"))
    body = _get_script_op_body(src)
    branch = body[body.rfind("else if") :]
    match = re.search(r"pc\s*\+=\s*(\d+)\s*;", branch)
    if not match:
        raise OracleParseError("could not read the ref operand width from GetScriptOp")
    return int(match.group(1))


def _get_script_op_body(src: str) -> str:
    start = src.find("bool GetScriptOp(")
    if start < 0:
        raise OracleParseError("could not locate GetScriptOp in vendored script.cpp")
    end = src.find("\nbool ", start + 1)
    return src[start : end if end > 0 else len(src)]


# ---------------------------------------------------------------------------
# Fact 3 — which of those land in an output's push-ref set (GetPushRefs)
# ---------------------------------------------------------------------------

_BRANCH = re.compile(r"(?:else\s+)?if\s*\(\s*opcode\s*==\s*(OP_\w+)\s*\)\s*\{")


@lru_cache(maxsize=1)
def push_ref_opcode_names() -> frozenset[str]:
    """Names of the opcodes whose refs Radiant files into ``foundPushRefs``.

    ``GetPushRefs`` walks all five operand-carrying opcodes but sorts them into
    four different sets. Only the push-ref set feeds an output's ref summary and
    therefore the ``hashOutputHashes`` sighash field, so "carries an operand" and
    "contributes a ref" are different questions with different answers — the
    distinction that made the second bug subtle.
    """
    src = _strip_comments(vendored_source("script.cpp"))
    body = _get_push_refs_body(src)

    matches = list(_BRANCH.finditer(body))
    if not matches:
        raise OracleParseError("no `if (opcode == OP_x) {` dispatch chain found in GetPushRefs")

    collected: set[str] = set()
    for i, match in enumerate(matches):
        branch_end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        if "foundPushRefs.insert" in body[match.end() : branch_end]:
            collected.add(match.group(1))
    if not collected:
        raise OracleParseError("GetPushRefs dispatch parsed to an empty push-ref set")
    return frozenset(collected)


@lru_cache(maxsize=1)
def push_refs_guard_opcode_names() -> frozenset[str]:
    """The opcode set in the outer guard of ``GetPushRefs``'s dispatch.

    Cross-check only: it must equal :func:`ref_operand_opcode_names`. The two are
    derived from different functions in the C++, so agreement between them is
    evidence the parser found the right blocks rather than plausible-looking
    ones.
    """
    src = _strip_comments(vendored_source("script.cpp"))
    body = _get_push_refs_body(src)
    guard = re.search(r"if\s*\((\s*opcode\s*==\s*OP_\w+\s*(?:\|\|\s*opcode\s*==\s*OP_\w+\s*)+)\)", body)
    if not guard:
        raise OracleParseError("could not locate the outer ref-opcode guard in GetPushRefs")
    return frozenset(_OPCODE_EQ.findall(guard.group(1)))


def _get_push_refs_body(src: str) -> str:
    start = src.find("bool CScript::GetPushRefs(")
    if start < 0:
        raise OracleParseError("could not locate CScript::GetPushRefs in vendored script.cpp")
    end = src.find("\nbool ", start + 1)
    return src[start : end if end > 0 else len(src)]


# ---------------------------------------------------------------------------
# Byte-valued convenience views
# ---------------------------------------------------------------------------


def ref_operand_opcodes() -> frozenset[int]:
    table = opcode_table()
    return frozenset(table[n] for n in ref_operand_opcode_names())


def push_ref_opcodes() -> frozenset[int]:
    table = opcode_table()
    return frozenset(table[n] for n in push_ref_opcode_names())

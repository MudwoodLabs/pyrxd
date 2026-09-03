"""Derive Radiant consensus facts by parsing the vendored C++ sources.

This module is the *oracle* half of the consensus differential tests. It reads
the verbatim, pinned copies of Radiant Core under ``tests/vendor/radiant_core/``
and extracts the facts pyrxd re-implements in Python: the opcode table and
script-walking rules (``script.h``/``script.cpp``), the BIP68 sequence-lock
constants (``primitives_transaction.h``) and how CSV consumes them
(``interpreter.cpp``), the DER signature-encoding rules (``sigencoding.cpp``),
and which verification flags are consensus rather than policy
(``script_flags.h``, ``policy.h``, ``validation.cpp``). See the README beside
those files for the full table.

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


@lru_cache(maxsize=16)  # >= the number of vendored files, or the cache thrashes
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
# Fact 5 — the scalar consensus limits (script.h)
# ---------------------------------------------------------------------------

#: ``static const[expr] <type> NAME = <int>;`` — the shape every scalar limit in
#: ``script.h`` is declared with. Deliberately anchored on ``=`` and a bare
#: integer so a value that becomes an expression fails the parse loudly rather
#: than being silently mis-read.
_SCALAR_LIMIT = r"static\s+const(?:expr)?\s+(?:unsigned\s+)?(?:int|long)\s+{name}\s*=\s*(\d+)\s*;"


@lru_cache(maxsize=16)
def script_limit(name: str) -> int:
    """A scalar consensus limit from ``script.h``, by its C++ name.

    Covers ``MAX_SCRIPT_ELEMENT_SIZE``, ``MAX_SCRIPT_ELEMENT_SIZE_LEGACY``,
    ``MAX_OPS_PER_SCRIPT``, ``MAX_SCRIPT_SIZE``, ``MAX_STACK_SIZE``,
    ``MAX_PUBKEYS_PER_MULTISIG`` and ``LOCKTIME_THRESHOLD``.

    Worth reading the values before assuming Bitcoin's: Radiant raised
    ``MAX_SCRIPT_ELEMENT_SIZE`` to 32,000,000 and kept Bitcoin's 520 under the
    separate name ``MAX_SCRIPT_ELEMENT_SIZE_LEGACY``. Code that "knows" the
    push limit is 520 is describing the wrong chain.
    """
    src = _strip_comments(vendored_source("script.h"))
    match = re.search(_SCALAR_LIMIT.format(name=re.escape(name)), src)
    if not match:
        raise OracleParseError(
            f"{name} is no longer declared as a plain `static const <type> {name} = <int>;` "
            "in the vendored script.h; re-derive it in tests/consensus_oracle.py."
        )
    return int(match.group(1))


# ---------------------------------------------------------------------------
# Byte-valued convenience views
# ---------------------------------------------------------------------------


def ref_operand_opcodes() -> frozenset[int]:
    table = opcode_table()
    return frozenset(table[n] for n in ref_operand_opcode_names())


def push_ref_opcodes() -> frozenset[int]:
    table = opcode_table()
    return frozenset(table[n] for n in push_ref_opcode_names())


# ---------------------------------------------------------------------------
# Fact 4 — BIP68 sequence-lock constants (primitives/transaction.h, CTxIn)
# ---------------------------------------------------------------------------

_CTXIN_CONST = re.compile(
    r"""
    static \s+ const \s+ (?:uint32_t|int) \s+
    (?P<name>SEQUENCE_\w+) \s* = \s* (?P<value>[^;]+) ;
    """,
    re.VERBOSE,
)


def _eval_int_literal(raw: str) -> int:
    """Evaluate the tiny expression grammar the CTxIn constants use.

    Exactly three shapes appear: a hex literal (``0xffffffff``), a decimal
    literal (``9``), and a parenthesised shift (``(1U << 31)``). Anything else
    raises rather than guessing, because a silently mis-evaluated consensus
    constant is the failure mode this whole module exists to prevent.
    """
    text = raw.strip().strip("()").strip()
    text = re.sub(r"\b(\d+)[uUlL]+\b", r"\1", text)  # drop U/L suffixes
    shift = re.fullmatch(r"(\w+)\s*<<\s*(\w+)", text)
    if shift:
        return _eval_int_literal(shift.group(1)) << _eval_int_literal(shift.group(2))
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
        return int(text, 16)
    if text.isdigit():
        return int(text)
    raise OracleParseError(f"unparsable integer expression in vendored source: {raw!r}")


@lru_cache(maxsize=1)
def sequence_locktime_constants() -> dict[str, int]:
    """``{name: value}`` for every ``CTxIn::SEQUENCE_*`` constant.

    These are the BIP68 relative-locktime encoding constants. pyrxd spelled
    them by hand in two unrelated modules (``script/timelock.py`` and
    ``btc_wallet/taproot.py``) and a third time inline in a test, which is the
    same shape as the ref-operand bug: several transcriptions, no mechanism
    tying any of them to the C++.
    """
    src = _strip_comments(vendored_source("primitives_transaction.h"))
    start = src.find("class CTxIn")
    if start < 0:
        raise OracleParseError("could not locate `class CTxIn` in vendored primitives/transaction.h")
    end = src.find("\nclass ", start + 1)
    body = src[start : end if end > 0 else len(src)]

    table = {m.group("name"): _eval_int_literal(m.group("value")) for m in _CTXIN_CONST.finditer(body)}
    required = {
        "SEQUENCE_FINAL",
        "SEQUENCE_LOCKTIME_DISABLE_FLAG",
        "SEQUENCE_LOCKTIME_TYPE_FLAG",
        "SEQUENCE_LOCKTIME_MASK",
        "SEQUENCE_LOCKTIME_GRANULARITY",
    }
    missing = required - table.keys()
    if missing:
        raise OracleParseError(f"CTxIn no longer defines {sorted(missing)} in the vendored primitives/transaction.h")
    return table


def _check_sequence_body() -> str:
    src = _strip_comments(vendored_source("interpreter.cpp"))
    start = src.find("GenericTransactionSignatureChecker<T>::CheckSequence(")
    if start < 0:
        raise OracleParseError("could not locate CheckSequence in vendored interpreter.cpp")
    end = src.find("\n}\n", start)
    if end < 0:
        raise OracleParseError("could not delimit the body of CheckSequence")
    return src[start:end]


@lru_cache(maxsize=1)
def check_sequence_min_tx_version() -> int:
    """The transaction version at or above which BIP68 rules engage.

    ``CheckSequence`` returns false outright below it, so a refund transaction
    built at a lower version has no relative lock at all — the CSV simply fails.
    """
    body = _check_sequence_body()
    match = re.search(r"txTo->nVersion\s*\)\s*<\s*(\d+)", body)
    if not match:
        raise OracleParseError("CheckSequence no longer gates on a minimum tx version")
    return int(match.group(1))


@lru_cache(maxsize=1)
def check_sequence_disable_flag_name() -> str:
    """The constant whose bit makes ``CheckSequence`` return false immediately."""
    body = _check_sequence_body()
    match = re.search(r"txToSequence\s*&\s*CTxIn::(SEQUENCE_\w+)", body)
    if not match:
        raise OracleParseError("CheckSequence no longer tests a disable bit on the input's nSequence")
    return match.group(1)


@lru_cache(maxsize=1)
def check_sequence_mask_flag_names() -> frozenset[str]:
    """The constants OR-ed into ``nLockTimeMask`` — the consensus-meaningful bits."""
    body = _check_sequence_body()
    match = re.search(r"nLockTimeMask\s*=\s*([^;]+);", body)
    if not match:
        raise OracleParseError("CheckSequence no longer builds an nLockTimeMask")
    names = frozenset(re.findall(r"CTxIn::(SEQUENCE_\w+)", match.group(1)))
    if not names:
        raise OracleParseError("nLockTimeMask parsed to an empty constant set")
    return names


# ---------------------------------------------------------------------------
# Fact 5 — script verification flags, and which of them are consensus
# ---------------------------------------------------------------------------

_FLAG_ENTRY = re.compile(r"^\s*(?P<name>SCRIPT_\w+)\s*=\s*(?P<value>[^,}]+)\s*,?", re.MULTILINE)


@lru_cache(maxsize=1)
def script_verify_flags() -> dict[str, int]:
    """``{flag name: bit value}`` from ``script/script_flags.h``."""
    src = _strip_comments(vendored_source("script_flags.h"))
    brace = src.find("enum {")
    end = src.find("};", brace)
    if brace < 0 or end < 0:
        raise OracleParseError("could not delimit the script-verification flag enum in vendored script_flags.h")
    table = {m.group("name"): _eval_int_literal(m.group("value")) for m in _FLAG_ENTRY.finditer(src[brace:end])}
    if "SCRIPT_VERIFY_LOW_S" not in table or "SCRIPT_VERIFY_STRICTENC" not in table:
        raise OracleParseError(f"implausible script-flag table parsed ({len(table)} entries)")
    return table


def _flag_set_names(constant: str, *, _seen: frozenset[str] = frozenset()) -> frozenset[str]:
    src = _strip_comments(vendored_source("policy.h"))
    match = re.search(rf"{constant}\s*=\s*([^;]+);", src)
    if not match:
        raise OracleParseError(f"could not locate {constant} in vendored policy.h")
    names: set[str] = set()
    for token in re.findall(r"[A-Z0-9_]+", match.group(1)):
        if token.startswith("SCRIPT_"):
            names.add(token)
        elif token.endswith("_SCRIPT_VERIFY_FLAGS") and token not in _seen:
            names |= _flag_set_names(token, _seen=_seen | {constant})
    if not names:
        raise OracleParseError(f"{constant} parsed to an empty flag set")
    return frozenset(names)


@lru_cache(maxsize=1)
def mandatory_script_verify_flag_names() -> frozenset[str]:
    """The flags Radiant enforces at **consensus** (``MANDATORY_SCRIPT_VERIFY_FLAGS``).

    A transaction violating one of these is invalid in a block, not merely
    non-standard. ``fRequireStandard`` being false on this chain removes the
    policy layer, so this set — not ``STANDARD_SCRIPT_VERIFY_FLAGS`` — is the
    one pyrxd has to agree with.
    """
    return _flag_set_names("MANDATORY_SCRIPT_VERIFY_FLAGS")


@lru_cache(maxsize=1)
def standard_script_verify_flag_names() -> frozenset[str]:
    """The flags a *standard* transaction complies with (policy, a superset)."""
    return _flag_set_names("STANDARD_SCRIPT_VERIFY_FLAGS")


@lru_cache(maxsize=1)
def block_script_flag_names() -> frozenset[str]:
    """Every flag ``GetNextBlockScriptFlags`` can set when connecting a block.

    This — not ``MANDATORY_SCRIPT_VERIFY_FLAGS``, whose comment is about whether
    to ban a peer — is the authority on what is consensus. Height-gated flags are
    included: every activation height in this set is long past on mainnet, and a
    flag that is off only for the first couple hundred blocks is not a rule pyrxd
    can usefully diverge from.
    """
    src = _strip_comments(vendored_source("validation.cpp"))
    start = src.find(
        "static uint32_t GetNextBlockScriptFlags(", src.find("static uint32_t GetNextBlockScriptFlags(") + 1
    )
    if start < 0:
        raise OracleParseError("could not locate the GetNextBlockScriptFlags definition in vendored validation.cpp")
    end = src.find("\n}\n", start)
    if end < 0:
        raise OracleParseError("could not delimit the body of GetNextBlockScriptFlags")
    names = frozenset(re.findall(r"flags\s*\|=\s*(SCRIPT_\w+)\s*;", src[start:end]))
    if len(names) < 10:
        raise OracleParseError(f"GetNextBlockScriptFlags parsed to an implausible flag set ({sorted(names)})")
    return names


@lru_cache(maxsize=1)
def requires_standard_default() -> bool:
    """The compiled-in value of ``fRequireStandard``.

    False on this chain, which is why a *policy-only* flag is not a rule pyrxd
    can rely on a node to apply — and equally why it must not be presented as
    one.
    """
    src = _strip_comments(vendored_source("validation.cpp"))
    match = re.search(r"\bbool\s+fRequireStandard\s*=\s*(true|false)\s*;", src)
    if not match:
        raise OracleParseError("could not locate the fRequireStandard definition in vendored validation.cpp")
    return match.group(1) == "true"


@lru_cache(maxsize=1)
def verify_script_implied_flag_names() -> dict[str, str]:
    """Flags ``VerifyScript`` turns on for you: ``{implied: because-this-is-set}``.

    ``SCRIPT_ENABLE_SIGHASH_FORKID`` is mandatory on Radiant and VerifyScript
    reacts to it by OR-ing in ``SCRIPT_VERIFY_STRICTENC``, so strict signature
    encoding is consensus here even though the flag is not listed in
    ``MANDATORY_SCRIPT_VERIFY_FLAGS`` for that reason.
    """
    src = _strip_comments(vendored_source("interpreter.cpp"))
    start = src.find("bool VerifyScript(")
    if start < 0:
        raise OracleParseError("could not locate VerifyScript in vendored interpreter.cpp")
    body = src[start : start + 2000]
    implied: dict[str, str] = {}
    for match in re.finditer(r"if\s*\(flags\s*&\s*(SCRIPT_\w+)\s*\)\s*\{\s*flags\s*\|=\s*(SCRIPT_\w+)\s*;", body):
        implied[match.group(2)] = match.group(1)
    if not implied:
        raise OracleParseError("VerifyScript no longer implies any verification flag")
    return implied


# ---------------------------------------------------------------------------
# Fact 6 — DER signature encoding rules (script/sigencoding.cpp)
# ---------------------------------------------------------------------------


def _is_valid_der_body() -> str:
    src = _strip_comments(vendored_source("sigencoding.cpp"))
    start = src.find("bool IsValidDERSignatureEncoding(")
    if start < 0:
        raise OracleParseError("could not locate IsValidDERSignatureEncoding in vendored sigencoding.cpp")
    end = src.find("\nstatic bool ", start + 1)
    return src[start : end if end > 0 else len(src)]


@lru_cache(maxsize=1)
def der_signature_size_bounds() -> tuple[int, int]:
    """``(min, max)`` byte length consensus accepts for a DER signature body.

    Excludes the trailing sighash byte: ``CheckTransactionSignatureEncoding``
    slices that off before calling ``IsValidDERSignatureEncoding``.
    """
    body = _is_valid_der_body()
    match = re.search(r"sig\.size\(\)\s*<\s*(\d+)\s*\|\|\s*sig\.size\(\)\s*>\s*(\d+)", body)
    if not match:
        raise OracleParseError("IsValidDERSignatureEncoding no longer bounds the signature size")
    return int(match.group(1)), int(match.group(2))


@lru_cache(maxsize=1)
def der_encoding_gate_flag_names() -> frozenset[str]:
    """The flags any one of which makes strict-DER encoding mandatory."""
    src = _strip_comments(vendored_source("sigencoding.cpp"))
    match = re.search(r"if\s*\(\(flags\s*&\s*\(([^)]+)\)\)\s*&&\s*\n?\s*!IsValidDERSignatureEncoding", src)
    if not match:
        raise OracleParseError("could not locate the flag gate on IsValidDERSignatureEncoding")
    return frozenset(re.findall(r"SCRIPT_\w+", match.group(1)))


@lru_cache(maxsize=1)
def low_s_gate_flag_name() -> str:
    """The flag that makes ``CheckLowS`` mandatory."""
    src = _strip_comments(vendored_source("sigencoding.cpp"))
    match = re.search(r"if\s*\(\(flags\s*&\s*(SCRIPT_\w+)\)\s*&&\s*!CPubKey::CheckLowS", src)
    if not match:
        raise OracleParseError("could not locate the low-S gate in sigencoding.cpp")
    return match.group(1)


# ---------------------------------------------------------------------------
# Fact 12 — WHICH ref opcodes the backing-subset rule actually covers
#           (script.cpp GetPushRefs -> validation.h validateTransactionReferenceOperations)
# ---------------------------------------------------------------------------
#
# "Carries a 36-byte ref operand" and "consensus guarantees the transaction spent
# that ref" are DIFFERENT QUESTIONS WITH DIFFERENT ANSWERS, and pyrxd shipped a
# verifier that conflated them: it read all five operand-carrying opcodes as proof
# of backing and stamped the result "VERIFIED — spent in this tx". Two of the five
# are never checked against the inputs at all, so anyone could name a collection
# they had never touched and be believed.
#
# The rule lives in ``validation.h``, which was NOT vendored when that verifier was
# written — so no differential could have caught it, and reasoning from the code
# under review could only ever confirm the code was self-consistent. That absence
# is the actual root cause, which is why the fix is an extractor here rather than a
# corrected constant in ``constants.py``.
#
# The chain this follows, in three hops:
#
#   1. ``GetPushRefs`` files each opcode's operand into a FUNCTION-LOCAL set
#      (``foundPushRefs``, ``foundRequiredRefs``, ``foundDisallowedRefs``, ...).
#   2. At the end, only SOME of those locals are merged into the caller's
#      out-parameters. ``foundDisallowedRefs`` (0xd2) is merged into NOTHING — it
#      is intersected against this script's own pushes and then discarded.
#   3. ``validateTransactionReferenceOperations`` passes only SOME of the
#      out-parameters to ``validatePushRefRule``, which is the actual
#      output-must-be-a-subset-of-input check. The disallow-sibling set (0xd3)
#      instead reaches ``validateDisallowedSiblingsRefRule``, which compares
#      outputs against OTHER OUTPUTS and never reads the inputs.
#
# An opcode is backed only if its operand survives all three hops.

#: ``pushRefSet.insert(foundPushRefs.begin(), ...)`` — hop 2, local set to out-param.
_MERGE = re.compile(r"(\w+)\s*\.insert\s*\(\s*(\w+)\s*\.begin\s*\(\s*\)")

#: ``validatePushRefRule(inputPushRefSet, outputRequireRefSet)`` — hop 3. The SECOND
#: argument is the output-side set being required to be a subset of the inputs.
_SUBSET_CHECK = re.compile(r"validatePushRefRule\s*\(\s*\w+\s*,\s*(\w+)\s*\)")


def _validate_tx_refs_body() -> str:
    src = _strip_comments(vendored_source("validation.h"))
    start = src.find("static bool validateTransactionReferenceOperations(")
    if start < 0:
        raise OracleParseError("could not locate validateTransactionReferenceOperations in vendored validation.h")
    end = src.find("\n    static ", start + 1)
    return src[start : end if end > 0 else len(src)]


@lru_cache(maxsize=1)
def _get_push_refs_out_params() -> list[str]:
    """The out-parameter names of ``GetPushRefs``, IN ORDER.

    Order is load-bearing: the caller passes its own variables positionally, so
    mapping caller name to consensus role is a positional join. Getting this
    backwards would silently swap "require" and "disallow-sibling", which is the
    exact confusion being guarded against.
    """
    src = _strip_comments(vendored_source("script.cpp"))
    sig = re.search(
        r"bool\s+CScript::GetPushRefs\s*\(\s*const_iterator\s+pc\s*,(.*?)\)\s*const\s*\{",
        src,
        re.DOTALL,
    )
    if not sig:
        raise OracleParseError("could not parse the GetPushRefs signature")
    params = [re.sub(r".*[\s&*]", "", p).strip() for p in sig.group(1).split(",") if p.strip()]
    if "pushRefSet" not in params:
        raise OracleParseError(f"GetPushRefs signature parsed to an unexpected parameter list: {params}")
    return params


@lru_cache(maxsize=1)
def input_backed_ref_opcode_names() -> frozenset[str]:
    """Opcode names whose output operand consensus REQUIRES an input to back.

    This is the set a reader may treat as authorisation. Its complement within
    :func:`ref_operand_opcode_names` — currently ``OP_DISALLOWPUSHINPUTREF`` and
    ``OP_DISALLOWPUSHINPUTREFSIBLING`` — may be written by anyone about anything,
    at the cost of one output, and means only what the script says locally.
    """
    script_src = _strip_comments(vendored_source("script.cpp"))
    body = _get_push_refs_body(script_src)

    # Hop 1: opcode -> the function-local sets its branch inserts into.
    branches = list(_BRANCH.finditer(body))
    if not branches:
        raise OracleParseError("no `if (opcode == OP_x) {` dispatch chain found in GetPushRefs")
    filed: dict[str, set[str]] = {}
    for i, match in enumerate(branches):
        end = branches[i + 1].start() if i + 1 < len(branches) else len(body)
        filed[match.group(1)] = {m.group(1) for m in re.finditer(r"(\w+)\s*\.insert\s*\(", body[match.end() : end])}
    if not any(filed.values()):
        raise OracleParseError("GetPushRefs dispatch parsed to no set insertions at all")

    # Hop 2: function-local set -> out-parameter. Only merges whose TARGET is an
    # out-param count; `foundDisallowedRefs` is consumed by a set_intersection into
    # a local and never merged, which is precisely why 0xd2 is unbacked.
    out_params = set(_get_push_refs_out_params())
    local_to_out: dict[str, str] = {m.group(2): m.group(1) for m in _MERGE.finditer(body) if m.group(1) in out_params}
    if not local_to_out:
        raise OracleParseError("no local-set -> out-parameter merges found at the end of GetPushRefs")

    # Hop 3: out-parameter role -> is it subset-checked against the inputs?
    validate_body = _validate_tx_refs_body()
    checked_caller_vars = {m.group(1) for m in _SUBSET_CHECK.finditer(validate_body)}
    if not checked_caller_vars:
        raise OracleParseError("no validatePushRefRule calls found in validateTransactionReferenceOperations")

    # The caller's variables are bound to consensus roles positionally, at its
    # buildRefSetFromScript call over the OUTPUTS. The input-side call is skipped:
    # what the inputs contribute is the thing being checked AGAINST, not checked.
    call = re.search(r"buildRefSetFromScript\s*\(\s*tx\.vout\[\w+\]\.scriptPubKey\s*,(.*?)\)", validate_body, re.DOTALL)
    if not call:
        raise OracleParseError("could not locate the per-output buildRefSetFromScript call")
    caller_args = [a.strip() for a in call.group(1).split(",") if a.strip()]
    roles = _get_push_refs_out_params()[: len(caller_args)]
    if len(caller_args) != len(roles):
        raise OracleParseError(f"arity mismatch: {len(caller_args)} args vs {len(roles)} out-params")
    arg_for_role = dict(zip(roles, caller_args, strict=True))

    # A caller variable may be accumulated into another before the check
    # (`outputPushRefSet.insert(outputPushRefSetLocal.begin(), ...)`), so follow one
    # hop of aliasing rather than requiring the checked name to appear verbatim.
    aliases: dict[str, str] = {m.group(2): m.group(1) for m in _MERGE.finditer(validate_body)}
    backed_roles = {
        role
        for role, var in arg_for_role.items()
        if var in checked_caller_vars or aliases.get(var) in checked_caller_vars
    }
    if not backed_roles:
        raise OracleParseError("no output ref set reached validatePushRefRule — parse is wrong")

    backed = {op for op, locals_ in filed.items() if {local_to_out.get(s) for s in locals_} & backed_roles}
    if not backed:
        raise OracleParseError("backing chain parsed to an empty opcode set")
    return frozenset(backed)


def input_backed_ref_opcodes() -> frozenset[int]:
    table = opcode_table()
    return frozenset(table[n] for n in input_backed_ref_opcode_names())

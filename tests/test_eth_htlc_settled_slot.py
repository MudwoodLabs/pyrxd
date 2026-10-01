"""``SETTLED_SLOT`` is DERIVED from the vendored runtimes, not assumed.

``verify_funded`` and ``claim`` refuse an HTLC whose ``settled`` flag is set, by reading storage
slot :data:`pyrxd.eth_wallet.htlc_leg.SETTLED_SLOT`. That constant is a claim about the contracts'
storage layout — and if a re-vendored artifact moved the flag, the check would keep reading slot 0,
find it zero, and pass every pre-settled contract while looking exactly as it does today.

So this traces the slot KEY of every ``SLOAD`` and ``SSTORE`` in each vendored HTLC runtime. Within
a basic block the stack is tracked symbolically — constants through ``PUSH``/``PUSH0``/``DUP``/
``SWAP``, everything else unknown — and each access must resolve to the constant ``SETTLED_SLOT``.
An access whose key arrives from another block, or resolves to any other slot, fails the test.

What this does NOT prove: that slot 0 means "settled" rather than something else. That is proven by
EXECUTION in the Anvil module (an honest claim sets the word, and a contract created with the word set
is refused) — which runs nightly. This file is the per-PR half: it fails
the moment the layout stops being a single word at the slot the leg reads.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from pyrxd.eth_wallet.htlc_leg import SETTLED_SLOT

_FIX = pathlib.Path(__file__).parent / "fixtures"

#: (pops, pushes) for every opcode a solc runtime can contain, except PUSH/DUP/SWAP (handled
#: inline). An opcode missing here resets the tracked stack, which can only make a key UNKNOWN —
#: it fails the test rather than inventing a constant.
_ARITY = {
    **{op: (2, 1) for op in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0A, 0x0B)},
    0x08: (3, 1), 0x09: (3, 1),
    **{op: (2, 1) for op in (0x10, 0x11, 0x12, 0x13, 0x14, 0x16, 0x17, 0x18, 0x1A, 0x1B, 0x1C, 0x1D)},
    0x15: (1, 1), 0x19: (1, 1), 0x20: (2, 1),
    **{op: (0, 1) for op in (0x30, 0x32, 0x33, 0x34, 0x36, 0x38, 0x3A, 0x3D)},
    0x31: (1, 1), 0x35: (1, 1), 0x37: (3, 0), 0x39: (3, 0), 0x3B: (1, 1), 0x3C: (4, 0), 0x3E: (3, 0), 0x3F: (1, 1),
    0x40: (1, 1), **{op: (0, 1) for op in range(0x41, 0x49)}, 0x49: (1, 1), 0x4A: (0, 1),
    0x50: (1, 0), 0x51: (1, 1), 0x52: (2, 0), 0x53: (2, 0), 0x54: (1, 1), 0x55: (2, 0),
    0x56: (1, 0), 0x57: (2, 0), 0x58: (0, 1), 0x59: (0, 1), 0x5A: (0, 1), 0x5B: (0, 0),
    0x5C: (1, 1), 0x5D: (2, 0), 0x5E: (3, 0), 0x5F: (0, 1),
    0xA0: (2, 0), 0xA1: (3, 0), 0xA2: (4, 0), 0xA3: (5, 0), 0xA4: (6, 0),
    0xF0: (3, 1), 0xF1: (7, 1), 0xF2: (7, 1), 0xF3: (2, 0), 0xF4: (6, 1), 0xF5: (4, 1), 0xFA: (6, 1),
    0xFD: (2, 0), 0xFE: (0, 0), 0xFF: (1, 0), 0x00: (0, 0),
}  # fmt: skip
_TERMINATORS = {0x00, 0x56, 0x57, 0xF3, 0xFD, 0xFE, 0xFF}
UNKNOWN = "unknown"


def _strip_metadata(code: bytes) -> bytes:
    """Drop solc's trailing CBOR metadata (its length is the last two bytes), so bytes inside the
    IPFS hash are not decoded as opcodes."""
    n = int.from_bytes(code[-2:], "big")
    if 0 < n + 2 <= len(code) and code[-(n + 2)] in (0xA1, 0xA2, 0xA3):
        return code[: -(n + 2)]
    return code


def storage_accesses(code: bytes) -> list[tuple[int, str, object]]:
    """``(pc, "SLOAD"|"SSTORE", key)`` for every storage access; ``key`` is an int or UNKNOWN."""
    out: list[tuple[int, str, object]] = []
    stack: list[object] = []
    i = 0
    while i < len(code):
        op = code[i]
        if op == 0x5B:  # JUMPDEST: a block can be entered from anywhere, so nothing is known
            stack = []
        if 0x60 <= op <= 0x7F:
            n = op - 0x5F
            stack.append(int.from_bytes(code[i + 1 : i + 1 + n], "big"))
            i += 1 + n
            continue
        if op == 0x5F:
            stack.append(0)
        elif 0x80 <= op <= 0x8F:
            k = op - 0x7F
            stack.append(stack[-k] if len(stack) >= k else UNKNOWN)
        elif 0x90 <= op <= 0x9F:
            k = op - 0x8F
            while len(stack) < k + 1:
                stack.insert(0, UNKNOWN)
            stack[-1], stack[-1 - k] = stack[-1 - k], stack[-1]
        elif op in _ARITY:
            if op in (0x54, 0x55):
                out.append((i, "SLOAD" if op == 0x54 else "SSTORE", stack[-1] if stack else UNKNOWN))
            pops, pushes = _ARITY[op]
            stack = stack[:-pops] if 0 < pops <= len(stack) else ([] if pops else stack)
            stack += [UNKNOWN] * pushes
            if op in _TERMINATORS:
                stack = []
        else:
            stack = []
        i += 1
    return out


def _htlc_artifacts() -> list[pathlib.Path]:
    """Every vendored HTLC artifact — derived (has an immutable layout), not a hand-kept list."""
    found = []
    for path in sorted(_FIX.glob("*.json")):
        try:
            art = json.loads(path.read_text())
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(art, dict) and "runtime_bytecode" in art and "immutableReferences" in art:
            found.append(path)
    return found


_ARTIFACTS = _htlc_artifacts()


def test_the_artifact_set_is_derived_and_not_empty():
    assert {p.name for p in _ARTIFACTS} >= {"EthHtlc.json", "Erc20Htlc.json"}, _ARTIFACTS


@pytest.mark.parametrize("path", _ARTIFACTS, ids=lambda p: p.name)
def test_every_storage_access_in_the_runtime_is_the_settled_slot(path):
    code = _strip_metadata(bytes.fromhex(json.loads(path.read_text())["runtime_bytecode"].removeprefix("0x")))
    accesses = storage_accesses(code)
    # Non-vacuity: the flag is read (claim/refund check it) AND written (they set it).
    assert any(kind == "SLOAD" for _pc, kind, _k in accesses), accesses
    assert any(kind == "SSTORE" for _pc, kind, _k in accesses), accesses
    wrong = [(pc, kind, key) for pc, kind, key in accesses if key != SETTLED_SLOT]
    assert not wrong, (
        f"{path.name}: storage accesses not provably at slot {SETTLED_SLOT}: {wrong}. The HTLC's "
        "storage layout changed; the settled check in verify_funded/claim must be revisited."
    )


# ── known-answer controls for the tracer itself ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "hexcode,expected",
    [
        ("5f54", [0]),  # PUSH0 SLOAD
        ("600154", [1]),  # PUSH1 1 SLOAD — a DIFFERENT slot must be reported as such
        ("5f8054", [0]),  # PUSH0 DUP1 SLOAD
        (
            "60016000905455",
            [1, UNKNOWN],
        ),  # PUSH1 1 PUSH1 0 SWAP1 SLOAD SSTORE: SWAP brings 1 up; a loaded value is unknown
        ("5f5b54", [UNKNOWN]),  # PUSH0 JUMPDEST SLOAD — the key crossed a block boundary
        ("3554", [UNKNOWN]),  # CALLDATALOAD SLOAD — a computed key
    ],
)
def test_the_tracer_reports_what_it_should(hexcode, expected):
    """A tracer that called everything slot 0 would make the test above pass vacuously."""
    assert [k for _pc, _kind, k in storage_accesses(bytes.fromhex(hexcode))] == expected

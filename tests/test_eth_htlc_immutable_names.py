"""An INDEPENDENT derivation of each HTLC artifact's ``immutable_names`` map.

``immutable_names`` pairs each ``immutableReferences`` id with the negotiated term the leg splices
into it, and the exact runtime compare in ``EthHtlcContractLeg._expected_runtime`` is only as right
as that pairing. The map is hand-kept, and the unit fakes that serve "honest" runtimes splice
through the artifact's OWN map, so a swapped pair (claimant <-> refundee, say) would be spliced
consistently wrong on both sides and every default-suite test would stay green.

This test derives the map WITHOUT reading ``immutable_names``: from the runtime bytecode, the ABI
and ``immutableReferences`` alone. For each no-argument view getter in the ABI it finds the
dispatcher entry for the getter's selector (``PUSHn <selector> EQ PUSHn <dest> JUMPI``), walks
every path reachable from ``dest`` through constant jump targets, and records which
``immutableReferences`` id the walk loads (a ``PUSH32`` whose immediate starts at a referenced
offset — how legacy codegen reads an immutable). A public immutable's getter loads exactly its own
id and no other, so the getter's name names that id.

The committed fixtures carry no AST, so the compiler's own id -> declaration table is not
available here. As a one-off cross-check (2026-09-29, not re-run by this test), both fixtures'
maps were also confirmed from a fresh ``forge build --ast`` of the contract sources: the name ->
offsets pairing matched for ``Erc20Htlc`` (optimizer on, 200 runs) and ``EthHtlc`` (optimizer off).
The ``@integration`` Anvil test ``test_immutable_names_match_what_each_getter_RETURNS`` checks the
same map by EXECUTING each getter against sentinel values.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from Cryptodome.Hash import keccak  # pycryptodomex is a CORE dependency, so this never skips


def _selector(signature: str) -> int:
    return int.from_bytes(keccak.new(digest_bits=256, data=signature.encode()).digest()[:4], "big")


_FIXTURES = pathlib.Path(__file__).parent / "fixtures"
_ARTIFACTS = ["EthHtlc.json", "Erc20Htlc.json"]

_JUMP, _JUMPI, _JUMPDEST, _PUSH32 = 0x56, 0x57, 0x5B, 0x7F
#: Opcodes after which execution does not fall through to the next instruction.
_HALTS = {0x00, _JUMP, 0xF3, 0xFD, 0xFE, 0xFF}


def _decode(code: bytes) -> dict[int, tuple[int, bytes]]:
    """pc -> (opcode, immediate). PUSH1..PUSH32 carry 1..32 immediate bytes; nothing else does."""
    out: dict[int, tuple[int, bytes]] = {}
    pc = 0
    while pc < len(code):
        op = code[pc]
        n = op - 0x5F if 0x60 <= op <= 0x7F else 0
        out[pc] = (op, code[pc + 1 : pc + 1 + n])
        pc += 1 + n
    return out


def _is_push(op: int) -> bool:
    return 0x60 <= op <= 0x7F


def getter_reads(artifact: dict) -> dict[str, set[int]]:
    """``{getter-name: {offset, ...}}``: the ``immutableReferences`` OFFSETS each no-argument view
    getter's code path loads, from bytecode + ABI + ``immutableReferences`` only.

    Solidity splices each immutable into several offsets and a getter reads only one of them, so
    this also tells a test which copy is NOT the getter's (the copy ``claim()`` pays from, for
    ``claimant``) without hardcoding an offset that moves with every build.
    """
    code = bytes.fromhex(artifact["runtime_bytecode"].removeprefix("0x"))
    ops = _decode(code)
    pcs = sorted(ops)
    index = {pc: i for i, pc in enumerate(pcs)}
    referenced = {slot["start"] for slots in artifact["immutableReferences"].values() for slot in slots}

    reads: dict[str, set[int]] = {}
    for fn in artifact["abi"]:
        if fn.get("type") != "function" or fn.get("inputs") or fn.get("stateMutability") not in ("view", "pure"):
            continue
        selector = _selector(fn["name"] + "()")
        entries = []
        for i in range(len(pcs) - 3):
            (op0, imm0), (op1, _), (op2, imm2), (op3, _) = (ops[pcs[i + k]] for k in range(4))
            if (
                _is_push(op0)
                and int.from_bytes(imm0, "big") == selector
                and op1 == 0x14
                and _is_push(op2)
                and op3 == _JUMPI
            ):
                entries.append(int.from_bytes(imm2, "big"))
        assert len(entries) == 1, f"{fn['name']}: expected one dispatcher entry, found {entries}"
        assert ops.get(entries[0], (None,))[0] == _JUMPDEST, f"{fn['name']}: dispatcher target is not a JUMPDEST"

        offsets: set[int] = set()
        seen: set[int] = set()
        todo = list(entries)
        while todo:
            pc = todo.pop()
            if pc in seen or pc not in ops:
                continue
            seen.add(pc)
            op, _ = ops[pc]
            if op == _PUSH32 and pc + 1 in referenced:
                offsets.add(pc + 1)
            i = index[pc]
            prev_op, prev_imm = ops[pcs[i - 1]] if i else (None, b"")
            if op in (_JUMP, _JUMPI) and prev_op is not None and _is_push(prev_op):
                todo.append(int.from_bytes(prev_imm, "big"))
            if op not in _HALTS and i + 1 < len(pcs):
                todo.append(pcs[i + 1])
        reads[fn["name"]] = offsets
    return reads


def derive_immutable_names(artifact: dict) -> dict[str, str]:
    """``{reference-id: getter-name}`` derived from bytecode + ABI + ``immutableReferences`` only."""
    id_at = {slot["start"]: str(rid) for rid, slots in artifact["immutableReferences"].items() for slot in slots}
    derived: dict[str, str] = {}
    for name, offsets in getter_reads(artifact).items():
        loaded = {id_at[o] for o in offsets}
        if not loaded:
            continue  # a view getter over storage (Erc20Htlc's `settled`), not an immutable
        assert len(loaded) == 1, f"getter {name} loads several immutables {sorted(loaded)}; cannot name one"
        (rid,) = loaded
        assert rid not in derived, f"ref id {rid} is loaded by both {derived[rid]!r} and {name!r}"
        derived[rid] = name
    return derived


@pytest.mark.parametrize("name", _ARTIFACTS)
def test_immutable_names_equals_the_map_derived_from_the_bytecode(name):
    artifact = json.loads((_FIXTURES / name).read_text())
    derived = derive_immutable_names(artifact)
    # Non-vacuity: the derivation must name EVERY referenced immutable, so an equality below cannot
    # pass because the walk found nothing (or found only the ids the map happens to get right).
    assert set(derived) == {str(k) for k in artifact["immutableReferences"]}, (
        f"derivation named {sorted(derived)} of {sorted(artifact['immutableReferences'])}"
    )
    assert len(derived) >= 4
    assert derived == artifact["immutable_names"]


def test_the_derivation_catches_a_SWAPPED_map():
    """The failure this exists for, run every time rather than only when someone plants it: swap
    two names in the committed map and the derived map no longer equals it."""
    artifact = json.loads((_FIXTURES / "EthHtlc.json").read_text())
    by_name = {v: k for k, v in artifact["immutable_names"].items()}
    swapped = dict(artifact["immutable_names"])
    swapped[by_name["claimant"]], swapped[by_name["refundee"]] = "refundee", "claimant"
    assert derive_immutable_names(artifact) != swapped

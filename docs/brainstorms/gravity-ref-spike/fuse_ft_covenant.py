#!/usr/bin/env python3
"""Phase-4 fusion: transform a generated standard SPV maker covenant (.rxd)
into the FT variant per the design note. Reads the standard covenant on stdin,
writes the FT-fused .rxd on stdout. The 4 deltas (everything else verbatim):

1. Constructor: ADD bytes36 REF, int amount, bytes32 expectedTakerFtHash,
   bytes32 expectedMakerFtHash; DROP takerRadiantPkh + totalPhotonsInOutput.
2. Shared preamble (after the claimDeadline require, before `return {`):
   the 3 FT hardening constraints (== amount, single ref, output-count).
3. finalize route: P2PKH(takerRadiantPkh) -> hash256(output[0]) == expectedTakerFtHash.
4. forfeit route: P2PKH(makerPkh) -> hash256(output[0]) == expectedMakerFtHash.

The FT epilogue (bd d0 <ref> dec0..) is appended POST-COMPILE by the
substituter (build_prologue_ft.py style), NOT here.
"""
import re
import sys

src = sys.stdin.read()

# --- Delta 1: constructor params (flat path) ---
# Drop takerRadiantPkh and totalPhotonsInOutput lines. Also drop makerPkh —
# the forfeit route now hash-compares to expectedMakerFtHash (which the maker
# computes from its own pkh + ref), so the bare makerPkh param is unused.
src = re.sub(r"^\s*bytes20 takerRadiantPkh,\n", "", src, flags=re.MULTILINE)
src = re.sub(r"^\s*bytes20 makerPkh,\n", "", src, flags=re.MULTILINE)
# totalPhotonsInOutput is the LAST ctor param (no trailing comma). Replace the
# whole "    int totalPhotonsInOutput" with the new FT params.
src = src.replace(
    "    int totalPhotonsInOutput\n) {",
    "    int amount,\n"
    "    bytes32 expectedTakerFtHash,\n"
    "    bytes32 expectedMakerFtHash,\n"
    "    bytes36 REF\n) {",
)

# --- Delta 2: shared preamble after the claimDeadline require ---
# The flat path emits `require(claimDeadline >= <floor>);` then a blank line
# then `    return {`. Insert the FT hardening just before `    return {`.
preamble = (
    "\n"
    "    // --- FT hardening (runs on both branches); see Phase-2 proof ---\n"
    "    bytes36 ref = pushInputRef(REF);\n"
    "    require(tx.outputs.length == 1);\n"
    "    require(tx.outputs.refOutputCount(ref) == 1);\n"
    "    require(tx.outputs.refValueSum(ref) == amount);\n"
)
assert "\n    return {" in src, "could not find `return {` insertion point"
src = src.replace("\n    return {", preamble + "\n    return {", 1)

# --- Delta 3: finalize route -> hash-compare to taker FT ---
src = src.replace(
    "            // --- Route to Taker ---\n"
    "            bytes25 takerLock = new LockingBytecodeP2PKH(takerRadiantPkh);\n"
    "            require(tx.outputs[0].lockingBytecode == takerLock);\n"
    "            require(tx.outputs[0].value >= totalPhotonsInOutput);",
    "            // --- Route to Taker FT (exact FT code-script via hash-compare) ---\n"
    "            require(hash256(tx.outputs[0].lockingBytecode) == expectedTakerFtHash);",
)

# --- Delta 4: forfeit route -> hash-compare to maker FT ---
src = src.replace(
    "            require(tx.time >= claimDeadline);\n"
    "            bytes25 makerLock = new LockingBytecodeP2PKH(makerPkh);\n"
    "            require(tx.outputs[0].lockingBytecode == makerLock);\n"
    "            require(tx.outputs[0].value >= totalPhotonsInOutput);",
    "            require(tx.time >= claimDeadline);\n"
    "            require(hash256(tx.outputs[0].lockingBytecode) == expectedMakerFtHash);",
)

# Rename the contract so the artifact is distinct.
src = re.sub(r"contract MakerCovenantFlat(\w+)\(", r"contract GravityFtCovenantFlat\1(", src)

# Sanity: the dropped params must be gone; the new ones present.
assert "takerRadiantPkh" not in src, "takerRadiantPkh leaked into FT covenant"
assert "totalPhotonsInOutput" not in src, "totalPhotonsInOutput leaked"
assert "LockingBytecodeP2PKH" not in src, "P2PKH route not fully replaced"
assert "expectedTakerFtHash" in src and "expectedMakerFtHash" in src
assert "pushInputRef(REF)" in src

# AUDIT 2026-05-24 M-FUSE-1: ROUTE-FIRED post-asserts — confirm the Delta-3/4
# route BODIES were actually rewritten (the hash-compares installed), not just
# that the new param NAMES exist. A silent `.replace` no-op on generator drift
# would otherwise ship an unhardened route that still compiles.
assert "hash256(tx.outputs[0].lockingBytecode) == expectedTakerFtHash" in src, (
    "Delta-3 finalize route did NOT fire — taker hash-compare missing (generator drift?)"
)
assert "hash256(tx.outputs[0].lockingBytecode) == expectedMakerFtHash" in src, (
    "Delta-4 forfeit route did NOT fire — maker hash-compare missing (generator drift?)"
)
assert "takerLock" not in src and "makerLock" not in src, (
    "old P2PKH route variables survived — a route replacement did not fully fire"
)

sys.stdout.write(src)

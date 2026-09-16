"""Script-construction primitives for the dMint subpackage.

Locking-script builders (V1 + V2), DAA helpers (ASERT, linear), and
the low-level push helpers. Depends on ``.types`` only.

``build_mint_scriptsig`` lives in ``.miner`` despite its name — its
sole callers are the mint-tx assembly functions, so the call cluster
stays local to that module.

NOTE ON PLAN DEVIATION: The plan placed ``_V1_EPILOGUE_PREFIX``,
``_V1_EPILOGUE_ALGO_OFFSET``, ``_V1_EPILOGUE_SUFFIX``, and
``_V1_EPILOGUE_LEN`` in ``chain.py``. However, ``build_dmint_v1_code_script``
(assigned to ``builders.py``) uses those constants directly, which would
require a ``builders → chain`` import and violate the one-way dependency
graph. Moving these four constants here resolves the cycle: ``chain.py``
imports them from ``builders.py`` via the allowed ``chain → builders``
edge. The ``_match_v1_epilogue`` function (which also uses them) is in
``chain.py`` and imports them from here.

Symbols (23 + 4 epilogue constants shared with chain):
    _push_minimal, _push_4bytes_le,
    _PART_A, _POW_HASH_OP,
    _build_asert_daa_legacy, _build_linear_daa_legacy, _build_linear_daa_legacy_prefloor,
    _build_asert_daa_v2, _build_linear_daa_v2, _build_epoch_daa, _build_schedule_daa,
    _build_part_b, DetectedDaaBytecode, detect_daa_bytecode,
    build_dmint_state_script, build_dmint_code_script,
    build_dmint_contract_script,
    _V1_ALGO_BYTE_TO_ENUM, _V1_ENUM_TO_ALGO_BYTE,
    build_dmint_v1_state_script, build_dmint_v1_code_script,
    _V1_FT_OUTPUT_EPILOGUE, build_dmint_v1_ft_output_script,
    build_dmint_v1_contract_script,
    _V1_EPILOGUE_PREFIX, _V1_EPILOGUE_ALGO_OFFSET,
    _V1_EPILOGUE_SUFFIX, _V1_EPILOGUE_LEN
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from pyrxd.security.errors import UnrecognizedDaaBytecodeError, ValidationError

from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types
from .types import (
    _OP_STATESEPARATOR,
    _PART_B1,
    _PART_B2,
    _PART_B4,
    ASERT_V2_DRIFT_CLAMP,
    ASERT_V2_RADIX,
    DEFAULT_ASERT_HALFLIFE,
    MAX_SHA256D_TARGET,
    DaaBytecodeVersion,
    DaaMode,
    DmintAlgo,
    DmintDeployParams,
)

# ---------------------------------------------------------------------------
# Minimal-push helpers (mirrors Photonic Wallet `pushMinimal` in script.ts)
# ---------------------------------------------------------------------------


def _push_minimal(n: int) -> bytes:
    """Encode integer n using Bitcoin script minimal push encoding."""
    if n == 0:
        return b"\x00"  # OP_0
    if n == -1:
        return b"\x4f"  # OP_1NEGATE
    if 1 <= n <= 16:
        return bytes([0x50 + n])  # OP_1 .. OP_16
    # General case: little-endian with sign bit.
    negative = n < 0
    n = abs(n)
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    payload = bytes(result)
    # Prefix with length byte (PUSHDATA1 if needed)
    length = len(payload)
    if length < 0x4C:
        return bytes([length]) + payload
    if length <= 0xFF:
        return b"\x4c" + bytes([length]) + payload
    raise ValidationError(f"pushMinimal: number too large: {n}")


def _push_4bytes_le(n: int) -> bytes:
    """Encode n as a 4-byte little-endian push (push opcode + 4 bytes)."""
    return b"\x04" + struct.pack("<I", n)


def _encode_data_push(data: bytes) -> bytes:
    """Prefix ``data`` with the minimal push opcode (mirrors libauth ``encodeDataPush``).

    Direct push for ``len < 0x4c``; ``0x4c`` PUSHDATA1 for ``[0x4c, 0xff]``;
    ``0x4d`` PUSHDATA2 / ``0x4e`` PUSHDATA4 beyond. The V2 PartC middle-literal
    blob (~83 bytes) lands in the PUSHDATA1 branch.
    """
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", n) + data
    return b"\x4e" + struct.pack("<I", n) + data


# ---------------------------------------------------------------------------
# V2 bytecode constants (from script.ts §4.3)
# ---------------------------------------------------------------------------

# Part A: preimage construction for V2 (10 state items).
#
# Byte-identical to the canonical Photonic ``buildDmintPreimageBytecodePartA(10)``
# (Radiant-Core/Photonic-Wallet, post-2026-05-26 redesign). Validated against a
# golden vector generated from that source (tests/test_dmint_v2_canonical.py).
#
# contractRefPickIndex = 10 - 1 = 9  → pushMinimal(9) = 0x59 (OP_9)
# inputOutputPickIndex = 10 + 3 = 13 → pushMinimal(13) = 0x5d (OP_13)
# nonceRollIndex       = 10 + 4 = 14 → pushMinimal(14) = 0x5e (OP_14)
#
# OP_INPUTINDEX (0xc0) before OP_OUTPOINTTXHASH (0xc8): the latter is a unary
# introspection op that pops an input index off the stack; 0xc0 supplies it.
# The canonical redesign opens straight at ``c0 c8`` — there is NO leading
# ``51 75`` (OP_1 OP_DROP). The old pyrxd/Photonic shape prefixed ``51 75``,
# which the redesign removed.
_PART_A = bytes.fromhex(
    "c0"  # OP_INPUTINDEX  (pushes current input index for OP_OUTPOINTTXHASH)
    "c8"  # OP_OUTPOINTTXHASH
    "59"  # pushMinimal(9) = OP_9
    "79"  # OP_PICK
    "7e"  # OP_CAT
    "a8"  # OP_SHA256
    "5d"  # pushMinimal(13) = OP_13
    "79"  # OP_PICK
    "5d"  # pushMinimal(13) = OP_13
    "79"  # OP_PICK
    "7e"  # OP_CAT
    "a8"  # OP_SHA256
    "7e"  # OP_CAT
    "5e"  # pushMinimal(14) = OP_14
    "7a"  # OP_ROLL
    "7e"  # OP_CAT
)

# PoW hash opcodes per algorithm
_POW_HASH_OP: dict[DmintAlgo, bytes] = {
    DmintAlgo.SHA256D: b"\xaa",  # OP_HASH256
    DmintAlgo.BLAKE3: b"\xee",  # OP_BLAKE3
    DmintAlgo.K12: b"\xef",  # OP_K12
}


# ---------------------------------------------------------------------------
# DAA bytecode builders
# ---------------------------------------------------------------------------
#
# TWO GENERATIONS of ASERT/LWMA retarget bytecode exist on chain, and both are
# built here (``DaaBytecodeVersion`` in ``.types`` names them):
#
# * ``_build_asert_daa_v2`` / ``_build_linear_daa_v2`` — the CURRENT canonical
#   fractional fixed-point retarget. Byte-for-byte transcriptions of
#   ``buildAsertDaaBytecode`` / ``buildLinearDaaBytecode`` in
#   Radiant-Core/Photonic-Wallet ``packages/lib/src/script.ts`` at commit
#   ``becf41a731e78ab98fdd88652527d7dda12784c6`` (upstream landed ASERT-v2 on
#   2026-06-19, ``ed53cd41``, and LWMA-v2 on 2026-06-20, ``c90e6506``; pyrxd
#   resynced on 2026-09-16). Every new deploy gets these.
# * ``_build_asert_daa_legacy`` / ``_build_linear_daa_legacy`` /
#   ``_build_linear_daa_legacy_prefloor`` — FROZEN. They are the bytecode pyrxd
#   emitted before the resync (the integer power-of-2 ASERT stepper; the
#   unity-gain LWMA with, and on 2026-06-16 without, the ``OP_0 OP_MAX``
#   timeDelta floor). They exist ONLY so a contract deployed under them can be
#   recognised (``detect_daa_bytecode``) and mined under the formula baked into
#   it. A covenant's bytecode is immutable: "fixing" these functions cannot
#   change any deployed contract, it can only make pyrxd unable to mine one.
#   ``tests/test_dmint_daa_v2_resync.py`` pins their bytes.
#
# Both generations share the Part B1/B2 prologue and the Part B4 epilogue and the
# same stack contract (entry ``[..., daaMode, targetTime, lastTime, target]`` with
# ``target`` on top; exit with ``newTarget`` in its place), so Part C is unchanged.
#
# Why the legacy ASERT shape looks the way it does: the pre-redesign ASERT used
# OP_LSHIFT/OP_RSHIFT (0x98/0x99), which Radiant Core evaluates as a big-endian
# bit-string shift — wrong for the 8-byte LE target encoding — so the 2026-05-26
# redesign replaced the shift with an UNROLLED OP_2MUL/OP_2DIV loop (4 steps) with
# per-step overflow caps. The legacy LWMA divides first with timeDelta and target
# caps so OP_MUL never overflows int64 (Radiant-Core/Photonic-Wallet#2 added the
# timeDelta floor). Both were validated against Photonic golden vectors at the time
# (tests/test_dmint_v2_canonical.py history) and are consensus-proven on regtest
# and mainnet.

# 8-byte LE pushes of MAX_TARGET and its /2, /4 (used as overflow caps).
_PUSH_MAX_TARGET = bytes.fromhex("08ffffffffffffff7f")  # 0x7fff_ffff_ffff_ffff
_PUSH_HALF_MAX_TARGET = bytes.fromhex("08ffffffffffffff3f")  # MAX/2
# Photonic ``PUSH_QUARTER_MAX_TARGET = "08ffffffffffffff1f"`` — MAX_TARGET/4 as 8-byte LE.
_PUSH_QUARTER_MAX_TARGET = bytes.fromhex("08ffffffffffffff1f")  # MAX/4
# Minimal push of EPOCH_MAX_SAFE_TARGET (2^48). 7-byte minimal LE (07 + 6×00 + 01).
# EPOCH clamps the target to this on BOTH sides of the retarget multiply so it
# can never overflow int64 (Radiant-Core/Photonic-Wallet#2).
_PUSH_EPOCH_MAX_SAFE_TARGET = bytes.fromhex("0700000000000001")  # 2^48

# ASERT-v2 / LWMA-v2 constant pushes — Photonic ``pushMinimal`` of the constants
# (script.ts comments: 65536 → "03000001"; the clamps are the 2-byte LE pushes
# 16384 → "020040" and -16384 → "0200c0", sign bit on the high byte).
_PUSH_ASERT_V2_RADIX = _push_minimal(ASERT_V2_RADIX)  # 03 00 00 01
_PUSH_ASERT_V2_CLAMP = _push_minimal(ASERT_V2_DRIFT_CLAMP)  # 02 00 40  (+16384)
_PUSH_ASERT_V2_NEG_CLAMP = _push_minimal(-ASERT_V2_DRIFT_CLAMP)  # 02 00 c0  (-16384)

# The 7-byte ``excess`` preamble every ASERT generation (and LWMA-v2) opens with:
# OP_TXLOCKTIME, OP_2 PICK lastTime, OP_SUB, OP_3 PICK targetTime, OP_SUB.
_V2_EXCESS_PREAMBLE = bytes.fromhex("c5527994537994")
# v2 discriminator right after the preamble: ``<RADIX push> OP_MUL``. The legacy
# ASERT goes straight to ``<halfLife push> OP_DIV`` there (its 5th byte is OP_DIV
# 0x96, never OP_MUL 0x95 — even for halfLife 65536, whose push is the same
# ``03000001`` bytes), and the legacy LWMA never computes ``excess`` at all: its
# 7th byte is OP_4 (``…5379 54 95 a3`` = OP_3 PICK OP_4 OP_MUL OP_MIN), not OP_SUB.
_ASERT_V2_SIGNATURE = _PUSH_ASERT_V2_RADIX + b"\x95"  # 03 00 00 01 95

# One unrolled positive-drift step: if drift_rem>0 then target = (target>MAX/2 ?
# MAX : target*2), drift_rem -= 1. Entry stack [drift_rem, target, ...].
_ASERT_2MUL_STEP = (
    bytes.fromhex("7600a0")  # DUP 0 GREATERTHAN
    + b"\x63"  # IF
    + b"\x8c"  #   1SUB drift_rem
    + b"\x7c"  #   SWAP
    + b"\x76"  #   DUP target
    + _PUSH_HALF_MAX_TARGET
    + b"\xa0"  #   GREATERTHAN (target > MAX/2?)
    + b"\x63"  #   IF
    + b"\x75"  #     DROP target
    + _PUSH_MAX_TARGET  #     push MAX
    + b"\x67"  #   ELSE
    + b"\x8d"  #     2MUL
    + b"\x68"  #   ENDIF
    + b"\x7c"  #   SWAP back
    + b"\x68"  # ENDIF
)

# One unrolled negative-drift step: if |drift|_rem>0 then target //= 2, dec.
_ASERT_2DIV_STEP = bytes.fromhex("7600a0638c7c8e7c68")


def _build_asert_daa_legacy(half_life: int) -> bytes:
    """LEGACY integer power-of-2 ASERT DAA bytecode — FROZEN, pre-2026-06-19 formula.

    Retained ONLY so contracts deployed before the ASERT-v2 resync keep mining
    under the exact formula baked into their codescript: ``detect_daa_bytecode``
    recognises them and the mint builder recomputes their target with
    :func:`pyrxd.glyph.dmint.miner.compute_next_target_asert_legacy`. **Never emit
    for a new deploy** — this is the structurally broken stepper the v2 redesign
    replaced (dead zone for ``|excess| < halfLife``; one-sided when
    ``halfLife >= targetTime``, so difficulty can only ratchet down or freeze;
    ≥2× lurches off a single miner-chosen nLockTime). Its bytes are pinned by
    ``tests/test_dmint_daa_v2_resync.py``; changing them makes every legacy
    ASERT contract unmineable by pyrxd and fixes nothing on chain.

    Entry stack: ``[target, lastTime, targetTime, daaMode, ...]``. Computes
    ``drift = (currentTime - lastTime - targetTime) / halfLife`` clamped to
    ``[-4, +4]``, then shifts ``target`` left (drift>0) or right (drift<0) by
    ``|drift|`` via the unrolled 2MUL/2DIV steps, and clamps ``target`` ≥ 1.
    """
    half_life_push = _push_minimal(half_life)
    return (
        b"\xc5"  # OP_TXLOCKTIME → currentTime
        + b"\x52\x79"  # OP_2 PICK lastTime
        + b"\x94"  # OP_SUB → time_delta
        + b"\x53\x79"  # OP_3 PICK targetTime
        + b"\x94"  # OP_SUB → excess
        + half_life_push
        + b"\x96"  # OP_DIV → drift
        # clamp drift to [-4, +4]
        + bytes.fromhex("7654a0")  # DUP OP_4 GREATERTHAN
        + b"\x63"  # IF
        + bytes.fromhex("7554")  #   DROP, push 4
        + b"\x68"  # ENDIF
        + bytes.fromhex("76548f")  # DUP OP_4 NEGATE
        + b"\x9f"  # LESSTHAN
        + b"\x63"  # IF
        + bytes.fromhex("75548f")  #   DROP, push -4
        + b"\x68"  # ENDIF
        # apply shift: drift>0 → 4× conditional 2MUL; drift<0 → NEGATE then 4× 2DIV
        + bytes.fromhex("7600a0")  # DUP 0 GREATERTHAN
        + b"\x63"  # IF (positive)
        + _ASERT_2MUL_STEP * 4
        + b"\x75"  #   DROP drift_remaining
        + b"\x67"  # ELSE
        + bytes.fromhex("76009f")  # DUP 0 LESSTHAN
        + b"\x63"  # IF (negative)
        + b"\x8f"  #   NEGATE → |drift|
        + _ASERT_2DIV_STEP * 4
        + b"\x75"  #   DROP |drift|_remaining
        + b"\x67"  # ELSE (zero)
        + b"\x75"  #   DROP drift
        + b"\x68"  # ENDIF
        + b"\x68"  # ENDIF
        # clamp target to minimum 1
        + bytes.fromhex("76519f")  # DUP OP_1 LESSTHAN
        + b"\x63"  # IF
        + bytes.fromhex("7551")  #   DROP, push 1
        + b"\x68"  # ENDIF
    )


def _build_linear_daa_legacy() -> bytes:
    """LEGACY unity-gain LWMA DAA bytecode WITH the timeDelta floor — FROZEN.

    ``new_target = (min(target, MAX/4) / targetTime) × clamp(timeDelta, 0, 4×targetTime)``,
    then ``min(MAX)`` and ``≥ 1``. This is what pyrxd emitted from 2026-06-17
    (the Radiant-Core/Photonic-Wallet#2 ``OP_0 OP_MAX`` floor) to 2026-09-15, and
    what ``tests/test_dmint_v2_regtest_e2e.py`` proved on consensus in that window.
    Retained ONLY for ``detect_daa_bytecode`` and the legacy mint path
    (:func:`pyrxd.glyph.dmint.miner.compute_next_target_linear_legacy`); **never
    emit for a new deploy** — upstream replaced it with the damped LWMA-v2 on
    2026-06-20 because it could jump difficulty 4× in one block and slam the target
    to 1 on a zero-delta block. Bytes pinned by ``tests/test_dmint_daa_v2_resync.py``.

    The 0-floor (``OP_0 OP_MAX``) is required because a block's nLockTime may be
    earlier than the previous mint's (it need only exceed the 11-block
    median-time-past), making ``timeDelta`` negative; without the floor
    ``(target/targetTime) × negativeDelta`` underflows int64 and OP_MUL aborts.
    """
    return (
        b"\xc5"  # OP_TXLOCKTIME → currentTime
        + b"\x52\x79"  # OP_2 PICK lastTime
        + b"\x94"  # OP_SUB → timeDelta
        + b"\x53\x79"  # OP_3 PICK targetTime
        + b"\x54"  # OP_4
        + b"\x95"  # OP_MUL → 4×targetTime
        + b"\xa3"  # OP_MIN → timeDelta_capped (upper)
        + b"\x00"  # OP_0
        + b"\xa4"  # OP_MAX → timeDelta_capped = max(0, min(4×targetTime, delta))
        + b"\x7c"  # SWAP → target on top
        + _PUSH_QUARTER_MAX_TARGET
        + b"\xa3"  # OP_MIN → target_capped
        + b"\x53\x79"  # OP_3 PICK targetTime
        + b"\x96"  # OP_DIV → target_capped / targetTime
        + b"\x95"  # OP_MUL → × timeDelta_capped = newTarget
        + _PUSH_MAX_TARGET
        + b"\xa3"  # OP_MIN (defensive cap)
        # clamp newTarget to minimum 1
        + bytes.fromhex("76519f")  # DUP 1 LESSTHAN
        + b"\x63"  # IF
        + bytes.fromhex("7551")  #   DROP 1
        + b"\x68"  # ENDIF
    )


def _build_linear_daa_legacy_prefloor() -> bytes:
    """LEGACY unity-gain LWMA DAA bytecode WITHOUT the timeDelta floor — FROZEN.

    Identical to :func:`_build_linear_daa_legacy` minus the two ``OP_0 OP_MAX``
    bytes. This is what pyrxd emitted on 2026-06-16 (commit ``d75dec5``), before
    Radiant-Core/Photonic-Wallet#2 added the floor — and therefore the bytecode of
    the mainnet LWMA deploy ``dea3beb9…`` whose mint ``e7b52f16…`` lowered the
    target on chain. That contract MUST stay mineable, so the template is kept and
    ``detect_daa_bytecode`` classifies it as ``DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR``.
    For every ``timeDelta >= 0`` (which the mint builder already requires) it
    computes exactly what the floored variant computes; for a negative delta the
    on-chain OP_MUL aborts instead of flooring. Bytes reconstructed from the
    ``d75dec5`` builder and pinned by ``tests/test_dmint_daa_v2_resync.py``.
    """
    floored = _build_linear_daa_legacy()
    floor = b"\x00\xa4"  # OP_0 OP_MAX — the #2 floor, inserted after the upper cap
    idx = floored.index(b"\xa3" + floor)
    return floored[: idx + 1] + floored[idx + 1 + len(floor) :]


def _build_asert_daa_v2(half_life: int) -> bytes:
    """ASERT-v2 DAA bytecode — fractional, symmetric, damped (the CURRENT formula).

    Byte-for-byte transcription of canonical Photonic ``buildAsertDaaBytecode``
    (``packages/lib/src/script.ts`` at ``becf41a``; upstream commit ``ed53cd41``,
    2026-06-19) and the on-chain half of
    :func:`pyrxd.glyph.dmint.miner.compute_next_target_asert_v2` /
    ``packages/lib/src/dmintDaaV2.ts`` ``computeAsertV2Target``. Golden
    byte-match: ``tests/test_dmint_daa_v2_resync.py``.

    Entry stack ``[target, lastTime, targetTime, daaMode, ...]`` (target on top)::

        excess    = (currentTime - lastTime) - targetTime
        driftFp   = (excess * RADIX) / halfLife            # signed, OP_DIV trunc toward 0
        driftFp   = clamp(driftFp, -RADIX/4, +RADIX/4)     # ±25%/mint damping
        t         = min(target, MAX_TARGET/4)              # difficulty floor 4 (as LWMA)
        newTarget = clamp(t + (t / RADIX) * driftFp, 1, MAX_TARGET/4)

    Divide-first keeps every intermediate inside int64 (proof in
    ``compute_next_target_asert_v2``), so unlike the legacy stepper there is no
    INVALID_NUMBER_RANGE_64_BIT risk, no dead zone, no one-sided ratchet and no 2×
    lurch. Uses only opcodes already present in deployed dMint contracts
    (OP_MUL/DIV/MIN/MAX/ROT). The stack contract is identical to the legacy
    builder, so Part B2/B4 and Part C are unchanged.
    """
    if isinstance(half_life, bool) or not isinstance(half_life, int) or half_life < 1:
        # Mirrors the canonical builder's guard (``halfLife must be an integer >= 1``);
        # DmintDeployParams enforces it too. A 0 here would bake OP_DIV by zero.
        raise ValidationError(f"ASERT: half_life must be an integer >= 1 (got {half_life!r})")
    half_life_push = _push_minimal(half_life)
    return (
        b"\xc5"  # OP_TXLOCKTIME → currentTime
        + b"\x52\x79"  # OP_2 PICK lastTime
        + b"\x94"  # OP_SUB → timeDelta = currentTime - lastTime
        + b"\x53\x79"  # OP_3 PICK targetTime
        + b"\x94"  # OP_SUB → excess = timeDelta - targetTime
        + _PUSH_ASERT_V2_RADIX  # push RADIX
        + b"\x95"  # OP_MUL → excess * RADIX
        + half_life_push  # push halfLife
        + b"\x96"  # OP_DIV → driftFp  (truncates toward zero)
        # Clamp driftFp to [-RADIX/4, +RADIX/4] via OP_MIN / OP_MAX.
        + _PUSH_ASERT_V2_CLAMP  # push +16384
        + b"\xa3"  # OP_MIN → min(driftFp, +16384)
        + _PUSH_ASERT_V2_NEG_CLAMP  # push -16384
        + b"\xa4"  # OP_MAX → driftFp clamped
        # t = min(target, MAX_TARGET/4). Bring target to top first.
        + b"\x7c"  # OP_SWAP → [target, driftFp, ...]
        + _PUSH_QUARTER_MAX_TARGET  # push MAX_TARGET/4
        + b"\xa3"  # OP_MIN → t
        # newTarget = t + (t / RADIX) * driftFp   (divide-first ⇒ overflow-safe)
        + b"\x76"  # OP_DUP t → [t, t, driftFp, ...]
        + _PUSH_ASERT_V2_RADIX  # push RADIX
        + b"\x96"  # OP_DIV → t / RADIX
        + b"\x7b"  # OP_ROT → bring driftFp to top: [driftFp, tdiv, t, ...]
        + b"\x95"  # OP_MUL → delta = (t/RADIX) * driftFp
        + b"\x93"  # OP_ADD → newTarget = t + delta
        # Clamp newTarget to [1, MAX_TARGET/4].
        + _PUSH_QUARTER_MAX_TARGET  # push MAX_TARGET/4
        + b"\xa3"  # OP_MIN
        + bytes.fromhex("76519f")  # DUP OP_1 LT
        + b"\x63"  # IF
        + bytes.fromhex("7551")  #   DROP, push 1
        + b"\x68"  # ENDIF
    )


def _build_linear_daa_v2() -> bytes:
    """LWMA-v2 DAA bytecode — fractional, symmetric, damped (the CURRENT formula).

    Byte-for-byte transcription of canonical Photonic ``buildLinearDaaBytecode``
    (``packages/lib/src/script.ts`` at ``becf41a``; upstream commit ``c90e6506``,
    2026-06-20) and the on-chain half of
    :func:`pyrxd.glyph.dmint.miner.compute_next_target_linear_v2` /
    ``packages/lib/src/dmintDaaV2.ts`` ``computeLwmaV2Target``. It is the ASERT-v2
    template with the responsiveness gain auto-set to ``targetTime`` — ``OP_3 PICK
    targetTime`` where ASERT pushes its ``halfLife`` constant — so a 2×-target block
    hits the ±25%/mint clamp::

        excess    = (currentTime - lastTime) - targetTime
        driftFp   = (excess * RADIX) / targetTime          # gain = 1/targetTime
        driftFp   = clamp(driftFp, -RADIX/4, +RADIX/4)      # ±25%/block damping
        t         = min(target, MAX_TARGET/4)               # diff floor 4
        newTarget = clamp(t + (t / RADIX) * driftFp, 1, MAX_TARGET/4)

    ``targetTime >= 1`` is deploy-enforced, so the OP_DIV never divides by zero.
    Golden byte-match: ``tests/test_dmint_daa_v2_resync.py``.
    """
    return (
        b"\xc5"  # OP_TXLOCKTIME → currentTime
        + b"\x52\x79"  # OP_2 PICK lastTime
        + b"\x94"  # OP_SUB → timeDelta = currentTime - lastTime
        + b"\x53\x79"  # OP_3 PICK targetTime
        + b"\x94"  # OP_SUB → excess = timeDelta - targetTime
        + _PUSH_ASERT_V2_RADIX  # push RADIX
        + b"\x95"  # OP_MUL → excess * RADIX
        + b"\x53\x79"  # OP_3 PICK targetTime  (the gain divisor — distinguishes LWMA from ASERT)
        + b"\x96"  # OP_DIV → driftFp = (excess * RADIX) / targetTime
        # Clamp driftFp to [-RADIX/4, +RADIX/4].
        + _PUSH_ASERT_V2_CLAMP  # push +16384
        + b"\xa3"  # OP_MIN
        + _PUSH_ASERT_V2_NEG_CLAMP  # push -16384
        + b"\xa4"  # OP_MAX → driftFp clamped
        # t = min(target, MAX_TARGET/4). Bring target to top first.
        + b"\x7c"  # OP_SWAP → [target, driftFp, ...]
        + _PUSH_QUARTER_MAX_TARGET  # push MAX_TARGET/4
        + b"\xa3"  # OP_MIN → t
        # newTarget = t + (t / RADIX) * driftFp   (divide-first ⇒ overflow-safe)
        + b"\x76"  # OP_DUP t
        + _PUSH_ASERT_V2_RADIX  # push RADIX
        + b"\x96"  # OP_DIV → t / RADIX
        + b"\x7b"  # OP_ROT → bring driftFp to top
        + b"\x95"  # OP_MUL → delta = (t/RADIX) * driftFp
        + b"\x93"  # OP_ADD → newTarget = t + delta
        # Clamp newTarget to [1, MAX_TARGET/4].
        + _PUSH_QUARTER_MAX_TARGET  # push MAX_TARGET/4
        + b"\xa3"  # OP_MIN
        + bytes.fromhex("76519f")  # DUP 1 LT
        + b"\x63"  # IF
        + bytes.fromhex("7551")  #   DROP 1
        + b"\x68"  # ENDIF
    )


def _build_epoch_daa(epoch_length: int, max_adjustment_log2: int) -> bytes:
    """EPOCH DAA bytecode (byte-matched to canonical ``buildEpochDaaBytecode``).

    Periodic retarget — only adjusts at epoch boundaries. When ``height > 0`` and
    ``height % epoch_length == 0``::

        delta        = currentTime - lastTime
        clampedDelta = max(targetTime>>N, min(targetTime<<N, delta))   # N = max_adjustment_log2
        newTarget    = max(1, min(2^48, (min(target, 2^48) // targetTime) * clampedDelta))

    otherwise the target is unchanged. The target is clamped to 2^48 on BOTH
    sides of the multiply and the divide runs FIRST, so the intermediate is
    ``(≤ 2^48 / targetTime) × (≤ targetTime × 16) ≤ 2^52`` and OP_MUL never
    overflows int64 for any reachable state (Radiant-Core/Photonic-Wallet#2). The
    earlier ``target × clampedDelta`` (multiply-first, MAX_TARGET output cap) let
    target drift past 2^48 and bricked the contract at a boundary mint.
    ``N`` is a deploy-time power-of-2 exponent
    (1..4 → 2×/4×/8×/16×); the shift is emitted as N× OP_2MUL / OP_2DIV (not
    OP_LSHIFT/RSHIFT, which are big-endian-buffer-wise and wrong on LE script
    numbers). Height is at state position 9 (OP_9 PICK).
    """
    lshift_n = b"\x8d" * max_adjustment_log2  # N × OP_2MUL  (targetTime << N)
    rshift_n = b"\x8e" * max_adjustment_log2  # N × OP_2DIV  (targetTime >> N)
    return (
        bytes.fromhex("5979")  # OP_9 PICK — copy height
        + b"\x76"  # DUP
        + bytes.fromhex("00a0")  # OP_0 GREATERTHAN — height > 0?
        + b"\x7c"  # SWAP
        + _push_minimal(epoch_length)
        + b"\x97"  # OP_MOD — height % epoch_length
        + bytes.fromhex("009c")  # OP_0 NUMEQUAL — == 0?
        + b"\x9a"  # OP_BOOLAND
        + b"\x63"  # IF (boundary)
        + b"\xc5"  # TXLOCKTIME — currentTime
        + bytes.fromhex("5279")  # OP_2 PICK lastTime
        + b"\x94"  # SUB → delta
        + bytes.fromhex("5379")  # OP_3 PICK targetTime
        + lshift_n  # upperBound = targetTime × 2^N
        + b"\xa3"  # MIN
        + bytes.fromhex("5379")  # OP_3 PICK targetTime
        + rshift_n  # lowerBound = targetTime / 2^N
        + b"\xa4"  # MAX → clampedDelta
        # newTarget = min(2^48, (min(target, 2^48) // targetTime) × clampedDelta)
        + b"\x7c"  # SWAP → [target, clampedDelta, ...]
        + _PUSH_EPOCH_MAX_SAFE_TARGET  # push 2^48
        + b"\xa3"  # MIN → target_capped = min(target, 2^48)
        + bytes.fromhex("5379")  # OP_3 PICK targetTime
        + b"\x96"  # DIV → target_capped // targetTime
        + b"\x95"  # MUL — × clampedDelta = newTarget (≤ 2^52)
        + _PUSH_EPOCH_MAX_SAFE_TARGET  # push 2^48
        + b"\xa3"  # MIN → cap newTarget at 2^48
        + bytes.fromhex("76519f")  # DUP 1 LESSTHAN
        + b"\x63"  # IF
        + bytes.fromhex("7551")  #   DROP 1
        + b"\x68"  # ENDIF
        + b"\x68"  # ENDIF (outer)
    )


def _build_schedule_daa(schedule: tuple[tuple[int, int], ...]) -> bytes:
    """SCHEDULE DAA bytecode (byte-matched to canonical ``buildScheduleDaaBytecode``).

    A pre-baked, time-independent difficulty curve: a nested descending IF chain
    that sets ``target`` to the entry of the highest boundary ``height`` reached.
    If ``height`` is below the lowest boundary the target is unchanged. Built
    inside-out from an ascending-by-height ``schedule`` (so the outermost check is
    the highest boundary).
    """
    body = b""
    for height, target in schedule:
        body = (
            bytes.fromhex("5979")  # OP_9 PICK — copy height
            + _push_minimal(height)  # boundary
            + b"\xa2"  # GREATERTHANOREQUAL
            + b"\x63"  # IF
            + b"\x75"  # DROP old target
            + _push_minimal(target)  # new target
            + (b"\x67" if body else b"")  # ELSE (only if a deeper fallback exists)
            + body
            + b"\x68"  # ENDIF
        )
    return body


def _daa_bytes_for(
    daa_mode: DaaMode,
    half_life: int,
    *,
    epoch_length: int,
    max_adjustment_log2: int,
    schedule: tuple[tuple[int, int], ...],
    daa_bytecode_version: DaaBytecodeVersion,
) -> bytes:
    """The DAA fragment of Part B for ``daa_mode`` under ``daa_bytecode_version``.

    FIXED has no fragment. EPOCH and SCHEDULE have a single generation, so the
    version is ignored for them. ASERT and LWMA route on the version:
    ``V2`` → the canonical fractional builders (every new deploy); ``LEGACY`` →
    the frozen pre-resync builders; ``LEGACY_LWMA_PREFLOOR`` → the 2026-06-16 LWMA
    (an ASERT request under that version is an error — no such contract exists).
    """
    if daa_mode == DaaMode.FIXED:
        return b""  # fixed difficulty — no DAA bytecode
    if daa_mode == DaaMode.ASERT:
        if daa_bytecode_version == DaaBytecodeVersion.V2:
            return _build_asert_daa_v2(half_life)
        if daa_bytecode_version == DaaBytecodeVersion.LEGACY:
            return _build_asert_daa_legacy(half_life)
        raise ValueError(f"no ASERT bytecode exists for {daa_bytecode_version!r}")
    if daa_mode == DaaMode.LWMA:
        if daa_bytecode_version == DaaBytecodeVersion.V2:
            return _build_linear_daa_v2()
        if daa_bytecode_version == DaaBytecodeVersion.LEGACY:
            return _build_linear_daa_legacy()
        if daa_bytecode_version == DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR:
            return _build_linear_daa_legacy_prefloor()
        raise ValueError(f"unknown DaaBytecodeVersion: {daa_bytecode_version!r}")
    if daa_mode == DaaMode.EPOCH:
        return _build_epoch_daa(epoch_length, max_adjustment_log2)
    if daa_mode == DaaMode.SCHEDULE:
        return _build_schedule_daa(schedule)
    raise ValueError(f"unknown DaaMode: {daa_mode!r}")


def _build_part_b(
    daa_mode: DaaMode,
    half_life: int = DEFAULT_ASERT_HALFLIFE,
    *,
    epoch_length: int = 2016,
    max_adjustment_log2: int = 2,
    schedule: tuple[tuple[int, int], ...] = (),
    daa_bytecode_version: DaaBytecodeVersion = DaaBytecodeVersion.V2,
) -> bytes:
    """Assemble Part B: PoW extract (B1) + target compare (B2) + DAA + stack cleanup (B4).

    ``daa_bytecode_version`` defaults to ``V2`` — the canonical fractional
    ASERT-v2 / LWMA-v2 retarget every NEW deploy must carry. The legacy versions
    exist ONLY so the mint builder can rebuild — and byte-verify against — the Part
    B of a contract deployed before the 2026-09-16 resync
    (:func:`detect_daa_bytecode` says which one a contract has). Ignored for
    FIXED/EPOCH/SCHEDULE, which have a single generation.
    """
    daa_bytes = _daa_bytes_for(
        daa_mode,
        half_life,
        epoch_length=epoch_length,
        max_adjustment_log2=max_adjustment_log2,
        schedule=schedule,
        daa_bytecode_version=daa_bytecode_version,
    )
    return _PART_B1 + _PART_B2 + daa_bytes + _PART_B4


# ---------------------------------------------------------------------------
# DAA bytecode-generation detection (which formula a deployed contract bakes)
# ---------------------------------------------------------------------------

#: Byte offset of the DAA fragment inside a V2 code section (the bytes AFTER the
#: 0xbd separator): Part A (16) + the 1-byte powHashOp + Part B1 (18) + Part B2 (5).
#: Derived from the constants, not typed; ``tests/test_dmint_daa_v2_resync.py``
#: checks it against the bytes ``build_dmint_code_script`` actually emits.
_DAA_BODY_OFFSET_IN_CODE = len(_PART_A) + 1 + len(_PART_B1) + len(_PART_B2)


@dataclass(frozen=True)
class DetectedDaaBytecode:
    """What :func:`detect_daa_bytecode` found baked into a contract's Part B.

    :param daa_mode:  The mode that was asked about (ASERT or LWMA).
    :param version:   Which retarget-formula generation the bytecode is.
    :param daa_bytes: The exact DAA fragment that matched, byte-for-byte.
    :param half_life: ASERT only — the half-life constant READ OUT OF the bytecode
                      (``None`` for LWMA, which bakes no parameter). This is the
                      ground truth a miner must use; a caller-supplied value that
                      differs from it produces a target the covenant rejects.
    """

    daa_mode: DaaMode
    version: DaaBytecodeVersion
    daa_bytes: bytes
    half_life: int | None = None


def _read_minimal_int_push(data: bytes, pos: int) -> tuple[int, int]:
    """Read one MINIMALLY-encoded script-number push at ``pos`` → ``(value, next_pos)``.

    Accepts exactly the encodings Photonic ``pushMinimal`` / :func:`_push_minimal`
    produce — OP_0, OP_1NEGATE, OP_1..OP_16, or a 1..8-byte direct push whose payload
    is a minimal CScriptNum — and refuses anything else with ``ValidationError``.
    Strictness is the point: Radiant runs with SCRIPT_VERIFY_MINIMALDATA mandatory
    (``policy.h`` MANDATORY_SCRIPT_VERIFY_FLAGS), so a non-minimal number push inside
    a covenant makes the CScriptNum constructor throw and the contract unmineable;
    such a contract must be reported, not mined.
    """
    if pos >= len(data):
        raise ValidationError(f"script-number push expected at offset {pos}, but the code ends there")
    op = data[pos]
    if op == 0x00:
        return 0, pos + 1
    if op == 0x4F:
        return -1, pos + 1
    if 0x51 <= op <= 0x60:
        return op - 0x50, pos + 1
    if not 1 <= op <= 8:
        raise ValidationError(f"opcode 0x{op:02x} at offset {pos} is not a minimal script-number push")
    payload = data[pos + 1 : pos + 1 + op]
    if len(payload) != op:
        raise ValidationError(f"script-number push at offset {pos} is truncated")
    # CScriptNum::IsMinimallyEncoded: the top byte may be 0x00/0x80 only to carry a
    # sign bit the byte below could not; and values in [-1, 16] must use the opcodes.
    if (payload[-1] & 0x7F) == 0 and (len(payload) == 1 or not (payload[-2] & 0x80)):
        raise ValidationError(f"non-minimal script-number push {payload.hex()} at offset {pos}")
    value = int.from_bytes(payload, "little")
    if payload[-1] & 0x80:
        value = -(value ^ (0x80 << (8 * (len(payload) - 1))))
    if -1 <= value <= 16:
        raise ValidationError(f"script number {value} at offset {pos} must be pushed as an opcode, not data")
    return value, pos + 1 + op


def _unrecognized(daa_mode: DaaMode, body: bytes, why: str) -> UnrecognizedDaaBytecodeError:
    return UnrecognizedDaaBytecodeError(
        f"{daa_mode.name} contract carries retarget bytecode pyrxd does not recognise ({why}); "
        f"DAA fragment starts {body[:24].hex()!r}. Known generations: "
        f"{', '.join(v.name for v in DaaBytecodeVersion)}. Refusing to guess a formula — a "
        "wrong one produces a next state the covenant rejects after the PoW grind."
    )


def detect_daa_bytecode(code: bytes, daa_mode: DaaMode) -> DetectedDaaBytecode:
    """Classify which ASERT/LWMA retarget-formula generation a V2 contract bakes.

    ``code`` is the contract's code section — the bytes AFTER the ``0xbd``
    OP_STATESEPARATOR (what ``build_dmint_code_script`` returns and what follows
    the parsed state in a UTXO script). ``daa_mode`` is the mode the state script
    declares (item 6); this function checks the CODE agrees with it.

    Recognition is rebuild-and-compare, not a prefix sniff: the half-life constant is
    read out of the bytecode, the candidate template is rebuilt from it with the
    same builder a deploy would use, and the whole fragment (plus the Part B4 that
    must follow it) has to match byte-for-byte. So a contract is classified only if
    pyrxd can reproduce its exact bytes, which is also the condition under which
    the mint builder can recompute its target. The discriminators, verified against
    the bytes the builders emit (``tests/test_dmint_daa_v2_resync.py``):

    * ASERT: after the 7-byte ``excess`` preamble ``c5 5279 94 5379 94``, v2 has
      ``<RADIX push> OP_MUL`` = ``03000001 95``; legacy has ``<halfLife push> OP_DIV``
      (5th byte ``96``, never ``95`` — even for halfLife 65536).
    * LWMA: v2 shares the preamble and signature, then ``5379 96`` (OP_3 PICK OP_DIV)
      as the gain divisor; legacy has no ``excess`` at all — ``c5 5279 94 5379 54 95
      a3`` (OP_4 OP_MUL OP_MIN), with (``LEGACY``) or without
      (``LEGACY_LWMA_PREFLOOR``) the ``00 a4`` timeDelta floor.

    Mirrors Photonic's Glyph-miner ``extractDaaParamsFromCodeScript`` in intent, with
    one deliberate difference from the Radiant-Core fork this was ported from: that
    fork's ``_asert_version_of_code`` classified ANY fragment lacking the v2 signature
    as legacy (``return 2 if sig else 1``), so a corrupt or unknown contract would be
    mined under a guessed formula. Here an unrecognised fragment is REPORTED with
    :class:`~pyrxd.security.errors.UnrecognizedDaaBytecodeError` (naming the bytes).

    :raises ValueError: ``daa_mode`` is not ASERT or LWMA — FIXED/EPOCH/SCHEDULE
        have a single generation and are byte-verified by rebuilding Part B from
        the deploy parameters instead.
    :raises UnrecognizedDaaBytecodeError: the code is not a V2 dMint template, or
        its DAA fragment matches no known generation of ``daa_mode``.
    """
    if daa_mode not in (DaaMode.ASERT, DaaMode.LWMA):
        raise ValueError(
            f"detect_daa_bytecode: {daa_mode.name} has a single bytecode generation; rebuild Part B from the "
            "deploy params to verify it"
        )
    body = code[_DAA_BODY_OFFSET_IN_CODE:]
    pow_op = code[len(_PART_A) : len(_PART_A) + 1]
    template_ok = (
        code[: len(_PART_A)] == _PART_A
        and pow_op in _POW_HASH_OP.values()
        and code[len(_PART_A) + 1 : _DAA_BODY_OFFSET_IN_CODE] == _PART_B1 + _PART_B2
    )
    if not template_ok:
        raise _unrecognized(daa_mode, code, "the code section does not open with the V2 Part A/B1/B2 template")

    if daa_mode == DaaMode.ASERT:
        try:
            if body.startswith(_V2_EXCESS_PREAMBLE + _ASERT_V2_SIGNATURE):
                version = DaaBytecodeVersion.V2
                half_life, _ = _read_minimal_int_push(body, len(_V2_EXCESS_PREAMBLE) + len(_ASERT_V2_SIGNATURE))
                candidate = _build_asert_daa_v2(half_life)
            elif body.startswith(_V2_EXCESS_PREAMBLE):
                version = DaaBytecodeVersion.LEGACY
                half_life, _ = _read_minimal_int_push(body, len(_V2_EXCESS_PREAMBLE))
                if half_life < 1:
                    raise ValidationError(f"legacy ASERT half-life {half_life} < 1")
                candidate = _build_asert_daa_legacy(half_life)
            else:
                raise _unrecognized(daa_mode, body, "no ASERT excess preamble")
        except UnrecognizedDaaBytecodeError:
            raise
        except ValidationError as exc:
            raise _unrecognized(daa_mode, body, f"half-life push unreadable: {exc}") from exc
        if not body.startswith(candidate + _PART_B4):
            raise _unrecognized(daa_mode, body, f"fragment diverges from the {version.name} ASERT template")
        return DetectedDaaBytecode(daa_mode, version, candidate, half_life)

    # LWMA bakes no parameter: compare against each generation's whole fragment.
    for version, candidate in (
        (DaaBytecodeVersion.V2, _build_linear_daa_v2()),
        (DaaBytecodeVersion.LEGACY, _build_linear_daa_legacy()),
        (DaaBytecodeVersion.LEGACY_LWMA_PREFLOOR, _build_linear_daa_legacy_prefloor()),
    ):
        if body.startswith(candidate + _PART_B4):
            return DetectedDaaBytecode(daa_mode, version, candidate, None)
    raise _unrecognized(daa_mode, body, "fragment matches no LWMA generation")


# ---------------------------------------------------------------------------
# Part C (output-validation block) — deploy-parameterized in the redesign
# ---------------------------------------------------------------------------
#
# In the redesign Part C is no longer a fixed constant. On every mint it rebuilds
# the expected next-state script FROM SCRATCH and OP_EQUALVERIFYs it against the
# actual next output, so it must embed the deploy's immutable middle slots
# (items 2-8) as a literal blob and reconstruct the variable height/target via a
# runtime MINIMAL_PUSH primitive. lastTime is rebuilt from OP_TXLOCKTIME, target
# from the alt-stack value PartB4 stashed. This is what lets ASERT/LWMA actually
# advance difficulty (the old shared-with-V1 _PART_C forbade any state change but
# height). Transcribed verbatim from Photonic ``buildV2PartC`` + ``MINIMAL_PUSH_BYTECODE``.

# MINIMAL_PUSH primitive: pops script-number n (≥0), pushes the bytes that would
# minimal-push n. Branches: n==0 → "00"; n in [1..16] → 0x50+n; else <len><LE>.
# Inlined twice in Part C (height, target).
_MINIMAL_PUSH_BYTECODE = bytes.fromhex("76009c63750100677660a163015093518067827c7e6868")


def _build_part_c(middle_literal: bytes) -> bytes:
    """Build the deploy-parameterized V2 Part C (output-validation block).

    ``middle_literal`` is items 2-8 of the state script (the immutable slots:
    ``d8 contractRef | d0 tokenRef | maxHeight | reward | algoId | daaId |
    targetTime``). It is wrapped with the minimal push opcode and baked in so
    the covenant can reconstruct the next state without parsing it on-chain.
    """
    mid_push = _encode_data_push(middle_literal)
    # Prologue: input/output script-ref check + height increment + maxHeight branch.
    prologue = bytes.fromhex(
        "577ae500a069567ae600a06901d053797e0cdec0e9aa76e378e4a269e69d7e"
        "aa76e47b9d547a818b76537a9c537ade789181547ae6939d63"
    )
    # IF branch (final mint, newHeight == maxHeight): consume alt-stack newTarget,
    # then the token-burn output check.
    if_branch = bytes.fromhex("6c755279cd01d853797e016a7e88")
    # ELSE branch (continue mining): rebuild expected_state from scratch.
    else_branch = (
        bytes.fromhex("78de519d")  # OVER REFOUTPUTCOUNT_OUTPUTS 1 NUMEQUALVERIFY
        + b"\x76"  # DUP newHeight (MUST be DUP 0x76, not OVER — see Photonic note)
        + _MINIMAL_PUSH_BYTECODE  # → newHeightPush
        + mid_push  # push literal middle blob
        + b"\x7e"  # CAT
        + bytes.fromhex("c55480547c7e7e")  # TXLOCKTIME 4 NUM2BIN OP_4 SWAP CAT CAT (append lastTime)
        + b"\x6c"  # FROMALTSTACK newTarget
        + _MINIMAL_PUSH_BYTECODE  # → newTargetPush
        + b"\x7e"  # CAT
        # continuation-verify epilogue (codescript continuity + output value == reward)
        + bytes.fromhex("5379ec7888")  # 3 PICK STATESCRIPTBYTECODE_NOSEP OVER EQUALVERIFY
        + bytes.fromhex("5379eac0e988")  # 3 PICK OUTPUTCODESCRIPTBYTECODE INPUTINDEX 0xe9 EQUALVERIFY
        + bytes.fromhex("5379cc519d")  # 3 PICK OUTPUTVALUE 1 NUMEQUALVERIFY
        + b"\x75"  # DROP
    )
    epilogue = bytes.fromhex("686d7551")  # ENDIF 2DROP DROP push-1
    return prologue + if_branch + b"\x67" + else_branch + epilogue


# ---------------------------------------------------------------------------
# State script + full contract script
# ---------------------------------------------------------------------------


def _middle_literal(params: DmintDeployParams) -> bytes:
    """The immutable state slots 2-8 (shared by the state script and Part C)."""
    return (
        b"\xd8"
        + params.contract_ref.to_bytes()
        + b"\xd0"
        + params.token_ref.to_bytes()
        + _push_minimal(params.max_height)
        + _push_minimal(params.reward)
        + _push_minimal(int(params.algo))
        + _push_minimal(int(params.daa_mode))
        + _push_minimal(params.target_time)
    )


def build_dmint_state_script(params: DmintDeployParams) -> bytes:
    """Build the 10-item V2 dMint state script (before OP_STATESEPARATOR).

    Layout (canonical redesign §4.2)::

        height(minimal) | d8:contractRef(36B) | d0:tokenRef(36B) |
        maxHeight | reward | algoId | daaMode | targetTime |
        lastTime(4B LE) | target(minimal)

    ``height`` and ``target`` use minimal pushes (variable width) so the state
    script is MINIMALDATA-compliant from height 0 / target MAX onward — the old
    fixed ``04 [LE4]`` height push was rejected by radiantd's MINIMALDATA mempool
    policy on mainnet. ``lastTime`` stays a 4-byte push (Unix timestamps are
    always 4-byte minimal), which simplifies Part C's ``04 || NUM2BIN(4, locktime)``
    reconstruction.
    """
    return (
        _push_minimal(params.height)
        + _middle_literal(params)
        + _push_4bytes_le(params.last_time)
        + _push_minimal(params.initial_target)
    )


def build_dmint_code_script(params: DmintDeployParams) -> bytes:
    """Build the V2 dMint code bytecode (Part A + powHashOp + Part B + Part C)."""
    pow_op = _POW_HASH_OP[params.algo]
    part_b = _build_part_b(
        params.daa_mode,
        params.half_life,
        epoch_length=params.epoch_length,
        max_adjustment_log2=params.max_adjustment_log2,
        schedule=params.schedule,
    )
    part_c = _build_part_c(_middle_literal(params))
    return _PART_A + pow_op + part_b + part_c


def build_dmint_contract_script(params: DmintDeployParams) -> bytes:
    """Build the full V2 dMint output script: state + OP_STATESEPARATOR + code.

    Byte-identical to the canonical Photonic ``dMintScript`` for the same
    parameters (validated against golden vectors in
    tests/test_dmint_v2_canonical.py, and consensus-proven on regtest + mainnet).
    """
    state = build_dmint_state_script(params)
    code = build_dmint_code_script(params)
    return state + _OP_STATESEPARATOR + code


# ---------------------------------------------------------------------------
# V1 dMint builders
# ---------------------------------------------------------------------------
#
# V1 is the only dMint contract format observed on Radiant mainnet. It has 6
# state items (height, contractRef, tokenRef, maxHeight, reward, target) and
# a 145-byte fixed code epilogue with one selector byte for the algorithm.
# Documented in docs/dmint-research-mainnet.md §2.2 (byte-by-byte) and §3
# (common template). The V1 parser (DmintState._from_v1_script) and
# fingerprint helpers (_match_v1_epilogue) are the inverse of these.

_V1_ALGO_BYTE_TO_ENUM: dict[int, DmintAlgo] = {
    0xAA: DmintAlgo.SHA256D,  # OP_HASH256
    0xEE: DmintAlgo.BLAKE3,  # OP_BLAKE3
    0xEF: DmintAlgo.K12,  # OP_K12
}
# Inverse derived from the source-of-truth mapping above. Building the
# inverse mechanically prevents drift: a future contributor adding e.g.
# DmintAlgo.SCRYPT only needs to extend the byte→enum map, and the
# enum→byte direction follows automatically.
_V1_ENUM_TO_ALGO_BYTE: dict[DmintAlgo, int] = {enum: byte for byte, enum in _V1_ALGO_BYTE_TO_ENUM.items()}


# --- V1 dMint contract fingerprinting -------------------------------------
#
# V1 is the only variant deployed on Radiant mainnet today. Its 145-byte code
# epilogue (starting at OP_STATESEPARATOR / 0xbd) is byte-identical across
# all V1 deployments EXCEPT for one byte: the algo selector at offset 19
# inside the epilogue (script-relative byte ~115, depending on state size).
# That byte is one of:
#   0xaa = OP_HASH256   → SHA256D
#   0xee = OP_BLAKE3    → BLAKE3
#   0xef = OP_K12       → K12
# We fingerprint the epilogue with that one byte wildcarded.
# Sources: docs/dmint-research-mainnet.md §2.2 (byte-by-byte decode of a
# real mainnet V1 contract), §3 ("Common template" block, offsets 79+).
#
# NOTE: These constants are defined in builders.py (not chain.py as the
# plan originally specified) because build_dmint_v1_code_script uses them
# here, and placing them in chain.py would require a builders → chain import
# that violates the one-way dependency graph. chain.py imports these from
# builders.py via the allowed chain → builders edge.

_V1_EPILOGUE_PREFIX = bytes.fromhex("bd5175c0c855797ea8597959797ea87e5a7a7e")
_V1_EPILOGUE_ALGO_OFFSET = 19  # offset INSIDE the epilogue (where the algo byte lives)
_V1_EPILOGUE_SUFFIX = bytes.fromhex(
    "bc01147f77587f040000000088"  # post-algo header through "load 4-byte zero, OP_EQUALVERIFY"
    "817600a269a269"
    "577ae500a069567ae600a069"
    "01d053797e0cdec0e9aa76e378e4a269e69d7eaa"  # FT-CSH builder + canonical fingerprint
    "76e47b9d"
    "547a818b"
    "76537a9c537ade789181547ae6939d"
    "635279cd01d853797e016a7e88"
    "67"
    "78de519d547854807ec0eb557f777e"
    "5379ec78885379eac0e9885379cc519d"
    "7568"
    "6d7551"
)
_V1_EPILOGUE_LEN = len(_V1_EPILOGUE_PREFIX) + 1 + len(_V1_EPILOGUE_SUFFIX)
# _V1_ALGO_BYTE_TO_ENUM and its inverse _V1_ENUM_TO_ALGO_BYTE are defined
# above so the V1 builder helpers can reference the inverse mapping.
# Single source of truth: byte→enum.


def build_dmint_v1_state_script(
    height: int,
    contract_ref: GlyphRef,
    token_ref: GlyphRef,
    max_height: int,
    reward: int,
    target: int,
) -> bytes:
    """Build the 6-item V1 dMint state script (before OP_STATESEPARATOR).

    Layout (docs/dmint-research-mainnet.md §2.2 offsets 0–94)::

        height(4B LE) | d8 contractRef(36B) | d0 tokenRef(36B) |
        maxHeight | reward | target(0x08 + 8B LE)

    The target is always pushed as a fixed 8-byte little-endian value
    (push opcode 0x08, then 8 bytes of payload). This is what
    distinguishes V1 from V2 in the state-script discriminator at parse
    time: V2's item 5 is ``algoId`` via ``_push_minimal``, never an
    8-byte push.

    :raises ValidationError: ``height < 0``; ``max_height < 1``;
        ``height >= max_height`` (born-exhausted contract); ``reward < 1``;
        ``target`` not in ``[1, MAX_SHA256D_TARGET]``. The upper target
        bound is ``MAX_SHA256D_TARGET = 0x7fff...ff`` rather than ``2**64``
        because Bitcoin script integers are signed: pushing a value with
        the high bit set produces a negative number on the stack, and the
        on-chain target comparison would behave wrongly. Photonic Wallet's
        ``dMintDiffToTarget`` formula always produces a value in this
        signed-positive range.
    """
    if height < 0:
        raise ValidationError("height must be >= 0")
    if max_height < 1:
        raise ValidationError("max_height must be >= 1")
    if height >= max_height:
        raise ValidationError(
            f"height ({height}) must be < max_height ({max_height}); "
            f"a contract built with height >= max_height is born-exhausted "
            f"and pool funds would be locked at deploy time"
        )
    if reward < 1:
        raise ValidationError("reward must be >= 1 photon")
    if not 1 <= target <= MAX_SHA256D_TARGET:
        raise ValidationError(
            f"target must be in [1, MAX_SHA256D_TARGET=0x{MAX_SHA256D_TARGET:x}], "
            f"got {target} (top-bit-set values are negative in Bitcoin script "
            f"semantics and the on-chain comparison would behave wrongly)"
        )

    return (
        _push_4bytes_le(height)
        + b"\xd8"
        + contract_ref.to_bytes()
        + b"\xd0"
        + token_ref.to_bytes()
        + _push_minimal(max_height)
        + _push_minimal(reward)
        + b"\x08"
        + struct.pack("<Q", target)
    )


def build_dmint_v1_code_script(algo: DmintAlgo) -> bytes:
    """Build the V1 dMint code epilogue (the 145 bytes after OP_STATESEPARATOR).

    Returns ``_V1_EPILOGUE_PREFIX + <algo_byte> + _V1_EPILOGUE_SUFFIX`` where
    ``algo_byte`` is the on-chain hash opcode for the requested algorithm
    (0xaa SHA256D, 0xee BLAKE3, 0xef K12). The byte sequence matches every
    V1 contract decoded from mainnet; ``_match_v1_epilogue`` is the inverse.

    :raises ValidationError: ``algo`` is not a recognized :class:`DmintAlgo`
        value (which would be a programming bug — the enum class enforces
        membership).
    """
    try:
        algo_byte = _V1_ENUM_TO_ALGO_BYTE[algo]
    except KeyError as exc:
        raise ValidationError(f"unsupported V1 algo: {algo!r}") from exc
    return _V1_EPILOGUE_PREFIX + bytes([algo_byte]) + _V1_EPILOGUE_SUFFIX


# 12-byte fingerprint baked into the V1 covenant at offset 148 of the code
# epilogue. The covenant builds the expected FT-output codescript hash by
# prepending 0xd0 + tokenRef and appending these 12 bytes, then HASH256s it
# (`_V1_EPILOGUE_SUFFIX` opcodes 01 d0 53 79 7e 0c <12 bytes> 7e aa). The
# miner's reward output script must end with these exact bytes so that
# the FT-conservation check passes.
# Source: docs/dmint-research-mainnet.md §2.2 offset 148, §4 vout[1] hex.
_V1_FT_OUTPUT_EPILOGUE = bytes.fromhex("dec0e9aa76e378e4a269e69d")


def build_dmint_v1_ft_output_script(
    miner_pkh: bytes,
    token_ref: GlyphRef,
) -> bytes:
    """Build the 75-byte P2PKH-wrapped FT output that a V1 mint produces.

    Layout (docs/dmint-research-mainnet.md §4 vout[1])::

        76 a9 14 <pkh:20>     OP_DUP OP_HASH160 PUSH20 pkh
        88 ac                 OP_EQUALVERIFY OP_CHECKSIG    (25-byte P2PKH prologue)
        bd                    OP_STATESEPARATOR
        d0 <tokenRef:36>      OP_PUSHINPUTREF tokenRef       (37 bytes)
        de c0 e9 aa 76 e3     12-byte covenant fingerprint   (`_V1_FT_OUTPUT_EPILOGUE`)
        78 e4 a2 69 e6 9d
        ──────────────────────
        Total: 75 bytes

    This is the **FT-bearing** reward output — the V1 contract's
    ``OP_CODESCRIPTHASHVALUESUM_OUTPUTS OP_NUMEQUALVERIFY`` at epilogue
    offset 168 sums photons under this codescript and requires the total
    to equal the contract's ``reward`` field. Producing a plain P2PKH
    instead breaks FT conservation and the network rejects the mint.

    :raises ValidationError: ``miner_pkh`` is not 20 bytes.
    """
    if len(miner_pkh) != 20:
        raise ValidationError(f"miner_pkh must be 20 bytes, got {len(miner_pkh)}")
    p2pkh_prologue = b"\x76\xa9\x14" + miner_pkh + b"\x88\xac"
    return p2pkh_prologue + _OP_STATESEPARATOR + b"\xd0" + token_ref.to_bytes() + _V1_FT_OUTPUT_EPILOGUE


def build_dmint_v1_contract_script(
    height: int,
    contract_ref: GlyphRef,
    token_ref: GlyphRef,
    max_height: int,
    reward: int,
    target: int,
    algo: DmintAlgo = DmintAlgo.SHA256D,
) -> bytes:
    """Build a full V1 dMint output script: state followed by V1 code epilogue.

    Note: V1's code epilogue begins with the OP_STATESEPARATOR byte (0xbd) —
    see ``_V1_EPILOGUE_PREFIX``. Unlike the V2 builder (which interpolates a
    separate ``_OP_STATESEPARATOR``), this function concatenates state and
    epilogue directly. Total length is 241 bytes for typical mainnet
    parameters (96-byte state + 145-byte epilogue), matching the byte-by-byte
    decode in docs/dmint-research-mainnet.md §2.2.

    The output of this function round-trips through
    :meth:`DmintState.from_script` with ``is_v1=True``.
    """
    state = build_dmint_v1_state_script(
        height=height,
        contract_ref=contract_ref,
        token_ref=token_ref,
        max_height=max_height,
        reward=reward,
        target=target,
    )
    return state + build_dmint_v1_code_script(algo)

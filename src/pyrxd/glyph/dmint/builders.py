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

Symbols (17 + 4 epilogue constants shared with chain):
    _push_minimal, _push_4bytes_le,
    _PART_A, _POW_HASH_OP,
    _build_asert_daa, _build_linear_daa, _build_part_b,
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

from pyrxd.security.errors import ValidationError

from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types
from .types import (
    _OP_STATESEPARATOR,
    _PART_B1,
    _PART_B2,
    _PART_B4,
    MAX_SHA256D_TARGET,
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
# DAA bytecode builders (byte-identical to the canonical Photonic redesign)
# ---------------------------------------------------------------------------
#
# The pre-redesign ASERT used OP_LSHIFT/OP_RSHIFT (0x98/0x99), which Radiant
# Core evaluates as a big-endian bit-string shift — wrong for the 8-byte LE
# target encoding, so every nonzero drift diverged from the miner's bigint
# shift. It also used 0x81 (OP_BIN2NUM) where it meant 0x8f (OP_NEGATE). The
# redesign replaces the shift with an UNROLLED OP_2MUL/OP_2DIV loop (4 steps)
# that operates correctly on multi-byte LE script numbers, with per-step
# overflow caps. The linear/LWMA DAA divides-first with timeDelta and target
# caps so OP_MUL never overflows int64. Both are transcribed verbatim from
# Radiant-Core/Photonic-Wallet ``buildAsertDaaBytecode`` / ``buildLinearDaaBytecode``
# and validated against golden vectors (tests/test_dmint_v2_canonical.py).

# 8-byte LE pushes of MAX_TARGET and its /2, /4 (used as overflow caps).
_PUSH_MAX_TARGET = bytes.fromhex("08ffffffffffffff7f")  # 0x7fff_ffff_ffff_ffff
_PUSH_HALF_MAX_TARGET = bytes.fromhex("08ffffffffffffff3f")  # MAX/2
_PUSH_QUARTER_MAX_TARGET = bytes.fromhex("08ffffffffffffff1f")  # MAX/4

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


def _build_asert_daa(half_life: int) -> bytes:
    """ASERT-lite DAA bytecode (§4.5). half_life embedded as a constant.

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


def _build_linear_daa() -> bytes:
    """Linear/LWMA DAA bytecode (§4.6). ``new_target = target * timeDelta / targetTime``.

    Divide-first with caps so OP_MUL never overflows int64: timeDelta is capped
    to ``4×targetTime`` and target to ``MAX_TARGET/4`` (so LWMA contracts need
    difficulty ≥ 4), then ``(target_capped / targetTime) × timeDelta_capped``,
    final MIN against MAX_TARGET, clamp ≥ 1.
    """
    return (
        b"\xc5"  # OP_TXLOCKTIME → currentTime
        + b"\x52\x79"  # OP_2 PICK lastTime
        + b"\x94"  # OP_SUB → timeDelta
        + b"\x53\x79"  # OP_3 PICK targetTime
        + b"\x54"  # OP_4
        + b"\x95"  # OP_MUL → 4×targetTime
        + b"\xa3"  # OP_MIN → timeDelta_capped
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


def _build_part_b(daa_mode: DaaMode, half_life: int) -> bytes:
    if daa_mode == DaaMode.FIXED:
        daa_bytes = b""  # fixed difficulty — no DAA bytecode
    elif daa_mode == DaaMode.ASERT:
        daa_bytes = _build_asert_daa(half_life)
    elif daa_mode == DaaMode.LWMA:
        daa_bytes = _build_linear_daa()
    elif daa_mode in (DaaMode.EPOCH, DaaMode.SCHEDULE):
        # Defined in the protocol but not yet implemented in pyrxd. Earlier
        # versions silently fell through to FIXED (empty daa_bytes), which
        # would deploy a contract with no DAA logic — irreversible on
        # mainnet for a PoW-dMint consumer that asked for adaptive difficulty.
        # Refuse to build rather than ship a footgun.
        raise NotImplementedError(
            f"DaaMode.{daa_mode.name} is defined in the protocol but not yet "
            "implemented in pyrxd. Use FIXED, ASERT, or LWMA, or contribute "
            "the missing bytecode emitter."
        )
    else:
        raise ValueError(f"unknown DaaMode: {daa_mode!r}")
    return _PART_B1 + _PART_B2 + daa_bytes + _PART_B4


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
    part_b = _build_part_b(params.daa_mode, params.half_life)
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

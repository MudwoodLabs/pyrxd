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
import warnings

from pyrxd.security.errors import ValidationError

from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types
from .types import (
    _OP_STATESEPARATOR,
    _PART_B1,
    _PART_B2,
    _PART_B4,
    _PART_C,
    MAX_SHA256D_TARGET,
    DaaMode,
    DmintAlgo,
    DmintDeployParams,
    V2UnvalidatedWarning,
    _warn_v2_unvalidated,
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


# ---------------------------------------------------------------------------
# V2 bytecode constants (from script.ts §4.3)
# ---------------------------------------------------------------------------

# Part A: preimage construction for V2 (10 state items).
#
# contractRefPickIndex = 10 - 1 = 9  → pushMinimal(9) = 0x59 (OP_9)
# inputOutputPickIndex = 10 + 3 = 13 → pushMinimal(13) = 0x5d (OP_13)
# nonceRollIndex       = 10 + 4 = 14 → pushMinimal(14) = 0x5e (OP_14)
_PART_A = bytes.fromhex(
    "51"  # OP_1
    "75"  # OP_DROP
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


def _build_asert_daa(half_life: int) -> bytes:
    """ASERT-lite DAA bytecode (§4.5). half_life embedded as constant."""
    half_life_push = _push_minimal(half_life)
    # Entry: [target, lastTime, targetTime, daaMode, ...]
    return (
        # Step 1: currentTime = OP_TXLOCKTIME
        b"\xc5"  # OP_TXLOCKTIME
        # Step 2: time_delta = currentTime - lastTime
        b"\x52\x79"  # OP_2 OP_PICK
        b"\x94"  # OP_SUB
        # Step 3: excess = time_delta - targetTime
        b"\x53\x79"  # OP_3 OP_PICK
        b"\x94" + half_life_push + b"\x96"  # OP_SUB
        # Step 4: drift = excess / halfLife  # OP_DIV
        # Step 5: clamp drift to [-4, +4]
        b"\x76\x54\xa0"  # DUP OP_4 OP_GREATERTHAN
        b"\x63"  # OP_IF
        b"\x75\x54"  #   OP_DROP OP_4
        b"\x68"  # OP_ENDIF
        b"\x76\x54\x81\x9f"  # DUP OP_4 OP_NEGATE OP_LESSTHAN
        b"\x63"  # OP_IF
        b"\x75\x54\x81"  #   OP_DROP OP_4 OP_NEGATE
        b"\x68"  # OP_ENDIF
        # Step 6: apply shift
        b"\x76\x00\xa0"  # DUP OP_0 OP_GREATERTHAN
        b"\x63"  # OP_IF (drift > 0 → LSHIFT)
        b"\x98"  #   OP_LSHIFT
        b"\x67"  # OP_ELSE
        b"\x76\x00\x9f"  #   DUP OP_0 OP_LESSTHAN
        b"\x63"  #   OP_IF (drift < 0 → RSHIFT)
        b"\x81\x99"  #     OP_NEGATE OP_RSHIFT
        b"\x67"  #   OP_ELSE (drift == 0)
        b"\x75"  #     OP_DROP
        b"\x68"  #   OP_ENDIF
        b"\x68"  # OP_ENDIF
        # Step 7: clamp target to minimum 1
        b"\x76\x51\x9f"  # DUP OP_1 OP_LESSTHAN
        b"\x63"  # OP_IF
        b"\x75\x51"  #   OP_DROP OP_1
        b"\x68"  # OP_ENDIF
    )


def _build_linear_daa() -> bytes:
    """Linear DAA bytecode (§4.6). new_target = old_target * time_delta / targetTime."""
    return (
        b"\xc5"  # OP_TXLOCKTIME → currentTime
        b"\x52\x79"  # OP_2 OP_PICK lastTime
        b"\x94"  # OP_SUB → time_delta
        b"\x7c"  # OP_SWAP
        b"\x95"  # OP_MUL
        b"\x53\x79"  # OP_3 OP_PICK targetTime
        b"\x96"  # OP_DIV → new_target
        # Clamp to minimum 1
        b"\x76\x51\x9f"
        b"\x63"
        b"\x75\x51"
        b"\x68"
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
# State script + full contract script
# ---------------------------------------------------------------------------


def build_dmint_state_script(params: DmintDeployParams) -> bytes:
    """Build the 10-item V2 dMint state script (before OP_STATESEPARATOR).

    Layout (§4.2):
        height(4B LE) | d8:contractRef(36B) | d0:tokenRef(36B) |
        maxHeight | reward | algoId | daaMode | targetTime |
        lastTime(4B LE) | target

    .. warning::
       V2 has never been validated on Radiant mainnet (no V2 contract
       exists as of pyrxd 0.5.1). Emits :class:`V2UnvalidatedWarning`
       once per call site. Use V1 (``build_dmint_v1_state_script``)
       unless you have a specific reason to test V2.
    """
    _warn_v2_unvalidated()
    target = params.initial_target
    return (
        _push_4bytes_le(params.height)
        + b"\xd8"
        + params.contract_ref.to_bytes()
        + b"\xd0"
        + params.token_ref.to_bytes()
        + _push_minimal(params.max_height)
        + _push_minimal(params.reward)
        + _push_minimal(int(params.algo))
        + _push_minimal(int(params.daa_mode))
        + _push_minimal(params.target_time)
        + _push_4bytes_le(params.last_time)
        + _push_minimal(target)
    )


def build_dmint_code_script(params: DmintDeployParams) -> bytes:
    """Build the V2 dMint code bytecode (Part A + powHashOp + Part B + Part C).

    .. warning::
       V2-only. See :class:`V2UnvalidatedWarning`.
    """
    _warn_v2_unvalidated()
    pow_op = _POW_HASH_OP[params.algo]
    part_b = _build_part_b(params.daa_mode, params.half_life)
    return _PART_A + pow_op + part_b + _PART_C


def build_dmint_contract_script(params: DmintDeployParams) -> bytes:
    """Build the full V2 dMint output script: state + OP_STATESEPARATOR + code.

    .. warning::
       V2-only. See :class:`V2UnvalidatedWarning`.
    """
    # Don't double-warn: the two helpers we delegate to already warn.
    # Suppress here so a caller sees exactly one warning per
    # build_dmint_contract_script call (not three).
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", V2UnvalidatedWarning)
        state = build_dmint_state_script(params)
        code = build_dmint_code_script(params)
    _warn_v2_unvalidated()
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

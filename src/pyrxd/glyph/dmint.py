"""dMint V2 — decentralized mineable token support.

Implements the V2 dMint contract script construction, PoW preimage building,
ASERT/linear DAA target computation, and mint-tx scriptSig assembly.

Design reference: glyph-miner/docs/V2_DMINT_DESIGN.md
"""

from __future__ import annotations

import hashlib
import math
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Literal

from pyrxd.security.errors import (
    ContractExhaustedError,
    CovenantError,
    InvalidFundingUtxoError,
    MaxAttemptsError,
    PoolTooSmallError,
    ValidationError,
)

from .types import GlyphRef

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum SHA256d target (64-bit; first 4 bytes implicitly zero).
# Valid: hash[0..4] == 0 AND hash[4..12] < MAX_SHA256D_TARGET.
MAX_SHA256D_TARGET = 0x7FFFFFFFFFFFFFFF

# Maximum V2 256-bit target for blake3 / k12.
MAX_V2_TARGET_256 = (1 << 256) - 1

# OP_STATESEPARATOR
_OP_STATESEPARATOR = b"\xbd"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DmintAlgo(IntEnum):
    SHA256D = 0
    BLAKE3 = 1
    K12 = 2


class DaaMode(IntEnum):
    FIXED = 0
    EPOCH = 1
    ASERT = 2
    LWMA = 3
    SCHEDULE = 4


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

# Part B.1: PoW hash extraction (shared by all modes)
_PART_B1 = bytes.fromhex("bc01147f77587f040000000088817600a269")

# Part B.2: target comparison (V2 preserves target for DAA)
_PART_B2 = bytes.fromhex("51797ca269")

# Part B.4: drop 5 V2 extras (new_target, lastTime, targetTime, daaMode, algoId)
_PART_B4 = bytes.fromhex("7575757575")

# Part C: output validation (identical to V1 — code script continuity + token reward + height checks)
_PART_C = bytes.fromhex(
    "a269577ae500a069567ae600a06901d053797e0c"
    "dec0e9aa76e378e4a269e69d7eaa76e47b9d547a"
    "818b76537a9c537ade789181547ae6939d635279"
    "cd01d853797e016a7e886778de519d547854807e"
    "c0eb557f777e5379ec78885379eac0e9885379cc"
    "519d75686d7551"
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


@dataclass(frozen=True)
class DmintDeployParams:
    """Parameters for deploying a V2 dMint contract."""

    contract_ref: GlyphRef  # singleton ref (will become contractRef in state)
    token_ref: GlyphRef  # normal ref (will become tokenRef in state)
    max_height: int  # maximum number of mints
    reward: int  # photons per mint
    difficulty: int  # initial difficulty → determines initial target
    algo: DmintAlgo = DmintAlgo.SHA256D
    daa_mode: DaaMode = DaaMode.FIXED
    target_time: int = 60  # seconds between mints (for DAA modes)
    half_life: int = 3600  # ASERT half-life in seconds
    height: int = 0  # current mint height (0 at deploy)
    last_time: int = 0  # timestamp of last mint (0 at deploy)

    def __post_init__(self) -> None:
        if self.max_height < 1:
            raise ValidationError("max_height must be >= 1")
        if self.reward < 1:
            raise ValidationError("reward must be >= 1 photon")
        if self.difficulty < 1:
            raise ValidationError("difficulty must be >= 1")
        if self.target_time < 1:
            raise ValidationError("target_time must be >= 1 second")
        if self.half_life < 1:
            raise ValidationError("half_life must be >= 1 second")
        if self.height < 0:
            raise ValidationError("height must be >= 0")
        if self.last_time < 0:
            raise ValidationError("last_time must be >= 0")

    @property
    def initial_target(self) -> int:
        """Compute initial target from difficulty using the SHA256d formula."""
        if self.algo == DmintAlgo.SHA256D:
            return MAX_SHA256D_TARGET // self.difficulty
        return MAX_V2_TARGET_256 // self.difficulty


def build_dmint_state_script(params: DmintDeployParams) -> bytes:
    """Build the 10-item V2 dMint state script (before OP_STATESEPARATOR).

    Layout (§4.2):
        height(4B LE) | d8:contractRef(36B) | d0:tokenRef(36B) |
        maxHeight | reward | algoId | daaMode | targetTime |
        lastTime(4B LE) | target
    """
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
    """Build the V2 dMint code bytecode (Part A + powHashOp + Part B + Part C)."""
    pow_op = _POW_HASH_OP[params.algo]
    part_b = _build_part_b(params.daa_mode, params.half_life)
    return _PART_A + pow_op + part_b + _PART_C


def build_dmint_contract_script(params: DmintDeployParams) -> bytes:
    """Build the full V2 dMint output script: state + OP_STATESEPARATOR + code."""
    return build_dmint_state_script(params) + _OP_STATESEPARATOR + build_dmint_code_script(params)


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


# ---------------------------------------------------------------------------
# PoW preimage (same structure as V1 — §2.5 / Appendix B)
# ---------------------------------------------------------------------------


def build_pow_preimage(
    txid_le: bytes,
    contract_ref_bytes: bytes,
    input_script: bytes,
    output_script: bytes,
) -> bytes:
    """Build the 64-byte PoW preimage.

    preimage[0..32] = SHA256(txid_LE || contractRef)
    preimage[32..64] = SHA256(SHA256d(inputScript) || SHA256d(outputScript))

    :param txid_le:            32-byte txid in little-endian (internal byte order)
    :param contract_ref_bytes: 36-byte contract ref (wire format)
    :param input_script:       miner's input locking script (e.g. P2PKH)
    :param output_script:      miner's output script (e.g. OP_RETURN message)
    """
    if len(txid_le) != 32:
        raise ValidationError("txid_le must be 32 bytes")
    if len(contract_ref_bytes) != 36:
        raise ValidationError("contract_ref_bytes must be 36 bytes")

    def sha256(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def sha256d(data: bytes) -> bytes:
        return sha256(sha256(data))

    half1 = sha256(txid_le + contract_ref_bytes)
    input_csh = sha256d(input_script)
    output_csh = sha256d(output_script)
    half2 = sha256(input_csh + output_csh)
    return half1 + half2


# ---------------------------------------------------------------------------
# Mint scriptSig builder
# ---------------------------------------------------------------------------


def build_mint_scriptsig(
    nonce: bytes,
    preimage: bytes,
    *,
    nonce_width: Literal[4, 8] = 8,
) -> bytes:
    """Build the scriptSig a miner includes in the contract-spend input.

    Format (SHA256d):
        V2 (nonce_width=8): ``<0x08> <nonce:8B> <0x20> <inputHash:32B> <0x20> <outputHash:32B> <0x00>`` → 76 bytes
        V1 (nonce_width=4): ``<0x04> <nonce:4B> <0x20> <inputHash:32B> <0x20> <outputHash:32B> <0x00>`` → 72 bytes

    The V1 layout is documented in docs/dmint-research-mainnet.md §4 (vin[0]
    of the mainnet mint trace at ``146a4d68…f3c``). Same shape as V2,
    differing only in nonce width and corresponding push opcode.

    :param nonce:        nonce_width-bytes nonce (found during mining).
    :param preimage:     64-byte preimage from :func:`build_pow_preimage`.
    :param nonce_width:  4 for V1 contracts, 8 for V2. Keyword-only and
                         ``Literal[4, 8]`` so a stray positional value is a
                         type error rather than a silent V1/V2 confusion.
                         Default 8 preserves pre-V1-support behavior.
    """
    if nonce_width not in (4, 8):
        raise ValidationError(f"nonce_width must be 4 or 8, got {nonce_width}")
    if len(nonce) != nonce_width:
        raise ValidationError(f"nonce must be {nonce_width} bytes, got {len(nonce)}")
    if len(preimage) != 64:
        raise ValidationError(f"preimage must be 64 bytes, got {len(preimage)}")
    # Push opcode = nonce length (works for both 4 and 8 since both are < 0x4C).
    return (
        bytes([nonce_width])
        + nonce  # PUSH nonce_width + nonce
        + b"\x20"
        + preimage[:32]  # PUSH 32 + inputHash half
        + b"\x20"
        + preimage[32:]  # PUSH 32 + outputHash half
        + b"\x00"  # OP_0
    )


# ---------------------------------------------------------------------------
# DAA target computation (off-chain mirror of on-chain formula)
# ---------------------------------------------------------------------------


def compute_next_target_asert(
    current_target: int,
    last_time: int,
    current_time: int,
    target_time: int,
    half_life: int,
) -> int:
    """Compute next ASERT-lite target (mirrors on-chain OP_LSHIFT/OP_RSHIFT logic).

    drift = (current_time - last_time - target_time) // half_life
    drift is clamped to [-4, +4].
    drift > 0 → target <<= drift (easier)
    drift < 0 → target >>= |drift| (harder)
    Minimum target is 1.
    """
    time_delta = current_time - last_time
    excess = time_delta - target_time
    drift = excess // half_life
    drift = max(-4, min(4, drift))

    if drift > 0:
        new_target = current_target << drift
    elif drift < 0:
        new_target = current_target >> (-drift)
    else:
        new_target = current_target

    return max(1, new_target)


def compute_next_target_linear(
    current_target: int,
    last_time: int,
    current_time: int,
    target_time: int,
) -> int:
    """Compute next linear DAA target: new_target = old_target * time_delta / target_time."""
    time_delta = current_time - last_time
    new_target = current_target * time_delta // target_time
    return max(1, new_target)


# ---------------------------------------------------------------------------
# Difficulty ↔ target conversion
# ---------------------------------------------------------------------------


def difficulty_to_target(difficulty: int, algo: DmintAlgo = DmintAlgo.SHA256D) -> int:
    """Convert difficulty to PoW target."""
    if difficulty < 1:
        raise ValidationError("difficulty must be >= 1")
    if algo == DmintAlgo.SHA256D:
        return MAX_SHA256D_TARGET // difficulty
    return MAX_V2_TARGET_256 // difficulty


def target_to_difficulty(target: int, algo: DmintAlgo = DmintAlgo.SHA256D) -> int:
    """Convert PoW target to difficulty (approximate)."""
    if target < 1:
        raise ValidationError("target must be >= 1")
    if algo == DmintAlgo.SHA256D:
        return MAX_SHA256D_TARGET // target
    return MAX_V2_TARGET_256 // target


# ---------------------------------------------------------------------------
# Solution verification (CPU side)
# ---------------------------------------------------------------------------


def verify_sha256d_solution(
    preimage: bytes,
    nonce: bytes,
    target: int,
    *,
    nonce_width: Literal[4, 8] = 8,
) -> bool:
    """Verify a SHA256d PoW solution.

    Valid if: hash[0..4] == 0x00000000 AND int.from_bytes(hash[4..12], 'big') < target

    target is clamped to MAX_SHA256D_TARGET before comparison — a caller-supplied
    target above the maximum would make the check trivially pass for any hash
    that starts with four zero bytes.

    :param nonce_width: 4 for V1 contracts, 8 for V2. Default 8 preserves the
        pre-V1-support behavior. Passed as keyword-only so a stray positional
        ``4`` vs ``8`` is a type error rather than a silent V1/V2 confusion.
    """
    if nonce_width not in (4, 8):
        raise ValidationError(f"nonce_width must be 4 or 8, got {nonce_width}")
    if len(nonce) != nonce_width:
        raise ValidationError(f"nonce must be {nonce_width} bytes, got {len(nonce)}")
    if target <= 0:
        return False
    effective_target = min(target, MAX_SHA256D_TARGET)
    full = hashlib.sha256(hashlib.sha256(preimage + nonce).digest()).digest()
    if full[:4] != b"\x00\x00\x00\x00":
        return False
    value = int.from_bytes(full[4:12], "big")
    return value < effective_target


# ---------------------------------------------------------------------------
# Reference miner — slow but correct CPU-side nonce search.
# ---------------------------------------------------------------------------
#
# Production miners (glyph-miner with WebGPU, custom C/CUDA) live outside
# pyrxd. This loop is "slow but correct": it exists so tests can mine a
# low-difficulty contract end-to-end, and so a determined user can mine a
# real contract overnight without external tooling.
#
# The reference miner calls verify_sha256d_solution per candidate rather than
# inlining its own hash check. That single source of truth prevents the
# mining-check-vs-verifier-check drift that would let pyrxd produce a tx
# whose nonce passes locally but fails on-chain (or vice versa) — the same
# class of bug as the V1 classifier gap (docs/solutions/logic-errors/
# dmint-v1-classifier-gap.md). The performance cost of one extra Python
# call per attempt is negligible compared to the SHA-256d itself.

# Default: ≈minutes single-core at the SHA256d rate of ~1-2M h/s observed on
# modern x86. A naive `mine_solution()` call against a real-mainnet target
# would otherwise wedge for hours; callers who want unbounded mining can
# raise this explicitly.
DEFAULT_MAX_ATTEMPTS = 600_000_000


@dataclass(frozen=True)
class DmintMineResult:
    """The output of a successful :func:`mine_solution` call.

    :param nonce:     The nonce bytes (4B for V1, 8B for V2) that satisfy the target.
    :param attempts:  Number of nonce candidates tried before finding the solution.
    :param elapsed_s: Wall-clock seconds spent searching.
    """

    nonce: bytes
    attempts: int
    elapsed_s: float


def mine_solution(
    preimage: bytes,
    target: int,
    *,
    algo: DmintAlgo = DmintAlgo.SHA256D,
    nonce_width: Literal[4, 8] = 4,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> DmintMineResult:
    """Search for a nonce satisfying the V1/V2 dMint PoW target.

    Sequential nonce sweep starting at 0. The nonce is encoded as a
    little-endian unsigned integer of the requested width (4 bytes for
    V1, 8 bytes for V2 — matches glyph-miner's ``nonceBytesForContracts``).

    Calls :func:`verify_sha256d_solution` per candidate; that's the single
    source of truth for "does this hash satisfy the target." Drift between
    the mining check and the verifier check would let pyrxd produce a
    nonce that passes locally but fails on-chain (or vice versa).

    :param preimage:     64-byte preimage from :func:`build_pow_preimage`.
    :param target:       8-byte 64-bit target (the V1/V2 contract's ``target`` state field).
    :param algo:         Hash algorithm. Only SHA256D is implemented; BLAKE3 and K12
                         raise :class:`NotImplementedError`.
    :param nonce_width:  4 for V1, 8 for V2. Keyword-only and ``Literal[4, 8]``
                         so a stray positional value is a type error rather than
                         a silent V1/V2 confusion.
    :param max_attempts: Upper bound on iterations before raising
                         :class:`MaxAttemptsError`. Defaults to ≈minutes
                         single-core at typical CPython hashlib speeds.
    :raises ValidationError:   ``preimage`` is not 64 bytes, ``target`` is not positive,
                               ``nonce_width`` is not 4 or 8, or ``max_attempts`` is < 1.
    :raises NotImplementedError: ``algo`` is BLAKE3 or K12.
    :raises MaxAttemptsError:  No solution found within ``max_attempts`` iterations.
                               The exception's ``attempts`` and ``elapsed_s``
                               attributes carry telemetry.

    Worked example (small target chosen so the loop completes in ms)::

        >>> from pyrxd.glyph.dmint import (
        ...     mine_solution, verify_sha256d_solution, MAX_SHA256D_TARGET,
        ... )
        >>> preimage = b"\\x00" * 64
        >>> target = MAX_SHA256D_TARGET >> 8  # easy: ~1 in 256 expected
        >>> result = mine_solution(preimage, target, nonce_width=4)
        >>> verify_sha256d_solution(preimage, result.nonce, target, nonce_width=4)
        True
    """
    if len(preimage) != 64:
        raise ValidationError(f"preimage must be 64 bytes, got {len(preimage)}")
    if target <= 0:
        raise ValidationError(f"target must be positive, got {target}")
    if nonce_width not in (4, 8):
        raise ValidationError(f"nonce_width must be 4 or 8, got {nonce_width}")
    if max_attempts < 1:
        raise ValidationError(f"max_attempts must be >= 1, got {max_attempts}")
    if algo != DmintAlgo.SHA256D:
        raise NotImplementedError(f"mine_solution: algo {algo.name} not implemented in M1; only SHA256D ships")

    started = time.monotonic()
    for n in range(max_attempts):
        nonce = n.to_bytes(nonce_width, "little")
        if verify_sha256d_solution(preimage, nonce, target, nonce_width=nonce_width):
            return DmintMineResult(
                nonce=nonce,
                attempts=n + 1,
                elapsed_s=time.monotonic() - started,
            )

    elapsed = time.monotonic() - started
    raise MaxAttemptsError(
        f"no SHA256d solution found in {max_attempts} attempts ({elapsed:.1f}s) for nonce_width={nonce_width}",
        attempts=max_attempts,
        elapsed_s=elapsed,
    )


# ---------------------------------------------------------------------------
# External miner shim
# ---------------------------------------------------------------------------
#
# pyrxd's reference miner is correct but slow (~minutes pure-Python for one
# real-mainnet RBG claim, vs seconds for a GPU miner). The shim lets users
# delegate the nonce search to any external process — glyph-miner being the
# canonical example — without coupling pyrxd to GPU/CUDA/WebGPU dependencies.
#
# Wire protocol:
#   stdin  (one JSON line):  {"preimage_hex": "...", "target_hex": "...",
#                             "nonce_width": 4 | 8}
#   stdout (one JSON line):  {"nonce_hex": "...", "attempts": N, "elapsed_s": F}
#
# Whatever nonce the external process returns is RE-VERIFIED locally before
# being returned to the caller. A buggy or malicious miner that returns a
# wrong nonce raises ValidationError rather than letting pyrxd build a tx
# the network would reject.

EXTERNAL_MINER_TIMEOUT_S = 600.0  # 10 minutes — generous default for slow contracts


def mine_solution_external(
    preimage: bytes,
    target: int,
    *,
    miner_argv: list[str],
    nonce_width: Literal[4, 8] = 4,
    timeout_s: float = EXTERNAL_MINER_TIMEOUT_S,
) -> DmintMineResult:
    """Delegate nonce search to an external miner via JSON-over-subprocess.

    Spawns ``miner_argv`` as a subprocess, writes one JSON line to its stdin,
    reads one JSON line from its stdout, and re-verifies the returned nonce
    locally. The local re-verification is the load-bearing safety check —
    a wrong nonce from the external process raises rather than getting
    silently embedded in a transaction.

    The miner is expected to:

    1. Read one JSON object from stdin: ``{"preimage_hex", "target_hex", "nonce_width"}``
    2. Search for a valid nonce
    3. Write one JSON object to stdout: ``{"nonce_hex", "attempts", "elapsed_s"}``
    4. Exit cleanly

    .. warning::
       **Supply-chain risk: pyrxd does NOT pin or verify the miner binary.**
       ``miner_argv[0]`` is resolved by the OS at exec time, so a malicious
       binary earlier in ``$PATH`` can intercept calls. The local nonce
       re-verification (below) defends against the miner returning a *wrong*
       nonce, but cannot detect side-channel exfiltration: a malicious
       miner sees the preimage (which encodes the contract ref + miner
       binding) and can leak it out-of-band over the network.

       Mitigations the caller should consider:

       - Invoke with an absolute path (``["/usr/local/bin/glyph-miner", ...]``)
         rather than a bare name to bypass ``$PATH`` resolution.
       - Verify the binary's checksum against the upstream release before
         first use.
       - Run pyrxd in an environment where ``$PATH`` is controlled (e.g.
         a dedicated user account, sandbox, or container).

       For testing and trusted environments the bare-name form is fine.

    :param preimage:     64-byte preimage from :func:`build_pow_preimage`.
    :param target:       The PoW target.
    :param miner_argv:   argv passed to :func:`subprocess.run` (e.g.
                         ``["glyph-miner", "--stdin"]``). The first element
                         must be a binary or shell-resolvable name; pyrxd
                         does not pin a specific miner. See the supply-chain
                         warning above.
    :param nonce_width:  4 for V1, 8 for V2.
    :param timeout_s:    Hard timeout. The subprocess is killed and
                         :class:`MaxAttemptsError` raised on expiry.
    :raises ValidationError:   The miner returned a malformed JSON response,
                               a nonce of wrong width, or a nonce that fails
                               local verification.
    :raises MaxAttemptsError:  The miner exceeded ``timeout_s``.
    :raises FileNotFoundError: ``miner_argv[0]`` is not on PATH.
    """
    import json
    import subprocess  # nosec B404 — used to invoke a caller-supplied external miner; see docstring supply-chain warning

    if len(preimage) != 64:
        raise ValidationError(f"preimage must be 64 bytes, got {len(preimage)}")
    if target <= 0:
        raise ValidationError(f"target must be positive, got {target}")
    if nonce_width not in (4, 8):
        raise ValidationError(f"nonce_width must be 4 or 8, got {nonce_width}")
    if not miner_argv:
        raise ValidationError("miner_argv must not be empty")

    request = json.dumps(
        {
            "preimage_hex": preimage.hex(),
            "target_hex": f"{target:016x}",
            "nonce_width": nonce_width,
        }
    )

    started = time.monotonic()
    try:
        # miner_argv is caller-controlled by design (this is a plug-in
        # protocol for external miners); the contract is "you tell pyrxd
        # which binary to invoke." Local re-verification of the returned
        # nonce below is the load-bearing safety check, not subprocess
        # argv sanitization.
        #
        # stderr is discarded rather than captured: a misbehaving miner
        # writing gigabytes to stderr would otherwise OOM the parent before
        # the timeout fires. Loss of debug info is an acceptable trade for
        # the bounded-memory guarantee. The subprocess's stdin/stdout
        # protocol is the only contract; stderr is implementation chatter.
        completed = subprocess.run(  # noqa: S603 # nosec B603 — see comment + docstring supply-chain warning
            miner_argv,
            input=request.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - started
        raise MaxAttemptsError(
            f"external miner {miner_argv[0]!r} did not return a solution within {timeout_s}s",
            attempts=0,
            elapsed_s=elapsed,
        ) from exc

    if completed.returncode != 0:
        raise ValidationError(f"external miner {miner_argv[0]!r} exited with code {completed.returncode}")

    # Decode stdout. A miner returning malformed UTF-8 is a malformed
    # response, not an exception that should escape.
    try:
        stdout = (completed.stdout or b"").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"external miner {miner_argv[0]!r} returned non-UTF-8 stdout") from exc
    if len(stdout) > 4096:
        raise ValidationError(f"external miner produced {len(stdout)} bytes of stdout; expected one short JSON line")
    try:
        response = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"external miner returned non-JSON stdout: {stdout!r}") from exc

    if not isinstance(response, dict):
        raise ValidationError(f"external miner response must be a JSON object, got {type(response).__name__}")
    nonce_hex = response.get("nonce_hex")
    if not isinstance(nonce_hex, str):
        raise ValidationError(f"external miner response missing or non-string nonce_hex: {response!r}")
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise ValidationError(f"external miner returned non-hex nonce: {nonce_hex!r}") from exc
    if len(nonce) != nonce_width:
        raise ValidationError(
            f"external miner returned nonce of wrong width: got {len(nonce)} bytes, expected {nonce_width}"
        )

    # Local re-verification: defense against a buggy or malicious miner.
    if not verify_sha256d_solution(preimage, nonce, target, nonce_width=nonce_width):
        raise ValidationError(
            f"external miner returned nonce {nonce.hex()} that fails local SHA256d verification "
            f"against target {target:#x} — refusing to use it"
        )

    elapsed = time.monotonic() - started
    # Trust the miner's self-reported metrics if present, else fall back.
    # Defense-in-depth against malicious/buggy miner responses:
    # - attempts capped at 2**40 to prevent log poisoning / aggregator overflow
    # - elapsed_s rejected if NaN, inf, or negative (json.loads accepts
    #   "NaN" / "Infinity" via parse_constant; both pass isinstance(_, float))
    raw_attempts = response.get("attempts", 0)
    if not isinstance(raw_attempts, int) or raw_attempts < 0 or raw_attempts > (1 << 40):
        attempts = 0
    else:
        attempts = raw_attempts
    raw_elapsed = response.get("elapsed_s", elapsed)
    if (
        not isinstance(raw_elapsed, (int, float))
        or isinstance(raw_elapsed, bool)  # bools are int subclass — reject explicitly
        or not math.isfinite(raw_elapsed)
        or raw_elapsed < 0
    ):
        miner_elapsed = elapsed
    else:
        miner_elapsed = raw_elapsed

    return DmintMineResult(
        nonce=nonce,
        attempts=attempts,
        elapsed_s=float(miner_elapsed),
    )


# ---------------------------------------------------------------------------
# V2 state script parser (for reading on-chain UTXO state)
# ---------------------------------------------------------------------------


def _parse_script_int(data: bytes, pos: int) -> tuple[int, int]:
    """Parse a Bitcoin script-encoded integer at ``pos``, returning (value, new_pos).

    Handles all push encodings produced by ``_push_minimal`` and
    ``_push_4bytes_le``:

    * ``OP_0`` (0x00)             → 0
    * ``OP_1NEGATE`` (0x4f)       → -1
    * ``OP_1``–``OP_16`` (0x51–0x60) → 1–16
    * ``<length> <data>``         → little-endian signed integer
    * ``0x4c <length> <data>``    → PUSHDATA1
    """
    if pos >= len(data):
        raise ValidationError(f"DmintState.from_script: unexpected end of script at position {pos}")
    op = data[pos]
    # OP_0
    if op == 0x00:
        return 0, pos + 1
    # OP_1NEGATE
    if op == 0x4F:
        return -1, pos + 1
    # OP_1 .. OP_16
    if 0x51 <= op <= 0x60:
        return op - 0x50, pos + 1
    # PUSHDATA1
    if op == 0x4C:
        if pos + 1 >= len(data):
            raise ValidationError("DmintState.from_script: PUSHDATA1 length byte missing")
        n = data[pos + 1]
        start = pos + 2
        raw = data[start : start + n]
        if len(raw) != n:
            raise ValidationError(f"DmintState.from_script: PUSHDATA1 underrun: need {n}, got {len(raw)}")
        return _decode_script_le_int(raw), start + n
    # Direct push (1..75 bytes)
    if 1 <= op <= 75:
        n = op
        start = pos + 1
        raw = data[start : start + n]
        if len(raw) != n:
            raise ValidationError(f"DmintState.from_script: direct push underrun: need {n}, got {len(raw)}")
        return _decode_script_le_int(raw), start + n
    raise ValidationError(f"DmintState.from_script: unrecognised opcode 0x{op:02x} at pos {pos}")


def _decode_script_le_int(raw: bytes) -> int:
    """Decode a Bitcoin script integer from little-endian bytes (with sign bit)."""
    if not raw:
        return 0
    result = int.from_bytes(raw, "little")
    # High bit of last byte is the sign bit.
    if raw[-1] & 0x80:
        # Clear sign bit and negate.
        result ^= 0x80 << (8 * (len(raw) - 1))
        return -result
    return result


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
# earlier in the module (around the V1 builders) so the V1 builder helpers
# can reference the inverse mapping. Single source of truth: byte→enum.


def _match_v1_epilogue(script: bytes, start: int) -> DmintAlgo | None:
    """Return the algo enum if a V1 epilogue starts at *start*, else ``None``.

    Returning ``None`` means "not a V1 epilogue at this position." Callers
    do not need to distinguish *which* check failed (length / prefix / algo
    byte / suffix) — only "is this a V1 contract or not."
    """
    if start + _V1_EPILOGUE_LEN > len(script):
        return None
    if script[start : start + len(_V1_EPILOGUE_PREFIX)] != _V1_EPILOGUE_PREFIX:
        return None
    algo = _V1_ALGO_BYTE_TO_ENUM.get(script[start + _V1_EPILOGUE_ALGO_OFFSET])
    if algo is None:
        return None
    suffix_start = start + _V1_EPILOGUE_ALGO_OFFSET + 1
    if script[suffix_start : suffix_start + len(_V1_EPILOGUE_SUFFIX)] != _V1_EPILOGUE_SUFFIX:
        return None
    return algo


@dataclass(frozen=True)
class DmintState:
    """Parsed dMint contract state (from on-chain UTXO script).

    Supports both V1 (the current Radiant mainnet format) and V2 (Photonic
    Wallet's HEAD spec, not yet seen on mainnet). V1 has 6 state items;
    V2 has 10. ``is_v1`` is True iff this state was parsed from V1 layout
    — in which case ``target_time`` and ``last_time`` are not meaningful
    on-chain values and are set to 0; ``daa_mode`` is always ``FIXED`` for
    V1 (the V1 contract template has no DAA bytecode).
    """

    height: int
    contract_ref: GlyphRef
    token_ref: GlyphRef
    max_height: int
    reward: int
    algo: DmintAlgo
    daa_mode: DaaMode
    target_time: int
    last_time: int
    target: int
    is_v1: bool = False

    @property
    def is_exhausted(self) -> bool:
        return self.height >= self.max_height

    @classmethod
    def from_script(cls, script_bytes: bytes) -> DmintState:
        """Parse a dMint contract UTXO script into a ``DmintState``.

        Tries V2 layout first (10 state items), falls back to V1 (6 items
        + fingerprinted code epilogue). Raises ``ValidationError`` if the
        script matches neither.

        :param script_bytes: Raw script bytes from a dMint contract UTXO output.
        :raises ValidationError: Script is malformed or matches neither V1
            nor V2 layout.
        """
        # Try V2 first. If V2 raises, try V1; if V1 also raises, surface a
        # combined error that names both attempts so callers don't have to
        # guess which version they had.
        try:
            return cls._from_v2_script(script_bytes)
        except ValidationError as v2_exc:
            try:
                return cls._from_v1_script(script_bytes)
            except ValidationError as v1_exc:
                raise ValidationError(
                    f"DmintState.from_script: not a dMint contract (V2: {v2_exc}; V1: {v1_exc})"
                ) from None

    @classmethod
    def _from_v2_script(cls, script_bytes: bytes) -> DmintState:
        """Parse a V2 dMint contract (10 state items + ``bd``).

        Walks the 10 state pushes in declared order, then verifies that the
        next byte is ``OP_STATESEPARATOR`` (0xbd). Closes ultrareview
        re-review N7: the previous implementation searched for the FIRST
        0xbd byte anywhere in the script and sliced the state at that
        position. Because 0xbd is a perfectly valid byte value inside any
        push payload (a 36-byte wire ref, a 4-byte height, a script-int
        target, etc.), an unlucky byte pattern would truncate the state
        at the wrong offset and either fail with a misleading error or —
        if the truncation happened to land on a recognizable opcode — return
        a DmintState built from garbage parsed past the wrong cut point.

        Layout (matches ``build_dmint_state_script``):
          [0] height      — ``_push_4bytes_le`` (opcode 0x04 + 4-byte LE uint32)
          [1] contractRef — ``0xd8`` + 36-byte wire ref
          [2] tokenRef    — ``0xd0`` + 36-byte wire ref
          [3] maxHeight   — ``_push_minimal``
          [4] reward      — ``_push_minimal``
          [5] algoId      — ``_push_minimal``
          [6] daaMode     — ``_push_minimal``
          [7] targetTime  — ``_push_minimal``
          [8] lastTime    — ``_push_4bytes_le`` (opcode 0x04 + 4-byte LE uint32)
          [9] target      — ``_push_minimal`` (may be large for 256-bit algos)
          —— OP_STATESEPARATOR (0xbd) ——
          (code section follows; not parsed here)
        """
        # Walk the full script — do NOT pre-slice on the first 0xbd. The
        # parser consumes exactly the bytes belonging to each push, so by
        # the time we reach position `pos` after item 9, that position is
        # by definition the boundary between state and code regardless of
        # what bytes appeared inside the pushes.
        pos = 0

        # --- Item 0: height (always _push_4bytes_le → opcode 0x04 + 4 bytes LE)
        if pos >= len(script_bytes) or script_bytes[pos] != 0x04:
            if pos >= len(script_bytes):
                raise ValidationError("DmintState.from_script: script too short for height")
            raise ValidationError(
                f"DmintState.from_script: expected 0x04 (push-4) at pos {pos} for height, got 0x{script_bytes[pos]:02x}"
            )
        if pos + 5 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside height")
        height = struct.unpack("<I", script_bytes[pos + 1 : pos + 5])[0]
        pos += 5

        # --- Item 1: contractRef (0xd8 + 36 bytes wire ref)
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD8:
            raise ValidationError(f"DmintState.from_script: expected 0xd8 (OP_PUSHINPUTREFSINGLETON) at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside contractRef")
        contract_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Item 2: tokenRef (0xd0 + 36 bytes wire ref)
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD0:
            raise ValidationError(f"DmintState.from_script: expected 0xd0 (OP_PUSHINPUTREF) at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside tokenRef")
        token_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Items 3–7: variable-length script integers
        max_height, pos = _parse_script_int(script_bytes, pos)
        reward, pos = _parse_script_int(script_bytes, pos)
        algo_id, pos = _parse_script_int(script_bytes, pos)
        daa_id, pos = _parse_script_int(script_bytes, pos)
        target_time, pos = _parse_script_int(script_bytes, pos)

        # --- Item 8: lastTime (always _push_4bytes_le → opcode 0x04 + 4 bytes LE)
        if pos >= len(script_bytes) or script_bytes[pos] != 0x04:
            raise ValidationError(f"DmintState.from_script: expected 0x04 (push-4) at pos {pos} for lastTime")
        if pos + 5 > len(script_bytes):
            raise ValidationError("DmintState.from_script: script truncated inside lastTime")
        last_time = struct.unpack("<I", script_bytes[pos + 1 : pos + 5])[0]
        pos += 5

        # --- Item 9: target (variable length — large for 256-bit algos)
        target, pos = _parse_script_int(script_bytes, pos)

        # --- After 10 state items, the next byte MUST be OP_STATESEPARATOR.
        # Closes N7: the previous implementation took the first 0xbd
        # byte anywhere in the script as the separator, which a 0xbd
        # inside push-data would defeat. By walking the well-defined
        # state layout first we land on the actual separator position
        # by construction.
        if pos >= len(script_bytes):
            raise ValidationError("DmintState.from_script: script ended before OP_STATESEPARATOR")
        if script_bytes[pos] != _OP_STATESEPARATOR[0]:
            raise ValidationError(
                f"DmintState.from_script: expected OP_STATESEPARATOR (0xbd) "
                f"at pos {pos} after 10-item state, got 0x{script_bytes[pos]:02x}"
            )

        try:
            algo = DmintAlgo(algo_id)
        except ValueError:
            raise ValidationError(f"DmintState.from_script: unknown algo id {algo_id}")
        try:
            daa_mode = DaaMode(daa_id)
        except ValueError:
            raise ValidationError(f"DmintState.from_script: unknown daa_mode id {daa_id}")

        return cls(
            height=height,
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=max_height,
            reward=reward,
            algo=algo,
            daa_mode=daa_mode,
            target_time=target_time,
            last_time=last_time,
            target=target,
            is_v1=False,
        )

    @classmethod
    def _from_v1_script(cls, script_bytes: bytes) -> DmintState:
        """Parse a V1 dMint contract (the current mainnet format).

        V1 has 6 state items plus a 145-byte fixed code epilogue (varying
        only in the algo selector byte). Layout:

          [0] height       — ``_push_4bytes_le`` (opcode 0x04 + 4 bytes LE)
          [1] contractRef  — ``0xd8`` + 36-byte wire ref
          [2] tokenRef     — ``0xd0`` + 36-byte wire ref
          [3] maxHeight    — ``_push_minimal``
          [4] reward       — ``_push_minimal``
          [5] target       — full 8-byte push (``0x08`` + 8 LE bytes)
          —— OP_STATESEPARATOR (0xbd) + 144-byte fixed code epilogue ——

        ``daa_mode`` is always ``FIXED`` for V1 (V1 has no DAA bytecode).
        ``target_time`` and ``last_time`` are V2-only and set to 0; the
        ``is_v1`` flag is True so callers can ignore those fields.
        """
        pos = 0

        # --- Item 0: height
        if pos >= len(script_bytes) or script_bytes[pos] != 0x04:
            raise ValidationError(
                f"DmintState._from_v1_script: expected 0x04 (push-4) at pos {pos}, "
                f"got 0x{(script_bytes[pos] if pos < len(script_bytes) else 0):02x}"
            )
        if pos + 5 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside height")
        height = struct.unpack("<I", script_bytes[pos + 1 : pos + 5])[0]
        pos += 5

        # --- Item 1: contractRef
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD8:
            raise ValidationError(f"DmintState._from_v1_script: expected 0xd8 at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside contractRef")
        contract_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Item 2: tokenRef
        if pos >= len(script_bytes) or script_bytes[pos] != 0xD0:
            raise ValidationError(f"DmintState._from_v1_script: expected 0xd0 at pos {pos}")
        pos += 1
        if pos + 36 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside tokenRef")
        token_ref = GlyphRef.from_bytes(script_bytes[pos : pos + 36])
        pos += 36

        # --- Items 3-4: maxHeight and reward (variable-length pushes)
        max_height, pos = _parse_script_int(script_bytes, pos)
        reward, pos = _parse_script_int(script_bytes, pos)

        # --- Item 5: target (V1 always uses an 8-byte push; never the
        #     algoId/daaMode pushes V2 has).
        if pos >= len(script_bytes) or script_bytes[pos] != 0x08:
            raise ValidationError(f"DmintState._from_v1_script: expected 0x08 (push-8) for target at pos {pos}")
        if pos + 9 > len(script_bytes):
            raise ValidationError("DmintState._from_v1_script: script truncated inside target")
        target = int.from_bytes(script_bytes[pos + 1 : pos + 9], "little")
        pos += 9

        # --- After 6 state items, fingerprint the V1 code epilogue. The
        # epilogue is byte-identical across V1 deployments except for one
        # algo selector byte; a successful fingerprint match is the
        # discriminator that proves "this is a V1 contract" (rather than
        # a script that happened to start with similar pushes).
        algo = _match_v1_epilogue(script_bytes, pos)
        if algo is None:
            raise ValidationError(f"DmintState._from_v1_script: code epilogue at pos {pos} does not match V1 template")

        return cls(
            height=height,
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=max_height,
            reward=reward,
            algo=algo,
            daa_mode=DaaMode.FIXED,  # V1 contracts have no DAA bytecode
            target_time=0,  # not encoded in V1
            last_time=0,  # not encoded in V1
            target=target,
            is_v1=True,
        )


# ---------------------------------------------------------------------------
# CBOR payload object — embedded in GlyphMetadata as "dmint" key (V2 spec §8)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DmintCborPayload:
    """The ``dmint`` object embedded in Glyph V2 token metadata CBOR.

    Indexers read this to discover dMint contracts and display mining
    parameters in wallets/explorers without parsing the contract script.

    Field names mirror Photonic Wallet ``DmintPayload`` type in types.ts.
    """

    algo: DmintAlgo  # 0=sha256d, 1=blake3, 2=k12
    num_contracts: int  # number of parallel mining contract UTXOs
    max_height: int  # total mints allowed
    reward: int  # photons per mint
    premine: int  # photons pre-minted to deployer (0 if none)
    diff: int  # initial difficulty (1 = easiest)
    daa_mode: DaaMode = DaaMode.FIXED
    target_block_time: int = 60  # seconds between mints (ignored for FIXED)
    half_life: int = 0  # ASERT half-life seconds (0 = N/A)
    window_size: int = 0  # LWMA window size (0 = N/A)

    def __post_init__(self) -> None:
        if self.num_contracts < 1:
            raise ValidationError("num_contracts must be >= 1")
        if self.max_height < 1:
            raise ValidationError("max_height must be >= 1")
        if self.reward < 0:
            raise ValidationError("reward must be >= 0")
        if self.premine < 0:
            raise ValidationError("premine must be >= 0")
        if self.diff < 1:
            raise ValidationError("diff must be >= 1")

    def to_cbor_dict(self) -> dict:
        """Encode to the dict that becomes the ``dmint`` CBOR value."""
        d: dict = {
            "algo": int(self.algo),
            "numContracts": self.num_contracts,
            "maxHeight": self.max_height,
            "reward": self.reward,
            "premine": self.premine,
            "diff": self.diff,
        }
        if self.daa_mode != DaaMode.FIXED:
            daa: dict = {
                "mode": int(self.daa_mode),
                "targetBlockTime": self.target_block_time,
            }
            if self.half_life:
                daa["halfLife"] = self.half_life
            if self.window_size:
                daa["windowSize"] = self.window_size
            d["daa"] = daa
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> DmintCborPayload:
        """Parse the ``dmint`` CBOR value from an on-chain payload."""
        try:
            algo = DmintAlgo(int(d["algo"]))
        except (KeyError, ValueError) as e:
            raise ValidationError("dmint.algo missing or invalid") from e
        try:
            daa_mode = DaaMode.FIXED
            target_block_time = 60
            half_life = 0
            window_size = 0
            if "daa" in d:
                daa = d["daa"]
                daa_mode = DaaMode(int(daa.get("mode", 0)))
                target_block_time = int(daa.get("targetBlockTime", 60))
                half_life = int(daa.get("halfLife", 0))
                window_size = int(daa.get("windowSize", 0))
            return cls(
                algo=algo,
                num_contracts=int(d.get("numContracts", 1)),
                max_height=int(d["maxHeight"]),
                reward=int(d["reward"]),
                premine=int(d.get("premine", 0)),
                diff=int(d["diff"]),
                daa_mode=daa_mode,
                target_block_time=target_block_time,
                half_life=half_life,
                window_size=window_size,
            )
        except KeyError as e:
            raise ValidationError(f"dmint CBOR missing required field: {e}") from e


# ---------------------------------------------------------------------------
# Contract UTXO descriptor (for build_dmint_mint_tx)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DmintContractUtxo:
    """Describes a live dMint contract UTXO to be spent in a mint transaction.

    :param txid:         txid of the UTXO (hex, not reversed)
    :param vout:         output index
    :param value:        photon value locked in the UTXO. For V1 contracts
                         this is the singleton carrier (1 photon on the live
                         RBG-class deploys). For V2 it is the running reward
                         pool that decrements per mint.
    :param script:       full output script bytes (state + OP_STATESEPARATOR + code)
    :param state:        parsed :class:`DmintState` — caller can obtain via
                         ``DmintState.from_script(script)``
    """

    txid: str
    vout: int
    value: int
    script: bytes
    state: DmintState


@dataclass(frozen=True)
class DmintMinerFundingUtxo:
    """A plain RXD UTXO supplied by the miner to fund a V1 mint.

    The V1 covenant takes its FT output value (``reward`` photons) and the
    miner's tx fee from a separate plain-RXD input — the contract output is
    a singleton and never funds the mint. This dataclass describes that
    funding input.

    The locking script must be a plain script with NO Glyph/FT/dMint
    ref pushes (``OP_PUSHINPUTREF*``, opcodes 0xd0–0xd8). Spending a
    token-bearing UTXO as fee silently destroys the token; the V1 mint
    builder validates this and raises :class:`InvalidFundingUtxoError`
    if the funding script carries any ref envelope.

    :param txid:    txid of the UTXO (hex, not reversed)
    :param vout:    output index
    :param value:   photons locked in the UTXO
    :param script:  full locking script bytes (typically 25-byte P2PKH)
    """

    txid: str
    vout: int
    value: int
    script: bytes


# Opcodes in the OP_PUSHINPUTREF family — any of these in a candidate
# funding script (as an *opcode*, not as push-data payload) is grounds
# for refusing to spend it as fee.
# 0xd0 OP_PUSHINPUTREF, 0xd1 OP_REQUIREINPUTREF, 0xd2 OP_DISALLOWPUSHINPUTREF,
# 0xd3 OP_DISALLOWPUSHINPUTREFSIBLING, 0xd4–0xd7 reserved/related,
# 0xd8 OP_PUSHINPUTREFSINGLETON.
_FUNDING_REF_OPCODE_RANGE = range(0xD0, 0xD9)


def is_token_bearing_script(script: bytes) -> bool:
    """Return True if ``script`` uses any OP_PUSHINPUTREF-family opcode.

    Walks the script as an opcode stream: push opcodes (0x01..0x4e) consume
    their payload, and only the *opcode position* bytes are checked against
    the deny-list. A naive bare-byte scan would falsely flag any P2PKH
    whose 20-byte hash contains a 0xd0–0xd8 byte (~51% of random
    addresses), denying about half of honest miners.

    Push opcode encoding (Bitcoin/Radiant script):

    - ``0x01..0x4b``: push the next N bytes (N == opcode value)
    - ``0x4c`` PUSHDATA1: next 1 byte is length, then push that many
    - ``0x4d`` PUSHDATA2: next 2 bytes (LE) are length, then push
    - ``0x4e`` PUSHDATA4: next 4 bytes (LE) are length, then push
    - everything else: opcode with no payload (advance by 1)

    Truncated push fields are treated as token-bearing — a malformed
    script of ambiguous length should not be accepted as funding.
    """
    pos = 0
    n = len(script)
    while pos < n:
        op = script[pos]
        if op in _FUNDING_REF_OPCODE_RANGE:
            return True
        # Direct push: 1..0x4b bytes follow.
        if 0x01 <= op <= 0x4B:
            new_pos = 1 + pos + op
            if new_pos > n:
                return True  # truncated push: refuse the funding UTXO
            pos = new_pos
            continue
        if op == 0x4C:  # PUSHDATA1
            if pos + 1 >= n:
                return True
            length = script[pos + 1]
            new_pos = pos + 2 + length
            if new_pos > n:
                return True
            pos = new_pos
            continue
        if op == 0x4D:  # PUSHDATA2
            if pos + 2 >= n:
                return True
            length = int.from_bytes(script[pos + 1 : pos + 3], "little")
            new_pos = pos + 3 + length
            if new_pos > n:
                return True
            pos = new_pos
            continue
        if op == 0x4E:  # PUSHDATA4
            if pos + 4 >= n:
                return True
            length = int.from_bytes(script[pos + 1 : pos + 5], "little")
            new_pos = pos + 5 + length
            if new_pos > n:
                return True
            pos = new_pos
            continue
        pos += 1
    return False


# ---------------------------------------------------------------------------
# dMint mint transaction builder
# ---------------------------------------------------------------------------


@dataclass
class DmintMintResult:
    """Output of :func:`build_dmint_mint_tx`.

    :param tx:                 Unsigned transaction (caller must sign).
    :param updated_state:      New :class:`DmintState` written into the
                               contract output (height incremented, target
                               updated if DAA is active).
    :param contract_script:    New contract output script (state + separator + code).
    :param reward_script:      P2PKH locking script of the miner reward output.
    :param fee:                Transaction fee in photons.

    .. note::
       The transaction returned here is **unsigned** — it uses raw script bytes
       for the contract input's unlocking script (nonce + preimage halves) built
       by :func:`build_mint_scriptsig`.  The contract script is a covenant, not
       a P2PKH, so standard :class:`Transaction.sign()` is not appropriate.
       The caller must either set the unlocking script directly or use a custom
       signing path.  See docstring of :func:`build_dmint_mint_tx` for details.
    """

    tx: Any
    updated_state: DmintState
    contract_script: bytes
    reward_script: bytes
    fee: int


def build_dmint_mint_tx(
    contract_utxo: DmintContractUtxo,
    nonce: bytes,
    miner_pkh: bytes,
    current_time: int,
    fee_rate: int = 10_000,
    *,
    funding_utxo: DmintMinerFundingUtxo | None = None,
    op_return_msg: bytes | None = None,
) -> DmintMintResult:
    """Build an unsigned dMint mint transaction.

    Constructs the transaction that spends the live dMint contract UTXO,
    recreates the contract with the updated state (incremented height + DAA
    target adjustment), and pays the miner reward to ``miner_pkh``.

    Transaction structure
    ---------------------
    **Inputs**
      * Input 0: contract UTXO — unlocked by ``build_mint_scriptsig(nonce, preimage)``
        where ``preimage = build_pow_preimage(txid_le, contract_ref, miner_input_script, miner_output_script)``

    **Outputs**
      * Output 0: recreated contract UTXO (updated DmintState + same code section)
      * Output 1: miner reward P2PKH output (value = state.reward)

    .. note::
       The preimage is a function of the *transaction itself* (txid of the input
       being spent and the content of both the input and output locking scripts),
       which creates a circular dependency that cannot be resolved without a real
       node.  The nonce + preimage in the returned tx's unlocking script are
       therefore **placeholder bytes** derived from the inputs as known at build
       time.  A production miner loop must:

       1. Build the unsigned tx shell via this function.
       2. Compute the real ``preimage`` using ``build_pow_preimage`` once the
          tx's txid and script hashes are stable (they are stable once outputs
          are finalised — the txid doesn't depend on the unlocking script in
          Radiant/Bitcoin sighash).
       3. Mine for a valid ``nonce`` via ``verify_sha256d_solution`` (or the
          relevant algo).
       4. Replace input 0's unlocking script with ``build_mint_scriptsig(nonce, preimage)``.
       5. Broadcast.

       Steps 2–5 are deliberately out of scope here — they require a live node
       connection or deterministic txid from a fully-built tx.

    :param contract_utxo:  The live dMint contract UTXO to spend.
    :param nonce:          8-byte PoW nonce (use ``b'\\x00' * 8`` as placeholder
                           when building the tx shell; replace after mining).
    :param miner_pkh:      20-byte P2PKH hash of the miner's reward address.
    :param current_time:   Unix timestamp of the block (used for DAA target
                           computation).  Caller is responsible for supplying a
                           value consistent with the transaction's locktime.
    :param fee_rate:       Photons per byte for fee calculation (default 10_000,
                           the Radiant post-V2 relay minimum).
    :raises ValidationError: ``contract_utxo.state.is_exhausted`` is True;
        ``nonce`` is not 8 bytes; ``miner_pkh`` is not 20 bytes.
    :returns: :class:`DmintMintResult` with the unsigned tx and updated state.
    """

    # Local imports to keep module-load-time light (mirrors builder.py pattern).
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    if fee_rate < 1:
        raise ValidationError(f"fee_rate must be >= 1, got {fee_rate}")

    state = contract_utxo.state

    # V1 dispatch: V1 contracts have a different state layout, scriptSig
    # nonce width (4B vs 8B), and no DAA. Branch early-return to keep the V1
    # path completely separate from V2's DAA-target-update flow rather than
    # threading conditionals through the V2 logic below.
    if state.is_v1:
        if funding_utxo is None:
            raise ValidationError(
                "V1 mint requires a funding_utxo: V1 contracts are singletons "
                "(typically 1 photon) and the FT reward + tx fee come from a "
                "separate plain-RXD input. Pass funding_utxo=DmintMinerFundingUtxo(...) "
                "as a keyword argument."
            )
        if current_time != 0:
            raise ValidationError(
                "current_time must be 0 for V1 mints — V1 has no DAA and the "
                "value would be silently ignored. Pass current_time=0 to make "
                "the no-op explicit."
            )
        return _build_dmint_v1_mint_tx(
            contract_utxo=contract_utxo,
            nonce=nonce,
            miner_pkh=miner_pkh,
            fee_rate=fee_rate,
            funding_utxo=funding_utxo,
            op_return_msg=op_return_msg,
        )

    if op_return_msg is not None:
        raise ValidationError(
            "op_return_msg is V1-only — V2 mints do not include the Photonic 'msg' OP_RETURN convention by default."
        )
    if state.is_exhausted:
        raise ContractExhaustedError(
            f"dMint contract is exhausted: height={state.height} >= max_height={state.max_height}"
        )
    if len(nonce) != 8:
        raise ValidationError(f"nonce must be 8 bytes, got {len(nonce)}")
    if len(miner_pkh) != 20:
        raise ValidationError(f"miner_pkh must be 20 bytes, got {len(miner_pkh)}")

    # --- Compute updated state ---
    new_height = state.height + 1

    # DAA target update (off-chain mirror of on-chain script logic).
    if state.daa_mode == DaaMode.ASERT:
        new_target = compute_next_target_asert(
            current_target=state.target,
            last_time=state.last_time,
            current_time=current_time,
            target_time=state.target_time,
            half_life=3600,  # embedded in the on-chain ASERT DAA bytecode
        )
    elif state.daa_mode == DaaMode.LWMA:
        new_target = compute_next_target_linear(
            current_target=state.target,
            last_time=state.last_time,
            current_time=current_time,
            target_time=state.target_time,
        )
    else:
        new_target = state.target  # FIXED — no DAA

    updated_state = DmintState(
        height=new_height,
        contract_ref=state.contract_ref,
        token_ref=state.token_ref,
        max_height=state.max_height,
        reward=state.reward,
        algo=state.algo,
        daa_mode=state.daa_mode,
        target_time=state.target_time,
        last_time=current_time,
        target=new_target,
    )

    # --- Build the updated contract script ---
    # Reconstruct using DmintDeployParams as a vehicle for the builder (we only
    # need the state + code sections; height/last_time will be updated).
    updated_deploy_params = DmintDeployParams(
        contract_ref=state.contract_ref,
        token_ref=state.token_ref,
        max_height=state.max_height,
        reward=state.reward,
        difficulty=1,  # dummy — we supply target directly below
        algo=state.algo,
        daa_mode=state.daa_mode,
        target_time=state.target_time,
        height=new_height,
        last_time=current_time,
    )
    # Build code section from updated params (the code never changes across mints —
    # only the state prefix changes).  We override the target in the state script
    # by constructing it manually from the updated_state.
    code_script = build_dmint_code_script(updated_deploy_params)

    # Build updated state script directly from updated_state fields.
    new_state_script = (
        _push_4bytes_le(updated_state.height)
        + b"\xd8"
        + updated_state.contract_ref.to_bytes()
        + b"\xd0"
        + updated_state.token_ref.to_bytes()
        + _push_minimal(updated_state.max_height)
        + _push_minimal(updated_state.reward)
        + _push_minimal(int(updated_state.algo))
        + _push_minimal(int(updated_state.daa_mode))
        + _push_minimal(updated_state.target_time)
        + _push_4bytes_le(updated_state.last_time)
        + _push_minimal(updated_state.target)
    )
    contract_script = new_state_script + _OP_STATESEPARATOR + code_script

    # --- Build reward output script (P2PKH) ---
    reward_script = b"\x76\xa9\x14" + miner_pkh + b"\x88\xac"

    # --- Placeholder scriptSig (nonce + sentinel preimage 0xff*64) ---
    # The real preimage requires txid + script hashes which are only
    # available once outputs are finalised (see docstring). The
    # placeholder uses 0xff bytes (rather than zeros) as a visibly-invalid
    # sentinel: a miner loop that forgets to replace it produces a tx
    # whose covenant rejects fast on the network rather than silently
    # passing structural checks. Same sentinel used in the V1 path
    # (see _build_dmint_v1_mint_tx).
    placeholder_preimage = b"\xff" * 64
    placeholder_scriptsig = build_mint_scriptsig(nonce, placeholder_preimage)

    # --- Estimate tx size for fee ---
    # Approximate: 4 (ver) + 1 (in count) + 41 (outpoint+seq) + 1 (len) + len(scriptsig)
    #              + 1 (out count) + 2 * (8+1+len(script)) + 4 (locktime)
    _contract_script_len = len(contract_script)
    _reward_script_len = len(reward_script)
    _scriptsig_len = len(placeholder_scriptsig)
    estimated_size = (
        4  # version
        + 1  # vin count
        + 36  # outpoint (txid + vout)
        + 4  # sequence
        + _varint_size(_scriptsig_len)
        + _scriptsig_len  # scriptsig
        + 1  # vout count
        + 8
        + _varint_size(_contract_script_len)
        + _contract_script_len  # contract out
        + 8
        + _varint_size(_reward_script_len)
        + _reward_script_len  # reward out
        + 4  # locktime
    )
    fee = estimated_size * fee_rate

    # Contract output value = pool balance minus reward minus fee.
    contract_out_value = contract_utxo.value - state.reward - fee

    if contract_out_value < 546:
        raise PoolTooSmallError(
            f"Contract UTXO value ({contract_utxo.value}) too small to cover "
            f"reward ({state.reward}) + fee ({fee}): contract output would be "
            f"{contract_out_value} photons, below 546 dust limit."
        )

    # --- Assemble transaction (unsigned) ---
    # We use Script wrappers for the transaction infra's type system.
    padding_output = TransactionOutput(Script(b""), 0)
    shim_outputs = [padding_output] * contract_utxo.vout + [
        TransactionOutput(Script(contract_utxo.script), contract_utxo.value)
    ]
    src_tx = Transaction(tx_inputs=[], tx_outputs=shim_outputs)
    src_tx.txid = lambda: contract_utxo.txid  # type: ignore[method-assign]

    # The contract input's unlocking_script_template is set to None — we manage
    # the scriptSig directly by setting unlocking_script after construction.
    contract_input = TransactionInput(
        source_transaction=src_tx,
        source_txid=contract_utxo.txid,
        source_output_index=contract_utxo.vout,
        unlocking_script_template=None,
    )
    contract_input.satoshis = contract_utxo.value
    contract_input.locking_script = Script(contract_utxo.script)
    # Attach the placeholder scriptSig so callers can inspect the tx structure.
    contract_input.unlocking_script = Script(placeholder_scriptsig)

    tx = Transaction(
        tx_inputs=[contract_input],
        tx_outputs=[
            TransactionOutput(Script(contract_script), contract_out_value),
            TransactionOutput(Script(reward_script), state.reward),
        ],
    )

    return DmintMintResult(
        tx=tx,
        updated_state=updated_state,
        contract_script=contract_script,
        reward_script=reward_script,
        fee=fee,
    )


def _build_dmint_v1_mint_tx(
    contract_utxo: DmintContractUtxo,
    nonce: bytes,
    miner_pkh: bytes,
    fee_rate: int,
    funding_utxo: DmintMinerFundingUtxo,
    op_return_msg: bytes | None = None,
) -> DmintMintResult:
    """Build a V1 dMint mint tx. Internal — dispatched from build_dmint_mint_tx
    when state.is_v1.

    Mainnet V1 mint transaction shape (docs/dmint-research-mainnet.md §4)::

        vin[0]  contract UTXO          unlocked by build_mint_scriptsig(nonce_4b, preimage)
        vin[1]  funding UTXO           plain-RXD P2PKH paying reward + fee + change
        vout[0] recreated contract     value = contract_utxo.value (singleton, no fee taken)
        vout[1] FT-wrapped reward      75-byte P2PKH+tokenRef, value = state.reward
        vout[2] OP_RETURN msg          (optional; Photonic-Wallet convention)
        vout[3] miner change           plain P2PKH, value = funding − reward − fee

    The contract output value is **preserved across mints** — the V1 covenant
    enforces a singleton, not a value pool. The miner's funding input pays
    the reward (which lands in the FT carrier output) plus the tx fee, and
    receives change.

    :raises InvalidFundingUtxoError: ``funding_utxo.script`` contains any
        OP_PUSHINPUTREF-family opcode (0xd0–0xd8). Spending a token-bearing
        UTXO as fee silently destroys the token; this is the load-bearing
        defense against that mistake.
    :raises ContractExhaustedError: ``state.height >= state.max_height``.
    :raises PoolTooSmallError:      funding UTXO can't cover reward + fee + change dust.
    :raises ValidationError:        nonce/miner_pkh length wrong, fee_rate < 1.
    """
    from pyrxd.script.script import Script
    from pyrxd.transaction.transaction import Transaction
    from pyrxd.transaction.transaction_input import TransactionInput
    from pyrxd.transaction.transaction_output import TransactionOutput

    state = contract_utxo.state

    if state.is_exhausted:
        raise ContractExhaustedError(
            f"V1 dMint contract is exhausted: height={state.height} >= max_height={state.max_height}"
        )
    if len(nonce) != 4:
        raise ValidationError(f"V1 nonce must be 4 bytes, got {len(nonce)}")
    if len(miner_pkh) != 20:
        raise ValidationError(f"miner_pkh must be 20 bytes, got {len(miner_pkh)}")
    if fee_rate < 1:
        raise ValidationError(f"fee_rate must be >= 1, got {fee_rate}")

    # Reject token-bearing funding UTXOs to prevent silent token-burn.
    if is_token_bearing_script(funding_utxo.script):
        raise InvalidFundingUtxoError(
            f"funding_utxo at {funding_utxo.txid}:{funding_utxo.vout} carries an "
            f"OP_PUSHINPUTREF-family opcode (token envelope) and cannot be spent "
            f"as fee — that would silently destroy the token. Use a plain RXD UTXO."
        )

    if op_return_msg is not None and len(op_return_msg) > 80:
        # Standardness limit: most node policies cap OP_RETURN data at 80 bytes.
        raise ValidationError(f"op_return_msg too long ({len(op_return_msg)} bytes); standardness limit is 80 bytes")

    # --- Compute updated state. V1 has no DAA, so target is unchanged. ---
    new_height = state.height + 1
    updated_state = DmintState(
        height=new_height,
        contract_ref=state.contract_ref,
        token_ref=state.token_ref,
        max_height=state.max_height,
        reward=state.reward,
        algo=state.algo,
        daa_mode=DaaMode.FIXED,
        target_time=0,
        last_time=0,
        target=state.target,
        is_v1=True,
    )

    # --- Output scripts ---
    contract_script = build_dmint_v1_contract_script(
        height=new_height,
        contract_ref=state.contract_ref,
        token_ref=state.token_ref,
        max_height=state.max_height,
        reward=state.reward,
        target=state.target,
        algo=state.algo,
    )
    # The 75-byte FT-wrapped reward — load-bearing for the V1 covenant's
    # OP_CODESCRIPTHASHVALUESUM_OUTPUTS conservation check.
    reward_script = build_dmint_v1_ft_output_script(miner_pkh, state.token_ref)
    change_script = b"\x76\xa9\x14" + miner_pkh + b"\x88\xac"
    op_return_script: bytes | None = None
    if op_return_msg is not None:
        # Photonic-Wallet convention (docs/dmint-research-mainnet.md §4 vout[2]):
        # OP_RETURN PUSH3 "msg" <push-len> <message>
        # The "msg" marker push is what wallet/explorer parsers key on to
        # surface the message; without it, the OP_RETURN is just opaque
        # bytes from the indexer's perspective. The covenant doesn't enforce
        # this — but we want byte-equivalence with mainnet for ecosystem
        # compatibility.
        msg_marker = b"\x03msg"
        if len(op_return_msg) <= 0x4B:
            data_push = bytes([len(op_return_msg)]) + op_return_msg
        else:
            # PUSHDATA1
            data_push = b"\x4c" + bytes([len(op_return_msg)]) + op_return_msg
        op_return_script = b"\x6a" + msg_marker + data_push

    # --- Placeholder scriptSigs.
    # Contract input: nonce-bearing scriptSig with sentinel 0xff*64 preimage.
    # The 0xff bytes are visibly-invalid: a miner that forgets to replace
    # them gets fast network rejection rather than a covenant-fail silent
    # bug. Mining replaces this whole scriptSig.
    placeholder_preimage = b"\xff" * 64
    placeholder_contract_scriptsig = build_mint_scriptsig(nonce, placeholder_preimage, nonce_width=4)
    # Funding input: 108 zero bytes — the WORST-CASE size of a signed P2PKH
    # scriptSig. A real signed scriptSig is 106-108 bytes:
    #   <push-len 0x47..0x49> <DER sig 70-72 bytes + sighash 1 byte>
    #   <push-len 0x21> <compressed pubkey 33 bytes>
    # Low-S DER signatures distribute roughly 25/50/25% over 70/71/72 bytes,
    # so ~25% of real scriptSigs will be 108 bytes. We pad to 108 — over-
    # estimation by ≤2 bytes is harmless (slight fee over-payment), but
    # under-estimation causes ~25% of broadcasts to fall under the relay
    # min-fee floor (fee/size < 10000 photons/byte) and get rejected.
    # Asymmetric over-padding is the only safe direction.
    #
    # Assumes compressed pubkeys (every signing path in pyrxd uses them).
    # An uncompressed pubkey would push this to ~140 bytes; if a future
    # caller signs uncompressed, fix the placeholder and this comment.
    _P2PKH_SCRIPTSIG_MAX_LEN = 108
    placeholder_funding_scriptsig = b"\x00" * _P2PKH_SCRIPTSIG_MAX_LEN

    # --- Assemble unsigned tx with both placeholder scriptSigs attached so
    # `len(tx.serialize())` reflects the final on-wire size. Cleaner than
    # hand-rolling varint accounting and avoids drift between the fee
    # estimate and the actual tx bytes.
    padding_output = TransactionOutput(Script(b""), 0)

    contract_src_outputs = [padding_output] * contract_utxo.vout + [
        TransactionOutput(Script(contract_utxo.script), contract_utxo.value)
    ]
    contract_src_tx = Transaction(tx_inputs=[], tx_outputs=contract_src_outputs)
    contract_src_tx.txid = lambda: contract_utxo.txid  # type: ignore[method-assign]

    funding_src_outputs = [padding_output] * funding_utxo.vout + [
        TransactionOutput(Script(funding_utxo.script), funding_utxo.value)
    ]
    funding_src_tx = Transaction(tx_inputs=[], tx_outputs=funding_src_outputs)
    funding_src_tx.txid = lambda: funding_utxo.txid  # type: ignore[method-assign]

    contract_input = TransactionInput(
        source_transaction=contract_src_tx,
        source_txid=contract_utxo.txid,
        source_output_index=contract_utxo.vout,
        unlocking_script_template=None,
    )
    contract_input.satoshis = contract_utxo.value
    contract_input.locking_script = Script(contract_utxo.script)
    contract_input.unlocking_script = Script(placeholder_contract_scriptsig)

    funding_input = TransactionInput(
        source_transaction=funding_src_tx,
        source_txid=funding_utxo.txid,
        source_output_index=funding_utxo.vout,
        unlocking_script_template=None,
    )
    funding_input.satoshis = funding_utxo.value
    funding_input.locking_script = Script(funding_utxo.script)
    # Attach a same-size placeholder so len(tx.serialize()) below reflects
    # the post-signing size. Caller replaces with the real signature.
    funding_input.unlocking_script = Script(placeholder_funding_scriptsig)

    # Trial-assemble outputs with a placeholder change value of 0 so we
    # can serialize the tx, measure its byte length, compute the real
    # fee, then patch the change output to its final value. The
    # serialized size doesn't depend on the change-output *value* (the
    # 8-byte satoshi field is fixed-width regardless), only on its
    # script length — so the trial measurement matches the final size
    # exactly.
    trial_outputs = [
        TransactionOutput(Script(contract_script), contract_utxo.value),
        TransactionOutput(Script(reward_script), state.reward),
    ]
    if op_return_script:
        trial_outputs.append(TransactionOutput(Script(op_return_script), 0))
    change_output = TransactionOutput(Script(change_script), 0)  # value patched below
    trial_outputs.append(change_output)

    tx = Transaction(
        tx_inputs=[contract_input, funding_input],
        tx_outputs=trial_outputs,
    )

    # The funding input pays:
    #   - the FT reward output's photons (state.reward, FT carrier value on vout[1])
    #   - the tx fee (size × fee_rate)
    #   - the change output back to miner_pkh
    fee = len(tx.serialize()) * fee_rate
    change_value = funding_utxo.value - state.reward - fee
    if change_value < 546:
        raise PoolTooSmallError(
            f"funding_utxo ({funding_utxo.value} photons) too small to cover "
            f"reward ({state.reward}) + fee ({fee}): change would be "
            f"{change_value} photons, below 546 dust limit."
        )
    change_output.satoshis = change_value

    return DmintMintResult(
        tx=tx,
        updated_state=updated_state,
        contract_script=contract_script,
        reward_script=reward_script,
        fee=fee,
    )


def _varint_size(n: int) -> int:
    """Return the number of bytes needed to encode ``n`` as a Bitcoin varint."""
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


# ---------------------------------------------------------------------------
# Chain-touching helpers (network-side; require an ElectrumXClient)
# ---------------------------------------------------------------------------
#
# These functions touch the network — they live here rather than in
# pyrxd.network because the protocol logic (token-burn defense,
# preimage construction binding) is dMint-specific and shouldn't leak
# into the network layer. Imports are lazy so dmint.py stays
# light-import for callers that only need the pure builders/parsers.


async def find_dmint_funding_utxo(
    client: Any,
    miner_address: str,
    needed: int,
    *,
    require_confirmed: bool = True,
) -> DmintMinerFundingUtxo:
    """Scan ``miner_address`` for a plain-RXD UTXO that funds a V1 mint.

    Excludes token-bearing UTXOs (FT, NFT, dMint covenant scripts)
    using :func:`is_token_bearing_script` — the same opcode-aware
    walker the V1 mint builder enforces. Returns the largest qualifying
    candidate to minimise change-output dust risk.

    A plain-RXD funding input is what the V1 covenant requires (V1
    contracts are singletons; reward + fee come from a separate input).
    Spending an FT/NFT/dMint UTXO as fee silently destroys the token —
    this scan is the load-bearing defense.

    :param client:             An already-connected ``pyrxd.network.electrumx.ElectrumXClient``.
    :param miner_address:      Radiant address (R…) of the wallet to scan.
    :param needed:             Minimum photons the candidate must hold.
    :param require_confirmed:  Default ``True``. Skip UTXOs with
        ``height == 0`` (unconfirmed). Picking an unconfirmed UTXO can
        cause "missing inputs" rejection when the parent tx hasn't
        propagated to all relays, or leave a dangling tx if the parent
        gets evicted from mempool. Set ``False`` only if you're
        deliberately funding from a same-tx chain.
    :returns:                  The largest qualifying funding UTXO.
    :raises InvalidFundingUtxoError:
        No plain-RXD UTXO at ``miner_address`` covers ``needed``. The
        error message reports counts of (a) token-bearing skipped,
        (b) too-small skipped, (c) unconfirmed skipped (when
        ``require_confirmed=True``), and (d) network-error skipped, so
        the caller can diagnose why the wallet failed the scan.
    """
    # Lazy imports so callers that only use the pure builders/parsers
    # don't pay the import cost of the network and transaction modules.
    from pyrxd.network.electrumx import script_hash_for_address
    from pyrxd.security.errors import NetworkError
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    raw = await client.get_utxos(script_hash_for_address(miner_address))
    candidates: list[DmintMinerFundingUtxo] = []
    skipped_tokens = 0
    skipped_too_small = 0
    skipped_unconfirmed = 0
    skipped_network_error = 0

    for u in raw:
        if require_confirmed and u.height == 0:
            skipped_unconfirmed += 1
            continue
        try:
            tx_bytes = await client.get_transaction(Txid(u.tx_hash))
        except NetworkError:
            skipped_network_error += 1
            continue
        tx = Transaction.from_hex(bytes(tx_bytes))
        if tx is None or u.tx_pos >= len(tx.outputs):
            continue
        script = tx.outputs[u.tx_pos].locking_script.serialize()
        if is_token_bearing_script(script):
            skipped_tokens += 1
            continue
        if u.value < needed:
            skipped_too_small += 1
            continue
        candidates.append(
            DmintMinerFundingUtxo(
                txid=u.tx_hash,
                vout=u.tx_pos,
                value=u.value,
                script=script,
            )
        )

    if not candidates:
        parts = [f"{skipped_tokens} token-bearing", f"{skipped_too_small} too small"]
        if require_confirmed and skipped_unconfirmed:
            parts.append(f"{skipped_unconfirmed} unconfirmed")
        if skipped_network_error:
            parts.append(f"{skipped_network_error} network-error")
        raise InvalidFundingUtxoError(
            f"no plain-RXD funding UTXO at {miner_address} covers {needed} photons (skipped: {', '.join(parts)})"
        )
    # Largest-first: minimises change-output dust risk.
    candidates.sort(key=lambda u: u.value, reverse=True)
    return candidates[0]


def build_dmint_v1_mint_preimage(
    contract_utxo: DmintContractUtxo,
    funding_utxo: DmintMinerFundingUtxo,
    unsigned_tx: Any,
) -> bytes:
    """Build the 64-byte V1 mining preimage for an unsigned mint tx.

    The V1 covenant binds the PoW preimage to:

    1. The contract input's outpoint txid + the contract ref
       (so a nonce mined for one contract slot can't be replayed
       against another)
    2. The miner's funding-input locking script
       (so the miner cannot substitute a different funding source
       after finding a nonce)
    3. The OP_RETURN msg output script at vout[2]
       (Photonic's mainnet-canonical layout; the covenant computes
       outputHash = SHA256d(this script))

    Layout (matches :func:`build_pow_preimage`)::

        SHA256(txid_LE || contractRef) ||
        SHA256(SHA256d(input_script) || SHA256d(output_script))

    :param contract_utxo:  The V1 contract UTXO being spent.
    :param funding_utxo:   The plain-RXD UTXO providing reward + fee.
    :param unsigned_tx:    The unsigned :class:`Transaction` from
                           :func:`build_dmint_mint_tx` — vout[2] is
                           required to be the OP_RETURN msg output
                           (mainnet-canonical 4-output shape).
    :returns:              64 bytes ready to feed into :func:`mine_solution`
                           or :func:`mine_solution_external`.
    :raises ValidationError:
        ``unsigned_tx`` has fewer than 4 outputs (no OP_RETURN at vout[2])
        OR vout[2] is not actually an OP_RETURN script. Build the tx via
        :func:`build_dmint_mint_tx` with a non-empty ``op_return_msg``;
        skipping that produces a 3-output tx, and hand-building a 4-output
        tx with a different vout[2] would silently bind the preimage to
        wrong bytes (the on-chain covenant would then reject after a
        successful mine — wasting the mining work).
    """
    if len(unsigned_tx.outputs) < 4:
        raise ValidationError(
            "V1 mint preimage construction expects an OP_RETURN msg "
            "output at vout[2] (mainnet-canonical shape). Build the tx "
            "with op_return_msg set to a non-empty bytes value before "
            "computing the preimage."
        )
    output_script = unsigned_tx.outputs[2].locking_script.serialize()
    if not output_script or output_script[0] != 0x6A:
        raise ValidationError(
            "V1 mint preimage requires vout[2] to be an OP_RETURN script "
            "(starts with 0x6a). The on-chain covenant binds outputHash "
            "to vout[2]; a non-OP_RETURN at this position would produce "
            "a preimage that fails the covenant check after mining."
        )
    txid_le = bytes.fromhex(contract_utxo.txid)[::-1]
    return build_pow_preimage(
        txid_le=txid_le,
        contract_ref_bytes=contract_utxo.state.contract_ref.to_bytes(),
        input_script=funding_utxo.script,
        output_script=output_script,
    )


# ---------------------------------------------------------------------------
# Live V1 contract UTXO discovery (M2 chain helper)
# ---------------------------------------------------------------------------
#
# Shipped here, alongside ``find_dmint_funding_utxo``, because both are
# protocol-aware ElectrumX consumers that the network layer should not have
# to know about. The helper supports two distinct call shapes — see plan
# §2b.1 (`docs/plans/2026-05-08-feat-dmint-v1-deploy-plan.md`) for the
# rationale (TL;DR: public ElectrumX has no ref-listing RPC, so callers
# without the deploy params must walk forward from the deploy reveal).


@dataclass(frozen=True)
class DmintV1ContractInitialState:
    """Just-deployed state of a V1 dMint contract template.

    Carries exactly the parameters needed to reconstruct the initial
    (height=0) contract codescript for *every* contract of a given
    deploy. Used by :func:`find_dmint_contract_utxos`'s fast path,
    where the caller already knows the deploy params.

    :param num_contracts: Count of parallel contracts the deploy created
        (1..255 for V1; mainnet GLYPH used 32).
    :param reward_sats: Photons emitted per successful mint (must fit in
        3 bytes — V1 protocol constant).
    :param max_height: Maximum mints per contract (3-byte ceiling).
    :param target: 8-byte SHA256d PoW target.
    :param algo: PoW algorithm. Defaults to ``DmintAlgo.SHA256D``,
        which is the only algorithm seen on V1 mainnet.
    """

    num_contracts: int
    reward_sats: int
    max_height: int
    target: int
    algo: DmintAlgo = DmintAlgo.SHA256D


def _scripthash_for_script(script: bytes) -> str:
    """Return the ElectrumX scripthash for *script* (sha256, then reversed).

    Inline two-line helper rather than a module-level export — used in
    exactly one place (the fast path below). ElectrumX's reverse step
    matches the display-byte-order convention used elsewhere in the
    codebase (see :func:`script_hash_for_address`).
    """
    return hashlib.sha256(script).digest()[::-1].hex()


async def find_dmint_contract_utxos(
    client: Any,
    *,
    token_ref: GlyphRef,
    initial_state: DmintV1ContractInitialState | None = None,
    limit: int | None = None,
    min_confirmations: int = 1,
) -> list[DmintContractUtxo]:
    """Discover live V1 dMint contract UTXOs for a given ``token_ref``.

    Two call shapes:

    - **Fast path** — pass ``initial_state``. The function rebuilds each
      contract's expected initial codescript locally
      (``contractRef[i] = (commit_txid, i+1)``, ``tokenRef = token_ref``),
      computes its scripthash inline, and asks the server for the UTXO
      at that scripthash. One ``get_utxos`` call per contract. Use this
      shape immediately after deploy to verify all N contracts went
      live, or any time the caller has the deploy params handy.

    - **Walk-from-reveal fallback** — omit ``initial_state``. The
      function fetches the deploy commit, derives the FT-commit
      hashlock's scripthash, queries history for the reveal txid, then
      fetches the reveal and extracts every fresh V1 contract output
      whose ``tokenRef`` matches. Slower (3+ extra round-trips) but
      works on any live token where you only know the ``token_ref``.

    Both shapes apply the same security S2 cross-check: for each
    candidate UTXO returned, the source transaction is fetched and
    verified to have ``txid()`` matching the server's ``tx_hash``, and
    its output script byte-equal to the script the server claimed.
    Defends against a malicious or buggy ElectrumX serving altered
    bytes (mirrors :func:`find_dmint_funding_utxo`'s round-4 defense).

    The fallback path returns *fresh* contracts only — UTXOs that have
    been mined from at least once are skipped (their state advanced and
    their scripthash drifted; following the spend chain forward to
    locate the current head is filed as deferred work).

    :param client:             An open ``pyrxd.network.electrumx.ElectrumXClient``.
    :param token_ref:          The token's permanent 36-byte ref (the
        deploy commit's vout-0 outpoint, LE-reversed). Equivalently:
        ``GlyphRef(txid=commit_txid, vout=0)``.
    :param initial_state:      If supplied, fast-path. If ``None``, walk
        from the deploy reveal.
    :param limit:              If supplied, cap the result list at this
        many contracts. ``None`` returns all available.
    :param min_confirmations:  Skip UTXOs younger than this many blocks.
        Default 1 (require at least 1 confirmation).
    :returns:                  A list of :class:`DmintContractUtxo` for
        each currently-unspent contract whose script verified S2.
    :raises ValidationError:   Inputs malformed (token_ref must point at
        ``vout=0``); or initial_state has out-of-range fields.
    :raises NetworkError:      Propagated from the ElectrumX client.
    """
    # Lazy imports — keeping dmint.py light for callers that don't touch
    # the network (the inspect tool in particular).
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    if token_ref.vout != 0:
        raise ValidationError(f"token_ref must point at vout=0 of the deploy commit; got vout={token_ref.vout}")
    if limit is not None and limit < 1:
        raise ValidationError(f"limit must be >= 1 if supplied, got {limit}")
    if min_confirmations < 0:
        raise ValidationError(f"min_confirmations must be >= 0, got {min_confirmations}")

    commit_txid = token_ref.txid

    if initial_state is not None:
        if initial_state.num_contracts < 1 or initial_state.num_contracts > 255:
            raise ValidationError(f"num_contracts must be in [1, 255], got {initial_state.num_contracts}")
        candidates = await _find_v1_contract_utxos_fast(
            client,
            token_ref=token_ref,
            commit_txid=commit_txid,
            initial_state=initial_state,
            min_confirmations=min_confirmations,
        )
    else:
        candidates = await _find_v1_contract_utxos_walk(
            client,
            token_ref=token_ref,
            commit_txid=commit_txid,
            min_confirmations=min_confirmations,
        )

    # Security S2 cross-check applied uniformly to whichever shape ran.
    verified = await _s2_verify_contract_utxos(client, candidates, Txid=Txid, Transaction=Transaction)

    if limit is not None:
        verified = verified[:limit]
    return verified


async def _find_v1_contract_utxos_fast(
    client: Any,
    *,
    token_ref: GlyphRef,
    commit_txid: str,
    initial_state: DmintV1ContractInitialState,
    min_confirmations: int,
) -> list[DmintContractUtxo]:
    """Shape A: the caller knows the deploy params, so we can rebuild
    each expected initial codescript and query its scripthash directly.
    """
    from pyrxd.security.types import Txid

    out: list[DmintContractUtxo] = []
    for i in range(initial_state.num_contracts):
        contract_ref = GlyphRef(txid=Txid(commit_txid), vout=i + 1)
        codescript = build_dmint_v1_contract_script(
            height=0,
            contract_ref=contract_ref,
            token_ref=token_ref,
            max_height=initial_state.max_height,
            reward=initial_state.reward_sats,
            target=initial_state.target,
            algo=initial_state.algo,
        )
        sh = _scripthash_for_script(codescript)
        utxos = await client.get_utxos(sh)
        for u in utxos:
            if u.height == 0 and min_confirmations > 0:
                continue
            # State is a known-initial state: we just built the
            # script, so DmintState.from_script(codescript) is the
            # ground truth here. Avoids re-parsing per UTXO.
            state = DmintState.from_script(codescript)
            out.append(
                DmintContractUtxo(
                    txid=u.tx_hash,
                    vout=u.tx_pos,
                    value=u.value,
                    script=codescript,
                    state=state,
                )
            )
    return out


async def _find_v1_contract_utxos_walk(
    client: Any,
    *,
    token_ref: GlyphRef,
    commit_txid: str,
    min_confirmations: int,
) -> list[DmintContractUtxo]:
    """Shape B: the caller has only ``token_ref``. Walk from the deploy
    commit's vout 0 history to locate the reveal, then enumerate the
    reveal's V1 dMint contract outputs and verify each is unspent.
    """
    from pyrxd.security.types import Txid
    from pyrxd.transaction.transaction import Transaction

    # 1. Fetch the commit; extract vout 0's locking script.
    commit_raw = await client.get_transaction(Txid(commit_txid))
    commit_tx = Transaction.from_hex(bytes(commit_raw))
    if commit_tx is None or len(commit_tx.outputs) == 0:
        raise ValidationError(f"deploy commit {commit_txid} has no outputs or did not parse")
    commit_vout0_script = commit_tx.outputs[0].locking_script.serialize()

    # 2. Find the reveal via scripthash history, then disambiguate by
    # input. The FT-commit hashlock script may have been reused across
    # several txs by the same deployer (e.g. failed earlier attempts at
    # the same deploy share the same payload-hash and therefore the same
    # 75-byte hashlock script). The scripthash alone is not unique to
    # this commit instance — we must filter by "spends commit_txid:0".
    sh = _scripthash_for_script(commit_vout0_script)
    history = await client.get_history(sh)
    reveal_txid: str | None = None
    reveal_tx = None
    for entry in history:
        h_txid = entry.get("tx_hash") if isinstance(entry, dict) else None
        if not h_txid or h_txid == commit_txid:
            continue
        # Confirm this candidate actually spends commit_txid:0.
        cand_raw = await client.get_transaction(Txid(h_txid))
        cand_tx = Transaction.from_hex(bytes(cand_raw))
        if cand_tx is None:
            continue
        spends_commit_vout0 = any(
            ti.source_txid == commit_txid and ti.source_output_index == 0 for ti in cand_tx.inputs
        )
        if spends_commit_vout0:
            reveal_txid = h_txid
            reveal_tx = cand_tx
            break
    if reveal_txid is None or reveal_tx is None:
        # Commit unspent (deploy never revealed) or server returned only
        # txs that share the scripthash by hashlock-reuse, none of which
        # actually spend the deploy commit.
        return []

    out: list[DmintContractUtxo] = []
    for vout_i, output in enumerate(reveal_tx.outputs):
        script = output.locking_script.serialize()
        try:
            state = DmintState.from_script(script)
        except ValidationError:
            continue
        if not state.is_v1:
            continue
        if state.token_ref.to_bytes() != token_ref.to_bytes():
            continue

        # 4. Confirm UTXO is currently unspent (skip mined-from contracts —
        # see docstring deferred-work note).
        out_sh = _scripthash_for_script(script)
        utxos = await client.get_utxos(out_sh)
        match = next(
            (u for u in utxos if u.tx_hash == reveal_txid and u.tx_pos == vout_i),
            None,
        )
        if match is None:
            continue
        if match.height == 0 and min_confirmations > 0:
            continue
        out.append(
            DmintContractUtxo(
                txid=match.tx_hash,
                vout=match.tx_pos,
                value=match.value,
                script=script,
                state=state,
            )
        )
    return out


async def _s2_verify_contract_utxos(
    client: Any,
    candidates: list[DmintContractUtxo],
    *,
    Txid: Any,
    Transaction: Any,
) -> list[DmintContractUtxo]:
    """Apply security S2: re-fetch each candidate's source tx, confirm
    txid matches and the output script is byte-equal to what the server
    returned. Rejects altered scripts before they reach the caller.

    Mirrors the round-4 defense in :func:`find_dmint_funding_utxo`.
    """
    verified: list[DmintContractUtxo] = []
    for c in candidates:
        raw = await client.get_transaction(Txid(c.txid))
        tx = Transaction.from_hex(bytes(raw))
        if tx is None:
            raise CovenantError(f"S2 cross-check: source tx {c.txid} did not parse")
        if tx.txid() != c.txid:
            raise CovenantError(f"S2 cross-check: server reported txid {c.txid} but tx parses as {tx.txid()}")
        if c.vout >= len(tx.outputs):
            raise CovenantError(
                f"S2 cross-check: tx {c.txid} has only {len(tx.outputs)} outputs but server claimed vout={c.vout}"
            )
        on_chain_script = tx.outputs[c.vout].locking_script.serialize()
        if on_chain_script != c.script:
            raise CovenantError(
                f"S2 cross-check: script mismatch at {c.txid}:{c.vout} "
                f"(server returned {len(c.script)} bytes; on-chain is {len(on_chain_script)} bytes)"
            )
        verified.append(c)
    return verified

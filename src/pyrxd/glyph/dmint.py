"""dMint V2 — decentralized mineable token support.

Implements the V2 dMint contract script construction, PoW preimage building,
ASERT/linear DAA target computation, and mint-tx scriptSig assembly.

Design reference: glyph-miner/docs/V2_DMINT_DESIGN.md
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from pyrxd.security.errors import ValidationError

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


def build_mint_scriptsig(nonce: bytes, preimage: bytes) -> bytes:
    """Build the scriptSig a miner includes in the contract-spend input.

    Format (SHA256d): <nonce:8B> 20 <inputHash:32B> 20 <outputHash:32B> 00
    The nonce is 8 bytes (two u32 values concatenated, as in V1).

    :param nonce:    8-byte nonce (found during GPU/CPU mining)
    :param preimage: 64-byte preimage from build_pow_preimage()
    """
    if len(nonce) != 8:
        raise ValidationError(f"nonce must be 8 bytes, got {len(nonce)}")
    if len(preimage) != 64:
        raise ValidationError(f"preimage must be 64 bytes, got {len(preimage)}")
    # Push nonce (8 bytes), then two 32-byte pushes (first/second half of preimage),
    # then OP_0 (padding for scriptSig structure).
    return (
        b"\x08"
        + nonce  # PUSH 8 + nonce
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


def verify_sha256d_solution(preimage: bytes, nonce: bytes, target: int) -> bool:
    """Verify a SHA256d PoW solution.

    Valid if: hash[0..4] == 0x00000000 AND int.from_bytes(hash[4..12], 'big') < target

    target is clamped to MAX_SHA256D_TARGET before comparison — a caller-supplied
    target above the maximum would make the check trivially pass for any hash
    that starts with four zero bytes.
    """
    if target <= 0:
        return False
    effective_target = min(target, MAX_SHA256D_TARGET)
    full = hashlib.sha256(hashlib.sha256(preimage + nonce).digest()).digest()
    if full[:4] != b"\x00\x00\x00\x00":
        return False
    value = int.from_bytes(full[4:12], "big")
    return value < effective_target


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
_V1_ALGO_BYTE_TO_ENUM: dict[int, DmintAlgo] = {
    0xAA: DmintAlgo.SHA256D,
    0xEE: DmintAlgo.BLAKE3,
    0xEF: DmintAlgo.K12,
}


def _match_v1_epilogue(script: bytes, start: int) -> tuple[bool, DmintAlgo | None]:
    """Return (matched, algo) for a V1 epilogue starting at *start*."""
    if start + _V1_EPILOGUE_LEN > len(script):
        return (False, None)
    if script[start : start + len(_V1_EPILOGUE_PREFIX)] != _V1_EPILOGUE_PREFIX:
        return (False, None)
    algo_byte = script[start + _V1_EPILOGUE_ALGO_OFFSET]
    algo = _V1_ALGO_BYTE_TO_ENUM.get(algo_byte)
    if algo is None:
        return (False, None)
    suffix_start = start + _V1_EPILOGUE_ALGO_OFFSET + 1
    if script[suffix_start : suffix_start + len(_V1_EPILOGUE_SUFFIX)] != _V1_EPILOGUE_SUFFIX:
        return (False, None)
    return (True, algo)


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
        matched, algo = _match_v1_epilogue(script_bytes, pos)
        if not matched or algo is None:
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
    :param value:        photon value locked in the UTXO (reward pool balance)
    :param script:       full output script bytes (state + OP_STATESEPARATOR + code)
    :param state:        parsed :class:`DmintState` — caller can obtain via
                         ``DmintState.from_script(script)``
    """

    txid: str
    vout: int
    value: int
    script: bytes
    state: DmintState


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

    state = contract_utxo.state

    if state.is_exhausted:
        raise ValidationError(f"dMint contract is exhausted: height={state.height} >= max_height={state.max_height}")
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

    # --- Placeholder scriptSig (nonce + dummy preimage zeros) ---
    # The real preimage requires txid + script hashes which are only available
    # once outputs are finalised (see docstring). Preimage bytes here are zeros;
    # a miner loop MUST replace this before broadcast.
    placeholder_preimage = bytes(64)
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
        raise ValidationError(
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


def _varint_size(n: int) -> int:
    """Return the number of bytes needed to encode ``n`` as a Bitcoin varint."""
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9

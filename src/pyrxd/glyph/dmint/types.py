"""Type definitions for the dMint subpackage.

Pure data types consumed by ≥2 sibling submodules, plus the
``V2UnvalidatedWarning`` warning class and shared module-level byte
constants. Depends on nothing within the subpackage; siblings import
from here, not the reverse.

Symbols (37 — every module-level name defined here, so the count is checkable rather than
decorative, and ``tests/test_dmint_deploy_bounds.py`` checks it and the list below against the
module's own definitions; it read "20" while listing 17 before 2026-09-22, and "31" while
listing 32 on 2026-09-23):
    V2UnvalidatedWarning,
    MAX_SHA256D_TARGET, MAX_V2_TARGET_256,
    MAX_SCRIPT_NUM_BYTES, MAX_SCRIPT_NUM, MAX_V1_MAX_HEIGHT, MAX_V2_TARGET_TIME,
    target_for_difficulty, _refuse_above, check_dmint_core_bounds, check_dmint_v1_bounds,
    check_v2_numeric_bounds,
    EPOCH_MAX_ADJUSTMENT_LOG2_VALUES, EPOCH_MAX_ADJUSTMENT_PAYLOAD_VALUES,
    EPOCH_MAX_SAFE_TARGET, SCHEDULE_MAX_ENTRIES,
    ASERT_V2_RADIX, ASERT_V2_DRIFT_CLAMP, ASERT_V2_MAX_TARGET_DIV4,
    DEFAULT_ASERT_HALFLIFE,
    DmintAlgo, DaaMode, DaaBytecodeVersion,
    _OP_STATESEPARATOR, _PART_B1, _PART_B2, _PART_B4,
    is_minimal_4byte_scriptnum, is_readable_last_time,
    DAA_MODES_READING_DEPLOY_LAST_TIME, DAA_MODES_READING_LAST_TIME,
    DAA_MODES_READING_TARGET_TIME,
    DmintDeployParams, DmintCborPayload, _schedule_from_cbor, DmintMintResult,
    DmintV1ContractInitialState
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from pyrxd.security.errors import ValidationError
from pyrxd.security.json_guards import cbor_int

from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types

if TYPE_CHECKING:
    from collections.abc import Mapping

# ---------------------------------------------------------------------------
# V2 warning category (retired)
# ---------------------------------------------------------------------------
#
# V2 dMint was once quarantined behind a per-call warning because it had never
# run against live consensus. That is no longer true (see the class docstring):
# the canonical-Photonic V2 redesign is byte-matched to upstream and mainnet-
# proven, so the warning is retained as an importable category but is no longer
# emitted. V2 now sits alongside V1 in the README's "Working on mainnet today"
# list under the same blanket "unaudited primitives" caveat.


class V2UnvalidatedWarning(UserWarning):
    """Retained warning category for V2 dMint code paths.

    HISTORY: V2 dMint was once quarantined behind this warning because it had
    never been exercised against live consensus. That is no longer true — the
    canonical-Photonic V2 redesign is byte-matched to upstream and consensus-
    validated on radiant-core v3.1.1 regtest AND Radiant mainnet (3.1.2): the
    first V2 dMint deploy + PoW mint confirmed on mainnet (deploy
    ``95335028…bb16fb09``, mint ``1239f64a…e0cd6c67``; #219). The per-call
    warning is therefore no longer emitted.

    The class is kept (not deleted) so any downstream ``warnings.simplefilter(…,
    V2UnvalidatedWarning)`` filters remain importable. V2 is still **pre-external-
    audit** — that caveat lives in the README / threat-model, the same level as
    V1, not in a per-call warning.
    """


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum dMint target, for EVERY hash algorithm (64-bit; first 4 bytes implicitly zero).
# Valid: hash[0..4] == 0 AND hash[4..12] < MAX_SHA256D_TARGET. The name is historical: Part B1
# (``_PART_B1``) cuts the same 8-byte window out of the PoW hash whichever hash opcode precedes
# it, so a BLAKE3 or K12 contract compares against a target of exactly this width too.
MAX_SHA256D_TARGET = 0x7FFFFFFFFFFFFFFF

# NOT a dMint target bound — retained only so existing imports keep working. Until 2026-09-23
# pyrxd derived BLAKE3/K12 deploy targets from it (``(2**256 - 1) // difficulty``), which for any
# difficulty below 2**192 is wider than 8 bytes: Part B2 reads the target as a script number, and
# an operand wider than 8 bytes aborts the script, so those contracts could never be minted. No
# dMint target, for any algorithm, exceeds MAX_SHA256D_TARGET; nothing in pyrxd reads this
# constant any more.
MAX_V2_TARGET_256 = (1 << 256) - 1

#: The widest numeric operand Radiant's interpreter reads: ``CScriptNum`` refuses an operand
#: longer than ``MAXIMUM_ELEMENT_SIZE_64_BIT`` = 8 bytes (Radiant Core ``script.h``, vendored at
#: ``tests/vendor/radiant_core/script.h``), so the largest script number is ``2**63 - 1``. Every
#: number a dMint covenant reads as one — the state's height, maxHeight, reward and target on
#: every mint, targetTime in ASERT/LWMA/EPOCH, and the constants its DAA fragment bakes — has to
#: fit, or the script aborts.
MAX_SCRIPT_NUM_BYTES = 8
MAX_SCRIPT_NUM = (1 << 63) - 1

#: The largest ``max_height`` whose last mint a V1 contract can reach: ``2**31``. A V1 contract
#: stores its height as a 4-byte field, and every mint but the last writes the next one as
#: ``04 || NUM2BIN(height + 1, 4)`` (epilogue ``54 78 54 80 7e``). ``OP_NUM2BIN`` aborts with
#: ``IMPOSSIBLE_ENCODING`` when the minimal encoding of the number is longer than the size asked
#: for (Radiant Core ``interpreter.cpp``, vendored at ``tests/vendor/radiant_core/``), and
#: ``2**31`` needs five bytes. The last mint, the one whose new height equals ``max_height``,
#: takes the epilogue's other branch and writes no height, so a contract with ``max_height =
#: 2**31`` makes its last mint from height ``2**31 - 1``. With a larger ``max_height`` the mint
#: from ``2**31 - 1`` is not the last, needs ``NUM2BIN(2**31, 4)``, and aborts, so the contract
#: can never be minted past that height. V2 pushes its height minimally and has no such limit.
MAX_V1_MAX_HEIGHT = 1 << 31

#: Upper bound on a V2 deploy's ``target_time`` in the modes whose retarget reads it as a number
#: (:data:`DAA_MODES_READING_TARGET_TIME`: ASERT, LWMA, EPOCH). There ``target_time`` is a spacing
#: in seconds that the retarget compares with the difference of two timestamps, and in any mint the
#: covenant accepts both are below ``2**31``: the state's ``lastTime`` is a 4-byte signed script
#: number, and the mint's own time must fit the same 4-byte field, since Part C writes it into the
#: next state with ``NUM2BIN(…, 4)``. So no mint observes a spacing of ``2**31`` seconds or more.
#: The cap is looser than that, at ``0xFFFFFFFF``: every value it refuses is a spacing no mint can
#: meet, and the values between ``2**31`` and the cap, which no mint can meet either, still deploy
#: (narrowing it is not needed for the int64 bound below). The bound is NOT the
#: int64 abort point, which is further out (ASERT and LWMA multiply ``(timeDelta - targetTime)``
#: by 2**16, which aborts the script once the difference reaches 2**47; EPOCH doubles
#: ``targetTime`` up to four times), and it keeps every intermediate of those retargets inside
#: int64 for any pair of such timestamps. FIXED and SCHEDULE never read ``targetTime`` as a number,
#: so this bound does not apply to them. (Photonic's Mint form offers 10..3600;
#: ``tests/test_dmint_deploy_bounds.py`` pins the values mainnet deploys use.)
MAX_V2_TARGET_TIME = 0xFFFFFFFF

# EPOCH DAA: allowed max-adjustment factors and their log2 (shift count). Restricted
# to powers of 2 so the boundary clamp uses bit-shifts (N× OP_2MUL / OP_2DIV).
EPOCH_MAX_ADJUSTMENT_LOG2_VALUES = (1, 2, 3, 4)  # → 2× / 4× / 8× / 16×
# The ``maxAdjustment`` values Photonic's builder ACCEPTS from a ``DmintPayload.daa``
# (``packages/lib/src/script.ts`` ``maxAdjustmentToLog2`` at becf41a7): 1..4 are read as
# the log2 shift count itself and 8/16 as multipliers — so a payload ``maxAdjustment`` of
# 2 or 4 bakes a 4× or 16× clamp there, not 2× or 4×. The Mint UI passes its "4" default
# straight through to both the payload and the builder (``pages/Mint.tsx``). Anything
# outside this set throws in that builder, so no Photonic-built token carries another value.
EPOCH_MAX_ADJUSTMENT_PAYLOAD_VALUES = (*EPOCH_MAX_ADJUSTMENT_LOG2_VALUES, 8, 16)
# EPOCH target ceiling: target > 2^48 risks overflow in `target × clampedDelta`
# (clampedDelta ≤ targetTime × 2^N). Enforced at deploy when daa_mode == EPOCH.
EPOCH_MAX_SAFE_TARGET = 1 << 48

# SCHEDULE DAA: maximum number of (height, target) entries in a baked schedule.
SCHEDULE_MAX_ENTRIES = 10

# ASERT-v2 / LWMA-v2 fixed-point retarget constants. Transcribed from canonical
# Radiant-Core/Photonic-Wallet ``packages/lib/src/script.ts`` (``ASERT_V2_RADIX``,
# ``ASERT_V2_DRIFT_CLAMP``, ``DEFAULT_ASERT_HALFLIFE``) and
# ``packages/lib/src/dmintDaaV2.ts`` (``ASERT_V2_MAX_TARGET_DIV4``) at commit
# becf41a731e78ab98fdd88652527d7dda12784c6. Both v2 modes carry the per-mint drift
# as ``drift × 2^16`` and clamp it to ±RADIX/4, so the target moves at most ±25% per
# mint; the pre-cap at MAX_TARGET/4 is the difficulty floor of 4 (as LWMA had).
ASERT_V2_RADIX = 1 << 16  # 65536 — fixed-point scale
ASERT_V2_DRIFT_CLAMP = ASERT_V2_RADIX >> 2  # 16384 — ±RADIX/4 per-mint drift clamp
ASERT_V2_MAX_TARGET_DIV4 = MAX_SHA256D_TARGET >> 2  # 0x1FFF_FFFF_FFFF_FFFF — headroom + floor 4

# Canonical default ASERT half-life in seconds when a deploy omits it — script.ts
# ``DEFAULT_ASERT_HALFLIFE = 240`` (≈ 4× the default 60 s target block time). Photonic's
# Mint UI and its Glyph-miner fallback use the SAME value, so a deploy that omits the
# half-life and the miner that later mines it agree. Before 2026-09-16 pyrxd defaulted to
# 3600 (the pre-v2 stepper's default), which a Photonic miner would not have assumed.
DEFAULT_ASERT_HALFLIFE = 240


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


class DaaBytecodeVersion(IntEnum):
    """Which GENERATION of ASERT/LWMA retarget bytecode a deployed contract carries.

    This is orthogonal to the dMint contract format (V1 vs V2 state layout): every
    member here is a V2-format contract. The retarget *formula* baked into Part B
    changed upstream on 2026-06-19 (ASERT, Photonic ``ed53cd41``) and 2026-06-20
    (LWMA, Photonic ``c90e6506``); pyrxd did not follow until 2026-09-16, so contracts
    deployed by pyrxd in between carry the older formula and MUST keep being mined
    under it — a covenant's bytecode is immutable, and a miner that recomputes the
    next target with the wrong formula produces a state the covenant rejects.

    * ``V2`` — the current canonical fractional fixed-point retarget
      (``_build_asert_daa_v2`` / ``_build_linear_daa_v2``). Every new deploy.
    * ``LEGACY`` — the integer power-of-2 ASERT stepper (``_build_asert_daa_legacy``)
      or the unity-gain LWMA WITH the ``OP_0 OP_MAX`` timeDelta floor
      (``_build_linear_daa_legacy``); what pyrxd emitted from 2026-06-17 to 2026-09-15.
    * ``LEGACY_LWMA_PREFLOOR`` — LWMA only: the unity-gain retarget WITHOUT the
      timeDelta floor (``_build_linear_daa_legacy_prefloor``), as pyrxd emitted on
      2026-06-16 — the bytecode of the mainnet LWMA deploy ``dea3beb9…``.

    Detected from a contract's code section by
    :func:`pyrxd.glyph.dmint.builders.detect_daa_bytecode`; a contract matching no
    known template is REPORTED (``UnrecognizedDaaBytecodeError``), never guessed.
    """

    LEGACY_LWMA_PREFLOOR = 0
    LEGACY = 1
    V2 = 2


# ---------------------------------------------------------------------------
# V2 bytecode constants (Part B — shared by builders and chain)
# ---------------------------------------------------------------------------

# OP_STATESEPARATOR — used in builders (V1+V2 contract assembler) and chain
# (V2 state parser). Placed here (types.py) rather than chain.py so that
# builders.py can use it without a builders → chain import that would
# violate the one-way dependency graph.
_OP_STATESEPARATOR = b"\xbd"

# Part B.1: PoW hash extraction (shared by all modes)
_PART_B1 = bytes.fromhex("bc01147f77587f040000000088817600a269")

# Part B.2: target comparison (V2 preserves target for DAA)
_PART_B2 = bytes.fromhex("51797ca269")

# Part B.4: TOALTSTACK newTarget + 4×OP_DROP (lastTime, targetTime, daaMode, algoId).
# The pre-redesign shape was ``7575757575`` (5×OP_DROP), which discarded the
# DAA-computed newTarget so difficulty never advanced on-chain. ``6b`` (TOALTSTACK)
# preserves newTarget on the alt stack for Part C to write into the next state.
_PART_B4 = bytes.fromhex("6b75757575")

# NOTE: Part C is no longer a fixed constant. In the redesign it is
# deploy-parameterized (embeds the immutable state slots so it can rebuild the
# next-state script and let ASERT/LWMA advance difficulty), so it is built per
# contract by ``builders._build_part_c(middle_literal)`` rather than stored here.


# ---------------------------------------------------------------------------
# Script-number minimality (consensus, not policy)
# ---------------------------------------------------------------------------


def is_minimal_4byte_scriptnum(n: int) -> bool:
    """Is ``n``'s FIXED 4-byte little-endian push a minimally encoded ``CScriptNum``?

    The V2 dMint state script pushes ``lastTime`` as a fixed ``04 <4B LE>`` (see
    ``builders._push_4bytes_le``), and the ASERT/LWMA/EPOCH retarget fragments read
    that item back as a NUMBER (``OP_2 OP_PICK; OP_SUB`` — see
    ``builders._V2_EXCESS_PREAMBLE``). Radiant-Core builds the operand with
    ``CScriptNum(vch, fRequireMinimal=true)`` because ``SCRIPT_VERIFY_MINIMALDATA`` is
    in ``MANDATORY_SCRIPT_VERIFY_FLAGS`` (``policy.h``) — so this is CONSENSUS, not
    mempool policy, and a non-minimal operand aborts the script rather than being
    merely non-standard.

    The rule, transcribed from ``CScriptNum``'s constructor: the encoding is minimal
    unless the most-significant byte has nothing but the sign bit, with one exception
    — if the second-most-significant byte already has its high bit set, the extra byte
    is carrying the sign and IS minimal (this is how ``+255`` encodes as ``ff00``).

    Over ``[0, 0x7FFFFFFF]`` — the locktimes Part C's ``NUM2BIN(_, 4)`` can write back —
    this is exactly ``n >= 2**23``; that equality is not hard-coded here, it is derived
    by this predicate and pinned in ``tests/test_dmint_daa_v2_resync.py``. The 2026-09-21
    review measured the same boundary against a real radiant-core node:
    ``last_time=8388608`` accepted, ``8388607`` rejected with
    ``mandatory-script-verify-flag-failed``.

    This answers ONLY the encoding question. A value with bit 31 set (``0x80800000``,
    ``0xFFFFFFFF``) can be minimally encoded and still not mean ``n``: its top bit is the
    script-number SIGN, so the covenant reads it as a negative number while
    :class:`~pyrxd.glyph.dmint.chain.DmintState` parses it unsigned. To ask whether a
    lastTime reads back as the number pyrxd wrote, use :func:`is_readable_last_time`.
    """
    if not 0 <= n <= 0xFFFFFFFF:
        return False  # outside what a 4-byte push can carry at all
    vch = n.to_bytes(4, "little")
    if vch[-1] & 0x7F:
        return True
    return bool(vch[-2] & 0x80)


def is_readable_last_time(n: int) -> bool:
    """Does a V2 state's fixed 4-byte ``lastTime`` push read back, as a number, as ``n``?

    True exactly when the push is minimally encoded (:func:`is_minimal_4byte_scriptnum`)
    AND bit 31 is clear, i.e. ``2**23 <= n <= 0x7FFFFFFF``. Below ``2**23`` the retarget's
    ``CScriptNum`` read aborts the script (MINIMALDATA is consensus on Radiant); with
    bit 31 set the covenant reads a negative number that pyrxd's off-chain mirrors,
    which parse the state unsigned, would not reproduce. Both the deploy guard
    (``pyrxd.glyph.builder.require_mineable_last_time``) and the mint builder
    (``build_dmint_mint_tx``) refuse on this predicate, so pyrxd never writes a lastTime
    a later retarget reads differently from — or cannot read at all.
    """
    return 0 <= n <= 0x7FFFFFFF and is_minimal_4byte_scriptnum(n)


#: The DAA modes whose retarget fragment reads ``lastTime`` on the **first** mint,
#: i.e. while the state still carries the value chosen at deploy.
#:
#: ASERT and LWMA open their fragment with the unconditional "excess" preamble
#: (``OP_TXLOCKTIME OP_2 OP_PICK OP_SUB …``), so the very first mint — and every mint
#: after it — constructs a ``CScriptNum`` from the state's ``lastTime``. EPOCH reads it
#: only inside a branch gated on ``height > 0 and height % epochLength == 0``, which
#: height 0 never takes; SCHEDULE/FIXED never read it at all. So the value chosen AT
#: DEPLOY is never read by those three: every state above height 0 carries the
#: ``lastTime`` its own mint wrote. (That second value IS read by EPOCH at each
#: boundary — see :data:`DAA_MODES_READING_LAST_TIME`, which the mint builder guards.)
#:
#: This membership is DERIVED from the emitted bytecode and checked against this
#: constant in ``tests/test_dmint_daa_v2_resync.py`` (a mode whose fragment starts
#: reading ``lastTime`` unconditionally must appear here, or that test fails).
DAA_MODES_READING_DEPLOY_LAST_TIME = frozenset({DaaMode.ASERT, DaaMode.LWMA})

#: The DAA modes whose retarget fragment reads ``lastTime`` as a number on SOME mint —
#: so a ``lastTime`` a mint WRITES for one of these can be read by a later mint.
#:
#: ASERT and LWMA read it on every mint; EPOCH reads it on every epoch-boundary mint
#: (a state at ``height > 0`` with ``height % epochLength == 0``). SCHEDULE and FIXED
#: never read it. ``build_dmint_mint_tx`` refuses to write an unreadable ``lastTime``
#: (:func:`is_readable_last_time`) for these modes. Membership is DERIVED by running
#: every generation of every mode's fragment under the int64/MINIMALDATA evaluator in
#: ``tests/test_dmint_daa_offchain_onchain_differential.py`` with an unreadable lastTime,
#: and checked against this constant there.
DAA_MODES_READING_LAST_TIME = frozenset({DaaMode.ASERT, DaaMode.LWMA, DaaMode.EPOCH})

#: The DAA modes whose retarget fragment reads the state's ``targetTime`` as a number.
#:
#: ASERT and LWMA subtract it from the observed spacing; EPOCH scales and divides by it at an
#: epoch boundary. FIXED has no fragment and SCHEDULE's reads only the height, so for those two
#: ``targetTime`` is only ever carried as bytes: Part A never picks it, Part B4 drops it with
#: ``OP_DROP``, and Part C copies it inside the baked middle literal. :data:`MAX_V2_TARGET_TIME`
#: applies to these modes only. Membership is DERIVED by running every generation of every
#: mode's fragment under the int64/MINIMALDATA evaluator with a ``targetTime`` too wide to read
#: as a number (``tests/test_dmint_deploy_bounds.py``), and checked against this constant there.
DAA_MODES_READING_TARGET_TIME = frozenset({DaaMode.ASERT, DaaMode.LWMA, DaaMode.EPOCH})


# ---------------------------------------------------------------------------
# Deploy-parameter arithmetic and bounds (shared by DmintDeployParams and
# pyrxd.glyph.builder.DmintV2DeployParams)
# ---------------------------------------------------------------------------


def target_for_difficulty(difficulty: int) -> int:
    """The PoW target a dMint contract is deployed with at ``difficulty``: ``MAX_SHA256D_TARGET // difficulty``.

    The same formula for EVERY hash algorithm. Part B1 (``_PART_B1``, identical in V1 and V2
    code) reverses the PoW hash, drops all but 12 bytes, requires 4 of them to be zero and reads
    the other 8 as the number Part B2 compares with the target — whether the hash opcode before
    it is OP_HASH256, OP_BLAKE3 or OP_K12. It is the formula of canonical Photonic
    ``dMintDiffToTarget`` (``MAX_TARGET / BigInt(difficulty)``, ``packages/lib/src/script.ts`` at
    becf41a7), which takes no algorithm argument, and the BLAKE3/K12 V2 contracts on mainnet
    carry exactly these targets (e.g. a declared ``diff`` of 2 → ``0x3fffffffffffffff``).
    """
    if difficulty < 1:
        raise ValidationError("difficulty must be >= 1")
    return MAX_SHA256D_TARGET // difficulty


def _refuse_above(stage: str, name: str, value: int, cap: int, why: str) -> None:
    if value > cap:
        raise ValidationError(f"{stage}: {name} must be <= {cap:,} ({why}), got {value:,}")


def check_dmint_core_bounds(
    *,
    stage: str,
    max_height: int,
    reward: int,
    difficulty: int,
    names: Mapping[str, str] | None = None,
) -> None:
    """Refuse a ``max_height``, ``reward`` or ``difficulty`` no dMint contract, V1 or V2, can use.

    Called from :func:`check_v2_numeric_bounds` (so from every V2 deploy path) and from
    :func:`check_dmint_v1_bounds` (every V1 deploy path), so the two versions refuse the same
    values with the same words. ``names`` maps a parameter to the name the
    caller knows it by (``reward`` -> ``reward_photons`` or ``--reward``). Each bound is what the
    covenant reads, and the V1 epilogue reads these the same way V2's Part C does:

    * ``max_height`` <= ``MAX_SCRIPT_NUM`` — the covenant adds 1 to the height and compares it
      with maxHeight as script numbers on every mint (``OP_1ADD`` … ``OP_NUMEQUAL``; V1:
      ``54 7a 81 8b 76 53 7a 9c``).
    * ``reward`` <= ``RADIANT_MAX_PHOTONS`` — each mint's reward outputs must together hold
      exactly ``reward`` photons (``OP_CODESCRIPTHASHVALUESUM_OUTPUTS … OP_NUMEQUALVERIFY``; V1:
      ``76 e4 7b 9d``), and Radiant consensus refuses a transaction whose outputs total more than
      ``MAX_MONEY`` (``bad-txns-txouttotal-toolarge``), so a larger reward could never be paid.
    * ``difficulty`` <= ``MAX_SHA256D_TARGET`` — above it the target is 0, which only a hash
      whose compared 8 bytes are all zero can meet.

    Before 2026-09-23 V1 held ``max_height`` and ``reward`` to ``0xFFFFFF``, called "V1's
    3-byte ceiling". No covenant rule was behind it: the first V1 contracts pyrxd decoded carry
    both as 3-byte pushes (``docs/dmint-research-mainnet.md`` §2.3,
    ``docs/dmint-research-photonic-deploy.md``), and that width became a limit. It refused
    deploys Photonic builds — mainnet V1 contracts include a max height of 300,000,000 and a
    reward of 888,888,888, which ``tests/test_dmint_v1_target_push.py`` rebuilds byte for byte.
    V1 has one tighter limit of its own, on ``max_height``: see :func:`check_dmint_v1_bounds`.
    """
    from pyrxd.security.types import RADIANT_MAX_PHOTONS

    called = dict(names or {})
    _refuse_above(
        stage,
        called.get("max_height", "max_height"),
        max_height,
        MAX_SCRIPT_NUM,
        "the covenant compares height+1 with maxHeight as an 8-byte script number on every mint",
    )
    _refuse_above(
        stage,
        called.get("reward", "reward"),
        reward,
        RADIANT_MAX_PHOTONS,
        "Radiant's money supply: a mint's outputs must hold the whole reward, and no transaction's outputs may total more",
    )
    _refuse_above(
        stage,
        called.get("difficulty", "difficulty"),
        difficulty,
        MAX_SHA256D_TARGET,
        "above it the target MAX_SHA256D_TARGET // difficulty is 0, which only a hash whose compared 8 bytes "
        "are all zero can meet",
    )


def check_dmint_v1_bounds(
    *,
    stage: str,
    max_height: int,
    reward: int,
    difficulty: int,
    names: Mapping[str, str] | None = None,
) -> None:
    """Refuse V1 deploy parameters that no V1 contract built from them could mint to the end.

    :func:`check_dmint_core_bounds` (the bounds V1 shares with V2), then ``max_height`` <=
    :data:`MAX_V1_MAX_HEIGHT` (``2**31``), past which a V1 contract stops at height
    ``2**31 - 1`` with mints left (that constant has the reason). Called from
    ``DmintV1DeployParams.__post_init__`` (every V1 deploy is built from one) and from
    ``deploy-dmint`` for V1, first, so a refusal names the flag the user typed.

    This bounds DEPLOYS. Mainnet has V1 contracts with a larger ``max_height`` (``$BRO``:
    696,969,000,000); pyrxd parses and mints them like any other up to height ``2**31 - 1``,
    and refuses the mint from there (``miner._unmintable_reason``).
    """
    check_dmint_core_bounds(stage=stage, max_height=max_height, reward=reward, difficulty=difficulty, names=names)
    _refuse_above(
        stage,
        dict(names or {}).get("max_height", "max_height"),
        max_height,
        MAX_V1_MAX_HEIGHT,
        "a V1 contract's height is a 4-byte field that every mint but the last rewrites with "
        "NUM2BIN(height + 1, 4), which cannot encode 2**31, so with a larger max_height the contract "
        "stops at height 2**31 - 1 and its remaining mints can never happen",
    )


def check_v2_numeric_bounds(
    *,
    stage: str,
    max_height: int,
    reward: int,
    difficulty: int,
    daa_mode: DaaMode,
    target_time: int,
    half_life: int,
    epoch_length: int,
    schedule: tuple[tuple[int, int], ...],
    names: Mapping[str, str] | None = None,
) -> None:
    """Refuse V2 deploy parameters no contract built from them could ever be minted with.

    Upper bounds only; each type keeps its own lower-bound checks. The three V1 shares —
    ``max_height``, ``reward`` and ``difficulty`` — are :func:`check_dmint_core_bounds`, which
    this calls first. Called from
    ``DmintDeployParams.__post_init__`` (which both V2 deploy scripts — the fee placeholder and
    the real reveal — are built from), from ``DmintV2DeployParams.__post_init__`` (so the API
    refuses on the caller's own object) and from ``deploy-dmint --v2`` (so the CLI refuses
    before any wallet or network work, naming the flag the user typed). ``names`` maps a
    parameter (``max_height``, ``reward``, ``difficulty``, ``target_time``, ``half_life``,
    ``epoch_length``, ``schedule``) to the name the caller knows it by; unmapped ones keep their
    own name. ``_push_minimal`` separately refuses to emit any number wider than
    ``MAX_SCRIPT_NUM_BYTES``, whichever builder asks.

    Each bound comes from what the covenant can read or observe, not from a guess at what is
    sensible; every value on the mainnet V2 deploys surveyed is far inside all of them
    (``tests/test_dmint_deploy_bounds.py`` pins the observed values as accepted):

    * ``max_height``, ``reward``, ``difficulty`` — see :func:`check_dmint_core_bounds`.
    * ``target_time`` <= ``MAX_V2_TARGET_TIME`` in the modes that read it as a number
      (:data:`DAA_MODES_READING_TARGET_TIME`) — a wider spacing than any mint can observe; see
      that constant. FIXED and SCHEDULE only carry ``targetTime`` as bytes, so there it is held
      only to ``MAX_SCRIPT_NUM``: the one bound here that is pyrxd's encoder's (it writes every
      state number in at most 8 bytes), not the covenant's.
    * ``half_life`` <= ``MAX_SCRIPT_NUM`` (ASERT, where it is baked in) — only ever a divisor
      (``OP_DIV``), so any readable number works; nothing narrower is imposed.
    * ``epoch_length`` <= ``MAX_SCRIPT_NUM`` (EPOCH) — only ever a divisor (``OP_MOD``).
    * each SCHEDULE height <= ``MAX_SCRIPT_NUM`` — compared with the height
      (``OP_GREATERTHANOREQUAL``).
    """
    check_dmint_core_bounds(stage=stage, max_height=max_height, reward=reward, difficulty=difficulty, names=names)
    called = dict(names or {})

    def _cap(field: str, value: int, cap: int, why: str, *, label: str | None = None) -> None:
        _refuse_above(stage, label if label is not None else called.get(field, field), value, cap, why)

    if daa_mode in DAA_MODES_READING_TARGET_TIME:
        _cap(
            "target_time",
            target_time,
            MAX_V2_TARGET_TIME,
            f"no {daa_mode.name} mint can meet a larger spacing: both timestamps its retarget compares are below "
            "2**31; the cap also keeps the retarget's arithmetic inside int64",
        )
    else:
        _cap(
            "target_time",
            target_time,
            MAX_SCRIPT_NUM,
            f"pyrxd writes every dMint state number in at most 8 bytes; {daa_mode.name} never reads targetTime "
            "as a number, so this is pyrxd's limit, not the covenant's",
        )
    if daa_mode == DaaMode.ASERT:
        _cap("half_life", half_life, MAX_SCRIPT_NUM, "it is baked into the ASERT retarget as an 8-byte script number")
    if daa_mode == DaaMode.EPOCH:
        _cap(
            "epoch_length",
            epoch_length,
            MAX_SCRIPT_NUM,
            "it is baked into the EPOCH retarget as an 8-byte script number",
        )
    if daa_mode == DaaMode.SCHEDULE:
        for i, (h, _t) in enumerate(schedule):
            _cap(
                "schedule",
                h,
                MAX_SCRIPT_NUM,
                "it is baked into the SCHEDULE retarget as an 8-byte script number",
                label=f"{called.get('schedule', 'schedule')} entry {i} height",
            )


# ---------------------------------------------------------------------------
# Dataclasses
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
    half_life: int = DEFAULT_ASERT_HALFLIFE  # ASERT half-life in seconds (canonical default, script.ts)
    height: int = 0  # current mint height (0 at deploy)
    # Unix timestamp of the last mint. NOT validated for script-number minimality here,
    # deliberately: this type is the argument to the byte-level mirror of Photonic's
    # `dMintScript`, which accepts any lastTime, and pyrxd has to stay able to reproduce
    # the exact bytes of a contract that already exists on chain (including one another
    # implementation deployed with lastTime=0) for inspection and conformance. Refusing
    # here would break that and the byte-parity goldens with it. The refusal lives on the
    # deploy paths instead — pyrxd.glyph.builder.require_mineable_last_time, which every
    # shipped caller of build_dmint_contract_script crosses (the set of callers is derived
    # from the source by tests/test_reachability_shipped_callers.py, not listed here) — and
    # uses is_readable_last_time + DAA_MODES_READING_DEPLOY_LAST_TIME from this module.
    last_time: int = 0
    epoch_length: int = 2016  # EPOCH: retarget every N blocks
    max_adjustment_log2: int = 2  # EPOCH: max adjustment 2^N per epoch (1..4 → 2×..16×)
    schedule: tuple[tuple[int, int], ...] = ()  # SCHEDULE: ascending (height, target) entries

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
        if not 0 <= self.last_time <= 0xFFFFFFFF:
            # The state carries lastTime as a fixed 4-byte push; nothing outside this range
            # can be encoded, in any mode. (Whether a value in range is one a retarget can READ
            # is a separate, deploy-path question: see require_mineable_last_time.)
            raise ValidationError(
                f"last_time must fit the state's 4-byte lastTime push (0..0xFFFFFFFF), got {self.last_time}"
            )
        check_v2_numeric_bounds(
            stage="DmintDeployParams",
            max_height=self.max_height,
            reward=self.reward,
            difficulty=self.difficulty,
            daa_mode=self.daa_mode,
            target_time=self.target_time,
            half_life=self.half_life,
            epoch_length=self.epoch_length,
            schedule=self.schedule,
        )
        if self.daa_mode == DaaMode.EPOCH:
            if self.epoch_length < 1:
                raise ValidationError("epoch_length must be >= 1 for EPOCH")
            if self.max_adjustment_log2 not in EPOCH_MAX_ADJUSTMENT_LOG2_VALUES:
                raise ValidationError(
                    f"max_adjustment_log2 must be one of {EPOCH_MAX_ADJUSTMENT_LOG2_VALUES} for EPOCH "
                    f"(got {self.max_adjustment_log2})"
                )
            if self.target_time < 1 << self.max_adjustment_log2:
                raise ValidationError(
                    f"EPOCH target_time ({self.target_time}) must be >= 2**max_adjustment_log2 "
                    f"({1 << self.max_adjustment_log2}): below that the retarget's lower clamp, "
                    "target_time >> max_adjustment_log2, is 0 and can set the target to 1"
                )
            # target × clampedDelta must not overflow int64 → cap target at 2^48.
            if self.initial_target > EPOCH_MAX_SAFE_TARGET:
                raise ValidationError(
                    f"EPOCH requires initial target <= 2^48 (use difficulty >= "
                    f"{MAX_SHA256D_TARGET // EPOCH_MAX_SAFE_TARGET + 1}); got target {self.initial_target} "
                    "— larger targets risk OP_MUL overflow in the on-chain retarget"
                )
        if self.daa_mode == DaaMode.SCHEDULE:
            if not self.schedule:
                raise ValidationError("SCHEDULE requires a non-empty schedule (use FIXED for no schedule)")
            if len(self.schedule) > SCHEDULE_MAX_ENTRIES:
                raise ValidationError(
                    f"SCHEDULE allows at most {SCHEDULE_MAX_ENTRIES} entries, got {len(self.schedule)}"
                )
            prev_h = -1
            for i, (h, t) in enumerate(self.schedule):
                if h < 0:
                    raise ValidationError(f"SCHEDULE entry {i}: height must be >= 0, got {h}")
                if h <= prev_h:
                    raise ValidationError(f"SCHEDULE entries must be strictly ascending by height (entry {i})")
                if not 1 <= t <= MAX_SHA256D_TARGET:
                    raise ValidationError(f"SCHEDULE entry {i}: target must be in [1, MAX_SHA256D_TARGET], got {t}")
                prev_h = h

    @property
    def initial_target(self) -> int:
        """The deploy target for ``difficulty`` — :func:`target_for_difficulty`, for every ``algo``.

        BLAKE3 and K12 used to get ``MAX_V2_TARGET_256 // difficulty`` here: a target wider than
        the 8 bytes Part B2 can read, so the contract could never be minted. ``algo`` selects the
        hash opcode (and the algoId the state records); it does not change the target formula.
        """
        return target_for_difficulty(self.difficulty)


@dataclass(frozen=True)
class DmintCborPayload:
    """The ``dmint`` object embedded in Glyph V2 token metadata CBOR.

    Indexers read this to discover dMint contracts and display mining
    parameters in wallets/explorers without parsing the contract script.

    Field names mirror Photonic Wallet's ``DmintPayload`` type
    (``packages/lib/src/types.ts`` at ``becf41a``)::

        daa?: { mode, targetBlockTime,
                halfLife?, asymptote?,        // ASERT
                windowSize?,                  // LWMA
                epochLength?, maxAdjustment?, // EPOCH
                schedule?: { height, difficulty }[] }  // SCHEDULE

    Every optional key is emitted ONLY when set (non-zero / non-empty), so a
    payload that does not use one is byte-identical to what pyrxd emitted before
    the key existed (2026-09-16: ``asymptote``, ``epochLength``, ``maxAdjustment``,
    ``schedule`` were added; FIXED/ASERT/LWMA payloads that do not set them are
    unchanged). ``schedule`` entries are ``(height, difficulty)`` — difficulty, not
    target, is what the payload type declares.

    ``max_adjustment`` is stored as the RAW payload number and is informational only:
    Photonic's builder reads a payload value of 1..4 as the log2 shift count and 8/16
    as multipliers (``script.ts`` ``maxAdjustmentToLog2``; its Mint UI passes the same
    number to the payload and the builder), while pyrxd's ``deploy-dmint
    --max-adjustment`` is a multiplier baked as ``DmintDeployParams.max_adjustment_log2``.
    So the payload value alone does not say which clamp a contract bakes — only the
    contract bytecode does. Validation accepts exactly the values Photonic's builder
    accepts (``EPOCH_MAX_ADJUSTMENT_PAYLOAD_VALUES``); pyrxd does not reinterpret them.
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
    asymptote: int = 0  # ASERT asymptote (0 = N/A; declared by Photonic, not read by any bytecode)
    epoch_length: int = 0  # EPOCH retarget interval in mints (0 = N/A)
    max_adjustment: int = 0  # EPOCH maxAdjustment as the payload carries it (0 = N/A; see class docstring)
    schedule: tuple[tuple[int, int], ...] = ()  # SCHEDULE: (height, difficulty) entries

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
        if self.asymptote < 0:
            raise ValidationError("asymptote must be >= 0")
        if self.epoch_length < 0:
            raise ValidationError("epoch_length must be >= 0")
        if self.max_adjustment < 0:
            raise ValidationError("max_adjustment must be >= 0")
        if self.max_adjustment and self.max_adjustment not in EPOCH_MAX_ADJUSTMENT_PAYLOAD_VALUES:
            raise ValidationError(
                f"max_adjustment must be one of {EPOCH_MAX_ADJUSTMENT_PAYLOAD_VALUES} (the values Photonic's "
                f"maxAdjustmentToLog2 accepts: log2 counts 1..4 or multipliers 8/16), got {self.max_adjustment}"
            )
        for i, (height, difficulty) in enumerate(self.schedule):
            if height < 0:
                raise ValidationError(f"schedule entry {i}: height must be >= 0, got {height}")
            if difficulty < 1:
                raise ValidationError(f"schedule entry {i}: difficulty must be >= 1, got {difficulty}")

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
            if self.asymptote:
                daa["asymptote"] = self.asymptote
            if self.window_size:
                daa["windowSize"] = self.window_size
            if self.epoch_length:
                daa["epochLength"] = self.epoch_length
            if self.max_adjustment:
                daa["maxAdjustment"] = self.max_adjustment
            if self.schedule:
                daa["schedule"] = [{"height": h, "difficulty": diff} for h, diff in self.schedule]
            d["daa"] = daa
        return d

    @classmethod
    def from_cbor_dict(cls, d: dict) -> DmintCborPayload:
        """Parse the ``dmint`` CBOR value from an on-chain payload."""
        try:
            algo = DmintAlgo(cbor_int(d["algo"]))
        except (KeyError, ValueError) as e:
            raise ValidationError("dmint.algo missing or invalid") from e
        try:
            daa_mode = DaaMode.FIXED
            target_block_time = 60
            half_life = 0
            window_size = 0
            asymptote = 0
            epoch_length = 0
            max_adjustment = 0
            schedule: tuple[tuple[int, int], ...] = ()
            if "daa" in d:
                daa = d["daa"]
                daa_mode = DaaMode(cbor_int(daa.get("mode", 0)))
                target_block_time = cbor_int(daa.get("targetBlockTime", 60))
                half_life = cbor_int(daa.get("halfLife", 0))
                window_size = cbor_int(daa.get("windowSize", 0))
                asymptote = cbor_int(daa.get("asymptote", 0))
                epoch_length = cbor_int(daa.get("epochLength", 0))
                max_adjustment = cbor_int(daa.get("maxAdjustment", 0))
                schedule = _schedule_from_cbor(daa.get("schedule"))
            return cls(
                algo=algo,
                num_contracts=cbor_int(d.get("numContracts", 1)),
                max_height=cbor_int(d["maxHeight"]),
                reward=cbor_int(d["reward"]),
                premine=cbor_int(d.get("premine", 0)),
                diff=cbor_int(d["diff"]),
                daa_mode=daa_mode,
                target_block_time=target_block_time,
                half_life=half_life,
                window_size=window_size,
                asymptote=asymptote,
                epoch_length=epoch_length,
                max_adjustment=max_adjustment,
                schedule=schedule,
            )
        except KeyError as e:
            raise ValidationError(f"dmint CBOR missing required field: {e}") from e
        except (ValueError, AttributeError) as e:
            # `cbor_int` refusing a field, or `daa` not being a map. Raised as the decoder's own
            # refusal rather than escaping as a bare ValueError, like the missing-field case.
            raise ValidationError(f"dmint CBOR field is not usable: {e}") from e


def _schedule_from_cbor(raw: object) -> tuple[tuple[int, int], ...]:
    """Decode a Photonic ``schedule: { height, difficulty }[]`` payload array.

    Absent / ``None`` → empty. Anything else must be a list of objects each carrying
    a numeric ``height`` and ``difficulty`` — the shape ``DmintPayload`` declares. An
    entry carrying only a ``target`` (which Photonic's *script builder* also accepts
    from its wallet UI) is refused by name rather than silently dropped or coerced:
    a target is not a difficulty, and the payload type does not declare it.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"dmint.daa.schedule must be a list, got {type(raw).__name__}")
    entries: list[tuple[int, int]] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValidationError(f"dmint.daa.schedule[{i}] must be an object, got {type(entry).__name__}")
        if "height" not in entry or "difficulty" not in entry:
            raise ValidationError(
                f"dmint.daa.schedule[{i}] needs numeric 'height' and 'difficulty' (got keys {sorted(entry)})"
            )
        entries.append((cbor_int(entry["height"]), cbor_int(entry["difficulty"])))
    return tuple(entries)


@dataclass
class DmintMintResult:
    """Output of :func:`build_dmint_mint_tx`.

    :param tx:                 Unsigned transaction (caller must sign).
    :param updated_state:      New :class:`DmintState` written into the
                               contract output (height incremented, target
                               updated if DAA is active). On the final mint no
                               output carries a state: this is the spent state
                               with only ``height`` advanced to ``max_height``
                               (so ``is_exhausted`` is True).
    :param contract_script:    The script of output 0: the recreated contract
                               (state + separator + code), or on the final mint
                               the burn ``d8 <contractRef> 6a`` that replaces it.
    :param reward_script:      The FT-wrapped reward output script (P2PKH, then
                               ``bd d0 <tokenRef>`` and the 12-byte FT code), paid to
                               the miner.
    :param fee:                Transaction fee in photons.
    :param is_final_mint:      True when this mint takes the contract to
                               ``max_height``: output 0 is the burn, not a
                               recreated contract, and no further mint of this
                               contract is possible.

    .. note::
       The transaction returned here is **unsigned** — it uses raw script bytes
       for the contract input's unlocking script (nonce + preimage halves) built
       by :func:`build_mint_scriptsig`.  The contract script is a covenant, not
       a P2PKH, so standard :class:`Transaction.sign()` is not appropriate.
       The caller must either set the unlocking script directly or use a custom
       signing path.  See docstring of :func:`build_dmint_mint_tx` for details.
    """

    tx: Any
    updated_state: Any  # DmintState — forward reference; resolved at runtime
    contract_script: bytes
    reward_script: bytes
    fee: int
    is_final_mint: bool = False


@dataclass(frozen=True)
class DmintV1ContractInitialState:
    """Just-deployed state of a V1 dMint contract template.

    Carries exactly the parameters needed to reconstruct the initial
    (height=0) contract codescript for *every* contract of a given
    deploy. Used by :func:`find_dmint_contract_utxos`'s fast path,
    where the caller already knows the deploy params.

    :param num_contracts: Count of parallel contracts the deploy created
        (1..255 for V1; mainnet GLYPH used 32).
    :param reward_sats: Photons emitted per successful mint.
    :param max_height: Maximum mints per contract.
    :param target: The PoW target (``MAX_SHA256D_TARGET // difficulty``). The codescript is
        rebuilt with today's builder, which pushes it minimally; a contract pyrxd deployed
        before 2026-09-23 at difficulty 256 or more carries a non-minimal 8-byte push instead,
        so this fast path does not find it (it can never be minted anyway).
    :param algo: PoW algorithm. Defaults to ``DmintAlgo.SHA256D``,
        which is the only algorithm seen on V1 mainnet.
    """

    num_contracts: int
    reward_sats: int
    max_height: int
    target: int
    algo: DmintAlgo = DmintAlgo.SHA256D

"""Type definitions for the dMint subpackage.

Pure data types consumed by ≥2 sibling submodules, plus the
``V2UnvalidatedWarning`` warning class and shared module-level byte
constants. Depends on nothing within the subpackage; siblings import
from here, not the reverse.

Symbols (27 — every module-level name, so the count is checkable rather than
decorative; it read "20" while listing 17 before 2026-09-22):
    V2UnvalidatedWarning,
    MAX_SHA256D_TARGET, MAX_V2_TARGET_256,
    EPOCH_MAX_ADJUSTMENT_LOG2_VALUES, EPOCH_MAX_ADJUSTMENT_PAYLOAD_VALUES,
    EPOCH_MAX_SAFE_TARGET, SCHEDULE_MAX_ENTRIES,
    ASERT_V2_RADIX, ASERT_V2_DRIFT_CLAMP, ASERT_V2_MAX_TARGET_DIV4,
    DEFAULT_ASERT_HALFLIFE,
    DmintAlgo, DaaMode, DaaBytecodeVersion,
    _OP_STATESEPARATOR, _PART_B1, _PART_B2, _PART_B4,
    is_minimal_4byte_scriptnum, is_readable_last_time,
    DAA_MODES_READING_DEPLOY_LAST_TIME, DAA_MODES_READING_LAST_TIME,
    DmintDeployParams, DmintCborPayload, _schedule_from_cbor, DmintMintResult,
    DmintV1ContractInitialState
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

from pyrxd.security.errors import ValidationError
from pyrxd.security.json_guards import cbor_int

from ..types import GlyphRef  # ..types resolves to pyrxd.glyph.types

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

# Maximum SHA256d target (64-bit; first 4 bytes implicitly zero).
# Valid: hash[0..4] == 0 AND hash[4..12] < MAX_SHA256D_TARGET.
MAX_SHA256D_TARGET = 0x7FFFFFFFFFFFFFFF

# Maximum V2 256-bit target for blake3 / k12.
MAX_V2_TARGET_256 = (1 << 256) - 1

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
        """Compute initial target from difficulty using the SHA256d formula."""
        if self.algo == DmintAlgo.SHA256D:
            return MAX_SHA256D_TARGET // self.difficulty
        return MAX_V2_TARGET_256 // self.difficulty


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

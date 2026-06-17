"""Mining + mint-tx assembly for the dMint subpackage.

Mining loop (in-process + external + dispatch), PoW preimage
construction, difficulty/target math, scriptSig assembly, and the
complete ``build_dmint_mint_tx`` pipeline. Carries the miner-domain
result dataclasses (``PowPreimageResult``, ``DmintMineResult``) and
timeout constants (``DEFAULT_MAX_ATTEMPTS``, ``EXTERNAL_MINER_TIMEOUT_S``).
Depends on ``.types``, ``.builders``, ``.chain``.

Symbols (19):
    PowPreimageResult, build_pow_preimage,
    build_mint_scriptsig,
    compute_next_target_asert, compute_next_target_linear,
    difficulty_to_target, target_to_difficulty,
    verify_sha256d_solution,
    DEFAULT_MAX_ATTEMPTS, EXTERNAL_MINER_TIMEOUT_S,
    DmintMineResult, mine_solution, mine_solution_external,
    mine_solution_dispatch,
    build_dmint_mint_tx, _build_dmint_v1_mint_tx,
    _varint_size,
    build_dmint_v1_mint_preimage, build_dmint_v2_mint_preimage
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from typing import Any, Literal

from pyrxd.security.errors import (
    ContractExhaustedError,
    InvalidFundingUtxoError,
    MaxAttemptsError,
    PoolTooSmallError,
    ValidationError,
)

from .builders import (
    _push_4bytes_le,
    _push_minimal,
    build_dmint_v1_contract_script,
    build_dmint_v1_ft_output_script,
)
from .chain import (
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    is_token_bearing_script,
)
from .types import (
    _OP_STATESEPARATOR,
    MAX_SHA256D_TARGET,
    MAX_V2_TARGET_256,
    DaaMode,
    DmintAlgo,
    DmintMintResult,
)

# ---------------------------------------------------------------------------
# PoW preimage (same structure as V1 — §2.5 / Appendix B)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PowPreimageResult:
    """The 64-byte PoW preimage plus the two script hashes a miner must push.

    The covenant binds the PoW hash AND the scriptSig pushes together: it
    recomputes ``H2 = SHA256(scriptSig_inputHash || scriptSig_outputHash)``
    and folds that into the same hash the miner solved. Diverging the
    preimage from the scriptSig pushes is a silent on-chain rejection —
    see ``docs/solutions/runtime-errors/dmint-v1-mint-scriptsig-shape.md``
    for the prior incident that motivated returning all three values from
    a single helper.

    :param preimage:    64-byte SHA256d PoW preimage; feeds ``mine_solution``.
    :param input_hash:  ``SHA256d(input_script)`` — push as ``scriptSig_inputHash``.
    :param output_hash: ``SHA256d(output_script)`` — push as ``scriptSig_outputHash``.
    """

    preimage: bytes
    input_hash: bytes
    output_hash: bytes


def build_pow_preimage(
    txid_le: bytes,
    contract_ref_bytes: bytes,
    input_script: bytes,
    output_script: bytes,
) -> PowPreimageResult:
    """Build the PoW preimage AND the two script hashes the scriptSig must push.

    preimage[0..32] = SHA256(txid_LE || contractRef)
    preimage[32..64] = SHA256(SHA256d(inputScript) || SHA256d(outputScript))

    The covenant pulls ``inputHash`` and ``outputHash`` from the scriptSig
    pushes (not from the preimage halves) and recomputes the second SHA256
    on-chain. Returning all three values here forces callers to feed both
    sites from the same source — splitting the helper into "preimage
    builder" and "scriptSig builder" with independently-recomputed hashes
    is what produced the M1 covenant-rejection bug.

    :param txid_le:            32-byte txid in little-endian (internal byte order)
    :param contract_ref_bytes: 36-byte contract ref (wire format)
    :param input_script:       miner's input locking script (e.g. P2PKH)
    :param output_script:      miner's output script (e.g. OP_RETURN message)
    :returns: :class:`PowPreimageResult` with ``preimage``, ``input_hash``,
              ``output_hash``.
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
    return PowPreimageResult(preimage=half1 + half2, input_hash=input_csh, output_hash=output_csh)


# ---------------------------------------------------------------------------
# Mint scriptSig builder
# ---------------------------------------------------------------------------


def build_mint_scriptsig(
    nonce: bytes,
    input_hash: bytes,
    output_hash: bytes,
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

    The hashes pushed here MUST equal :class:`PowPreimageResult.input_hash`
    and ``output_hash`` from the same :func:`build_pow_preimage` call that
    produced the preimage the miner solved. The on-chain covenant
    recomputes ``SHA256(input_hash || output_hash)`` from these pushes and
    folds that into the PoW hash — diverging them silently produces a
    ``mandatory-script-verify-flag-failed`` rejection after a successful
    mine.

    :param nonce:        nonce_width-bytes nonce (found during mining).
    :param input_hash:   32-byte ``SHA256d(input_script)`` from :class:`PowPreimageResult`.
    :param output_hash:  32-byte ``SHA256d(output_script)`` from :class:`PowPreimageResult`.
    :param nonce_width:  4 for V1 contracts, 8 for V2. Keyword-only and
                         ``Literal[4, 8]`` so a stray positional value is a
                         type error rather than a silent V1/V2 confusion.
                         Default 8 preserves pre-V1-support behavior.
    """
    if nonce_width not in (4, 8):
        raise ValidationError(f"nonce_width must be 4 or 8, got {nonce_width}")
    if len(nonce) != nonce_width:
        raise ValidationError(f"nonce must be {nonce_width} bytes, got {len(nonce)}")
    if len(input_hash) != 32:
        raise ValidationError(f"input_hash must be 32 bytes, got {len(input_hash)}")
    if len(output_hash) != 32:
        raise ValidationError(f"output_hash must be 32 bytes, got {len(output_hash)}")
    # Push opcode = nonce length (works for both 4 and 8 since both are < 0x4C).
    return (
        bytes([nonce_width])
        + nonce  # PUSH nonce_width + nonce
        + b"\x20"
        + input_hash  # PUSH 32 + inputHash
        + b"\x20"
        + output_hash  # PUSH 32 + outputHash
        + b"\x00"  # OP_0
    )


# ---------------------------------------------------------------------------
# DAA target computation (off-chain mirror of on-chain formula)
# ---------------------------------------------------------------------------


def _trunc_div(a: int, b: int) -> int:
    """Integer division truncating toward zero (matches Radiant OP_DIV / C++ int64).

    Python's ``//`` floors toward −∞; OP_DIV on CScriptNum truncates toward 0.
    They differ when the numerator is negative (e.g. a block arrives early, so
    ``excess < 0``). The on-chain ASERT divides by ``OP_DIV``, so the off-chain
    mirror must truncate too, or the recreated state's target diverges and the
    mint is rejected.
    """
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def compute_next_target_asert(
    current_target: int,
    last_time: int,
    current_time: int,
    target_time: int,
    half_life: int,
) -> int:
    """Compute next ASERT-lite target (mirrors the redesigned on-chain bytecode).

    The redesign replaced OP_LSHIFT/OP_RSHIFT (which Radiant evaluates as a
    big-endian bit-string shift — wrong on the LE target encoding) with an
    unrolled 4-step OP_2MUL/OP_2DIV loop with a per-step overflow cap::

        drift = trunc((current_time - last_time - target_time) / half_life)  # clamp [-4,+4]
        drift > 0:  repeat |drift|x:  target = MAX_TARGET if target > MAX/2 else target*2
        drift < 0:  repeat |drift|x:  target = target // 2
        minimum target is 1

    The per-step cap matches the miner's ``newTarget = min(MAX, oldTarget<<drift)``
    clamp-at-MAX semantics (a naive ``target << drift`` would overshoot MAX).

    .. note::
       V2-only DAA. V1 has no DAA (fixed difficulty).
    """
    excess = (current_time - last_time) - target_time
    drift = _trunc_div(excess, half_life)
    drift = max(-4, min(4, drift))

    new_target = current_target
    if drift > 0:
        for _ in range(drift):
            new_target = MAX_SHA256D_TARGET if new_target > MAX_SHA256D_TARGET // 2 else new_target * 2
    elif drift < 0:
        for _ in range(-drift):
            new_target //= 2

    return max(1, new_target)


def compute_next_target_linear(
    current_target: int,
    last_time: int,
    current_time: int,
    target_time: int,
) -> int:
    """Compute next linear/LWMA target (mirrors the redesigned on-chain bytecode).

    Divide-first with caps so the on-chain OP_MUL never overflows int64::

        timeDelta_capped = min(current_time - last_time, 4 * target_time)
        target_capped    = min(current_target, MAX_TARGET // 4)
        new_target       = min(MAX_TARGET, (target_capped // target_time) * timeDelta_capped)
        minimum target is 1

    The MAX/4 target cap means LWMA contracts cannot have a difficulty floor
    below 4 (``target <= MAX_TARGET/4``).

    .. note::
       V2-only DAA.
    """
    time_delta_capped = min(current_time - last_time, 4 * target_time)
    target_capped = min(current_target, MAX_SHA256D_TARGET // 4)
    new_target = (target_capped // target_time) * time_delta_capped
    new_target = min(new_target, MAX_SHA256D_TARGET)
    return max(1, new_target)


def compute_next_target_epoch(
    current_target: int,
    last_time: int,
    current_time: int,
    target_time: int,
    height: int,
    epoch_length: int,
    max_adjustment_log2: int,
) -> int:
    """Compute next EPOCH target (mirrors the on-chain ``buildEpochDaaBytecode``).

    Periodic retarget — only at epoch boundaries. ``height`` is the CURRENT (spent)
    contract's height (the covenant gates on the state's own height, OP_9 PICK)::

        if height > 0 and height % epoch_length == 0:
            delta        = current_time - last_time
            clampedDelta = max(target_time >> N, min(target_time << N, delta))
            new          = min(MAX, max(1, target * clampedDelta // target_time))
        else: target unchanged

    N = max_adjustment_log2 (1..4). The clamp keeps ``clampedDelta`` ≥ target_time>>N > 0,
    so the division has positive operands (floor == OP_DIV's truncate-toward-zero).

    .. note:: V2-only DAA.
    """
    if height > 0 and height % epoch_length == 0:
        delta = current_time - last_time
        upper = target_time << max_adjustment_log2  # targetTime × 2^N
        lower = target_time >> max_adjustment_log2  # targetTime ÷ 2^N
        clamped = max(lower, min(upper, delta))
        new_target = (current_target * clamped) // target_time
        return max(1, min(new_target, MAX_SHA256D_TARGET))
    return current_target


def compute_next_target_schedule(
    current_target: int,
    height: int,
    schedule: tuple[tuple[int, int], ...],
) -> int:
    """Compute next SCHEDULE target (mirrors the on-chain ``buildScheduleDaaBytecode``).

    The target of the highest boundary ``height`` reached; unchanged if ``height`` is
    below the lowest boundary. ``height`` is the CURRENT (spent) contract's height.
    ``schedule`` is ascending ``(height, target)`` pairs.

    .. note:: V2-only DAA.
    """
    new_target = current_target
    for boundary_height, boundary_target in schedule:  # ascending → highest match wins
        if height >= boundary_height:
            new_target = boundary_target
    return new_target


def _v2_state_script_bytes(st: DmintState) -> bytes:
    """Build the 10-item V2 state script (before 0xbd) from a parsed DmintState.

    Mirrors ``builders.build_dmint_state_script`` but reads ``target``/``last_time``
    directly off the state rather than deriving from difficulty. Used by the mint
    builder to (a) locate the spent contract's state/code boundary and (b) emit
    the recreated next-state prefix. Redesign encoding: height + target are
    minimal pushes; lastTime is a 4-byte push.
    """
    return (
        _push_minimal(st.height)
        + b"\xd8"
        + st.contract_ref.to_bytes()
        + b"\xd0"
        + st.token_ref.to_bytes()
        + _push_minimal(st.max_height)
        + _push_minimal(st.reward)
        + _push_minimal(int(st.algo))
        + _push_minimal(int(st.daa_mode))
        + _push_minimal(st.target_time)
        + _push_4bytes_le(st.last_time)
        + _push_minimal(st.target)
    )


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

    1. Read one JSON object from stdin: ``{"preimage_hex", "target_hex", "nonce_width"}``.
    2. Search for a valid nonce.
    3. Write one JSON object to stdout — on a hit (exit 0):
       ``{"nonce_hex", "attempts", "elapsed_s"}``; on nonce-space exhaustion
       (exit 2, added in 0.5.1): ``{"exhausted": true}`` (pyrxd then raises
       :class:`MaxAttemptsError` immediately rather than waiting for the parent
       timeout to fire).

    A bundled reference implementation ships at :mod:`pyrxd.contrib.miner`
    (added in 0.5.1) — see :doc:`/concepts/parallel-mining` for the full
    protocol spec and operational notes. Invoke it via::

        miner_argv=[sys.executable, "-m", "pyrxd.contrib.miner"]

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

    # Decode stdout. A miner returning malformed UTF-8 is a malformed
    # response, not an exception that should escape.
    try:
        stdout = (completed.stdout or b"").decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"external miner {miner_argv[0]!r} returned non-UTF-8 stdout") from exc
    if len(stdout) > 4096:
        raise ValidationError(f"external miner produced {len(stdout)} bytes of stdout; expected one short JSON line")

    # Protocol-level exhaustion signal (added 0.5.1): a miner that
    # finishes its sweep without finding a hit may exit 2 with
    # ``{"exhausted": true}`` on stdout. Raise MaxAttemptsError
    # immediately so callers don't have to wait for the parent timeout.
    # Older miners that don't know this convention fall through to the
    # generic rc != 0 path below (or are SIGKILLed by the parent timeout).
    if completed.returncode == 2 and stdout.strip():
        try:
            maybe_exhausted = json.loads(stdout)
        except json.JSONDecodeError:
            maybe_exhausted = None
        if isinstance(maybe_exhausted, dict) and maybe_exhausted.get("exhausted") is True:
            elapsed = time.monotonic() - started
            raise MaxAttemptsError(
                f"external miner {miner_argv[0]!r} exhausted the nonce space without finding a solution",
                attempts=0,
                elapsed_s=elapsed,
            )

    if completed.returncode != 0:
        raise ValidationError(f"external miner {miner_argv[0]!r} exited with code {completed.returncode}")

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
# Dispatch helper — pick in-process vs external based on miner_argv
# ---------------------------------------------------------------------------


def mine_solution_dispatch(
    preimage: bytes,
    target: int,
    *,
    nonce_width: Literal[4, 8] = 4,
    algo: DmintAlgo = DmintAlgo.SHA256D,
    miner_argv: list[str] | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    timeout_s: float = EXTERNAL_MINER_TIMEOUT_S,
) -> DmintMineResult:
    """Mine a nonce — picks the in-process or subprocess miner from one entrypoint.

    Most callers want this helper rather than calling
    :func:`mine_solution` or :func:`mine_solution_external` directly.
    The two paths share semantics — both return a :class:`DmintMineResult`
    with a nonce that satisfies the target — but have disjoint parameter
    sets (``max_attempts`` vs ``timeout_s``, no-argv vs argv). Picking
    between them was a 30-line wrapper that every demo and operator
    script ended up rewriting; this function is that wrapper, with the
    branch in one place.

    Dispatch rule:

    * ``miner_argv is None`` (default): run :func:`mine_solution` in
      this process. Slow but correct. Use for tests, small examples,
      and contracts where mining takes < a minute.
    * ``miner_argv is not None``: invoke :func:`mine_solution_external`
      with the supplied argv. The external miner (e.g.
      ``pyrxd.contrib.miner``, a custom binary, or ``glyph-miner``)
      runs as a subprocess and returns a verified nonce via the
      JSON-over-stdio protocol. The local re-verification in
      ``mine_solution_external`` is the load-bearing safety check
      against a buggy or malicious miner.

    :param preimage:     64-byte preimage from :func:`build_pow_preimage`.
    :param target:       The PoW target.
    :param nonce_width:  4 for V1 contracts, 8 for V2.
    :param algo:         Hash algorithm. Currently only SHA256D is implemented;
                         BLAKE3 and K12 raise from :func:`mine_solution`.
                         Ignored on the external-miner path (the protocol
                         doesn't carry an algo field; external miners
                         are assumed SHA256D until the protocol is
                         extended).
    :param miner_argv:   ``None`` → in-process; otherwise an argv list
                         passed to :func:`subprocess.run` for the
                         external miner. Use
                         ``[sys.executable, "-m", "pyrxd.contrib.miner"]``
                         for the bundled parallel miner.
    :param max_attempts: Iteration cap on the in-process path. Ignored
                         on the external-miner path (the external miner
                         caps via ``timeout_s`` instead).
    :param timeout_s:    Subprocess timeout on the external-miner path.
                         Ignored in-process (use ``max_attempts`` there).

    :returns: :class:`DmintMineResult` with the verified nonce.
    :raises MaxAttemptsError:  in-process exhausted ``max_attempts``,
                               or external miner exceeded ``timeout_s``
                               / explicitly signalled exhaustion.
    :raises ValidationError:   external miner returned a malformed
                               response or a nonce that fails local
                               verification.
    """
    if miner_argv is None:
        return mine_solution(
            preimage=preimage,
            target=target,
            algo=algo,
            nonce_width=nonce_width,
            max_attempts=max_attempts,
        )
    return mine_solution_external(
        preimage=preimage,
        target=target,
        miner_argv=miner_argv,
        nonce_width=nonce_width,
        timeout_s=timeout_s,
    )


# ---------------------------------------------------------------------------
# dMint mint transaction builder
# ---------------------------------------------------------------------------


def _varint_size(n: int) -> int:
    """Return the number of bytes needed to encode ``n`` as a Bitcoin varint."""
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def build_dmint_mint_tx(
    contract_utxo: DmintContractUtxo,
    nonce: bytes,
    miner_pkh: bytes,
    current_time: int,
    fee_rate: int = 10_000,
    *,
    funding_utxo: DmintMinerFundingUtxo | None = None,
    op_return_msg: bytes | None = None,
    epoch_length: int | None = None,
    max_adjustment_log2: int | None = None,
    schedule: tuple[tuple[int, int], ...] | None = None,
) -> DmintMintResult:
    """Build an unsigned dMint mint transaction.

    Spends the live dMint contract UTXO, recreates the 1-photon contract
    singleton at ``height + 1``, and pays the FT reward to ``miner_pkh`` from a
    separate plain-RXD funding input. V1 and V2 use the **same consensus shape**
    (the V2 covenant's output-validation block is byte-identical to V1's);
    they differ only in the nonce width (4B V1 / 8B V2) and the 10-item V2 state.

    Transaction structure (both V1 and V2)
    --------------------------------------
    **Inputs**
      * Input 0: contract UTXO — covenant scriptSig
        ``build_mint_scriptsig(nonce, pow.input_hash, pow.output_hash, nonce_width=4|8)``.
      * Input 1: ``funding_utxo`` — a plain-RXD P2PKH input that pays the reward
        photons + tx fee + change (the contract is a 1-photon singleton).

    **Outputs**
      * Output 0: recreated contract (current script with only ``height`` bumped), value **1**.
      * Output 1: FT-wrapped reward output (value = ``state.reward``).
      * Output 2: OP_RETURN (when ``op_return_msg`` is set) — the output the PoW
        preimage binds (see :func:`build_dmint_v2_mint_preimage` / V1 analog).
      * Output 3: change back to ``miner_pkh``.

    .. note::
       **V2 supports FIXED, ASERT, and LWMA** (the canonical Photonic redesign).
       The covenant rebuilds the next state's ``last_time`` from ``OP_TXLOCKTIME``
       and its ``target`` from the alt-stack DAA result on every mint, so
       ``current_time`` IS the block locktime: it is written into the recreated
       state's ``last_time`` AND set as the tx ``nLockTime`` (the two must agree),
       and for DAA modes it drives the target retarget. EPOCH/SCHEDULE are not yet
       ported and raise :class:`NotImplementedError`.

    .. note::
       The preimage is a function of the *transaction itself* (txid of the input
       being spent and the content of both the input and output locking scripts),
       which creates a circular dependency that cannot be resolved without a real
       node.  The nonce + preimage in the returned tx's unlocking script are
       therefore **placeholder bytes** derived from the inputs as known at build
       time.  A production miner loop must:

       1. Build the unsigned tx shell via this function.
       2. Compute the real preimage AND scriptSig hashes via
          ``build_pow_preimage`` once the tx's txid and script hashes are
          stable (they are stable once outputs are finalised — the txid
          doesn't depend on the unlocking script in Radiant/Bitcoin sighash).
       3. Mine for a valid ``nonce`` via ``verify_sha256d_solution`` (or the
          relevant algo).
       4. Replace input 0's unlocking script with
          ``build_mint_scriptsig(nonce, pow.input_hash, pow.output_hash)``.
          The two hashes MUST come from the same ``build_pow_preimage`` call
          that produced the preimage the miner solved — splitting the
          sources is a silent on-chain rejection.
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

    # --- V2 mint -----------------------------------------------------------
    # The V2 covenant's output-validation block (_PART_C) is byte-identical to
    # V1's tail, so a consensus-valid V2 mint has the SAME shape as V1: the
    # 1-photon contract singleton + a plain funding input; it recreates the
    # contract (height+1, value 1) and pays the FT reward, with an optional
    # OP_RETURN at vout[2] that the PoW preimage binds (build_dmint_v2_mint_preimage).
    # V2 differs from V1 only in the 8-byte nonce and the 10-item state. Proven
    # on regtest by tests/test_dmint_v2_regtest_e2e.py (#219).
    if funding_utxo is None:
        raise ValidationError(
            "V2 mint requires a funding_utxo: the contract is a 1-photon singleton "
            "and the FT reward + tx fee come from a separate plain-RXD input (same "
            "shape as V1). Pass funding_utxo=DmintMinerFundingUtxo(...)."
        )
    if state.daa_mode == DaaMode.EPOCH and (epoch_length is None or max_adjustment_log2 is None):
        raise ValidationError(
            "EPOCH mint requires epoch_length and max_adjustment_log2 (baked into the contract "
            "at deploy, not carried in the parsed state) so the off-chain retarget can be computed."
        )
    if state.daa_mode == DaaMode.SCHEDULE and not schedule:
        raise ValidationError(
            "SCHEDULE mint requires the schedule entries (baked into the contract at deploy, not "
            "carried in the parsed state) so the off-chain target lookup can be computed."
        )
    # Redesign: the covenant rebuilds the next state's lastTime from OP_TXLOCKTIME
    # and its target from the alt-stack DAA result on EVERY mint (FIXED included),
    # so current_time IS the block locktime written into the recreated state. It
    # must be a sane Unix-timestamp-range locktime so the tx is final and the
    # nLockTime byte-matches what the covenant reconstructs.
    if current_time < 0:
        raise ValidationError(f"current_time must be >= 0, got {current_time}")
    if state.is_exhausted:
        raise ContractExhaustedError(
            f"dMint contract is exhausted: height={state.height} >= max_height={state.max_height}"
        )
    if len(nonce) != 8:
        raise ValidationError(f"V2 nonce must be 8 bytes, got {len(nonce)}")
    if len(miner_pkh) != 20:
        raise ValidationError(f"miner_pkh must be 20 bytes, got {len(miner_pkh)}")
    if contract_utxo.value != 1:
        raise ValidationError(
            f"V2 dMint contract must be a 1-photon singleton, got {contract_utxo.value} photons. "
            "The covenant enforces OP_OUTPUTVALUE==1 on the recreated contract output, so a "
            "non-1-photon carrier is unmintable. Deploy with a 1-photon contract output."
        )

    # Reject token-bearing funding UTXOs to prevent silent token-burn.
    if is_token_bearing_script(funding_utxo.script):
        raise InvalidFundingUtxoError(
            f"funding_utxo at {funding_utxo.txid}:{funding_utxo.vout} carries an "
            "OP_PUSHINPUTREF-family opcode (token envelope) and cannot be spent as "
            "fee \u2014 that would silently destroy the token. Use a plain RXD UTXO."
        )
    if op_return_msg is not None and len(op_return_msg) > 80:
        raise ValidationError(f"op_return_msg too long ({len(op_return_msg)} bytes); standardness limit is 80 bytes")

    # --- Updated state (redesign): height += 1, lastTime = locktime, target via
    # the DAA mirror (unchanged for FIXED). The covenant's Part C rebuilds this
    # exact next state from MINIMAL_PUSH(height) || <middle literal> ||
    # 04 NUM2BIN(locktime) || MINIMAL_PUSH(target) and OP_EQUALVERIFYs it, so the
    # off-chain reconstruction must byte-match.
    new_height = state.height + 1
    if state.daa_mode == DaaMode.ASERT:
        new_target = compute_next_target_asert(
            current_target=state.target,
            last_time=state.last_time,
            current_time=current_time,
            target_time=state.target_time,
            half_life=3600,  # embedded in the on-chain ASERT bytecode
        )
    elif state.daa_mode == DaaMode.LWMA:
        new_target = compute_next_target_linear(
            current_target=state.target,
            last_time=state.last_time,
            current_time=current_time,
            target_time=state.target_time,
        )
    elif state.daa_mode == DaaMode.EPOCH:
        new_target = compute_next_target_epoch(
            current_target=state.target,
            last_time=state.last_time,
            current_time=current_time,
            target_time=state.target_time,
            height=state.height,  # on-chain EPOCH gates on the CURRENT (spent) height
            epoch_length=epoch_length,
            max_adjustment_log2=max_adjustment_log2,
        )
    elif state.daa_mode == DaaMode.SCHEDULE:
        new_target = compute_next_target_schedule(
            current_target=state.target,
            height=state.height,  # on-chain SCHEDULE gates on the CURRENT (spent) height
            schedule=schedule,
        )
    else:  # FIXED \u2014 target unchanged
        new_target = state.target

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
        is_v1=False,
    )

    # Recreate the contract output script. The code section (Part A/B/C, after
    # the 0xbd separator) is invariant across mints \u2014 slice it from the spent
    # UTXO and graft the rebuilt state prefix. We reconstruct the spent state
    # bytes from the parsed state and assert they prefix the UTXO script, which
    # both locates the separator and guards against a contract whose on-chain
    # encoding diverges from what we parsed.
    old_state_bytes = _v2_state_script_bytes(state)
    if (
        not contract_utxo.script.startswith(old_state_bytes)
        or contract_utxo.script[len(old_state_bytes) : len(old_state_bytes) + 1] != _OP_STATESEPARATOR
    ):
        raise ValidationError(
            "V2 mint: parsed state does not round-trip to the contract UTXO script "
            "(non-canonical encoding or unexpected layout); cannot safely recreate."
        )
    code_with_separator = contract_utxo.script[len(old_state_bytes) :]
    contract_script = _v2_state_script_bytes(updated_state) + code_with_separator

    # The 75-byte FT-wrapped reward \u2014 load-bearing for the covenant's
    # OP_CODESCRIPTHASHVALUESUM_OUTPUTS conservation check (_PART_C == V1 tail).
    reward_script = build_dmint_v1_ft_output_script(miner_pkh, state.token_ref)
    change_script = b"\x76\xa9\x14" + miner_pkh + b"\x88\xac"
    op_return_script: bytes | None = None
    if op_return_msg is not None:
        # Photonic-Wallet convention: OP_RETURN PUSH3 "msg" <push-len> <message>.
        msg_marker = b"\x03msg"
        if len(op_return_msg) <= 0x4B:
            data_push = bytes([len(op_return_msg)]) + op_return_msg
        else:
            data_push = b"\x4c" + bytes([len(op_return_msg)]) + op_return_msg
        op_return_script = b"\x6a" + msg_marker + data_push

    # --- Placeholder scriptSigs: 8-byte-nonce covenant scriptSig (sentinel
    # 0xff*32 hashes) + 108-byte worst-case P2PKH funding scriptSig (see the V1
    # path for the 108-byte rationale). Both replaced after mining / signing.
    placeholder_hash = b"\xff" * 32
    placeholder_contract_scriptsig = build_mint_scriptsig(nonce, placeholder_hash, placeholder_hash, nonce_width=8)
    placeholder_funding_scriptsig = b"\x00" * 108

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
    funding_input.unlocking_script = Script(placeholder_funding_scriptsig)

    trial_outputs = [
        TransactionOutput(Script(contract_script), contract_utxo.value),  # value 1 (singleton), preserved
        TransactionOutput(Script(reward_script), state.reward),
    ]
    if op_return_script:
        trial_outputs.append(TransactionOutput(Script(op_return_script), 0))
    change_output = TransactionOutput(Script(change_script), 0)  # value patched below
    trial_outputs.append(change_output)

    # nLockTime MUST equal current_time: the covenant reconstructs the next
    # state's lastTime from OP_TXLOCKTIME, so the recreated state only byte-matches
    # if the tx's locktime is exactly the value we wrote into updated_state.
    tx = Transaction(
        tx_inputs=[contract_input, funding_input],
        tx_outputs=trial_outputs,
        locktime=current_time,
    )
    # The funding input pays the FT reward photons + the tx fee + change.
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

        vin[0]  contract UTXO          unlocked by build_mint_scriptsig(nonce_4b, input_hash, output_hash)
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
    from pyrxd.security.errors import InvalidFundingUtxoError
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
    if contract_utxo.value != 1:
        # The V1 covenant's continue branch enforces
        # ``OP_OUTPUTVALUE OP_1 OP_NUMEQUALVERIFY`` on the recreated contract
        # output, and the mint preserves ``contract_utxo.value``. So a contract
        # deployed with any carrier other than 1 photon is *unmintable* — the
        # node rejects every mint with a cryptic ``mandatory-script-verify-flag-
        # failed (OP_NUMEQUALVERIFY)``. Every live dMint contract is a 1-photon
        # singleton (``build_reveal_outputs`` emits ``contract_value=1``); fail
        # fast here rather than after a wasted PoW grind + broadcast. Proven on
        # regtest by tests/test_dmint_v1_regtest_e2e.py.
        raise ValidationError(
            f"V1 dMint contract must be a 1-photon singleton, got {contract_utxo.value} photons. "
            f"The covenant enforces OP_OUTPUTVALUE==1 on the recreated contract output, so a "
            f"non-1-photon carrier is unmintable. Deploy with a 1-photon contract output."
        )

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
    # Contract input: nonce-bearing scriptSig with two sentinel 0xff*32 hashes.
    # The 0xff bytes are visibly-invalid: a miner that forgets to replace
    # them gets fast network rejection rather than a covenant-fail silent
    # bug. Mining replaces this whole scriptSig.
    placeholder_hash = b"\xff" * 32
    placeholder_contract_scriptsig = build_mint_scriptsig(nonce, placeholder_hash, placeholder_hash, nonce_width=4)
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


# ---------------------------------------------------------------------------
# Preimage builders for V1 and V2 mint transactions
# ---------------------------------------------------------------------------


def build_dmint_v1_mint_preimage(
    contract_utxo: DmintContractUtxo,
    funding_utxo: DmintMinerFundingUtxo,
    unsigned_tx: Any,
) -> PowPreimageResult:
    """Build the V1 mining preimage AND scriptSig hashes for an unsigned mint tx.

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

        preimage    = SHA256(txid_LE || contractRef) ||
                      SHA256(SHA256d(input_script) || SHA256d(output_script))
        input_hash  = SHA256d(input_script)    ← scriptSig push
        output_hash = SHA256d(output_script)   ← scriptSig push

    Callers feed ``preimage`` to :func:`mine_solution` and pass
    ``input_hash`` + ``output_hash`` to :func:`build_mint_scriptsig`.

    :param contract_utxo:  The V1 contract UTXO being spent.
    :param funding_utxo:   The plain-RXD UTXO providing reward + fee.
    :param unsigned_tx:    The unsigned :class:`Transaction` from
                           :func:`build_dmint_mint_tx` — vout[2] is
                           required to be the OP_RETURN msg output
                           (mainnet-canonical 4-output shape).
    :returns:              :class:`PowPreimageResult` carrying the preimage
                           and the two script hashes that the scriptSig
                           must push for the covenant to accept the mint.
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


def build_dmint_v2_mint_preimage(
    contract_utxo: DmintContractUtxo,
    funding_utxo: DmintMinerFundingUtxo,
    output_script: bytes,
) -> PowPreimageResult:
    """Build the V2 mining preimage AND scriptSig hashes.

    V2 analog of :func:`build_dmint_v1_mint_preimage`. The preimage
    shape (and the on-chain covenant's H1/H2 binding logic) is identical
    to V1 — V2 inherits the output-validation block via ``_PART_C`` =
    ``_V1_EPILOGUE_SUFFIX[18:]``. The only V1/V2 differences at the
    mint-tx level are the nonce width (8 bytes for V2 vs 4 for V1, a
    parameter of :func:`build_mint_scriptsig`) and the absence of the
    Photonic-Wallet ``op_return_msg`` convention in V2.

    Layout (matches :func:`build_pow_preimage`)::

        preimage    = SHA256(txid_LE || contractRef) ||
                      SHA256(SHA256d(input_script) || SHA256d(output_script))
        input_hash  = SHA256d(input_script)    ← scriptSig push
        output_hash = SHA256d(output_script)   ← scriptSig push

    Unlike the V1 helper, this function takes ``output_script`` as an
    **explicit argument**. V2 has no canonical "OP_RETURN msg at vout[2]"
    convention (that's Photonic-Wallet's V1 layout); the V2 covenant
    binds outputHash to whatever bytes the caller chooses to push.
    Callers selecting ``output_script`` should pick one of the actual
    transaction outputs and document the binding in their own code.

    .. note::
       This helper closes the audit's security-H1 finding (no V2 analog of
       ``build_dmint_v1_mint_preimage`` left V2 callers one careless
       script-mismatch away from reproducing the M1 bug pattern). V2 is
       consensus-proven on regtest + mainnet (#219).

    :param contract_utxo:  The V2 contract UTXO being spent. Its
                           ``state.is_v1`` MUST be ``False`` — passing
                           a V1 UTXO is a bug.
    :param funding_utxo:   The plain-RXD UTXO providing reward + fee.
    :param output_script:  The output-script bytes to bind into the
                           preimage. V2 has no canonical convention;
                           pick a transaction output the caller cares
                           about (e.g. an OP_RETURN identifier, or
                           the reward output's locking script).
    :returns:              :class:`PowPreimageResult` with the preimage
                           and the two script hashes the scriptSig
                           must push.
    :raises ValidationError: V1 contract UTXO passed by mistake, or an
                           empty ``output_script``.
    """
    if contract_utxo.state.is_v1:
        raise ValidationError(
            "build_dmint_v2_mint_preimage called with a V1 contract UTXO "
            "(state.is_v1 is True). Use build_dmint_v1_mint_preimage instead."
        )
    if not output_script:
        raise ValidationError(
            "output_script must be non-empty bytes — the V2 covenant binds "
            "outputHash to SHA256d(output_script); empty bytes would produce "
            "a degenerate preimage."
        )
    txid_le = bytes.fromhex(contract_utxo.txid)[::-1]
    # The inner build_pow_preimage call doesn't emit V2 warnings — it's
    # shared with V1. The single warning at the top of this function is
    # the right granularity (one per V2-preimage-build call site).
    return build_pow_preimage(
        txid_le=txid_le,
        contract_ref_bytes=contract_utxo.state.contract_ref.to_bytes(),
        input_script=funding_utxo.script,
        output_script=output_script,
    )

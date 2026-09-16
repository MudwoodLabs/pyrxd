"""Differential guard: every off-chain DAA target mirror must compute EXACTLY what the
on-chain covenant bytecode computes, under Radiant's int64 ``CScriptNum`` semantics.

On-chain/off-chain divergence is the bug class that bricked EPOCH (the wallet's BigInt
math built a recreated state the int64 covenant rejected; see
Radiant-Core/Photonic-Wallet#2), and it is the bug class a wrong DAA port produces: the
miner grinds PoW, the covenant recomputes the target with the bytecode it was born with,
and Part C's OP_EQUALVERIFY rejects the mint. This test executes the *actual* bytecode each
builder emits under a faithful int64 evaluator and asserts it matches the mirror.

Modes covered, each against the bytes its builder emits (never a hand-typed fragment):

* EPOCH — ``_build_epoch_daa`` vs ``compute_next_target_epoch`` (2500 cases).
* ASERT-v2 — ``_build_asert_daa_v2`` vs ``compute_next_target_asert_v2`` (3000 seeded cases
  spanning negative / zero / huge excess, half_life 1 and huge, targets at 1, MAX/4 and MAX,
  plus every int64 boundary explicitly: the largest excess whose ``× RADIX`` fits, the first
  that aborts, and the OP_SUB underflow — where BOTH sides must abort).
* LWMA-v2 — ``_build_linear_daa_v2`` vs ``compute_next_target_linear_v2`` (same regime, the
  gain is ``target_time``).
* Legacy LWMA — BOTH deployed variants (``_build_linear_daa_legacy`` with the ``OP_0 OP_MAX``
  floor, and the pre-floor ``_build_linear_daa_legacy_prefloor`` the mainnet ``dea3beb9…``
  contract bakes) vs ``compute_next_target_linear_legacy``: the no-brick guard for LWMA
  contracts deployed before the 2026-09-16 resync.
* Legacy ASERT — ``_build_asert_daa_legacy`` vs ``compute_next_target_asert_legacy``: the
  no-brick guard for pre-resync ASERT contracts (never differential-tested before the resync).

The evaluator (``_run``) is a faithful subset of ``interpreter.cpp`` for the opcodes these
fragments use: OP_ADD/OP_SUB/OP_MUL/OP_2MUL abort when the result leaves
``[-(2^63-1), 2^63-1]`` (``safeAdd``/``safeSub``/``safeMul``; INT64_MIN is forbidden by
``valid64BitRange``, script.h:521), OP_DIV truncates toward zero (C++ ``/``), OP_ROT is
``(x1 x2 x3 → x2 x3 x1)`` (interpreter.cpp:750), and MINIMALDATA — mandatory on Radiant
(``policy.h`` MANDATORY_SCRIPT_VERIFY_FLAGS) — is enforced both for pushes (``CheckMinimalPush``)
and for every stack item read as a number (``CScriptNum::IsMinimallyEncoded``), so a
non-minimal constant in a fragment fails here the way it fails on the node. Negative controls
prove the evaluator detects an int64 overflow and a non-minimal push.

Radiant-Core sources vendored at tests/vendor/radiant_core/ (v3.1.2); Photonic references
at ``packages/lib/src/script.ts`` / ``dmintDaaV2.ts`` commit becf41a731e78ab98fdd88652527d7dda12784c6.
"""

from __future__ import annotations

import random
from collections.abc import Callable

import pytest

from pyrxd.glyph.dmint.builders import (
    _build_asert_daa_legacy,
    _build_asert_daa_v2,
    _build_epoch_daa,
    _build_linear_daa_legacy,
    _build_linear_daa_legacy_prefloor,
    _build_linear_daa_v2,
    _push_minimal,
)
from pyrxd.glyph.dmint.miner import (
    compute_next_target_asert_legacy,
    compute_next_target_asert_v2,
    compute_next_target_epoch,
    compute_next_target_linear_legacy,
    compute_next_target_linear_v2,
)
from pyrxd.glyph.dmint.types import ASERT_V2_MAX_TARGET_DIV4, ASERT_V2_RADIX, MAX_SHA256D_TARGET
from pyrxd.security.errors import ValidationError

INT64_MAX = (1 << 63) - 1
#: Radiant's CScriptNum range is [INT64_MIN + 1, INT64_MAX]: INT64_MIN is forbidden
#: (script.h ``valid64BitRange``, it would need a 9-byte encoding), and safeAdd/safeSub/
#: safeMul return nullopt for it, so the opcode aborts. The range is symmetric.
SCRIPT_INT_MIN = -INT64_MAX


class _Abort(Exception):
    """Models a Radiant script abort (int64 range error, MINIMALDATA, div-by-zero, ...)."""


def _idiv(a: int, b: int) -> int:
    """Integer division truncated TOWARD ZERO (CScriptNum / C++ semantics)."""
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def _cs_encode(n: int) -> bytes:
    """CScriptNum → minimal little-endian byte string."""
    if n == 0:
        return b""
    neg = n < 0
    a = abs(n)
    out = bytearray()
    while a:
        out.append(a & 0xFF)
        a >>= 8
    if out[-1] & 0x80:
        out.append(0x80 if neg else 0x00)
    elif neg:
        out[-1] |= 0x80
    return bytes(out)


def _cs_decode(b: bytes) -> int:
    if not b:
        return 0
    a = 0
    for i, by in enumerate(b):
        a |= by << (8 * i)
    if b[-1] & 0x80:
        a &= ~(0x80 << (8 * (len(b) - 1)))
        return -a
    return a


def _is_minimal_num(b: bytes) -> bool:
    """``CScriptNum::IsMinimallyEncoded`` (script.cpp): the top byte may be 0x00/0x80 only
    to carry a sign bit the byte below could not."""
    if not b:
        return True
    if (b[-1] & 0x7F) == 0:
        if len(b) <= 1:
            return False
        if (b[-2] & 0x80) == 0:
            return False
    return True


def _num(x) -> int:
    """Read a stack item as a CScriptNum (fRequireMinimal, maxIntegerSize=8), as the arithmetic
    opcodes do — a non-minimal or over-long number aborts the script on the node."""
    if isinstance(x, (bytes, bytearray)):
        if len(x) > 8:
            raise _Abort(f"script number longer than 8 bytes: {bytes(x).hex()}")
        if not _is_minimal_num(bytes(x)):
            raise _Abort(f"non-minimal script number {bytes(x).hex()}")
        return _cs_decode(bytes(x))
    return x


def _run(code: bytes, stack: list, locktime: int) -> list:
    """Execute `code` over `stack` (list of CScriptNum byte items, top = last)."""
    exec_stack: list[bool] = []
    i = 0

    def _push(n: int) -> None:
        if n > INT64_MAX or n < SCRIPT_INT_MIN:
            raise _Abort("result out of int64 range")
        stack.append(_cs_encode(n))

    while i < len(code):
        op = code[i]
        i += 1
        if op == 0x63:  # OP_IF
            exec_stack.append(_num(stack.pop()) != 0 if all(exec_stack) else False)
            continue
        if op == 0x67:  # OP_ELSE
            exec_stack[-1] = not exec_stack[-1]
            continue
        if op == 0x68:  # OP_ENDIF
            exec_stack.pop()
            continue
        if not all(exec_stack):
            if 0x01 <= op <= 0x4B:
                i += op
            continue
        if op == 0x00:
            stack.append(b"")
        elif 0x01 <= op <= 0x4B:
            data = code[i : i + op]
            if len(data) != op:
                raise _Abort("truncated push")
            # CheckMinimalPush (interpreter.cpp:361): a 1-byte push of 1..16 must be OP_N and
            # of 0x81 must be OP_1NEGATE. MINIMALDATA is mandatory on Radiant — this is exactly
            # the class that bricked a Gravity covenant (F-001).
            if op == 1 and (1 <= data[0] <= 16 or data[0] == 0x81):
                raise _Abort(f"non-minimal push {data.hex()} (must be OP_N / OP_1NEGATE)")
            stack.append(data)
            i += op
        elif op == 0x4F:  # OP_1NEGATE
            _push(-1)
        elif op == 0x51:
            _push(1)
        elif 0x52 <= op <= 0x60:  # OP_2..OP_16
            _push(op - 0x50)
        elif op == 0x76:  # OP_DUP
            stack.append(stack[-1])
        elif op == 0x75:  # OP_DROP
            stack.pop()
        elif op == 0x7B:  # OP_ROT — (x1 x2 x3 → x2 x3 x1), interpreter.cpp:750
            if len(stack) < 3:
                raise _Abort("OP_ROT on a stack of fewer than 3 items")
            stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]
        elif op == 0x7C:  # OP_SWAP
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 0x79:  # OP_PICK
            stack.append(stack[-1 - _num(stack.pop())])
        elif op == 0xC5:  # OP_TXLOCKTIME
            _push(locktime)
        elif op == 0x8C:  # OP_1SUB
            _push(_num(stack.pop()) - 1)
        elif op == 0x8D:  # OP_2MUL
            v = _num(stack.pop()) * 2
            if v > INT64_MAX or v < SCRIPT_INT_MIN:
                raise _Abort("2MUL overflow")
            _push(v)
        elif op == 0x8E:  # OP_2DIV
            _push(_idiv(_num(stack.pop()), 2))
        elif op == 0x8F:  # OP_NEGATE
            _push(-_num(stack.pop()))
        elif op in (0x93, 0x94, 0x95, 0x96, 0x97, 0x9A, 0x9C, 0x9F, 0xA0, 0xA2, 0xA3, 0xA4):
            b = _num(stack.pop())
            a = _num(stack.pop())
            if op == 0x93:
                r = a + b
            elif op == 0x94:
                r = a - b
            elif op == 0x95:  # OP_MUL — safeMul abort
                r = a * b
                if r > INT64_MAX or r < SCRIPT_INT_MIN:
                    raise _Abort("OP_MUL int64 overflow")
            elif op == 0x96:  # OP_DIV
                if b == 0:
                    raise _Abort("div0")
                r = _idiv(a, b)
            elif op == 0x97:  # OP_MOD
                if b == 0:
                    raise _Abort("mod0")
                r = a - _idiv(a, b) * b
            elif op == 0x9A:
                r = 1 if (a != 0 and b != 0) else 0
            elif op == 0x9C:
                r = 1 if a == b else 0
            elif op == 0x9F:
                r = 1 if a < b else 0
            elif op == 0xA0:
                r = 1 if a > b else 0
            elif op == 0xA2:
                r = 1 if a >= b else 0
            elif op == 0xA3:
                r = min(a, b)
            else:  # 0xA4
                r = max(a, b)
            _push(r)  # OP_ADD / OP_SUB results are range-checked here (safeAdd / safeSub)
        else:
            raise _Abort(f"unhandled opcode {hex(op)}")
    return stack


# dMint state layout (bottom→top): height, cRef, tRef, maxHeight, reward, algoId,
# daaMode, targetTime, lastTime, target. The DAA fragments only read height
# (OP_9 PICK), lastTime (OP_2 PICK), targetTime (OP_3 PICK) and target (top); the
# rest are placeholders. Every fragment must leave the depth unchanged, with
# newTarget where target was (Part B4 then TOALTSTACKs it).
def _daa_stack(daa_mode_id: int, target_time: int, last_time: int, target: int, height: int = 0) -> list:
    return [_cs_encode(v) for v in (height, 0, 0, 0, 0, 0, daa_mode_id, target_time, last_time, target)]


def _result(stack: list) -> int:
    assert len(stack) == 10, f"DAA fragment changed the stack depth: {len(stack)}"
    return _num(stack[-1])


def _epoch_onchain(target, last_time, current_time, target_time, height, epoch_length, n) -> int:
    stack = _daa_stack(1, target_time, last_time, target, height)
    _run(_build_epoch_daa(epoch_length, n), stack, current_time)
    return _result(stack)


def _lwma_legacy_onchain(target, last_time, current_time, target_time) -> int:
    stack = _daa_stack(3, target_time, last_time, target)
    _run(_build_linear_daa_legacy(), stack, current_time)
    return _result(stack)


def _lwma_prefloor_onchain(target, last_time, current_time, target_time) -> int:
    stack = _daa_stack(3, target_time, last_time, target)
    _run(_build_linear_daa_legacy_prefloor(), stack, current_time)
    return _result(stack)


def _lwma_v2_onchain(target, last_time, current_time, target_time) -> int:
    stack = _daa_stack(3, target_time, last_time, target)
    _run(_build_linear_daa_v2(), stack, current_time)
    return _result(stack)


def _asert_v2_onchain(target, last_time, current_time, target_time, half_life) -> int:
    stack = _daa_stack(2, target_time, last_time, target)
    _run(_build_asert_daa_v2(half_life), stack, current_time)
    return _result(stack)


def _asert_legacy_onchain(target, last_time, current_time, target_time, half_life) -> int:
    stack = _daa_stack(2, target_time, last_time, target)
    _run(_build_asert_daa_legacy(half_life), stack, current_time)
    return _result(stack)


_TARGETS = [
    1,
    2,
    1000,
    1 << 20,
    1 << 40,
    (1 << 48) - 1,
    1 << 48,
    (1 << 48) + 1,
    1 << 52,
    INT64_MAX // 4,
    INT64_MAX // 8,
    INT64_MAX // 100000,
]
_TTS = [1, 2, 30, 60, 600, 2048, 86400]
_DELTAS = [-1_000_000, -300, -1, 0, 1, 15, 30, 60, 240, 3600, 1 << 30, 1 << 40]
_LAST = 1_700_000_000
#: The locktime domain ``build_dmint_mint_tx`` accepts: ``[0, 0x7FFFFFFF]`` (Part C's
#: NUM2BIN(4) cannot encode a locktime with bit 31 set) and ``current_time >= last_time``.
_LOCKTIME_MAX = 0x7FFFFFFF  # spelled as the mint builder spells its own bound


def test_epoch_offchain_matches_onchain() -> None:
    rnd = random.Random(20260618)
    for _ in range(2500):
        tgt = rnd.choice([*_TARGETS, rnd.randint(1, 1 << 53)])
        tt = rnd.choice(_TTS)
        el = rnd.choice([1, 2, 10, 20, 2016])
        n = rnd.choice([1, 2, 3, 4])
        h = rnd.choice([0, el, 2 * el, el + 1, 5, 7, 100, 3 * el])  # boundary + non-boundary
        ct = _LAST + rnd.choice(_DELTAS)
        off = compute_next_target_epoch(tgt, _LAST, ct, tt, h, el, n)
        on = _epoch_onchain(tgt, _LAST, ct, tt, h, el, n)  # must not raise (no overflow)
        assert on == off, (
            f"EPOCH divergence tgt={tgt} tt={tt} n={n} h={h} el={el} delta={ct - _LAST}: on={on} off={off}"
        )
        assert on >= 1
        # a boundary retarget caps the output at 2^48 (the difficulty floor); the
        # fuzz also feeds target > 2^48 at non-boundary heights, where target is
        # passed through unchanged (deploy validation keeps real contracts <= 2^48).
        if h > 0 and h % el == 0:
            assert on <= (1 << 48)


# ---------------------------------------------------------------------------------------
# Legacy LWMA (both deployed variants) — the no-brick guard for pre-resync LWMA contracts
# ---------------------------------------------------------------------------------------


def test_lwma_legacy_floored_offchain_matches_onchain() -> None:
    """The floored legacy LWMA (pyrxd deploys 2026-06-17 → 2026-09-15) vs its mirror, including
    NEGATIVE deltas, which the ``OP_0 OP_MAX`` floor turns into a 0 delta (target → 1)."""
    rnd = random.Random(20260619)
    for _ in range(2500):
        tgt = rnd.choice([*_TARGETS, rnd.randint(1, 1 << 53)])
        tt = rnd.choice(_TTS)
        ct = _LAST + rnd.choice(_DELTAS)
        off = compute_next_target_linear_legacy(tgt, _LAST, ct, tt)
        on = _lwma_legacy_onchain(tgt, _LAST, ct, tt)  # must not raise (no overflow)
        assert on == off, f"legacy LWMA divergence tgt={tgt} tt={tt} delta={ct - _LAST}: on={on} off={off}"
        assert on >= 1


def test_lwma_legacy_prefloor_offchain_matches_onchain() -> None:
    """The pre-floor legacy LWMA — the bytecode of the mainnet ``dea3beb9…`` deploy — vs the
    SAME mirror, over the domain the mint builder accepts (``current_time >= last_time``).
    Without the floor a negative delta multiplies into the target; the builder refuses such
    a locktime before grinding, so the mirror is only ever asked about delta >= 0."""
    rnd = random.Random(20260616)
    for _ in range(2500):
        tgt = rnd.choice([*_TARGETS, MAX_SHA256D_TARGET, rnd.randint(1, 1 << 53)])
        tt = rnd.choice(_TTS)
        ct = _LAST + rnd.choice([d for d in _DELTAS if d >= 0] + [rnd.randint(0, 1 << 20)])
        off = compute_next_target_linear_legacy(tgt, _LAST, ct, tt)
        on = _lwma_prefloor_onchain(tgt, _LAST, ct, tt)
        assert on == off, f"pre-floor LWMA divergence tgt={tgt} tt={tt} delta={ct - _LAST}: on={on} off={off}"
    # The one input the two legacy variants disagree on, spelled out: a 30 s-early block.
    # Floored: delta → 0 → target 1. Pre-floor: (MAX/4 / 60) × -30 < 0 → clamped to 1 as well
    # (the mirror floors, so all three agree here); the divergence between the variants is
    # only ever an int64 ABORT on a large negative product, which the builder never emits.
    assert _lwma_legacy_onchain(MAX_SHA256D_TARGET, _LAST, _LAST - 30, 60) == 1
    assert _lwma_prefloor_onchain(MAX_SHA256D_TARGET, _LAST, _LAST - 30, 60) == 1
    with pytest.raises(_Abort, match="OP_MUL"):
        _lwma_prefloor_onchain(MAX_SHA256D_TARGET, _LAST, _LAST - 1_000_000, 60)
    assert _lwma_legacy_onchain(MAX_SHA256D_TARGET, _LAST, _LAST - 1_000_000, 60) == 1


# ---------------------------------------------------------------------------------------
# Legacy ASERT — the no-brick guard for pre-resync ASERT contracts
# ---------------------------------------------------------------------------------------

_LEGACY_HALFLIVES = [1, 2, 30, 60, 240, 600, 3600, 65536, 86400]


def test_asert_legacy_offchain_matches_onchain() -> None:
    """The integer power-of-2 stepper baked into pre-resync ASERT contracts vs its mirror.
    Includes targets at MAX (the per-step cap) and negative excess (OP_NEGATE + 2DIV path)."""
    rnd = random.Random(20260621)
    moved = 0
    for _ in range(3000):
        tgt = rnd.choice([*_TARGETS, MAX_SHA256D_TARGET, MAX_SHA256D_TARGET // 2 + 1, rnd.randint(1, INT64_MAX)])
        tt = rnd.choice(_TTS)
        hl = rnd.choice(_LEGACY_HALFLIVES)
        ct = _LAST + rnd.choice([*_DELTAS, rnd.randint(-100_000, 500_000)])
        off = compute_next_target_asert_legacy(tgt, _LAST, ct, tt, hl)
        on = _asert_legacy_onchain(tgt, _LAST, ct, tt, hl)  # must not raise
        assert on == off, f"legacy ASERT divergence tgt={tgt} tt={tt} hl={hl} delta={ct - _LAST}: on={on} off={off}"
        assert 1 <= on <= MAX_SHA256D_TARGET
        moved += on != tgt
    assert moved > 500, "the sweep never left the legacy dead zone — it proves nothing about the stepper"


# ---------------------------------------------------------------------------------------
# ASERT-v2 / LWMA-v2 — the CURRENT formulas
# ---------------------------------------------------------------------------------------

_V2_TARGETS = [
    1,
    2,
    ASERT_V2_RADIX - 1,  # t // RADIX == 0: the step is exactly 0
    ASERT_V2_RADIX,
    ASERT_V2_RADIX + 1,
    1 << 40,
    1 << 48,
    INT64_MAX // 8,
    ASERT_V2_MAX_TARGET_DIV4 - 1,
    ASERT_V2_MAX_TARGET_DIV4,
    ASERT_V2_MAX_TARGET_DIV4 + 1,  # above the pre-cap
    INT64_MAX // 2,
    MAX_SHA256D_TARGET - 1,
    MAX_SHA256D_TARGET,
]
_V2_HALFLIVES = [1, 2, 3, 7, 60, 240, 3600, 86400, 65536, 2**31 - 1, 2**47, INT64_MAX]
_V2_TTS = [1, 2, 7, 60, 600, 3600, 86400, 2**31 - 1]
#: Deltas keep ``current_time`` inside the builder's locktime domain: ``-_LAST`` is locktime 0,
#: ``_LOCKTIME_MAX - _LAST`` is the largest accepted locktime.
_V2_DELTAS = [
    -_LAST,
    -86400,
    -3600,
    -121,
    -61,
    -60,
    -59,
    -1,
    0,
    1,
    29,
    30,
    31,
    59,
    60,
    61,
    119,
    120,
    121,
    240,
    3600,
    86400,
    _LOCKTIME_MAX - _LAST,
]

_ABORT = object()


def _outcome(fn: Callable[..., int], abort_exc: type[Exception], *args: int):
    """``fn(*args)``, or the ``_ABORT`` sentinel if it raised the side's abort exception."""
    try:
        return fn(*args)
    except abort_exc:
        return _ABORT


def _sweep_v2(mode: str, seed: int) -> None:
    rnd = random.Random(seed)
    up = down = capped = unchanged = 0
    for _ in range(3000):
        tgt = rnd.choice([*_V2_TARGETS, rnd.randint(1, MAX_SHA256D_TARGET)])
        tt = rnd.choice([*_V2_TTS, rnd.randint(1, 1 << 20)])
        delta = rnd.choice([*_V2_DELTAS, rnd.randint(-1_000_000, 400_000_000)])
        ct = _LAST + delta
        assert 0 <= ct <= _LOCKTIME_MAX
        if mode == "asert":
            hl = rnd.choice([*_V2_HALFLIVES, rnd.randint(1, 1 << 40)])
            off = compute_next_target_asert_v2(tgt, _LAST, ct, tt, hl)
            on = _asert_v2_onchain(tgt, _LAST, ct, tt, hl)  # must not raise: the int64 proof
            label = f"ASERT-v2 tgt={tgt} tt={tt} hl={hl} delta={delta}"
        else:
            off = compute_next_target_linear_v2(tgt, _LAST, ct, tt)
            on = _lwma_v2_onchain(tgt, _LAST, ct, tt)
            label = f"LWMA-v2 tgt={tgt} tt={tt} delta={delta}"
        assert on == off, f"{label}: on={on} off={off}"
        assert 1 <= on <= ASERT_V2_MAX_TARGET_DIV4
        t = min(tgt, ASERT_V2_MAX_TARGET_DIV4)
        if on > t:
            up += 1
        elif on < t:
            down += 1
        else:
            unchanged += 1
        capped += on == ASERT_V2_MAX_TARGET_DIV4
    # Non-vacuity: every branch of the fragment was exercised — a target that rose, one that
    # fell (negative driftFp, the truncation-toward-zero path), the MAX/4 cap, and the
    # unchanged case (on-target block, or t // RADIX == 0).
    assert up > 100 and down > 100 and capped > 50 and unchanged > 20, (up, down, capped, unchanged)


def test_asert_v2_offchain_matches_onchain() -> None:
    """ASERT-v2: the mirror equals the bytecode under int64 semantics with NO abort anywhere
    in the builder's domain (dmintDaaV2.ts proof + the widened bounds in the mirror docstring)."""
    _sweep_v2("asert", 20260916)


def test_lwma_v2_offchain_matches_onchain() -> None:
    """LWMA-v2: ASERT-v2 with the gain set to ``target_time`` — same guarantees."""
    _sweep_v2("lwma", 20260917)


def _v2_boundary_cases() -> list[tuple[int, int, int, int, bool]]:
    """``(target, current_time, target_time, half_life, expect_abort)`` at every int64 edge.

    ``excess = timeDelta - target_time``; ``target_time`` is the only operand that can drive
    ``excess * RADIX`` out of int64 (positive excess is bounded by the 31-bit locktime). The
    largest magnitude whose product fits is ``2^47 - 1`` (``× 2^16 = 2^63 - 2^16``); ``2^47``
    gives ``-2^63`` = INT64_MIN, which Radiant forbids. And with ``target_time = INT64_MAX`` the
    OP_SUB itself underflows for any negative ``timeDelta``... here ``timeDelta = -1``
    (``excess = -2^63``), while ``timeDelta = 0`` is representable and only the multiply aborts.
    """
    cases = []
    for hl in (1, 240, INT64_MAX):
        for tgt in (1, ASERT_V2_MAX_TARGET_DIV4, MAX_SHA256D_TARGET):
            for delta in (0, -1, 5):
                ct = _LAST + delta
                cases.append((tgt, ct, delta + (1 << 47) - 1, hl, False))  # excess = -(2^47 - 1): fits
                cases.append((tgt, ct, delta + (1 << 47), hl, True))  # excess = -2^47: OP_MUL aborts
            cases.append((tgt, _LAST - 1, INT64_MAX, hl, True))  # OP_SUB underflow (excess = -2^63)
            cases.append((tgt, _LAST, INT64_MAX, hl, True))  # excess = -(2^63-1) fits; × RADIX aborts
            cases.append((tgt, _LAST + 5, INT64_MAX - 5, hl, True))  # same, positive timeDelta
    return cases


def test_asert_v2_int64_boundaries_agree_including_aborts() -> None:
    """At each int64 edge the mirror and the bytecode must AGREE: both compute the same value,
    or both abort (the mirror raises ``ValidationError`` before any PoW grind; the evaluator
    raises ``_Abort`` as the node would with INVALID_NUMBER_RANGE_64_BIT). A mirror that
    returned a number where the covenant aborts would predict an unmineable state."""
    aborted = fitted = 0
    for tgt, ct, tt, hl, expect_abort in _v2_boundary_cases():
        off = _outcome(compute_next_target_asert_v2, ValidationError, tgt, _LAST, ct, tt, hl)
        on = _outcome(_asert_v2_onchain, _Abort, tgt, _LAST, ct, tt, hl)
        label = f"ASERT-v2 boundary tgt={tgt} ct-last={ct - _LAST} tt={tt} hl={hl}"
        assert (off is _ABORT) == expect_abort, f"{label}: mirror {'raised' if off is _ABORT else off}"
        assert (on is _ABORT) == expect_abort, f"{label}: bytecode {'aborted' if on is _ABORT else on}"
        if expect_abort:
            aborted += 1
        else:
            fitted += 1
            assert on == off, f"{label}: on={on} off={off}"
    assert aborted >= 45 and fitted >= 27, (aborted, fitted)


def test_lwma_v2_int64_boundaries_agree_including_aborts() -> None:
    """Same edges for LWMA-v2, whose gain is ``target_time`` (so the divisor and the excess
    operand move together)."""
    aborted = fitted = 0
    for tgt, ct, tt, _hl, expect_abort in _v2_boundary_cases():
        off = _outcome(compute_next_target_linear_v2, ValidationError, tgt, _LAST, ct, tt)
        on = _outcome(_lwma_v2_onchain, _Abort, tgt, _LAST, ct, tt)
        label = f"LWMA-v2 boundary tgt={tgt} ct-last={ct - _LAST} tt={tt}"
        assert (off is _ABORT) == (on is _ABORT) == expect_abort, f"{label}: off={off!r} on={on!r}"
        if expect_abort:
            aborted += 1
        else:
            fitted += 1
            assert on == off, f"{label}: on={on} off={off}"
    assert aborted >= 45 and fitted >= 27, (aborted, fitted)


def test_v2_clamp_and_truncation_edges_by_hand() -> None:
    """The drift clamp boundary (driftFp exactly ±16384, one past it) and truncation toward
    zero, through the ACTUAL bytecode — the values a floor-dividing mirror would get wrong."""
    t = 1 << 40
    step = t // ASERT_V2_RADIX  # 2^24
    # half_life 240, target_time 60: excess 60 → driftFp 16384 (the clamp), 61 → clamped too.
    assert _asert_v2_onchain(t, _LAST, _LAST + 120, 60, 240) == t + step * 16384
    assert _asert_v2_onchain(t, _LAST, _LAST + 121, 60, 240) == t + step * 16384
    assert _asert_v2_onchain(t, _LAST, _LAST + 119, 60, 240) == t + step * 16110  # 59·65536/240 = 16110.9 → 16110
    assert _asert_v2_onchain(t, _LAST, _LAST, 60, 240) == t - step * 16384  # excess -60 → -16384
    assert _asert_v2_onchain(t, _LAST, _LAST + 1, 60, 240) == t - step * 16110  # -59 → trunc(-16110.9) = -16110
    assert _asert_v2_onchain(t, _LAST, _LAST + 59, 60, 240) == t - step * 273  # -1 → trunc(-273.07) = -273
    # LWMA-v2 with gain 60: +10 s late → trunc(10·65536/60) = 10922; -10 s early → -10922.
    assert _lwma_v2_onchain(t, _LAST, _LAST + 70, 60) == t + step * 10922
    assert _lwma_v2_onchain(t, _LAST, _LAST + 50, 60) == t - step * 10922
    # The mirror agrees on every one of these.
    assert compute_next_target_asert_v2(t, _LAST, _LAST + 59, 60, 240) == t - step * 273
    assert compute_next_target_linear_v2(t, _LAST, _LAST + 50, 60) == t - step * 10922


# ---------------------------------------------------------------------------------------
# Negative controls: the evaluator detects what it claims to detect
# ---------------------------------------------------------------------------------------


def test_evaluator_detects_old_overflow() -> None:
    """Negative control: the OLD multiply-first EPOCH bytecode (output capped at
    MAX_TARGET, not 2^48) aborts on int64 overflow under the evaluator — proving
    the 'no aborts' assertions above are not a blind spot."""
    push_max = bytes.fromhex("08ffffffffffffff7f")  # MAX_TARGET
    el, n = 10, 4
    lsh, rsh = b"\x8d" * n, b"\x8e" * n
    old = (
        bytes.fromhex("5979")
        + b"\x76"
        + bytes.fromhex("00a0")
        + b"\x7c"
        + _push_minimal(el)
        + b"\x97"
        + bytes.fromhex("009c")
        + b"\x9a"
        + b"\x63"
        + b"\xc5"
        + bytes.fromhex("5279")
        + b"\x94"
        + bytes.fromhex("5379")
        + lsh
        + b"\xa3"
        + bytes.fromhex("5379")
        + rsh
        + b"\xa4"
        + b"\x7c"
        + b"\x95"
        + bytes.fromhex("5279")
        + b"\x96"
        + push_max
        + b"\xa3"  # multiply-first
        + bytes.fromhex("76519f")
        + b"\x63"
        + bytes.fromhex("7551")
        + b"\x68"
        + b"\x68"
    )
    tgt, tt = 1 << 48, 2048  # target=2^48, slow epoch, N=4 → target × (tt<<4) > 2^63
    stack = [_cs_encode(v) for v in (10, 0, 0, 0, 0, 0, 1, tt, _LAST, tgt)]
    with pytest.raises(_Abort, match="OP_MUL"):
        _run(old, stack, _LAST + (tt << n))


def test_evaluator_detects_a_multiply_first_v2_variant() -> None:
    """Negative control for the v2 shape: swapping the divide-first ``t / RADIX × driftFp``
    for ``t × driftFp / RADIX`` overflows for a target at MAX/4 — the evaluator aborts, so
    the divide-first ordering in the shipped fragment is load-bearing and observed."""
    frag = bytearray(_build_asert_daa_v2(240))
    # ... 76 <RADIX> 96 7b 95 93 ...  →  ... 76 7b 95 <RADIX> 96 93 ...  (multiply first)
    radix = _push_minimal(ASERT_V2_RADIX)
    at = frag.index(b"\x76" + radix + b"\x96\x7b\x95\x93")
    frag[at : at + 1 + len(radix) + 4] = b"\x76\x7b\x95" + radix + b"\x96\x93"
    stack = _daa_stack(2, 60, _LAST, ASERT_V2_MAX_TARGET_DIV4)
    with pytest.raises(_Abort, match="OP_MUL"):
        _run(bytes(frag), stack, _LAST + 120)


def test_evaluator_rejects_non_minimal_push_and_number() -> None:
    """Negative control for MINIMALDATA: a ``01 05`` push (must be OP_5) and a padded
    number (``02 f0 00`` is minimal for 240, ``03 f0 00 00`` is not) both abort — the way
    a Gravity F-001-style non-minimal constant bricks a covenant on the node."""
    with pytest.raises(_Abort, match="non-minimal push"):
        _run(bytes.fromhex("0105"), [], 0)
    with pytest.raises(_Abort, match="non-minimal script number"):
        _run(bytes.fromhex("03f000005193"), [], 0)  # push 240 padded, OP_1, OP_ADD
    assert _num(_run(bytes.fromhex("02f0005193"), [], 0)[-1]) == 241  # the minimal spelling works

"""Differential guard: the off-chain DAA target replicas
(``compute_next_target_epoch`` / ``compute_next_target_linear``) must compute
EXACTLY what the on-chain EPOCH/LWMA covenant bytecode computes.

On-chain/off-chain divergence is the bug class that bricked EPOCH (the wallet's
BigInt math built a recreated state the int64 covenant rejected; see
Radiant-Core/Photonic-Wallet#2). This test executes the *actual* bytecode emitted
by ``_build_epoch_daa`` / ``_build_linear_daa`` under a faithful int64
(``CScriptNum``) evaluator — including the ``OP_MUL`` int64-overflow abort that
real consensus enforces (``radiant-core`` ``interpreter.cpp`` ``safeMul``) — and
asserts it matches the replicas across boundary + random inputs, with no aborts.
A negative control proves the evaluator actually detects the overflow.
"""

from __future__ import annotations

import random

from pyrxd.glyph.dmint.builders import _build_epoch_daa, _build_linear_daa, _push_minimal
from pyrxd.glyph.dmint.miner import (
    compute_next_target_epoch,
    compute_next_target_linear,
)

INT64_MAX = (1 << 63) - 1
INT64_MIN = -(1 << 63)


class _Abort(Exception):
    """Models a Radiant script abort (e.g. OP_MUL int64 range error)."""


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


def _num(x) -> int:
    return _cs_decode(x) if isinstance(x, (bytes, bytearray)) else x


def _run(code: bytes, stack: list, locktime: int) -> list:
    """Execute `code` over `stack` (list of CScriptNum byte items, top = last)."""
    exec_stack: list[bool] = []
    i = 0

    def _push(n: int) -> None:
        if n > INT64_MAX or n < INT64_MIN:
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
            stack.append(code[i : i + op])
            i += op
        elif op == 0x51:
            _push(1)
        elif 0x52 <= op <= 0x60:  # OP_2..OP_16
            _push(op - 0x50)
        elif op == 0x76:  # OP_DUP
            stack.append(stack[-1])
        elif op == 0x75:  # OP_DROP
            stack.pop()
        elif op == 0x7C:  # OP_SWAP
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 0x79:  # OP_PICK
            stack.append(stack[-1 - _num(stack.pop())])
        elif op == 0xC5:  # OP_TXLOCKTIME
            _push(locktime)
        elif op == 0x8D:  # OP_2MUL
            v = _num(stack.pop()) * 2
            if v > INT64_MAX or v < INT64_MIN:
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
                if r > INT64_MAX or r < INT64_MIN:
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
            _push(r)
        else:
            raise _Abort(f"unhandled opcode {hex(op)}")
    return stack


# dMint state layout (bottom→top): height, cRef, tRef, maxHeight, reward, algoId,
# daaMode, targetTime, lastTime, target. The DAA fragment only reads height
# (OP_9 PICK), lastTime, targetTime, and target; the rest are placeholders.
def _epoch_onchain(target, last_time, current_time, target_time, height, epoch_length, n) -> int:
    stack = [_cs_encode(v) for v in (height, 0, 0, 0, 0, 0, 1, target_time, last_time, target)]
    _run(_build_epoch_daa(epoch_length, n), stack, current_time)
    return _num(stack[-1])


def _lwma_onchain(target, last_time, current_time, target_time) -> int:
    stack = [_cs_encode(v) for v in (0, 0, 0, 0, 0, 0, 3, target_time, last_time, target)]
    _run(_build_linear_daa(), stack, current_time)
    return _num(stack[-1])


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


def test_lwma_offchain_matches_onchain() -> None:
    rnd = random.Random(20260619)
    for _ in range(2500):
        tgt = rnd.choice([*_TARGETS, rnd.randint(1, 1 << 53)])
        tt = rnd.choice(_TTS)
        ct = _LAST + rnd.choice(_DELTAS)
        off = compute_next_target_linear(tgt, _LAST, ct, tt)
        on = _lwma_onchain(tgt, _LAST, ct, tt)  # must not raise (no overflow)
        assert on == off, f"LWMA divergence tgt={tgt} tt={tt} delta={ct - _LAST}: on={on} off={off}"
        assert on >= 1


def test_evaluator_detects_old_overflow() -> None:
    """Negative control: the OLD multiply-first EPOCH bytecode (output capped at
    MAX_TARGET, not 2^48) aborts on int64 overflow under the evaluator — proving
    the 'no aborts' assertions above are not a blind spot."""
    import pytest

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

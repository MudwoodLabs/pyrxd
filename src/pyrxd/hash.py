"""Hash primitives used across the SDK.

Historical note on RIPEMD160:
    Earlier revisions imported ``RIPEMD160`` from ``pycryptodomex``. That
    works on a developer laptop but creates two real problems:

    1. ``pycryptodomex`` only ships C-extension wheels — no pure-Python
       wheel. Pyodide / WebAssembly targets cannot install it via
       micropip, which blocks any browser-hosted use of the SDK.
    2. It is a heavy native dependency for what amounts to one small
       hash function. Most users carry it solely so this module keeps
       working.

    OpenSSL 3 disabled RIPEMD160 by default (it was moved to the legacy
    provider), so ``hashlib.new("ripemd160")`` raises on most current
    distros and on python.org installer builds. We can't rely on it
    alone. So this module implements a **two-tier strategy**:

    * **Fast path** — try ``hashlib.new("ripemd160")``. If OpenSSL still
      exposes it (e.g. Ubuntu's openssl.cnf re-enabling the legacy
      provider, or older OpenSSL 1.1.x), this is what you get and it's
      a native C call.
    * **Fallback** — a pure-Python RIPEMD160 implementation that runs
      without OpenSSL. Works everywhere a Python interpreter does,
      including Pyodide/WASM. Roughly 20× slower than the C path but
      RIPEMD160 is only ever applied to 32-byte sha256 outputs in this
      codebase, so the absolute cost is microseconds per call.

    The fallback is selected at module-load time, not per-call, so the
    branch cost is paid exactly once per process.

The pure-Python implementation below is a direct transcription of the
RIPEMD160 reference algorithm published by Hans Dobbertin, Antoon
Bosselaers, and Bart Preneel in "RIPEMD-160: A Strengthened Version of
RIPEMD" (1996). It is exercised against the test vectors from that
paper (and the Bitcoin Core hash unit tests) in
``tests/test_ripemd160_fallback.py``.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections.abc import Callable


def sha1(payload: bytes) -> bytes:
    # nosec B324 -- SHA1 is required by Bitcoin Script (OP_SHA1); not used for security purposes
    return hashlib.sha1(payload).digest()  # nosec B324


def sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def double_sha256(payload: bytes) -> bytes:
    return sha256(sha256(payload))


# --------------------------------------------------------------------------
# RIPEMD160 — hashlib fast path with pure-Python fallback.
# --------------------------------------------------------------------------


def _ripemd160_via_hashlib(payload: bytes) -> bytes:
    """RIPEMD160 via ``hashlib.new``. Raises ``ValueError`` on OpenSSL 3
    where the legacy provider is not loaded."""
    return hashlib.new("ripemd160", payload).digest()


def _ripemd160_pure_python(payload: bytes) -> bytes:
    """Pure-Python RIPEMD160. Reference implementation per Dobbertin,
    Bosselaers, Preneel (1996). Used as a fallback when OpenSSL refuses
    ``ripemd160`` (true on most OpenSSL-3 distros and on Pyodide/WASM).

    Test-vector covered in ``tests/test_ripemd160_fallback.py``.
    """
    return _RIPEMD160().update(payload).digest()


def _select_ripemd160() -> Callable[[bytes], bytes]:
    """Pick the best available RIPEMD160 implementation once at import
    time. Verifies the chosen path matches a known answer so a
    half-broken hashlib (custom OpenSSL build) can't silently produce
    wrong digests."""
    _empty_digest = bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")
    try:
        if _ripemd160_via_hashlib(b"") == _empty_digest:
            return _ripemd160_via_hashlib
    except (ValueError, OSError):
        # ValueError on OpenSSL-3 disabled-legacy-provider; OSError on
        # exotic FIPS-mode builds. Either way: fall through.
        pass
    return _ripemd160_pure_python


_ripemd160_impl = _select_ripemd160()


def ripemd160(payload: bytes) -> bytes:
    return _ripemd160_impl(payload)


def ripemd160_sha256(payload: bytes) -> bytes:
    return ripemd160(sha256(payload))


hash256 = double_sha256
hash160 = ripemd160_sha256


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def hmac_sha512(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha512).digest()


# --------------------------------------------------------------------------
# Pure-Python RIPEMD160 reference implementation.
#
# Direct transcription of the algorithm from Dobbertin et al. (1996).
# The constants, message schedule, rotation table, and round functions
# are exactly as published; renaming any of them obscures the connection
# to the spec for no benefit. Reviewers cross-checking this against the
# reference paper should find a 1:1 mapping.
# --------------------------------------------------------------------------

# fmt: off
# The four tables below mirror the reference paper exactly. Ruff would
# otherwise expand them to one element per line, which is unreviewable
# against the spec. Keep them packed in 16-element rows.

# Per-round 32-bit shift counts — left line and right line.
_ROL_LEFT = (
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
)
_ROL_RIGHT = (
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
)

# Message-word selection tables — left line and right line.
_R_LEFT = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
)
_R_RIGHT = (
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
)

# Per-round added constants — left line and right line.
_K_LEFT = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_K_RIGHT = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
# fmt: on


def _rol(x: int, n: int) -> int:
    """32-bit rotate left."""
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(j: int, x: int, y: int, z: int) -> int:
    """Round function — depends on which 16-step round we're in."""
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & 0xFFFFFFFF & z)
    if j < 48:
        return (x | (~y & 0xFFFFFFFF)) ^ z
    if j < 64:
        return (x & z) | (y & ~z & 0xFFFFFFFF)
    return x ^ (y | (~z & 0xFFFFFFFF))


class _RIPEMD160:
    """Streaming RIPEMD160 state. Modelled on hashlib's hash objects but
    intentionally minimal — we only need ``update`` + ``digest``."""

    def __init__(self) -> None:
        # Initial chaining values — the IV from the spec.
        self._h = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        self._buffer = b""
        self._length = 0  # in bytes, total over the lifetime of the object

    def update(self, data: bytes) -> _RIPEMD160:
        self._buffer += bytes(data)
        self._length += len(data)
        while len(self._buffer) >= 64:
            self._compress(self._buffer[:64])
            self._buffer = self._buffer[64:]
        return self

    def digest(self) -> bytes:
        # Finalise on a copy of the state so re-calling digest() returns
        # the same bytes — never mutate self._h here.
        h = self._h
        buf = self._buffer
        length_bits = self._length * 8

        # Pad: 0x80 then zero bytes until length ≡ 56 (mod 64), then 8-byte
        # little-endian bit count.
        buf += b"\x80"
        while len(buf) % 64 != 56:
            buf += b"\x00"
        buf += struct.pack("<Q", length_bits)

        for offset in range(0, len(buf), 64):
            block = buf[offset : offset + 64]
            h = self._compress_block(block, h)

        return struct.pack("<5I", *h)

    def _compress(self, block: bytes) -> None:
        self._h = self._compress_block(block, self._h)

    @staticmethod
    def _compress_block(block: bytes, hin: tuple) -> tuple:
        x = struct.unpack("<16I", block)
        a_l, b_l, c_l, d_l, e_l = hin
        a_r, b_r, c_r, d_r, e_r = hin

        for j in range(80):
            # Left line.
            t = (a_l + _f(j, b_l, c_l, d_l) + x[_R_LEFT[j]] + _K_LEFT[j // 16]) & 0xFFFFFFFF
            t = (_rol(t, _ROL_LEFT[j]) + e_l) & 0xFFFFFFFF
            a_l, e_l, d_l, c_l, b_l = e_l, d_l, _rol(c_l, 10), b_l, t

            # Right line — round functions counted from the *other* end.
            t = (a_r + _f(79 - j, b_r, c_r, d_r) + x[_R_RIGHT[j]] + _K_RIGHT[j // 16]) & 0xFFFFFFFF
            t = (_rol(t, _ROL_RIGHT[j]) + e_r) & 0xFFFFFFFF
            a_r, e_r, d_r, c_r, b_r = e_r, d_r, _rol(c_r, 10), b_r, t

        h0, h1, h2, h3, h4 = hin
        return (
            (h1 + c_l + d_r) & 0xFFFFFFFF,
            (h2 + d_l + e_r) & 0xFFFFFFFF,
            (h3 + e_l + a_r) & 0xFFFFFFFF,
            (h4 + a_l + b_r) & 0xFFFFFFFF,
            (h0 + b_l + c_r) & 0xFFFFFFFF,
        )

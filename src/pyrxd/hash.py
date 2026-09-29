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

SHA-512/256, the Radiant block hash, has the same shape for the same reason: ``hashlib`` where it
has one, a pure-Python FIPS 180-4 implementation where it does not (Pyodide). See
:func:`_sha512_256` and ``tests/test_sha512_256_fallback.py``.
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


def radiant_block_hash(header: bytes) -> str:
    """The Radiant block hash of an 80-byte header, in display order: double SHA-512/256, reversed.

    The ONE definition. :func:`pyrxd.network.registry.block_hash_hex` validates its argument and
    delegates here; it lives in this module because it must be importable without
    ``pyrxd.network`` (whose ``__init__`` loads the ElectrumX and Bitcoin clients), so the
    browser-importable :mod:`pyrxd.glyph.mark_anchor` can bind a height to a header too.

    Raises ``ValueError`` if *header* is not 80 bytes, or if this runtime cannot compute
    SHA-512/256 at all (see :func:`_sha512_256`; with the pure-Python fallback, that takes the
    fallback itself failing).
    """
    if not isinstance(header, (bytes, bytearray)) or len(header) != 80:
        raise ValueError("a Radiant block header is exactly 80 bytes")
    once = _sha512_256(bytes(header))
    return _sha512_256(once)[::-1].hex()


def _sha512_256(payload: bytes) -> bytes:
    """SHA-512/256 of *payload*: ``hashlib``'s where it has one, else :func:`_sha512_256_pure_python`.

    CPython with OpenSSL has ``sha512_256``. Pyodide 0.26.4 does NOT: its ``hashlib`` raises
    ``ValueError("unsupported hash type sha512_256")`` unless Pyodide's OpenSSL package is loaded
    first, and the ``/inspect/`` and ``/verify/`` pages no longer load it (#757) — with it, a
    CDN-served OpenSSL 1.1.1n (end of life) computed every hash on the page, the signature
    check's included, for the sake of this one function.

    Decided per call rather than once at import, unlike RIPEMD160 below: the fallback's own cost
    dwarfs one caught ``ValueError``, and a test can then reproduce Pyodide by making
    ``hashlib.new`` refuse the name, without reaching into this module.

    If the fallback fails too, the ``ValueError`` STARTS with the fallback's own error — the
    unexpected one, since ``hashlib`` refusing is simply Pyodide — and only then says where it
    happened and why ``hashlib`` could not help. It starts there because callers cap what they
    display: the pages' ``glue.py`` shows 80 characters, and a preamble would fill them.
    """
    try:
        return hashlib.new("sha512_256", payload).digest()
    except ValueError as unsupported:
        try:
            return _sha512_256_pure_python(payload)
        except Exception as exc:
            raise ValueError(
                f"{type(exc).__name__}: {exc} — in the pure-Python SHA-512/256, run because hashlib "
                f"has none ({unsupported})"
            ) from exc


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
    except Exception:  # nosec B110 -- intentional broad catch; see comment below
        # If ``hashlib`` is unusable for any reason, fall through to the
        # pure-Python path. Better to be slow than to fail import:
        # ``pyrxd.hash`` is imported during package init, so an
        # exception here would abort every downstream caller.
        # Concrete cases this catches:
        #   - ValueError: OpenSSL-3 with the legacy provider unloaded
        #     (the common case on Ubuntu 24.04 / Debian 12 / macOS
        #     python.org installer).
        #   - OSError: exotic FIPS-mode OpenSSL builds.
        #   - RuntimeError / AttributeError / ImportError: degenerate
        #     hashlib environments (vendored Python stubs, partial
        #     namespace packages, pyodide-style platform variants).
        # Bandit flags the bare ``except: pass`` shape (B110); annotated
        # nosec because the failure-mode is an exhaustively-enumerated
        # universe of "hashlib can't help us right now" — we want to
        # gracefully degrade, not fail closed.
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


#: RIPEMD160's chaining value: five 32-bit words. Spelled out rather than left
#: as a bare ``tuple`` because ``pyrxd.security`` now reaches this module through
#: ``pyrxd.base58`` (the WIF decoder was consolidated onto the one base58 codec),
#: and that package is typechecked strictly.
_ChainingValue = tuple[int, int, int, int, int]


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
    def _compress_block(block: bytes, hin: _ChainingValue) -> _ChainingValue:
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


# --------------------------------------------------------------------------
# Pure-Python SHA-512/256 — the Radiant block hash's fallback (#757).
#
# FIPS 180-4: SHA-512 (§6.4) started from the SHA-512/256 initial hash value
# (§5.3.6.2) instead of SHA-512's, with the 512-bit result truncated to its
# leftmost 256 bits (§6.7). Padding is §5.1.2, the schedule and round functions
# are §4.1.3 / §6.4.2, the constants §4.2.3. Only ever reached where ``hashlib``
# has no ``sha512_256`` (Pyodide without its OpenSSL package); on CPython the
# C path is taken and this is what tests compare it against, in
# ``tests/test_sha512_256_fallback.py``.
# --------------------------------------------------------------------------

_MASK64 = 0xFFFFFFFFFFFFFFFF

# fmt: off
# Kept in rows of four, as FIPS 180-4 §4.2.3 prints them, so the table can be read against it.

#: SHA-512's 80 round constants (FIPS 180-4 §4.2.3): the first 64 bits of the fractional parts
#: of the cube roots of the first 80 primes.
_SHA512_K = (
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
)

#: The SHA-512/256 initial hash value, FIPS 180-4 §5.3.6.2. This, and the truncation, are all
#: that distinguish SHA-512/256 from SHA-512.
_SHA512_256_IV = (
    0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD,
    0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2,
)
# fmt: on

_Sha512State = tuple[int, int, int, int, int, int, int, int]


def _rotr64(x: int, n: int) -> int:
    """64-bit rotate right (FIPS 180-4 §3.2 ROTR^n)."""
    return ((x >> n) | (x << (64 - n))) & _MASK64


def _sha512_compress(state: _Sha512State, block: bytes) -> _Sha512State:
    """One SHA-512 compression of a 128-byte *block* into *state* (FIPS 180-4 §6.4.2)."""
    w = list(struct.unpack(">16Q", block))
    for t in range(16, 80):
        s0 = _rotr64(w[t - 15], 1) ^ _rotr64(w[t - 15], 8) ^ (w[t - 15] >> 7)
        s1 = _rotr64(w[t - 2], 19) ^ _rotr64(w[t - 2], 61) ^ (w[t - 2] >> 6)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK64)

    a, b, c, d, e, f, g, h = state
    for t in range(80):
        big_s1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)
        ch = (e & f) ^ (~e & _MASK64 & g)
        t1 = (h + big_s1 + ch + _SHA512_K[t] + w[t]) & _MASK64
        big_s0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + maj) & _MASK64
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK64, c, b, a, (t1 + t2) & _MASK64

    return (
        (state[0] + a) & _MASK64,
        (state[1] + b) & _MASK64,
        (state[2] + c) & _MASK64,
        (state[3] + d) & _MASK64,
        (state[4] + e) & _MASK64,
        (state[5] + f) & _MASK64,
        (state[6] + g) & _MASK64,
        (state[7] + h) & _MASK64,
    )


def _sha512_padding(length: int) -> bytes:
    """What FIPS 180-4 §5.1.2 appends to a message of *length* bytes: a single 1 bit, zeros until
    the length is 896 mod 1024 bits, then the message length IN BITS as a 128-bit big-endian
    integer. Separate so the length field can be tested at lengths no test could hash."""
    return b"\x80" + b"\x00" * ((111 - length) % 128) + (length * 8).to_bytes(16, "big")


def _sha512_256_pure_python(payload: bytes) -> bytes:
    """SHA-512/256 in pure Python: SHA-512 from the §5.3.6.2 initial value, truncated to 256 bits.

    Tested against ``hashlib.new("sha512_256")`` in ``tests/test_sha512_256_fallback.py``: the
    FIPS examples, every length across the padding boundaries, fixed 8 KiB and 1 MiB inputs,
    random inputs, and real Radiant mainnet headers. Reached only through :func:`_sha512_256`.
    """
    data = bytes(payload)
    padded = data + _sha512_padding(len(data))
    state: _Sha512State = _SHA512_256_IV
    for offset in range(0, len(padded), 128):
        state = _sha512_compress(state, padded[offset : offset + 128])
    # §6.7: the leftmost 256 bits of the final hash value.
    return struct.pack(">8Q", *state)[:32]

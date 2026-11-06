"""A pure-Python stand-in for the part of ``coincurve`` pyrxd uses, for the playground ONLY.

WHY THIS EXISTS. ``pyrxd.keys`` imports ``coincurve`` at module top level, and coincurve is
a C extension with no Pyodide build (it is not in Pyodide 0.26.4's package lock). Without a
curve, nothing in the browser can derive an address or sign a transaction, so the playground
installs this module as ``sys.modules["coincurve"]`` before it imports ``pyrxd.keys``.

WHAT IT IS NOT. It is not constant-time, it has had no review a wallet would need, and it
must never sign for a key that holds value. The playground only ever hands it keys it
generated for a chain that exists inside one browser tab. The page says so, and its network
policy (``connect-src``) has no node to send anything to. Nothing in ``src/pyrxd`` imports
this file, and the published wheel does not contain it.

HOW IT IS KEPT HONEST. The surface is the one ``src/pyrxd/keys.py`` and ``src/pyrxd/curve.py``
call, and ``tests/web/test_playground_curve_matches_coincurve.py`` checks every entry point
against the real coincurve under CPython: public keys, byte-identical DER and recoverable
signatures (both are deterministic RFC 6979 with low-s), verify verdicts on honest and
mutated signatures, DER parse accept/reject, recovery, point add and multiply.

Behaviour copied from libsecp256k1 as coincurve exposes it:

* ``sign`` uses RFC 6979 (HMAC-SHA256, key || msg32, no extra data) and normalises to low-s.
* ``verify`` returns False for a high-s signature, as ``secp256k1_ecdsa_verify`` does.
* ``der_to_cdata`` raises ``ValueError`` for anything that is not strict DER, as
  ``secp256k1_ecdsa_signature_parse_der`` does. An r or s at or above the group order parses,
  and then never verifies.
* hasher semantics: a callable is applied to the message; ``None`` means the message is
  already the 32-byte digest.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import types
from collections.abc import Callable

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_HALF_N = N // 2

Affine = tuple[int, int] | None  # None is the point at infinity


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ---------------------------------------------------------------------------
# Field and group arithmetic (Jacobian coordinates)
# ---------------------------------------------------------------------------


def _jac_double(x: int, y: int, z: int) -> tuple[int, int, int]:
    if y == 0 or z == 0:
        return 0, 1, 0
    ysq = y * y % P
    s = 4 * x * ysq % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    ny = (m * (s - nx) - 8 * ysq * ysq) % P
    nz = 2 * y * z % P
    return nx, ny, nz


def _jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    z1s = z1 * z1 % P
    z2s = z2 * z2 % P
    u1 = x1 * z2s % P
    u2 = x2 * z1s % P
    s1 = y1 * z2s * z2 % P
    s2 = y2 * z1s * z1 % P
    if u1 == u2:
        if s1 != s2:
            return 0, 1, 0
        return _jac_double(x1, y1, z1)
    h = (u2 - u1) % P
    r = (s2 - s1) % P
    h2 = h * h % P
    h3 = h * h2 % P
    u1h2 = u1 * h2 % P
    nx = (r * r - h3 - 2 * u1h2) % P
    ny = (r * (u1h2 - nx) - s1 * h3) % P
    nz = h * z1 * z2 % P
    return nx, ny, nz


def _to_affine(j: tuple[int, int, int]) -> Affine:
    x, y, z = j
    if z == 0:
        return None
    zinv = pow(z, -1, P)
    zinv2 = zinv * zinv % P
    return x * zinv2 % P, y * zinv2 * zinv % P


def _to_jac(a: Affine) -> tuple[int, int, int]:
    if a is None:
        return 0, 1, 0
    return a[0], a[1], 1


def point_add(a: Affine, b: Affine) -> Affine:
    return _to_affine(_jac_add(_to_jac(a), _to_jac(b)))


def point_mul(k: int, a: Affine) -> Affine:
    k %= N
    if k == 0 or a is None:
        return None
    result = (0, 1, 0)
    addend = _to_jac(a)
    while k:
        if k & 1:
            result = _jac_add(result, addend)
        addend = _jac_double(*addend)
        k >>= 1
    return _to_affine(result)


# 2^i * G for i in 0..255, so k*G is additions only.
_G_POWERS: list[tuple[int, int, int]] = []


def _g_mul(k: int) -> Affine:
    k %= N
    if k == 0:
        return None
    if not _G_POWERS:
        cur = (GX, GY, 1)
        for _ in range(256):
            _G_POWERS.append(cur)
            cur = _jac_double(*cur)
    result = (0, 1, 0)
    i = 0
    while k:
        if k & 1:
            result = _jac_add(result, _G_POWERS[i])
        k >>= 1
        i += 1
    return _to_affine(result)


def _on_curve(x: int, y: int) -> bool:
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x - 7) % P == 0


def _lift_x(x: int, odd: bool) -> Affine:
    if not 0 <= x < P:
        return None
    c = (x * x * x + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if y * y % P != c:
        return None
    if (y & 1) != int(odd):
        y = P - y
    return x, y


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def _int32(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _b32(n: int) -> bytes:
    return n.to_bytes(32, "big")


def _parse_pubkey(data: bytes) -> tuple[int, int]:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("public key must be bytes")
    data = bytes(data)
    if len(data) == 33 and data[0] in (2, 3):
        pt = _lift_x(_int32(data[1:]), data[0] == 3)
        if pt is None:
            raise ValueError("The public key could not be parsed or is invalid.")
        return pt
    if len(data) == 65 and data[0] in (4, 6, 7):
        x, y = _int32(data[1:33]), _int32(data[33:])
        if not _on_curve(x, y):
            raise ValueError("The public key could not be parsed or is invalid.")
        if data[0] in (6, 7) and (y & 1) != (data[0] & 1):
            raise ValueError("The public key could not be parsed or is invalid.")
        return x, y
    raise ValueError("The public key could not be parsed or is invalid.")


def _der_int(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def _der_encode(r: int, s: int) -> bytes:
    body = _der_int(r) + _der_int(s)
    return b"\x30" + bytes([len(body)]) + body


def _der_read_len(sig: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(sig):
        raise ValueError("The DER-encoded signature could not be parsed.")
    first = sig[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    nbytes = first & 0x7F
    if first == 0xFF or nbytes == 0 or nbytes > len(sig) - pos:
        raise ValueError("The DER-encoded signature could not be parsed.")
    if sig[pos] == 0:
        raise ValueError("The DER-encoded signature could not be parsed.")
    length = int.from_bytes(sig[pos : pos + nbytes], "big")
    if length < 0x80:
        raise ValueError("The DER-encoded signature could not be parsed.")
    return length, pos + nbytes


def _der_read_int(sig: bytes, pos: int, end: int) -> tuple[int, int]:
    if pos >= end or sig[pos] != 0x02:
        raise ValueError("The DER-encoded signature could not be parsed.")
    length, pos = _der_read_len(sig, pos + 1)
    if length == 0 or length > end - pos:
        raise ValueError("The DER-encoded signature could not be parsed.")
    body = sig[pos : pos + length]
    # libsecp256k1's secp256k1_der_parse_integer: excessive 0x00 or 0xFF padding is a
    # parse failure; a negative integer parses, as an overflow that never verifies.
    if length > 1 and body[0] == 0 and not body[1] & 0x80:
        raise ValueError("The DER-encoded signature could not be parsed.")
    if length > 1 and body[0] == 0xFF and body[1] & 0x80:
        raise ValueError("The DER-encoded signature could not be parsed.")
    value = N if body[0] & 0x80 else int.from_bytes(body, "big")
    return value, pos + length


def _der_decode(sig: bytes) -> tuple[int, int]:
    """Strict DER, the shape ``secp256k1_ecdsa_signature_parse_der`` accepts.

    An integer at or above the group order parses (libsecp256k1 stores an all-zero
    signature for it, which then never verifies); this returns it as is and ``_verify``
    refuses it.
    """
    if not isinstance(sig, (bytes, bytearray)):
        raise TypeError("signature must be bytes")
    sig = bytes(sig)
    if len(sig) < 2 or sig[0] != 0x30:
        raise ValueError("The DER-encoded signature could not be parsed.")
    length, pos = _der_read_len(sig, 1)
    if length != len(sig) - pos:
        raise ValueError("The DER-encoded signature could not be parsed.")
    end = len(sig)
    r, pos = _der_read_int(sig, pos, end)
    s, pos = _der_read_int(sig, pos, end)
    if pos != end:
        raise ValueError("The DER-encoded signature could not be parsed.")
    return r, s


def _digest(message: bytes, hasher: Callable[[bytes], bytes] | None) -> bytes:
    msg_hash = hasher(message) if hasher is not None else message
    if len(msg_hash) != 32:
        raise ValueError("Message hash must be 32 bytes long.")
    return msg_hash


# ---------------------------------------------------------------------------
# ECDSA
# ---------------------------------------------------------------------------


def _rfc6979_nonces(secret: bytes, msg32: bytes):
    """RFC 6979 §3.2 with HMAC-SHA256, as libsecp256k1's default nonce function."""
    k = b"\x00" * 32
    v = b"\x01" * 32
    data = secret + msg32
    k = hmac.new(k, v + b"\x00" + data, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + data, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = _int32(v)
        if 1 <= candidate < N:
            yield candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def _sign(secret: bytes, msg32: bytes) -> tuple[int, int, int]:
    d = _int32(secret)
    z = _int32(msg32)
    for k in _rfc6979_nonces(secret, msg32):
        R = _g_mul(k)
        assert R is not None  # k is in [1, n-1]
        r = R[0] % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (z + r * d) % N
        if s == 0:
            continue
        recid = (R[1] & 1) | (2 if R[0] >= N else 0)
        if s > _HALF_N:
            s = N - s
            recid ^= 1
        return r, s, recid
    raise ValueError("The nonce generation function failed, or the private key was invalid.")  # pragma: no cover


def _verify(pub: tuple[int, int], r: int, s: int, msg32: bytes) -> bool:
    if not (1 <= r < N and 1 <= s < N) or s > _HALF_N:
        return False
    z = _int32(msg32)
    w = pow(s, -1, N)
    pt = point_add(_g_mul(z * w % N), point_mul(r * w % N, pub))
    return pt is not None and pt[0] % N == r


def _recover(msg32: bytes, r: int, s: int, recid: int) -> tuple[int, int]:
    if not (1 <= r < N and 1 <= s < N) or not 0 <= recid <= 3:
        raise ValueError("Recovery of the ECDSA public key failed.")
    x = r + (N if recid & 2 else 0)
    R = _lift_x(x, bool(recid & 1))
    if R is None:
        raise ValueError("Recovery of the ECDSA public key failed.")
    z = _int32(msg32)
    rinv = pow(r, -1, N)
    q = point_add(point_mul(s * rinv % N, R), _g_mul(-z * rinv % N))
    if q is None:
        raise ValueError("Recovery of the ECDSA public key failed.")
    return q


# ---------------------------------------------------------------------------
# The coincurve-shaped classes
# ---------------------------------------------------------------------------


def _validate_secret(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    secret = bytes(secret)
    if len(secret) < 32:
        secret = secret.rjust(32, b"\x00")
    if len(secret) != 32 or not 0 < _int32(secret) < N:
        raise ValueError("Secret scalar must be greater than 0 and less than the group order.")
    return secret


class PublicKey:
    def __init__(self, data: bytes) -> None:
        if isinstance(data, tuple):
            self._pt = data
        else:
            self._pt = _parse_pubkey(data)

    @classmethod
    def from_point(cls, x: int, y: int) -> PublicKey:
        return cls(b"\x04" + _b32(x) + _b32(y))

    @classmethod
    def from_secret(cls, secret: bytes) -> PublicKey:
        pt = _g_mul(_int32(_validate_secret(secret)))
        assert pt is not None
        return cls(pt)

    @classmethod
    def from_signature_and_message(
        cls, signature: bytes, message: bytes, hasher: Callable[[bytes], bytes] | None = _sha256
    ) -> PublicKey:
        if len(signature) != 65:
            raise ValueError("Serialized signature must be 65 bytes long.")
        msg32 = _digest(message, hasher)
        return cls(_recover(msg32, _int32(signature[:32]), _int32(signature[32:64]), signature[64]))

    @classmethod
    def combine_keys(cls, public_keys: list[PublicKey]) -> PublicKey:
        acc: Affine = None
        for pk in public_keys:
            acc = point_add(acc, pk._pt)
        if acc is None:
            raise ValueError("The sum of the public keys is invalid.")
        return cls(acc)

    def format(self, compressed: bool = True) -> bytes:
        x, y = self._pt
        if compressed:
            return bytes([2 + (y & 1)]) + _b32(x)
        return b"\x04" + _b32(x) + _b32(y)

    def point(self) -> tuple[int, int]:
        return self._pt

    def verify(self, signature: bytes, message: bytes, hasher: Callable[[bytes], bytes] | None = _sha256) -> bool:
        msg32 = _digest(message, hasher)
        r, s = _der_decode(signature)
        return _verify(self._pt, r, s, msg32)

    def multiply(self, scalar: bytes) -> PublicKey:
        pt = point_mul(_int32(_validate_secret(scalar)), self._pt)
        assert pt is not None
        return PublicKey(pt)

    def add(self, scalar: bytes) -> PublicKey:
        scalar = bytes(scalar).rjust(32, b"\x00")
        t = _int32(scalar)
        if t >= N:
            raise ValueError("The tweak was out of range, or the resulting public key is invalid.")
        pt = point_add(self._pt, _g_mul(t))
        if pt is None:
            raise ValueError("The tweak was out of range, or the resulting public key is invalid.")
        return PublicKey(pt)

    def combine(self, public_keys: list[PublicKey]) -> PublicKey:
        return PublicKey.combine_keys([self, *public_keys])

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicKey) and self._pt == other._pt

    def __hash__(self) -> int:
        return hash(self._pt)


class PrivateKey:
    def __init__(self, secret: bytes | None = None) -> None:
        if secret is None:
            while True:
                candidate = os.urandom(32)
                if 0 < _int32(candidate) < N:
                    secret = candidate
                    break
        self.secret: bytes = _validate_secret(secret)
        self.public_key: PublicKey = PublicKey.from_secret(self.secret)

    @classmethod
    def from_int(cls, num: int) -> PrivateKey:
        return cls(num.to_bytes(32, "big"))

    @classmethod
    def from_hex(cls, hexed: str) -> PrivateKey:
        return cls(bytes.fromhex(hexed))

    @classmethod
    def from_der(cls, der: bytes) -> PrivateKey:
        raise NotImplementedError("DER private keys are not supported in the playground")

    @classmethod
    def from_pem(cls, pem: bytes) -> PrivateKey:
        raise NotImplementedError("PEM private keys are not supported in the playground")

    def to_int(self) -> int:
        return _int32(self.secret)

    def to_hex(self) -> str:
        return self.secret.hex()

    def to_der(self) -> bytes:
        raise NotImplementedError("DER private keys are not supported in the playground")

    def to_pem(self) -> bytes:
        raise NotImplementedError("PEM private keys are not supported in the playground")

    def sign(self, message: bytes, hasher: Callable[[bytes], bytes] | None = _sha256) -> bytes:
        r, s, _ = _sign(self.secret, _digest(message, hasher))
        return _der_encode(r, s)

    def sign_recoverable(self, message: bytes, hasher: Callable[[bytes], bytes] | None = _sha256) -> bytes:
        r, s, recid = _sign(self.secret, _digest(message, hasher))
        return _b32(r) + _b32(s) + bytes([recid])

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PrivateKey) and hmac.compare_digest(self.secret, other.secret)

    def __hash__(self) -> int:
        return hash(self.secret)

    def __repr__(self) -> str:
        return "<sandbox PrivateKey>"


def der_to_cdata(der: bytes) -> tuple[int, int]:
    return _der_decode(der)


def cdata_to_der(sig: tuple[int, int]) -> bytes:
    return _der_encode(*sig)


def install() -> None:
    """Register this module as ``coincurve`` (and ``coincurve.ecdsa``) in ``sys.modules``.

    Refuses if a real coincurve is already importable, so CPython test runs and any
    environment with the genuine library keep using it.
    """
    existing = sys.modules.get("coincurve")
    if existing is not None and getattr(existing, "_PYRXD_PLAYGROUND_SHIM", False):
        return
    try:
        import coincurve  # noqa: F401
    except ImportError:
        pass
    else:
        raise RuntimeError("a real coincurve is importable here; the playground shim is for Pyodide only")
    mod = types.ModuleType("coincurve")
    mod.PrivateKey = PrivateKey  # type: ignore[attr-defined]
    mod.PublicKey = PublicKey  # type: ignore[attr-defined]
    mod._PYRXD_PLAYGROUND_SHIM = True  # type: ignore[attr-defined]
    ecdsa = types.ModuleType("coincurve.ecdsa")
    ecdsa.der_to_cdata = der_to_cdata  # type: ignore[attr-defined]
    ecdsa.cdata_to_der = cdata_to_der  # type: ignore[attr-defined]
    mod.ecdsa = ecdsa  # type: ignore[attr-defined]
    sys.modules["coincurve"] = mod
    sys.modules["coincurve.ecdsa"] = ecdsa

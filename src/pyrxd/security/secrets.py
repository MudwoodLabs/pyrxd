"""Wrappers for secret byte material (private keys, shared secrets, etc.).

Design rules
------------
* ``__repr__`` and ``__str__`` never include the raw bytes.
* Equality uses :func:`hmac.compare_digest` (constant-time) so timing-oracle
  attacks on secret comparison are not possible at the Python level.
* ``__hash__`` is disabled. A hashable ``SecretBytes`` would expose the secret
  to any dict/set side channel and make it a leak risk in structured logs.
* ``zeroize()`` best-effort overwrites the internal ``bytearray`` with zeros.
  CPython's memory model means copies may survive in the interpreter, but
  zeroizing what we control is still defense-in-depth.
* ``unsafe_raw_bytes()`` is the ONLY way to get the underlying bytes. The
  name is intentionally long and ugly for grep-in-code-review visibility.
"""

from __future__ import annotations

import ctypes
import hmac
from typing import Any, SupportsIndex

from .errors import KeyMaterialError
from .rng import secure_scalar_bytes_mod_n

__all__ = ["PrivateKeyMaterial", "SecretBytes", "secure_scalar_mod_n"]

# secp256k1 curve order
_SECP256K1_N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# --------------------------------------------------------------------------- base58check
def _base58check_decode(s: str) -> bytes:
    """Decode a base58check string via the SDK's one base58 codec.

    This module used to carry a second, self-contained implementation "so the
    security module has no heavy deps". The dependency was never heavy —
    :mod:`pyrxd.base58` imports ``hashlib`` and one exception class — and the
    cost of the second copy was real: two independent WIF decoders, either of
    which could come to accept a string the other rejects. Since
    :meth:`PrivateKeyMaterial.from_wif` and :func:`pyrxd.utils.decode_wif` are
    both entry points for the same private keys, a divergence between them is a
    divergence about what somebody's key *is*.

    The import is function-local because :mod:`pyrxd.base58` imports
    ``pyrxd.security.errors``, and ``pyrxd/security/__init__.py`` imports THIS
    module. A module-scope import would work today only because ``.errors``
    happens to be imported before ``.secrets`` in that ``__init__``; deferring
    it means the import graph does not depend on that ordering. (The same
    function-local pattern is already used in ``gravity/codehash.py`` and
    ``gravity/transactions.py``.)

    Everything this copy did that the shared codec did not now lives in the
    shared codec: constant-time checksum comparison, and rejecting a payload too
    short to contain one. Both were strengthenings, applied to every caller.
    """
    from ..base58 import base58check_decode

    return base58check_decode(s)


class SecretBytes:
    """A wrapper around ``bytes`` that will not leak its contents on repr/str.

    The internal storage is a :class:`bytearray` so :meth:`zeroize` can mutate
    it in place. ``unsafe_raw_bytes`` returns an immutable ``bytes`` copy.
    """

    __slots__ = ("_buf", "_zeroed")

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SecretBytes requires bytes or bytearray input")
        # Copy into a mutable bytearray we own so zeroize can scrub it.
        self._buf: bytearray = bytearray(data)
        self._zeroed: bool = False

    # ------------------------------------------------------------------ repr
    def __repr__(self) -> str:
        return f"<SecretBytes:{len(self._buf)}b>"

    def __str__(self) -> str:
        return self.__repr__()

    # ------------------------------------------------------------------ eq
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretBytes):
            return NotImplemented
        # Constant-time comparison defends against timing side channels.
        return hmac.compare_digest(bytes(self._buf), bytes(other._buf))

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return NotImplemented
        return not result

    # SecretBytes is not hashable — putting secrets in dict/set risks leaking via hash collisions.
    __hash__ = None  # type: ignore[assignment]

    # ------------------------------------------------------------------ serialization guards
    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError(
            f"{type(self).__name__} cannot be pickled — serializing secret material "
            "to a byte stream defeats the purpose of in-memory protection."
        )

    __reduce__ = __reduce_ex__  # type: ignore[assignment]

    def __copy__(self) -> SecretBytes:
        raise TypeError(f"{type(self).__name__} cannot be copied (use explicit construction)")

    def __deepcopy__(self, memo: dict[int, Any]) -> SecretBytes:
        raise TypeError(f"{type(self).__name__} cannot be deep-copied (use explicit construction)")

    def __len__(self) -> int:
        return len(self._buf)

    # ------------------------------------------------------------------ mutation / access
    def zeroize(self) -> None:
        """Best-effort overwrite of the internal buffer with zeros.

        Python's memory model does not guarantee that every copy of a string or
        bytes object is scrubbed; only the buffer we own is cleared. Call this
        when you know a key will not be used again.
        """
        if self._zeroed:
            return
        buf_len = len(self._buf)
        if buf_len:
            # ctypes.memset on the underlying buffer. Works on CPython where
            # bytearray exposes a stable address via c_char * len.
            addr_type = ctypes.c_char * buf_len
            try:
                addr = addr_type.from_buffer(self._buf)
                ctypes.memset(ctypes.addressof(addr), 0, buf_len)
            except (TypeError, ValueError):
                # Buffer cannot be locked (e.g. under memoryview). Fall back
                # to Python-level zero fill.
                for i in range(buf_len):
                    self._buf[i] = 0
        self._zeroed = True

    def unsafe_raw_bytes(self) -> bytes:
        """Return the raw secret bytes.

        Named ``unsafe_*`` on purpose: every call site should be auditable
        with a single ``grep``. Prefer SDK methods that consume ``SecretBytes``
        directly over pulling the raw bytes out.
        """
        if self._zeroed:
            raise KeyMaterialError("attempt to access secret after zeroize()")
        return bytes(self._buf)

    # ------------------------------------------------------------------ factories
    @classmethod
    def from_hex(cls, h: str) -> SecretBytes:
        """Construct from a hex string.

        The hex string itself is not embedded in any error message — an
        attacker who can see the exception must not learn the invalid input
        was "0x..." with specific bytes.
        """
        if not isinstance(h, str):
            raise KeyMaterialError("hex input must be a string")
        try:
            data = bytes.fromhex(h)
        except ValueError:
            raise KeyMaterialError("invalid hex string for SecretBytes") from None
        return cls(data)

    # ------------------------------------------------------------------ lifecycle
    def __del__(self) -> None:
        # Best-effort zeroize on GC. May not run (interpreter shutdown, cycles),
        # but costs nothing to attempt.
        try:
            self.zeroize()
        except Exception:
            pass  # nosec B110


class PrivateKeyMaterial(SecretBytes):
    """A :class:`SecretBytes` whose contents are a valid secp256k1 private key.

    Invariants enforced at construction:
      * length is exactly 32 bytes
      * integer value is in the valid scalar range ``[1, N-1]``
    """

    __slots__ = ()

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise KeyMaterialError("private key must be bytes or bytearray")
        if len(data) != 32:
            # Length is not secret; keep the message useful.
            raise KeyMaterialError(f"private key must be 32 bytes, got {len(data)}")
        scalar = int.from_bytes(bytes(data), "big")
        if scalar == 0:
            raise KeyMaterialError("private key scalar is zero")
        if scalar >= _SECP256K1_N:
            raise KeyMaterialError("private key scalar is >= curve order N")
        super().__init__(bytes(data))

    def __repr__(self) -> str:
        # No length either — the length is known (32), but leaking nothing
        # at all keeps logs trivial to review.
        return "<PrivateKeyMaterial>"

    # ------------------------------------------------------------------ factories
    @classmethod
    def from_wif(cls, wif: str) -> PrivateKeyMaterial:
        """Decode a WIF-encoded private key.

        On failure raises :class:`KeyMaterialError` WITHOUT embedding the
        input ``wif`` in the message — an attacker watching logs must not
        learn any part of the candidate key.

        Implementation is self-contained (no heavy coincurve dependency) so
        the security module can be imported before the rest of the SDK.
        """
        if not isinstance(wif, str):
            raise KeyMaterialError("WIF must be a string")

        decoded_arr: bytearray | None = None
        try:
            try:
                decoded_arr = bytearray(_base58check_decode(wif))
            except Exception:
                # Do not chain; the original exception message may echo the input.
                raise KeyMaterialError("invalid WIF") from None

            # WIF layout: 1-byte network prefix + 32-byte key [+ 0x01 compressed flag]
            if len(decoded_arr) == 34 and decoded_arr[-1] == 0x01:
                key_bytes = bytes(decoded_arr[1:-1])
            elif len(decoded_arr) == 33:
                key_bytes = bytes(decoded_arr[1:])
            else:
                raise KeyMaterialError("invalid WIF length")

            return cls(key_bytes)
        finally:
            # Zero the bytearray holding the full decoded payload (network prefix
            # + raw key bytes + optional compression flag) before it is freed.
            # Using bytearray allows in-place zeroing, unlike immutable bytes.
            if decoded_arr is not None:
                for i in range(len(decoded_arr)):
                    decoded_arr[i] = 0

    @classmethod
    def generate(cls) -> PrivateKeyMaterial:
        """Generate a fresh random private key using the secure RNG."""
        return cls(secure_scalar_bytes_mod_n())


def secure_scalar_mod_n() -> PrivateKeyMaterial:
    """Draw a uniform random scalar in ``[1, N-1]`` and return it wrapped.

    Convenience wrapper combining :func:`pyrxd.security.rng.secure_scalar_bytes_mod_n`
    with :class:`PrivateKeyMaterial`. Lives in this module (not :mod:`.rng`)
    so :mod:`.rng` has no dependency on :class:`PrivateKeyMaterial` —
    that keeps the import graph acyclic.
    """
    return PrivateKeyMaterial(secure_scalar_bytes_mod_n())

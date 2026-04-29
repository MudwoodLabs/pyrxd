"""Secure random-number helpers.

All randomness used for key generation, nonces, or anything security-critical
must come from this module. Never use :mod:`random` — it is a PRNG seeded
from system time by default and unsuitable for cryptographic purposes.
"""

from __future__ import annotations

import secrets as _pysecrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .secrets import PrivateKeyMaterial

__all__ = ["secure_random_bytes", "secure_scalar_mod_n"]

# secp256k1 curve order -- duplicated from secrets.py so rng.py has no
# circular import dependency at module-import time.
_SECP256K1_N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Rejection-sampling fail-safe: probability of needing >100 draws is roughly
# (1 - N/2^256)^100 which is effectively zero (~10^-38). If we ever hit this
# limit something is catastrophically wrong with the RNG.
_MAX_REJECTION_ATTEMPTS: int = 100


def secure_random_bytes(n: int) -> bytes:
    """Return ``n`` cryptographically secure random bytes.

    Thin wrapper over :func:`secrets.token_bytes`. Exists so callers have a
    single chokepoint to audit/mock and so the ``n <= 0`` guard lives in one
    place.
    """
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n <= 0:
        raise ValueError("n must be > 0")
    return _pysecrets.token_bytes(n)


def secure_scalar_mod_n() -> "PrivateKeyMaterial":
    """Draw a uniform random scalar in ``[1, N-1]`` via rejection sampling.

    Returns a :class:`PrivateKeyMaterial` so the result is wrapped in the
    leak-resistant container immediately. The caller never sees raw bytes.

    The rejection loop has a hard upper bound; reaching it indicates the
    system RNG is broken, which is a fatal condition we surface explicitly.
    """
    # Lazy import so this module can be imported before secrets.py finishes.
    from .secrets import PrivateKeyMaterial

    for _attempt in range(_MAX_REJECTION_ATTEMPTS):
        candidate = secure_random_bytes(32)
        scalar = int.from_bytes(candidate, "big")
        if 1 <= scalar < _SECP256K1_N:
            return PrivateKeyMaterial(candidate)

    # Unreachable under a functioning RNG. Raising RuntimeError instead of
    # looping forever keeps the process from hanging if the RNG is broken.
    raise RuntimeError(
        "secure_scalar_mod_n exhausted rejection attempts; RNG may be broken"
    )

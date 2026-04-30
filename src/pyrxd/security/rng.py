"""Secure random-number helpers.

All randomness used for key generation, nonces, or anything security-critical
must come from this module. Never use :mod:`random` — it is a PRNG seeded
from system time by default and unsuitable for cryptographic purposes.
"""

from __future__ import annotations

import secrets as _pysecrets

__all__ = [
    "secure_random_bytes",
    "secure_scalar_bytes_mod_n",
]

# secp256k1 curve order.
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


def secure_scalar_bytes_mod_n() -> bytes:
    """Draw a uniform random scalar in ``[1, N-1]`` via rejection sampling.

    Returns the raw 32-byte big-endian scalar. Callers in :mod:`.secrets`
    wrap this in :class:`PrivateKeyMaterial` to get the leak-resistant
    container — splitting the wrap step keeps this module free of any
    dependency on :mod:`.secrets` (avoids a circular import).

    The rejection loop has a hard upper bound; reaching it indicates the
    system RNG is broken, which is a fatal condition we surface explicitly.
    """
    for _attempt in range(_MAX_REJECTION_ATTEMPTS):
        candidate = secure_random_bytes(32)
        scalar = int.from_bytes(candidate, "big")
        if 1 <= scalar < _SECP256K1_N:
            return candidate

    # Unreachable under a functioning RNG. Raising RuntimeError instead of
    # looping forever keeps the process from hanging if the RNG is broken.
    raise RuntimeError(
        "secure_scalar_bytes_mod_n exhausted rejection attempts; RNG may be broken"
    )



"""Security primitives for pyrxd.

This package contains the security foundation the rest of the SDK is built on:
exception hierarchy, key-material wrappers, secure RNG helpers, and typed
newtypes enforcing trust-boundary invariants.

Nothing in this package should ever log, print, or format raw key material.
"""

from __future__ import annotations

from .errors import (
    CovenantError,
    KeyMaterialError,
    NetworkError,
    RxdSdkError,
    SpvVerificationError,
    ValidationError,
    redact,
)
from .rng import secure_random_bytes
from .secrets import PrivateKeyMaterial, SecretBytes, secure_scalar_mod_n
from .types import (
    BlockHeight,
    Hex20,
    Hex32,
    Nbits,
    Photons,
    RawTx,
    Satoshis,
    SighashFlag,
    Txid,
)

__all__ = [
    "BlockHeight",
    "CovenantError",
    "Hex20",
    "Hex32",
    "KeyMaterialError",
    "Nbits",
    "NetworkError",
    "Photons",
    "PrivateKeyMaterial",
    "RawTx",
    "RxdSdkError",
    "Satoshis",
    "SecretBytes",
    "SighashFlag",
    "SpvVerificationError",
    "Txid",
    "ValidationError",
    "redact",
    "secure_random_bytes",
    "secure_scalar_mod_n",
]

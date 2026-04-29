"""Exception hierarchy for pyrxd.

Design rules
------------
1. No exception class in this SDK may embed raw private-key bytes, mnemonics,
   or WIF strings in its ``args``. The ``redact`` helper enforces this by
   replacing any ``str``/``bytes`` value longer than 8 characters that
   "looks like" key material with the literal ``"<redacted>"``.
2. All SDK-defined exceptions inherit from :class:`RxdSdkError`, so callers can
   catch the whole family with a single handler.
3. Call sites SHOULD construct these exceptions via ``redact`` on any
   caller-supplied value, e.g. ``raise KeyMaterialError(redact(bad_wif))``.

Redaction heuristic
-------------------
The heuristic is intentionally aggressive: anything longer than 8 chars/bytes
that is hex-only, base58-only, or high-entropy bytes is treated as potential
key material. False positives (a long error code or filename) are acceptable
— a slightly less informative error message is a much better failure mode
than a private key in a stack trace.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "CovenantError",
    "KeyMaterialError",
    "NetworkError",
    "RxdSdkError",
    "SpvVerificationError",
    "UnsupportedScriptError",
    "ValidationError",
    "redact",
]

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]+$")


def _looks_like_key_material(value: str) -> bool:
    """Return True if ``value`` looks like it could be key material.

    Checks for:
      * all hex characters (private keys, hashes, ciphertext)
      * all base58 characters (WIF, addresses, mnemonic seeds in base58)
      * bip39-style all-lowercase ASCII words joined by spaces (>=8 tokens)
    """
    if _HEX_RE.match(value):
        return True
    if _BASE58_RE.match(value):
        return True
    # BIP-39 mnemonic heuristic: >=8 space-separated ASCII lowercase tokens.
    tokens = value.split()
    if len(tokens) >= 8 and all(t.isascii() and t.isalpha() and t.islower() for t in tokens):
        return True
    return False


def redact(value: Any) -> Any:
    """Return a redacted representation of ``value`` if it looks sensitive.

    * ``str`` longer than 8 chars that looks like key material -> ``"<redacted>"``
    * ``bytes`` longer than 8 bytes -> ``"<redacted:Nb>"``
    * other types -> returned unchanged
    """
    if isinstance(value, bytes):
        if len(value) > 8:
            return f"<redacted:{len(value)}b>"
        return value
    if isinstance(value, str):
        if len(value) > 8 and _looks_like_key_material(value):
            return "<redacted>"
        return value
    return value


class RxdSdkError(Exception):
    """Base class for every exception raised by pyrxd.

    Applying ``redact`` to each positional arg on construction defends against
    accidental key-material leakage when callers pass user-supplied values
    straight into the exception.
    """

    def __init__(self, *args: Any) -> None:
        super().__init__(*(redact(a) for a in args))


class KeyMaterialError(RxdSdkError):
    """Raised for errors touching private keys, mnemonics, or WIFs.

    Constructors raising this error MUST NOT include the offending key
    material in the message — pass a static description only.
    """


class ValidationError(RxdSdkError):
    """Raised when input fails a trust-boundary validation check."""


class SpvVerificationError(RxdSdkError):
    """Raised when an SPV proof (Merkle path, header chain) fails to verify."""


class NetworkError(RxdSdkError):
    """Raised for transport / RPC / network failures."""


class CovenantError(RxdSdkError):
    """Raised for covenant construction or verification failures."""


class UnsupportedScriptError(RxdSdkError):
    """Raised when the script engine encounters an opcode or script type it
    does not fully implement.

    Callers should treat this as a hard failure — silently returning "valid"
    for an unrecognised script is a security vulnerability.
    """

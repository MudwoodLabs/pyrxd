"""Typed newtypes for trust-boundary invariants.

Every value that crosses a trust boundary (network input, RPC response,
user-supplied argument) should be wrapped in one of these types as soon as
possible. Construction validates; after that, downstream code can treat the
value as trusted.

Implementation notes
--------------------
All types here subclass immutable builtins (``str``, ``bytes``, ``int``).
Validation therefore lives in ``__new__``, never ``__init__`` -- by the time
``__init__`` runs, the object already exists. We also cannot add ``__slots__``
to a subclass of ``int`` / ``bytes`` / ``str``, but the parents are immutable
so state-mutation is already prevented.

Errors NEVER embed the offending value verbatim when the value could be key
material -- the error message uses a bounded summary (length, redacted tag).
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from .errors import ValidationError

__all__ = [
    "BlockHeight",
    "Hex20",
    "Hex32",
    "Nbits",
    "Photons",
    "RawTx",
    "Satoshis",
    "SighashFlag",
    "Txid",
]

# --------------------------------------------------------------------------- Txid

_TXID_RE = re.compile(r"^[0-9a-f]{64}$")


class Txid(str):
    """A lowercase-hex transaction id (64 chars)."""

    __slots__ = ()

    def __new__(cls, value: Any) -> Txid:
        if not isinstance(value, str):
            raise ValidationError(f"Txid must be str, got {type(value).__name__}")
        if not _TXID_RE.match(value):
            # The length is not secret, and the pattern is public. We do NOT
            # include the raw value to avoid logging any id-like input that
            # an attacker might probe with.
            raise ValidationError(f"Txid must be 64 lowercase hex chars (got length {len(value)})")
        return str.__new__(cls, value)


# --------------------------------------------------------------------------- Hex32 / Hex20


class _FixedBytes(bytes):
    """Base for fixed-length byte types.

    Subclasses must define ``_expected_len`` (class var) and a human-friendly
    ``_name`` used in error messages.
    """

    __slots__ = ()
    _expected_len: ClassVar[int] = 0
    _name: ClassVar[str] = "_FixedBytes"

    def __new__(cls, value: Any) -> _FixedBytes:
        if not isinstance(value, (bytes, bytearray)):
            raise ValidationError(f"{cls._name} must be bytes, got {type(value).__name__}")
        if len(value) != cls._expected_len:
            raise ValidationError(f"{cls._name} must be {cls._expected_len} bytes, got {len(value)}")
        return bytes.__new__(cls, bytes(value))

    @classmethod
    def from_hex(cls, value: str) -> _FixedBytes:
        """Construct from a hex string. Strict: rejects 0x prefix, whitespace,
        and wrong length. Use when inputs are human-readable (config, CLI)."""
        if not isinstance(value, str):
            raise ValidationError(f"{cls._name}.from_hex requires str, got {type(value).__name__}")
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValidationError(f"{cls._name}.from_hex: invalid hex: {exc}") from None
        return cls(raw)


class Hex32(_FixedBytes):
    """Exactly 32 raw bytes (e.g. a hash digest)."""

    __slots__ = ()
    _expected_len: ClassVar[int] = 32
    _name: ClassVar[str] = "Hex32"


class Hex20(_FixedBytes):
    """Exactly 20 raw bytes (e.g. a hash160 public-key hash)."""

    __slots__ = ()
    _expected_len: ClassVar[int] = 20
    _name: ClassVar[str] = "Hex20"


# --------------------------------------------------------------------------- Satoshis / Photons

# BTC-max cap. Radiant inherits Bitcoin's 21,000,000 * 10^8 = 2.1e15 sats hard
# supply upper bound for validation purposes.
_BTC_MAX_SATS: int = 2_100_000_000_000_000


class Satoshis(int):
    """Non-negative integer amount in satoshis, capped at Bitcoin max supply."""

    __slots__ = ()
    MAX: ClassVar[int] = _BTC_MAX_SATS

    def __new__(cls, value: Any) -> Satoshis:
        # Reject bool (which is an int subclass) and non-int types like float.
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"Satoshis must be int, got {type(value).__name__}")
        if value < 0:
            raise ValidationError(f"Satoshis must be >= 0, got {value}")
        if value > _BTC_MAX_SATS:
            raise ValidationError(f"Satoshis must be <= {_BTC_MAX_SATS}, got {value}")
        return int.__new__(cls, value)


class Photons(int):
    """Non-negative integer amount in photons (RXD smallest unit)."""

    __slots__ = ()

    def __new__(cls, value: Any) -> Photons:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"Photons must be int, got {type(value).__name__}")
        if value < 0:
            raise ValidationError(f"Photons must be >= 0, got {value}")
        return int.__new__(cls, value)


# --------------------------------------------------------------------------- BlockHeight

_BLOCK_HEIGHT_CEIL: int = 10_000_000


class BlockHeight(int):
    """Non-negative block height with a generous sanity ceiling."""

    __slots__ = ()
    MAX: ClassVar[int] = _BLOCK_HEIGHT_CEIL

    def __new__(cls, value: Any) -> BlockHeight:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"BlockHeight must be int, got {type(value).__name__}")
        if value < 0:
            raise ValidationError(f"BlockHeight must be >= 0, got {value}")
        if value > _BLOCK_HEIGHT_CEIL:
            raise ValidationError(f"BlockHeight must be <= {_BLOCK_HEIGHT_CEIL}, got {value}")
        return int.__new__(cls, value)


# --------------------------------------------------------------------------- Nbits


class Nbits(bytes):
    """The compact difficulty target (nBits) from a block header.

    Wire format
    -----------
    nBits is a 4-byte little-endian encoding of a uint32. When decoded:
      * ``exponent = nBits_uint32 >> 24``          (high byte, little-endian: byte[3])
      * ``mantissa = nBits_uint32 & 0x007fffff``   (low 3 bytes)
      * ``target   = mantissa * 256^(exponent-3)``

    This type accepts the raw 4 wire bytes and validates the three conditions
    Bitcoin Core enforces on target-word parsing. A malformed nBits can be
    used to forge PoW (e.g. a negative target evaluates the comparison
    weirdly, a zero target is trivially satisfied, an over-large exponent
    shifts out of range). Rejecting these at the trust boundary protects
    every SPV check downstream.
    """

    __slots__ = ()

    def __new__(cls, value: Any) -> Nbits:
        if not isinstance(value, (bytes, bytearray)):
            raise ValidationError(f"Nbits must be bytes, got {type(value).__name__}")
        if len(value) != 4:
            raise ValidationError(f"Nbits must be 4 bytes, got {len(value)}")

        raw = bytes(value)
        # Little-endian wire layout: byte[3] is the high byte (exponent);
        # bytes [0..3] little-endian == nBits_uint32.
        exponent = raw[3]
        mantissa = (raw[2] << 16) | (raw[1] << 8) | raw[0]

        if exponent > 0x1D:
            raise ValidationError(f"Nbits exponent {exponent} > 0x1d (would overflow 256-bit target)")
        # Negative-target bit: mantissa bit 23 set.
        if mantissa & 0x00800000:
            raise ValidationError("Nbits mantissa has sign bit set (negative target)")
        # Zero target is trivially satisfied and must be rejected.
        if mantissa == 0:
            raise ValidationError("Nbits mantissa is zero (trivially-satisfied target)")

        return bytes.__new__(cls, raw)


# --------------------------------------------------------------------------- RawTx


class RawTx(bytes):
    """Raw transaction bytes.

    Enforces the 64-byte Merkle-forgery defense: any candidate transaction
    must be strictly greater than 64 bytes. A 64-byte "transaction" can be
    forged from an internal Merkle-tree node, letting an attacker prove
    inclusion of bogus data. See audit finding 02-F-1 and Bitcoin BIP-141's
    segwit commitment for the historical context (and the CVE-2017-12842
    family for concrete exploits).
    """

    __slots__ = ()
    MIN_SIZE: ClassVar[int] = 65  # strictly greater than 64

    def __new__(cls, value: Any) -> RawTx:
        if not isinstance(value, (bytes, bytearray)):
            raise ValidationError(f"RawTx must be bytes, got {type(value).__name__}")
        if len(value) <= 64:
            raise ValidationError(f"RawTx must be > 64 bytes (Merkle forgery defense), got {len(value)}")
        return bytes.__new__(cls, bytes(value))


# --------------------------------------------------------------------------- SighashFlag


# Allowed sighash flag values for Radiant (BCH/BSV-style FORKID variants).
_VALID_SIGHASH_FLAGS: frozenset[int] = frozenset({0x41, 0x42, 0x43, 0xC1, 0xC2, 0xC3})


class SighashFlag(int):
    """A valid Radiant sighash flag byte."""

    __slots__ = ()

    SIGHASH_ALL: ClassVar[int] = 0x41
    SIGHASH_NONE: ClassVar[int] = 0x42
    SIGHASH_SINGLE: ClassVar[int] = 0x43
    SIGHASH_ALL_ANYONECANPAY: ClassVar[int] = 0xC1
    SIGHASH_NONE_ANYONECANPAY: ClassVar[int] = 0xC2
    SIGHASH_SINGLE_ANYONECANPAY: ClassVar[int] = 0xC3

    def __new__(cls, value: Any) -> SighashFlag:
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValidationError(f"SighashFlag must be int, got {type(value).__name__}")
        if value not in _VALID_SIGHASH_FLAGS:
            raise ValidationError(f"Invalid sighash flag: {hex(value)}")
        return int.__new__(cls, value)

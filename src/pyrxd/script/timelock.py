"""Time-lock script primitives — CLTV (absolute) and CSV (relative).

Canonical Bitcoin/Radiant time-lock locking scripts. Each helper builds a
``<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <P2PKH tail>`` shape (or the
CSV equivalent), which is the standard form used by wallets and
specifications since BIP-65 / BIP-112.

Scope: **locking scripts only**. These helpers emit the output script
bytes; spending such an output (and threading the corresponding
``nLockTime`` / ``nSequence`` constraints through transaction
construction) is intentionally out of scope until a concrete pyrxd
consumer needs it. See ``docs/solutions/design-decisions/`` for the
deferral note covering the transaction-level wiring.

Reference shapes
----------------

**Absolute time-lock (CLTV)** — output is spendable only when the
spending transaction's ``nLockTime`` is at or after ``locktime``::

    <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
    OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG

The ``locktime`` value follows Bitcoin's dual interpretation:

* ``locktime < 500_000_000`` — block-height absolute lock
* ``locktime >= 500_000_000`` — Unix-time absolute lock (seconds)

**Relative time-lock (CSV)** — output is spendable only after the
encoded relative wait, measured from the funding-output's confirmation::

    <sequence> OP_CHECKSEQUENCEVERIFY OP_DROP
    OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG

The ``sequence`` value follows BIP-112's encoded form: a 32-bit
non-negative integer whose bit-22 selects time vs blocks and whose
low 16 bits hold the count. ``build_csv_sequence`` is a small helper
that encodes ``(units, kind)`` into the on-wire integer; callers may
also pass a pre-encoded integer if they already have one.
"""

from __future__ import annotations

from enum import Enum

from ..constants import PUBLIC_KEY_HASH_BYTE_LENGTH, OpCode
from ..security.errors import ValidationError
from ..security.types import Hex20
from ..utils import encode_int

# BIP-65 boundary between height-based and time-based locktime.
# Values below this are interpreted as block heights; values at or above
# this are interpreted as Unix timestamps (seconds since epoch).
LOCKTIME_THRESHOLD = 500_000_000

# Max nLockTime is a 32-bit field on the wire.
_MAX_LOCKTIME = 0xFFFF_FFFF

# BIP-112 OP_CHECKSEQUENCEVERIFY encoding constants.
# A 32-bit value on the stack; only the low 17 bits are used at consensus.
_CSV_TYPE_FLAG = 1 << 22  # bit 22: 0 = blocks, 1 = time (512-second units)
_CSV_DISABLE_FLAG = 1 << 31  # bit 31: 1 = "no relative lock" (consensus-disabled bit)
_CSV_VALUE_MASK = 0xFFFF  # low 16 bits hold the unit count


class CsvKind(Enum):
    """Relative time-lock kind, per BIP-112."""

    BLOCKS = "blocks"
    TIME_512_SECONDS = "time"


def build_csv_sequence(units: int, kind: CsvKind) -> int:
    """Encode an ``(units, kind)`` pair into the integer form CSV expects
    on the stack and in the spending input's ``nSequence`` field.

    ``units`` is the BIP-112 unit count: blocks for ``CsvKind.BLOCKS``,
    or 512-second intervals for ``CsvKind.TIME_512_SECONDS``. Must be in
    the range ``[0, 65535]`` (16 bits)."""
    if not (0 <= units <= _CSV_VALUE_MASK):
        raise ValidationError(f"CSV unit count out of range: {units} not in [0, {_CSV_VALUE_MASK}]")
    encoded = units & _CSV_VALUE_MASK
    if kind is CsvKind.TIME_512_SECONDS:
        encoded |= _CSV_TYPE_FLAG
    elif kind is not CsvKind.BLOCKS:  # pragma: no cover — Enum exhausts the choices
        raise ValidationError(f"unknown CsvKind: {kind!r}")
    return encoded


def _p2pkh_tail(pkh: bytes) -> bytes:
    if len(pkh) != PUBLIC_KEY_HASH_BYTE_LENGTH:
        raise ValidationError(f"pkh must be {PUBLIC_KEY_HASH_BYTE_LENGTH} bytes, got {len(pkh)}")
    return (
        OpCode.OP_DUP
        + OpCode.OP_HASH160
        + bytes([PUBLIC_KEY_HASH_BYTE_LENGTH])
        + pkh
        + OpCode.OP_EQUALVERIFY
        + OpCode.OP_CHECKSIG
    )


def build_p2pkh_with_cltv_script(owner_pkh: Hex20, locktime: int) -> bytes:
    """Build a P2PKH locking script gated by an absolute time-lock (CLTV).

    The output is spendable only when the spending transaction's
    ``nLockTime`` is at or after ``locktime``.

    ``locktime < 500_000_000`` selects a block-height lock; values at or
    above ``LOCKTIME_THRESHOLD`` select a Unix-time lock (seconds). The
    caller is responsible for choosing the right interpretation — both
    are accepted at the script level.

    Returns the raw locking-script bytes.
    """
    if not (0 <= locktime <= _MAX_LOCKTIME):
        raise ValidationError(f"locktime out of range: {locktime} not in [0, {_MAX_LOCKTIME}]")
    return encode_int(locktime) + OpCode.OP_CHECKLOCKTIMEVERIFY + OpCode.OP_DROP + _p2pkh_tail(bytes(owner_pkh))


def build_p2pkh_with_csv_script(owner_pkh: Hex20, sequence: int) -> bytes:
    """Build a P2PKH locking script gated by a relative time-lock (CSV).

    The output is spendable only after the BIP-112-encoded ``sequence``
    has elapsed (measured from the funding-output's confirmation). Use
    ``build_csv_sequence(units, kind)`` to construct ``sequence`` from a
    block count or a 512-second interval count.

    Callers must NOT pass a sequence with the disable bit (1 << 31) set
    — that value means "no relative lock" and would silently make the
    script trivially spendable.

    Returns the raw locking-script bytes.
    """
    if not (0 <= sequence <= _MAX_LOCKTIME):
        raise ValidationError(f"sequence out of range: {sequence} not in [0, {_MAX_LOCKTIME}]")
    if sequence & _CSV_DISABLE_FLAG:
        raise ValidationError(
            f"sequence has disable bit (1<<31) set ({sequence:#x}); this would make the relative time-lock a no-op"
        )
    return encode_int(sequence) + OpCode.OP_CHECKSEQUENCEVERIFY + OpCode.OP_DROP + _p2pkh_tail(bytes(owner_pkh))

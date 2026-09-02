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

from dataclasses import dataclass
from enum import Enum

from ..constants import LOCKTIME_THRESHOLD as _LOCKTIME_THRESHOLD
from ..constants import (
    PUBLIC_KEY_HASH_BYTE_LENGTH,
    SEQUENCE_FINAL,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
    OpCode,
)
from ..security.errors import ValidationError
from ..security.types import Hex20
from ..utils import decode_script_num, encode_int

# BIP-65 boundary between height-based and time-based locktime. Values below
# this are block heights; values at or above it are Unix timestamps.
#
# Re-exported from :mod:`pyrxd.constants` rather than spelled out again: that
# copy is checked against Radiant Core's ``script.h`` by
# ``tests/test_consensus_opcode_parity.py``, and this module is the constant's
# only consumer. The name stays public here because ``pyrxd.script`` has
# exported it since it was added.
LOCKTIME_THRESHOLD = _LOCKTIME_THRESHOLD

# Max nLockTime is a 32-bit field on the wire — the same 32-bit ceiling as
# CTxIn::SEQUENCE_FINAL, taken from the one place that value is written down.
_MAX_LOCKTIME = SEQUENCE_FINAL

# BIP-112 OP_CHECKSEQUENCEVERIFY encoding constants live in
# :mod:`pyrxd.constants`, derived from Radiant's ``CTxIn`` and pinned to the
# vendored header by the consensus differential. This module used to carry its
# own copy of all three, as did ``btc_wallet/taproot.py`` — two independent
# transcriptions of one consensus rule, which is the exact condition that
# produced three ref-walker bugs in two days.


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
    if not (0 <= units <= SEQUENCE_LOCKTIME_MASK):
        raise ValidationError(f"CSV unit count out of range: {units} not in [0, {SEQUENCE_LOCKTIME_MASK}]")
    encoded = units & SEQUENCE_LOCKTIME_MASK
    if kind is CsvKind.TIME_512_SECONDS:
        encoded |= SEQUENCE_LOCKTIME_TYPE_FLAG
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
    if sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        raise ValidationError(
            f"sequence has disable bit (1<<31) set ({sequence:#x}); this would make the relative time-lock a no-op"
        )
    # The SAME no-op, the other spelling. The disable bit above was refused from the start;
    # a zero UNIT COUNT was not, so this builder emitted `OP_0 OP_CSV OP_DROP` — a lock of
    # zero, spendable in its own funding block — for a caller that asked for a time-lock.
    # Masked, not `< 1`: `build_csv_sequence(0, TIME_512_SECONDS)` is 0x400000, which is
    # non-zero and still a lock of zero. `build_csv_sequence` itself stays permissive by
    # DECISION, not oversight — it encodes an integer; this is where the integer becomes
    # bytes that hold funds, so this is where the floor belongs.
    if sequence & SEQUENCE_LOCKTIME_MASK == 0:
        raise ValidationError(
            f"sequence {sequence:#x} has a unit count of 0 — a relative lock of zero is a no-op; "
            "the output would be spendable in its own funding block. Pass at least 1 unit."
        )
    return encode_int(sequence) + OpCode.OP_CHECKSEQUENCEVERIFY + OpCode.OP_DROP + _p2pkh_tail(bytes(owner_pkh))


def _decode_minimal_int_push(head: bytes) -> int | None:
    """Decode *head* as a single MINIMALDATA-conformant push of a non-negative
    integer, or return ``None``.

    Accepts the three shapes :func:`~pyrxd.utils.encode_int` can emit for a
    value ``>= 0`` — ``OP_0``, ``OP_1``–``OP_16``, and a direct
    ``0x01``–``0x4b`` push — and then re-encodes the decoded value and demands
    the bytes match. That round trip is what rejects non-minimal encodings
    (a padded ``02 05 00`` for 5, an ``OP_PUSHDATA1`` wrapper, a negative
    zero): two different byte strings must never both be reported as the same
    time-lock, and non-minimal pushes are rejected by MINIMALDATA on-chain
    anyway, so a script carrying one is not the shape it appears to be.
    """
    if not head:
        return None
    op = head[0]
    if len(head) == 1 and op == 0x00:  # OP_0
        value = 0
    elif len(head) == 1 and 0x51 <= op <= 0x60:  # OP_1 .. OP_16
        value = op - 0x50
    elif 0x01 <= op <= 0x4B and len(head) == 1 + op:  # direct push
        value = decode_script_num(head[1:])
    else:
        return None
    # OP_1NEGATE and sign-bit-set bodies decode negative: not a time-lock
    # (consensus fails CLTV/CSV outright on a negative stack value).
    if value < 0 or value > _MAX_LOCKTIME:
        return None
    if encode_int(value) != head:
        return None
    return value


@dataclass(frozen=True)
class ParsedTimelockScript:
    """A decoded ``<value> OP_CLTV|OP_CSV OP_DROP <P2PKH>`` locking script.

    Returned by :func:`parse_p2pkh_timelock_script`. This is a **structural**
    parse: it proves the bytes have the canonical BIP-65 / BIP-112 time-lock
    shape and reports the encoded value. It says nothing about whether the
    lock has elapsed (that needs a chain tip / the funding output's height)
    or about who controls ``owner_pkh``.
    """

    kind: str
    """``"cltv"`` (absolute) or ``"csv"`` (relative)."""

    owner_pkh: bytes
    """The 20-byte hash160 in the P2PKH tail."""

    value: int
    """The raw integer pushed onto the stack — an ``nLockTime`` for CLTV, a
    BIP-112-encoded ``nSequence`` for CSV."""

    basis: str
    """What ``units`` counts: ``"height"`` / ``"unix_time"`` for CLTV,
    ``"blocks"`` / ``"time_512s"`` for CSV."""

    units: int
    """The count in ``basis`` units. Equals ``value`` for CLTV; for CSV it is
    ``value & SEQUENCE_LOCKTIME_MASK`` (the low 16 bits)."""

    relative_lock_disabled: bool = False
    """CSV only: the ``1 << 31`` disable bit is set, so consensus treats the
    relative lock as **absent** — the output is spendable immediately. Always
    ``False`` for CLTV. :func:`build_p2pkh_with_csv_script` refuses to build
    such a script, but one can exist on-chain."""


# The P2PKH tail is fixed-width, so the time-lock prologue is found by
# measuring back from the end rather than by walking opcodes forward. Offsets:
# script[-25:] is the tail, script[-27] the CLTV/CSV opcode, script[-26]
# OP_DROP, and script[:-27] the single value push.
_P2PKH_TAIL_LEN = 25
_TIMELOCK_SUFFIX_LEN = _P2PKH_TAIL_LEN + 2  # + <cltv|csv> + OP_DROP
_OP_CLTV_BYTE = OpCode.OP_CHECKLOCKTIMEVERIFY[0]
_OP_CSV_BYTE = OpCode.OP_CHECKSEQUENCEVERIFY[0]
_OP_DROP_BYTE = OpCode.OP_DROP[0]


def parse_p2pkh_timelock_script(script: bytes) -> ParsedTimelockScript | None:
    """Parse a ``<value> OP_CLTV|OP_CSV OP_DROP <P2PKH>`` locking script.

    Returns ``None`` for anything that is not exactly that shape — this is the
    inverse of :func:`build_p2pkh_with_cltv_script` /
    :func:`build_p2pkh_with_csv_script` and is deliberately strict: a
    near-miss (wrong opcode, missing ``OP_DROP``, non-minimal value push,
    trailing bytes after the P2PKH tail) is not a time-lock and must not be
    reported as one.

    Never raises — safe to run over arbitrary chain bytes.
    """
    if len(script) < _TIMELOCK_SUFFIX_LEN + 1:  # needs at least a 1-byte push
        return None
    tail = script[-_P2PKH_TAIL_LEN:]
    if tail[:3] != b"\x76\xa9\x14" or tail[23:] != b"\x88\xac":
        return None
    op_timelock = script[-_TIMELOCK_SUFFIX_LEN]
    if script[-_TIMELOCK_SUFFIX_LEN + 1] != _OP_DROP_BYTE:
        return None
    if op_timelock == _OP_CLTV_BYTE:
        kind = "cltv"
    elif op_timelock == _OP_CSV_BYTE:
        kind = "csv"
    else:
        return None

    value = _decode_minimal_int_push(script[:-_TIMELOCK_SUFFIX_LEN])
    if value is None:
        return None

    owner_pkh = tail[3:23]
    if kind == "cltv":
        # BIP-65's dual interpretation, decided by the same pinned constant
        # the builder documents.
        basis = "height" if value < LOCKTIME_THRESHOLD else "unix_time"
        return ParsedTimelockScript(kind=kind, owner_pkh=owner_pkh, value=value, basis=basis, units=value)

    disabled = bool(value & SEQUENCE_LOCKTIME_DISABLE_FLAG)
    basis = "time_512s" if value & SEQUENCE_LOCKTIME_TYPE_FLAG else "blocks"
    return ParsedTimelockScript(
        kind=kind,
        owner_pkh=owner_pkh,
        value=value,
        basis=basis,
        units=value & SEQUENCE_LOCKTIME_MASK,
        relative_lock_disabled=disabled,
    )

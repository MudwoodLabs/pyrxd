"""Radiant's difficulty rule: the nBits every mainnet header must carry, from its parent alone.

WHY. Radiant Core rejects a block whose nBits is not exactly the value its difficulty rule computes
(``bad-diffbits``, ``tests/vendor/radiant_core/validation.cpp:3869-3871``). pyrxd's verifier used
to check only that a header met the target its OWN nBits stated, plus a floor
(:data:`pyrxd.glyph.mark_block.FLOOR_WORK_DIVISOR`), so a server could serve a forged header that
stated an easy target. With this rule, a header above a shipped checkpoint must state the
difficulty Radiant itself requires of a block on top of its parent.

THE RULE (``tests/vendor/radiant_core/pow.cpp``, Radiant-Core v3.1.2, verbatim). ASERT in its
absolute form: the target of the block after ``prev`` is

    anchor_target * 2 ** ((time(prev) - anchor_prev_time - SPACING * (height(prev) - anchor_height + 1)) / HALF_LIFE)

in 16.16 fixed point with a cubic approximation of ``2 ** frac`` (``CalculateASERT``,
``pow.cpp:215-299``), clamped to the proof-of-work limit, then encoded as compact nBits. It needs
no window of earlier headers: only the parent's height and timestamp and three anchor constants.

THE ANCHOR. From height :data:`HALF_LIFE_UPGRADE_HEIGHT` (410,000) Radiant uses a 12-hour half-life
and re-anchors on block 409,999: its nBits, and the timestamp of ITS parent, 409,998
(``pow.cpp:126-147``). ``chainparams.cpp:124`` still states the old two-day half-life; the 12 hours
is in ``pow.cpp:138`` only. :data:`MAINNET_ANCHOR` holds the two values read from those mainnet
headers (2026-11-03, served byte for byte alike by two operators); they equal Photonic Wallet's
``anchorV2``. A wrong anchor makes every honest header fail the rule, which the parity tests
(``tests/test_asert_difficulty_rule.py``) would show: they replay real mainnet headers.

WHAT IS NOT COVERED. Heights below 410,000 (the original 2022 anchor and two-day half-life). The
rule is applied only above the NEWEST checkpoint, which is far above them (477,792 in 0.27.1;
``tests/test_asert_difficulty_rule.py`` asserts it is at least 409,999); headers at or below it are
pinned by hash. Older checkpoints in the table sit below 410,000, but nothing is walked from them.
Radiant's rule as of v3.1.2 only: Radiant changed it once by height (``pow.cpp:126-151``). If it
changes again, honest headers above the change fail this rule and are reported CONTRADICTED until
pyrxd ships the new rule. That fails closed, and it needs a release.
Networks other than mainnet: regtest does not retarget (``fPowNoRetargeting``,
``chainparams.cpp``), and pyrxd ships no checkpoints for testnet, so :func:`required_nbits` returns
``None`` there and callers apply no rule. Testnet's min-difficulty exception (``pow.cpp:116-121``)
is therefore never modelled.

PARITY WITH THE C++. These details are mirrored deliberately:

* the exponent's division TRUNCATES toward zero (C++ ``/`` on int64), while its split into whole
  and fractional parts is an arithmetic shift, which FLOORS. A port using Python's ``//`` for the
  division differs on every block ahead of schedule (measured 2026-11-03: 23,057 of 68,484 mainnet
  blocks from 410,000 to 478,483);
* the cubic's accumulator is a uint64, so it is taken modulo 2**64. This is for fidelity only:
  its largest value (``frac`` = 65535) is about 2**47 below the wrap, so the mask never changes
  the result;
* a shift that would overflow 256 bits clamps to powLimit, as ``pow.cpp:278-287`` does (a parent
  stamped weeks ahead of schedule reaches it);
* compact encoding is ``arith_uint256::GetCompact``, including the sign-bit renormalisation.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "HALF_LIFE_SECONDS",
    "HALF_LIFE_UPGRADE_HEIGHT",
    "MAINNET_ANCHOR",
    "MAINNET_POW_LIMIT",
    "SPACING_SECONDS",
    "AsertAnchor",
    "calculate_asert",
    "compact_from_target",
    "header_nbits",
    "header_time",
    "next_nbits",
    "required_nbits",
    "target_from_compact",
]

#: ``consensus.nPowTargetSpacing`` (``tests/vendor/radiant_core/chainparams.cpp:117``).
SPACING_SECONDS = 300

#: ``consensus.asertHalfLifeUpgradeHeight`` (``chainparams.cpp:125``): from this height on, the
#: half-life is :data:`HALF_LIFE_SECONDS` and the anchor is block ``HALF_LIFE_UPGRADE_HEIGHT - 1``.
HALF_LIFE_UPGRADE_HEIGHT = 410_000

#: The half-life from :data:`HALF_LIFE_UPGRADE_HEIGHT` on (``pow.cpp:138``, ``12 * 60 * 60``).
HALF_LIFE_SECONDS = 12 * 60 * 60

#: Mainnet ``consensus.powLimit`` (``chainparams.cpp:113-114``).
MAINNET_POW_LIMIT = (1 << 224) - 1

_UINT64 = (1 << 64) - 1
_UINT256 = (1 << 256) - 1


@dataclass(frozen=True)
class AsertAnchor:
    """An ASERT anchor: the anchor block's height and nBits, and its PARENT's timestamp."""

    height: int
    nbits: int
    prev_time: int


#: Block 409,999's nBits and block 409,998's timestamp, read from mainnet headers 2026-11-03 (both
#: operators served them byte for byte alike; equal to Photonic Wallet's ``anchorV2``).
MAINNET_ANCHOR = AsertAnchor(height=HALF_LIFE_UPGRADE_HEIGHT - 1, nbits=0x1A008D39, prev_time=1_773_088_826)


def target_from_compact(nbits: int) -> int:
    """``arith_uint256::SetCompact`` for a non-negative, non-overflowing compact value."""
    size = nbits >> 24
    word = nbits & 0x007FFFFF
    if size <= 3:
        return word >> (8 * (3 - size))
    return word << (8 * (size - 3))


def compact_from_target(target: int) -> int:
    """``arith_uint256::GetCompact`` (``arith_uint256.cpp``) for a target in ``0 .. 2**256 - 1``."""
    size = (target.bit_length() + 7) // 8
    if size <= 3:
        compact = (target & _UINT64) << (8 * (3 - size))
    else:
        compact = target >> (8 * (size - 3))
    # The 0x00800000 bit is the sign: if it is set, divide the mantissa by 256 and grow the exponent.
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return (compact | (size << 24)) & 0xFFFFFFFF


def _cpp_div(a: int, b: int) -> int:
    """int64 division as C++ does it: rounded toward zero (Python's ``//`` floors)."""
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b > 0) else -q


def calculate_asert(
    ref_target: int, spacing: int, time_diff: int, height_diff: int, pow_limit: int, half_life: int
) -> int:
    """``CalculateASERT`` (``pow.cpp:215-299``), bit for bit. Raises ``ValueError`` where the C++
    asserts."""
    if not 0 < ref_target <= pow_limit:
        raise ValueError("the anchor target must be in 1..powLimit")
    if pow_limit >> 224:
        raise ValueError("powLimit needs 32 leading zero bits")
    if height_diff < 0:
        raise ValueError("the parent must not be below the anchor")
    if abs(time_diff - spacing * height_diff) >= 1 << (63 - 16):
        raise ValueError("time difference out of the range Radiant Core accepts")
    exponent = _cpp_div((time_diff - spacing * (height_diff + 1)) * 65536, half_life)
    shifts = exponent >> 16  # an arithmetic shift: floors, unlike the division above
    frac = exponent & 0xFFFF
    accumulator = (195766423245049 * frac + 971821376 * frac * frac + 5127 * frac**3 + (1 << 47)) & _UINT64
    factor = 65536 + (accumulator >> 48)
    target = ref_target * factor
    shifts -= 16
    if shifts <= 0:
        target >>= -shifts
    else:
        shifted = (target << shifts) & _UINT256
        target = pow_limit if (shifted >> shifts) != target else shifted
    if target == 0:
        return 1
    return min(target, pow_limit)


def next_nbits(
    prev_height: int, prev_time: int, *, anchor: AsertAnchor = MAINNET_ANCHOR, pow_limit: int = MAINNET_POW_LIMIT
) -> int:
    """The nBits Radiant requires of the block on top of a parent at *prev_height* with timestamp
    *prev_time*, for a block at or above :data:`HALF_LIFE_UPGRADE_HEIGHT`."""
    if prev_height + 1 < HALF_LIFE_UPGRADE_HEIGHT:
        raise ValueError(f"only blocks from {HALF_LIFE_UPGRADE_HEIGHT} on are covered")
    target = calculate_asert(
        target_from_compact(anchor.nbits),
        SPACING_SECONDS,
        prev_time - anchor.prev_time,
        prev_height - anchor.height,
        pow_limit,
        HALF_LIFE_SECONDS,
    )
    return compact_from_target(target)


def header_time(header: bytes) -> int:
    """A raw 80-byte header's timestamp (bytes 68..71, little-endian)."""
    return int.from_bytes(header[68:72], "little")


def header_nbits(header: bytes) -> int:
    """A raw 80-byte header's nBits (bytes 72..75, little-endian)."""
    return int.from_bytes(header[72:76], "little")


def required_nbits(network: str, prev_height: int, prev_header: bytes) -> int | None:
    """The nBits the header at ``prev_height + 1`` must carry, or ``None`` when pyrxd applies no
    difficulty rule there (any network but mainnet; a block below 410,000)."""
    if network != "mainnet" or prev_height + 1 < HALF_LIFE_UPGRADE_HEIGHT:
        return None
    return next_nbits(prev_height, header_time(prev_header))

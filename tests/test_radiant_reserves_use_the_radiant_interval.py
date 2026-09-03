"""A RADIANT-chain reserve must never be converted with the BITCOIN interval.

`rxd_claim_burial` and `rxd_claim_inclusion` count RADIANT blocks. They were
converted with `policy.block_interval_s` — Bitcoin's — at seven sites, and
`policy.rxd_block_interval_s` was used for them nowhere (#579).

It survived because it is INERT while every constructor tags those fields BLOCKS:
`normalize_to`/`_reserve_to_blocks` are then the identity and the interval
argument is never read. **A wrong argument that is never used looks exactly like
a right one**, which is why neither review nor the type system nor the parity
sweep caught it — `security/units.py` has one `BlockSpan` for all chains, so a
Radiant block and a Bitcoin block are the same type to it.

Both failure directions are real once a SECONDS value exists, measured at 600/300:

* an 1800 s burial is 6 Radiant blocks and was read as **3** — half the intended
  depth, the unsafe direction;
* a 900 s burial is 3 honest Radiant blocks and was **REFUSED at construction**
  as "1 blk < safety floor 2" — a guard refusing valid work.

Seven sites is why this is a scanner and not seven fixes.

WHAT THIS COVERS, AND WHAT IT DOES NOT. The scanner is line-based: it catches a
CALL SITE that names a Radiant field and the Bitcoin interval together — the shape
that actually shipped. It cannot see a regression INSIDE
`_radiant_reserve_blocks`, whose parameter is a generic `reserve` with no field
name on the line.

That half is covered by `test_assess_claim_finality_parity_sweep_byte_equivalent`,
whose reference derives the interval from the rule independently and now sweeps a
SECONDS-tagged policy. Verified rather than assumed: switching the helper back to
the Bitcoin interval fails the parity sweep, and adding a fresh call site that
bypasses the helper fails this file. Neither guard covers both, and saying so is
the point — a scanner presented as complete is worse than one with a stated edge.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"

#: Fields that count RADIANT blocks.
_RADIANT_FIELDS = ("rxd_claim_burial", "rxd_claim_inclusion")

#: A conversion naming a Radiant field and the BITCOIN interval in one expression.
#: `rxd_block_interval_s` contains `block_interval_s`, so the pattern must exclude
#: the correct spelling explicitly rather than by substring.
_BAD = re.compile(
    r"(?<!rxd_)block_interval_s\s*=?\s*[^,)\n]*(?:" + "|".join(_RADIANT_FIELDS) + r")"
    r"|(?:" + "|".join(_RADIANT_FIELDS) + r")[^)\n]{0,80}?(?<!rxd_)block_interval_s"
)


def _offenders() -> list[str]:
    hits = []
    for path in sorted(_SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or "test" in path.name:
                continue
            if _BAD.search(line):
                hits.append(f"{path.relative_to(_ROOT)}:{lineno}: {stripped[:100]}")
    return hits


def test_the_scanner_catches_the_shipped_defect() -> None:
    """Non-vacuity: a scanner matching nothing is indistinguishable from a clean tree."""
    shipped = "        burial_blocks = _reserve_to_blocks(policy.rxd_claim_burial, policy.block_interval_s)"
    assert _BAD.search(shipped), "the pattern must fire on the line that actually shipped"


def test_the_scanner_accepts_the_CORRECT_spelling() -> None:
    """Honest path. `rxd_block_interval_s` contains `block_interval_s` as a substring,
    so a naive pattern would flag every correct call site — a guard that refuses
    valid work, on the very line that fixes the bug."""
    fixed = "        burial_blocks = _reserve_to_blocks(policy.rxd_claim_burial, policy.rxd_block_interval_s)"
    assert not _BAD.search(fixed)


def test_no_radiant_reserve_is_converted_with_the_bitcoin_interval() -> None:
    offenders = _offenders()
    assert not offenders, (
        "a RADIANT-chain reserve is being converted with the BITCOIN interval:\n  "
        + "\n  ".join(offenders)
        + "\n\nUse `_radiant_reserve_blocks(policy, reserve)`, which picks the interval once."
    )


@pytest.mark.parametrize("field", _RADIANT_FIELDS)
def test_the_fields_this_guards_still_exist(field: str) -> None:
    """Stale-guard ratchet: if a field is renamed, this scanner silently stops
    covering it and would keep passing forever."""
    from pyrxd.gravity.swap_coordinator import MarginPolicy

    assert field in MarginPolicy.__dataclass_fields__, f"{field} no longer exists; update this scanner"

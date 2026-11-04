"""Parity of :mod:`pyrxd.spv.asert` with Radiant Core's difficulty rule.

Three independent signals, none of them a Python transcription of the rule:

* the CONSTANTS are read from the vendored Radiant Core sources (``tests/vendor/radiant_core``,
  v3.1.2): spacing, upgrade height and powLimit from ``chainparams.cpp``, the 12-hour half-life
  and the cubic's coefficients from ``pow.cpp``;
* the ARITHMETIC is checked against Bitcoin Cash Node's published aserti3-2d test vectors
  (``tests/vendor/bchn_aserti3_2d``), the algorithm Radiant's ``CalculateASERT`` was taken from.
  Run 11 has blocks ahead of schedule, so the truncating division is exercised: a port that
  floors instead fails 811 of its 1,000 vectors (measured 2026-11-04);
* the ANCHOR and the whole rule together are checked against real mainnet headers: every
  consecutive pair in ``tests/fixtures/mark_block_fixtures_2026-09-30.json``.

A full replay over mainnet headers 410,000 to 478,483 (68,484 blocks, both shipped operators,
2026-11-03) matched on every block; it ran outside the suite, which has no network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from pyrxd.spv import asert
from pyrxd.spv.asert import (
    HALF_LIFE_SECONDS,
    HALF_LIFE_UPGRADE_HEIGHT,
    MAINNET_ANCHOR,
    MAINNET_POW_LIMIT,
    SPACING_SECONDS,
    calculate_asert,
    compact_from_target,
    header_nbits,
    header_time,
    next_nbits,
    required_nbits,
    target_from_compact,
)

ROOT = Path(__file__).resolve().parent.parent
RADIANT = ROOT / "tests/vendor/radiant_core"
BCHN = ROOT / "tests/vendor/bchn_aserti3_2d"


def _mainnet_params() -> str:
    text = (RADIANT / "chainparams.cpp").read_text(encoding="utf-8")
    start = text.index("class CMainParams")
    return text[start : text.index("class CTestNetParams", start)]


# ── constants, from the vendored C++ ─────────────────────────────────────────────────────────────


def test_spacing_upgrade_height_and_pow_limit_are_mainnets() -> None:
    main = _mainnet_params()
    spacing = re.search(r"consensus\.nPowTargetSpacing = (\d+) \* (\d+);", main)
    assert spacing is not None
    assert int(spacing.group(1)) * int(spacing.group(2)) == SPACING_SECONDS
    upgrade = re.search(r"consensus\.asertHalfLifeUpgradeHeight = (\d+);", main)
    assert upgrade is not None and int(upgrade.group(1)) == HALF_LIFE_UPGRADE_HEIGHT
    limit = re.search(r'consensus\.powLimit = uint256S\(\s*"([0-9a-f]{64})"\);', main)
    assert limit is not None and int(limit.group(1), 16) == MAINNET_POW_LIMIT
    assert MAINNET_ANCHOR.height == HALF_LIFE_UPGRADE_HEIGHT - 1


def test_half_life_and_cubic_coefficients_are_pow_cpps() -> None:
    pow_cpp = (RADIANT / "pow.cpp").read_text(encoding="utf-8")
    half = re.search(r"halfLife = (\d+) \* (\d+) \* (\d+);", pow_cpp)
    assert half is not None
    assert int(half.group(1)) * int(half.group(2)) * int(half.group(3)) == HALF_LIFE_SECONDS
    coefficients = re.findall(r"\+ (\d+)ull \* frac", pow_cpp)
    assert len(coefficients) == 3, coefficients
    ours = Path(asert.__file__).read_text(encoding="utf-8")
    for c in coefficients:
        assert re.search(rf"\b{c} \* frac", ours), f"pow.cpp's coefficient {c} is not in pyrxd.spv.asert"
    assert "(1ull << 47)" in pow_cpp and "(1 << 47)" in ours


# ── arithmetic, against BCHN's vectors ───────────────────────────────────────────────────────────

_RUNS = sorted(BCHN.glob("run*"))


def test_the_bchn_vectors_are_here() -> None:
    assert len(_RUNS) == 11, [p.name for p in _RUNS]


@pytest.mark.parametrize("run", _RUNS, ids=[p.name for p in _RUNS])
def test_calculate_asert_matches_bchns_aserti3_2d_vectors(run: Path) -> None:
    """BCHN's vectors are for its own chain (600 s spacing, two-day half-life, powLimit 2**224 - 1);
    the function takes those as arguments, as Radiant's ``CalculateASERT`` does."""
    text = run.read_text(encoding="utf-8")

    def header(name: str) -> int:
        m = re.search(rf"##\s+{name}: (\S+)", text)
        assert m is not None, name
        return int(m.group(1), 0)

    anchor_h, anchor_t, anchor_bits = header("anchor height"), header("anchor parent time"), header("anchor nBits")
    rows = [line.split() for line in text.splitlines() if line and not line.startswith("#")]
    assert len(rows) == header("iterations")
    for _it, height, time, want in rows:
        got = calculate_asert(
            target_from_compact(anchor_bits), 600, int(time) - anchor_t, int(height) - anchor_h, (1 << 224) - 1, 172800
        )
        assert compact_from_target(got) == int(want, 16), (run.name, height, time)


# ── the whole rule, against real mainnet headers ─────────────────────────────────────────────────


def _mainnet_pairs() -> list[tuple[int, bytes, bytes]]:
    fixtures = json.loads((ROOT / "tests/fixtures/mark_block_fixtures_2026-09-30.json").read_text(encoding="utf-8"))
    pairs = []
    for fx in fixtures["fixtures"].values():
        raw = bytes.fromhex(fx["headers_hex"])
        headers = [raw[i : i + 80] for i in range(0, len(raw), 80)]
        for i in range(1, len(headers)):
            pairs.append((fx["headers_start"] + i, headers[i - 1], headers[i]))
    return pairs


def test_every_real_mainnet_header_carries_the_required_nbits() -> None:
    pairs = _mainnet_pairs()
    assert len(pairs) == 32
    for height, parent, child in pairs:
        assert required_nbits("mainnet", height - 1, parent) == header_nbits(child), height


def test_the_anchor_is_where_the_rule_starts() -> None:
    """The block right after the anchor is computed from the anchor itself: zero height difference,
    one spacing of time, the anchor's own target."""
    first = next_nbits(MAINNET_ANCHOR.height, MAINNET_ANCHOR.prev_time + SPACING_SECONDS)
    assert first == MAINNET_ANCHOR.nbits
    assert compact_from_target(target_from_compact(MAINNET_ANCHOR.nbits)) == MAINNET_ANCHOR.nbits


def test_the_rule_is_applied_only_where_it_is_modelled() -> None:
    parent = _mainnet_pairs()[0][1]
    assert required_nbits("regtest", 460_000, parent) is None
    assert required_nbits("testnet", 460_000, parent) is None
    assert required_nbits("mainnet", HALF_LIFE_UPGRADE_HEIGHT - 2, parent) is None
    assert required_nbits("mainnet", HALF_LIFE_UPGRADE_HEIGHT - 1, parent) is not None
    with pytest.raises(ValueError, match="only blocks from 410000 on"):
        next_nbits(HALF_LIFE_UPGRADE_HEIGHT - 2, header_time(parent))


def test_calculate_asert_refuses_what_the_cpp_asserts() -> None:
    lim = MAINNET_POW_LIMIT
    for args in (
        (0, 300, 0, 0, lim, 1),
        (lim + 1, 300, 0, 0, lim, 1),
        (1, 300, 0, -1, lim, 1),
        (1, 300, 0, 0, 1 << 230, 1),
    ):
        with pytest.raises(ValueError):
            calculate_asert(*args)
    with pytest.raises(ValueError, match="time difference"):
        calculate_asert(1, 300, 1 << 48, 0, lim, 1)

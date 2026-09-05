"""A reserve must CEIL when converted to blocks. Flooring under-counts it — the unsafe direction.

`_reserve_to_blocks` says so in its own docstring: *"A reserve (claim burial, reorg depth) must
round UP: flooring it under-counts the reserve — the UNSAFE direction."* `Timelock.normalize_to`
floors (`int(value // interval)`), and says so too. Both are correct for their own purpose — the
defect is using the deadline conversion on a reserve.

#607 found this and fixed ONE of three sites (`_required_btc_depth_blocks`), and scoped its guard
to `decide.py`. `swap_coordinator.py` and `watch/claim_executor.py` kept flooring the same
`btc_claim_reorg_depth` that `assess_claim_finality` ceils — and all three numbers feed the SAME
`CounterClaimFinality.from_btc_depth` gate, so the two floorers declared the maker's BTC claim
final a block early. One of them is the autonomous claim path, where nothing human re-checks it.

That is the recurring shape: a guard written from one example generalises over the axis it was
shown and stays blind to the others. So this file is derived rather than scoped — the field set
comes from `dataclasses.fields(MarginPolicy)`, so a reserve added later is covered without anyone
remembering to extend a list.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit
from pyrxd.gravity.finality import CounterClaimFinality
from pyrxd.gravity.swap_coordinator import MarginPolicy, _reserve_to_blocks

_SRC = Path(__file__).resolve().parents[1] / "src" / "pyrxd"


def _reserve_fields() -> frozenset[str]:
    """Every Timelock-typed field on MarginPolicy. Derived, never typed out.

    These are all reserves: MarginPolicy carries requirements. The DEADLINES (`t_rxd`, `t_btc`)
    live on `NegotiatedTerms`, where flooring is correct because it only shrinks the window
    available to the holder. That split is what makes this set safe to derive wholesale.
    """
    return frozenset(f.name for f in dataclasses.fields(MarginPolicy) if f.type in ("Timelock", Timelock))


#: A site may floor a reserve when the direction genuinely reverses, but it must SAY SO. Requiring
#: a marker rather than keeping an allowlist in this file means a new site fails until someone
#: states a reason — and the reason lives beside the code, where the next reader is.
_DELIBERATE = "floor-is-deliberate:"


def _floor_conversions(source: str, fields: frozenset[str]) -> list[tuple[int, str]]:
    """`<anything>.<reserve field>.normalize_to(...)` with no `floor-is-deliberate:` justification.

    NOT a blanket ban, because a blanket ban would be WRONG. Whether flooring is safe depends on
    which way the value is used, which no syntactic scan can see:

    * fed to `CounterClaimFinality.from_btc_depth` as a required depth — flooring under-counts the
      requirement and calls a claim final early. Ceil.
    * added to the bar in `maker_refund_opens_s < taker_refund_opens_s + margin_s` — flooring
      shrinks the bar. Ceil.
    * fed to `max_protected_value` (= burial x cost) — a LARGER burial permits MORE value, so
      flooring is the conservative direction and ceiling would be the defect. Floor.

    Writing this as "reserves must ceil" would have converted that third site and raised the value
    ceiling the gate exists to hold down. The guard for a class can fail the same way the class
    does; this one asks for a justification instead of assuming one.
    """
    lines = source.splitlines()
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "normalize_to"):
            continue
        inner = fn.value
        if not (isinstance(inner, ast.Attribute) and inner.attr in fields):
            continue
        window = "\n".join(lines[max(0, node.lineno - 9) : node.lineno])
        if _DELIBERATE in window:
            continue
        out.append((node.lineno, inner.attr))
    return out


def test_the_reserve_set_is_derived_and_non_empty() -> None:
    """A scan over an empty field set passes vacuously — the exact shape of a guard that reads
    like coverage and checks nothing."""
    fields = _reserve_fields()
    assert fields, "no Timelock fields found on MarginPolicy — the derivation has broken"
    assert "btc_claim_reorg_depth" in fields, "the field this defect was found on must be covered"


@pytest.mark.parametrize(
    "path",
    sorted(p for p in _SRC.rglob("*.py")),
    ids=lambda p: p.relative_to(_SRC).as_posix(),
)
def test_no_shipped_module_floors_a_reserve(path: Path) -> None:
    bad = _floor_conversions(path.read_text(), _reserve_fields())
    assert not bad, (
        f"{path.relative_to(_SRC)} converts a RESERVE with normalize_to (which floors): "
        + "; ".join(f"line {ln}: .{name}.normalize_to(...)" for ln, name in bad)
        + ". Use _reserve_to_blocks, which ceils. Flooring under-counts the reserve and declares "
        "the counter-leg claim final earlier than the gate requires."
    )


def test_the_scanner_can_actually_see_the_defect() -> None:
    """Non-vacuity. The parametrised sweep above passes on a tree with no matches; prove that a
    match is something it can find, rather than trusting a green run over 200 files."""
    planted = "required = policy.btc_claim_reorg_depth.normalize_to(unit, block_interval_s=i).value"
    assert _floor_conversions(planted, _reserve_fields()) == [(1, "btc_claim_reorg_depth")]


def test_a_deadline_is_left_alone() -> None:
    """The other direction. `t_rxd` is a DEADLINE on NegotiatedTerms, where flooring is correct —
    a guard that refused it would be refusing valid work."""
    ok = "x = terms.t_rxd.normalize_to(unit, block_interval_s=i)"
    assert _floor_conversions(ok, _reserve_fields()) == []


class TestTheConversionsAgreeOnARealValue:
    """The structural check pins the call; this pins the ARITHMETIC it exists to protect.

    3700 s at 600 s/block is 6.17 blocks. Chosen because floor and ceil DIFFER here — a value where
    they agree would let a conflation pass unnoticed, which is how the parity sweep in #581 shared
    production's own defect.
    """

    RESERVE = Timelock(3700, TimeUnit.SECONDS)
    INTERVAL = 600.0

    def test_the_reserve_conversion_rounds_up(self) -> None:
        assert _reserve_to_blocks(self.RESERVE, self.INTERVAL) == 7

    def test_the_deadline_conversion_rounds_down(self) -> None:
        floored = self.RESERVE.normalize_to(TimeUnit.BLOCKS, block_interval_s=self.INTERVAL).value
        assert floored == 6, "if these ever agree, this fixture has stopped discriminating"

    def test_the_extra_block_changes_the_gate_verdict(self) -> None:
        """Why the block matters: at depth 6 the two conversions disagree about FINALITY itself."""
        assert CounterClaimFinality.from_btc_depth(6, _reserve_to_blocks(self.RESERVE, self.INTERVAL)) is not (
            CounterClaimFinality.from_btc_depth(
                6, self.RESERVE.normalize_to(TimeUnit.BLOCKS, block_interval_s=self.INTERVAL).value
            )
        )

    def test_a_blocks_tagged_reserve_is_unchanged(self) -> None:
        """Honest path, and the reason this fix is a no-op today: everything shipped constructs
        BLOCKS-tagged reserves, where both conversions are the identity."""
        blocks = Timelock(7, TimeUnit.BLOCKS)
        assert _reserve_to_blocks(blocks, self.INTERVAL) == 7
        assert blocks.normalize_to(TimeUnit.BLOCKS, block_interval_s=self.INTERVAL).value == 7


class TestTheGuardAllowsAJustifiedFloor:
    """Both directions. A guard that cannot be satisfied by correct code is a guard that will be
    deleted the first time it blocks someone."""

    def test_a_marked_site_is_allowed(self) -> None:
        marked = (
            "# floor-is-deliberate: burial feeds max_protected_value, where larger permits more.\n"
            "b = policy.rxd_claim_burial.normalize_to(unit, block_interval_s=i).value"
        )
        assert _floor_conversions(marked, _reserve_fields()) == []

    def test_an_unmarked_site_is_still_caught(self) -> None:
        assert _floor_conversions(
            "b = policy.rxd_claim_burial.normalize_to(unit, block_interval_s=i).value", _reserve_fields()
        ) == [(1, "rxd_claim_burial")]

    def test_a_marker_far_above_does_not_excuse_it(self) -> None:
        """Scoped to the lines just above the call. A marker anywhere in the file would let one
        justified site excuse every later one — the failure the 260-char window caused in the
        published-spec guard on this same branch."""
        far = (
            "# floor-is-deliberate: about something else\n"
            + ("x = 1\n" * 20)
            + ("b = policy.rxd_claim_burial.normalize_to(unit, block_interval_s=i).value")
        )
        assert _floor_conversions(far, _reserve_fields())

"""Every `Timelock` field on `MarginPolicy` carries a floor, and every floor names a real field.

WHY THIS EXISTS. `__post_init__` validated a HAND-KEPT list of three fields. When #511 added
`rxd_claim_inclusion` it was simply left off — a fail-OPEN omission: `Timelock(0)` was accepted and
silently restored the pre-#511 floor the field exists to raise, and a bare `int` was accepted at
construction to fail much later with an `AttributeError` instead of a fail-closed `ValidationError`.

The first fix hand-typed a fourth check beside the other three. Same shape, one instance later —
which is this codebase's most-repeated defect and the reason the second fix derives the check from a
table and this file cross-checks the table against the dataclass ITSELF.

BOTH DIRECTIONS MATTER. A field with no floor is the #511 gap again. A floor naming a field that no
longer exists is a check that silently stopped running.
"""

from __future__ import annotations

import dataclasses

import pytest

import pyrxd.btc_wallet.taproot as t
from pyrxd.gravity.swap_coordinator import _TIMELOCK_FLOORS, MarginPolicy
from pyrxd.security.errors import ValidationError

#: Deliberately unfloored. `margin` is a policy quantity with no protocol-imposed minimum — a dust
#: run legitimately uses 3 — and what bounds it is the wall-clock gate (#567), not a constant here.
_INTENTIONALLY_UNFLOORED = {"margin"}


def _timelock_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(MarginPolicy) if "Timelock" in str(f.type) and "None" not in str(f.type)}


def _base(**kw) -> dict:
    return {
        "margin": t.Timelock(36, t.TimeUnit.BLOCKS),
        "block_interval_s": 600.0,
        "is_measured": False,
        **kw,
    }


class TestTheFloorTableMatchesTheDataclass:
    def test_every_timelock_field_has_a_floor_or_is_listed_as_exempt(self) -> None:
        """The #511 gap, as a test. A field added without a floor fails HERE, at the moment it is
        added, instead of being discovered by a security panel months later."""
        missing = _timelock_fields() - set(_TIMELOCK_FLOORS) - _INTENTIONALLY_UNFLOORED
        assert not missing, (
            f"MarginPolicy Timelock fields with no floor and no exemption: {sorted(missing)}. "
            "Add them to _TIMELOCK_FLOORS, or to _INTENTIONALLY_UNFLOORED with a reason."
        )

    def test_every_floor_names_a_field_that_still_exists(self) -> None:
        """The other direction: a floor for a renamed or deleted field is a check that stopped
        running, and nothing else would notice."""
        stale = set(_TIMELOCK_FLOORS) - _timelock_fields()
        assert not stale, f"_TIMELOCK_FLOORS names fields MarginPolicy no longer has: {sorted(stale)}"

    def test_the_scan_actually_finds_fields(self) -> None:
        """Guard the guard: an annotation-matching heuristic that matches nothing makes both
        assertions above vacuously true."""
        found = _timelock_fields()
        assert len(found) >= 4, f"the Timelock-field scan found only {found} — the heuristic is wrong"
        assert "margin" in found and "rxd_claim_burial" in found


class TestEveryFlooredFieldIsActuallyEnforced:
    """The table existing is not the same as it being applied. Drive each field to its floor - 1."""

    @pytest.mark.parametrize("label", sorted(_TIMELOCK_FLOORS))
    def test_one_below_the_floor_is_REFUSED(self, label: str) -> None:
        floor = _TIMELOCK_FLOORS[label]
        with pytest.raises(ValidationError, match=label):
            MarginPolicy(**_base(**{label: t.Timelock(floor - 1, t.TimeUnit.BLOCKS)}))

    @pytest.mark.parametrize("label", sorted(_TIMELOCK_FLOORS))
    def test_exactly_the_floor_is_ACCEPTED(self, label: str) -> None:
        """Paired honest path. A floor that refuses its own boundary is a guard refusing valid
        work — and on this chain that costs a claim."""
        floor = _TIMELOCK_FLOORS[label]
        MarginPolicy(**_base(**{label: t.Timelock(floor, t.TimeUnit.BLOCKS)}))

    @pytest.mark.parametrize("label", sorted(_TIMELOCK_FLOORS))
    def test_a_bare_int_FAILS_CLOSED_rather_than_later(self, label: str) -> None:
        """`Timelock` is not `int`. Accepting one at construction defers the failure to an
        `AttributeError` deep in the arithmetic, which is not a fail-closed path."""
        with pytest.raises(ValidationError, match="must be a Timelock"):
            MarginPolicy(**_base(**{label: 2}))

    def test_a_SECONDS_tagged_value_is_normalised_before_the_floor_is_applied(self) -> None:
        """The floor is in BLOCKS, so a seconds-tagged reserve must be converted first — otherwise
        `Timelock(1, SECONDS)` would pass a 2-block floor on its raw number.

        The VALUES changed with #579, the property did not. `rxd_claim_burial` counts RADIANT
        blocks, so it converts at the Radiant interval (300 s default), not the Bitcoin one
        (600 s). Under the old arithmetic 600 s read as 1 block; it is 2 Radiant blocks, which is
        what a Radiant burial of 600 s actually is. Deliberately using the two intervals'
        DIFFERENT values here — equal intervals would hide exactly the conflation this pins.
        """
        with pytest.raises(ValidationError, match="rxd_claim_burial"):
            MarginPolicy(**_base(rxd_claim_burial=t.Timelock(300, t.TimeUnit.SECONDS)))  # 1 RXD block
        MarginPolicy(**_base(rxd_claim_burial=t.Timelock(600, t.TimeUnit.SECONDS)))  # 2 RXD blocks

    def test_a_BITCOIN_reserve_still_converts_at_the_BITCOIN_interval(self) -> None:
        """The other half of #579: only the RADIANT fields moved. `btc_claim_reorg_depth` counts
        Bitcoin blocks and must keep the Bitcoin interval, or the fix would have swapped one
        conflation for its mirror image."""
        with pytest.raises(ValidationError, match="btc_claim_reorg_depth"):
            MarginPolicy(**_base(btc_claim_reorg_depth=t.Timelock(600, t.TimeUnit.SECONDS)))  # 1 BTC block
        MarginPolicy(**_base(btc_claim_reorg_depth=t.Timelock(1200, t.TimeUnit.SECONDS)))  # 2 BTC blocks

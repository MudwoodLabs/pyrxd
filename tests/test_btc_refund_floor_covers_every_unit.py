"""A zero relative lock must be refused however it is spelled.

`refund_leaf_script`'s floor was `unit is BLOCKS and value < 1`, under a comment
saying "every caller gets the floor by construction". That was false for a
SECONDS-tagged Timelock: BIP68 quantises time locks to 512 s, so
`Timelock(0..511, SECONDS)` all encode to `nSequence = 0x00400000` — zero time
units, the SAME no-op relative lock, emitted without complaint.

REACHABLE END TO END, not theoretical. Nothing in `pyrxd` or `scripts/` constructs
a SECONDS `t_btc`, but `NegotiatedTerms.from_dict` takes the unit tag straight off
the wire, `swap_state`'s own `t_btc` floor was scoped to BLOCKS in exactly the same
way, and its ordering guard only fires when both units match. So a
counterparty-authored envelope carrying `{"value": 0, "unit": "seconds"}` reached
this function and produced a refund leaf spendable in its own funding block — the
#482-shaped free option, one unit tag away from the floor meant to stop it.

The fix derives the refusal from `csv_script_operand()` instead of the tag, so it
is unit-agnostic by construction. That is the difference between a floor and a
floor for the one spelling someone thought of — the defect class this repo keeps
meeting.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.btc_wallet.taproot import Timelock, TimeUnit, refund_leaf_script
from pyrxd.constants import SEQUENCE_LOCKTIME_MASK
from pyrxd.security.errors import ValidationError


@pytest.fixture
def pk() -> bytes:
    return os.urandom(32)


class TestEveryZeroLockIsRefused:
    @pytest.mark.parametrize(
        ("value", "unit"),
        [(0, TimeUnit.BLOCKS), (0, TimeUnit.SECONDS), (1, TimeUnit.SECONDS), (511, TimeUnit.SECONDS)],
        ids=["0 blocks", "0 seconds", "1 second", "511 seconds"],
    )
    def test_it_is_refused(self, value: int, unit: TimeUnit, pk: bytes) -> None:
        with pytest.raises(ValidationError, match="ZERO|no-op"):
            refund_leaf_script(pk, Timelock(value, unit))

    def test_the_sub_512_second_values_really_DO_encode_to_zero(self) -> None:
        """The premise. If BIP68 ever stopped quantising, these would be honest
        values and refusing them would become a guard refusing valid work."""
        for seconds in (0, 1, 300, 511):
            assert Timelock(seconds, TimeUnit.SECONDS).csv_script_operand() & SEQUENCE_LOCKTIME_MASK == 0

    def test_the_refusal_names_the_unit_it_was_given(self) -> None:
        """A caller who wrote 511 seconds needs to be told why that is zero."""
        with pytest.raises(ValidationError, match="511 seconds"):
            refund_leaf_script(os.urandom(32), Timelock(511, TimeUnit.SECONDS))


class TestNothingHonestIsRefused:
    """The paired half. This guard sits on the refund path of a live swap — refusing
    an honest timeout strands the counter leg."""

    @pytest.mark.parametrize("blocks", [1, 2, 6, 144, 1000, SEQUENCE_LOCKTIME_MASK])
    def test_every_nonzero_block_count_is_accepted(self, blocks: int, pk: bytes) -> None:
        assert refund_leaf_script(pk, Timelock(blocks, TimeUnit.BLOCKS))

    @pytest.mark.parametrize("seconds", [512, 1024, 3600, 86_400])
    def test_every_real_time_lock_is_accepted(self, seconds: int, pk: bytes) -> None:
        assert refund_leaf_script(pk, Timelock(seconds, TimeUnit.SECONDS))

    def test_512_seconds_is_the_boundary(self, pk: bytes) -> None:
        """One BIP68 unit — the smallest time lock that is not zero."""
        with pytest.raises(ValidationError):
            refund_leaf_script(pk, Timelock(511, TimeUnit.SECONDS))
        assert refund_leaf_script(pk, Timelock(512, TimeUnit.SECONDS))

    def test_the_leaf_is_unchanged_for_accepted_values(self, pk: bytes) -> None:
        """Widening a refusal must not alter the bytes of anything it still accepts:
        this leaf is committed to the taptree, so a change would move the HTLC
        address and strand every existing swap."""
        leaf = refund_leaf_script(pk, Timelock(6, TimeUnit.BLOCKS))
        assert leaf.startswith(b"\x56\xb2\x75")  # OP_6 OP_CSV OP_DROP
        assert leaf.endswith(b"\xac")  # OP_CHECKSIG


class TestTheWireCannotSmuggleOneIn:
    """The path that made this reachable: the unit tag comes off the wire."""

    def test_the_deserialiser_still_accepts_a_seconds_tag(self) -> None:
        """Unchanged on purpose — SECONDS is a legitimate unit. The floor is what
        had to become unit-agnostic, not the parser."""
        from pyrxd.gravity.swap_state import _timelock_from_dict

        assert _timelock_from_dict({"value": 0, "unit": "seconds"}).unit is TimeUnit.SECONDS

    def test_but_the_leaf_builder_refuses_it(self) -> None:
        """So the envelope can carry it and the bytes can never be built."""
        from pyrxd.gravity.swap_state import _timelock_from_dict

        smuggled = _timelock_from_dict({"value": 0, "unit": "seconds"})
        with pytest.raises(ValidationError):
            refund_leaf_script(os.urandom(32), smuggled)

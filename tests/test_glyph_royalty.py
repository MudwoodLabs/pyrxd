"""Royalty arithmetic and payout resolution — offline, no network.

The thing these tests are really guarding is the claim in
``pyrxd/glyph/royalty.py``'s docstring: that a royalty is a number pyrxd chooses
to pay, not one the chain compels. So they check the arithmetic against
Photonic's ``calculateRoyalty`` (``packages/lib/src/royalty.ts``), the two
deliberate deviations on the splits path, and the invariant that makes the
result auditable — ``sum(payouts) == royalty_due``.

They also cover the failure Photonic's own type shares with pyrxd's:
``GlyphRoyalty`` accepts any non-empty ``address`` string, so an unusable
address survives minting and is only detectable at payment time.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.royalty import (
    RoyaltyPayout,
    royalty_due,
    royalty_output_scripts,
    royalty_payouts,
)
from pyrxd.glyph.types import GlyphRoyalty
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError

# Real, derived addresses — never hand-written key material (a weak inline key
# in this repo's history was swept by a live bot).
_CREATOR = PrivateKey().public_key().address()
_SPLIT_A = PrivateKey().public_key().address()
_SPLIT_B = PrivateKey().public_key().address()


class TestRoyaltyDue:
    """``min(max(minimum, floor(sale_price * bps / 10_000)), sale_price)``.

    The ``max`` half is Photonic parity. The ``min`` half is a pyrxd bound that
    Photonic does not have — see :class:`TestMinimumIsBounded`.
    """

    @pytest.mark.parametrize(
        ("bps", "price", "expected"),
        [
            (500, 10_000, 500),  # royalty.test.ts: 5% of 10000 -> 500
            (250, 10_000, 250),  # 2.5%
            (500, 0, 0),  # zero price -> zero royalty
            (333, 1_000, 33),  # floors, does not round (33.3 -> 33)
            (10_000, 1_000, 1_000),  # 100%
            (0, 1_000_000, 0),  # no rate declared
        ],
    )
    def test_matches_photonic_calculate_royalty(self, bps, price, expected):
        assert royalty_due(GlyphRoyalty(bps=bps, address=_CREATOR), price) == expected

    def test_minimum_raises_a_small_percentage(self):
        r = GlyphRoyalty(bps=100, address=_CREATOR, minimum=1_000)
        assert royalty_due(r, 1_000) == 1_000  # 1% of 1000 = 10, floored up to 1000

    def test_minimum_does_not_cap_a_large_percentage(self):
        r = GlyphRoyalty(bps=1_000, address=_CREATOR, minimum=50)
        assert royalty_due(r, 10_000) == 1_000

    def test_negative_price_refused(self):
        with pytest.raises(ValidationError, match="sale_price must be >= 0"):
            royalty_due(GlyphRoyalty(bps=500, address=_CREATOR), -1)

    def test_bool_price_refused(self):
        # bool is an int subclass; True would silently mean "1 photon".
        with pytest.raises(ValidationError, match="must be an int"):
            royalty_due(GlyphRoyalty(bps=500, address=_CREATOR), True)


class TestMinimumIsBounded:
    """``minimum`` is an unbounded integer chosen by the token's creator.

    ``GlyphRoyalty`` only requires ``minimum >= 0``, nothing at mint time checks
    it, and nothing on chain does either — so a token can declare
    ``minimum = 10**15``. That number is not paid by a buyer: it is paid out of
    the funding inputs of whoever moves the token, by a wallet that supplied the
    royalty because it was trying to be honest. The payable total is therefore
    capped at the consideration.
    """

    @pytest.mark.parametrize("minimum", [10**9, 10**15, 21_000_000_000 * 100_000_000])
    def test_a_huge_minimum_cannot_exceed_the_sale_price(self, minimum):
        r = GlyphRoyalty(bps=100, address=_CREATOR, minimum=minimum)
        assert royalty_due(r, 10_000) == 10_000

    def test_a_huge_minimum_on_a_zero_price_transfer_pays_nothing(self):
        """The flat-fee-on-a-gift path is gone; it was the unbounded-spend path."""
        r = GlyphRoyalty(bps=0, address=_CREATOR, minimum=10**15)
        assert royalty_due(r, 0) == 0
        assert royalty_payouts(r, 0) == ()

    def test_a_minimum_below_the_sale_price_is_untouched(self):
        r = GlyphRoyalty(bps=100, address=_CREATOR, minimum=1_000)
        assert royalty_due(r, 10_000) == 1_000  # 1% = 100, raised to the minimum

    def test_a_100_percent_royalty_is_still_exactly_the_sale_price(self):
        """The cap must not clip a legitimately-declared full-price royalty."""
        r = GlyphRoyalty(bps=10_000, address=_CREATOR)
        assert royalty_due(r, 12_345) == 12_345


class TestRoyaltyPayouts:
    def test_single_recipient(self):
        payouts = royalty_payouts(GlyphRoyalty(bps=500, address=_CREATOR), 10_000)
        assert len(payouts) == 1
        assert payouts[0].address == _CREATOR
        assert payouts[0].photons == 500
        assert len(payouts[0].pkh) == 20

    def test_zero_total_pays_nobody(self):
        assert royalty_payouts(GlyphRoyalty(bps=500, address=_CREATOR), 0) == ()

    def test_splits_sum_exactly_to_the_total(self):
        r = GlyphRoyalty(
            bps=1_000,
            address=_CREATOR,
            splits=((_SPLIT_A, 600), (_SPLIT_B, 400)),
        )
        payouts = royalty_payouts(r, 100_000)
        assert sum(p.photons for p in payouts) == royalty_due(r, 100_000) == 10_000
        assert [p.address for p in payouts] == [_SPLIT_A, _SPLIT_B]
        assert [p.photons for p in payouts] == [6_000, 4_000]

    def test_minimum_is_honoured_on_the_splits_path(self):
        """Deviation 1 from Photonic.

        ``buildRoyaltyOutputs`` computes each split from ``sale_price`` directly
        and never consults ``minimum``, so declaring a minimum and then adding a
        second recipient silently drops it. pyrxd computes the total once and
        divides that.
        """
        r = GlyphRoyalty(
            bps=100,
            address=_CREATOR,
            minimum=50_000,
            splits=((_SPLIT_A, 50), (_SPLIT_B, 50)),
        )
        # Priced above the minimum so the sale-price cap is not what is under
        # test here — see TestMinimumIsBounded for that.
        payouts = royalty_payouts(r, 1_000_000)
        # Photonic would pay floor(1_000_000 * 50/10000) = 5_000 each, 10_000 total.
        assert sum(p.photons for p in payouts) == 50_000
        assert [p.photons for p in payouts] == [25_000, 25_000]

    def test_residue_from_under_covering_splits_goes_to_the_top_level_address(self):
        """Deviation 2: GlyphRoyalty allows sum(split bps) < bps."""
        r = GlyphRoyalty(bps=1_000, address=_CREATOR, splits=((_SPLIT_A, 600),))
        payouts = royalty_payouts(r, 100_000)
        assert sum(p.photons for p in payouts) == 10_000
        assert {p.address: p.photons for p in payouts} == {_SPLIT_A: 6_000, _CREATOR: 4_000}

    def test_rounding_residue_is_not_lost(self):
        r = GlyphRoyalty(bps=3, address=_CREATOR, splits=((_SPLIT_A, 1), (_SPLIT_B, 1), (_CREATOR, 1)))
        total = royalty_due(r, 100_001)
        payouts = royalty_payouts(r, 100_001)
        assert sum(p.photons for p in payouts) == total

    def test_repeated_address_is_merged_into_one_output(self):
        """The residue recipient may also be a split recipient."""
        r = GlyphRoyalty(bps=1_000, address=_SPLIT_A, splits=((_SPLIT_A, 600),))
        payouts = royalty_payouts(r, 100_000)
        assert len(payouts) == 1
        assert payouts[0].address == _SPLIT_A
        assert payouts[0].photons == 10_000

    def test_zero_share_recipient_is_dropped(self):
        r = GlyphRoyalty(bps=1_000, address=_CREATOR, splits=((_SPLIT_A, 1_000), (_SPLIT_B, 0)))
        payouts = royalty_payouts(r, 100_000)
        assert [p.address for p in payouts] == [_SPLIT_A]

    def test_undecodable_address_is_caught_here_not_on_chain(self):
        """GlyphRoyalty only checks non-empty; this is where a typo dies."""
        r = GlyphRoyalty(bps=500, address="not-an-address")
        with pytest.raises(ValidationError, match="not a decodable Radiant address"):
            royalty_payouts(r, 10_000)

    def test_undecodable_split_address_is_caught(self):
        r = GlyphRoyalty(bps=500, address=_CREATOR, splits=(("nope", 500),))
        with pytest.raises(ValidationError, match="not a decodable Radiant address"):
            royalty_payouts(r, 10_000)


class TestRoyaltyOutputScripts:
    def test_scripts_are_plain_p2pkh_and_carry_no_ref(self):
        payouts = royalty_payouts(GlyphRoyalty(bps=500, address=_CREATOR), 10_000)
        outs = royalty_output_scripts(payouts)
        assert len(outs) == 1
        spk, photons = outs[0]
        assert photons == 500
        # 25-byte P2PKH: no OP_PUSHINPUTREF (0xd0) and no singleton (0xd8), so
        # the output contributes to no ref's conservation sum.
        assert len(spk) == 25
        assert spk[:3] == b"\x76\xa9\x14"
        assert spk[23:] == b"\x88\xac"
        assert 0xD0 not in spk[:1]
        assert spk[0] != 0xD8

    def test_empty_payouts_give_empty_scripts(self):
        assert royalty_output_scripts(()) == ()

    def test_payout_is_frozen(self):
        import dataclasses

        p = RoyaltyPayout(address=_CREATOR, pkh=b"\x00" * 20, photons=1)
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.photons = 2  # type: ignore[misc]

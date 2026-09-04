"""Everything `swap reserve` accepts must be refundable. It was not.

`pyrxd swap reserve` printed, on the interactive consent screen:

    * Reclaim at --expiry is GUARANTEED — `pyrxd swap refund` always works
      at/after that height (barring a lost key).

Its only amount guard refused below the 546-photon DUST floor. But a refund is a
one-in-one-out spend that pays its fee OUT OF the covenant value and must still
leave a non-dust output, so it needs the relay fee for its own size PLUS dust —
roughly 2,000,000 photons at the mainnet floor, not 546.

MEASURED through the production builders before the fix: reservations of 546,
100,000, 1,000,000 and 1,900,000 photons were all accepted and then produced NO
refund at any fee. `swap cancel` — documented as "the ONLY hard revocation" —
fails identically. Those funds were unreachable by any pyrxd path, under an
unconditional guarantee.

The guard existed and was sized to the wrong quantity. Its own comment named the
right one: "a covenant UTXO the maker could not later fill or refund".

WHY NO TEST SAW IT: every fixture in `test_swap_and_nft_fee_floors.py` uses
`_RESERVE = 500_000_000`, commented "big enough to pay a real fee out of", and the
only sub-floor case uses `photons=100` — below dust, so it was refused for the
other reason. The band between dust and the real floor was never expressed.
"""

from __future__ import annotations

import os

import pytest

from pyrxd.fee_sizing import radiant_relay_size
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import ValidationError
from pyrxd.swap import FundingInput
from pyrxd.swap.rswp.covenant import (
    _DUST_PHOTONS,
    _REFUND_TX_BYTES,
    build_covenant_refund_tx,
    minimum_reservable_photons,
    prepare_covenant_offer,
)
from tests.test_swap_and_nft_fee_floors import _EXPIRY, _rxd_src


def _maker():
    key = PrivateKey(os.urandom(32))
    return key, key.public_key().hash160()


def _reserve(photons: int):
    key, pkh = _maker()
    tx = prepare_covenant_offer(
        funding=[FundingInput(_rxd_src(pkh, photons + 900_000_000), 0, key)],
        photons=photons,
        owner_pkh=pkh,
        expiry_height=_EXPIRY,
        change_pkh=pkh,
        fee=10_000_000,
    )
    return key, pkh, tx


def _is_refundable(photons: int) -> bool:
    key, pkh, tx = _reserve(photons)
    for fee in (546, 500_000, 1_000_000, 2_000_000, 3_000_000, photons // 2, photons - 546):
        if fee <= 0:
            continue
        try:
            build_covenant_refund_tx(covenant_source_tx=tx, covenant_vout=0, maker_key=key, refund_pkh=pkh, fee=fee)
        except Exception:
            continue
        return True
    return False


class TestTheGuaranteeHolds:
    """The property, swept — not a restatement of the constant."""

    @pytest.mark.parametrize("over", [0, 1, 10_000, 500_000_000])
    def test_everything_the_guard_ACCEPTS_can_be_refunded(self, over: int) -> None:
        assert _is_refundable(minimum_reservable_photons() + over)

    @pytest.mark.parametrize("photons", [546, 100_000, 1_000_000, 1_900_000])
    def test_the_old_unreclaimable_band_is_now_REFUSED_AT_RESERVE(self, photons: int) -> None:
        """Each of these was accepted, guaranteed reclaimable, and unrefundable."""
        assert photons >= _DUST_PHOTONS, "these were all above the old dust-only floor"
        with pytest.raises(ValidationError, match="cannot fund its own refund"):
            _reserve(photons)

    def test_the_boundary_is_exact_in_both_directions(self) -> None:
        floor = minimum_reservable_photons()
        with pytest.raises(ValidationError):
            _reserve(floor - 1)
        assert _is_refundable(floor)


class TestTheFloorIsNeitherTooLowNorTooHigh:
    """Both directions are defects. Too low re-opens the unreclaimable band; too
    high refuses honest reservations that could in fact be refunded — the first
    draft of this guessed 320 bytes and would have refused down to ~1.6x the real
    floor."""

    def test_the_size_constant_covers_a_REAL_refund(self) -> None:
        key, pkh, tx = _reserve(500_000_000)
        refund = build_covenant_refund_tx(
            covenant_source_tx=tx, covenant_vout=0, maker_key=key, refund_pkh=pkh, fee=5_000_000
        )
        assert radiant_relay_size(refund.serialize()) <= _REFUND_TX_BYTES

    def test_it_covers_the_DER_length_tail(self) -> None:
        """Signature length varies by key, so one sample is not the maximum."""
        sizes = []
        for _ in range(12):
            key, pkh, tx = _reserve(500_000_000)
            refund = build_covenant_refund_tx(
                covenant_source_tx=tx, covenant_vout=0, maker_key=key, refund_pkh=pkh, fee=5_000_000
            )
            sizes.append(radiant_relay_size(refund.serialize()))
        assert max(sizes) <= _REFUND_TX_BYTES

    def test_it_is_not_wildly_oversized(self) -> None:
        """A constant far above the real size is a guard refusing valid work."""
        key, pkh, tx = _reserve(500_000_000)
        refund = build_covenant_refund_tx(
            covenant_source_tx=tx, covenant_vout=0, maker_key=key, refund_pkh=pkh, fee=5_000_000
        )
        real = radiant_relay_size(refund.serialize())
        assert real * 1.5 > _REFUND_TX_BYTES, f"{_REFUND_TX_BYTES} vs a real {real} bytes"

    def test_the_floor_is_dust_PLUS_a_fee_not_dust_alone(self) -> None:
        """The whole defect in one assertion."""
        assert minimum_reservable_photons() > _DUST_PHOTONS * 100

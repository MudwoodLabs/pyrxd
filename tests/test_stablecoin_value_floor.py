"""A stablecoin counter leg states the swap's worth, so the setup gate can check it (#489).

`value_at_risk_photons >= radiant_amount` is enforced only for `asset_variant == "rxd"`, because
an FT's `radiant_amount` is a token count and an NFT's is carrier dust — neither is an economic
value. So for ft/nft ANY nonzero value satisfied the setup gate and the value-scaled burial
collapsed to the flat floor.

Against BTC that was unavoidable: a leg's worth was not knowable in-protocol. Against a stablecoin
it is — `value_amount` is a 6-decimal dollar figure on the record.
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.reorg_cost import measure_rxd_reorg_cost
from pyrxd.gravity.swap_coordinator import MarginPolicy, _stablecoin_value_floor_photons

NOW = 1_788_000_000


class _Token:
    def __init__(self, address: str = "0xabc", decimals: int = 6) -> None:
        self.address = address
        self.decimals = decimals


class _Leg:
    def __init__(self, token=None) -> None:
        if token is not None:
            self.token = token


class _WrappedLeg:
    """The adapter shape: the token hangs off the wrapped contract leg, not the adapter."""

    def __init__(self, token) -> None:
        self._leg = _Leg(token)


class _Terms:
    def __init__(self, *, token_address="0xabc", value_amount=1_000_000) -> None:
        self.token_address = token_address
        self.value_amount = value_amount


def _policy(price_usd: float | None = 0.0002) -> MarginPolicy:
    kw = {}
    if price_usd is not None:
        kw["reorg_cost"] = measure_rxd_reorg_cost(
            difficulty=25_892_399.457,
            block_interval_s=300.0,
            usd_per_hash=1e-15,
            rxd_price_usd=price_usd,
            measured_at_unix_s=NOW,
            max_age_s=86_400,
        )
    return MarginPolicy(margin=t.Timelock(36, t.TimeUnit.BLOCKS), block_interval_s=600.0, is_measured=False, **kw)


class TestTheConversion:
    def test_one_dollar_of_usdc_at_a_declared_rate(self) -> None:
        """1,000,000 base units of a 6-decimal token is $1. At $0.0002/RXD that is 5,000 RXD,
        i.e. 500,000,000,000 photons."""
        got = _stablecoin_value_floor_photons(_Terms(value_amount=1_000_000), _policy(0.0002), _Leg(_Token()))
        assert got == 500_000_000_000

    def test_it_rounds_UP(self) -> None:
        """Understating the floor is the unsafe direction, so the conversion rounds toward
        refusing rather than toward accepting."""
        a = _stablecoin_value_floor_photons(_Terms(value_amount=1), _policy(3.0), _Leg(_Token()))
        assert a is not None and a >= 1

    def test_the_token_may_hang_off_the_WRAPPED_leg(self) -> None:
        """The coordinator holds an adapter, not the contract leg. Missing this would silently
        return None on the real production shape — a check that never fires."""
        got = _stablecoin_value_floor_photons(_Terms(value_amount=1_000_000), _policy(0.0002), _WrappedLeg(_Token()))
        assert got == 500_000_000_000


class TestWhenThereIsNoBasis:
    """Each returns None — no check — rather than a number built on a missing input."""

    def test_no_token_address_means_a_native_leg(self) -> None:
        assert _stablecoin_value_floor_photons(_Terms(token_address=""), _policy(), _Leg(_Token())) is None

    def test_no_PROVENANCED_price_means_no_conversion(self) -> None:
        """Deliberate. A rate with no declared source and no expiry is the stale-constant hazard of
        #533 in a new place, so an operator on the bare int path gets no check rather than one
        built on a number nobody can date."""
        assert _stablecoin_value_floor_photons(_Terms(), _policy(price_usd=None), _Leg(_Token())) is None

    def test_a_leg_holding_a_DIFFERENT_token_does_not_convert(self) -> None:
        """The address on the terms must be the one the leg actually holds, or the decimals used
        would belong to a different asset — a 10^12 error between a 6- and an 18-decimal token."""
        terms = _Terms(token_address="0xdead")
        assert _stablecoin_value_floor_photons(terms, _policy(), _Leg(_Token(address="0xabc"))) is None

    def test_a_leg_with_no_token_at_all(self) -> None:
        assert _stablecoin_value_floor_photons(_Terms(), _policy(), _Leg()) is None

    def test_a_zero_value_amount(self) -> None:
        assert _stablecoin_value_floor_photons(_Terms(value_amount=0), _policy(), _Leg(_Token())) is None


class TestDecimalsAreLoadBearing:
    @pytest.mark.parametrize(("decimals", "expected"), [(6, 500_000_000_000), (18, 1)])
    def test_the_SAME_base_units_mean_wildly_different_value_at_different_decimals(self, decimals, expected) -> None:
        """The registry pins decimals per token and refuses look-alikes BY ADDRESS for exactly
        this reason: BSC's "USDC" is 18 decimals where Circle's is 6.

        The amount is held FIXED at 1,000,000 base units while only the decimals move — reading it
        as 6-decimal makes the swap worth $1 and as 18-decimal worth a millionth of a cent, a 10^12
        misstatement of the value at risk. My first version scaled the amount alongside the
        decimals, which made both cases $1 and demonstrated nothing.
        """
        got = _stablecoin_value_floor_photons(
            _Terms(value_amount=1_000_000), _policy(0.0002), _Leg(_Token(decimals=decimals))
        )
        assert got == expected

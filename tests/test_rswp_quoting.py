"""Quoting toolkit: exact-Fraction prices, maker-favorable rounding invariants."""

from __future__ import annotations

from fractions import Fraction

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyrxd.glyph.types import GlyphRef
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Txid
from pyrxd.swap import Asset, SwapTerms
from pyrxd.swap.rswp.quoting import PriceFeed, implied_price, quote_ladder, quote_legs

_REF = GlyphRef(txid=Txid("ab" * 32), vout=0)


# --------------------------------------------------------------------------- implied price


def test_implied_price_sell_and_buy_read_the_same_market() -> None:
    sell = SwapTerms(give=Asset("ft", 400, _REF), receive=Asset("rxd", 900))
    buy = SwapTerms(give=Asset("rxd", 900), receive=Asset("ft", 400, _REF))
    assert implied_price(sell) == implied_price(buy) == Fraction(900, 400)


def test_implied_price_is_exact_not_float() -> None:
    terms = SwapTerms(give=Asset("ft", 3, _REF), receive=Asset("rxd", 1))
    assert implied_price(terms) == Fraction(1, 3)  # a float would have lied here


@pytest.mark.parametrize(
    "terms",
    [
        SwapTerms(give=Asset("rxd", 10), receive=Asset("rxd", 20)),
        SwapTerms(give=Asset("ft", 10, _REF), receive=Asset("ft", 20, GlyphRef(txid=Txid("cd" * 32), vout=1))),
    ],
)
def test_implied_price_rejects_non_token_rxd_pairs(terms) -> None:
    with pytest.raises(ValidationError, match="token/RXD pair"):
        implied_price(terms)


# --------------------------------------------------------------------------- ladder


def test_ladder_shape_and_monotonicity() -> None:
    quotes = quote_ladder(Fraction(100), 200, [10, 20, 30])  # 2% spread
    sells = [q for q in quotes if q.side == "sell"]
    buys = [q for q in quotes if q.side == "buy"]
    assert len(sells) == len(buys) == 3
    assert [s.price for s in sells] == sorted(s.price for s in sells)  # asks rise with depth
    assert [b.price for b in buys] == sorted((b.price for b in buys), reverse=True)  # bids fall
    assert all(s.price > Fraction(100) > b.price for s, b in zip(sells, buys, strict=True))


@given(
    mid_num=st.integers(min_value=1, max_value=10**9),
    mid_den=st.integers(min_value=1, max_value=10**4),
    spread_bps=st.integers(min_value=0, max_value=2000),
    size=st.integers(min_value=1, max_value=10**9),
)
def test_rounding_is_always_maker_favorable(mid_num, mid_den, spread_bps, size) -> None:
    """sell: demanded photons >= exact size×ask; buy: given photons <= exact size×bid."""
    mid = Fraction(mid_num, mid_den)
    try:
        quotes = quote_ladder(mid, spread_bps, [size])
    except ValidationError:
        return  # zero-rounding / non-positive-bid guards are allowed to fire
    (sell,) = (q for q in quotes if q.side == "sell")
    (buy,) = (q for q in quotes if q.side == "buy")
    assert sell.receive_photons >= size * sell.price
    assert buy.give_photons <= size * buy.price
    assert buy.give_photons >= 1


def test_zero_rounding_buy_is_refused() -> None:
    with pytest.raises(ValidationError, match="0 photons"):
        quote_ladder(Fraction(1, 1000), 100, [10])  # 10 units at ~0.001 photon/unit


def test_too_wide_spread_refused() -> None:
    with pytest.raises(ValidationError, match="non-positive"):
        quote_ladder(Fraction(100), 10_000, [1, 1, 1, 1])  # level 4 bid would cross zero


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        (dict(mid=0, spread_bps=10, sizes=[1]), "positive"),
        (dict(mid=100, spread_bps=-1, sizes=[1]), "non-negative"),
        (dict(mid=100, spread_bps=10, sizes=[]), "at least 1"),
        (dict(mid=100, spread_bps=10, sizes=[0]), "positive"),
    ],
)
def test_ladder_input_validation(kwargs, match) -> None:
    with pytest.raises(ValidationError, match=match):
        quote_ladder(kwargs["mid"], kwargs["spread_bps"], kwargs["sizes"])


# --------------------------------------------------------------------------- order-leg composition


def test_quote_legs_compose_into_valid_assets_and_round_trip_the_price() -> None:
    quotes = quote_ladder(Fraction(150), 100, [40])
    for q in quotes:
        give, receive = quote_legs(q, _REF)
        terms = SwapTerms(give=give, receive=receive)  # Asset validation runs here
        got = implied_price(terms)
        # Maker-favorable: an order built from a sell quote implies >= the quoted
        # ask; from a buy quote it implies <= the quoted bid.
        assert got >= q.price if q.side == "sell" else got <= q.price


# --------------------------------------------------------------------------- price feed protocol


def test_price_feed_is_runtime_checkable() -> None:
    class StaticFeed:
        def __init__(self, price: Fraction) -> None:
            self._price = price

        async def mid_price(self, ref: GlyphRef) -> Fraction:
            return self._price

    assert isinstance(StaticFeed(Fraction(1)), PriceFeed)
    assert not isinstance(object(), PriceFeed)

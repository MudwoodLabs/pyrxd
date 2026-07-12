"""Market-maker quoting helpers for the RSWP orderbook — pure math, no price source.

pyrxd NEVER fabricates a price: the operator supplies the mid (their own
oracle behind the :class:`PriceFeed` protocol), and these helpers turn it into
exact integer order legs. All prices are :class:`fractions.Fraction` in
**photons per token unit** — floats never touch money here, and every rounding
step is explicit and maker-favorable (a posted order can round FOR the maker,
never against, because the ``0xC3`` signature freezes whatever was posted).

Composition with the order flows::

    give, receive = quote_legs(quote, ref)
    utxo_tx = prepare_offered_utxo(funding=…, asset=give, …)     # exact-amount UTXO
    post    = create_rswp_order(give_source_tx=utxo_tx, give_vout=0,
                                receive=receive, …)
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal, Protocol, runtime_checkable

from ...glyph.types import GlyphRef
from ...security.errors import ValidationError
from ..types import Asset, SwapTerms

_BPS = 10_000


@runtime_checkable
class PriceFeed(Protocol):
    """Operator-supplied mid-price oracle (pyrxd ships no implementation).

    Implementations MUST raise when a fresh price is unavailable — returning a
    stale or guessed mid would silently misprice every quote built from it.
    """

    async def mid_price(self, ref: GlyphRef) -> Fraction:
        """Current mid for the token, in photons per token unit."""
        ...  # pragma: no cover


def implied_price(terms: SwapTerms) -> Fraction:
    """The maker's demanded price implied by an order's terms, in photons per token unit.

    Reads either direction of a token/RXD order: for *sell* orders (give FT,
    want RXD) this is ``receive / give``; for *buy* orders (give RXD, want FT)
    it is ``give / receive``. Raises for RXD/RXD or FT/FT terms — "photons per
    unit" is not defined there (compare those with plain ``Fraction`` math on
    the amounts).
    """
    give, receive = terms.give, terms.receive
    if give.kind == "ft" and receive.kind == "rxd":
        return Fraction(receive.amount, give.amount)
    if give.kind == "rxd" and receive.kind == "ft":
        return Fraction(give.amount, receive.amount)
    raise ValidationError(f"implied_price needs a token/RXD pair, got {give.kind}/{receive.kind}")


@dataclass(frozen=True)
class LadderQuote:
    """One priced level of a two-sided ladder, with exact integer order legs.

    ``sell``: the maker gives ``size`` token units and demands
    ``receive_photons`` (= ``ceil(size × price)`` — the ceil is the
    maker-favorable direction). ``buy``: the maker gives ``give_photons``
    (= ``floor(size × price)``) and demands ``size`` token units.
    """

    side: Literal["sell", "buy"]
    level: int  # 0-based distance from mid
    size: int  # token units
    price: Fraction  # photons per token unit, as quoted
    give_photons: int | None  # buy side only
    receive_photons: int | None  # sell side only


def quote_ladder(mid: Fraction | int, spread_bps: int, sizes: Sequence[int]) -> list[LadderQuote]:
    """Build a two-sided quote ladder around *mid*.

    Level *i* (one per entry of *sizes*, both sides) is priced
    ``mid × (1 ± half_spread × (i+1))`` with ``half_spread = spread_bps/2``
    — deeper levels back away from mid linearly. Rounding is maker-favorable
    and explicit (see :class:`LadderQuote`). Raises if any buy level rounds
    to zero photons (size × price too small to be a real order) or if a bid
    would go non-positive (spread too wide for the level count).
    """
    if isinstance(mid, float):
        # A float mid introduces binary-rounding error into an exact-Fraction price ladder (review INFO);
        # require an exact type so the maker-favorable rounding is the ONLY rounding that happens.
        raise ValidationError("mid must be an int, Fraction, or decimal string — not a float (binary rounding)")
    mid = Fraction(mid)
    if mid <= 0:
        raise ValidationError(f"mid price must be positive, got {mid}")
    if spread_bps < 0:
        raise ValidationError("spread_bps must be non-negative")
    if not sizes:
        raise ValidationError("quote_ladder needs at least 1 size")
    half = Fraction(spread_bps, 2 * _BPS)

    quotes: list[LadderQuote] = []
    for level, size in enumerate(sizes):
        if size <= 0:
            raise ValidationError(f"ladder sizes must be positive, got {size}")
        ask = mid * (1 + half * (level + 1))
        bid = mid * (1 - half * (level + 1))
        if bid <= 0:
            raise ValidationError(
                f"level {level} bid is non-positive (spread {spread_bps} bps too wide for {len(sizes)} levels)"
            )
        receive = math.ceil(size * ask)
        give = math.floor(size * bid)
        if give <= 0:
            raise ValidationError(f"level {level} buy gives 0 photons for size {size} — size × price too small")
        quotes.append(
            LadderQuote(side="sell", level=level, size=size, price=ask, give_photons=None, receive_photons=receive)
        )
        quotes.append(
            LadderQuote(side="buy", level=level, size=size, price=bid, give_photons=give, receive_photons=None)
        )
    return quotes


def quote_legs(quote: LadderQuote, ref: GlyphRef) -> tuple[Asset, Asset]:
    """The ``(give, receive)`` assets an order for *quote* must post.

    ``give`` is exactly what :func:`~pyrxd.swap.rswp.orders.prepare_offered_utxo`
    should mint; ``receive`` goes straight into
    :func:`~pyrxd.swap.rswp.orders.create_rswp_order`.
    """
    if quote.side == "sell":
        return (
            Asset(kind="ft", amount=quote.size, ref=ref),
            Asset(kind="rxd", amount=quote.receive_photons),
        )
    return (
        Asset(kind="rxd", amount=quote.give_photons),
        Asset(kind="ft", amount=quote.size, ref=ref),
    )

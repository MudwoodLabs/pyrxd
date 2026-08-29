"""Zero-cost unit tags for the numbers this codebase has repeatedly conflated.

Why this module exists
----------------------
Three confirmed defects, all the same shape: two quantities that are both ``int``,
both non-negative, and semantically incompatible, met in a field or a parameter that
could hold either. No type system was ever asked to check them.

1. **Block height vs confirmation count.** ``UtxoRecord.height`` is documented as a
   block height. The mainnet ssh-tr shim — the only transport real-value RXD runs use —
   stored a CONFIRMATION COUNT there. ``RadiantChainIO.find_covenant_utxo`` resolves a
   multi-funded covenant scriptPubKey by "earliest-confirmed = min(height)" precisely
   because the honest funding necessarily precedes any poison; ascending height is
   oldest-first, ascending confs is NEWEST-first, so on that shim the anti-poisoning
   rule selected the POISON. A downstream runner then compensated with
   ``tip - confs + 1``, and when the producer was fixed the compensation became an
   inversion that would have armed an ungated claim.

2. **Token count vs native photon value.** ``NegotiatedTerms.radiant_amount`` holds an
   FT token amount, an NFT carrier photon value, or an RXD photon value depending on
   ``asset_variant`` — three units in one ``int``. The funding gate filters covenant
   UTXOs on their native photon ``value``, so for the FT variant it compares a TOKEN
   COUNT against a PHOTON VALUE (issue #505, still open).

3. **Seconds vs blocks** in the timelock arithmetic — two off-by-ones in one week.

How this differs from :mod:`pyrxd.security.types`
-------------------------------------------------
The two modules answer different questions and are meant to be used together:

* :mod:`pyrxd.security.types` — **is this number PLAUSIBLE?** ``Photons``,
  ``Satoshis``, ``BlockHeight`` are ``int`` subclasses that validate range at
  construction, at the trust boundary where a hostile server's number arrives.
* this module — **is this number the right KIND?** Every name here is a
  :func:`typing.NewType` over ``int``: a compile-time tag with *no* runtime behaviour
  and *no* validation. ``ChainHeight(x)`` is an identity call.

That split is deliberate. Reusing the validating classes as unit tags would have
attached a *new range check* to every producer that re-tagged a value — the exact
change that once made ``Satoshis`` (a cap 1000x too low for this chain) abort a whole
``listunspent`` comprehension and get healthy endpoints evicted. A unit tag must be
free, or it will not be applied where it matters.

Interop is one explicit call in each direction. ``BlockHeight`` is an ``int``, so
``ChainHeight(bh)`` re-tags it for free; going the other way, ``BlockHeight(h)``
validates, which is what you want at a header/merkle API boundary.

Using them
----------
Type the **producers** (where a number enters the process) and the **gates** (where a
decision is made on it). Do not thread tags through every intermediate — arithmetic on
a ``NewType`` over ``int`` yields a plain ``int``, so a computed value is re-tagged
once, at the point where you can state why it has that unit::

    height = ChainHeight(nonneg_int(item["height"]))       # producer: this IS a height
    deadline = ChainHeight(int(anchor) + int(csv_blocks))  # height + span = height

A re-tag is a claim. Put it where the claim is proven — usually right after the check
that establishes it (``if terms.asset_variant == "rxd": return PhotonValue(...)``) —
never to quiet the checker at a site that has proven nothing.
"""

from __future__ import annotations

from typing import NewType

__all__ = [
    "BlockSpan",
    "ChainHeight",
    "Confirmations",
    "PhotonValue",
    "Seconds",
    "TokenUnits",
]

# --------------------------------------------------------------------------- chain position

#: An ABSOLUTE block height — a position on the chain, not a distance from anywhere.
#: On a UTXO record ``0`` means "unconfirmed" and therefore sorts as newest, never as
#: oldest. Ascending ``ChainHeight`` is OLDEST-first; ascending :data:`Confirmations` is
#: NEWEST-first. Any ordering rule built on one inverts under the other.
ChainHeight = NewType("ChainHeight", int)

#: A confirmation DEPTH: how many blocks bury a transaction, i.e. ``tip - height + 1``
#: for a mined tx and ``0`` for an unmined one. A count, not a position. It changes every
#: block for a fixed transaction, which a :data:`ChainHeight` never does.
Confirmations = NewType("Confirmations", int)

# --------------------------------------------------------------------------- value

#: Native RXD value in photons (the chain's smallest unit) — what a UTXO's ``value``
#: field holds and what a covenant's carrier output is funded with. On Radiant this is
#: ALSO the Glyph FT quantity when the output carries an FT ref; see :data:`TokenUnits`.
PhotonValue = NewType("PhotonValue", int)

#: A Glyph fungible-token quantity — and on Radiant that IS a photon value, which is why
#: this is a NewType OVER :data:`PhotonValue` rather than beside it.
#:
#: **1 photon = 1 token unit** (``docs/concepts/radiant-fts-are-on-chain.md``).
#: ``OP_REFVALUESUM_OUTPUTS`` sums the native ``nValue`` of ref-bearing outputs
#: (Radiant-Core ``src/script/interpreter.cpp``), and :class:`~pyrxd.glyph.ft.FtUtxo`
#: RAISES on ``value != ft_amount`` because such an output cannot exist on chain.
#:
#: An earlier revision made this a NewType over ``int``, INDEPENDENT of ``PhotonValue``,
#: on the belief that "1000 tokens can sit on 546 photons of dust". That is the Bitcoin
#: colored-coin model (Atomicals/Runes) and Radiant does not use it. The consequence is
#: worth remembering: the incompatible pair produced a mypy error on CORRECT code, that
#: error was read as confirmation of issue #505, and a fix was written to refuse FT
#: swaps outright. A type system taught a distinction the chain does not make will
#: manufacture evidence for the bug you told it to expect.
#:
#: Kept as a subtype so the INTENT ("this number is a token quantity") is still
#: expressible, while a token quantity flows into a photon slot — because it is one.
TokenUnits = NewType("TokenUnits", PhotonValue)

# --------------------------------------------------------------------------- duration

#: A DURATION measured in blocks — a CSV operand, a required reorg depth, a margin.
#: Distinct from :data:`ChainHeight` (a position) and from :data:`Seconds`. Converting
#: between this and :data:`Seconds` needs a block interval and is floor-based, so the
#: conversion must be explicit and its rounding accounted for.
BlockSpan = NewType("BlockSpan", int)

#: A DURATION measured in wall-clock seconds — a BIP68 seconds-unit timelock, an ETH
#: contract ``timeout``, a poll interval. Never interchangeable with :data:`BlockSpan`.
Seconds = NewType("Seconds", int)

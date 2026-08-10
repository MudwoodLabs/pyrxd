"""Glyph royalty payment — **advisory**, not consensus-enforced.

Read this before using anything here
------------------------------------
A royalty on an ordinary Radiant token transfer is a **social convention**. A
compliant wallet honours it; a non-compliant one omits it and the transaction
confirms exactly the same. Nothing in Radiant consensus, and nothing in any
script pyrxd builds, forces a royalty output to exist.

The evidence, checked rather than assumed:

* The scripts a transfer produces are P2PKH-gated. ``build_nft_locking_script``
  (:mod:`pyrxd.glyph.script`) is ``OP_PUSHINPUTREFSINGLETON <ref> OP_DROP`` plus
  a bare P2PKH tail; ``build_ft_locking_script`` is a bare P2PKH prefix plus a
  ref/amount **conservation** epilogue. Conservation constrains *how much of the
  token* may exist on the output side. It says nothing about where **value**
  goes, so it cannot require a payment to anybody.
* No covenant that ships in pyrxd references a royalty — not the Gravity swap
  covenants, not the RSWP refund covenant, not the dMint V1/V2 contracts, not
  the timelock scripts.
* :class:`~pyrxd.glyph.types.GlyphRoyalty` describes itself as a *hint for
  secondary-market wallets*, and its ``enforced`` flag means "wallets should
  enforce", not "the chain will".
* Photonic Wallet — pyrxd's default reference — reaches the same structural
  conclusion. In ``packages/lib/src/royaltyCovenant.ts`` the NFT at rest lives
  in the ordinary ``nftScript``; enforcement exists only when a holder
  *voluntarily* lists it into a sale covenant, and that file's own "Honest
  scope" note records that the covenant cannot stop a malicious seller from
  crafting a non-compliant listing, nor a holder gifting the token out of band.

So a royalty **can** be made binding on a *buyer*, by putting the token into a
covenant that only releases it against the required outputs — that is what a
listing covenant does, and Radiant's introspection opcodes are perfectly capable
of it. It **cannot** be made binding on a *holder* who simply transfers the
token, because the holder chooses the transaction. pyrxd does not ship a listing
covenant today; see the deferral note in the CHANGELOG.

What this module therefore is
-----------------------------
The arithmetic and the outputs for a wallet that *chooses* to be honest. Callers
that hold a token's :class:`~pyrxd.glyph.types.GlyphRoyalty` and know the sale
price get the payout set; the transfer builders in :mod:`pyrxd.glyph.ft` and
:mod:`pyrxd.glyph.builder` pay it **by default** once a royalty is supplied, and
require an explicit opt-out to skip. Nothing here should be described to a user
as a guarantee.

Arithmetic
----------
``due = max(minimum, floor(sale_price * bps / 10_000))``

That matches Photonic's ``calculateRoyalty`` (``packages/lib/src/royalty.ts``)
exactly, including the flooring direction, so a pyrxd-built payment and a
Photonic-built payment agree to the photon on the single-recipient path.

Two deliberate deviations from Photonic on the ``splits`` path, both because
Photonic's version can pay the creator *less than the terms they recorded*:

1. **``minimum`` is honoured when splits are present.** Photonic's
   ``buildRoyaltyOutputs`` computes each split independently as
   ``floor(sale_price * split.bps / 10_000)`` and never consults ``minimum``, so
   a royalty declaring ``bps=100, minimum=50_000`` pays ``minimum`` with one
   recipient and ignores it entirely with two. pyrxd computes the total once and
   then divides it.
2. **The residue is paid, not dropped.** ``GlyphRoyalty`` only requires
   ``sum(split.bps) <= bps``, so the splits may legally under-cover the declared
   rate; integer flooring loses a few photons on top. pyrxd routes whatever is
   left to the top-level ``address``. The invariant is exact:
   ``sum(payout.photons) == royalty_due(...)``.

There is no ``enforced``-flag branch here. Photonic returns *no* outputs when
``enforced`` is false, which makes an advisory royalty mean "never paid" — the
opposite of advisory. In pyrxd the caller's decision to pass a royalty *is* the
decision to pay it; ``enforced`` stays a metadata field that a marketplace may
use for display or policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from pyrxd.security.errors import ValidationError

from .types import GlyphRoyalty

__all__ = [
    "RoyaltyPayout",
    "royalty_due",
    "royalty_output_scripts",
    "royalty_payouts",
]

_BPS_DENOMINATOR = 10_000


@dataclass(frozen=True)
class RoyaltyPayout:
    """One royalty recipient and the photons owed to them.

    :param address: the recipient's Radiant address, verbatim from the token's
        :class:`~pyrxd.glyph.types.GlyphRoyalty`.
    :param pkh:     the 20-byte public-key hash decoded from ``address``.
        Decoding happens once, in :func:`royalty_payouts`, so a malformed
        address fails there rather than producing an unspendable output.
    :param photons: the amount to pay. Always ``>= 1`` — a payout that rounds to
        zero is dropped rather than emitted, so no caller has to handle a
        zero-value output.
    """

    address: str
    pkh: bytes
    photons: int


def royalty_due(royalty: GlyphRoyalty, sale_price: int) -> int:
    """Total photons owed on a sale of ``sale_price`` photons.

    ``max(minimum, floor(sale_price * bps / 10_000))`` — Photonic parity.

    ``sale_price`` is the consideration the seller receives, in photons. There
    is no such thing as a royalty on a *transfer*: a gift has no price, and
    charging basis points of nothing yields nothing. A caller that wants a flat
    per-move payment expresses it as ``minimum`` with ``sale_price=0``.

    :raises ValidationError: ``sale_price`` is negative or not an ``int``.
    """
    if isinstance(sale_price, bool) or not isinstance(sale_price, int):
        raise ValidationError(f"sale_price must be an int (photons), got {type(sale_price).__name__}")
    if sale_price < 0:
        raise ValidationError(f"sale_price must be >= 0 photons, got {sale_price}")
    return max(royalty.minimum, (sale_price * royalty.bps) // _BPS_DENOMINATOR)


def royalty_payouts(royalty: GlyphRoyalty, sale_price: int) -> tuple[RoyaltyPayout, ...]:
    """Resolve ``royalty`` at ``sale_price`` into concrete, addressed payouts.

    ``sum(p.photons for p in result) == royalty_due(royalty, sale_price)``
    exactly, unless the total is 0 (in which case the result is empty).

    With no ``splits`` this is a single payout to ``royalty.address``. With
    ``splits`` the total is divided ``floor(total * split_bps / bps)`` per
    recipient and the residue — flooring loss plus any bps the splits do not
    cover — goes to ``royalty.address``. Recipients that round to zero photons
    are dropped.

    This is also where royalty addresses are actually **validated**.
    :class:`~pyrxd.glyph.types.GlyphRoyalty` only checks that the address string
    is non-empty, so a typo survives minting, sits in the signed CBOR, and would
    otherwise surface as a burned output at payment time.

    :raises ValidationError: any recipient address fails to decode, or
        ``sale_price`` is invalid.
    """
    total = royalty_due(royalty, sale_price)
    if total <= 0:
        return ()

    # Splits only make sense against a positive rate; `bps == 0` with a
    # `minimum` set is a legal flat fee, and there is nothing to divide it by.
    if royalty.splits and royalty.bps > 0:
        allocations: list[tuple[str, int]] = []
        for address, split_bps in royalty.splits:
            allocations.append((address, (total * split_bps) // royalty.bps))
        residue = total - sum(photons for _, photons in allocations)
        if residue > 0:
            allocations.append((royalty.address, residue))
    else:
        allocations = [(royalty.address, total)]

    # Merge repeats so one address never receives two outputs — an address may
    # legitimately appear both in `splits` and as the residue recipient.
    merged: dict[str, int] = {}
    order: list[str] = []
    for address, photons in allocations:
        if address not in merged:
            merged[address] = 0
            order.append(address)
        merged[address] += photons

    from pyrxd.utils import address_to_public_key_hash

    payouts: list[RoyaltyPayout] = []
    for address in order:
        photons = merged[address]
        if photons <= 0:
            continue
        try:
            pkh = address_to_public_key_hash(address)
        except (ValidationError, ValueError) as exc:
            raise ValidationError(
                f"royalty recipient address {address!r} is not a decodable Radiant address: {exc}. "
                "GlyphRoyalty only checks that the address is non-empty, so a typo survives minting "
                "and is caught here instead — at the point where it would burn the payment."
            ) from exc
        if len(pkh) != 20:
            raise ValidationError(f"royalty recipient address {address!r} decoded to {len(pkh)} bytes, expected 20")
        payouts.append(RoyaltyPayout(address=address, pkh=bytes(pkh), photons=photons))
    return tuple(payouts)


def royalty_output_scripts(payouts: tuple[RoyaltyPayout, ...]) -> tuple[tuple[bytes, int], ...]:
    """Turn payouts into ``(locking_script, photons)`` pairs, ready for outputs.

    Plain 25-byte P2PKH locks. They carry no ref, which is the property that
    makes a royalty safe to bolt onto an FT transfer: Radiant's conservation
    rule sums token amounts per ref across the output side, and an output with
    no ref contributes nothing to any of those sums. A royalty is paid out of
    the transaction's **RXD** side, never out of the token side.
    """
    return tuple((b"\x76\xa9\x14" + p.pkh + b"\x88\xac", p.photons) for p in payouts)

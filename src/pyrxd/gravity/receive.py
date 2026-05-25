"""Per-offer BTC receive-address derivation (cross-offer replay defense).

A Bitcoin payment cannot reference a Radiant offer, so the MakerClaimed covenant
binds a payment only by ``btcReceiveHash + btcSatoshis + btcChainAnchor`` (the
fields in its code section). If two offers reuse the same receive hash + amount +
anchor, they compile to a *byte-identical* MakerClaimed redeem script, so ONE BTC
payment + ONE SPV proof finalizes BOTH — a taker pays once and takes two assets
(the "C-ECON-1 / H1" cross-offer replay; proven exploitable 2026-05-24).

The structural fix is to give every offer a DISTINCT BTC receive address derived
from the maker's BIP32 account xpub at a per-offer index. A payment to offer 1's
address then cannot satisfy offer 2's covenant: different ``btcReceiveHash`` ⇒
different code hash ⇒ no replay. The maker holds the matching child private keys
(non-hardened derivation from the account xpub), so received BTC stays spendable
and the derivation is auditable from the xpub alone.

This module derives only **P2WPKH** receive hashes (20-byte HASH160 of the child
compressed pubkey) — the type the SPV verifier and covenant generator handle for
bech32 single-key destinations. Index reuse is the one thing the caller must not
do; :func:`derive_offer_btc_receive` is pure, so the caller owns the monotonic
index allocation (e.g. a persistent counter per account).
"""

from __future__ import annotations

from dataclasses import dataclass

from pyrxd.hd.bip32 import Xpub
from pyrxd.security.errors import ValidationError

__all__ = ["BIP32_MAX_NONHARDENED_INDEX", "OfferReceive", "derive_offer_btc_receive"]

# BIP32 non-hardened indices are [0, 2**31). Hardened (>= 2**31) cannot be derived
# from an xpub, which is the whole point — keep offer indices auditable.
BIP32_MAX_NONHARDENED_INDEX = 2**31 - 1


@dataclass(frozen=True)
class OfferReceive:
    """A per-offer BTC receive destination derived from a maker account xpub.

    Persist ``offer_index`` with the offer: the maker needs it to (a) spend the
    received BTC via the matching child key and (b) never reuse it for another
    live offer.
    """

    btc_receive_hash: bytes  # 20-byte HASH160(child compressed pubkey)
    btc_receive_type: str  # always "p2wpkh" from this helper
    offer_index: int  # the non-hardened BIP32 child index used


def derive_offer_btc_receive(account_xpub: str | bytes | Xpub, offer_index: int) -> OfferReceive:
    """Derive a unique P2WPKH receive hash for one offer.

    Args:
        account_xpub: The maker's BIP32 account-level xpub (e.g. the public form
            of ``m/84'/0'/0'``). Child derivation is non-hardened so it is
            reproducible from the xpub; the maker holds the matching xprv to
            spend received BTC.
        offer_index: A per-offer, never-reused non-hardened index. The caller
            owns allocation (a monotonic counter) — this function is pure and
            does NOT track which indices have been issued.

    Returns:
        :class:`OfferReceive` with the derived 20-byte receive hash and the index.

    Raises:
        ValidationError: on an out-of-range index or an unusable xpub.
    """
    if not isinstance(offer_index, int) or isinstance(offer_index, bool):
        raise ValidationError("offer_index must be an int")
    if offer_index < 0 or offer_index > BIP32_MAX_NONHARDENED_INDEX:
        raise ValidationError(
            f"offer_index must be a non-hardened BIP32 index in [0, {BIP32_MAX_NONHARDENED_INDEX}]; "
            f"got {offer_index}. Hardened indices cannot be derived from an xpub."
        )

    xpub = account_xpub if isinstance(account_xpub, Xpub) else Xpub(account_xpub)
    # Standard receive chain: <account>/0/<offer_index>. The 0 ("external"/receive
    # branch) matches BIP44/BIP84 so the maker's wallet can find the funds.
    child = xpub.ckd(0).ckd(offer_index)
    receive_hash = child.public_key().hash160()
    if len(receive_hash) != 20:
        raise ValidationError(f"derived receive hash must be 20 bytes; got {len(receive_hash)}")
    return OfferReceive(btc_receive_hash=receive_hash, btc_receive_type="p2wpkh", offer_index=offer_index)

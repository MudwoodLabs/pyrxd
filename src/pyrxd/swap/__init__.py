"""Same-chain partial-transaction swaps for RXD and Glyph FTs.

A high-level, guard-railed offer/accept API over ``SIGHASH_SINGLE |
ANYONECANPAY`` signature-level atomicity — the "maker signs one input
committing to one output, taker completes and broadcasts" pattern.

Quick start::

    from pyrxd.swap import create_offer, accept_offer, Asset, FundingInput

    # Maker: give 1000 RXD-photons, want 50 units of FT `ref`.
    offer = create_offer(
        give_source_tx=maker_utxo_source_tx,
        give_vout=0,
        maker_key=maker_key,
        receive=Asset(kind="ft", amount=50, ref=ft_ref),
        maker_receive_pkh=maker_pkh,
    )
    payload = offer.to_dict()          # send over any transport

    # Taker: verify + complete + sign.
    tx = accept_offer(
        SwapOffer.from_dict(payload),
        funding=[FundingInput(source_tx=taker_ft_source, vout=0, key=taker_key)],
        taker_receive_pkh=taker_pkh,
        taker_change_pkh=taker_pkh,
        fee=500,
    )
    raw = tx.serialize().hex()         # broadcast

This is distinct from :mod:`pyrxd.gravity`, which does *cross-chain*
atomic swaps gated by SPV proofs. Use this for same-chain RXD/token
trades; use Gravity when the two assets live on different chains.

The core (``create_offer`` / ``accept_offer``) is pure — no network. Use
the :mod:`pyrxd.swap.resolve` helpers to fetch the transactions an offer
references.
"""

from __future__ import annotations

from .partial import FundingInput, accept_offer, create_offer
from .resolve import fetch_funding_input, fetch_transaction
from .types import Asset, AssetKind, SwapOffer, SwapTerms

__all__ = [
    "Asset",
    "AssetKind",
    "FundingInput",
    "SwapOffer",
    "SwapTerms",
    "accept_offer",
    "create_offer",
    "fetch_funding_input",
    "fetch_transaction",
]

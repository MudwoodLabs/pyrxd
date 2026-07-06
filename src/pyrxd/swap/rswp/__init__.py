"""RSWP on-chain swap orderbook — post, take, cancel, and browse (same-chain).

The public import home for everything RSWP. The wire *decoder* implementation
lives in :mod:`pyrxd.gravity.swap_order` for historical reasons and is
re-exported here; new code should import from ``pyrxd.swap.rswp``.

Quick start (regtest — the library never broadcasts by itself)::

    from pyrxd.swap import Asset, FundingInput
    from pyrxd.swap.rswp import (
        create_rswp_order, build_advert_tx, decode_rswp_order, take_rswp_order,
    )

    # Maker: offer the exact-amount UTXO at source:0, demand 50 units of an FT.
    post = create_rswp_order(
        give_source_tx=source_tx, give_vout=0, maker_key=maker_key,
        receive=Asset(kind="ft", amount=50, ref=ft_ref),
        maker_receive_pkh=maker_pkh,
    )
    advert_tx = build_advert_tx(
        advert_script=post.advert_script, funding=[...], change_pkh=maker_pkh, fee=500,
    )
    # broadcast advert_tx through your own node → the order is on the book.

    # Taker: decode from chain, verify EVERYTHING, complete.
    order = decode_rswp_order(op_return_script)
    tx = take_rswp_order(
        order, give_source_tx=fetched_and_txid_verified_source,
        funding=[...], taker_receive_pkh=taker_pkh, taker_change_pkh=taker_pkh, fee=500,
    )

Design + byte-level authority: ``docs/plans/2026-07-05-rswp-orderbook-design.md``
and ``docs/swap-order-wire-format.md``. Value mechanics are the proven
``SIGHASH_SINGLE | ANYONECANPAY | FORKID`` primitives of :mod:`pyrxd.swap.partial`.
"""

from __future__ import annotations

from ...gravity.swap_order import (
    DemandedOutput,
    RswpOrder,
    decode_rswp_order,
    parse_price_terms,
    parse_price_terms_lenient,
)
from .book import BookEntry, OrderbookClient, OrderbookSource
from .covenant import (
    REFUND_SEQUENCE,
    build_covenant_cancel_tx,
    build_covenant_refund_tx,
    build_refund_covenant_script,
    create_covenant_order,
    is_refund_covenant,
    parse_refund_covenant,
    prepare_covenant_offer,
    take_covenant_order,
)
from .orders import (
    RswpOrderPost,
    build_advert_tx,
    build_cancel_tx,
    create_rswp_order,
    prepare_offered_utxo,
    rswp_order_to_swap_offer,
    take_rswp_order,
    verify_offer_signature,
)
from .wire import (
    CONTRACT_TYPE_FT,
    CONTRACT_TYPE_NFT,
    CONTRACT_TYPE_RXD,
    CONTRACT_TYPE_VAULT,
    FLAG_HAS_EXPIRY,
    FLAG_HAS_WANT,
    RSWP_MAGIC,
    RSWP_VERSION_V2,
    RSWP_VERSION_V3,
    RXD_TOKEN_ID,
    encode_price_terms,
    encode_rswp_order,
    swap_token_id,
)

__all__ = [
    "CONTRACT_TYPE_FT",
    "CONTRACT_TYPE_NFT",
    "CONTRACT_TYPE_RXD",
    "CONTRACT_TYPE_VAULT",
    "FLAG_HAS_EXPIRY",
    "FLAG_HAS_WANT",
    "REFUND_SEQUENCE",
    "RSWP_MAGIC",
    "RSWP_VERSION_V2",
    "RSWP_VERSION_V3",
    "RXD_TOKEN_ID",
    "BookEntry",
    "DemandedOutput",
    "OrderbookClient",
    "OrderbookSource",
    "RswpOrder",
    "RswpOrderPost",
    "build_advert_tx",
    "build_cancel_tx",
    "build_covenant_cancel_tx",
    "build_covenant_refund_tx",
    "build_refund_covenant_script",
    "create_covenant_order",
    "create_rswp_order",
    "decode_rswp_order",
    "encode_price_terms",
    "encode_rswp_order",
    "is_refund_covenant",
    "parse_price_terms",
    "parse_price_terms_lenient",
    "parse_refund_covenant",
    "prepare_covenant_offer",
    "prepare_offered_utxo",
    "rswp_order_to_swap_offer",
    "swap_token_id",
    "take_covenant_order",
    "take_rswp_order",
    "verify_offer_signature",
]

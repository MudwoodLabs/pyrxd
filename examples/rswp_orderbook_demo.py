#!/usr/bin/env python3
"""RSWP on-chain swap orderbook (``pyrxd.swap.rswp``) — post → decode → take demo.

The on-chain book is the public version of the ``pyrxd.swap`` partial-tx
swap: instead of handing the signed offer to a counterparty over a private
transport, the maker broadcasts an ``OP_RETURN`` advertisement ("RSWP" frame)
that any taker — any wallet, not just pyrxd — can discover, verify, and fill.

    Maker:  offers a 1000-unit FT UTXO, demands 800 RXD photons,
            signs SIGHASH_SINGLE|ANYONECANPAY|FORKID, posts the advert.
    Taker:  decodes the advert BYTES from the chain, re-verifies every claim
            against the offered UTXO, completes and signs the swap tx.

This demo is self-contained: it synthesises the source UTXOs in memory so it
runs with no node and no network, while exercising the REAL wire encoder,
decoder, verification bridge, and signing. To run it against a live regtest
node with the actual swap index (``getopenorders``), see
``tests/test_rswp_regtest_e2e.py`` — the flow is identical, plus broadcasts.

Usage::

    python examples/rswp_orderbook_demo.py

Design + wire authority: docs/plans/2026-07-05-rswp-orderbook-design.md,
docs/swap-order-wire-format.md.
"""

from __future__ import annotations

from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput
from pyrxd.swap.rswp import (
    build_advert_tx,
    build_cancel_tx,
    create_rswp_order,
    decode_rswp_order,
    rswp_order_to_swap_offer,
    take_rswp_order,
)
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

FT_REF = GlyphRef(txid=Txid("aa" * 32), vout=0)


def _p2pkh_source(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_source(pkh: bytes, ref: GlyphRef, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), value))
    return tx


def main() -> None:
    maker = PrivateKey()
    taker = PrivateKey()
    maker_pkh = maker.public_key().hash160()
    taker_pkh = taker.public_key().hash160()

    # ── Maker: post ──────────────────────────────────────────────────────────
    # The offered UTXO is given WHOLE (SINGLE binds only the demanded output),
    # so real makers first mint an exact-amount UTXO — see prepare_offered_utxo.
    ft_source = _ft_source(maker_pkh, FT_REF, 1000)
    post = create_rswp_order(
        give_source_tx=ft_source,
        give_vout=0,
        maker_key=maker,
        receive=Asset(kind="rxd", amount=800),
        maker_receive_pkh=maker_pkh,
    )
    advert_tx = build_advert_tx(
        advert_script=post.advert_script,
        funding=[FundingInput(_p2pkh_source(maker_pkh, 5_000), 0, maker)],
        change_pkh=maker_pkh,
        fee=500,
    )
    print(f"advert OP_RETURN script ({len(post.advert_script)} bytes):")
    print(f"  {post.advert_script.hex()}")
    print(f"advert tx to broadcast: {advert_tx.txid()}\n")

    # ── Taker: discover + verify + take ─────────────────────────────────────
    # On a live chain the taker gets these bytes from the swap index (see
    # OrderbookClient) or an OP_RETURN scan, and fetches the offered UTXO's
    # source tx with pyrxd.swap.resolve.fetch_transaction (txid-verified).
    order = decode_rswp_order(post.advert_script)
    print("decoded order:")
    print(
        f"  offers   : {'RXD' if order.offered_is_rxd else 'FT'} UTXO {order.offered_txid[:16]}…:{order.offered_utxo_index}"
    )
    print(f"  demands  : {order.demanded_outputs[0].value} photons → maker script")
    print(f"  signature: {len(order.signature)} bytes, sighash 0xc3\n")

    swap_tx = take_rswp_order(
        order,
        give_source_tx=ft_source,  # in production: fetch_transaction(client, order.offered_txid)
        funding=[FundingInput(_p2pkh_source(taker_pkh, 2_000), 0, taker)],
        taker_receive_pkh=taker_pkh,
        taker_change_pkh=taker_pkh,
        fee=300,
    )
    print(f"completion tx to broadcast: {swap_tx.txid()}")
    print(f"  output[0] (maker receives): {swap_tx.outputs[0].satoshis} photons")
    print(f"  output[1] (taker receives): {swap_tx.outputs[1].satoshis} FT units\n")

    # ── The verification is not cosmetic ─────────────────────────────────────
    # A lying advertisement (here: claiming to offer a different token) dies at
    # the bridge, before any funds are committed.
    lying = decode_rswp_order(post.advert_script)
    fields = {f: getattr(lying, f) for f in type(lying).__dataclass_fields__}
    fields["token_id"] = b"\x11" * 32
    try:
        rswp_order_to_swap_offer(type(lying)(**fields), give_source_tx=ft_source)
    except ValidationError as exc:
        print(f"lying advert rejected: {exc}\n")

    # ── Maker: cancel (the only hard revocation) ────────────────────────────
    # The 0xC3 signature never expires; self-spending the offered UTXO is what
    # kills the order. FT cancels conserve the token and fund the fee with RXD.
    #
    # The fee here is REAL, unlike the illustrative ones above: `build_cancel_tx`
    # refuses anything below Radiant's relay floor. This shape (FT input + RXD funding
    # input) measures 421-424 bytes over 150 builds, so its floor is up to 4,240,000
    # photons at 10,000 photons/byte. The demo used to pass 400 — about 10,000x under —
    # which would have produced a cancel no node relays while the order stayed takeable.
    cancel_tx = build_cancel_tx(
        offered_source_tx=ft_source,
        offered_vout=0,
        maker_key=maker,
        refund_pkh=maker_pkh,
        fee=5_000_000,
        funding=[FundingInput(_p2pkh_source(maker_pkh, 10_000_000), 0, maker)],
    )
    print(f"cancel tx (broadcast INSTEAD of letting the order rest): {cancel_tx.txid()}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Same-chain partial-transaction swap (``pyrxd.swap``) — end-to-end demo.

Shows the full offer → transport → accept → verify flow for a Glyph FT
traded against plain RXD, all in one process:

    Maker:  gives 1000 FT units, wants 800 RXD photons.
    Taker:  funds the 800 + fee, receives the 1000 FT.

This demo is self-contained: it synthesises the maker's and taker's
source UTXOs in memory so it runs with no node and no network — it
exercises the *real* swap API (signing, conservation, and the maker
signature re-verification), it just doesn't broadcast.

To run a real swap, replace the synthetic source transactions with ones
fetched from the chain via :mod:`pyrxd.swap.resolve`
(``fetch_transaction`` / ``fetch_funding_input``) and broadcast the
resulting hex. The maker's source transaction travels inside the offer,
so the taker needs the network only to gather their own funding.

Usage::

    python examples/partial_swap_demo.py

See also: docs/concepts/partial-tx-swaps.md
"""

from __future__ import annotations

from pyrxd.glyph.script import build_ft_locking_script, extract_ref_from_ft_script, is_ft_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, SwapOffer, accept_offer, create_offer
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput


def _p2pkh_source(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_source(pkh: bytes, ref: GlyphRef, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), value))
    return tx


def _describe(out: TransactionOutput) -> str:
    script = out.locking_script.serialize()
    if is_ft_script(script.hex()):
        ref = extract_ref_from_ft_script(script)
        return f"{out.satoshis:>6} FT  (ref {ref.txid[:8]}…:{ref.vout})"
    return f"{out.satoshis:>6} RXD"


def main() -> None:
    maker = PrivateKey()
    taker = PrivateKey()
    maker_pkh = maker.public_key().hash160()
    taker_pkh = taker.public_key().hash160()
    token_ref = GlyphRef(txid=Txid("cd" * 32), vout=0)

    # --- Maker side --------------------------------------------------------
    # The maker holds an FT UTXO of 1000 units and wants 800 RXD for it.
    maker_ft_utxo = _ft_source(maker_pkh, token_ref, 1000)
    offer = create_offer(
        give_source_tx=maker_ft_utxo,
        give_vout=0,
        maker_key=maker,
        receive=Asset(kind="rxd", amount=800),
        maker_receive_pkh=maker_pkh,
    )
    print("Maker created an offer:")
    print(f"  gives:    {offer.terms.give.amount} FT (ref {token_ref.txid[:8]}…)")
    print(f"  receives: {offer.terms.receive.amount} RXD")

    # The offer is JSON-able — send it over any transport.
    payload = offer.to_dict()
    print(f"\nOffer serialized to a {len(str(payload))}-char transport payload.\n")

    # --- Taker side --------------------------------------------------------
    # The taker funds the maker's 800 RXD (+ fee) from a 2000-RXD UTXO and
    # receives the FT. accept_offer reads the maker's real given asset from
    # the offer, reconciles the terms, and re-verifies the maker signature.
    taker_rxd_utxo = _p2pkh_source(taker_pkh, 2000)
    fee = 300
    tx = accept_offer(
        SwapOffer.from_dict(payload),
        funding=[FundingInput(source_tx=taker_rxd_utxo, vout=0, key=taker)],
        taker_receive_pkh=taker_pkh,
        taker_change_pkh=taker_pkh,
        fee=fee,
    )

    print("Taker accepted; final swap transaction:")
    print(
        f"  inputs:  {len(tx.inputs)} (maker FT + taker RXD), all signed: "
        f"{all(i.unlocking_script is not None for i in tx.inputs)}"
    )
    print("  outputs:")
    print(f"    [0] maker receives: {_describe(tx.outputs[0])}")
    print(f"    [1] taker receives: {_describe(tx.outputs[1])}")
    for i, out in enumerate(tx.outputs[2:], start=2):
        print(f"    [{i}] taker change:   {_describe(out)}")

    total_in = maker_ft_utxo.outputs[0].satoshis + taker_rxd_utxo.outputs[0].satoshis
    total_out = sum(o.satoshis for o in tx.outputs)
    print(f"\n  fee (in - out): {total_in - total_out} photons")
    print(f"\nBroadcast-ready raw tx ({len(tx.serialize())} bytes):")
    print(f"  {tx.serialize().hex()[:80]}…")


if __name__ == "__main__":
    main()

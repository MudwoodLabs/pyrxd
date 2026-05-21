#!/usr/bin/env python3
"""Sweep the recovered BTC back to the user's address using the audited
single-input build_payment_tx. Spends the 10000-sat maker output of the
covenant payment f5588bfb (MUST be confirmed) -> the user's P2WPKH address,
all-minus-fee (no change). The 850-sat funding change is left/handled
separately. Prints signed tx hex + txid; broadcast separately.

DEST = bc1qr8z8h4pul3txemxkqzuwma447un5nu6fhxmmr0
       witness program 19c47bd43cfc566cecd600b8edf6b5f72749f349 (verified from
       the user's own funding tx e98942ac...:1).
"""
import json

from pyrxd.btc_wallet.keys import keypair_from_wif
from pyrxd.btc_wallet.payment import BtcUtxo, build_payment_tx

PAYMENT_TXID = "f5588bfbc0630a047d067073b6bb60bc86c8644b6deb7e99483dd8ab595aed44"
MAKER_VOUT, MAKER_VAL = 0, 10000
DEST_PROGRAM = bytes.fromhex("19c47bd43cfc566cecd600b8edf6b5f72749f349")
FEE = 150  # ~1.3 sat/vB for a 1-in/1-out segwit tx (~110 vB)

maker = json.load(open("docs/brainstorms/gravity-ref-spike/.maker_btc_keypair.json"))
kp = keypair_from_wif(maker["wif"])
utxo = BtcUtxo(txid=PAYMENT_TXID, vout=MAKER_VOUT, value=MAKER_VAL)

# Send (10000 - FEE) to DEST as P2WPKH; no change (single output).
res = build_payment_tx(
    keypair=kp,
    utxo=utxo,
    to_hash=DEST_PROGRAM,
    to_type="p2wpkh",
    amount_sats=MAKER_VAL - FEE,
    fee_sats=FEE,
    input_type="p2wpkh",
)
print(json.dumps({"tx_hex": res.tx_hex, "txid": res.txid, "out_sats": MAKER_VAL - FEE, "fee": res.fee_sats}))

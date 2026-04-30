"""Bitcoin wallet tooling for the Gravity Taker.

Public API
----------
BtcKeypair      — keypair with all 4 address formats
BtcUtxo         — UTXO descriptor
BtcPaymentTx    — signed transaction result
generate_keypair    — generate a fresh keypair from CSPRNG
keypair_from_wif    — load keypair from WIF (testing/recovery)
build_payment_tx    — build+sign a 1-input segwit-v0 payment tx
validate_btc_address — validate a mainnet Bitcoin address string
validate_satoshis    — validate a satoshi amount
"""

from __future__ import annotations

from .keys import BtcKeypair, generate_keypair, keypair_from_wif
from .payment import BtcPaymentTx, BtcUtxo, build_payment_tx
from .validate import validate_btc_address, validate_satoshis

__all__ = [
    "BtcKeypair",
    "BtcPaymentTx",
    "BtcUtxo",
    "build_payment_tx",
    "generate_keypair",
    "keypair_from_wif",
    "validate_btc_address",
    "validate_satoshis",
]

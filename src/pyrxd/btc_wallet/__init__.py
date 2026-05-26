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

from .htlc_leg import (
    BitcoinCoreBroadcaster,
    BitcoinTaprootLeg,
    BtcBroadcaster,
    BtcFundingReader,
    require_audit_cleared,
)
from .keys import BtcKeypair, generate_keypair, keypair_from_wif
from .payment import BtcPaymentTx, BtcUtxo, build_payment_tx
from .taproot import (
    BtcHtlc,
    BtcHtlcLocator,
    BtcOutpoint,
    ScriptTree,
    Timelock,
    TimeUnit,
    build_claim_tx,
    build_htlc,
    build_refund_tx,
    scrape_secret,
)
from .validate import validate_btc_address, validate_satoshis

__all__ = [
    "BitcoinCoreBroadcaster",
    "BitcoinTaprootLeg",
    "BtcBroadcaster",
    "BtcFundingReader",
    "BtcHtlc",
    "BtcHtlcLocator",
    "BtcKeypair",
    "BtcOutpoint",
    "BtcPaymentTx",
    "BtcUtxo",
    "ScriptTree",
    "TimeUnit",
    "Timelock",
    "build_claim_tx",
    "build_htlc",
    "build_payment_tx",
    "build_refund_tx",
    "generate_keypair",
    "keypair_from_wif",
    "require_audit_cleared",
    "scrape_secret",
    "validate_btc_address",
    "validate_satoshis",
]

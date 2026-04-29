"""pyrxd — Python SDK for the Radiant (RXD) blockchain.

Provides transaction building, HD wallet, Glyph token protocol (NFT/FT/dMint),
Gravity cross-chain atomic swaps, SPV verification, and ElectrumX networking.

Quickstart::

    from pyrxd import GlyphBuilder, GlyphMetadata, GlyphProtocol
    from pyrxd import RxdSdkError, ValidationError

Subpackages:
    pyrxd.glyph      — Glyph token protocol (NFT, FT, dMint, mutable, V2)
    pyrxd.gravity    — BTC↔RXD atomic swaps (Gravity protocol)
    pyrxd.security   — Typed secrets, error hierarchy, secure RNG
    pyrxd.hd         — BIP-32/39/44 HD wallet
    pyrxd.network    — ElectrumX client, BTC data sources
    pyrxd.spv        — SPV chain/payment verification
    pyrxd.transaction — Transaction building and serialization
    pyrxd.script     — Script types and evaluation
"""
from __future__ import annotations

from pyrxd.glyph import (
    GlyphBuilder,
    GlyphInspector,
    GlyphItem,
    GlyphMetadata,
    GlyphProtocol,
    GlyphRef,
    GlyphScanner,
)
from pyrxd.gravity import ActiveOffer, GravityMakerSession, GravityOfferParams, GravityTrade
from pyrxd.hd.bip32 import Xprv, Xpub, ckd, bip32_derive_xprv_from_mnemonic, bip32_derive_xkeys_from_xkey
from pyrxd.hd.bip39 import mnemonic_from_entropy, seed_from_mnemonic
from pyrxd.hd.bip44 import bip44_derive_xprv_from_mnemonic
from pyrxd.hd.wallet import AddressRecord, HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.security import (
    RxdSdkError,
    ValidationError,
)

__version__ = "0.3.0a1"

__all__ = [
    "__version__",
    # Glyph
    "GlyphBuilder",
    "GlyphInspector",
    "GlyphItem",
    "GlyphMetadata",
    "GlyphProtocol",
    "GlyphRef",
    "GlyphScanner",
    # Gravity
    "GravityTrade",
    "GravityMakerSession",
    "GravityOfferParams",
    "ActiveOffer",
    # HD wallet — BIP-32
    "Xprv",
    "Xpub",
    "ckd",
    "bip32_derive_xprv_from_mnemonic",
    "bip32_derive_xkeys_from_xkey",
    # HD wallet — BIP-39
    "mnemonic_from_entropy",
    "seed_from_mnemonic",
    # HD wallet — BIP-44
    "AddressRecord",
    "bip44_derive_xprv_from_mnemonic",
    "HdWallet",
    # Keys
    "PrivateKey",
    # Network utilities
    "UtxoRecord",
    "script_hash_for_address",
    # Errors
    "RxdSdkError",
    "ValidationError",
]

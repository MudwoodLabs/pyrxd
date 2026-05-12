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

Implementation note — lazy top-level re-exports:

The public names listed in ``__all__`` are resolved on first attribute
access via PEP 562 ``__getattr__``, not eagerly imported at package
load time. This keeps ``import pyrxd`` (or any submodule) cheap, and
crucially keeps the import graph **minimal** for callers that only
touch a small slice of the SDK — most importantly the browser-hosted
inspect tool, which imports ``pyrxd.glyph.inspect`` and would
otherwise transitively load ``coincurve`` (no Pyodide wheel),
``aiohttp``, ``websockets``, etc.

Typing tools (``mypy``, IDE introspection, ``dir()``) read the
``_LAZY_EXPORTS`` mapping and the ``__all__`` list; runtime users
see the same names with no behaviour change.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.5.0"

# Map of public-name → (module, attr) pairs. Resolved lazily on first
# attribute access. Order is alphabetical by name to make additions
# easy to spot in diffs.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # Gravity
    "ActiveOffer": ("pyrxd.gravity", "ActiveOffer"),
    # HD wallet — BIP-44
    "AddressRecord": ("pyrxd.hd.wallet", "AddressRecord"),
    # Glyph
    "GlyphBuilder": ("pyrxd.glyph", "GlyphBuilder"),
    "GlyphInspector": ("pyrxd.glyph", "GlyphInspector"),
    "GlyphItem": ("pyrxd.glyph", "GlyphItem"),
    "GlyphMetadata": ("pyrxd.glyph", "GlyphMetadata"),
    "GlyphProtocol": ("pyrxd.glyph", "GlyphProtocol"),
    "GlyphRef": ("pyrxd.glyph", "GlyphRef"),
    "GlyphScanner": ("pyrxd.glyph", "GlyphScanner"),
    "GravityMakerSession": ("pyrxd.gravity", "GravityMakerSession"),
    "GravityOfferParams": ("pyrxd.gravity", "GravityOfferParams"),
    "GravityTrade": ("pyrxd.gravity", "GravityTrade"),
    "HdWallet": ("pyrxd.hd.wallet", "HdWallet"),
    # Keys
    "PrivateKey": ("pyrxd.keys", "PrivateKey"),
    # Errors
    "RxdSdkError": ("pyrxd.security", "RxdSdkError"),
    # Single-key wallet facade
    "RxdWallet": ("pyrxd.wallet", "RxdWallet"),
    # Network utilities
    "UtxoRecord": ("pyrxd.network.electrumx", "UtxoRecord"),
    "ValidationError": ("pyrxd.security", "ValidationError"),
    # HD wallet — BIP-32
    "Xprv": ("pyrxd.hd.bip32", "Xprv"),
    "Xpub": ("pyrxd.hd.bip32", "Xpub"),
    "bip32_derive_xkeys_from_xkey": ("pyrxd.hd.bip32", "bip32_derive_xkeys_from_xkey"),
    "bip32_derive_xprv_from_mnemonic": ("pyrxd.hd.bip32", "bip32_derive_xprv_from_mnemonic"),
    "bip44_derive_xprv_from_mnemonic": ("pyrxd.hd.bip44", "bip44_derive_xprv_from_mnemonic"),
    "ckd": ("pyrxd.hd.bip32", "ckd"),
    # HD wallet — BIP-39
    "mnemonic_from_entropy": ("pyrxd.hd.bip39", "mnemonic_from_entropy"),
    "script_hash_for_address": ("pyrxd.network.electrumx", "script_hash_for_address"),
    "seed_from_mnemonic": ("pyrxd.hd.bip39", "seed_from_mnemonic"),
}

__all__ = sorted([*_LAZY_EXPORTS.keys(), "__version__"])


def __getattr__(name: str) -> Any:
    """PEP 562 lazy attribute access for public re-exports.

    Imports the underlying module on first access, caches the resolved
    object on the package namespace so subsequent accesses are direct
    attribute lookups (no repeat import call)."""
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pyrxd' has no attribute {name!r}")
    module_path, attr = target
    import importlib

    obj = getattr(importlib.import_module(module_path), attr)
    globals()[name] = obj  # cache for subsequent accesses
    return obj


def __dir__() -> list[str]:
    """Make ``dir(pyrxd)`` show the lazy names. IDEs and ``help()``
    rely on this for autocomplete."""
    return __all__

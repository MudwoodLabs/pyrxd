"""pyrxd — Python SDK for the Radiant (RXD) blockchain.

Provides transaction building, HD wallet, Glyph token protocol (NFT/FT/dMint),
Gravity cross-chain atomic swaps, SPV verification, and ElectrumX networking.

Quickstart::

    from pyrxd import GlyphBuilder, GlyphMetadata, GlyphProtocol
    from pyrxd import RxdSdkError, ValidationError

Subpackages:
    pyrxd.glyph      — Glyph token protocol (NFT, FT, dMint, mutable, V2)
    pyrxd.swap       — Same-chain partial-transaction swaps (RXD/token)
    pyrxd.gravity    — Cross-chain (BTC/ETH↔RXD) HTLC atomic swaps
    pyrxd.security   — Typed secrets, error hierarchy, secure RNG
    pyrxd.hd         — BIP-32/39/44 HD wallet
    pyrxd.network    — ElectrumX client, BTC data sources
    pyrxd.spv        — SPV chain/payment verification
    pyrxd.transaction — Transaction building and serialization
    pyrxd.script     — Script types and evaluation
    pyrxd.devnet     — Local regtest dev node (see `pyrxd regtest`)

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

from importlib.metadata import PackageNotFoundError, version
from typing import Any

# Single source of truth for the version is pyproject.toml. Derive __version__
# from the installed package metadata so the CLI's --version can never drift
# from what was published — a hardcoded string here went stale and shipped a
# 0.6.0 wheel that reported "0.5.1". The fallback covers a raw source checkout
# with no installed dist metadata (and Pyodide, where pyrxd may load without it).
try:
    __version__ = version("pyrxd")
except PackageNotFoundError:  # pragma: no cover - source checkout without install
    __version__ = "0.0.0+unknown"

# Map of public-name → (module, attr) pairs. Resolved lazily on first
# attribute access. Order is alphabetical by name to make additions
# easy to spot in diffs.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # Injection points — the protocols a CONSUMER implements and hands to the SDK. They have no
    # in-repo caller BY DESIGN: the SDK duck-types them and the implementation comes from outside,
    # so "no caller" is the correct shape rather than dead code. Exporting them says that
    # deliberately — and a package export is a real consumer surface, where a module's own
    # `__all__` is only a declaration of intent (#553, where `__all__` stopped counting as a
    # reference and surfaced these).
    "CredentialResolver": ("pyrxd.glyph.credential_binding", "CredentialResolver"),
    "FlashbotsSubmitter": ("pyrxd.eth_wallet.private_submit", "FlashbotsSubmitter"),
    "PrivateSubmitter": ("pyrxd.eth_wallet.private_submit", "PrivateSubmitter"),
    "RadiantBroadcaster": ("pyrxd.gravity.radiant_leg", "RadiantBroadcaster"),
    # Gravity
    "ActiveOffer": ("pyrxd.gravity", "ActiveOffer"),
    # HD wallet — BIP-44
    "AddressRecord": ("pyrxd.hd.wallet", "AddressRecord"),
    # Glyph
    "GlyphBuilder": ("pyrxd.glyph", "GlyphBuilder"),
    "GlyphInspector": ("pyrxd.glyph", "GlyphInspector"),
    "GlyphItem": ("pyrxd.glyph", "GlyphItem"),
    "GlyphMetadata": ("pyrxd.glyph", "GlyphMetadata"),
    # The high-level mint facade. GlyphMinter + JsonFilePendingStore are surfaced at the
    # top level because they are the pair a caller needs to mint at all — the store is a
    # required constructor argument, so exporting one without the other would leave the
    # advertised entry point unusable from `from pyrxd import ...`.
    "GlyphClient": ("pyrxd.glyph", "GlyphClient"),
    # The 0.19.0 notes tell callers to catch this on every fund-moving path, and it was
    # reachable only as `pyrxd.glyph.client.BroadcastEchoMismatch` — an exception you are
    # instructed to handle but cannot conveniently import is the same reachability gap
    # the facade itself exists to close.
    "BroadcastEchoMismatch": ("pyrxd.glyph", "BroadcastEchoMismatch"),
    "GlyphMinter": ("pyrxd.glyph", "GlyphMinter"),
    "GlyphProtocol": ("pyrxd.glyph", "GlyphProtocol"),
    "GlyphRef": ("pyrxd.glyph", "GlyphRef"),
    "GlyphScanner": ("pyrxd.glyph", "GlyphScanner"),
    "GravityMakerSession": ("pyrxd.gravity", "GravityMakerSession"),
    "GravityOfferParams": ("pyrxd.gravity", "GravityOfferParams"),
    "GravityTrade": ("pyrxd.gravity", "GravityTrade"),
    "HdWallet": ("pyrxd.hd.wallet", "HdWallet"),
    "JsonFilePendingStore": ("pyrxd.glyph", "JsonFilePendingStore"),
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
    # Same-chain swaps — pyrxd.swap (SIGHASH_SINGLE|ANYONECANPAY partial-tx offers)
    "Asset": ("pyrxd.swap", "Asset"),
    "FundingInput": ("pyrxd.swap", "FundingInput"),
    "SwapOffer": ("pyrxd.swap", "SwapOffer"),
    "SwapTerms": ("pyrxd.swap", "SwapTerms"),
    "accept_offer": ("pyrxd.swap", "accept_offer"),
    "create_offer": ("pyrxd.swap", "create_offer"),
    # Cross-chain atomic swap — pyrxd.gravity HTLC primitive (BTC/ETH↔RXD). Proven on
    # regtest + small real-value (dust) mainnet runs; this stack is unaudited — verify it
    # yourself before moving real value. See docs/how-to/build-a-cross-chain-swap.md.
    "SwapCoordinator": ("pyrxd.gravity.swap_coordinator", "SwapCoordinator"),
    "CoordinatorConfig": ("pyrxd.gravity.swap_coordinator", "CoordinatorConfig"),
    "MarginPolicy": ("pyrxd.gravity.swap_coordinator", "MarginPolicy"),
    "generate_secret": ("pyrxd.gravity.swap_coordinator", "generate_secret"),
    "NegotiatedTerms": ("pyrxd.gravity.swap_state", "NegotiatedTerms"),
    "SwapRecord": ("pyrxd.gravity.swap_state", "SwapRecord"),
    "SwapState": ("pyrxd.gravity.swap_state", "SwapState"),
    "CounterChainLeg": ("pyrxd.gravity.counter_chain_leg", "CounterChainLeg"),
    "RadiantCovenantLeg": ("pyrxd.gravity.radiant_leg", "RadiantCovenantLeg"),
    "CappedFeeWalletSource": ("pyrxd.gravity.capped_fee_source", "CappedFeeWalletSource"),
    "EthLeg": ("pyrxd.gravity.eth_leg", "EthLeg"),
    # Counter-chain registries (per-chain safety knobs; see the cross-chain how-to)
    "EvmChain": ("pyrxd.eth_wallet.chains", "EvmChain"),
    "KNOWN_EVM_CHAINS": ("pyrxd.eth_wallet.chains", "KNOWN_EVM_CHAINS"),
    "PowChain": ("pyrxd.btc_wallet.chains", "PowChain"),
    "KNOWN_POW_CHAINS": ("pyrxd.btc_wallet.chains", "KNOWN_POW_CHAINS"),
    # Covenant building blocks (docs/concepts/covenant-building-blocks.md):
    # consensus-validated on regtest (several mainnet-proven); unaudited.
    "HtlcCovenant": ("pyrxd.gravity.htlc_covenant", "HtlcCovenant"),
    "build_htlc_covenant_rxd": ("pyrxd.gravity.htlc_covenant", "build_htlc_covenant_rxd"),
    "build_htlc_covenant_ft": ("pyrxd.gravity.htlc_covenant", "build_htlc_covenant_ft"),
    "build_htlc_covenant_nft": ("pyrxd.gravity.htlc_covenant", "build_htlc_covenant_nft"),
    "SoulboundNftCovenant": ("pyrxd.glyph.soulbound_covenant", "SoulboundNftCovenant"),
    "build_soulbound_nft_covenant": ("pyrxd.glyph.soulbound_covenant", "build_soulbound_nft_covenant"),
    "verify_ref_authenticity": ("pyrxd.gravity.ref_authenticity", "verify_ref_authenticity"),
    # SPV verification
    "SpvProof": ("pyrxd.spv", "SpvProof"),
    "SpvProofBuilder": ("pyrxd.spv", "SpvProofBuilder"),
    "verify_tx_in_block": ("pyrxd.spv", "verify_tx_in_block"),
    # Content encryption primitives — pyrxd.crypto (#556).
    #
    # These are BYTE-COMPATIBLE WITH PHOTONIC WALLET (`packages/lib/src/encryption.ts`), which is
    # what makes them worth a public export rather than an internal detail: a caller encrypting
    # Glyph content with pyrxd and decrypting it in Photonic, or the reverse, is the actual use
    # case. `aead` is verified against the draft-irtf-cfrg-xchacha-03 Appendix A.3.1 vector.
    #
    # Exported rather than wired to a caller, deliberately. #556 found them unreachable along with
    # the timelocked-content feature that is their only in-repo consumer, but they are GENERAL
    # primitives whose reachability does not depend on that feature's fate — see the allowlist in
    # tests/test_reachability_shipped_callers.py, where the timelock half stays recorded as debt.
    #
    # The set is chosen so the surface is USABLE, the same rule as GlyphMinter/JsonFilePendingStore
    # above: `encrypt_chunked` returns a `ChunkedCiphertext` that `decrypt_chunked` consumes, and
    # `wrap_cek_x25519` needs a recipient public key the caller can only derive with
    # `x25519_public_key`. Exporting the functions without those leaves the entry point
    # unreachable in practice, which is the defect class this whole export exists to answer.
    "ChunkedCiphertext": ("pyrxd.crypto.aead", "ChunkedCiphertext"),
    "EncryptedChunk": ("pyrxd.crypto.aead", "EncryptedChunk"),
    "WrappedCEK": ("pyrxd.crypto.kem", "WrappedCEK"),
    "decrypt_chunked": ("pyrxd.crypto.aead", "decrypt_chunked"),
    "encrypt_chunked": ("pyrxd.crypto.aead", "encrypt_chunked"),
    "unwrap_cek_x25519": ("pyrxd.crypto.kem", "unwrap_cek_x25519"),
    "wrap_cek_x25519": ("pyrxd.crypto.kem", "wrap_cek_x25519"),
    "x25519_public_key": ("pyrxd.crypto.kem", "x25519_public_key"),
    # Local regtest dev node (see `pyrxd regtest` / the quickstart tutorial)
    "RegtestNode": ("pyrxd.devnet", "RegtestNode"),
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

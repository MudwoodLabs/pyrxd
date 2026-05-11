"""Glyph protocol — NFT singletons, FT tokens, dMint contracts, mutable refs.

Re-exports the public Glyph API from the submodules. Lazy via PEP 562
``__getattr__`` so ``import pyrxd.glyph.X`` paths that don't need the
full builder/signing chain (e.g. ``pyrxd.glyph.inspect`` from the
browser-hosted inspect tool) avoid pulling in ``coincurve``,
``aiohttp``, ``Cryptodome.Cipher``, etc. transitively.

See :mod:`pyrxd` for the broader rationale on lazy public re-exports.
"""

from __future__ import annotations

# Map of public-name → (module-path, attribute) pairs. Resolved on
# first attribute access.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ContainerRevealScripts": ("pyrxd.glyph.builder", "ContainerRevealScripts"),
    "DaaMode": ("pyrxd.glyph.dmint", "DaaMode"),
    "DmintAlgo": ("pyrxd.glyph.dmint", "DmintAlgo"),
    "DmintCborPayload": ("pyrxd.glyph.dmint", "DmintCborPayload"),
    "DmintDeployParams": ("pyrxd.glyph.dmint", "DmintDeployParams"),
    "DmintState": ("pyrxd.glyph.dmint", "DmintState"),
    "DmintV1ContractInitialState": ("pyrxd.glyph.dmint", "DmintV1ContractInitialState"),
    "DmintV1DeployParams": ("pyrxd.glyph.builder", "DmintV1DeployParams"),
    "DmintV1DeployResult": ("pyrxd.glyph.builder", "DmintV1DeployResult"),
    "DmintV1RevealScripts": ("pyrxd.glyph.builder", "DmintV1RevealScripts"),
    "DmintV2DeployParams": ("pyrxd.glyph.builder", "DmintV2DeployParams"),
    "DmintV2DeployResult": ("pyrxd.glyph.builder", "DmintV2DeployResult"),
    "find_dmint_contract_utxos": ("pyrxd.glyph.dmint", "find_dmint_contract_utxos"),
    "FtTransferParams": ("pyrxd.glyph.builder", "FtTransferParams"),
    "FtTransferResult": ("pyrxd.glyph.ft", "FtTransferResult"),
    "FtUtxo": ("pyrxd.glyph.ft", "FtUtxo"),
    "FtUtxoSet": ("pyrxd.glyph.ft", "FtUtxoSet"),
    "GlyphBuilder": ("pyrxd.glyph.builder", "GlyphBuilder"),
    "GlyphCreator": ("pyrxd.glyph.types", "GlyphCreator"),
    "GlyphFt": ("pyrxd.glyph.types", "GlyphFt"),
    "GlyphInspector": ("pyrxd.glyph.inspector", "GlyphInspector"),
    "GlyphItem": ("pyrxd.glyph.scanner", "GlyphItem"),
    "GlyphMetadata": ("pyrxd.glyph.types", "GlyphMetadata"),
    "GlyphNft": ("pyrxd.glyph.types", "GlyphNft"),
    "GlyphPolicy": ("pyrxd.glyph.types", "GlyphPolicy"),
    "GlyphProtocol": ("pyrxd.glyph.types", "GlyphProtocol"),
    "GlyphRef": ("pyrxd.glyph.types", "GlyphRef"),
    "GlyphRights": ("pyrxd.glyph.types", "GlyphRights"),
    "GlyphRoyalty": ("pyrxd.glyph.types", "GlyphRoyalty"),
    "GlyphScanner": ("pyrxd.glyph.scanner", "GlyphScanner"),
    "MutableRevealScripts": ("pyrxd.glyph.builder", "MutableRevealScripts"),
    "build_dmint_contract_script": ("pyrxd.glyph.dmint", "build_dmint_contract_script"),
    "build_dmint_state_script": ("pyrxd.glyph.dmint", "build_dmint_state_script"),
    "build_mint_scriptsig": ("pyrxd.glyph.dmint", "build_mint_scriptsig"),
    "build_mutable_nft_script": ("pyrxd.glyph.script", "build_mutable_nft_script"),
    "build_mutable_scriptsig": ("pyrxd.glyph.payload", "build_mutable_scriptsig"),
    "build_pow_preimage": ("pyrxd.glyph.dmint", "build_pow_preimage"),
    "compute_next_target_asert": ("pyrxd.glyph.dmint", "compute_next_target_asert"),
    "compute_next_target_linear": ("pyrxd.glyph.dmint", "compute_next_target_linear"),
    "difficulty_to_target": ("pyrxd.glyph.dmint", "difficulty_to_target"),
    "parse_mutable_nft_script": ("pyrxd.glyph.script", "parse_mutable_nft_script"),
    "sign_metadata": ("pyrxd.glyph.creator", "sign_metadata"),
    "target_to_difficulty": ("pyrxd.glyph.dmint", "target_to_difficulty"),
    "verify_creator_signature": ("pyrxd.glyph.creator", "verify_creator_signature"),
    "verify_sha256d_solution": ("pyrxd.glyph.dmint", "verify_sha256d_solution"),
}

__all__ = sorted(_LAZY_EXPORTS.keys())


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pyrxd.glyph' has no attribute {name!r}")
    module_path, attr = target
    import importlib

    obj = getattr(importlib.import_module(module_path), attr)
    globals()[name] = obj
    return obj


def __dir__() -> list[str]:
    return __all__

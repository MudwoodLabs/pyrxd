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
    "AirdropFunding": ("pyrxd.glyph.ft", "AirdropFunding"),
    "AirdropReceipt": ("pyrxd.glyph.client", "AirdropReceipt"),
    "AirdropRecipient": ("pyrxd.glyph.ft", "AirdropRecipient"),
    "ContainerChildRevealScripts": ("pyrxd.glyph.builder", "ContainerChildRevealScripts"),
    "ContainerRevealScripts": ("pyrxd.glyph.builder", "ContainerRevealScripts"),
    "DaaMode": ("pyrxd.glyph.dmint", "DaaMode"),
    "DmintAlgo": ("pyrxd.glyph.dmint", "DmintAlgo"),
    "DmintCborPayload": ("pyrxd.glyph.dmint", "DmintCborPayload"),
    "DmintDeployParams": ("pyrxd.glyph.dmint", "DmintDeployParams"),
    "DmintMineResult": ("pyrxd.glyph.dmint", "DmintMineResult"),
    "DmintMintResult": ("pyrxd.glyph.dmint", "DmintMintResult"),
    "DmintState": ("pyrxd.glyph.dmint", "DmintState"),
    "DmintV1ContractInitialState": ("pyrxd.glyph.dmint", "DmintV1ContractInitialState"),
    "DmintV1DeployParams": ("pyrxd.glyph.builder", "DmintV1DeployParams"),
    "DmintV1DeployResult": ("pyrxd.glyph.builder", "DmintV1DeployResult"),
    "DmintV1RevealScripts": ("pyrxd.glyph.builder", "DmintV1RevealScripts"),
    "DmintV2DeployParams": ("pyrxd.glyph.builder", "DmintV2DeployParams"),
    "DmintV2DeployResult": ("pyrxd.glyph.builder", "DmintV2DeployResult"),
    "find_dmint_contract_utxos": ("pyrxd.glyph.dmint", "find_dmint_contract_utxos"),
    "FtAirdropParams": ("pyrxd.glyph.builder", "FtAirdropParams"),
    "FtAirdropResult": ("pyrxd.glyph.ft", "FtAirdropResult"),
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
    "BroadcastEchoMismatch": ("pyrxd.glyph.client", "BroadcastEchoMismatch"),
    "FtAirdropBuild": ("pyrxd.glyph.transfer", "FtAirdropBuild"),
    "FtTransferBuild": ("pyrxd.glyph.transfer", "FtTransferBuild"),
    "GlyphClient": ("pyrxd.glyph.client", "GlyphClient"),
    "GlyphMinter": ("pyrxd.glyph.mint", "GlyphMinter"),
    "NftTransferBuild": ("pyrxd.glyph.transfer", "NftTransferBuild"),
    "TransferReceipt": ("pyrxd.glyph.client", "TransferReceipt"),
    "GlyphNft": ("pyrxd.glyph.types", "GlyphNft"),
    "GlyphPolicy": ("pyrxd.glyph.types", "GlyphPolicy"),
    "GlyphProtocol": ("pyrxd.glyph.types", "GlyphProtocol"),
    "GlyphRef": ("pyrxd.glyph.types", "GlyphRef"),
    "GlyphRights": ("pyrxd.glyph.types", "GlyphRights"),
    "GlyphRoyalty": ("pyrxd.glyph.types", "GlyphRoyalty"),
    "GlyphScanner": ("pyrxd.glyph.scanner", "GlyphScanner"),
    "JsonFilePendingStore": ("pyrxd.glyph.mint", "JsonFilePendingStore"),
    "MintResult": ("pyrxd.glyph.mint", "MintResult"),
    "MutableRevealScripts": ("pyrxd.glyph.builder", "MutableRevealScripts"),
    "PendingMint": ("pyrxd.glyph.mint", "PendingMint"),
    "PendingMintNotFound": ("pyrxd.glyph.mint", "PendingMintNotFound"),
    "PendingStore": ("pyrxd.glyph.mint", "PendingStore"),
    "PowPreimageResult": ("pyrxd.glyph.dmint", "PowPreimageResult"),
    "UnsafeNullPendingStore": ("pyrxd.glyph.mint", "UnsafeNullPendingStore"),
    "V2UnvalidatedWarning": ("pyrxd.glyph.dmint", "V2UnvalidatedWarning"),
    "build_dmint_code_script": ("pyrxd.glyph.dmint", "build_dmint_code_script"),
    "build_dmint_contract_script": ("pyrxd.glyph.dmint", "build_dmint_contract_script"),
    "build_dmint_state_script": ("pyrxd.glyph.dmint", "build_dmint_state_script"),
    "build_dmint_v1_ft_output_script": ("pyrxd.glyph.dmint", "build_dmint_v1_ft_output_script"),
    "build_dmint_v1_mint_preimage": ("pyrxd.glyph.dmint", "build_dmint_v1_mint_preimage"),
    "build_dmint_v2_mint_preimage": ("pyrxd.glyph.dmint", "build_dmint_v2_mint_preimage"),
    "build_mint_scriptsig": ("pyrxd.glyph.dmint", "build_mint_scriptsig"),
    "build_mutable_nft_script": ("pyrxd.glyph.script", "build_mutable_nft_script"),
    "build_mutable_scriptsig": ("pyrxd.glyph.payload", "build_mutable_scriptsig"),
    "build_pow_preimage": ("pyrxd.glyph.dmint", "build_pow_preimage"),
    "build_reveal_unlock_template": ("pyrxd.glyph.mint", "build_reveal_unlock_template"),
    "compute_next_target_asert": ("pyrxd.glyph.dmint", "compute_next_target_asert"),
    "compute_next_target_linear": ("pyrxd.glyph.dmint", "compute_next_target_linear"),
    "difficulty_to_target": ("pyrxd.glyph.dmint", "difficulty_to_target"),
    "mine_solution": ("pyrxd.glyph.dmint", "mine_solution"),
    "mine_solution_dispatch": ("pyrxd.glyph.dmint", "mine_solution_dispatch"),
    "mine_solution_external": ("pyrxd.glyph.dmint", "mine_solution_external"),
    "parse_mutable_nft_script": ("pyrxd.glyph.script", "parse_mutable_nft_script"),
    "sign_metadata": ("pyrxd.glyph.creator", "sign_metadata"),
    "target_to_difficulty": ("pyrxd.glyph.dmint", "target_to_difficulty"),
    "verify_creator_signature": ("pyrxd.glyph.creator", "verify_creator_signature"),
    # Walking a mutable glyph's own spend chain, and proving the walk reached the tip.
    # EXPORTED DELIBERATELY, not orphaned: an indexer or wallet integrating WAVE (or any mutable
    # glyph) needs "what did this token say, and am I looking at its current state" — and getting
    # that wrong quietly is how a superseded target gets served as authoritative. The in-repo
    # caller arrives with HashMark §7.6 form 2 (#598); until then this is consumer surface, the
    # same shape as `verify_creator_signature` above.
    "walk_mutable_chain": ("pyrxd.glyph.mutable_chain", "walk_mutable_chain"),
    "MutableChainWalk": ("pyrxd.glyph.mutable_chain", "MutableChainWalk"),
    "ChainStep": ("pyrxd.glyph.mutable_chain", "ChainStep"),
    "FoldedRecord": ("pyrxd.glyph.mutable_chain", "FoldedRecord"),
    "fold_chain": ("pyrxd.glyph.mutable_chain", "fold_chain"),
    # HashMark §7.6 form 2. Consumer surface for the same reason as the walker above: the CLI
    # cannot drive it yet because pyrxd has no way to enumerate a token's transactions (the
    # indexer client has `glyph_get_token`, which returns a record, not a history), so the
    # candidate set has to come from the consumer's own index for now.
    "MarkAnchor": ("pyrxd.glyph.mark_anchor", "MarkAnchor"),
    "resolve_mark_anchor": ("pyrxd.glyph.mark_anchor", "resolve_mark_anchor"),
    "WaveIdentityVerdict": ("pyrxd.glyph.wave_identity", "WaveIdentityVerdict"),
    "judge_name_at_mark": ("pyrxd.glyph.wave_identity", "judge_name_at_mark"),
    "verify_sha256d_solution": ("pyrxd.glyph.dmint", "verify_sha256d_solution"),
    "RoyaltyPayout": ("pyrxd.glyph.royalty", "RoyaltyPayout"),
    "royalty_due": ("pyrxd.glyph.royalty", "royalty_due"),
    "royalty_output_scripts": ("pyrxd.glyph.royalty", "royalty_output_scripts"),
    "royalty_payouts": ("pyrxd.glyph.royalty", "royalty_payouts"),
    "RxinDexerClient": ("pyrxd.network.rxindexer", "RxinDexerClient"),
    "RxinDexerError": ("pyrxd.network.rxindexer", "RxinDexerError"),
    "RxinDexerNotFound": ("pyrxd.network.rxindexer", "RxinDexerNotFound"),
    "WaveAttrs": ("pyrxd.glyph.wave", "WaveAttrs"),
    "WaveNameNotFound": ("pyrxd.glyph.wave", "WaveNameNotFound"),
    "WaveRecord": ("pyrxd.glyph.wave", "WaveRecord"),
    "WaveResolver": ("pyrxd.glyph.wave", "WaveResolver"),
    "WaveResolverError": ("pyrxd.glyph.wave", "WaveResolverError"),
    "build_wave_metadata": ("pyrxd.glyph.wave", "build_wave_metadata"),
    "classify_glyph_metadata": ("pyrxd.glyph.wave", "classify_glyph_metadata"),
    "extract_wave_attrs": ("pyrxd.glyph.wave", "extract_wave_attrs"),
    "split_qualified_name": ("pyrxd.glyph.wave", "split_qualified_name"),
    "wave_attrs_from_metadata": ("pyrxd.glyph.wave", "wave_attrs_from_metadata"),
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

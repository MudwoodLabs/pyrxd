"""dMint protocol implementation — subpackage split from the original
``dmint.py`` per the plan at
``docs/plans/2026-05-18-refactor-dmint-py-subpackage-split-plan.md``.

The subpackage layers as ``types ← builders ← chain ← miner`` (one-way
dependency). The ``__init__.py`` uses PEP 562 lazy ``__getattr__`` to
re-export every public symbol — plus 10 underscore-private symbols that
existing tests + ``pyrxd.glyph.builder`` import directly — at their
original ``pyrxd.glyph.dmint`` path. This matches the convention used
by ``pyrxd/__init__.py``, ``pyrxd/glyph/__init__.py``, and
``pyrxd/script/__init__.py``.

A handful of symbols were relocated during execution to keep the
dependency graph one-way:

* ``_OP_STATESEPARATOR`` lives in ``types`` (not ``chain``) because
  ``builders`` needs it and ``builders → chain`` would be a cycle.
* ``_V1_EPILOGUE_PREFIX/_ALGO_OFFSET/_SUFFIX/_LEN`` live in
  ``builders`` (not ``chain``) for the same reason; ``chain``
  re-exports them under their original names.

Mock targeting note: ``mock.patch`` patches the namespace where the
test names the target, not where the calling code resolves it via
PEP 562 ``__getattr__``. Test sites that previously used
``patch("pyrxd.glyph.dmint.hashlib")`` and similar were updated to
target the submodule where the imported name lives (typically
``pyrxd.glyph.dmint.miner.hashlib``).
"""

from __future__ import annotations

# Map of public + shimmed-private symbol name → (module_path, attr_name).
# Resolved on first attribute access via __getattr__ below.
_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    # Public — types bucket
    "DaaMode": ("pyrxd.glyph.dmint.types", "DaaMode"),
    "DmintAlgo": ("pyrxd.glyph.dmint.types", "DmintAlgo"),
    "DmintCborPayload": ("pyrxd.glyph.dmint.types", "DmintCborPayload"),
    "DmintDeployParams": ("pyrxd.glyph.dmint.types", "DmintDeployParams"),
    "DmintMintResult": ("pyrxd.glyph.dmint.types", "DmintMintResult"),
    "DmintV1ContractInitialState": (
        "pyrxd.glyph.dmint.types",
        "DmintV1ContractInitialState",
    ),
    "MAX_SHA256D_TARGET": ("pyrxd.glyph.dmint.types", "MAX_SHA256D_TARGET"),
    "MAX_V2_TARGET_256": ("pyrxd.glyph.dmint.types", "MAX_V2_TARGET_256"),
    "V2UnvalidatedWarning": ("pyrxd.glyph.dmint.types", "V2UnvalidatedWarning"),
    # Public — builders bucket
    "build_dmint_code_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_code_script",
    ),
    "build_dmint_contract_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_contract_script",
    ),
    "build_dmint_state_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_state_script",
    ),
    "build_dmint_v1_code_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_v1_code_script",
    ),
    "build_dmint_v1_contract_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_v1_contract_script",
    ),
    "build_dmint_v1_ft_output_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_v1_ft_output_script",
    ),
    "build_dmint_v1_state_script": (
        "pyrxd.glyph.dmint.builders",
        "build_dmint_v1_state_script",
    ),
    # Public — chain bucket
    "DmintContractUtxo": ("pyrxd.glyph.dmint.chain", "DmintContractUtxo"),
    "DmintMinerFundingUtxo": (
        "pyrxd.glyph.dmint.chain",
        "DmintMinerFundingUtxo",
    ),
    "DmintState": ("pyrxd.glyph.dmint.chain", "DmintState"),
    "find_dmint_contract_utxos": (
        "pyrxd.glyph.dmint.chain",
        "find_dmint_contract_utxos",
    ),
    "find_dmint_funding_utxo": (
        "pyrxd.glyph.dmint.chain",
        "find_dmint_funding_utxo",
    ),
    "is_token_bearing_script": (
        "pyrxd.glyph.dmint.chain",
        "is_token_bearing_script",
    ),
    # Public — miner bucket
    "DEFAULT_MAX_ATTEMPTS": (
        "pyrxd.glyph.dmint.miner",
        "DEFAULT_MAX_ATTEMPTS",
    ),
    "DmintMineResult": ("pyrxd.glyph.dmint.miner", "DmintMineResult"),
    "EXTERNAL_MINER_TIMEOUT_S": (
        "pyrxd.glyph.dmint.miner",
        "EXTERNAL_MINER_TIMEOUT_S",
    ),
    "PowPreimageResult": ("pyrxd.glyph.dmint.miner", "PowPreimageResult"),
    "build_dmint_mint_tx": (
        "pyrxd.glyph.dmint.miner",
        "build_dmint_mint_tx",
    ),
    "build_dmint_v1_mint_preimage": (
        "pyrxd.glyph.dmint.miner",
        "build_dmint_v1_mint_preimage",
    ),
    "build_dmint_v2_mint_preimage": (
        "pyrxd.glyph.dmint.miner",
        "build_dmint_v2_mint_preimage",
    ),
    "build_mint_scriptsig": (
        "pyrxd.glyph.dmint.miner",
        "build_mint_scriptsig",
    ),
    "build_pow_preimage": (
        "pyrxd.glyph.dmint.miner",
        "build_pow_preimage",
    ),
    "compute_next_target_asert": (
        "pyrxd.glyph.dmint.miner",
        "compute_next_target_asert",
    ),
    "compute_next_target_linear": (
        "pyrxd.glyph.dmint.miner",
        "compute_next_target_linear",
    ),
    "difficulty_to_target": (
        "pyrxd.glyph.dmint.miner",
        "difficulty_to_target",
    ),
    "mine_solution": ("pyrxd.glyph.dmint.miner", "mine_solution"),
    "mine_solution_dispatch": (
        "pyrxd.glyph.dmint.miner",
        "mine_solution_dispatch",
    ),
    "mine_solution_external": (
        "pyrxd.glyph.dmint.miner",
        "mine_solution_external",
    ),
    "target_to_difficulty": (
        "pyrxd.glyph.dmint.miner",
        "target_to_difficulty",
    ),
    "verify_sha256d_solution": (
        "pyrxd.glyph.dmint.miner",
        "verify_sha256d_solution",
    ),
    # Underscore-private shims — re-exported here so existing test
    # imports like `from pyrxd.glyph.dmint import _match_v1_epilogue`
    # keep working unchanged. Per the brainstorm's PR #49 facade
    # precedent: re-exported under their original underscore names,
    # not promoted to public.
    "_OP_STATESEPARATOR": ("pyrxd.glyph.dmint.types", "_OP_STATESEPARATOR"),
    "_PART_B1": ("pyrxd.glyph.dmint.types", "_PART_B1"),
    "_PART_B2": ("pyrxd.glyph.dmint.types", "_PART_B2"),
    "_PART_B4": ("pyrxd.glyph.dmint.types", "_PART_B4"),
    "_build_part_b": ("pyrxd.glyph.dmint.builders", "_build_part_b"),
    "_build_part_c": ("pyrxd.glyph.dmint.builders", "_build_part_c"),
    "_match_v1_epilogue": ("pyrxd.glyph.dmint.chain", "_match_v1_epilogue"),
    "_push_4bytes_le": ("pyrxd.glyph.dmint.builders", "_push_4bytes_le"),
    "_push_minimal": ("pyrxd.glyph.dmint.builders", "_push_minimal"),
}

# Only public symbols (no leading underscore) appear in __all__ /
# __dir__, matching how pyrxd/glyph/__init__.py treats its own
# lazy-export map. Shimmed underscore-private symbols are still
# resolvable via __getattr__ but not advertised.
__all__ = sorted(name for name in _LAZY_EXPORTS if not name.startswith("_"))


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pyrxd.glyph.dmint' has no attribute {name!r}")
    module_path, attr = target
    import importlib

    obj = getattr(importlib.import_module(module_path), attr)
    globals()[name] = obj
    return obj


def __dir__() -> list[str]:
    return __all__

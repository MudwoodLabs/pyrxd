"""Re-exports the dmint subpackage public + private surface from
the new submodules. Kept during the split for backwards compatibility
with the lazy facade at dmint/__init__.py; will be deleted in Phase 3.

All 70 symbols from the original dmint.py now live in:
  - types.py    (15 symbols)
  - builders.py (17 symbols + 4 epilogue constants shared with chain)
  - chain.py    (19 symbols)
  - miner.py    (19 symbols)

NOTE: Two plan-specified placements were adjusted to preserve the one-way
  ``types ← builders ← chain ← miner`` dependency graph:

  1. ``_OP_STATESEPARATOR`` moved to ``types.py`` (plan: chain.py) — both
     ``builders.py`` and ``chain.py`` use it; placing it in chain.py would
     require a ``builders → chain`` edge.

  2. ``_V1_EPILOGUE_PREFIX``, ``_V1_EPILOGUE_ALGO_OFFSET``,
     ``_V1_EPILOGUE_SUFFIX``, ``_V1_EPILOGUE_LEN`` moved to ``builders.py``
     (plan: chain.py) — ``build_dmint_v1_code_script`` in builders.py uses
     them; placing them in chain.py would require a ``builders → chain`` edge.
     ``chain.py`` imports them from ``builders.py`` via the allowed
     ``chain → builders`` edge.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# types bucket (15 symbols)
# ---------------------------------------------------------------------------
from .types import (
    DaaMode,
    DmintAlgo,
    DmintCborPayload,
    DmintDeployParams,
    DmintMintResult,
    DmintV1ContractInitialState,
    MAX_SHA256D_TARGET,
    MAX_V2_TARGET_256,
    V2UnvalidatedWarning,
    _PART_B1,
    _PART_B2,
    _PART_B4,
    _PART_C,
    _V2_QUARANTINE_TEXT,
    _warn_v2_unvalidated,
)

# _OP_STATESEPARATOR lives in types.py (see module docstring for rationale)
from .types import _OP_STATESEPARATOR

# ---------------------------------------------------------------------------
# builders bucket (17 symbols + epilogue constants)
# ---------------------------------------------------------------------------
from .builders import (
    _PART_A,
    _POW_HASH_OP,
    _V1_ALGO_BYTE_TO_ENUM,
    _V1_ENUM_TO_ALGO_BYTE,
    _V1_EPILOGUE_ALGO_OFFSET,
    _V1_EPILOGUE_LEN,
    _V1_EPILOGUE_PREFIX,
    _V1_EPILOGUE_SUFFIX,
    _V1_FT_OUTPUT_EPILOGUE,
    _build_asert_daa,
    _build_linear_daa,
    _build_part_b,
    _push_4bytes_le,
    _push_minimal,
    build_dmint_code_script,
    build_dmint_contract_script,
    build_dmint_state_script,
    build_dmint_v1_code_script,
    build_dmint_v1_contract_script,
    build_dmint_v1_ft_output_script,
    build_dmint_v1_state_script,
)

# ---------------------------------------------------------------------------
# chain bucket (19 symbols)
# ---------------------------------------------------------------------------
from .chain import (
    _FUNDING_REF_OPCODE_RANGE,
    _find_v1_contract_utxos_fast,
    _find_v1_contract_utxos_walk,
    _match_v1_epilogue,
    _s2_verify_contract_utxos,
    _scripthash_for_script,
    DmintContractUtxo,
    DmintMinerFundingUtxo,
    DmintState,
    find_dmint_contract_utxos,
    find_dmint_funding_utxo,
    is_token_bearing_script,
    _decode_script_le_int,
    _parse_script_int,
)

# ---------------------------------------------------------------------------
# miner bucket (19 symbols)
# ---------------------------------------------------------------------------
from .miner import (
    DEFAULT_MAX_ATTEMPTS,
    EXTERNAL_MINER_TIMEOUT_S,
    DmintMineResult,
    PowPreimageResult,
    _build_dmint_v1_mint_tx,
    _varint_size,
    build_dmint_mint_tx,
    build_dmint_v1_mint_preimage,
    build_dmint_v2_mint_preimage,
    build_mint_scriptsig,
    build_pow_preimage,
    compute_next_target_asert,
    compute_next_target_linear,
    difficulty_to_target,
    mine_solution,
    mine_solution_dispatch,
    mine_solution_external,
    target_to_difficulty,
    verify_sha256d_solution,
)

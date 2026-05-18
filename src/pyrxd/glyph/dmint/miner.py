"""Mining + mint-tx assembly for the dMint subpackage.

Mining loop (in-process + external + dispatch), PoW preimage
construction, difficulty/target math, scriptSig assembly, and the
complete ``build_dmint_mint_tx`` pipeline. Carries the miner-domain
result dataclasses (``PowPreimageResult``, ``DmintMineResult``) and
timeout constants (``DEFAULT_MAX_ATTEMPTS``, ``EXTERNAL_MINER_TIMEOUT_S``).
Depends on ``.types``, ``.builders``, ``.chain``.

Phase 2 of the split moves symbols into this module one at a time.
Until then, this file is intentionally empty.
"""

from __future__ import annotations

"""Chain-walking + on-chain-byte parsing for the dMint subpackage.

Covers ``find_dmint_*_utxo*`` helpers, the ``is_token_bearing_script``
classifier, opcode-walker primitives (``_parse_script_int``,
``_decode_script_le_int``, ``_match_v1_epilogue``), and the
``DmintState``/``DmintContractUtxo``/``DmintMinerFundingUtxo``
dataclasses whose construction depends on parser logic. Depends on
``.types`` and ``.builders`` (the latter via
``_find_v1_contract_utxos_fast`` which uses
``build_dmint_v1_contract_script`` for shape validation).

Phase 2 of the split moves symbols into this module one at a time.
Until then, this file is intentionally empty.
"""

from __future__ import annotations

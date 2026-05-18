"""Script-construction primitives for the dMint subpackage.

Locking-script builders (V1 + V2), DAA helpers (ASERT, linear), and
the low-level push helpers. Depends on ``.types`` only.

``build_mint_scriptsig`` lives in ``.miner`` despite its name — its
sole callers are the mint-tx assembly functions, so the call cluster
stays local to that module.

Phase 2 of the split moves symbols into this module one at a time.
Until then, this file is intentionally empty.
"""

from __future__ import annotations

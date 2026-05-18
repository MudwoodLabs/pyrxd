"""Type definitions for the dMint subpackage.

Pure data types consumed by ≥2 sibling submodules, plus the
``V2UnvalidatedWarning`` warning class and shared module-level byte
constants. Depends on nothing within the subpackage; siblings import
from here, not the reverse.

Phase 2 of the split moves symbols into this module one at a time.
Until then, this file is intentionally empty.
"""

from __future__ import annotations

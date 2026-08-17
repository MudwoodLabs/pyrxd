from __future__ import annotations

from .satoshis_per_kilobyte import SatoshisPerKilobyte

# Alias for the default fee model
DefaultFeeModel = SatoshisPerKilobyte

#: Explicit re-export. Without this mypy treats the name as private to the module
#: it was imported from, and every typed caller of `from ..fee_models import
#: SatoshisPerKilobyte` fails with attr-defined.
__all__ = ["DefaultFeeModel", "SatoshisPerKilobyte"]

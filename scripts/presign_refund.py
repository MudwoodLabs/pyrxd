#!/usr/bin/env python3
"""Back-compat shim — this module moved to ``pyrxd.gravity.watch.presign``.

See ``scripts/watchtower_run.py`` for why this shim exists and how it works (identity
re-export via ``sys.modules``, so this module and the real one are indistinguishable to
any importer).

New code should import :mod:`pyrxd.gravity.watch.presign` directly, or invoke
``pyrxd-presign-refund``.
"""

from __future__ import annotations

import sys

from pyrxd.gravity.watch import presign as _presign

if __name__ != "__main__":
    sys.modules[__name__] = _presign

if __name__ == "__main__":
    raise SystemExit(_presign.main())

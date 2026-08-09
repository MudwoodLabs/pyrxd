#!/usr/bin/env python3
"""Back-compat shim — this module moved to ``pyrxd.gravity.watch.deadman``.

See ``scripts/watchtower_run.py`` for why this shim exists (a console-script entry point
must resolve to importable package code) and how it works (identity re-export via
``sys.modules``, so this module and the real one are indistinguishable to any importer).

New code should import :mod:`pyrxd.gravity.watch.deadman` directly, or invoke
``pyrxd-watchtower-deadman``.
"""

from __future__ import annotations

import sys

from pyrxd.gravity.watch import deadman as _deadman

if __name__ != "__main__":
    sys.modules[__name__] = _deadman

if __name__ == "__main__":
    raise SystemExit(_deadman.main())

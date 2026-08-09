#!/usr/bin/env python3
"""Back-compat shim — this module moved to ``pyrxd.gravity.watch.run``.

The watchtower runner now ships in the installed package (``pip install pyrxd`` gives you
the ``pyrxd-watchtower`` console script) since a ``[project.scripts]`` entry point must
resolve to importable package code, not a file under ``scripts/`` (nothing there ships in
the wheel/sdist). This file is kept ONLY so ``python scripts/watchtower_run.py`` and the
``sys.path.insert(0, ".../scripts")``-based test suite keep working unchanged.

New code should import :mod:`pyrxd.gravity.watch.run` directly, or invoke
``pyrxd-watchtower``. Do not add new logic here — it is re-exported by identity below, so
this module and the real one are indistinguishable to any importer (including
``monkeypatch``).
"""

from __future__ import annotations

import sys

from pyrxd.gravity.watch import run as _run

if __name__ != "__main__":
    # Re-point this module's entry in sys.modules at the real one so `import watchtower_run`
    # / `from watchtower_run import X` (including private helpers like `_parse_args`) resolve
    # to the SAME module object as `pyrxd.gravity.watch.run` — not a copy.
    sys.modules[__name__] = _run

if __name__ == "__main__":
    raise SystemExit(_run.main())

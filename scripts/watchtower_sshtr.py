#!/usr/bin/env python3
"""Back-compat shim — this module moved to ``pyrxd.gravity.watch.sshtr``.

See ``scripts/watchtower_run.py`` for why this shim exists and how it works (identity
re-export via ``sys.modules``, so this module and the real one are indistinguishable to
any importer — including ``monkeypatch.setattr(watchtower_sshtr.subprocess, "run", ...)``
in the test suite, which patches the same ``subprocess`` module the real reader calls).

This module has no ``main()`` — it is a library class (``SshTrRxdReader``), not a CLI
entrypoint, so it has no ``[project.scripts]`` entry of its own.
"""

from __future__ import annotations

import sys

from pyrxd.gravity.watch import sshtr as _sshtr

sys.modules[__name__] = _sshtr

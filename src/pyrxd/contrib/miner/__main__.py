"""Entry point for ``python -m pyrxd.contrib.miner``.

Defers to :func:`pyrxd.contrib.miner.cli.main` so the same code path
runs whether invoked as a module or via the ``pyrxd-miner`` console
script.
"""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

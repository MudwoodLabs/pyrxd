"""``python -m pyrxd`` entry — defers to :func:`pyrxd.cli.main.run`."""

from __future__ import annotations

from .cli.main import run

if __name__ == "__main__":
    run()

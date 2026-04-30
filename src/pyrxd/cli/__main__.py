"""``python -m pyrxd`` entry point — defers to :func:`pyrxd.cli.main.run`."""

from __future__ import annotations

from .main import run

if __name__ == "__main__":
    run()

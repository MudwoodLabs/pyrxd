"""Automated coverage of the eth_swap_two_host.py PREP harness's OFFLINE self-check.

Its BTC sibling has had this since the harness was written, and
``tests/test_btc_two_host_self_check.py`` said so in its own docstring: "the ETH sibling has no
such test." That documented gap let a real defect through.

The counter leg is DERIVED from ``t_rxd`` in wall clock with an elapsed reserve. When the reserve
was added, the runner's argparse default was raised to suit it and the hardcoded ``t_rxd_blocks``
inside ``run_self_check`` — 250 lines away in the SAME FILE — was not. It fell below the value that
yields a positive ``t_btc``, so the self-check raised ``SystemExit`` at startup. Nothing failed,
because nothing ran it.

A harness's ``--self-check`` is its only validatable deliverable without a chain. If CI does not
run it, it is not covered by anything.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eth_swap_two_host.py"


def _load():
    sys.path.insert(0, str(_SCRIPT.parent))  # the harness imports its sibling _dust_swap_shared
    spec = importlib.util.spec_from_file_location("eth_swap_two_host", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_self_check_passes():
    """run_self_check asserts internally and raises on ANY seam failure — a clean return IS the
    pass. It also raises SystemExit if its own timelocks no longer derive, which is the regression
    this test exists for."""
    _load().run_self_check()

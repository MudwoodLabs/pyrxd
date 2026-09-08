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


class TestTheFastTailIsWiredAndTheRegimeIsDISCLOSED:
    """#621: every reserve DIVIDES by the fast tail, and this harness had no way to supply one.

    `_dividing_interval_s` falls back to the NOMINAL interval when no fast tail is set, so an
    omitted flag did not fail — it sized every reserve against 300 s instead of the 36 s measured
    p10. Measured at the shipped defaults: **8.3x looser**.

    `eth_swap_run.py:193` REFUSES a real-value run without it. Refusing HERE would be wrong: this
    file has no mainnet path at all (`_ALLOWED_*_NETWORKS` is regtest/testnet, and its own header
    says so), so a refusal would block the only work it can legitimately do.

    But this harness drives the two-party adversarial run, and that run is meant to be EVIDENCE.
    Evidence that silently exercised a configuration production refuses is worth less than its
    reader assumes — so the run states which regime it was in.
    """

    @staticmethod
    def _args(mod, **over):
        import argparse
        import inspect
        import re

        src = inspect.getsource(mod._margin_policy)
        if hasattr(mod, "_cross_clock_margin"):
            src += inspect.getsource(mod._cross_clock_margin)
        base = {a: 0 for a in set(re.findall(r"args\.([a-z_]+)", src))}
        base.update(
            margin_blocks=36,
            btc_block_interval_s=600.0,
            rxd_block_interval_s=300.0,
            rxd_block_interval_fast_s=None,
            eth_finalization_window_s=768,
            max_covenant_confirm_wait_s=600,
            eth_finality_stall_tolerance_s=3600,
        )
        base.update(over)
        return argparse.Namespace(**base)

    def test_the_flag_reaches_the_policy(self, capsys):
        """The defect: there was no way to supply it, so the field stayed None however you invoked
        the harness."""
        mod = _load()
        policy = mod._margin_policy(self._args(mod, rxd_block_interval_fast_s=36.0))
        assert policy.rxd_block_interval_fast_s == 36.0

    def test_supplying_it_changes_what_reserves_DIVIDE_by(self, capsys):
        """Pinning the field alone would pass on a policy that ignored it. This pins the arithmetic
        the field exists to drive."""
        from pyrxd.gravity.swap_coordinator import _dividing_interval_s

        mod = _load()
        without = _dividing_interval_s(mod._margin_policy(self._args(mod)))
        with_tail = _dividing_interval_s(mod._margin_policy(self._args(mod, rxd_block_interval_fast_s=36.0)))
        assert without == 300.0 and with_tail == 36.0
        assert without / with_tail > 8, "the gap this discloses must actually be large"

    def test_omitting_it_DISCLOSES_the_looser_regime(self, capsys):
        mod = _load()
        mod._margin_policy(self._args(mod))
        err = capsys.readouterr().err
        assert "no --rxd-block-interval-fast-s" in err
        assert "8.3x" in err, "the disclosure must quantify it, not just mention it"
        assert "not evidence about timing" in err, "say what the run is and is not worth"

    def test_supplying_it_says_SO_rather_than_going_quiet(self, capsys):
        """Silence on the good path would make the warning's absence ambiguous — indistinguishable
        from a run where the disclosure itself broke."""
        mod = _load()
        mod._margin_policy(self._args(mod, rxd_block_interval_fast_s=36.0))
        err = capsys.readouterr().err
        assert "fast tail 36.0s" in err and "no --rxd-block-interval-fast-s" not in err

    def test_omitting_it_is_NOT_refused(self, capsys):
        """The honest path. There is no mainnet wiring in this file, so a refusal would block the
        regtest/testnet work it exists for — `eth_swap_run.py` refuses because it CAN carry value."""
        mod = _load()
        assert mod._margin_policy(self._args(mod)) is not None

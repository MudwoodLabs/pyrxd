"""Every runner's SHIPPED DEFAULTS must survive its own safety gate.

Twice in one day a runner was left holding defaults its gate refuses:

* ``btc_swap_two_host`` kept ``t_rxd=20 / t_btc=60`` — the PRE-#482 ordering,
  with ``--help`` still teaching "must exceed t_rxd + margin" — when the other
  runners moved to the derived counter-timelock. Missed by a sweep that fixed
  its siblings.
* ``eth_swap_two_host`` defaulted ``t_rxd=60``, which was valid under the
  superseded ``t_rxd - margin - 4`` and exits at startup under the wall-clock
  derivation that replaced it. Broken BY the commit that fixed the class,
  which changed the formula and did not re-check the inputs feeding it.

Neither was reachable by the unit tests: they all construct terms by hand, so
no test ever ran the defaults an operator gets by typing the command with no
flags. This closes that gap by parsing the defaults out of argparse and pushing
them through the real derivation and the real gate.
"""

from __future__ import annotations

import ast
import pathlib
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from _dust_swap_shared import derive_counter_timelock

from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin

_FLAGS = ("--t-rxd-blocks", "--margin-blocks", "--rxd-block-interval-s", "--btc-block-interval-s")


def _argparse_defaults(source: str) -> dict[str, object]:
    out = {}
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and getattr(node.func, "attr", None) == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value in _FLAGS
        ):
            for kw in node.keywords:
                if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                    out[node.args[0].value] = kw.value.value
    return out


def _runners_that_derive() -> list[pathlib.Path]:
    return sorted(p for p in (_ROOT / "scripts").glob("*.py") if "derive_counter_timelock(" in p.read_text())


def test_at_least_one_runner_derives():
    """Non-vacuity: if the discovery finds nothing, every case below vacuously passes."""
    assert _runners_that_derive(), "no runner calls derive_counter_timelock — discovery is broken"


@pytest.mark.parametrize("path", _runners_that_derive(), ids=lambda p: p.name)
def test_shipped_defaults_survive_the_gate(path):
    d = _argparse_defaults(path.read_text())
    t_rxd = d.get("--t-rxd-blocks")
    margin = d.get("--margin-blocks")

    if t_rxd == 0:
        # 0 is the documented "derive me at runtime from the deadline" sentinel.
        return
    if t_rxd is None or margin is None:
        # Margin comes from a measured policy rather than a flag; nothing static to check.
        return

    i_rxd = d.get("--rxd-block-interval-s", 300.0)
    i_btc = d.get("--btc-block-interval-s", 600.0)

    t_btc = derive_counter_timelock(
        t_rxd_blocks=t_rxd,
        margin_blocks=margin,
        rxd_block_interval_s=i_rxd,
        btc_block_interval_s=i_btc,
    )
    policy = MarginPolicy(
        margin=bt.Timelock(margin, bt.TimeUnit.BLOCKS),
        block_interval_s=i_btc,
        is_measured=False,
        rxd_block_interval_s=i_rxd,
        accept_flat_burial=True,
    )
    assert_timelock_margin(bt.Timelock(t_btc, bt.TimeUnit.BLOCKS), bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS), policy)

"""The derived counter leg must survive the gate CALL THE COORDINATOR REALLY MAKES.

``derive_counter_timelock`` solved the margin inequality to equality, which is the
largest ``t_btc`` the gate accepts **at ``elapsed_blocks=0``**.

The coordinator does not call it that way. ``pre_btc_lock_check`` passes
``elapsed_blocks=cov_confs`` — the covenant's confirmation count — and
``assert_timelock_margin`` does ``rxd_blocks -= elapsed_blocks`` before judging. The
taker refuses to fund BTC until the covenant has confirmed, so ``cov_confs`` is never
0 on a real run.

So the derivation produced terms the production gate ALWAYS refuses: measured, it
passed at ``elapsed=0`` and at no other value, for every ``t_rxd`` tried.

Every unit test around this constructed terms by hand and called the gate with the
default ``elapsed_blocks=0``. The fixture was internally consistent, the assertions
were load-bearing, and the situation it set up could not occur in production — the
defect lived in the gap between the fixture and the real call.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

from _dust_swap_shared import (
    PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS,
    derive_counter_timelock,
)

from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.swap_coordinator import MarginPolicy, assert_timelock_margin


def _policy(margin: int, i_btc: float, i_rxd: float) -> MarginPolicy:
    return MarginPolicy(
        margin=bt.Timelock(margin, bt.TimeUnit.BLOCKS),
        block_interval_s=i_btc,
        is_measured=False,
        rxd_block_interval_s=i_rxd,
        accept_flat_burial=True,
    )


# 600/300 is the nominal pair; 600/222 is the MEASURED Radiant median. They are
# deliberately different so a conflation of the two intervals cannot pass by symmetry.
@pytest.mark.parametrize(("i_btc", "i_rxd"), [(600.0, 300.0), (600.0, 222.0)])
@pytest.mark.parametrize("t_rxd", [120, 200, 400])
@pytest.mark.parametrize("margin", [3, 36])
def test_derived_leg_survives_every_elapsed_value_it_reserved_for(t_rxd, margin, i_btc, i_rxd):
    """For a reserve of R, the gate must accept elapsed anywhere in [0, R]."""
    reserve = PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS
    t_btc = derive_counter_timelock(
        t_rxd_blocks=t_rxd,
        margin_blocks=margin,
        rxd_block_interval_s=i_rxd,
        btc_block_interval_s=i_btc,
        elapsed_reserve_blocks=reserve,
    )
    policy = _policy(margin, i_btc, i_rxd)
    for elapsed in range(reserve + 1):
        assert_timelock_margin(
            bt.Timelock(t_btc, bt.TimeUnit.BLOCKS),
            bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS),
            policy,
            elapsed_blocks=elapsed,
        )


def test_a_zero_reserve_is_refused_by_the_real_call():
    """The honest negative: this is what shipped, and why it could not work.

    Pairs with the case above so the suite proves the reserve is load-bearing rather
    than merely present.
    """
    t_rxd, margin = 120, 36
    t_btc = derive_counter_timelock(
        t_rxd_blocks=t_rxd,
        margin_blocks=margin,
        rxd_block_interval_s=300.0,
        btc_block_interval_s=600.0,
        elapsed_reserve_blocks=0,
    )
    policy = _policy(margin, 600.0, 300.0)
    # elapsed=0 is fine — that is exactly the call no production path makes.
    assert_timelock_margin(bt.Timelock(t_btc, bt.TimeUnit.BLOCKS), bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS), policy)
    with pytest.raises(Exception):
        assert_timelock_margin(
            bt.Timelock(t_btc, bt.TimeUnit.BLOCKS),
            bt.Timelock(t_rxd, bt.TimeUnit.BLOCKS),
            policy,
            elapsed_blocks=1,
        )


def test_reserve_covers_every_runner_confirmation_floor():
    """The reserve must cover the depth each runner waits for, or it under-reserves.

    Derived from the runners rather than asserted against a copy of their numbers, so
    raising a floor without raising the reserve fails here.
    """
    import ast

    floors = {}
    for path in (_ROOT / "scripts").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "add_argument"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "--taker-min-rxd-confs"
            ):
                for kw in node.keywords:
                    if kw.arg == "default" and isinstance(kw.value, ast.Constant):
                        floors[path.name] = kw.value.value
    assert floors, "no runner exposes --taker-min-rxd-confs — discovery is broken"
    for name, floor in floors.items():
        assert floor <= PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS, (
            f"{name} waits for {floor} confirmations but the derivation reserves only "
            f"{PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS} blocks"
        )

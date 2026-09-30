"""A mainnet swap's taker gate needs the MEASURED Radiant fast tail — and that is decided BEFORE
anyone locks.

The gate (``SwapCoordinator.taker_verify_asset_funding``) divides elapsed time by
``MarginPolicy.rxd_block_interval_fast_s`` on a value-bearing network and refuses without it. It
runs at ``pre_btc_lock_check`` step 5 and again inside ``taker_funds_btc`` — after the maker has
locked its Radiant covenant. ``scripts/eth_swap_run.py``'s sepolia-dust stage and
``scripts/eth_swap_grief_run.py`` built a policy with no fast tail while their Radiant leg was
mainnet, so the coordinator constructed, the maker locked mainnet RXD, and the taker's gate then
refused. Pinned here:

* the coordinator REFUSES TO CONSTRUCT on a value-bearing network without the fast tail (the
  negotiation-time check), so no runner can reach a lock without it;
* both ETH scripts refuse at startup without ``--rxd-block-interval-fast-s`` and pass the measured
  value into their policy — never a substituted one;
* every script under ``scripts/`` that builds a coordinator against the mainnet node client passes
  a fast tail into the policy it hands that coordinator. The set of scripts is DERIVED from the
  source (with a non-vacuity check and a known member), and so is the policy each one uses.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import hashlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

from pyrxd.btc_wallet import taproot as bt
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, SwapCoordinator
from pyrxd.gravity.swap_state import SwapRecord, SwapState
from pyrxd.security.errors import ValidationError
from tests.test_swap_coordinator import FakeEthLeg, FakeIndexer, FakeSeenStore, _eth_terms, _final
from tests.test_taker_funding_spv_gate import _HARD_BITS, _ChainView, _covenant, _real_leg, _value_bearing_chain

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    sys.path.insert(0, str(_SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(f"{name}_fast_tail", _SCRIPTS / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(_SCRIPTS))


@pytest.fixture(scope="module")
def eth_run():
    return _load("eth_swap_run")


@pytest.fixture(scope="module")
def grief_run():
    return _load("eth_swap_grief_run")


def _sepolia_dust_args(mod, monkeypatch, *extra: str) -> argparse.Namespace:
    monkeypatch.setattr(sys, "argv", ["eth_swap_run.py", "--stage", "sepolia-dust", "--i-accept-dust-loss", *extra])
    args = mod._args()
    assert not mod._token_leg_is_real(args), "this pins the throwaway-token branch of _policy"
    return args


def _eth_coord_on_mainnet_radiant(monkeypatch, policy):
    """The reviewer's shape: an ETH (Sepolia) counter leg, the Radiant leg tagged 'bc' — mainnet,
    as ``SshTrRadiantClient.NETWORK`` is — and a fresh NEGOTIATED record."""
    base, _chain = _value_bearing_chain(monkeypatch)
    p = os.urandom(32)
    terms = dataclasses.replace(
        _eth_terms(hashlock=hashlib.sha256(p).digest()),
        t_rxd=bt.Timelock(60, bt.TimeUnit.BLOCKS),
        radiant_amount=1000,
    )
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
    eth = FakeEthLeg(preimage=p, verdict=_final())
    eth.network = "sepolia"
    eth.chain_id = 11155111
    return SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=eth,
        radiant_leg=_real_leg(view, network="bc"),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(
            margin_policy=policy,
            maker_stall_safety_window_blocks=6,
            accept_estimated_eth_margins=True,
            accept_nondurable_seen=True,
        ),
    )


def test_a_mainnet_radiant_coordinator_without_the_fast_tail_refuses_to_construct(eth_run, monkeypatch):
    """The reviewer's probe, turned round. The sepolia-dust stage's policy exactly as it was built
    before the fix (the stage's own ``_policy``, less the fast tail it now carries) used to
    CONSTRUCT a coordinator whose Radiant leg is mainnet; the maker then locked, and the taker gate
    refused. It now refuses at construction, before anyone locks — and the same policy WITH the
    fast tail constructs."""
    with_tail = eth_run._policy(_sepolia_dust_args(eth_run, monkeypatch, "--rxd-block-interval-fast-s", "36"))
    before_fix = type(with_tail)(**{**with_tail.__dict__, "rxd_block_interval_fast_s": None})
    with pytest.raises(ValidationError, match=r"refused before anyone locks.*rxd_block_interval_fast_s"):
        _eth_coord_on_mainnet_radiant(monkeypatch, before_fix)
    assert _eth_coord_on_mainnet_radiant(monkeypatch, with_tail).record.state is SwapState.NEGOTIATED


def test_the_sepolia_dust_stage_refuses_at_startup_without_the_fast_tail(eth_run, monkeypatch):
    args = _sepolia_dust_args(eth_run, monkeypatch)
    with pytest.raises(SystemExit, match="--rxd-block-interval-fast-s"):
        eth_run._policy(args)


def test_the_sepolia_dust_stage_passes_the_measured_fast_tail_into_its_policy(eth_run, monkeypatch):
    """The flag was parsed and then IGNORED on this stage (the reviewer's probe). Now it is the
    value the policy carries — the one typed, not a substitute."""
    args = _sepolia_dust_args(eth_run, monkeypatch, "--rxd-block-interval-fast-s", "37.5")
    policy = eth_run._policy(args)
    assert policy.rxd_block_interval_fast_s == 37.5
    assert policy.is_measured is False  # still the throwaway-token (estimated) branch


def _grief_args(mod, monkeypatch, *extra: str) -> argparse.Namespace:
    monkeypatch.setattr(sys, "argv", ["eth_swap_grief_run.py", "--i-accept-dust-loss", *extra])
    return mod._parse() if hasattr(mod, "_parse") else mod._args()


def test_the_grief_run_refuses_at_startup_without_the_fast_tail_and_passes_it_through(grief_run, monkeypatch):
    with pytest.raises(SystemExit, match="--rxd-block-interval-fast-s"):
        grief_run._policy(_grief_args(grief_run, monkeypatch))
    policy = grief_run._policy(_grief_args(grief_run, monkeypatch, "--rxd-block-interval-fast-s", "36"))
    assert policy.rxd_block_interval_fast_s == 36.0


# --------------------------------------------------------------------------- the derived set


def _calls(tree: ast.AST, name: str) -> list[ast.Call]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if (isinstance(f, ast.Name) and f.id == name) or (isinstance(f, ast.Attribute) and f.attr == name):
                out.append(node)
    return out


def _mainnet_coordinator_scripts() -> dict[str, ast.Module]:
    """Every script that constructs a ``SwapCoordinator`` AND builds its Radiant side on the mainnet
    node client (``SshTrRadiantClient``, whose ``NETWORK`` is ``'bc'``) — read from the source."""
    out = {}
    for path in sorted(_SCRIPTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        if _calls(tree, "SwapCoordinator") and "SshTrRadiantClient" in names:
            out[path.stem] = tree
    return out


def _defs(tree: ast.AST) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def _resolve(builder: str, tree: ast.Module) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """*builder* as the script sees it: its own definition first (two scripts both define
    ``_policy``), then the shared ``scripts/_*.py`` helpers it imports from."""
    own = _defs(tree)
    if builder in own:
        return own[builder]
    found = [
        d[builder]
        for path in sorted(_SCRIPTS.glob("_*.py"))
        if builder in (d := _defs(ast.parse(path.read_text(encoding="utf-8"))))
    ]
    assert len(found) == 1, f"{builder}: {len(found)} definitions in the shared helpers"
    return found[0]


def _callee(expr: ast.AST) -> str | None:
    if isinstance(expr, ast.Await):
        expr = expr.value
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        return expr.func.id
    return None


def _policy_builders(tree: ast.Module) -> set[str]:
    """The functions whose result is handed to a coordinator as ``margin_policy``: either called
    inline (``margin_policy=_policy(args)``) or assigned to the name passed there, in the function
    that builds the ``CoordinatorConfig``."""
    builders: set[str] = set()
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        for call in _calls(fn, "CoordinatorConfig"):
            for kw in call.keywords:
                if kw.arg != "margin_policy":
                    continue
                direct = _callee(kw.value)
                if direct:
                    builders.add(direct)
                    continue
                assert isinstance(kw.value, ast.Name), ast.dump(kw.value)
                for node in ast.walk(fn):
                    if not isinstance(node, ast.Assign):
                        continue
                    targets = [t for t in node.targets]
                    flat = [e for t in targets for e in (t.elts if isinstance(t, ast.Tuple) else [t])]
                    if any(isinstance(e, ast.Name) and e.id == kw.value.id for e in flat):
                        name = _callee(node.value)
                        assert name, f"margin_policy {kw.value.id!r} is not assigned from a call"
                        builders.add(name)
    return builders


def test_every_mainnet_coordinator_script_hands_its_coordinator_a_policy_with_the_fast_tail():
    scripts = _mainnet_coordinator_scripts()
    # Non-vacuity, with a member known to be in the set: the scan that cannot find eth_swap_run
    # (the script the reviewer's probe drove) is broken, not reassuring.
    assert "eth_swap_run" in scripts and "eth_swap_grief_run" in scripts, sorted(scripts)
    assert len(scripts) >= 4, sorted(scripts)
    checked = 0
    for name, tree in scripts.items():
        builders = _policy_builders(tree)
        assert builders, f"{name}: no margin_policy source found"
        for builder in builders:
            fn = _resolve(builder, tree)
            returns = [r.value for r in ast.walk(fn) if isinstance(r, ast.Return) and isinstance(r.value, ast.Call)]
            assert returns, f"{name}: {builder} returns no policy-building call"
            for ret in returns:
                kws = {kw.arg for kw in ret.keywords}
                assert "rxd_block_interval_fast_s" in kws, (
                    f"{name}: {builder} (line {ret.lineno}) builds the coordinator's policy without "
                    "rxd_block_interval_fast_s; its Radiant leg is mainnet, so the taker gate refuses "
                    "without it — after the maker has locked"
                )
                checked += 1
    assert checked >= len(scripts)

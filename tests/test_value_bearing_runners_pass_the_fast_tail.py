"""A mainnet swap needs the MEASURED Radiant fast tail — and that is decided BEFORE anyone locks.

The cross-clock timelock reserves convert time spans into Radiant blocks by dividing by
``MarginPolicy.rxd_block_interval_fast_s`` (``swap_coordinator._dividing_interval_s``); unset, they
fall back to the nominal interval and cover about an eighth of the blocks a measured p10 does. So a
value-bearing coordinator refuses without it. ``scripts/eth_swap_run.py``'s sepolia-dust stage and
``scripts/eth_swap_grief_run.py`` built a policy with no fast tail while their Radiant leg was
mainnet. Pinned here:

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


#: Placeholder node flags: every run that reaches the mainnet node requires them (no default).
_NODE_FLAGS = ("--rxd-ssh-host", "node.example.com", "--rxd-container", "radiant-node")


def _sepolia_dust_args(mod, monkeypatch, *extra: str, node=_NODE_FLAGS) -> argparse.Namespace:
    monkeypatch.setattr(
        sys, "argv", ["eth_swap_run.py", "--stage", "sepolia-dust", "--i-accept-dust-loss", *node, *extra]
    )
    args = mod._args()
    assert not mod._token_leg_is_real(args), "this pins the throwaway-token branch of _policy"
    return args


def _eth_coord_on_mainnet_radiant(monkeypatch, policy):
    """The reviewer's shape: an ETH (Sepolia) counter leg, the Radiant leg tagged 'bc' — mainnet,
    as ``SshTrRadiantClient.NETWORK`` is — and a fresh NEGOTIATED record."""
    import math

    from pyrxd.gravity import funding_spv
    from pyrxd.gravity.swap_coordinator import taker_gate_early_bound
    from tests.test_swap_coordinator import _NOW

    base, _chain = _value_bearing_chain(monkeypatch)
    p = os.urandom(32)
    terms = dataclasses.replace(_eth_terms(hashlock=hashlib.sha256(p).digest()), radiant_amount=1000)
    # t_rxd that outlasts the absolute deadline at the fast tail once the taker gate's modelled
    # elapsed-depth bound is spent — the ordering the coordinator now judges when it is built.
    fast = policy.rxd_block_interval_fast_s
    if fast and policy.cross_clock_margin is not None:
        reserve = taker_gate_early_bound(
            chain=funding_spv.MAINNET_CHAIN, policy=policy, value_at_stake_photons=terms.radiant_amount
        ).elapsed_blocks_upper
        span = terms.eth_timeout_unix_s - _NOW + policy.cross_clock_margin.total_s()
        terms = dataclasses.replace(terms, t_rxd=bt.Timelock(math.ceil(span / fast) + reserve, bt.TimeUnit.BLOCKS))
    else:
        terms = dataclasses.replace(terms, t_rxd=bt.Timelock(120, bt.TimeUnit.BLOCKS))
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
        now_unix_s=_NOW,
    )


def test_a_mainnet_radiant_coordinator_without_the_fast_tail_refuses_to_construct(eth_run, monkeypatch):
    """The reviewer's probe, turned round. The sepolia-dust stage's policy exactly as it was built
    before the fix (the stage's own ``_policy``, less the fast tail it now carries) used to
    CONSTRUCT a coordinator whose Radiant leg is mainnet, its reserves sized at the nominal
    interval. It now refuses at construction, before anyone locks — and the same policy WITH the
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


def _grief_args(mod, monkeypatch, *extra: str, node=_NODE_FLAGS) -> argparse.Namespace:
    monkeypatch.setattr(sys, "argv", ["eth_swap_grief_run.py", "--i-accept-dust-loss", *node, *extra])
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
                    "rxd_block_interval_fast_s; its Radiant leg is mainnet, and the coordinator refuses "
                    "without it (the timelock reserves divide by it)"
                )
                checked += 1
    assert checked >= len(scripts)


#: The coordinator methods that cross the taker gate (``taker_verify_asset_funding``) on the way to a lock.
_GATE_CALLS = ("taker_funds_btc", "pre_btc_lock_check", "resume_interrupted_fund", "taker_verify_asset_funding")


def test_every_mainnet_script_that_reaches_the_taker_gate_asks_at_least_two_operators():
    """Above dust the taker gate requires the funding's depth from two distinct operators, and the
    coordinator refuses at construction a Radiant leg configured to ask fewer. Every script that
    builds its Radiant leg on the mainnet node client AND calls a method that crosses the gate must
    therefore hand that leg ``RadiantChainIO(<node client>, proof_client=mainnet_proof_client())`` —
    the node (its ssh destination's ``source_key``) plus pyrxd's shipped endpoints, asked once per
    operator. The set of scripts is DERIVED; the one that never crosses the gate is pinned by name,
    and the reason it is exempt is asserted, not written."""
    scripts = _mainnet_coordinator_scripts()
    crossing = {n: t for n, t in scripts.items() if any(_calls(t, c) for c in _GATE_CALLS)}
    exempt = set(scripts) - set(crossing)
    assert {"dust_swap_run", "eth_swap_run", "eth_swap_grief_run"} <= set(crossing), sorted(crossing)
    # Pinned membership: dust_swap_resume rebuilds a swap already at BTC_LOCKED (both legs funded)
    # and drives only the claims — it never reaches a lock.
    assert exempt == {"dust_swap_resume"}, sorted(exempt)
    resume_src = (_SCRIPTS / "dust_swap_resume.py").read_text(encoding="utf-8")
    assert ".with_state(SwapState.BTC_LOCKED)" in resume_src
    checked = 0
    for name, tree in crossing.items():
        for leg in _calls(tree, "RadiantCovenantLeg"):
            io = next((kw.value for kw in leg.keywords if kw.arg == "chain_io"), None)
            assert isinstance(io, ast.Call) and _callee(io) == "RadiantChainIO", f"{name}:{leg.lineno}"
            proof = next((kw.value for kw in io.keywords if kw.arg == "proof_client"), None)
            assert _callee(proof) == "mainnet_proof_client", (
                f"{name}:{leg.lineno}: the Radiant leg asks only the node for the funding's depth — one "
                "operator; above dust the coordinator refuses it (pass proof_client=mainnet_proof_client())"
            )
            checked += 1
    assert checked >= len(crossing)

    # And what that construction asks, counted the way the gate counts it.
    shim = _load("radiant_mainnet_chainio")
    from pyrxd.gravity.funding_spv import MIN_REPORTING_OPERATORS, counted_operators
    from pyrxd.gravity.radiant_leg import RadiantChainIO
    from pyrxd.network.source_identity import source_key

    node = shim.SshTrRadiantClient(ssh_host="node.example.com", container="radiant-node")
    ops = counted_operators(RadiantChainIO(node, proof_client=shim.mainnet_proof_client()).configured_depth_operators())
    assert str(source_key(node._ssh_host)) in ops and len(ops) >= MIN_REPORTING_OPERATORS + 1, ops


# --------------------------------------------------------------------------- the single-operator override


def _parser_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    """The functions in a script that build an ``argparse.ArgumentParser``."""
    return [
        fn
        for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and _calls(fn, "ArgumentParser")
    ]


def test_every_mainnet_coordinator_script_exposes_the_override_flag_and_hands_it_to_its_coordinator():
    """Every script that builds a coordinator on the mainnet node client — the set DERIVED from the
    source, as above — adds ``--accept-single-operator-up-to`` to the parser it builds, and every
    ``CoordinatorConfig`` it constructs takes ``funding_bound=funding_bound_from_args(...)``, the one
    helper that turns the flag into ``ElapsedBoundPolicy.accept_single_operator_up_to_photons``."""
    scripts = _mainnet_coordinator_scripts()
    assert {"dust_swap_run", "eth_swap_run", "eth_swap_grief_run", "dust_swap_resume"} <= set(scripts), sorted(scripts)
    configs = 0
    for name, tree in scripts.items():
        parsers = _parser_functions(tree)
        assert parsers, f"{name}: no ArgumentParser found"
        for fn in parsers:
            assert _calls(fn, "add_single_operator_override_arg"), (
                f"{name}:{fn.name} builds a parser without --accept-single-operator-up-to"
            )
        for call in _calls(tree, "CoordinatorConfig"):
            fb = next((kw.value for kw in call.keywords if kw.arg == "funding_bound"), None)
            assert _callee(fb) == "funding_bound_from_args", (
                f"{name}:{call.lineno}: CoordinatorConfig without funding_bound=funding_bound_from_args(args) — "
                "the --accept-single-operator-up-to flag would be parsed and ignored"
            )
            configs += 1
    assert configs >= len(scripts)


def test_the_override_flag_parses_rxd_exactly_and_refuses_nonsense():
    shared = _load("_dust_swap_shared")
    ap = argparse.ArgumentParser()
    shared.add_single_operator_override_arg(ap)

    def parsed(*argv):
        return ap.parse_args(list(argv))

    assert parsed().accept_single_operator_up_to is None
    assert parsed("--accept-single-operator-up-to", "2500").accept_single_operator_up_to == 2500 * 10**8
    assert parsed("--accept-single-operator-up-to", "0.00000001").accept_single_operator_up_to == 1
    assert parsed("--accept-single-operator-up-to", "0").accept_single_operator_up_to == 0
    for bad in ("-1", "abc", "nan", "inf", "0.000000001", ""):
        with pytest.raises(SystemExit):
            parsed("--accept-single-operator-up-to", bad)


def test_the_flag_reaches_the_policy_and_the_output_says_so(capsys):
    """The value typed is the value the coordinator's policy carries — and the run's own output
    states it, with WARNING when it raises the threshold; unset, the shipped defaults, silently."""
    shared = _load("_dust_swap_shared")
    from pyrxd.gravity.funding_spv import DEFAULT_ELAPSED_BOUND_POLICY

    assert shared.funding_bound_from_args(argparse.Namespace(accept_single_operator_up_to=None)) == (
        DEFAULT_ELAPSED_BOUND_POLICY
    )
    assert capsys.readouterr().out == ""
    raised = shared.funding_bound_from_args(argparse.Namespace(accept_single_operator_up_to=2500 * 10**8))
    assert raised.accept_single_operator_up_to_photons == 2500 * 10**8
    out = capsys.readouterr().out
    assert (
        "WARNING" in out and "single-operator depth accepted up to 2500 RXD by user override (default 1000 RXD)" in out
    )
    lowered = shared.funding_bound_from_args(argparse.Namespace(accept_single_operator_up_to=10**8))
    assert lowered.single_operator_threshold_photons == 10**8
    out = capsys.readouterr().out
    assert "WARNING" not in out and "accepted up to 1 RXD by user override" in out


def test_each_mainnet_script_parses_the_flag_into_its_args(eth_run, grief_run, monkeypatch):
    """Through each script's OWN parser, not the helper alone."""
    flag = ("--accept-single-operator-up-to", "1500")
    args = _sepolia_dust_args(eth_run, monkeypatch, *flag)
    assert args.accept_single_operator_up_to == 1500 * 10**8
    assert _grief_args(grief_run, monkeypatch, *flag).accept_single_operator_up_to == 1500 * 10**8
    dust = _load("dust_swap_run")
    assert dust._parse_args(["--stage", "dry-run", *flag]).accept_single_operator_up_to == 1500 * 10**8
    resume = _load("dust_swap_resume")
    got = resume._parse_args(["--keys-out", "k", "--btc-htlc-funding-txid", "ab" * 32, *_NODE_FLAGS, *flag])
    assert got.accept_single_operator_up_to == 1500 * 10**8


# --------------------------------------------------------------------------- the node host is the user's


def test_the_node_shims_have_no_default_host_or_container():
    """The ssh shim and the REST REF-gate adapter are public code: neither may default to any one
    operator's host or container. Both refuse to construct without them, and refuse a value that
    would be read as an option once it reaches the ssh/docker argv."""
    import inspect

    shim = _load("radiant_mainnet_chainio")
    ref = _load("_glyph_ref_http")
    for cls, params in ((shim.SshTrRadiantClient, ("ssh_host", "container")), (ref.SshTrHttpRefAdapter, ("ssh_host",))):
        sig = inspect.signature(cls.__init__)
        for name in params:
            assert sig.parameters[name].default is inspect.Parameter.empty, f"{cls.__name__}.{name} has a default"
    with pytest.raises(TypeError):
        shim.SshTrRadiantClient()
    for host, container in (("", "radiant-node"), ("node.example.com", ""), ("-oProxyCommand=x", "c"), ("h", "-u")):
        with pytest.raises(ValidationError):
            shim.SshTrRadiantClient(ssh_host=host, container=container)
    client = shim.SshTrRadiantClient(ssh_host="node.example.com", container="radiant-node")
    argv = client._cli_argv("getblockcount")
    assert argv[3] == "node.example.com" and "radiant-node" in argv[4], argv


def _node_client_calls() -> dict[str, list[ast.Call]]:
    """Every ``SshTrRadiantClient(...)`` / ``SshTrHttpRefAdapter(...)`` construction in ``scripts/`` —
    derived from the source."""
    out: dict[str, list[ast.Call]] = {}
    for path in sorted(_SCRIPTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = _calls(tree, "SshTrRadiantClient") + _calls(tree, "SshTrHttpRefAdapter")
        if calls:
            out[path.stem] = calls
    return out


def test_every_script_names_the_node_it_reaches_from_the_command_line():
    """Every construction of the node shim (and of the REST adapter) in ``scripts/`` passes the host
    — and, for the shim, the container — explicitly, from the parsed flags: none relies on a
    default and none spells a host literal. The set is derived, with a known member."""
    calls = _node_client_calls()
    assert {"dust_swap_run", "eth_swap_run", "eth_swap_grief_run", "dust_swap_resume", "dmint_v2_mainnet_run"} <= set(
        calls
    ), sorted(calls)
    checked = 0
    for name, found in calls.items():
        for call in found:
            kws = {kw.arg: kw.value for kw in call.keywords}
            need = ("ssh_host", "container") if _callee(call) == "SshTrRadiantClient" else ("ssh_host",)
            for k in need:
                assert k in kws, f"{name}:{call.lineno}: {_callee(call)} without {k}="
                assert not isinstance(kws[k], ast.Constant), f"{name}:{call.lineno}: {k} is a literal"
            checked += 1
    assert checked >= len(calls)


def test_each_mainnet_script_refuses_at_startup_without_the_node_flags(eth_run, grief_run, monkeypatch, capsys):
    """Through each script's OWN parser: a run that reaches the mainnet node exits at startup with a
    message naming the missing flag; a run that does not reach it (a dry run) is not refused."""
    dust = _load("dust_swap_run")
    resume = _load("dust_swap_resume")
    dmint = _load("dmint_v2_mainnet_run")
    payouts = ("--btc-claim-payout", "51", "--btc-refund-payout", "51")
    refusals = [
        lambda: _sepolia_dust_args(eth_run, monkeypatch, node=()),
        lambda: _sepolia_dust_args(eth_run, monkeypatch, node=_NODE_FLAGS[:2]),
        lambda: _grief_args(grief_run, monkeypatch, node=()),
        lambda: dust._parse_args(["--stage", "dust", *payouts]),
        lambda: resume._parse_args(["--keys-out", "k", "--btc-htlc-funding-txid", "ab" * 32]),
        lambda: dmint._parse_args(["prepare"]),
    ]
    for refuse in refusals:
        with pytest.raises(SystemExit):
            refuse()
        err = capsys.readouterr().err
        assert "--rxd-container" in err, err
    # the partially-supplied case names only what is missing
    with pytest.raises(SystemExit):
        _sepolia_dust_args(eth_run, monkeypatch, node=_NODE_FLAGS[2:])
    err = capsys.readouterr().err
    assert "--rxd-ssh-host is required" in err, err
    # honest paths
    assert dust._parse_args(["--stage", "dry-run"]).rxd_ssh_host == ""
    assert dust._parse_args(["--stage", "dust", *payouts, *_NODE_FLAGS]).rxd_container == "radiant-node"
    assert _sepolia_dust_args(eth_run, monkeypatch).rxd_ssh_host == "node.example.com"
    assert dmint._parse_args(["prepare", *_NODE_FLAGS]).rxd_ssh_host == "node.example.com"

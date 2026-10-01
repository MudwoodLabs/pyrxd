"""The mainnet swap runners build their coordinator FIRST, on terms it accepts.

Three defects in the runners, each found by driving the real scripts up to their first chain action
(2026-09-30), pinned here through the scripts' own entry points:

* **No ``--t-rxd-blocks`` passed.** ``derive_counter_timelock`` reserved a flat 12 Radiant blocks for
  the blocks that elapse before the taker locks, while the coordinator's negotiation-time check
  models the taker gate's bound at about 80 at dust value. Every ``t_rxd`` swept (80 to 1000) gave
  ``dust_swap_run.py --stage dust`` terms the coordinator refused at construction, and the refusal
  printed a negative block count. The runners now reserve the gate's own model
  (``_dust_swap_shared.gate_elapsed_reserve_blocks``), and their defaults construct.
* **A mint before the refusal.** ``eth_swap_run.py --asset-variant nft|ft`` has no value at stake
  unless one is given, so its coordinator refuses — and without ``--*-reuse-reveal-txid`` the fresh
  MAINNET mint ran first. Every runner now builds its coordinator (every construction-time check)
  before anything is minted or broadcast, and ``--value-at-risk-photons`` supplies the value.
* **A dry run that never built the coordinator.** ``dust_swap_run.py --stage dry-run`` reported
  success on terms the broadcast stages refuse. It now builds the same coordinator and reports its
  verdict.

The set of scripts is DERIVED (every script that builds a coordinator on the mainnet node client);
each one needs a driver here or a pinned, asserted exemption.
"""

from __future__ import annotations

import ast
import struct
import sys

import pytest

from pyrxd.gravity import funding_spv
from pyrxd.gravity.funding_spv import DEFAULT_ELAPSED_BOUND_POLICY
from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.gravity.swap_coordinator import MarginPolicy, taker_gate_early_bound
from pyrxd.security.errors import ValidationError
from tests.test_value_bearing_runners_pass_the_fast_tail import (
    _NODE_FLAGS,
    _SCRIPTS,
    _calls,
    _load,
    _mainnet_coordinator_scripts,
)

#: The steps that move value or ask the operator to, by the name each script calls them by. Any of
#: them reached before the coordinator is constructed is the defect this file pins.
_BROADCASTS = (
    "mint_nft_inline",
    "mint_ft_inline",
    "lock_singleton_into_covenant",
    "lock_ft_into_covenant",
    "wait_for_covenant_funding",
    "wait_genesis_mature",
)


class _Stop(Exception):
    """Raised by the first broadcast-or-mint step reached: the run goes no further."""


class _FakeBtcHeaders:
    """Mainnet BTC headers for the margin measurement, without a network: 145 blocks 600 s apart, so
    the measured margin is one BTC block at a 600 s interval."""

    def __init__(self, base_url: str = "") -> None:
        pass

    async def get_tip_height(self) -> int:
        return 900_000

    async def get_block_header_hex(self, height: int) -> bytes:
        return b"\0" * 68 + struct.pack("<I", 1_700_000_000 + 600 * (int(height) - 899_000)) + b"\0" * 8

    async def close(self) -> None:
        pass


def _instrument(mod, events: list[str], monkeypatch) -> None:
    """Record, in order, each coordinator construction and the first broadcast/mint step reached."""
    real = mod.SwapCoordinator

    class _Recording(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            events.append("construct")

    monkeypatch.setattr(mod, "SwapCoordinator", _Recording)
    for name in _BROADCASTS:
        if hasattr(mod, name):

            def stop(*_a, _name=name, **_k):
                events.append(f"broadcast:{_name}")
                raise _Stop(_name)

            monkeypatch.setattr(mod, name, stop)

    async def no_broadcast(self, *_a, **_k):
        events.append(f"broadcast:{type(self).__name__}")
        raise _Stop("broadcast")

    monkeypatch.setattr(RadiantChainIO, "broadcast", no_broadcast)
    shim = sys.modules["radiant_mainnet_chainio"]

    async def no_node(self, *_a, **_k):
        events.append("node-rpc")
        raise _Stop("node RPC")

    monkeypatch.setattr(shim.SshTrRadiantClient, "_run", no_node)


async def _run(coro) -> str:
    try:
        await coro
    except _Stop as exc:
        return f"stopped at {exc}"
    return "returned"


# --------------------------------------------------------------------------- drivers, one per script


def _dust_argv(tmp_path, *extra: str) -> list[str]:
    return [
        "--stage",
        "dust",
        "--i-accept-dust-loss",
        "--yes",
        "--btc-claim-payout",
        "0014" + "aa" * 20,
        "--btc-refund-payout",
        "0014" + "bb" * 20,
        *_NODE_FLAGS,
        "--rxd-block-interval-fast-s",
        "36",
        "--keys-out",
        str(tmp_path / "dust-keys.json"),
        "--report-out",
        str(tmp_path / "dust-report.json"),
        *extra,
    ]


async def _drive_dust(tmp_path, monkeypatch, *extra: str, argv=None) -> tuple[list[str], str]:
    mod = _load("dust_swap_run")
    shared = sys.modules["_dust_swap_shared"]
    events: list[str] = []
    monkeypatch.setattr(shared, "MempoolSpaceSource", _FakeBtcHeaders)
    _instrument(mod, events, monkeypatch)
    import pyrxd.network.bitcoin as nb

    async def utxos(self, address):
        events.append("operator-funded")  # the operator was asked to fund the taker address first
        return [{"txid": "11" * 32, "vout": 0, "confirmed": True, "value_sats": 10**8}]

    async def no_btc_broadcast(self, raw):
        events.append("broadcast:btc")
        raise _Stop("btc broadcast")

    monkeypatch.setattr(nb.MempoolSpaceFundingReader, "list_address_utxos", utxos)
    monkeypatch.setattr(nb.MempoolSpaceBroadcaster, "broadcast", no_btc_broadcast)
    outcome = await _run(mod.run_dust_swap(mod._parse_args(argv or _dust_argv(tmp_path, *extra))))
    return events, outcome


def _eth_argv(tmp_path, *extra: str) -> list[str]:
    return [
        "eth_swap_run.py",
        "--stage",
        "sepolia-dust",
        "--i-accept-dust-loss",
        "--yes",
        "--eth-rpc-url",
        "https://rpc.sepolia.example",
        "--eth-key-hex",
        "11" * 32,
        "--eth-claim-to",
        "0x" + "22" * 20,
        "--eth-refund-to",
        "0x" + "33" * 20,
        *_NODE_FLAGS,
        "--rxd-block-interval-fast-s",
        "36",
        "--keys-out",
        str(tmp_path / f"eth-keys-{len(extra)}-{abs(hash(extra))}.json"),
        "--report-out",
        str(tmp_path / "eth-report.json"),
        *extra,
    ]


async def _drive_eth(tmp_path, monkeypatch, *extra: str) -> tuple[list[str], str]:
    mod = _load("eth_swap_run")
    events: list[str] = []
    _instrument(mod, events, monkeypatch)
    monkeypatch.setattr(sys, "argv", _eth_argv(tmp_path, *extra))
    return events, await _run(mod.run_sepolia_dust(mod._args()))


async def _drive_grief(tmp_path, monkeypatch, *extra: str) -> tuple[list[str], str]:
    mod = _load("eth_swap_grief_run")
    events: list[str] = []
    _instrument(mod, events, monkeypatch)
    argv = _eth_argv(tmp_path, *extra)
    argv = [a for a in argv if a not in ("--stage", "sepolia-dust")]
    argv[0] = "eth_swap_grief_run.py"
    monkeypatch.setattr(sys, "argv", argv)
    return events, await _run(mod.run(mod._args()))


_DRIVERS = {
    "dust_swap_run": _drive_dust,
    "eth_swap_run": _drive_eth,
    "eth_swap_grief_run": _drive_grief,
}


def _first(events: list[str], prefix: str) -> int:
    return next((i for i, e in enumerate(events) if e.startswith(prefix)), len(events))


@pytest.mark.parametrize("name", sorted(_DRIVERS))
async def test_every_mainnet_runner_constructs_at_its_defaults_before_anything_moves(name, tmp_path, monkeypatch):
    """At the shipped defaults each runner constructs its coordinator, and does so before the first
    step that mints, broadcasts, or asks the operator to fund anything; then that step is reached."""
    events, outcome = await _DRIVERS[name](tmp_path, monkeypatch)
    assert "construct" in events, (name, events, outcome)
    moved = min(_first(events, "broadcast"), _first(events, "operator-funded"), _first(events, "node-rpc"))
    assert events.index("construct") < moved, (name, events)
    assert outcome.startswith("stopped at"), (name, outcome, events)


def test_every_mainnet_coordinator_script_has_a_driver_or_a_pinned_exemption():
    """The set is DERIVED. ``dust_swap_resume`` is exempt, for a reason asserted here: it rebuilds a
    swap already at BTC_LOCKED (both legs funded by the forward run) and constructs its coordinator
    before any call that could move value."""
    scripts = _mainnet_coordinator_scripts()
    assert {"dust_swap_run", "eth_swap_run", "eth_swap_grief_run"} <= set(scripts), sorted(scripts)
    assert set(scripts) - set(_DRIVERS) == {"dust_swap_resume"}, sorted(scripts)
    tree = scripts["dust_swap_resume"]
    resume = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "resume")
    built = min(c.lineno for c in _calls(resume, "SwapCoordinator"))
    movers = [
        c.lineno
        for c in ast.walk(resume)
        if isinstance(c, ast.Call)
        and isinstance(c.func, ast.Attribute)
        and (c.func.attr in ("broadcast",) or c.func.attr.startswith(("maker_", "taker_", "mutual_")))
    ]
    assert movers and min(movers) > built, (built, sorted(movers))
    assert ".with_state(SwapState.BTC_LOCKED)" in (_SCRIPTS / "dust_swap_resume.py").read_text(encoding="utf-8")


@pytest.mark.parametrize("variant", ["nft", "ft"])
async def test_an_nft_or_ft_run_is_refused_before_its_mainnet_mint(variant, tmp_path, monkeypatch):
    """No value at stake: refused naming ``--value-at-risk-photons``, and the fresh mint never runs.
    With the flag the coordinator is built (every check) BEFORE the mint is reached."""
    events, outcome = None, None
    with pytest.raises(SystemExit, match="--value-at-risk-photons"):
        events, outcome = await _drive_eth(tmp_path, monkeypatch, "--asset-variant", variant)
    assert events is None  # refused, not stopped at a mint
    events, outcome = await _drive_eth(
        tmp_path, monkeypatch, "--asset-variant", variant, "--value-at-risk-photons", "100000"
    )
    assert outcome == f"stopped at mint_{variant}_inline", (outcome, events)
    assert events[: events.index(f"broadcast:mint_{variant}_inline")] == ["construct"], events


async def test_a_construction_refusal_stops_the_eth_run_before_the_mint(tmp_path, monkeypatch):
    """The preflight itself: with the reserve supplied (so the run reaches it) and no value at stake,
    the coordinator's construction refuses, the run stops naming the flag, and the mint is never
    reached."""
    mod = _load("eth_swap_run")
    mint_reached: list[int] = []
    monkeypatch.setattr(mod, "mint_nft_inline", lambda *a, **k: mint_reached.append(1))
    monkeypatch.setattr(mod, "_gate_reserve", lambda *a, **k: 80)
    monkeypatch.setattr(sys, "argv", _eth_argv(tmp_path, "--asset-variant", "nft"))
    with pytest.raises(SystemExit) as exc:
        await mod.run_sepolia_dust(mod._args())
    msg = str(exc.value)
    assert "refused before anything is minted or broadcast" in msg and "--value-at-risk-photons" in msg, msg
    assert mint_reached == []


# --------------------------------------------------------------------------- the reserve is the gate's


def test_the_runners_reserve_is_the_coordinators_own_model():
    """``gate_elapsed_reserve_blocks`` is ``taker_gate_early_bound`` on Radiant mainnet — the function
    ``SwapCoordinator._funding_proof_room_failure`` calls — and at dust value it is far above the flat
    12-block reserve it replaced."""
    shared = _load("_dust_swap_shared")
    policy = MarginPolicy.estimated(accept_flat_burial=True)
    for value in (1_000, 10**11, 10**13):
        got = shared.gate_elapsed_reserve_blocks(
            policy=policy, value_at_stake_photons=value, funding_bound=DEFAULT_ELAPSED_BOUND_POLICY
        )
        want = taker_gate_early_bound(
            chain=funding_spv.MAINNET_CHAIN, policy=policy, value_at_stake_photons=value
        ).elapsed_blocks_upper
        assert got == want
    assert got > shared.PRE_BTC_LOCK_ELAPSED_RESERVE_BLOCKS
    with pytest.raises(SystemExit, match="--value-at-risk-photons"):
        shared.gate_elapsed_reserve_blocks(
            policy=policy, value_at_stake_photons=None, funding_bound=DEFAULT_ELAPSED_BOUND_POLICY
        )


async def test_the_smallest_t_rxd_the_dust_runner_derives_constructs_and_one_less_is_refused(tmp_path, monkeypatch):
    """At the reserve the runner derives, the smallest ``t_rxd`` with a ``t_btc`` constructs; one less
    is refused at startup, before anything is funded, saying how many blocks short — never a negative."""
    shared = _load("_dust_swap_shared")
    reserve = shared.gate_elapsed_reserve_blocks(
        policy=MarginPolicy.estimated(accept_flat_burial=True),
        value_at_stake_photons=1000,
        funding_bound=DEFAULT_ELAPSED_BOUND_POLICY,
    )
    smallest = reserve + 2 * (1 + 1)  # one-block margin at 600 s BTC / 300 s Radiant: (1 + 1) × 2
    events, outcome = await _drive_dust(tmp_path, monkeypatch, "--t-rxd-blocks", str(smallest))
    assert events[0] == "construct", (events, outcome)
    with pytest.raises(SystemExit) as exc:
        await _drive_dust(tmp_path / "short", monkeypatch, "--t-rxd-blocks", str(smallest - 1))
    msg = str(exc.value)
    assert "it is 1 block short" in msg and f"at least {smallest}" in msg, msg
    assert not any(tok.startswith("-") and tok[1:].isdigit() for tok in msg.split()), msg


def test_the_construction_refusal_never_prints_a_negative_block_count(monkeypatch):
    """The negotiation-time refusal said "the -60 blocks of it left". With t_rxd below the modelled
    bound it now says none is left and how many blocks short t_rxd is; above it, how many are left."""
    from tests.test_taker_funding_spv_gate import _btc_coord, _ChainView, _covenant, _real_leg, _vb_policy, _wide_terms

    def refusal(t_rxd: int) -> str:
        terms = _wide_terms(t_rxd, t_btc_blocks=1)
        view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6)
        with pytest.raises(ValidationError) as exc:
            _btc_coord(terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True)
        return str(exc.value)

    low = refusal(20)
    assert "none of it is left once 80 have elapsed" in low and "blocks short of the" in low, low
    assert not any(tok.startswith("-") and tok[1:].rstrip(",.:;)").isdigit() for tok in low.split()), low
    mid = refusal(84)
    assert "only 4 blocks of it are left once 80 have elapsed" in mid and "blocks short of the" in mid, mid


# --------------------------------------------------------------------------- the dry run's verdict


async def test_the_dry_run_builds_the_coordinator_and_reports_its_verdict(tmp_path, monkeypatch, capsys):
    """The dry run used to stop after building the transactions and report success on terms the dust
    stage refused. It builds the same coordinator now: at the defaults it says the coordinator accepts
    them; with terms the coordinator refuses it says so, as its verdict; and without the fast tail it
    names the flag."""
    base = ["--stage", "dry-run", "--rxd-block-interval-fast-s", "36"]

    def argv(sub, *extra):
        d = tmp_path / sub
        d.mkdir()
        return [*base, "--keys-out", str(d / "k.json"), "--report-out", str(d / "r.json"), *extra]

    events, outcome = await _drive_dust(tmp_path, monkeypatch, argv=argv("ok"))
    assert outcome == "returned" and events == ["construct"], (outcome, events)
    assert "the swap coordinator accepts these terms" in capsys.readouterr().out

    # A value at risk below the covenant amount: the coordinator refuses it at construction.
    with pytest.raises(SystemExit) as exc:
        await _drive_dust(tmp_path, monkeypatch, argv=argv("low", "--value-at-risk-photons", "500"))
    assert "DRY-RUN verdict" in str(exc.value) and "value_at_risk_photons (500)" in str(exc.value), str(exc.value)

    with pytest.raises(SystemExit, match="DRY-RUN VERDICT.*--rxd-block-interval-fast-s"):
        await _drive_dust(
            tmp_path,
            monkeypatch,
            argv=[
                "--stage",
                "dry-run",
                "--keys-out",
                str(tmp_path / "nf.json"),
                "--report-out",
                str(tmp_path / "nf-r.json"),
            ],
        )


def test_the_value_flag_parses_photons_and_refuses_nonsense():
    shared = _load("_dust_swap_shared")
    import argparse

    ap = argparse.ArgumentParser()
    shared.add_value_at_risk_arg(ap)
    assert ap.parse_args([]).value_at_risk_photons is None
    assert ap.parse_args(["--value-at-risk-photons", "123456"]).value_at_risk_photons == 123456
    for bad in ("0", "-5", "1.5", "abc", "", "1e9"):
        with pytest.raises(SystemExit):
            ap.parse_args(["--value-at-risk-photons", bad])


def test_every_mainnet_coordinator_script_exposes_the_value_flag_and_its_policy_carries_it():
    """Derived like the override flag: every script that builds a mainnet coordinator adds
    ``--value-at-risk-photons`` to the parser it builds, and every policy builder it uses passes
    ``value_at_risk_photons`` into the policy it returns (directly, or in the ``**`` dict it spreads)."""
    from tests.test_value_bearing_runners_pass_the_fast_tail import _parser_functions, _policy_builders, _resolve

    def spread_keys(fn, name: str) -> set[str]:
        keys: set[str] = set()
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(t, ast.Name) and t.id == name for t in targets) and isinstance(node.value, ast.Call):
                    keys |= {kw.arg for kw in node.value.keywords if kw.arg}
        return keys

    scripts = _mainnet_coordinator_scripts()
    checked = 0
    for name, tree in scripts.items():
        for fn in _parser_functions(tree):
            assert _calls(fn, "add_value_at_risk_arg"), f"{name}:{fn.name} has no --value-at-risk-photons"
        for builder in _policy_builders(tree):
            fn = _resolve(builder, tree)
            returns = [r.value for r in ast.walk(fn) if isinstance(r, ast.Return) and isinstance(r.value, ast.Call)]
            for ret in returns:
                kws = {kw.arg for kw in ret.keywords if kw.arg}
                for kw in ret.keywords:
                    if kw.arg is None and isinstance(kw.value, ast.Name):
                        kws |= spread_keys(fn, kw.value.id)
                assert "value_at_risk_photons" in kws, (
                    f"{name}: {builder} (line {ret.lineno}) drops --value-at-risk-photons"
                )
                checked += 1
    assert checked >= len(scripts)


#: The coordinator methods that run the taker gate on a lock path; each takes the caller's wall clock.
_GATE_METHODS = ("taker_verify_asset_funding", "pre_btc_lock_check", "taker_funds_btc", "resume_interrupted_fund")


def test_every_script_call_into_the_taker_gate_passes_the_wall_clock():
    """The gate's elapsed-depth bound counts the time since its reference header, and refuses on
    mainnet without a clock. ``eth_swap_two_host.py`` called ``taker_verify_asset_funding(terms)`` with
    none (and printed the bound as "buried N conf(s)"). Every call under ``scripts/`` — DERIVED from
    the source — now passes ``now_unix_s``."""
    calls = []
    for path in sorted(_SCRIPTS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name in _GATE_METHODS:
            calls += [(path.stem, name, c) for c in _calls(tree, name)]
    assert len({stem for stem, _n, _c in calls}) >= 5, sorted({stem for stem, _n, _c in calls})
    assert any(stem == "eth_swap_two_host" and n == "taker_verify_asset_funding" for stem, n, _c in calls)
    missing = [f"{stem}:{c.lineno} {n}" for stem, n, c in calls if not any(kw.arg == "now_unix_s" for kw in c.keywords)]
    assert not missing, missing

"""Config loader: defaults, file, env-var precedence, and network binding."""

from __future__ import annotations

from pathlib import Path

import pytest

from pyrxd.cli import config as _config
from pyrxd.cli.config import load
from pyrxd.cli.context import CliContext
from pyrxd.cli.errors import UserError
from pyrxd.network.registry import DEFAULT_ENDPOINTS, GENESIS_BLOCK_HASHES, KNOWN_NETWORKS
from pyrxd.security.errors import ValidationError

# The endpoint that used to leak across every network selection.
MAINNET_PRIMARY = DEFAULT_ENDPOINTS["mainnet"][0]


def test_defaults_when_no_file(tmp_path: Path) -> None:
    cfg = _config.load(tmp_path / "absent.toml")
    assert cfg.network == "mainnet"
    assert cfg.fee_rate == 10_000
    assert cfg.source_path is None


def test_file_overrides_defaults(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'network = "testnet"\nelectrumx = "wss://custom/"\nfee_rate = 25000\nwallet_path = "{tmp_path / "w.dat"}"\n'
    )
    cfg = _config.load(cfg_file)
    assert cfg.network == "testnet"
    assert cfg.electrumx == "wss://custom/"
    assert cfg.fee_rate == 25_000
    assert cfg.source_path == cfg_file


def test_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "testnet"\nfee_rate = 25000\n')
    monkeypatch.setenv("PYRXD_NETWORK", "regtest")
    monkeypatch.setenv("PYRXD_FEE_RATE", "31234")
    cfg = _config.load(cfg_file)
    assert cfg.network == "regtest"
    assert cfg.fee_rate == 31234


def test_per_network_overrides(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        'network = "mainnet"\n'
        'electrumx = "wss://main/"\n'
        "fee_rate = 10000\n"
        "[networks.testnet]\n"
        'electrumx = "wss://test/"\n'
        # Was `fee_rate = 1` — 10,000x under the relay floor, which the
        # per-network path used to accept. See the FEE-FLOOR section below.
        "fee_rate = 25000\n"
    )
    cfg = _config.load(cfg_file)
    test_cfg = cfg.for_network("testnet")
    assert test_cfg.electrumx == "wss://test/"
    assert test_cfg.fee_rate == 25_000
    # Original mainnet config still has its own values.
    assert cfg.electrumx == "wss://main/"


def test_for_network_with_no_override_does_not_inherit_the_base_endpoint(tmp_path: Path) -> None:
    """Was ``test_for_network_with_unknown_returns_base``, which asserted the bug.

    Falling through to the base endpoint is precisely how ``--network regtest``
    ended up on the mainnet server. The endpoint is now resolved per network and
    the base value is NOT carried across.
    """
    cfg = _config.load(tmp_path / "missing.toml")
    out = cfg.for_network("regtest")
    assert out.network == "regtest"
    assert out.endpoints == ()
    assert out.endpoint_gap is not None


def test_write_default_creates_dir_with_correct_perms(tmp_path: Path) -> None:
    target = tmp_path / "subdir" / "config.toml"
    written = _config.write_default(target)
    assert written.exists()
    # File mode 0o600.
    assert oct(written.stat().st_mode)[-3:] == "600"
    # Parent dir mode 0o700.
    assert oct(target.parent.stat().st_mode)[-3:] == "700"
    # Loadable.
    cfg = _config.load(target)
    assert cfg.network == "mainnet"


def test_coin_type_defaults_to_512(tmp_path: Path) -> None:
    cfg = _config.load(tmp_path / "absent.toml")
    assert cfg.coin_type == 512


def test_coin_type_from_file(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\ncoin_type = 0\n')
    cfg = _config.load(cfg_file)
    # coin_type 0 (legacy Bitcoin-compatible) must survive — it is falsy and a
    # naive ``or`` chain would silently reset it to the 512 default.
    assert cfg.coin_type == 0


def test_coin_type_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("coin_type = 512\n")
    monkeypatch.setenv("PYRXD_COIN_TYPE", "236")
    cfg = _config.load(cfg_file)
    assert cfg.coin_type == 236


def test_write_default_records_coin_type(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    _config.write_default(target, coin_type=0)
    cfg = _config.load(target)
    assert cfg.coin_type == 0


def test_set_coin_type_creates_when_missing(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    _config.set_coin_type(0, target)
    assert _config.load(target).coin_type == 0


def test_set_coin_type_updates_in_place(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_text('network = "testnet"\nfee_rate = 25000\ncoin_type = 512\n')
    _config.set_coin_type(236, target)
    cfg = _config.load(target)
    # Only coin_type changed; the other keys are preserved verbatim.
    assert cfg.coin_type == 236
    assert cfg.network == "testnet"
    assert cfg.fee_rate == 25_000


def test_set_coin_type_appends_when_key_absent(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_text('network = "mainnet"\n')
    _config.set_coin_type(0, target)
    assert _config.load(target).coin_type == 0


def test_for_network_preserves_coin_type(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\ncoin_type = 0\n[networks.testnet]\nfee_rate = 12000\n')
    cfg = _config.load(cfg_file)
    assert cfg.for_network("testnet").coin_type == 0


def test_tomllib_is_available_at_module_load() -> None:
    """The `config` module must successfully import a TOML reader regardless
    of Python version. On 3.11+ the stdlib ``tomllib`` resolves; on 3.10 the
    ``tomli`` backport is the documented fallback (declared as a conditional
    dep in pyproject.toml). This test fails immediately if a future refactor
    drops one path without keeping the other.
    """
    assert _config.tomllib is not None
    # The reader must expose `loads` (the API both modules share).
    assert hasattr(_config.tomllib, "loads")
    # And actually parse a trivial TOML payload.
    parsed = _config.tomllib.loads('key = "value"\n')
    assert parsed == {"key": "value"}


def test_python_310_fallback_imports_tomli(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate Python 3.10 by hiding ``tomllib`` from import machinery and
    re-importing ``config``. The fallback must transparently land on ``tomli``
    (which provides the same surface). Mirrors how a 3.10 user's runtime
    sees ``ModuleNotFoundError`` on the bare ``import tomllib``.
    """
    import importlib
    import sys

    real_tomllib = sys.modules.get("tomllib")
    # Hide tomllib from the import system.
    monkeypatch.setitem(sys.modules, "tomllib", None)
    # Drop the cached config module so reload re-runs the try/except.
    cached = sys.modules.pop("pyrxd.cli.config", None)
    try:
        # Import will hit ModuleNotFoundError on `import tomllib` and fall
        # back to `import tomli as tomllib`. tomli is in the test env via the
        # python<3.11 conditional dep, but on 3.11+ it may not be installed —
        # in which case skip rather than fail (we proved the import path
        # exists, can't test the fallback if the backport isn't present).
        try:
            import tomli  # noqa: F401
        except ModuleNotFoundError:
            pytest.skip("tomli backport not installed — fallback path untestable on this env")
        reloaded = importlib.import_module("pyrxd.cli.config")
        assert reloaded.tomllib is not None
        assert reloaded.tomllib.loads("x = 1\n") == {"x": 1}
    finally:
        # Restore the real module table so subsequent tests see normal state.
        if real_tomllib is not None:
            sys.modules["tomllib"] = real_tomllib
        else:  # pragma: no cover — only on Python 3.10
            sys.modules.pop("tomllib", None)
        if cached is not None:
            sys.modules["pyrxd.cli.config"] = cached


# ── Network binding ───────────────────────────────────────────────────────────
#
# REGRESSION SUITE for the bug this section exists to make unreachable:
#
#   $ pyrxd --network regtest ...   ->  network=regtest,
#                                       electrumx=wss://electrumx.radiant4people.com:50022/  (MAINNET)
#
# `Config.for_network` used to return the unchanged default endpoint whenever the
# selected network had no `[networks.<name>]` block. The default is mainnet's, so a
# developer "testing on regtest" could broadcast a real transaction to mainnet while
# every status line said regtest.


@pytest.mark.parametrize("network", ["regtest", "testnet"])
def test_non_mainnet_selection_never_yields_the_mainnet_endpoint(tmp_path: Path, network: str) -> None:
    """THE regression test. A stock (mainnet) config, selected onto another network,
    must not produce the mainnet endpoint under any resolution path."""
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'network = "mainnet"\nelectrumx = "{MAINNET_PRIMARY}"\n')
    cfg = _config.load(cfg_file)

    out = cfg.for_network(network)

    assert out.network == network
    assert out.electrumx != MAINNET_PRIMARY
    assert MAINNET_PRIMARY not in out.endpoints
    assert out.endpoints == ()


@pytest.mark.parametrize("network", ["regtest", "testnet"])
def test_non_mainnet_selection_on_a_fresh_install_yields_nothing(tmp_path: Path, network: str) -> None:
    """Same property with NO config file at all — the built-in defaults must not
    contain a network-agnostic (i.e. mainnet) endpoint to leak in the first place."""
    cfg = _config.load(tmp_path / "absent.toml")
    out = cfg.for_network(network)
    assert out.endpoints == ()
    for shipped in DEFAULT_ENDPOINTS["mainnet"]:
        assert shipped not in out.endpoints


@pytest.mark.parametrize("network", ["regtest", "testnet"])
def test_the_error_names_exactly_what_to_configure(tmp_path: Path, network: str) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'network = "mainnet"\nelectrumx = "{MAINNET_PRIMARY}"\n')
    gap = _config.load(cfg_file).for_network(network).endpoint_gap
    assert gap is not None

    assert network in gap.message
    # The TOML table, the key, the file to edit, and the one-off flag.
    assert f"[networks.{network}]" in gap.fix
    assert "electrumx =" in gap.fix
    assert str(cfg_file) in gap.fix
    assert "--electrumx" in gap.fix
    # And WHY it refused, so the fix isn't cargo-culted.
    assert "mainnet" in gap.cause


@pytest.mark.parametrize("network", ["regtest", "testnet"])
def test_building_a_client_for_an_unconfigured_network_fails_closed(tmp_path: Path, network: str) -> None:
    """Fail-closed is enforced where it matters: you cannot obtain a client at all."""
    cfg = _config.load(tmp_path / "absent.toml").for_network(network)
    ctx = CliContext(config=cfg, network=network, electrumx_url=cfg.electrumx)

    with pytest.raises(UserError) as exc:
        ctx.make_client()
    rendered = exc.value.format_message()
    assert network in rendered
    assert f"[networks.{network}]" in rendered
    assert exc.value.exit_code == 1


def test_require_profile_raises_a_typed_library_error(tmp_path: Path) -> None:
    cfg = _config.load(tmp_path / "absent.toml").for_network("regtest")
    with pytest.raises(ValidationError, match="regtest"):
        cfg.require_profile()


def test_mainnet_still_resolves_to_the_historical_endpoint(tmp_path: Path) -> None:
    """`--network mainnet` must keep working unchanged: same primary server."""
    cfg = _config.load(tmp_path / "absent.toml").for_network("mainnet")
    assert cfg.electrumx == MAINNET_PRIMARY
    assert cfg.endpoint_gap is None


def test_mainnet_profile_is_chain_bound(tmp_path: Path) -> None:
    profile = _config.load(tmp_path / "absent.toml").for_network("mainnet").require_profile()
    assert profile.genesis_hash == GENESIS_BLOCK_HASHES["mainnet"]


def test_an_explicit_per_network_endpoint_is_used(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'network = "mainnet"\nelectrumx = "{MAINNET_PRIMARY}"\n'
        "[networks.regtest]\n"
        'electrumx = "ws://127.0.0.1:50022/"\n'
        "allow_insecure = true\n"
    )
    out = _config.load(cfg_file).for_network("regtest")
    assert out.endpoints == ("ws://127.0.0.1:50022/",)
    assert out.allow_insecure is True
    assert out.endpoint_gap is None
    assert out.require_profile().urls == ("ws://127.0.0.1:50022/",)


def test_allow_insecure_does_not_leak_from_the_top_level_to_another_network(tmp_path: Path) -> None:
    """A trust relaxation configured for one network must not silently apply to another."""
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        'network = "regtest"\nelectrumx = "ws://127.0.0.1:50022/"\nallow_insecure = true\n'
        "[networks.testnet]\n"
        'electrumx = "wss://testnet.example/"\n'
    )
    cfg = _config.load(cfg_file)
    assert cfg.for_network("regtest").allow_insecure is True
    assert cfg.for_network("testnet").allow_insecure is False


def test_electrumx_flag_override_wins_and_clears_the_gap(tmp_path: Path) -> None:
    """`--electrumx` alongside `--network` is an explicit statement about which
    server serves that network, so it must work without any config edit."""
    cfg = _config.load(tmp_path / "absent.toml")
    out = cfg.for_network("regtest", electrumx_override="wss://my-regtest.example/")
    assert out.endpoints == ("wss://my-regtest.example/",)
    assert out.endpoint_gap is None


def test_env_endpoint_only_applies_to_its_own_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """PYRXD_ELECTRUMX is bound to the resolved network like any other top-level
    endpoint — it must not follow a later `--network` change onto a different chain."""
    monkeypatch.setenv("PYRXD_ELECTRUMX", "wss://from-env.example/")
    cfg = _config.load(tmp_path / "absent.toml")  # network defaults to mainnet
    assert cfg.for_network("mainnet").endpoints == ("wss://from-env.example/",)
    assert cfg.for_network("regtest").endpoints == ()


def test_electrumx_servers_list_is_the_failover_order(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\nelectrumx_servers = ["wss://one.example/", "wss://two.example/"]\n')
    out = _config.load(cfg_file).for_network("mainnet")
    assert out.endpoints == ("wss://one.example/", "wss://two.example/")
    assert out.electrumx == "wss://one.example/"  # primary stays the display value


def test_per_network_servers_list(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\n[networks.testnet]\nelectrumx_servers = ["wss://t1/", "wss://t2/"]\n')
    assert _config.load(cfg_file).for_network("testnet").endpoints == ("wss://t1/", "wss://t2/")


def test_env_endpoint_replaces_a_configured_server_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A one-off override must not keep failing over to the servers it was bypassing."""
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\nelectrumx_servers = ["wss://one/", "wss://two/"]\n')
    monkeypatch.setenv("PYRXD_ELECTRUMX", "wss://only-this/")
    assert _config.load(cfg_file).for_network("mainnet").endpoints == ("wss://only-this/",)


def test_single_configured_endpoint_stays_single(tmp_path: Path) -> None:
    """The pre-existing single-endpoint behaviour must remain reachable unchanged:
    configure one server, get exactly one server (no silent failover partners)."""
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\nelectrumx = "wss://only-mine/"\n')
    out = _config.load(cfg_file).for_network("mainnet")
    assert out.endpoints == ("wss://only-mine/",)
    assert out.require_profile().urls == ("wss://only-mine/",)


def test_spki_pins_round_trip_from_config(tmp_path: Path) -> None:
    pin = "sha256/" + "A" * 43 + "="
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'network = "mainnet"\nelectrumx = "wss://a.example/"\nspki_pins = ["{pin}"]\n')
    profile = _config.load(cfg_file).for_network("mainnet").require_profile()
    assert profile.endpoints[0].spki_pins == (pin,)


def test_malformed_spki_pin_is_rejected(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\nelectrumx = "wss://a.example/"\nspki_pins = ["nope"]\n')
    with pytest.raises(ValidationError):
        _config.load(cfg_file).for_network("mainnet").require_profile()


def test_non_list_endpoint_config_is_a_typed_error(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("electrumx_servers = 5\n")
    with pytest.raises(ValidationError, match="list of strings"):
        _config.load(cfg_file)


def test_write_default_writes_a_failover_list_for_its_own_network(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    _config.write_default(target)
    cfg = _config.load(target)
    assert cfg.network == "mainnet"
    assert cfg.endpoints == DEFAULT_ENDPOINTS["mainnet"]
    # ...and the written file still refuses to serve another network.
    assert cfg.for_network("regtest").endpoints == ()


def test_fee_rate_below_the_relay_floor_is_refused(tmp_path, monkeypatch):
    """A sub-floor fee_rate must be refused at load, not discovered on-chain.

    Radiant has neither RBF nor CPFP (threat-model S21), so a transaction built
    below the effective relay floor cannot be bumped by any means and squats on
    its own inputs until mempool expiry. `DeadlineFeePolicy` already rejects a
    sub-floor rate for the swap stack; before this guard, every other CLI command
    accepted `PYRXD_FEE_RATE=1` without complaint.
    """
    from pyrxd.gravity.fee_policy import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

    floor_per_byte = RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB // 1000

    monkeypatch.setenv("PYRXD_FEE_RATE", str(floor_per_byte - 1))
    with pytest.raises(ValidationError, match="below Radiant's effective relay floor"):
        load()

    # At the floor, and a deliberate 5x above it, are both fine. Not *arbitrarily*
    # above, though — see the ceiling tests below; 5x is inside the 10x band.
    for ok in (floor_per_byte, floor_per_byte * 5):
        monkeypatch.setenv("PYRXD_FEE_RATE", str(ok))
        assert load().fee_rate == ok


def test_fee_rate_error_names_where_the_value_came_from(tmp_path, monkeypatch):
    """The message must point at the file, so the operator knows what to edit."""
    cfg = tmp_path / "config.toml"
    cfg.write_text('network = "mainnet"\nfee_rate = 1\n')
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    with pytest.raises(ValidationError, match=str(cfg)):
        load(cfg)


# ── FEE FLOOR: the per-network table ──────────────────────────────────────────
#
# REGRESSION SUITE. `_validated_fee_rate` ran only in `load()`. `for_network`
# applied `overrides.get("fee_rate")` from `[networks.<net>]` with no floor check
# at all — and `cli/main.py` routes EVERY invocation through `for_network`. So the
# guard added for the top-level key was bypassable by moving the same value one
# table down, and every mint/transfer/send then built ~100x under the floor.


def test_a_per_network_fee_rate_below_the_floor_is_refused(tmp_path: Path, monkeypatch) -> None:
    """THE regression test for the bypass. Measured before the fix:
    top-level `fee_rate = 100` was correctly rejected by `load()`, while
    `[networks.mainnet] fee_rate = 100` yielded `for_network("mainnet").fee_rate == 100`
    against a 10,000 photons/byte floor."""
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\n[networks.mainnet]\nfee_rate = 100\n')

    # The top-level key on its own IS caught — that is the guard being bypassed.
    control = tmp_path / "control.toml"
    control.write_text('network = "mainnet"\nfee_rate = 100\n')
    with pytest.raises(ValidationError, match="below Radiant's effective relay floor"):
        load(control)

    # ...and the per-network table must now be caught by the same guard.
    cfg = load(cfg_file)
    with pytest.raises(ValidationError, match="below Radiant's effective relay floor"):
        cfg.for_network("mainnet")


@pytest.mark.parametrize("network", ["mainnet", "testnet", "regtest"])
def test_the_per_network_fee_rate_error_names_the_table_not_the_top_level_key(
    tmp_path: Path, monkeypatch, network: str
) -> None:
    """Naming the top-level `fee_rate` would send the operator to edit a key that
    is not the one in force."""
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(f'network = "mainnet"\n[networks.{network}]\nfee_rate = 1\n')
    with pytest.raises(ValidationError) as exc:
        load(cfg_file).for_network(network)
    rendered = str(exc.value)
    assert f"[networks.{network}]" in rendered
    assert str(cfg_file) in rendered


def test_a_per_network_fee_rate_at_or_above_the_floor_is_kept(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\nfee_rate = 10000\n[networks.testnet]\nfee_rate = 90000\n')
    cfg = load(cfg_file)
    assert cfg.for_network("testnet").fee_rate == 90_000
    assert cfg.for_network("mainnet").fee_rate == 10_000


def test_a_non_integer_per_network_fee_rate_is_a_typed_error(tmp_path: Path, monkeypatch) -> None:
    """`int()` on garbage used to escape as a bare ValueError past the config boundary."""
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainnet"\n[networks.mainnet]\nfee_rate = "cheap"\n')
    with pytest.raises(ValidationError, match="networks.mainnet.fee_rate"):
        load(cfg_file).for_network("mainnet")


# ── NETWORK NAME: normalization + membership ──────────────────────────────────
#
# REGRESSION SUITE. The network name was taken verbatim; the only check was a
# `strip()` truthiness test. `PYRXD_NETWORK=REGTEST` therefore:
#   * missed the lowercase `[networks.regtest]` table;
#   * compared EQUAL in `network == cfg.network` (both sides the same env
#     string), so the top-level MAINNET server list was inherited;
#   * produced `genesis_hash_for("REGTEST") is None`, which made the failover
#     client skip `assert_chain` entirely.
# A run the operator believed was regtest broadcast to mainnet with the chain
# check disabled. `--network REGTEST` was safe only because click.Choice
# lowercases it first.

_MIXED_CASE_CONFIG = (
    'network = "mainnet"\n'
    'electrumx_servers = ["wss://mainnet.example:50022/"]\n'
    "[networks.regtest]\n"
    'electrumx = "ws://127.0.0.1:50010/"\n'
    "allow_insecure = true\n"
)


@pytest.mark.parametrize("spelling", ["REGTEST", "Regtest", " regtest ", "regTEST"])
def test_a_mixed_case_network_never_inherits_the_mainnet_endpoint(tmp_path: Path, monkeypatch, spelling: str) -> None:
    """THE regression test. Measured before the fix with ``PYRXD_NETWORK=REGTEST``:
    resolved endpoints were ``("wss://mainnet.example:50022/",)`` — the top-level
    MAINNET list — on a run reported as regtest."""
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(_MIXED_CASE_CONFIG)
    monkeypatch.setenv("PYRXD_NETWORK", spelling)

    cfg = _config.load(cfg_file)
    assert cfg.network == "regtest"

    out = cfg.for_network(cfg.network)
    assert out.network == "regtest"
    assert out.endpoints == ("ws://127.0.0.1:50010/",)
    assert "wss://mainnet.example:50022/" not in out.endpoints


@pytest.mark.parametrize("spelling", ["REGTEST", "Regtest", " regtest "])
def test_a_mixed_case_network_still_resolves_a_genesis_hash(tmp_path: Path, monkeypatch, spelling: str) -> None:
    """`genesis_hash is None` is what silently disabled `assert_chain`."""
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(_MIXED_CASE_CONFIG)
    monkeypatch.setenv("PYRXD_NETWORK", spelling)
    profile = _config.load(cfg_file).for_network("regtest").require_profile()
    assert profile.genesis_hash == GENESIS_BLOCK_HASHES["regtest"]


@pytest.mark.parametrize("bad", ["mainet", "main net", "REGTEST-2", "bitcoin", "   "])
def test_an_unknown_network_is_refused_at_load(tmp_path: Path, monkeypatch, bad: str) -> None:
    """Fail CLOSED: a typo must not land on the 'pyrxd has no genesis constant for
    this chain, so skip the check' path."""
    monkeypatch.setenv("PYRXD_NETWORK", bad)
    with pytest.raises(ValidationError):
        _config.load(tmp_path / "absent.toml")


def test_an_empty_PYRXD_NETWORK_means_unset_not_invalid(tmp_path: Path, monkeypatch) -> None:
    """``PYRXD_NETWORK=`` is the shell's way of clearing a variable, so it falls
    through to the file/default — which is itself validated. Whitespace-only is
    NOT the same thing and is refused (see above)."""
    monkeypatch.setenv("PYRXD_NETWORK", "")
    assert _config.load(tmp_path / "absent.toml").network == "mainnet"


@pytest.mark.parametrize("bad", ["mainet", "REGTEST-2", "bitcoin"])
def test_an_unknown_network_is_refused_by_for_network_too(tmp_path: Path, monkeypatch, bad: str) -> None:
    """`for_network` is what the CLI always calls, and a library caller can build a
    Config without going through `load` at all."""
    monkeypatch.delenv("PYRXD_NETWORK", raising=False)
    cfg = _config.load(tmp_path / "absent.toml")
    with pytest.raises(ValidationError, match="unknown network"):
        cfg.for_network(bad)


def test_the_unknown_network_error_lists_the_known_ones(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PYRXD_NETWORK", "mainet")
    with pytest.raises(ValidationError) as exc:
        _config.load(tmp_path / "absent.toml")
    rendered = str(exc.value)
    assert "PYRXD_NETWORK" in rendered
    for known in KNOWN_NETWORKS:
        assert known in rendered


def test_a_mixed_case_network_in_the_file_is_normalized(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PYRXD_NETWORK", raising=False)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "MainNet"\n')
    assert _config.load(cfg_file).network == "mainnet"


def test_an_unknown_network_in_the_file_names_the_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PYRXD_NETWORK", raising=False)
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "mainet"\n')
    with pytest.raises(ValidationError, match=str(cfg_file)):
        _config.load(cfg_file)


# ---------------------------------------------------------------------------
# The HIGH end of the band (#457). The CLI used to accept any rate at or above the
# floor, documented as "overpaying is the operator's prerogative", while the SDK has
# refused above MAX_FEE_OVERPAY_MULTIPLE x floor since #456. The CLI was therefore the
# LOOSER guard over the population more likely to make a unit slip: a human pasting a
# per-kB figure from a fee table into a per-BYTE flag.
# ---------------------------------------------------------------------------


def _floor_and_ceiling() -> tuple[int, int]:
    from pyrxd.fee_sizing import MAX_FEE_OVERPAY_MULTIPLE, relay_floor_photons_per_byte

    floor = relay_floor_photons_per_byte()
    return floor, floor * MAX_FEE_OVERPAY_MULTIPLE


def test_a_fee_rate_above_the_overpay_ceiling_is_refused(monkeypatch) -> None:
    """The exact slip this catches: the per-kB constant handed to a per-byte field.

    ``RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB`` is 10_000_000 and the per-byte floor
    is 10_000 — one is the other times 1000, and they are exported from the same module
    one import apart. Passing the first where the second belongs is a 1000x overpay that
    on Radiant cannot be recovered: no RBF, no CPFP, and ``wallet sweep`` has no change
    output, so the whole difference leaves with the miner.
    """
    from pyrxd.gravity.fee_policy import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

    monkeypatch.setenv("PYRXD_FEE_RATE", str(RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB))
    with pytest.raises(ValidationError, match="above the .*ceiling"):
        load()


def test_the_ceiling_is_judged_at_the_boundary_not_near_it(monkeypatch) -> None:
    """At the ceiling is accepted; one photon over is refused.

    Pinned because the error renders the multiple to one decimal specifically so the
    smallest refused rate does not report "is 10x ... above the 10x ceiling" — a message
    that reads as self-contradictory exactly where a caller is most likely to be standing.
    """
    _floor, ceiling = _floor_and_ceiling()

    monkeypatch.setenv("PYRXD_FEE_RATE", str(ceiling))
    assert load().fee_rate == ceiling

    monkeypatch.setenv("PYRXD_FEE_RATE", str(ceiling + 1))
    with pytest.raises(ValidationError) as exc:
        load()
    assert "10.0x" in str(exc.value), "the multiple must not floor-divide to a self-contradiction"


def test_the_ceiling_error_names_where_the_value_came_from(tmp_path, monkeypatch) -> None:
    """Same pointer the floor error gives. The source-naming block used to live inside
    the sub-floor branch; a ceiling that could not name the file would send an operator
    hunting for a value they cannot see."""
    _floor, ceiling = _floor_and_ceiling()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'network = "mainnet"\nfee_rate = {ceiling * 10}\n')
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    with pytest.raises(ValidationError, match=str(cfg)):
        _config.load(cfg)


def test_a_per_network_ceiling_breach_names_the_table(tmp_path, monkeypatch) -> None:
    """The per-network table is resolved by ``for_network``, not by ``load`` — so the
    ceiling has to be enforced there too, exactly as the floor is. This mirrors
    ``test_a_per_network_fee_rate_below_the_floor_is_refused``, which is the regression
    test for the bypass where a ``[networks.<net>]`` key skipped a guard the top-level
    key was subject to."""
    _floor, ceiling = _floor_and_ceiling()
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'network = "regtest"\n\n[networks.regtest]\nfee_rate = {ceiling * 10}\n')
    monkeypatch.delenv("PYRXD_FEE_RATE", raising=False)
    loaded = _config.load(cfg)
    with pytest.raises(ValidationError, match=r"\[networks\.regtest\]"):
        loaded.for_network("regtest")


def test_allow_overpay_is_the_way_through_and_only_for_the_ceiling() -> None:
    """The opt-out must skip its OWN bound and nothing else.

    An ``allow_overpay`` that also waived the floor would let the CLI emit a
    transaction the network will not relay — the opposite failure, and one that cannot
    be fee-bumped on Radiant.
    """
    from pyrxd.cli.config import validated_fee_rate

    floor, ceiling = _floor_and_ceiling()

    assert validated_fee_rate(ceiling * 100, None, allow_overpay=True) == ceiling * 100
    with pytest.raises(ValidationError, match="below Radiant's effective relay floor"):
        validated_fee_rate(floor - 1, None, allow_overpay=True)


def test_an_ordinary_rate_still_loads_untouched(monkeypatch) -> None:
    """The honest path. A guard that refuses valid work is a bug, and every rate an
    operator actually uses sits inside the band."""
    floor, ceiling = _floor_and_ceiling()

    for ok in (floor, floor * 2, floor * 9, ceiling):
        monkeypatch.setenv("PYRXD_FEE_RATE", str(ok))
        assert load().fee_rate == ok

"""Config loader: defaults, file, env-var precedence, and network binding."""

from __future__ import annotations

from pathlib import Path

import pytest

from pyrxd.cli import config as _config
from pyrxd.cli.config import load
from pyrxd.cli.context import CliContext
from pyrxd.cli.errors import UserError
from pyrxd.network.registry import DEFAULT_ENDPOINTS, GENESIS_BLOCK_HASHES
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
        "fee_rate = 1\n"
    )
    cfg = _config.load(cfg_file)
    test_cfg = cfg.for_network("testnet")
    assert test_cfg.electrumx == "wss://test/"
    assert test_cfg.fee_rate == 1
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
    cfg_file.write_text('network = "mainnet"\ncoin_type = 0\n[networks.testnet]\nfee_rate = 1\n')
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

    # At the floor, and above it, are both fine — overpaying is the operator's call.
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

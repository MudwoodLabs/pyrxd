"""Config loader: defaults, file, env-var precedence."""

from __future__ import annotations

from pathlib import Path

import pytest

from pyrxd.cli import config as _config


def test_defaults_when_no_file(tmp_path: Path) -> None:
    cfg = _config.load(tmp_path / "absent.toml")
    assert cfg.network == "mainnet"
    assert cfg.fee_rate == 10_000
    assert cfg.source_path is None


def test_file_overrides_defaults(tmp_path: Path) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text(
        f'network = "testnet"\nelectrumx = "wss://custom/"\nfee_rate = 5000\nwallet_path = "{tmp_path / "w.dat"}"\n'
    )
    cfg = _config.load(cfg_file)
    assert cfg.network == "testnet"
    assert cfg.electrumx == "wss://custom/"
    assert cfg.fee_rate == 5000
    assert cfg.source_path == cfg_file


def test_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('network = "testnet"\nfee_rate = 5000\n')
    monkeypatch.setenv("PYRXD_NETWORK", "regtest")
    monkeypatch.setenv("PYRXD_FEE_RATE", "1234")
    cfg = _config.load(cfg_file)
    assert cfg.network == "regtest"
    assert cfg.fee_rate == 1234


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


def test_for_network_with_unknown_returns_base(tmp_path: Path) -> None:
    cfg = _config.load(tmp_path / "missing.toml")
    out = cfg.for_network("regtest")
    assert out.network == "regtest"
    assert out.electrumx == cfg.electrumx  # falls through to base


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

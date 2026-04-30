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

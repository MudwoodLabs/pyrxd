"""Config file at ~/.pyrxd/config.toml.

Precedence (highest wins): CLI flags > env vars (PYRXD_*) > config file >
built-in defaults.

Schema:

  network = "mainnet"               # mainnet | testnet | regtest
  electrumx = "wss://..."
  fee_rate = 10000                  # photons per byte
  wallet_path = "~/.pyrxd/wallet.dat"

  [networks.testnet]
  electrumx = "wss://..."
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomllib

DEFAULT_CONFIG_DIR = Path.home() / ".pyrxd"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"
DEFAULT_WALLET_PATH = DEFAULT_CONFIG_DIR / "wallet.dat"

# Built-in defaults — used if config file is missing.
_DEFAULTS: dict[str, Any] = {
    "network": "mainnet",
    "electrumx": "wss://electrumx.radiant4people.com:50022/",
    "fee_rate": 10_000,
    "wallet_path": str(DEFAULT_WALLET_PATH),
}


@dataclass
class Config:
    """Resolved configuration. Built by merging defaults + file + env."""

    network: str = "mainnet"
    electrumx: str = _DEFAULTS["electrumx"]
    fee_rate: int = 10_000
    wallet_path: Path = field(default_factory=lambda: DEFAULT_WALLET_PATH)
    networks: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_path: Path | None = None  # which file (if any) was read

    def for_network(self, network: str) -> Config:
        """Return a copy with per-network overrides applied for *network*."""
        if network not in self.networks:
            return Config(
                network=network,
                electrumx=self.electrumx,
                fee_rate=self.fee_rate,
                wallet_path=self.wallet_path,
                networks=self.networks,
                source_path=self.source_path,
            )
        overrides = self.networks[network]
        return Config(
            network=network,
            electrumx=overrides.get("electrumx", self.electrumx),
            fee_rate=int(overrides.get("fee_rate", self.fee_rate)),
            wallet_path=Path(overrides.get("wallet_path", self.wallet_path)).expanduser(),
            networks=self.networks,
            source_path=self.source_path,
        )


def load(path: Path | None = None) -> Config:
    """Load config from *path* (default ~/.pyrxd/config.toml).

    Returns a Config with defaults applied if the file is missing. Env
    vars (PYRXD_NETWORK, PYRXD_ELECTRUMX, PYRXD_FEE_RATE,
    PYRXD_WALLET_PATH) override file values.
    """
    target = path or DEFAULT_CONFIG_PATH
    file_data: dict[str, Any] = {}
    source_path: Path | None = None

    if target.exists():
        with target.open("rb") as f:
            file_data = tomllib.load(f)
        source_path = target

    network = os.environ.get("PYRXD_NETWORK") or file_data.get("network") or _DEFAULTS["network"]
    electrumx = os.environ.get("PYRXD_ELECTRUMX") or file_data.get("electrumx") or _DEFAULTS["electrumx"]
    fee_rate_raw = os.environ.get("PYRXD_FEE_RATE") or file_data.get("fee_rate") or _DEFAULTS["fee_rate"]
    wallet_path = os.environ.get("PYRXD_WALLET_PATH") or file_data.get("wallet_path") or _DEFAULTS["wallet_path"]

    networks = file_data.get("networks", {})
    if not isinstance(networks, dict):
        networks = {}

    return Config(
        network=str(network),
        electrumx=str(electrumx),
        fee_rate=int(fee_rate_raw),
        wallet_path=Path(str(wallet_path)).expanduser(),
        networks=networks,
        source_path=source_path,
    )


def write_default(path: Path | None = None) -> Path:
    """Write the built-in defaults to *path*. Used by ``pyrxd setup``.

    Creates ``~/.pyrxd/`` with mode 0700 and writes the file with mode
    0600 (parent permissions matter because wallet.dat sits alongside).
    Returns the resolved path.
    """
    target = path or DEFAULT_CONFIG_PATH
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = (
        f'network = "{_DEFAULTS["network"]}"\n'
        f'electrumx = "{_DEFAULTS["electrumx"]}"\n'
        f"fee_rate = {_DEFAULTS['fee_rate']}\n"
        f'wallet_path = "{_DEFAULTS["wallet_path"]}"\n'
    )
    target.write_text(body)
    target.chmod(0o600)
    return target

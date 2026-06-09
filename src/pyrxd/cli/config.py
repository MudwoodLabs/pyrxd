"""Config file at ~/.pyrxd/config.toml.

Precedence (highest wins): CLI flags > env vars (PYRXD_*) > config file >
built-in defaults.

Schema:

  network = "mainnet"               # mainnet | testnet | regtest
  electrumx = "wss://..."
  fee_rate = 10000                  # photons per byte
  wallet_path = "~/.pyrxd/wallet.dat"
  coin_type = 512                   # SLIP-0044 coin type for `wallet new` derivation

  [networks.testnet]
  electrumx = "wss://..."
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..security.errors import ValidationError

# tomllib landed in Python 3.11. pyproject.toml declares ``requires-python = ">=3.10"``
# so 3.10 users must fall back to the ``tomli`` backport (it ships the same
# API as ``tomllib`` and is what CPython itself adopted upstream).
try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover — only fires on Python 3.10
    import tomli as tomllib  # type: ignore[import-not-found, no-redef]

DEFAULT_CONFIG_DIR = Path.home() / ".pyrxd"
DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"
DEFAULT_WALLET_PATH = DEFAULT_CONFIG_DIR / "wallet.dat"

# Built-in defaults — used if config file is missing.
_DEFAULTS: dict[str, Any] = {
    "network": "mainnet",
    "electrumx": "wss://electrumx.radiant4people.com:50022/",
    "fee_rate": 10_000,
    "wallet_path": str(DEFAULT_WALLET_PATH),
    # SLIP-0044 coin type used when `wallet new` derives a fresh wallet.
    # 512 = Radiant Standard (SLIP-0044). `setup --coin-type` writes this.
    "coin_type": 512,
}


@dataclass
class Config:
    """Resolved configuration. Built by merging defaults + file + env."""

    network: str = "mainnet"
    electrumx: str = _DEFAULTS["electrumx"]
    fee_rate: int = 10_000
    wallet_path: Path = field(default_factory=lambda: DEFAULT_WALLET_PATH)
    coin_type: int = 512
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
                coin_type=self.coin_type,
                networks=self.networks,
                source_path=self.source_path,
            )
        overrides = self.networks[network]
        return Config(
            network=network,
            electrumx=overrides.get("electrumx", self.electrumx),
            fee_rate=int(overrides.get("fee_rate", self.fee_rate)),
            wallet_path=Path(overrides.get("wallet_path", self.wallet_path)).expanduser(),
            coin_type=int(overrides.get("coin_type", self.coin_type)),
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
            try:
                file_data = tomllib.load(f)
            except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
                # A malformed config file is a user/operator error, not a bug.
                # Surface it as ValidationError so callers (and the CLI
                # boundary) get a clean, typed failure instead of a raw
                # traceback. UnicodeDecodeError fires when the file isn't
                # valid UTF-8 (tomllib decodes the bytes before parsing).
                raise ValidationError(f"config file at {target} is not valid TOML: {exc}") from exc
        source_path = target

    network = os.environ.get("PYRXD_NETWORK") or file_data.get("network") or _DEFAULTS["network"]
    electrumx = os.environ.get("PYRXD_ELECTRUMX") or file_data.get("electrumx") or _DEFAULTS["electrumx"]
    fee_rate_raw = os.environ.get("PYRXD_FEE_RATE") or file_data.get("fee_rate") or _DEFAULTS["fee_rate"]
    wallet_path = os.environ.get("PYRXD_WALLET_PATH") or file_data.get("wallet_path") or _DEFAULTS["wallet_path"]
    # ``or`` short-circuits on a falsy 0 — coin_type 0 (legacy Bitcoin-compatible)
    # is a valid value, so fall through explicitly instead of treating 0 as unset.
    coin_type_raw = os.environ.get("PYRXD_COIN_TYPE")
    if coin_type_raw is None:
        coin_type_raw = file_data.get("coin_type", _DEFAULTS["coin_type"])

    networks = file_data.get("networks", {})
    if not isinstance(networks, dict):
        networks = {}

    return Config(
        network=str(network),
        electrumx=str(electrumx),
        fee_rate=_as_int(fee_rate_raw, "fee_rate"),
        wallet_path=Path(str(wallet_path)).expanduser(),
        coin_type=_as_int(coin_type_raw, "coin_type"),
        networks=networks,
        source_path=source_path,
    )


def _as_int(value: Any, key: str) -> int:
    """Coerce a config/env value to int, raising ValidationError on garbage.

    A non-numeric ``fee_rate``/``coin_type`` (e.g. a string, list, or table
    in the TOML, or a bad ``PYRXD_*`` env var) must fail as a typed,
    user-facing error — not leak a raw ``ValueError``/``TypeError`` from
    ``int()`` past the config boundary.
    """
    try:
        return int(value)
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"config value for {key!r} is not an integer: {value!r}") from exc


def write_default(path: Path | None = None, *, coin_type: int | None = None) -> Path:
    """Write the built-in defaults to *path*. Used by ``pyrxd setup``.

    Creates ``~/.pyrxd/`` with mode 0700 and writes the file with mode
    0600 (parent permissions matter because wallet.dat sits alongside).
    *coin_type* overrides the SLIP-0044 coin type written for the
    ``wallet new`` derivation path (default 512). Returns the resolved
    path.
    """
    target = path or DEFAULT_CONFIG_PATH
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_coin_type = _DEFAULTS["coin_type"] if coin_type is None else coin_type
    body = (
        f'network = "{_DEFAULTS["network"]}"\n'
        f'electrumx = "{_DEFAULTS["electrumx"]}"\n'
        f"fee_rate = {_DEFAULTS['fee_rate']}\n"
        f'wallet_path = "{_DEFAULTS["wallet_path"]}"\n'
        f"coin_type = {resolved_coin_type}\n"
    )
    target.write_text(body)
    target.chmod(0o600)
    return target


def set_coin_type(coin_type: int, path: Path | None = None) -> Path:
    """Persist *coin_type* into the config at *path*, preserving other keys.

    Used by ``pyrxd setup --coin-type``. If the file does not exist it is
    created from the built-in defaults with the chosen coin type. If it
    exists, only the ``coin_type`` key is updated (other lines are kept
    verbatim so hand-edits survive). Returns the resolved path.
    """
    target = path or DEFAULT_CONFIG_PATH
    if not target.exists():
        return write_default(target, coin_type=coin_type)

    lines = target.read_text().splitlines()
    out: list[str] = []
    replaced = False
    for line in lines:
        if line.lstrip().startswith("coin_type") and "=" in line.split("#", 1)[0]:
            out.append(f"coin_type = {coin_type}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"coin_type = {coin_type}")
    target.write_text("\n".join(out) + "\n")
    target.chmod(0o600)
    return target

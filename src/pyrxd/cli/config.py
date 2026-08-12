"""Config file at ~/.pyrxd/config.toml.

Precedence (highest wins): CLI flags > env vars (PYRXD_*) > config file >
built-in per-network defaults.

Schema:

  network = "mainnet"               # mainnet | testnet | regtest
  electrumx = "wss://..."           # single server (legacy form)
  electrumx_servers = [             # ordered failover list; wins over `electrumx`
    "wss://...", "wss://...",
  ]
  allow_insecure = false            # permit ws:// (local regtest indexer only)
  spki_pins = ["sha256/BASE64="]    # opt-in TLS pinning; see pyrxd.network.tls_pin
  fee_rate = 10000                  # photons per byte
  wallet_path = "~/.pyrxd/wallet.dat"
  coin_type = 512                   # SLIP-0044 coin type for `wallet new` derivation

  [networks.testnet]
  electrumx = "wss://..."

Network binding — why the top-level endpoint does NOT follow ``--network``
--------------------------------------------------------------------------
The top-level ``electrumx`` / ``electrumx_servers`` belongs to the top-level
``network``, and to nothing else. It used to be carried across: with the stock
config (``network = "mainnet"``), ``pyrxd --network regtest`` reported itself as
regtest while pointing at the **mainnet** ElectrumX server, so a developer
"testing on regtest" could broadcast a real transaction to mainnet.

Now :meth:`Config.for_network` resolves an endpoint for network *N* from, in
order:

1. an explicit CLI ``--electrumx`` override (the operator named it for *this*
   invocation, so it is authoritative);
2. ``[networks.N].electrumx_servers`` / ``[networks.N].electrumx``;
3. the top-level endpoint **only when N is the config's own ``network``**;
4. pyrxd's shipped defaults for N (:data:`pyrxd.network.registry.DEFAULT_ENDPOINTS`)
   — which are empty for testnet and regtest, on purpose.

If none of those produce an endpoint, the resolved config carries an
``endpoint_error`` naming exactly what to add, and every attempt to build a
client raises it. It fails *closed*: the wrong-network endpoint is unreachable
rather than silently used.

The failure is deferred to client construction rather than raised during config
load so that the many offline commands (``wallet new``, ``swap build-refund``,
``--help``, ``setup``) still work on a machine that has no endpoint for the
selected network. Nothing that touches the network can proceed.

Endpoints are additionally verified against the chain they claim to serve — see
:meth:`pyrxd.network.electrumx.ElectrumXClient.assert_chain`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..fee_sizing import relay_floor_photons_per_byte
from ..gravity.fee_policy import RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB
from ..network.registry import (
    DEFAULT_ENDPOINTS,
    KNOWN_NETWORKS,
    NetworkProfile,
    default_endpoints,
    genesis_hash_for,
)
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

# The CLI's default fee rate, in photons per BYTE. DERIVED from the one definition
# of Radiant's effective relay floor, not written out — and this file is why that
# matters: :func:`validated_fee_rate` below REJECTS any rate under the floor, and it
# reads the floor from :mod:`pyrxd.fee_sizing`. The default it validates was a
# separate literal ``10_000``, so the value and the rule that judges it were derived
# independently, ~270 lines apart, and agreed only by coincidence.
#
# Both directions of a floor change were broken by that:
#
# * floor UP — ``load()`` starts raising ``ValidationError`` on a machine with no
#   config file at all, because pyrxd's own default is now sub-floor. Every CLI
#   command fails, and ``setup`` writes a config the loader then rejects.
# * ``Config()`` / ``CliContext()`` constructed directly do NOT pass through
#   ``validated_fee_rate`` — they take the dataclass default. A stale literal there
#   is a silent sub-floor build, and Radiant has neither RBF nor CPFP, so the
#   transaction cannot be bumped; it holds its inputs until mempool expiry.
#
# The floor has already moved once (the 2.0 activation raised it 10x), so this is a
# change that has happened, not one that might.
DEFAULT_FEE_RATE_PHOTONS_PER_BYTE: int = relay_floor_photons_per_byte()

# Built-in defaults — used if config file is missing.
#
# NOTE there is deliberately no "electrumx" key here any more. A single default
# endpoint is necessarily a *mainnet* endpoint, and a mainnet endpoint sitting in
# a network-agnostic default is precisely how `--network regtest` ended up on
# mainnet. Endpoints now come from the per-network registry instead.
_DEFAULTS: dict[str, Any] = {
    "network": "mainnet",
    "fee_rate": DEFAULT_FEE_RATE_PHOTONS_PER_BYTE,
    "wallet_path": str(DEFAULT_WALLET_PATH),
    # SLIP-0044 coin type used when `wallet new` derives a fresh wallet.
    # 512 = Radiant Standard (SLIP-0044). `setup --coin-type` writes this.
    "coin_type": 512,
}


@dataclass(frozen=True)
class EndpointGap:
    """Why no ElectrumX endpoint resolved for a network, and exactly what to add.

    Structured rather than a bare string so the CLI boundary can render it in the
    house ``message / cause / fix`` shape while programmatic callers still get one
    combined message from ``str()``.
    """

    network: str
    source_path: Path | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.network, str) or not self.network.strip():
            raise ValidationError("EndpointGap requires a non-empty network name")
        if self.source_path is not None and not isinstance(self.source_path, Path):
            raise ValidationError("EndpointGap source_path must be a Path or None")

    @property
    def config_path(self) -> str:
        return str(self.source_path) if self.source_path is not None else str(DEFAULT_CONFIG_PATH)

    @property
    def message(self) -> str:
        return f"no ElectrumX endpoint is configured for network {self.network!r}"

    @property
    def cause(self) -> str:
        shipped = ", ".join(sorted(n for n, urls in DEFAULT_ENDPOINTS.items() if urls)) or "none"
        return (
            f"pyrxd ships no default {self.network} server (shipped defaults exist for: {shipped}), "
            "and it will not fall back to another network's endpoint — that is exactly how a "
            f"{self.network} command ends up talking to mainnet"
        )

    @property
    def fix(self) -> str:
        example = f"wss://your-{self.network}-server:50022/"
        return (
            f'add [networks.{self.network}] with electrumx = "{example}" to {self.config_path}, '
            f"or pass --electrumx {example} (or set PYRXD_ELECTRUMX) for a one-off run"
        )

    def __str__(self) -> str:
        return f"{self.message}: {self.cause}. Fix: {self.fix}"


@dataclass
class Config:
    """Resolved configuration. Built by merging defaults + file + env.

    ``electrumx`` / ``electrumx_servers`` on a freshly :func:`load`-ed instance are
    the values *as configured* — they are bound to ``network`` and are empty when
    nothing was configured. Call :meth:`for_network` to get the instance a command
    should actually use; that is where per-network resolution and the fail-closed
    behaviour live.
    """

    network: str = "mainnet"
    electrumx: str = ""
    electrumx_servers: tuple[str, ...] = ()
    allow_insecure: bool = False
    spki_pins: tuple[str, ...] = ()
    fee_rate: int = DEFAULT_FEE_RATE_PHOTONS_PER_BYTE
    wallet_path: Path = field(default_factory=lambda: DEFAULT_WALLET_PATH)
    coin_type: int = 512
    networks: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_path: Path | None = None  # which file (if any) was read
    #: Set by :meth:`for_network` when no endpoint could be resolved for the
    #: selected network. Non-``None`` means "any network call must fail with this".
    endpoint_gap: EndpointGap | None = None

    @property
    def endpoint_error(self) -> str | None:
        """One-line rendering of :attr:`endpoint_gap`, or ``None`` when resolved."""
        return None if self.endpoint_gap is None else str(self.endpoint_gap)

    @property
    def endpoints(self) -> tuple[str, ...]:
        """Resolved endpoint list in preference order (empty when unresolved)."""
        if self.electrumx_servers:
            return self.electrumx_servers
        return (self.electrumx,) if self.electrumx else ()

    def for_network(self, network: str, *, electrumx_override: str | None = None) -> Config:
        """Return a copy resolved for *network*.

        *electrumx_override* is the ``--electrumx`` flag (or any caller-supplied
        endpoint): it wins over everything, because naming an endpoint alongside
        ``--network`` is an explicit statement about which server serves that
        network.

        Never falls back to another network's endpoint. When nothing resolves, the
        returned config has empty endpoints and a populated ``endpoint_error``;
        :meth:`require_profile` turns that into a typed failure at the point a
        client would be built.

        *network* is normalized and checked against
        :data:`~pyrxd.network.registry.KNOWN_NETWORKS` here as well as in
        :func:`load`, because this is the method the CLI always routes through
        (``--network`` lands here directly) and a library caller can construct a
        :class:`Config` without going through ``load`` at all.
        """
        network = _validated_network(network, self.source_path, source="argument")
        overrides = self.networks.get(network, {})
        if not isinstance(overrides, dict):
            overrides = {}

        servers = _resolve_servers(self, network, overrides, electrumx_override)
        # Top-level `allow_insecure` / `spki_pins` are bound to the top-level
        # network for the same reason the endpoint is: they describe how to talk to
        # THAT server, and inheriting them across networks would silently relax (or
        # misapply) a trust decision.
        own_network = network == self.network
        allow_insecure = bool(overrides.get("allow_insecure", self.allow_insecure if own_network else False))
        spki_pins = _as_str_tuple(
            overrides.get("spki_pins", self.spki_pins if own_network else ()),
            "spki_pins",
        )

        return replace(
            self,
            network=network,
            electrumx=servers[0] if servers else "",
            electrumx_servers=servers,
            allow_insecure=allow_insecure,
            spki_pins=spki_pins,
            # The per-network fee_rate goes through the SAME relay-floor guard as the
            # top-level one. It used to bypass it entirely — and since the CLI always
            # routes through `for_network`, `[networks.<net>] fee_rate = 100` produced
            # a config 100x under the floor that `load()` would have rejected outright.
            fee_rate=_network_fee_rate(self, network, overrides),
            wallet_path=Path(str(overrides.get("wallet_path", self.wallet_path))).expanduser(),
            coin_type=_as_int(overrides.get("coin_type", self.coin_type), f"networks.{network}.coin_type"),
            endpoint_gap=None if servers else EndpointGap(network, self.source_path),
        )

    def require_profile(self) -> NetworkProfile:
        """Return the :class:`NetworkProfile` for this config, or raise.

        Raises:
            ValidationError: when no endpoint resolved for the selected network.
                The message names the network and the exact TOML to add — this is
                the fail-closed half of the network-binding fix.
        """
        gap = self.endpoint_gap or (None if self.endpoints else EndpointGap(self.network, self.source_path))
        if gap is not None:
            raise ValidationError(str(gap))
        return NetworkProfile.build(
            self.network,
            self.endpoints,
            allow_insecure=self.allow_insecure,
            spki_pins=self.spki_pins,
            genesis_hash=genesis_hash_for(self.network),
        )


def _resolve_servers(
    cfg: Config,
    network: str,
    overrides: dict[str, Any],
    electrumx_override: str | None,
) -> tuple[str, ...]:
    """Endpoint resolution order for *network*. See the module docstring."""
    if electrumx_override:
        return (str(electrumx_override),)
    if overrides.get("electrumx_servers"):
        return _as_str_tuple(overrides["electrumx_servers"], f"networks.{network}.electrumx_servers")
    if overrides.get("electrumx"):
        return (str(overrides["electrumx"]),)
    # The top-level endpoint belongs to the top-level network ONLY. This single
    # condition is the network-binding fix.
    if network == cfg.network and cfg.endpoints:
        return cfg.endpoints
    return tuple(default_endpoints(network))


def _validated_network(value: Any, source_path: Path | None, *, source: str) -> str:
    """Normalize a network name and reject anything outside :data:`KNOWN_NETWORKS`.

    Fund-safety, not tidiness. The name used to be taken verbatim, with the only
    check being a ``strip()`` truthiness test. ``PYRXD_NETWORK=REGTEST`` therefore
    produced a config whose network was the literal string ``"REGTEST"``, and:

    * ``[networks.regtest]`` never matched, so the per-network block was ignored;
    * ``network == cfg.network`` compared *equal* (both sides were the same env
      string), so the **top-level mainnet server list was inherited**;
    * :func:`~pyrxd.network.registry.genesis_hash_for` returned ``None``, so the
      chain-binding check was skipped entirely.

    A run the operator believed was regtest talked to mainnet with the one check
    that would have caught it disabled. ``--network REGTEST`` was safe only by
    accident, because ``click.Choice`` lowercases it first.

    Normalizing (``strip().lower()``) fixes the mismatch; rejecting an unknown name
    is what makes it fail *closed* — a typo can no longer land on the "pyrxd has no
    constant for this chain, so don't verify it" path.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"network ({source}) must be a non-empty string")
    network = value.strip().lower()
    if network not in KNOWN_NETWORKS:
        known = ", ".join(KNOWN_NETWORKS)
        if source == "env":
            where = "the PYRXD_NETWORK environment variable"
        elif source == "argument":
            where = "the requested network"
        elif source_path is not None:
            where = f"the network key in {source_path}"
        else:
            where = "the network key"
        raise ValidationError(
            f"unknown network {network!r} in {where}. Known networks: {known}. "
            "pyrxd refuses an unrecognised name rather than guessing: it has no genesis "
            "hash for one, so the endpoint's chain could not be verified, and the name "
            "would not match any [networks.<name>] table either."
        )
    return network


def _network_fee_rate(cfg: Config, network: str, overrides: dict[str, Any]) -> int:
    """Fee rate for *network*: the ``[networks.<net>]`` override, floor-checked."""
    if "fee_rate" not in overrides:
        # Already validated by `load()` on the way in.
        return cfg.fee_rate
    return validated_fee_rate(
        _as_int(overrides["fee_rate"], f"networks.{network}.fee_rate"),
        cfg.source_path,
        table=f"networks.{network}",
    )


def validated_fee_rate(
    rate: int,
    source_path: Path | None,
    *,
    from_env: bool = False,
    table: str | None = None,
) -> int:
    """Reject a fee rate below Radiant's effective relay floor.

    Fund-safety, not tidiness. ``fee_rate`` is photons per BYTE; the chain's
    effective floor is :data:`RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB` per kB.
    A rate under that produces transactions the node will not relay — and Radiant
    has **neither RBF nor CPFP** (threat-model S21), so such a transaction cannot
    be bumped by any means and squats on its own inputs until mempool expiry (8h).
    On a time-critical spend that is a total loss.

    The default sits exactly at the floor, so this only ever fires on a deliberate
    override via ``PYRXD_FEE_RATE``, the top-level ``fee_rate``, or a
    ``[networks.<net>] fee_rate`` — all three of which are checked here.
    ``DeadlineFeePolicy`` already rejects a sub-floor rate for the swap stack; this
    closes the same gap for every other CLI command.

    A HIGHER rate is always allowed: overpaying is the operator's prerogative.

    Args:
        rate: photons per byte.
        source_path: the config file the value came from, if any.
        from_env: the value came from ``PYRXD_FEE_RATE``.
        table: the TOML table the value came from (e.g. ``networks.regtest``),
            when it is not the top-level key.
    """
    # The per-kB -> per-byte conversion is :func:`relay_floor_photons_per_byte`'s job,
    # not a division repeated at each call site: ``fee_for_kb_rate`` rounds UP and this
    # rounds DOWN, so a floor that is not an exact multiple of 1000 makes a hand-written
    # ``// 1000`` disagree with the module that owns the rule by one photon per byte.
    floor_per_byte = relay_floor_photons_per_byte()
    if rate < floor_per_byte:
        # Name the ACTUAL source. An env override with a config file present would
        # otherwise send the operator to edit a file that does not contain the value,
        # and a `[networks.<net>]` override would send them to a top-level key that
        # is not the one in force.
        if from_env:
            where = " (set via the PYRXD_FEE_RATE environment variable)"
        elif table is not None:
            in_file = f" in {source_path}" if source_path is not None else ""
            where = f" (set under [{table}]{in_file})"
        elif source_path is not None:
            where = f" (set in {source_path})"
        else:
            where = ""
        raise ValidationError(
            f"fee_rate={rate} photons/byte is below Radiant's effective relay floor of "
            f"{floor_per_byte} photons/byte ({RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB} per kB)"
            f"{where}. A transaction built at this rate will not relay, and Radiant has no RBF "
            "and no CPFP — it cannot be fee-bumped and will squat on its inputs until mempool "
            "expiry. Raise fee_rate to at least the floor."
        )
    return rate


def load(path: Path | None = None) -> Config:
    """Load config from *path* (default ~/.pyrxd/config.toml).

    Returns a Config with defaults applied if the file is missing. Env
    vars (PYRXD_NETWORK, PYRXD_ELECTRUMX, PYRXD_FEE_RATE,
    PYRXD_WALLET_PATH) override file values.

    The returned instance is NOT yet network-resolved — the endpoint fields hold
    what was configured for its own ``network``. Call :meth:`Config.for_network`.
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

    env_network = os.environ.get("PYRXD_NETWORK")
    network = _validated_network(
        env_network or file_data.get("network") or _DEFAULTS["network"],
        source_path,
        source="env" if env_network else "file",
    )
    # No built-in fallback here: an unset endpoint stays unset and is resolved
    # per-network by `for_network`. See the module docstring.
    electrumx = os.environ.get("PYRXD_ELECTRUMX") or file_data.get("electrumx") or ""
    servers = _as_str_tuple(file_data.get("electrumx_servers", ()), "electrumx_servers")
    if os.environ.get("PYRXD_ELECTRUMX"):
        # An explicit env endpoint replaces the file's list rather than joining it —
        # a one-off override must not silently keep failing over to servers the
        # operator was trying to bypass.
        servers = ()
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
        network=network,
        electrumx=str(electrumx),
        electrumx_servers=servers,
        allow_insecure=bool(file_data.get("allow_insecure", False)),
        spki_pins=_as_str_tuple(file_data.get("spki_pins", ()), "spki_pins"),
        fee_rate=validated_fee_rate(
            _as_int(fee_rate_raw, "fee_rate"),
            source_path,
            from_env=bool(os.environ.get("PYRXD_FEE_RATE")),
        ),
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


def _as_str_tuple(value: Any, key: str) -> tuple[str, ...]:
    """Coerce a TOML array (or single string) of strings to a tuple.

    A bare string is accepted as a one-element list — a plausible hand-edit that
    would otherwise silently iterate character by character.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValidationError(f"config value for {key!r} must be a list of strings")
            if item:
                out.append(item)
        return tuple(out)
    raise ValidationError(f"config value for {key!r} must be a list of strings")


def write_default(path: Path | None = None, *, coin_type: int | None = None) -> Path:
    """Write the built-in defaults to *path*. Used by ``pyrxd setup``.

    Creates ``~/.pyrxd/`` with mode 0700 and writes the file with mode
    0600 (parent permissions matter because wallet.dat sits alongside).
    *coin_type* overrides the SLIP-0044 coin type written for the
    ``wallet new`` derivation path (default 512). Returns the resolved
    path.

    Writes the shipped mainnet servers as ``electrumx_servers`` so a fresh install
    gets failover, and writes them under the ``network`` they belong to.
    """
    target = path or DEFAULT_CONFIG_PATH
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved_coin_type = _DEFAULTS["coin_type"] if coin_type is None else coin_type
    network = _DEFAULTS["network"]
    servers = ",\n".join(f'    "{url}"' for url in default_endpoints(network))
    body = (
        f'network = "{network}"\n'
        f"electrumx_servers = [\n{servers},\n]\n"
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

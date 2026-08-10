"""CliContext — the dataclass passed to every command.

Carries the resolved network, electrumx URL, fee rate, output mode,
wallet path, and (lazily) the loaded HdWallet. Tests inject this with
mocked ElectrumX clients and tmp_path-backed wallet directories so no
real filesystem or network is touched.

Why a dataclass instead of click's Context.obj convention: explicit
typing, easier to test with `dataclasses.replace`, no runtime click
dependency in non-CLI code paths.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Config
from .errors import UserError

if TYPE_CHECKING:
    from ..network.electrumx import ElectrumXClient
    from ..network.failover import FailoverElectrumXClient


@dataclass
class CliContext:
    """Resolved per-invocation CLI state.

    Constructed by ``cli()`` group from CLI flags + Config + env. Each
    subcommand receives this via the click ``@pass_context`` flow.
    """

    config: Config
    network: str = "mainnet"
    electrumx_url: str = ""
    fee_rate: int = 10_000
    wallet_path: Path = field(default_factory=Path)
    output_mode: str = "human"  # human | json | quiet
    no_color: bool = False
    yes: bool = False  # skip confirmation prompts
    debug: bool = False  # show full tracebacks on error
    # Optional injection point for tests: a callable returning
    # ElectrumXClient. Production code uses the default factory.
    client_factory: Callable[[], ElectrumXClient] | None = None

    def make_client(self) -> FailoverElectrumXClient | ElectrumXClient:
        """Return a network client for the resolved network. Tests swap via client_factory.

        Fails closed when the selected network has no endpoint: rather than
        connecting to whatever endpoint happens to be lying around (historically
        the mainnet default, regardless of ``--network``), this raises the
        config's ``endpoint_error``, which names the exact TOML to add. Every
        network-touching command goes through here, so there is no path that
        reaches a wrong-network server by accident.

        The returned client is a
        :class:`~pyrxd.network.failover.FailoverElectrumXClient`: it verifies each
        endpoint's genesis hash on first use, and retries reads on the next
        endpoint when one is unreachable. With a single configured endpoint it
        degenerates to the previous single-server behaviour.
        """
        if self.client_factory is not None:
            return self.client_factory()
        from ..network.failover import FailoverElectrumXClient

        # `--electrumx` on the command line is already folded into the config by
        # `main.cli()`; electrumx_url is kept as the display/primary value.
        gap = self.config.endpoint_gap
        if gap is not None:
            # CLI-boundary translation of the library-typed ValidationError
            # `require_profile()` would raise — same content, house error shape,
            # documented exit code 1 instead of the "unexpected failure" path.
            raise UserError(gap.message, cause=gap.cause, fix=gap.fix)
        profile = self.config.require_profile()
        return FailoverElectrumXClient(profile)

    def is_destructive_mode_safe(self) -> tuple[bool, str | None]:
        """Return (ok, reason) for whether we may run a destructive op now.

        --json without --yes is rejected for destructive ops (broadcast,
        wallet new with overwrite). Other modes are fine.
        """
        if self.output_mode == "json" and not self.yes:
            return (
                False,
                "--json requires --yes for destructive operations",
            )
        return (True, None)

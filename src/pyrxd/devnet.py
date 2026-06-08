"""One-command local Radiant regtest node for development.

Wraps a ``radiant-core`` regtest node running in docker so a developer can
stand up an isolated chain, mine blocks, and fund an address without learning
the node's RPC surface. This is the dev-facing promotion of the in-test
``_RegtestNode`` helper (``tests/test_htlc_regtest_e2e.py``).

Everything here targets **regtest only** — an ephemeral, throwaway chain bound
to the local docker host. The RPC credentials are deliberately fixed (it is a
localhost-only regtest sandbox reached via ``docker exec``, never exposed), so
separate CLI invocations (`up`, `mine`, `fund`, `down`) reconnect to the same
node with no state file to keep in sync.

Prerequisites: ``docker`` on PATH and the ``radiant-core`` regtest image
present locally (see :data:`RegtestNode.IMAGE`).
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404  # only ever runs a fixed `docker` argv (see call sites)
import time
from dataclasses import dataclass


class DevnetError(RuntimeError):
    """A devnet operation failed (docker missing, node not up, RPC error)."""


@dataclass(frozen=True)
class DevKey:
    """A freshly generated, pre-funded regtest key handed to the developer."""

    address: str
    wif: str
    funded_rxd: float


class RegtestNode:
    """A self-managed, isolated ``radiant-core`` regtest node (docker).

    The node is identified by a fixed container name so that ``up`` /
    ``mine`` / ``fund`` / ``down`` invoked as separate processes all operate on
    the same chain. ``up`` is the only call that creates the container; the
    others attach to the running one and raise :class:`DevnetError` if it is
    absent.
    """

    IMAGE = "radiant-core:v2.3.0-amd64"
    CONTAINER = "pyrxd-devnet"
    RPC_USER = "pyrxd"
    RPC_PASSWORD = "pyrxd"  # nosec B105  # localhost-only regtest sandbox cred (docker exec), not a secret
    WALLET = "devnet"
    _RPC_READY_TIMEOUT_S = 30

    # ----------------------------------------------------------------- docker

    @staticmethod
    def _require_docker() -> None:
        if shutil.which("docker") is None:
            raise DevnetError("docker is not on PATH — install docker to use `pyrxd regtest`")

    def cli(self, *args: str, wallet: bool = False) -> object:
        """Run ``radiant-cli`` inside the container; parse JSON when possible."""
        base = [
            "docker",
            "exec",
            self.CONTAINER,
            "radiant-cli",
            "-regtest",
            f"-rpcuser={self.RPC_USER}",
            f"-rpcpassword={self.RPC_PASSWORD}",
        ]
        if wallet:
            base.append(f"-rpcwallet={self.WALLET}")
        try:
            r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=60)  # nosec B603 B607  # controlled docker argv
        except FileNotFoundError as exc:  # docker vanished mid-run
            raise DevnetError("docker is not on PATH — install docker to use `pyrxd regtest`") from exc
        if r.returncode != 0:
            raise DevnetError(f"radiant-cli {args[0] if args else ''} failed: {r.stderr.strip()}")
        out = r.stdout.strip()
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return out

    def is_running(self) -> bool:
        """True if the devnet container exists and is running."""
        self._require_docker()
        r = subprocess.run(  # nosec B603 B607  # controlled docker argv
            ["docker", "inspect", "-f", "{{.State.Running}}", self.CONTAINER],
            capture_output=True,
            text=True,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"

    # ----------------------------------------------------------------- lifecycle

    def start(self, *, fresh: bool = False, initial_blocks: int = 101) -> None:
        """Start the regtest node, create the dev wallet, and mature a coinbase.

        Idempotent unless ``fresh`` is set: if the container is already running
        it is left untouched (the chain state is preserved). ``fresh=True``
        tears the existing container down first for a clean chain.
        """
        self._require_docker()
        if fresh:
            self.stop()
        elif self.is_running():
            return
        else:
            # A stopped/leftover container of the same name would block `run`.
            subprocess.run(["docker", "rm", "-f", self.CONTAINER], capture_output=True)  # nosec B603 B607  # controlled docker argv

        up = subprocess.run(  # nosec B603 B607  # controlled docker argv
            [
                "docker",
                "run",
                "-d",
                "--name",
                self.CONTAINER,
                "--entrypoint",
                "radiantd",
                self.IMAGE,
                "-regtest",
                "-server",
                "-txindex=1",
                "-disablewallet=0",
                "-fallbackfee=0.001",
                f"-rpcuser={self.RPC_USER}",
                f"-rpcpassword={self.RPC_PASSWORD}",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
            ],
            capture_output=True,
            text=True,
        )
        if up.returncode != 0:
            stderr = up.stderr.strip()
            if "No such image" in stderr or "not found" in stderr:
                raise DevnetError(
                    f"regtest image {self.IMAGE!r} is not present locally — "
                    "build or pull the radiant-core regtest image first"
                )
            raise DevnetError(f"failed to start regtest container: {stderr}")

        self._await_rpc()
        # Safety: never proceed unless this is genuinely a regtest chain.
        chain = self.cli("getblockchaininfo")
        if not isinstance(chain, dict) or chain.get("chain") != "regtest":
            raise DevnetError("node did not come up as regtest — aborting")
        self.cli("createwallet", self.WALLET)
        if initial_blocks:
            self.mine(initial_blocks)

    def _await_rpc(self) -> None:
        """Block until the node answers RPC (any chain). The regtest-only
        guard is enforced by the caller once RPC is up."""
        deadline = time.monotonic() + self._RPC_READY_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                info = self.cli("getblockchaininfo")
                if isinstance(info, dict) and "chain" in info:
                    return
            except DevnetError:
                pass
            time.sleep(0.5)
        raise DevnetError(f"regtest RPC did not become ready within {self._RPC_READY_TIMEOUT_S}s")

    def stop(self) -> None:
        """Remove the devnet container (no-op if absent). Wipes the chain."""
        self._require_docker()
        subprocess.run(["docker", "rm", "-f", self.CONTAINER], capture_output=True)  # nosec B603 B607  # controlled docker argv

    # ----------------------------------------------------------------- chain ops

    def _ensure_running(self) -> None:
        if not self.is_running():
            raise DevnetError("regtest node is not running — start it with `pyrxd regtest up`")

    def new_address(self) -> str:
        """A fresh address from the dev wallet."""
        self._ensure_running()
        return str(self.cli("getnewaddress", wallet=True))

    def mine(self, n: int = 1, address: str | None = None) -> int:
        """Mine ``n`` blocks to ``address`` (a fresh wallet address by default).

        Returns the new chain height.
        """
        self._ensure_running()
        target = address or self.new_address()
        self.cli("generatetoaddress", str(n), target)
        return int(self.cli("getblockcount"))

    def fund(self, address: str, amount_rxd: float, *, confirm: bool = True) -> str:
        """Faucet: send ``amount_rxd`` RXD to ``address`` from the dev wallet.

        Mines one block to confirm the payment unless ``confirm`` is False.
        Returns the funding txid.
        """
        self._ensure_running()
        txid = str(self.cli("sendtoaddress", address, f"{amount_rxd:.8f}", wallet=True))
        if confirm:
            self.mine(1)
        return txid

    def new_funded_key(self, amount_rxd: float = 100.0) -> DevKey:
        """Generate a wallet key, fund it, and return its address + WIF.

        The WIF is directly importable into pyrxd (``PrivateKey(wif)``), giving
        a developer a spendable, pre-funded regtest identity in one step.
        """
        self._ensure_running()
        address = self.new_address()
        wif = str(self.cli("dumpprivkey", address, wallet=True))
        self.fund(address, amount_rxd)
        return DevKey(address=address, wif=wif, funded_rxd=amount_rxd)

    def info(self) -> dict:
        """Connection + chain summary for display."""
        self._ensure_running()
        chain = self.cli("getblockchaininfo")
        height = chain.get("blocks") if isinstance(chain, dict) else None
        return {
            "container": self.CONTAINER,
            "image": self.IMAGE,
            "rpc_user": self.RPC_USER,
            "rpc_password": self.RPC_PASSWORD,
            "wallet": self.WALLET,
            "height": height,
            "exec_prefix": f"docker exec {self.CONTAINER} radiant-cli -regtest "
            f"-rpcuser={self.RPC_USER} -rpcpassword={self.RPC_PASSWORD}",
        }

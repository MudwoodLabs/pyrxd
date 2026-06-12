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
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# The Radiant-Core release the regtest image is built from. Bump this (and rebuild
# via `pyrxd regtest setup`) to track the latest release; see docs/ROADMAP.md and
# the bump plan for the revalidation the version pin carries.
DEFAULT_RADIANT_VERSION = "v3.1.1"

# Embedded copy of docker/regtest.Dockerfile so `pyrxd regtest setup` works for a
# `pip install pyrxd` developer who has no repo checkout. A test
# (tests/test_devnet.py) asserts this stays byte-identical to the committed file.
_REGTEST_DOCKERFILE = """\
# Regtest Radiant-Core node for local pyrxd development (`pyrxd regtest`).
#
# Wraps an OFFICIAL Radiant-Core release binary — we do not fork, patch, or
# recompile the node; we fetch the published linux-x64 daemon and verify its
# SHA-256 against the release's signed checksum file. This is the committed,
# reproducible replacement for the previously ad-hoc `radiant-core:*-amd64`
# image that was built outside the repo and that a fresh developer could not
# obtain.
#
# Build (pin to the latest Radiant-Core release):
#     docker build -f docker/regtest.Dockerfile \\
#         --build-arg RADIANT_VERSION=v3.1.1 \\
#         -t radiant-core:v3.1.1-amd64 .
#
# `pyrxd regtest setup` builds this for you; `pyrxd regtest up` then runs it.
# The container is regtest-only, binds RPC to 127.0.0.1, and is reached solely
# via `docker exec radiant-cli` — never exposed to the network.
#
# Base: ubuntu:22.04 is chosen deliberately — the release binary dynamically
# links Boost 1.74 (22.04's default) and needs GLIBC >= 2.34 (22.04 ships
# 2.35). Debian bullseye's glibc (2.31) is too old; bookworm's Boost (1.81) is
# the wrong soname. Measured with `ldd`/`objdump -T` on the v3.1.x daemon.

FROM ubuntu:22.04

ARG RADIANT_VERSION=v3.1.1
ARG RADIANT_TARBALL=radiant-${RADIANT_VERSION}-linux-x64.tar.gz
ARG RADIANT_BASEURL=https://github.com/Radiant-Core/Radiant-Core/releases/download/${RADIANT_VERSION}

# Runtime shared libraries the daemon links against (measured via ldd).
RUN apt-get update && apt-get install -y --no-install-recommends \\
        ca-certificates \\
        wget \\
        libboost-chrono1.74.0 \\
        libboost-filesystem1.74.0 \\
        libboost-system1.74.0 \\
        libboost-thread1.74.0 \\
        libdb5.3++ \\
        libevent-2.1-7 \\
        libevent-pthreads-2.1-7 \\
        libminiupnpc17 \\
        libsodium23 \\
        libssl3 \\
        libzmq5 \\
    && rm -rf /var/lib/apt/lists/*

# Fetch the official release daemon + cli, verify integrity against the
# release checksum file, install only the two binaries the devnet uses.
RUN set -eux; \\
    cd /tmp; \\
    wget -q "${RADIANT_BASEURL}/${RADIANT_TARBALL}"; \\
    wget -q "${RADIANT_BASEURL}/SHA256SUMS.txt"; \\
    grep " ${RADIANT_TARBALL}\\$" SHA256SUMS.txt | sha256sum -c -; \\
    tar xzf "${RADIANT_TARBALL}"; \\
    install -m0755 "radiant-${RADIANT_VERSION}-linux-x64/radiantd" /usr/local/bin/radiantd; \\
    install -m0755 "radiant-${RADIANT_VERSION}-linux-x64/radiant-cli" /usr/local/bin/radiant-cli; \\
    rm -rf /tmp/*

# Smoke-test that the binary actually runs in this base (catches a missing lib
# at build time rather than at `regtest up`).
RUN radiantd --version

# The devnet driver overrides the entrypoint and passes -regtest flags
# (see pyrxd/devnet.py); this default makes the image runnable standalone too.
ENTRYPOINT ["radiantd"]
CMD ["-regtest", "-server", "-printtoconsole"]
"""


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

    IMAGE = f"radiant-core:{DEFAULT_RADIANT_VERSION}-amd64"
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

    @classmethod
    def build_image(cls, version: str = DEFAULT_RADIANT_VERSION, *, no_cache: bool = False) -> str:
        """Build the regtest image from an OFFICIAL Radiant-Core release binary.

        Wraps the published ``radiant-<version>-linux-x64`` daemon (SHA-256-verified
        against the release checksum file) in a small ubuntu:22.04 image tagged
        ``radiant-core:<version>-amd64``. Builds from the Dockerfile embedded in this
        module, so it works for a ``pip install pyrxd`` developer with no repo checkout
        as well as from a clone. Returns the built image tag.

        This is the dev-facing replacement for the previously ad-hoc image that was
        built outside the repo; ``pyrxd regtest setup`` calls it.
        """
        cls._require_docker()
        tag = f"radiant-core:{version}-amd64"
        with tempfile.TemporaryDirectory() as ctx:
            (Path(ctx) / "Dockerfile").write_text(_REGTEST_DOCKERFILE, encoding="utf-8")
            cmd = ["docker", "build", "-f", f"{ctx}/Dockerfile", "--build-arg", f"RADIANT_VERSION={version}", "-t", tag]
            if no_cache:
                cmd.append("--no-cache")
            cmd.append(ctx)
            r = subprocess.run(cmd, capture_output=True, text=True)  # nosec B603 B607  # controlled docker argv
        if r.returncode != 0:
            raise DevnetError(f"failed to build {tag}: {r.stderr.strip() or r.stdout.strip()}")
        return tag

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
                    "build it with `pyrxd regtest setup` (wraps the official "
                    f"Radiant-Core {DEFAULT_RADIANT_VERSION} release binary)"
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

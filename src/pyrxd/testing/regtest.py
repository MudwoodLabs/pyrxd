"""A throwaway local regtest chain, a client and a funded wallet, for tests.

These are the pieces pyrxd's own node-backed suites used to keep private, packaged so a
project that depends on pyrxd can test against a real ``radiantd`` without copying them.
The pytest fixtures in :mod:`pyrxd.testing.pytest_plugin` are thin wrappers over this
module; nothing here imports pytest, so the same helpers work from a script or notebook.

Three objects:

* :func:`start_test_node` stands up a **fresh** regtest node in docker under a unique
  container name, so it never touches the node ``pyrxd regtest up`` started, and refuses to
  hand the node back unless it is regtest and enforces mainnet's relay floor.
* :class:`RegtestClient` is the client half of what :class:`~pyrxd.glyph.mint.GlyphMinter`
  and :func:`~pyrxd.network.confirm.wait_for_confirmation` expect (``broadcast`` and
  ``get_transaction_verbose``). It mines a block after each broadcast by default, because on
  regtest nothing else will.
* :class:`RegtestWallet` is one freshly generated key, funded from the node's faucet. The
  node's own wallet does not hold the key, so the faucet can never spend a test's coins out
  from under it while funding the next test.

Regtest only. The node is reached through ``docker exec``; its RPC is bound to the
container's localhost and its credentials are the fixed sandbox ones in
:class:`~pyrxd.devnet.RegtestNode`.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess  # nosec B404  # only ever runs a fixed `docker image inspect` argv
from decimal import Decimal

from ..constants import Network
from ..devnet import DevnetError, RegtestNode
from ..fee_sizing import relay_floor_photons_per_byte
from ..gravity.fee_policy import photons_per_kb_from_rxd_per_kb
from ..keys import PrivateKey
from ..network.electrumx import UtxoRecord
from ..security.units import ChainHeight, PhotonValue

__all__ = [
    "DEFAULT_WALLET_FUNDING_RXD",
    "PHOTONS_PER_RXD",
    "RegtestClient",
    "RegtestUnavailable",
    "RegtestWallet",
    "node_relay_floor_photons_per_kb",
    "start_test_node",
]

#: RXD a :class:`RegtestWallet` is funded with when no amount is given. Comfortably more
#: than a Glyph mint needs (``examples/regtest_quickstart.py`` asks for 0.2 RXD).
DEFAULT_WALLET_FUNDING_RXD = 10.0

PHOTONS_PER_RXD = 100_000_000

#: Prefix of every container :func:`start_test_node` names, so leftovers are easy to find
#: (``docker ps -a --filter name=pyrxd-test-``).
TEST_CONTAINER_PREFIX = "pyrxd-test-"


class RegtestUnavailable(DevnetError):
    """Docker, or the regtest node image, is not available on this machine."""


def _rxd_to_photons(amount: object) -> int:
    """An RPC ``amount`` (whole RXD, JSON number) as an exact photon count.

    Through ``Decimal(str(...))`` rather than ``round(amount * 1e8)`` so the conversion is
    exact for every value the node can print (it prints at most 8 decimal places).
    """
    if isinstance(amount, bool) or not isinstance(amount, (int, float, str)):
        raise DevnetError(f"node returned a non-numeric amount: {amount!r}")
    photons = Decimal(str(amount)) * PHOTONS_PER_RXD
    if photons != photons.to_integral_value() or photons < 0:
        raise DevnetError(f"node returned an amount that is not a whole number of photons: {amount!r}")
    return int(photons)


def node_relay_floor_photons_per_kb(node: RegtestNode) -> int:
    """The relay floor the node actually enforces, in photons per kB.

    ``effective_minrelaytxfee``, not ``minrelaytxfee``: the node reports both, and only the
    first is what its mempool checks a transaction against.
    """
    info = node.cli("getmempoolinfo")
    if not isinstance(info, dict) or "effective_minrelaytxfee" not in info:
        raise DevnetError(f"getmempoolinfo did not report effective_minrelaytxfee: {info!r}")
    return photons_per_kb_from_rxd_per_kb(float(info["effective_minrelaytxfee"]))


def _require_docker_and_image(node: RegtestNode) -> None:
    if shutil.which("docker") is None:
        raise RegtestUnavailable(
            "docker is not on PATH. pyrxd.testing runs a real Radiant node in docker; install docker, "
            "then build the node image once with `pyrxd regtest setup`."
        )
    argv = ["docker", "image", "inspect", node.IMAGE]
    has_image = subprocess.run(argv, capture_output=True, text=True)  # noqa: S603  # nosec B603 B607  # fixed docker argv
    if has_image.returncode != 0:
        raise RegtestUnavailable(
            f"the regtest node image {node.IMAGE!r} is not present. Build it once with `pyrxd regtest setup`."
        )


def start_test_node(*, container: str | None = None) -> RegtestNode:
    """Start a fresh regtest node for a test session and return it.

    The container is named ``pyrxd-test-<random>`` unless ``container`` is given, so it
    cannot collide with ``pyrxd regtest up``'s node or with another test session. Any
    container already holding that name is removed first, so pass ``container`` only for a
    name nothing else uses. The caller owns the node: call ``node.stop()`` when done (the
    pytest fixture does).

    Raises :class:`RegtestUnavailable` when docker or the image is missing, and
    :class:`~pyrxd.devnet.DevnetError` when the node comes up as anything other than a
    regtest chain at mainnet's relay floor. A local chain that accepts transactions mainnet
    would refuse tells a test nothing, so this refuses it rather than warning.
    """
    node = RegtestNode(container=container or f"{TEST_CONTAINER_PREFIX}{secrets.token_hex(4)}")
    _require_docker_and_image(node)
    node.start(fresh=True)
    try:
        expected = relay_floor_photons_per_byte() * 1000
        enforced = node_relay_floor_photons_per_kb(node)
        if enforced != expected:
            raise DevnetError(
                f"regtest node enforces a relay floor of {enforced} photons/kB, not mainnet's {expected}; "
                "a test against it would accept transactions mainnet refuses"
            )
    except BaseException:
        node.stop()
        raise
    return node


class RegtestClient:
    """The broadcast-and-look-up client a minter or a confirmation wait expects.

    ``auto_mine`` (default on) mines one block after every broadcast. Regtest only produces
    blocks on request, so without it anything that waits for a confirmation waits until it
    times out. Turn it off to hold a transaction in the mempool and :meth:`mine` yourself.
    """

    def __init__(self, node: RegtestNode, *, auto_mine: bool = True) -> None:
        self.node = node
        self.auto_mine = auto_mine

    async def broadcast(self, raw_tx: bytes | str) -> str:
        """Send a raw transaction (bytes or hex) and return its txid."""
        raw_hex = raw_tx.hex() if isinstance(raw_tx, (bytes, bytearray)) else str(raw_tx)
        txid = str(self.node.cli("sendrawtransaction", raw_hex))
        if self.auto_mine:
            self.node.mine(1)
        return txid

    async def get_transaction_verbose(self, txid: str) -> dict:
        """The node's verbose view of ``txid`` (includes ``confirmations`` once mined)."""
        result = self.node.cli("getrawtransaction", str(txid), "1")
        if not isinstance(result, dict):
            raise DevnetError(f"getrawtransaction {txid} did not return an object")
        return result

    def mine(self, n: int = 1) -> int:
        """Mine ``n`` blocks and return the new height."""
        return self.node.mine(n)


class RegtestWallet:
    """One generated regtest key and the coins on its address.

    Build one with :meth:`funded`. It implements the two methods
    :class:`~pyrxd.glyph.mint.GlyphMinter` uses from a wallet (``collect_spendable`` and
    ``privkey_for_address``), so it can fund a mint directly.

    Coins are found with the node's ``scantxoutset``, which reads the confirmed UTXO set: an
    output still in the mempool is not listed until a block is mined. With
    :class:`RegtestClient`'s default ``auto_mine`` that never shows.
    """

    def __init__(self, node: RegtestNode, private_key: PrivateKey) -> None:
        self.node = node
        self.private_key = private_key
        self.address = private_key.address(network=Network.TESTNET)

    @classmethod
    def funded(cls, node: RegtestNode, amount_rxd: float = DEFAULT_WALLET_FUNDING_RXD) -> RegtestWallet:
        """A wallet on a freshly generated key, funded with ``amount_rxd`` and confirmed."""
        if isinstance(amount_rxd, bool) or not isinstance(amount_rxd, (int, float)) or not amount_rxd > 0:
            raise ValueError("amount_rxd must be a positive number")
        wallet = cls(node, PrivateKey(network=Network.TESTNET))
        node.fund(wallet.address, float(amount_rxd))
        return wallet

    def utxos(self) -> list[UtxoRecord]:
        """Confirmed unspent outputs paying this wallet's address."""
        scan = self.node.cli("scantxoutset", "start", f'["addr({self.address})"]')
        if not isinstance(scan, dict) or scan.get("success") is not True:
            raise DevnetError(f"scantxoutset failed for {self.address}: {scan!r}")
        return [
            UtxoRecord(
                tx_hash=str(u["txid"]),
                tx_pos=int(u["vout"]),
                value=PhotonValue(_rxd_to_photons(u["amount"])),
                height=ChainHeight(int(u["height"])),
            )
            for u in scan.get("unspents", [])
        ]

    def balance_photons(self) -> int:
        """Sum of :meth:`utxos`, in photons."""
        return sum(u.value for u in self.utxos())

    async def collect_spendable(self, client: object = None) -> list[tuple[UtxoRecord, str, PrivateKey]]:
        """``[(utxo, address, private_key)]`` for every coin, in the minter's shape."""
        return [(u, self.address, self.private_key) for u in self.utxos()]

    def privkey_for_address(self, address: str) -> PrivateKey:
        """This wallet's key, if ``address`` is this wallet's address.

        Any other address is refused rather than answered with this key: a wallet that
        signs for an address it does not own produces a transaction the node rejects, and
        the refusal names the cause where the rejection would not.
        """
        if address != self.address:
            raise KeyError(f"{address} is not this wallet's address ({self.address})")
        return self.private_key

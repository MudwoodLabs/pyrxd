"""Live-regtest proof that a wallet made by ``pyrxd wallet new`` can spend what it was sent (#759).

The failure this pins: ``HdWallet.collect_spendable`` read UTXOs only for addresses marked
``used``, only the gap-limit scan (``HdWallet.refresh``) marked them, and nothing saved the
mark. ``wallet send`` and ``wallet sweep`` scanned first; every other spend command did not.
So on mainnet a wallet made with ``pyrxd wallet new`` and holding 100 RXD on its first receive
address was told by ``pyrxd mark``::

    error: no plain-RXD UTXO large enough to fund the mark
      fix: fund this wallet with a little plain RXD and retry.

``tests/test_hashmark_regtest_e2e.py`` runs the real ``pyrxd mark`` against a node too, but
through a stand-in wallet whose ``collect_spendable`` returns the funded UTXO directly, so the
real wallet's read path never ran there. That suite stays, and does not count as coverage for
this. Here NOTHING on the wallet side is swapped:

* the wallet is created by the real ``pyrxd wallet new`` from a mnemonic it generates, and is
  opened again by the real ``_load_wallet`` from the file and the mnemonic typed at the prompt;
* ``collect_spendable`` is the real ``HdWallet`` method;
* it is funded on the node at the first receive address ``wallet new`` printed.

The one stand-in is the TRANSPORT, because a bare node runs no ElectrumX: :class:`_ChainIndex`
answers ElectrumX's per-script calls (``get_history``, ``get_utxos``) from the node's own blocks,
by indexing every output's ``sha256(scriptPubKey)`` the way ElectrumX does. It decides nothing
about the wallet: it answers only for script hashes the wallet asks about, and it only knows
what is on the chain.

Each spend is paired with the honest refusal: an UNFUNDED wallet made the same way must still be
told to fund itself. Without that pair, "the funded wallet spends" would be equally true of a
command that never looked at the wallet at all.

``glyph resume-mint`` is here too, for the key lookup rather than the scan: a new wallet's
commit, its reveal interrupted, is revealed by ``resume-mint`` from the same wallet file, which
records no address; another wallet is refused.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Throwaway container, regtest only.

Run: ``RADIANT_REGTEST=1 pytest -o addopts= -m integration tests/test_fresh_wallet_spends_regtest_e2e.py -rap``
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from test_htlc_regtest_e2e import _IMAGE, _pay_to_spk, _RegtestNode

from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.constants import GENESIS_BLOCK_HASHES
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError

pytestmark = pytest.mark.integration

#: What the mainnet wallet in #759 held. Far over a mark's funding bar or a mint's commit.
_FUND = 100 * 100_000_000

#: The text #759 printed for a wallet holding 100 RXD. It must only ever reach an empty wallet.
_FALSE_ADVICE = "fund this wallet"

_REGTEST_GENESIS = GENESIS_BLOCK_HASHES["regtest"]

#: This module's own container, named per process: ``_RegtestNode.start`` force-removes its
#: container by name, so a shared name lets two runs (two sessions, two suites) destroy each
#: other's node mid-test. ``stop`` removes it when the module is done.
_CONTAINER = f"pyrxd-regtest-fresh-wallet-{os.getpid()}"


@pytest.fixture(scope="module")
def node():
    if not os.environ.get("RADIANT_REGTEST"):
        pytest.skip("RADIANT_REGTEST not set (opt-in for the live regtest e2e)")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if subprocess.run(["docker", "image", "inspect", _IMAGE], capture_output=True).returncode != 0:
        pytest.skip(f"{_IMAGE} image not available")
    n = _RegtestNode(container=_CONTAINER)
    n.start()
    try:
        yield n
    finally:
        n.stop()


class _ChainIndex:
    """ElectrumX's per-script view, rebuilt from the node's blocks.

    Every output of every block is indexed by ``sha256(scriptPubKey)`` (ElectrumX's script
    hash), and every input is attributed to the script of the output it spends, so
    ``get_history`` is the list of transactions touching a script, as ElectrumX serves it.
    ``get_utxos`` asks the node's ``gettxout`` whether each indexed output is still unspent.

    The index is brought up to the tip by :meth:`sync`, which the test calls after it funds a
    wallet and :meth:`broadcast` calls after it mines. Every change to this chain goes through
    one of those two, so the view is never staler than the chain.
    """

    def __init__(self, rt: _RegtestNode) -> None:
        self.rt = rt
        self._height = -1
        self._outputs: dict[bytes, set[tuple[str, int]]] = {}
        self._history: dict[bytes, dict[str, int]] = {}
        self._owner: dict[tuple[str, int], bytes] = {}
        self.broadcasts: list[str] = []
        self.history_asked: set[bytes] = set()

    async def __aenter__(self) -> _ChainIndex:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    def sync(self) -> None:
        tip = int(self.rt.cli("getblockcount"))  # type: ignore[arg-type]
        for height in range(self._height + 1, tip + 1):
            block = self.rt.cli("getblock", str(self.rt.cli("getblockhash", str(height))), "2")
            assert isinstance(block, dict)
            for tx in block["tx"]:
                self._add(tx, height)
        self._height = tip

    def _add(self, tx: dict, height: int) -> None:
        txid = tx["txid"]
        for vin in tx["vin"]:
            spent = (vin.get("txid"), vin.get("vout"))
            if spent in self._owner:
                self._history[self._owner[spent]][txid] = height
        for out in tx["vout"]:
            sh = bytes(script_hash_for_script(bytes.fromhex(out["scriptPubKey"]["hex"])))
            self._owner[(txid, out["n"])] = sh
            self._outputs.setdefault(sh, set()).add((txid, out["n"]))
            self._history.setdefault(sh, {})[txid] = height

    async def get_history(self, script_hash: Any) -> list[dict]:
        sh = bytes(script_hash)
        self.history_asked.add(sh)
        return [{"tx_hash": txid, "height": h} for txid, h in sorted(self._history.get(sh, {}).items())]

    async def get_utxos(self, script_hash: Any) -> list[UtxoRecord]:
        found = []
        for txid, vout in sorted(self._outputs.get(bytes(script_hash), set())):
            info = self.rt.cli("gettxout", txid, str(vout))
            if not isinstance(info, dict):
                continue  # spent: gettxout answers nothing
            found.append(UtxoRecord(tx_hash=txid, tx_pos=vout, value=round(info["value"] * 1e8), height=1))
        return found

    async def get_transaction(self, txid: Any) -> bytes:
        return bytes.fromhex(str(self.rt.cli("getrawtransaction", str(txid))))

    async def get_transaction_verbose(self, txid: Any) -> dict:
        return self.rt.cli("getrawtransaction", str(txid), "true")  # type: ignore[return-value]

    async def assert_chain(self, expected_genesis_hash: str) -> str:
        from pyrxd.security.errors import ValidationError

        observed = str(self.rt.cli("getblockhash", "0")).strip().lower()
        if observed != str(expected_genesis_hash).strip().lower():
            raise ValidationError(f"regtest node is on the wrong chain: genesis {observed} != {expected_genesis_hash}")
        return observed

    async def broadcast(self, raw: bytes) -> str:
        txid = str(self.rt.cli("sendrawtransaction", bytes(raw).hex()))
        self.broadcasts.append(txid)
        self.rt.mine(1)
        self.sync()
        return txid


def _base(tmp_path: Path, wallet: str = "wallet.dat") -> list[str]:
    return [
        "--config",
        str(tmp_path / "absent.toml"),
        "--network",
        "regtest",
        "--wallet",
        str(tmp_path / wallet),
        "--json",
        "--yes",
    ]


def _new_wallet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wallet: str = "wallet.dat") -> tuple[str, str]:
    """``pyrxd wallet new``, for real. Returns ``(mnemonic, first receive address)``."""
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)
    made = CliRunner().invoke(cli, [*_base(tmp_path, wallet), "wallet", "new"])
    assert made.exit_code == 0, (made.output, made.exception)
    doc = json.loads(made.stdout)
    # The precondition #759 is about: the file on disk records no address as used. If
    # `wallet new` ever started saving a scanned wallet, this test would stop testing the case.
    saved = HdWallet.load(tmp_path / wallet, doc["mnemonic"])
    assert not [r for r in saved.addresses.values() if r.used]
    return doc["mnemonic"], doc["address"]


def _wire(rt: _RegtestNode, monkeypatch: pytest.MonkeyPatch) -> _ChainIndex:
    """Swap the transport — and only the transport — for the chain index."""
    index = _ChainIndex(rt)
    monkeypatch.setattr(CliContext, "make_client", lambda self: index)
    return index


def _fund(rt: _RegtestNode, index: _ChainIndex, address: str) -> str:
    txid = _pay_to_spk(rt, bytes(P2PKH().lock(address).serialize()), _FUND)
    index.sync()
    return txid


def _run(tmp_path: Path, mnemonic: str, *args: str, wallet: str = "wallet.dat") -> Any:
    """Run a command with the mnemonic typed at the real ``_load_wallet`` prompt."""
    return CliRunner().invoke(cli, [*_base(tmp_path, wallet), *args], input=mnemonic + "\n")


def _doc(result: Any) -> dict:
    """The JSON document on stdout, after the mnemonic prompt click writes there."""
    return json.loads(result.stdout[result.stdout.index("{") :])


# --------------------------------------------------------------------------- pyrxd mark


def test_a_new_wallet_funded_at_its_first_address_can_mark(node, tmp_path, monkeypatch) -> None:
    mnemonic, address = _new_wallet(tmp_path, monkeypatch)
    index = _wire(node, monkeypatch)
    funding_txid = _fund(node, index, address)
    target = tmp_path / "advisory.txt"
    target.write_bytes(b"a wallet made by `pyrxd wallet new` can mark\n")

    result = _run(tmp_path, mnemonic, "mark", str(target))

    assert _FALSE_ADVICE not in result.output
    assert result.exit_code == 0, (result.output, result.exception)
    mark_txid = _doc(result)["txid"]
    # Read back off the chain: the mark spent the UTXO at the first receive address.
    mark = node.cli("getrawtransaction", mark_txid, "true")
    assert mark["confirmations"] >= 1
    assert [(i["txid"], i["vout"]) for i in mark["vin"]] == [(funding_txid, 0)]
    assert not node.cli("gettxout", funding_txid, "0"), "the funding UTXO should be spent"
    # The scan ran: the wallet asked about its first receive address.
    assert bytes(script_hash_for_script(bytes(P2PKH().lock(address).serialize()))) in index.history_asked


def test_an_unfunded_new_wallet_is_still_told_to_fund_itself(node, tmp_path, monkeypatch) -> None:
    """The honest refusal: with the scan in place, an EMPTY wallet still gets the advice."""
    mnemonic, _address = _new_wallet(tmp_path, monkeypatch)
    index = _wire(node, monkeypatch)
    index.sync()
    target = tmp_path / "advisory.txt"
    target.write_bytes(b"nothing to pay for this\n")

    result = _run(tmp_path, mnemonic, "mark", str(target))

    assert result.exit_code != 0, result.output
    assert _FALSE_ADVICE in result.output
    assert index.broadcasts == []


# --------------------------------------------------------------------------- glyph mint-nft


def _nft_metadata(tmp_path: Path) -> Path:
    path = tmp_path / "nft.json"
    path.write_text(json.dumps({"protocol": ["NFT"], "name": "fresh-wallet-759"}))
    return path


def test_a_new_wallet_funded_at_its_first_address_can_mint_an_nft(node, tmp_path, monkeypatch) -> None:
    mnemonic, address = _new_wallet(tmp_path, monkeypatch)
    index = _wire(node, monkeypatch)
    funding_txid = _fund(node, index, address)

    result = _run(tmp_path, mnemonic, "glyph", "mint-nft", str(_nft_metadata(tmp_path)))

    assert result.exit_code == 0, (result.output, result.exception)
    out = _doc(result)
    commit = node.cli("getrawtransaction", out["commit_txid"], "true")
    reveal = node.cli("getrawtransaction", out["reveal_txid"], "true")
    assert commit["confirmations"] >= 1 and reveal["confirmations"] >= 1
    # The commit was funded by the UTXO at the first receive address.
    assert [(i["txid"], i["vout"]) for i in commit["vin"]] == [(funding_txid, 0)]
    assert (out["commit_txid"], 0) in [(i["txid"], i["vout"]) for i in reveal["vin"]]


def test_an_unfunded_new_wallet_is_refused_by_mint_nft(node, tmp_path, monkeypatch) -> None:
    mnemonic, _address = _new_wallet(tmp_path, monkeypatch)
    index = _wire(node, monkeypatch)
    index.sync()

    result = _run(tmp_path, mnemonic, "glyph", "mint-nft", str(_nft_metadata(tmp_path)))

    assert result.exit_code != 0, result.output
    assert "no spendable UTXOs in the wallet" in result.output
    assert index.broadcasts == []


# --------------------------------------------------------------------------- glyph resume-mint


class _RevealDropped(_ChainIndex):
    """The chain index, with the connection lost as the reveal is sent.

    The first broadcast (the commit) is relayed and mined. The second (the reveal) raises before
    it reaches the node, the way a dropped connection does, so the commit is left confirmed and
    unspent with its pending record on disk: the state ``glyph resume-mint`` exists to finish.
    """

    def __init__(self, rt: _RegtestNode) -> None:
        super().__init__(rt)
        self.dropped: list[bytes] = []

    async def broadcast(self, raw: bytes) -> str:
        if self.broadcasts:
            self.dropped.append(bytes(raw))
            raise NetworkError("simulated: the connection dropped as the reveal was sent")
        return await super().broadcast(raw)


def test_a_new_wallet_resumes_a_mint_whose_reveal_was_interrupted(node, tmp_path, monkeypatch) -> None:
    """``resume-mint`` finds the commit's key in a wallet whose file records no address.

    ``privkey_for_address`` looked the funding address up in the wallet's recorded addresses
    only, and a ``wallet new`` file records none: nothing saves the scan that ``mint-nft`` ran.
    So a new wallet's commit, its reveal interrupted, was refused by ``resume-mint`` with
    "address ... is not known to this wallet", and the commit's value was stranded until the
    owner found another way to sign for it. The lookup now derives across the gap window.

    The honest pair first: ANOTHER new wallet, in the same directory and so reading the same
    pending record, is still refused and broadcasts nothing. Deriving must widen what this
    wallet can find, not let a wallet sign for an address that is not its own.
    """
    mnemonic, address = _new_wallet(tmp_path, monkeypatch)
    dropping = _RevealDropped(node)
    monkeypatch.setattr(CliContext, "make_client", lambda self: dropping)
    funding_txid = _fund(node, dropping, address)

    stopped = _run(tmp_path, mnemonic, "glyph", "mint-nft", str(_nft_metadata(tmp_path)))

    assert stopped.exit_code != 0, stopped.output
    assert "a server stopped answering after the commit was broadcast" in stopped.output
    commit_txid = _doc(stopped)["commit_txid"]
    assert dropping.broadcasts == [commit_txid] and len(dropping.dropped) == 1
    commit = node.cli("getrawtransaction", commit_txid, "true")
    assert commit["confirmations"] >= 1
    assert [(i["txid"], i["vout"]) for i in commit["vin"]] == [(funding_txid, 0)]
    assert node.cli("gettxout", commit_txid, "0"), "the commit output should be confirmed and unspent"
    # The case under test: the file still records no address at all, so the resume below has
    # to find the key for the commit's funding address without a recorded one.
    assert HdWallet.load(tmp_path / "wallet.dat", mnemonic).addresses == {}

    # The honest refusal: another wallet cannot reveal it, and nothing is broadcast.
    other_mnemonic, _other = _new_wallet(tmp_path, monkeypatch, wallet="other.dat")
    index = _wire(node, monkeypatch)
    index.sync()
    refused = _run(tmp_path, other_mnemonic, "glyph", "resume-mint", commit_txid, wallet="other.dat")
    assert refused.exit_code != 0, refused.output
    assert "this wallet cannot reveal that commit" in refused.output
    assert index.broadcasts == []
    assert node.cli("gettxout", commit_txid, "0"), "a refused resume must leave the commit unspent"

    resumed = _run(tmp_path, mnemonic, "glyph", "resume-mint", commit_txid)

    assert resumed.exit_code == 0, (resumed.output, resumed.exception)
    reveal_txid = _doc(resumed)["reveal_txid"]
    assert index.broadcasts == [reveal_txid]
    reveal = node.cli("getrawtransaction", reveal_txid, "true")
    assert reveal["confirmations"] >= 1
    assert (commit_txid, 0) in [(i["txid"], i["vout"]) for i in reveal["vin"]]
    assert not node.cli("gettxout", commit_txid, "0"), "the reveal should have spent the commit"


def test_nothing_in_this_file_touched_anything_but_regtest(node) -> None:
    assert node.cli("getblockchaininfo")["chain"] == "regtest"
    assert str(node.cli("getblockhash", "0")) == _REGTEST_GENESIS

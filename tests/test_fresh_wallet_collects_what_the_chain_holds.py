"""A wallet nobody has scanned still sees its funds: ``collect_spendable`` scans first (#759).

``HdWallet.collect_spendable`` reads UTXOs only for addresses marked ``used``, and only the
gap-limit scan (``refresh``) marks them. ``wallet send`` and ``wallet sweep`` scanned before
collecting; ``pyrxd mark``, the ``glyph`` spend commands, the swap-book commands and
``utxos`` did not, and nothing saved a scan's result. So a wallet made by ``pyrxd wallet new``
and funded at its first receive address had nothing to spend, and ``pyrxd mark`` told its
owner, holding 100 RXD on mainnet, to "fund this wallet".

The scan now happens inside ``collect_spendable``, the one method every spend path crosses
(:class:`TestEverySpendPathCrossesTheScan` holds that true). The node-backed proof, with a real
wallet funded on regtest, is ``tests/test_fresh_wallet_spends_regtest_e2e.py``; this file is
the offline half, so the default suite fails if the scan is removed.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

#: What #759 printed for a wallet holding 100 RXD.
_FALSE_ADVICE = "fund this wallet"

_FUND = 100 * 100_000_000

_SRC = Path(__file__).resolve().parents[1] / "src" / "pyrxd"


class _Chain:
    """An ElectrumX that knows about UTXOs at given addresses, and nothing else.

    ``get_history`` answers for exactly the addresses holding something, the way a real server
    does: an address with a UTXO has history. ``fail_history`` makes every history read fail.
    """

    def __init__(self, funded: dict[str, UtxoRecord] | None = None, *, fail_history: bool = False) -> None:
        self.by_hash = {bytes(script_hash_for_address(a)): (a, u) for a, u in (funded or {}).items()}
        self.fail_history = fail_history
        self.broadcasts: list[bytes] = []

    async def __aenter__(self) -> _Chain:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_history(self, script_hash):
        if self.fail_history:
            raise NetworkError("simulated: the server dropped the connection mid-scan")
        hit = self.by_hash.get(bytes(script_hash))
        return [{"tx_hash": hit[1].tx_hash, "height": 1}] if hit else []

    async def get_utxos(self, script_hash):
        hit = self.by_hash.get(bytes(script_hash))
        return [hit[1]] if hit else []

    async def get_transaction(self, txid):
        for address, utxo in self.by_hash.values():
            if utxo.tx_hash == str(txid):
                outs = [TransactionOutput(Script(b""), 0) for _ in range(utxo.tx_pos)]
                outs.append(TransactionOutput(P2PKH().lock(address), utxo.value))
                return Transaction(tx_inputs=[], tx_outputs=outs).serialize()
        raise AssertionError(f"unknown txid {txid}")

    async def assert_chain(self, genesis):
        return genesis

    async def broadcast(self, raw: bytes) -> str:
        self.broadcasts.append(bytes(raw))
        return Transaction.from_hex(bytes(raw).hex()).txid()


def _utxo(tx_hash: str = "cc" * 32, tx_pos: int = 0, value: int = _FUND) -> UtxoRecord:
    return UtxoRecord(tx_hash=tx_hash, tx_pos=tx_pos, value=value, height=1)


# --------------------------------------------------------------------------- the method


class TestCollectSpendableScansFirst:
    def test_a_fresh_wallet_sees_a_utxo_at_its_first_receive_address(self) -> None:
        w = HdWallet.from_mnemonic(MNEMONIC)
        assert not [r for r in w.addresses.values() if r.used]
        first = w.next_receive_address()
        triples = asyncio.run(w.collect_spendable(_Chain({first: _utxo()})))
        assert [(u.tx_hash, a) for u, a, _k in triples] == [("cc" * 32, first)]
        assert triples[0][2].public_key().address() == first

    def test_a_fresh_wallet_sees_funds_anywhere_inside_the_gap_window(self) -> None:
        w = HdWallet.from_mnemonic(MNEMONIC)
        receive, change = w.derive_address(0, 7), w.derive_address(1, 3)
        chain = _Chain({receive: _utxo("aa" * 32), change: _utxo("bb" * 32, value=5_000)})
        found = {(u.tx_hash, a) for u, a, _k in asyncio.run(w.collect_spendable(chain))}
        assert found == {("aa" * 32, receive), ("bb" * 32, change)}

    def test_a_wallet_with_nothing_on_chain_collects_nothing(self) -> None:
        """The honest path: the scan does not invent funds."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        assert asyncio.run(w.collect_spendable(_Chain())) == []

    def test_a_scan_that_cannot_read_raises_rather_than_reporting_empty(self) -> None:
        """An unreadable address is not an empty one: the funded wallet must not read as unfunded."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        chain = _Chain({w.next_receive_address(): _utxo()}, fail_history=True)
        with pytest.raises(NetworkError):
            asyncio.run(w.collect_spendable(chain))


# --------------------------------------------------------------------------- the commands


def _new_wallet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """The real ``pyrxd wallet new``. Returns ``(mnemonic, first receive address)``."""
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)
    made = CliRunner().invoke(cli, [*_base(tmp_path), "wallet", "new"])
    assert made.exit_code == 0, (made.output, made.exception)
    doc = json.loads(made.stdout)
    return doc["mnemonic"], doc["address"]


def _base(tmp_path: Path) -> list[str]:
    return ["--config", str(tmp_path / "absent.toml"), "--wallet", str(tmp_path / "wallet.dat"), "--json", "--yes"]


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chain: _Chain, mnemonic: str, *args: str):
    """A command against the real wallet file, with the mnemonic typed at the real prompt.

    Only the transport is swapped. ``_load_wallet`` and ``collect_spendable`` are the real ones.
    """
    monkeypatch.setattr(CliContext, "make_client", lambda self: chain)
    return CliRunner().invoke(cli, [*_base(tmp_path), *args], input=mnemonic + "\n")


def _doc(result) -> dict | list:
    out = result.stdout
    return json.loads(out[min(i for i in (out.find("{"), out.find("[")) if i >= 0) :])


class TestMarkFromAWalletNobodyScanned:
    def test_a_funded_new_wallet_marks(self, tmp_path, monkeypatch) -> None:
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        chain = _Chain({first: _utxo()})
        (tmp_path / "f.txt").write_bytes(b"x")
        result = _run(tmp_path, monkeypatch, chain, mnemonic, "mark", str(tmp_path / "f.txt"))
        assert _FALSE_ADVICE not in result.output
        assert result.exit_code == 0, (result.output, result.exception)
        sent = Transaction.from_hex(chain.broadcasts[0].hex())
        assert [(i.source_txid, i.source_output_index) for i in sent.inputs] == [("cc" * 32, 0)]
        assert _doc(result)["txid"] == sent.txid()

    def test_an_unfunded_new_wallet_is_told_to_fund_itself(self, tmp_path, monkeypatch) -> None:
        mnemonic, _first = _new_wallet(tmp_path, monkeypatch)
        chain = _Chain()
        (tmp_path / "f.txt").write_bytes(b"x")
        result = _run(tmp_path, monkeypatch, chain, mnemonic, "mark", str(tmp_path / "f.txt"))
        assert result.exit_code != 0
        assert _FALSE_ADVICE in result.output
        assert chain.broadcasts == []

    def test_a_scan_that_fails_is_a_network_error_not_advice_to_fund(self, tmp_path, monkeypatch) -> None:
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        chain = _Chain({first: _utxo()}, fail_history=True)
        (tmp_path / "f.txt").write_bytes(b"x")
        result = _run(tmp_path, monkeypatch, chain, mnemonic, "mark", str(tmp_path / "f.txt"))
        assert result.exit_code == 2, result.output
        assert _FALSE_ADVICE not in result.output
        assert "could not reach ElectrumX" in result.output
        assert chain.broadcasts == []


class TestUtxosFromAWalletNobodyScanned:
    def test_a_funded_new_wallet_lists_its_utxo(self, tmp_path, monkeypatch) -> None:
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, _Chain({first: _utxo()}), mnemonic, "utxos")
        assert result.exit_code == 0, (result.output, result.exception)
        rows = _doc(result)
        assert [(r["txid"], r["address"], r["value"]) for r in rows] == [("cc" * 32, first, _FUND)]

    def test_an_unfunded_new_wallet_lists_nothing(self, tmp_path, monkeypatch) -> None:
        mnemonic, _first = _new_wallet(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, _Chain(), mnemonic, "utxos")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _doc(result) == []


# --------------------------------------------------------------------------- the funnel


class TestEverySpendPathCrossesTheScan:
    """The fix is in ``HdWallet.collect_spendable``. That is only the funnel while it is the
    ONE ``collect_spendable`` in ``src/``: every caller (``hashmark_tx``, ``glyph/transfer``,
    ``glyph/mint``, ``glyph/timelock_reveal_tx``, the ``glyph``, ``swap-book``, ``wallet`` and
    ``utxos`` commands) reaches the wallet through that name. A second implementation, a wallet
    type of its own, would be a spend path that does not cross this scan, so it fails here and
    has to be looked at."""

    def test_hd_wallet_is_the_only_implementation(self) -> None:
        defs = []
        for path in sorted(_SRC.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "collect_spendable":
                    defs.append(path.relative_to(_SRC).as_posix())
        assert defs == ["hd/wallet.py"]

    def test_there_are_spend_paths_to_protect(self) -> None:
        """Paired with the one above: a scan that found no callers would pass it vacuously."""
        callers = {
            path.relative_to(_SRC).as_posix()
            for path in _SRC.rglob("*.py")
            if ".collect_spendable(" in path.read_text(encoding="utf-8")
        }
        assert {"hashmark_tx.py", "cli/glyph_cmds.py", "cli/swap_book_cmds.py", "cli/query_cmds.py"} <= callers

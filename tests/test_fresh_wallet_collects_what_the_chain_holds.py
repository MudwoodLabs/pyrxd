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
from pyrxd.hd.wallet import _GAP_LIMIT, AddressRecord, HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError, ValidationError
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
    does: an address with a UTXO has history. ``fail_history`` makes every history read fail;
    ``fail_utxos`` makes every UTXO read fail while history still answers.
    """

    def __init__(
        self, funded: dict[str, UtxoRecord] | None = None, *, fail_history: bool = False, fail_utxos: bool = False
    ) -> None:
        self.by_hash = {bytes(script_hash_for_address(a)): (a, u) for a, u in (funded or {}).items()}
        self.fail_history = fail_history
        self.fail_utxos = fail_utxos
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
        if self.fail_utxos:
            raise NetworkError("simulated: listunspent failed for this address")
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


class _LaggingChain(_Chain):
    """A server whose history index lags its UTXO set: it reports no history for anything."""

    async def get_history(self, script_hash):
        return []


class TestAKnownUsedAddressStaysUsed:
    """``_scan_chain`` never demotes an address the wallet already knows is used.

    It used to overwrite the flag with whatever this server said, and ``collect_spendable``
    kept a snapshot of the known-used addresses taken before its own scan. That protected one
    call: the scan cleared the flag, so the NEXT call's snapshot no longer held the address and
    a lagging server hid its funds. A command that spends twice (a mint's commit, then its
    reveal) makes exactly that second call.
    """

    def test_two_calls_in_a_row_both_read_it(self) -> None:
        w = HdWallet.from_mnemonic(MNEMONIC)
        known = w.derive_address(0, 2)
        w.addresses["0/2"] = AddressRecord(address=known, change=0, index=2, used=True)
        chain = _LaggingChain({known: _utxo()})
        for call in ("first", "second"):
            triples = asyncio.run(w.collect_spendable(chain))
            assert [(u.tx_hash, a) for u, a, _k in triples] == [("cc" * 32, known)], call
        assert w.addresses["0/2"].used

    def test_a_scan_still_does_not_invent_a_used_address(self) -> None:
        """The honest half: only what the wallet knew is kept. An address it never knew as
        used, which this server reports no history for, is not read."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        known, unknown = w.derive_address(0, 2), w.derive_address(0, 5)
        w.addresses["0/2"] = AddressRecord(address=known, change=0, index=2, used=True)
        chain = _LaggingChain({known: _utxo("aa" * 32), unknown: _utxo("bb" * 32)})
        for _call in range(2):
            assert [a for _u, a, _k in asyncio.run(w.collect_spendable(chain))] == [known]
        assert not w.addresses["0/5"].used


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

    def test_a_utxo_read_that_fails_is_a_network_error_not_advice_to_fund(self, tmp_path, monkeypatch) -> None:
        """The scan answers, so the funded address is found; then its UTXO read fails. A
        non-strict collect returned nothing for it, and ``mark`` told the owner to fund the
        wallet. Collection is strict by default now, so the failure is reported as one."""
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        chain = _Chain({first: _utxo()}, fail_utxos=True)
        (tmp_path / "f.txt").write_bytes(b"x")
        result = _run(tmp_path, monkeypatch, chain, mnemonic, "mark", str(tmp_path / "f.txt"))
        assert result.exit_code == 2, result.output
        assert _FALSE_ADVICE not in result.output
        assert "could not reach ElectrumX" in result.output
        assert "1 of 1 address reads failed" in result.output
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


# --------------------------------------------------------------------------- key lookup


class TestKeyLookupDerivesInTheGapWindow:
    """``privkey_for_address`` finds an unrecorded address by deriving, with no network.

    A ``wallet new`` file records no address, and nothing saves a scan, so a lookup that read
    only the recorded addresses could not find the key for a new wallet's own funding address.
    ``glyph resume-mint`` then refused to reveal that wallet's commit (proved on regtest in
    ``test_fresh_wallet_spends_regtest_e2e.py``). The lookup now searches the gap window on
    both chains, and nothing past it.
    """

    @pytest.mark.parametrize(("change", "index"), [(0, 7), (1, 3)])
    def test_an_unrecorded_address_inside_the_window_is_found(self, change: int, index: int) -> None:
        w = HdWallet.from_mnemonic(MNEMONIC)
        assert w.addresses == {}
        address = w.derive_address(change, index)
        key = w.privkey_for_address(address)
        assert key.public_key().address() == address
        assert key.public_key().hash160() == w.privkey_for(change, index).public_key().hash160()
        assert w.addresses == {}, "a lookup must not change the wallet"

    @pytest.mark.parametrize("change", [0, 1])
    def test_an_address_past_the_window_is_still_refused(self, change: int) -> None:
        """The honest bound: one past the window is not searched, so it is not this wallet's."""
        w = HdWallet.from_mnemonic(MNEMONIC)
        with pytest.raises(ValidationError, match="not known to this wallet"):
            w.privkey_for_address(w.derive_address(change, _GAP_LIMIT))

    def test_the_window_runs_past_the_highest_known_index(self) -> None:
        w = HdWallet.from_mnemonic(MNEMONIC)
        w.addresses["0/30"] = AddressRecord(address=w.derive_address(0, 30), change=0, index=30, used=True)
        last = w.derive_address(0, 30 + _GAP_LIMIT)
        assert w.privkey_for_address(last).public_key().address() == last
        with pytest.raises(ValidationError, match="not known to this wallet"):
            w.privkey_for_address(w.derive_address(0, 31 + _GAP_LIMIT))

    def test_another_wallets_address_is_refused(self) -> None:
        stranger = HdWallet.from_mnemonic(MNEMONIC, passphrase="another wallet").derive_address(0, 0)
        with pytest.raises(ValidationError, match="not known to this wallet"):
            HdWallet.from_mnemonic(MNEMONIC).privkey_for_address(stranger)


class _MintChain(_Chain):
    """``_Chain`` plus the confirmation read the minter polls."""

    async def get_transaction_verbose(self, txid):
        return {"confirmations": 1}


class TestTheMinterRevealsFromAWalletNobodyScanned:
    """The SDK caller, through its own entry point: ``GlyphMinter.reveal_nft`` after a crash.

    The commit is made by one ``HdWallet``; the reveal by a second one opened from the same
    mnemonic, as a process restarted after a crash would open it, recording nothing.
    """

    def _commit(self, tmp_path: Path, funded_at: tuple[int, int]):
        from pyrxd.glyph.mint import GlyphMinter, JsonFilePendingStore
        from pyrxd.glyph.types import GlyphMetadata, GlyphProtocol

        committer = HdWallet.from_mnemonic(MNEMONIC)
        chain = _MintChain({committer.derive_address(*funded_at): _utxo()})
        store = JsonFilePendingStore(tmp_path / "pending")
        minter = GlyphMinter(chain, committer, store, poll_interval_s=0.01)
        metadata = GlyphMetadata(protocol=[GlyphProtocol.NFT], name="fresh-wallet-reveal")
        pending = asyncio.run(minter.commit_nft(metadata))
        assert pending.funding_address == committer.derive_address(*funded_at)
        return chain, store, pending

    def test_a_fresh_wallet_from_the_same_mnemonic_reveals(self, tmp_path) -> None:
        from pyrxd.glyph.mint import GlyphMinter

        chain, store, pending = self._commit(tmp_path, funded_at=(0, 7))
        restarted = HdWallet.from_mnemonic(MNEMONIC)
        assert restarted.addresses == {}
        result = asyncio.run(GlyphMinter(chain, restarted, store, poll_interval_s=0.01).reveal_nft(pending))
        reveal = Transaction.from_hex(chain.broadcasts[-1].hex())
        assert result.reveal_txid == reveal.txid()
        assert [(i.source_txid, i.source_output_index) for i in reveal.inputs] == [(pending.commit_txid, 0)]

    def test_another_wallet_still_cannot_reveal(self, tmp_path) -> None:
        from pyrxd.glyph.mint import GlyphMinter

        chain, store, pending = self._commit(tmp_path, funded_at=(0, 0))
        stranger = HdWallet.from_mnemonic(MNEMONIC, passphrase="another wallet")
        sent = len(chain.broadcasts)
        with pytest.raises(ValidationError, match="not known to this wallet"):
            asyncio.run(GlyphMinter(chain, stranger, store, poll_interval_s=0.01).reveal_nft(pending))
        assert len(chain.broadcasts) == sent


class TestMarkSignsWithAnUnrecordedAddress:
    """``pyrxd mark --signer-address`` crosses the same lookup, from a ``wallet new`` file."""

    def test_a_signer_address_inside_the_window_signs(self, tmp_path, monkeypatch) -> None:
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        signer = HdWallet.from_mnemonic(mnemonic)
        (tmp_path / "f.txt").write_bytes(b"x")
        chain = _Chain({first: _utxo()})
        result = _run(
            tmp_path, monkeypatch, chain, mnemonic, "mark", str(tmp_path / "f.txt"),
            "--signer-address", signer.derive_address(0, 7),
        )  # fmt: skip
        assert result.exit_code == 0, (result.output, result.exception)
        assert _doc(result)["signer_hash160"] == signer.privkey_for(0, 7).public_key().hash160().hex()
        assert len(chain.broadcasts) == 1

    def test_a_signer_address_past_the_window_is_refused(self, tmp_path, monkeypatch) -> None:
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        outside = HdWallet.from_mnemonic(mnemonic).derive_address(0, _GAP_LIMIT)
        (tmp_path / "f.txt").write_bytes(b"x")
        chain = _Chain({first: _utxo()})
        result = _run(
            tmp_path, monkeypatch, chain, mnemonic, "mark", str(tmp_path / "f.txt"), "--signer-address", outside
        )
        assert result.exit_code != 0
        assert f"cannot sign with {outside}" in result.output
        assert chain.broadcasts == []


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

    def test_only_the_named_callers_accept_a_partial_view(self) -> None:
        """``collect_spendable`` is strict by default, so a caller that turns "nothing found"
        into "fund this wallet" cannot be handed a partial view by a failed read. Opting out is
        a judgement, so the set of callers that pass ``strict=False`` is pinned: ``send`` (an
        amount only needs *enough*) and the read-only ``utxos`` listing. Any change to the set
        fails here and has to say why."""
        calls: list[tuple[str, str]] = []
        opted_out: set[tuple[str, str]] = set()

        def visit(node: ast.AST, where: str, func: str) -> None:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                func = node.name
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "collect_spendable":
                calls.append((where, func))
                for kw in node.keywords:
                    # Anything but a literal True counts as opting out, so a variable cannot hide one.
                    if kw.arg == "strict" and not (isinstance(kw.value, ast.Constant) and kw.value.value is True):
                        opted_out.add((where, func))
            for child in ast.iter_child_nodes(node):
                visit(child, where, func)

        for path in sorted(_SRC.rglob("*.py")):
            visit(ast.parse(path.read_text(encoding="utf-8")), path.relative_to(_SRC).as_posix(), "<module>")
        assert ("hashmark_tx.py", "build_hashmark_mark") in calls, "the walk found no callers — it is broken"
        assert opted_out == {("hd/wallet.py", "send"), ("cli/query_cmds.py", "_query")}

    def test_there_are_spend_paths_to_protect(self) -> None:
        """Paired with the one above: a scan that found no callers would pass it vacuously."""
        callers = {
            path.relative_to(_SRC).as_posix()
            for path in _SRC.rglob("*.py")
            if ".collect_spendable(" in path.read_text(encoding="utf-8")
        }
        assert {"hashmark_tx.py", "cli/glyph_cmds.py", "cli/swap_book_cmds.py", "cli/query_cmds.py"} <= callers

"""``pyrxd balance`` and ``pyrxd glyph list`` scan the chain by default (after #759 / #768).

Both read only the addresses marked ``used``, and only the gap-limit scan (``HdWallet.refresh``)
marks them. ``balance`` ran the scan only under ``--refresh``, ``glyph list`` never ran it, and
nothing saves a scan, so a wallet made by ``pyrxd wallet new`` and funded at its first receive
address showed a balance of 0 and listed no tokens. Both now run the scan ``collect_spendable``
runs, through ``query_cmds.scan_then_read``, and report an address they could not read as
INCOMPLETE (``query_cmds.refuse_if_incomplete``) instead of as empty.

Every test here drives the real command: the real ``pyrxd wallet new`` file, the mnemonic typed
at the real prompt, the real ``HdWallet``, ``GlyphScanner`` and inspector. The one fake is the
ElectrumX client (:class:`_ElectrumX`), swapped in at ``CliContext.make_client``. #759 hid behind
a regtest test that stubbed the wallet, so nothing above the transport is stubbed here.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput

_FUND = 100 * 100_000_000
_CHANGE = 7_000_000


class _ElectrumX:
    """Stands in for the ElectrumX client and nothing else: the reads these commands make.

    *holdings* maps an address to the transactions paying it at vout 0. The server model is the
    one the scanner and ``collect_spendable`` already assume (not re-verified against a live
    server here): what an address holds, a token output included, is listed under its P2PKH
    script hash, and an address holding something has history there.

    Failures, each the failure of one read: ``history_fails_after=n`` answers *n* history reads
    and fails every later one (a connection lost mid-scan); ``unreadable`` fails the balance and
    UTXO reads for those addresses; ``tx_unreadable`` fails the raw-transaction read for those
    txids.
    """

    def __init__(
        self,
        holdings: dict[str, list[Transaction]] | None = None,
        *,
        history_fails_after: int | None = None,
        unreadable: set[str] = frozenset(),
        tx_unreadable: set[str] = frozenset(),
    ) -> None:
        self.held = {bytes(script_hash_for_address(a)): txs for a, txs in (holdings or {}).items()}
        self.txs = {tx.txid(): tx for txs in (holdings or {}).values() for tx in txs}
        self.history_fails_after = history_fails_after
        self.history_reads = 0
        self.unreadable = {bytes(script_hash_for_address(a)) for a in unreadable}
        self.tx_unreadable = set(tx_unreadable)

    async def __aenter__(self) -> _ElectrumX:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_history(self, script_hash):
        self.history_reads += 1
        if self.history_fails_after is not None and self.history_reads > self.history_fails_after:
            raise NetworkError("simulated: the server dropped the connection mid-scan")
        return [{"tx_hash": tx.txid(), "height": 1} for tx in self.held.get(bytes(script_hash), [])]

    def _read(self, script_hash) -> list[Transaction]:
        if bytes(script_hash) in self.unreadable:
            raise NetworkError("simulated: this address's read failed")
        return self.held.get(bytes(script_hash), [])

    async def get_balance(self, script_hash):
        return sum(tx.outputs[0].satoshis for tx in self._read(script_hash)), 0

    async def get_utxos(self, script_hash):
        return [
            UtxoRecord(tx_hash=tx.txid(), tx_pos=0, value=tx.outputs[0].satoshis, height=1)
            for tx in self._read(script_hash)
        ]

    async def get_transaction(self, txid):
        if str(txid) in self.tx_unreadable or str(txid) not in self.txs:
            # Not in this chain covers the token's commit tx, which the metadata lookup asks for:
            # a failed metadata lookup must leave the token listed with no name.
            raise NetworkError(f"simulated: no transaction {str(txid)[:16]}")
        return self.txs[str(txid)].serialize()


def _paying(locking: bytes, value: int, salt: int) -> Transaction:
    tx = Transaction()
    tx.add_input(TransactionInput(source_txid=f"{salt:064x}", source_output_index=0, unlocking_script=Script(b"")))
    tx.add_output(TransactionOutput(Script(locking), value))
    return tx


def _plain(address: str, value: int = _FUND, salt: int = 1) -> Transaction:
    return _paying(P2PKH().lock(address).serialize(), value, salt)


def _pkh(wallet: HdWallet, change: int, index: int) -> Hex20:
    return Hex20(wallet.privkey_for(change, index).public_key().hash160())


def _nft(wallet: HdWallet, change: int, index: int, ref_byte: str) -> tuple[Transaction, str]:
    ref = GlyphRef(txid=Txid(ref_byte * 32), vout=0)
    return _paying(build_nft_locking_script(_pkh(wallet, change, index), ref), 1, 100 + index), f"{ref.txid}:0"


def _ft(wallet: HdWallet, change: int, index: int, ref_byte: str, amount: int) -> tuple[Transaction, str]:
    ref = GlyphRef(txid=Txid(ref_byte * 32), vout=0)
    return _paying(build_ft_locking_script(_pkh(wallet, change, index), ref), amount, 200 + index), f"{ref.txid}:0"


# --------------------------------------------------------------------------- running the CLI


def _base(tmp_path: Path, mode: str) -> list[str]:
    flag = {"json": ["--json"], "quiet": ["--quiet"], "human": []}[mode]
    return ["--config", str(tmp_path / "absent.toml"), "--wallet", str(tmp_path / "wallet.dat"), *flag]


def _new_wallet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, HdWallet]:
    """The real ``pyrxd wallet new``. Returns the mnemonic and the same wallet, to derive with."""
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)
    made = CliRunner().invoke(cli, [*_base(tmp_path, "json"), "--yes", "wallet", "new"])
    assert made.exit_code == 0, (made.output, made.exception)
    mnemonic = json.loads(made.stdout)["mnemonic"]
    on_disk = HdWallet.load(tmp_path / "wallet.dat", mnemonic)
    assert not [rec for rec in on_disk.addresses.values() if rec.used], "the file must record no used address"
    return mnemonic, HdWallet.from_mnemonic(mnemonic)


def _run(tmp_path, monkeypatch, server: _ElectrumX, mnemonic: str, *args: str, mode: str = "json"):
    """A command against the real wallet file. Only the transport is swapped."""
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    return CliRunner().invoke(cli, [*_base(tmp_path, mode), *args], input=mnemonic + "\n")


def _json(result) -> dict | list:
    out = result.stdout
    return json.loads(out[min(i for i in (out.find("{"), out.find("[")) if i >= 0) :])


def _shown(result) -> str:
    """What the command printed on stdout, less the hidden mnemonic prompt."""
    return result.stdout.split("Mnemonic (input hidden): ", 1)[-1].strip()


# --------------------------------------------------------------------------- balance


class TestBalanceScansByDefault:
    def test_a_funded_new_wallet_shows_its_balance(self, tmp_path, monkeypatch) -> None:
        """#759's case: funded at the first receive address, which the file never marked used."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _ElectrumX({w.derive_address(0, 0): [_plain(w.derive_address(0, 0))]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _json(result)["confirmed_photons"] == _FUND

    def test_funds_on_addresses_never_marked_used_are_all_counted(self, tmp_path, monkeypatch) -> None:
        """The honest path, across the window: a receive address past the first and a change
        address, neither recorded anywhere in the file, both counted, and nothing else."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        receive, change = w.derive_address(0, 7), w.derive_address(1, 3)
        server = _ElectrumX({receive: [_plain(receive)], change: [_plain(change, _CHANGE, salt=2)]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _json(result) == {"network": "mainnet", "confirmed_photons": _FUND + _CHANGE, "unconfirmed_photons": 0}

    def test_a_wallet_with_nothing_on_chain_shows_zero(self, tmp_path, monkeypatch) -> None:
        """A zero after a scan that read every address is a real zero, and still exits 0."""
        mnemonic, _w = _new_wallet(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, _ElectrumX(), mnemonic, "balance")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _json(result)["confirmed_photons"] == 0

    def test_refresh_still_parses_and_changes_nothing(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _ElectrumX({w.derive_address(0, 0): [_plain(w.derive_address(0, 0))]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance", "--refresh")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _json(result)["confirmed_photons"] == _FUND

    def test_help_says_the_scan_is_the_default(self) -> None:
        text = " ".join(CliRunner().invoke(cli, ["balance", "--help"]).output.split())
        assert "the gap-limit scan is now the default" in text

    def test_the_scan_is_not_saved(self, tmp_path, monkeypatch) -> None:
        """``balance --refresh`` never saved its scan; scanning by default does not start to."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        before = (tmp_path / "wallet.dat").read_bytes()
        server = _ElectrumX({w.derive_address(0, 0): [_plain(w.derive_address(0, 0))]})
        for args in (("balance",), ("balance", "--refresh"), ("glyph", "list")):
            assert _run(tmp_path, monkeypatch, server, mnemonic, *args).exit_code == 0, args
        assert (tmp_path / "wallet.dat").read_bytes() == before

    @pytest.mark.parametrize("mode", ["json", "human", "quiet"])
    def test_a_read_failure_mid_scan_is_not_a_zero_balance(self, tmp_path, monkeypatch, mode) -> None:
        """The scan reads 5 addresses, then the connection drops. The funded address is past
        that point, so a view built from what was read would say 0."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        funded = w.derive_address(0, 9)
        server = _ElectrumX({funded: [_plain(funded)]}, history_fails_after=5)
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance", mode=mode)
        assert result.exit_code == 2, result.output
        assert "could not reach ElectrumX" in result.output
        assert _shown(result) == "", "a failed scan must print no balance at all"

    def test_one_unreadable_address_is_incomplete_not_a_lower_balance(self, tmp_path, monkeypatch) -> None:
        """Human output shows what WAS read, marked INCOMPLETE and naming the unread address,
        on stdout; the command still exits 2."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        good, bad = w.derive_address(0, 0), w.derive_address(0, 1)
        server = _ElectrumX({good: [_plain(good, _CHANGE)], bad: [_plain(bad, salt=2)]}, unreadable={bad})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance", mode="human")
        assert result.exit_code == 2, result.output
        shown = _shown(result)
        assert "Confirmed  7,000,000 photons" in shown
        assert "INCOMPLETE: 1 of 2 used addresses could not be read, so the balance leaves out" in shown
        assert bad in shown
        assert "the balance is incomplete" in result.stderr

    @pytest.mark.parametrize("mode", ["json", "quiet"])
    def test_machine_output_prints_no_partial_balance(self, tmp_path, monkeypatch, mode) -> None:
        """JSON and quiet have no place to say "incomplete", so they print nothing a script
        could take for the balance."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        good, bad = w.derive_address(0, 0), w.derive_address(0, 1)
        server = _ElectrumX({good: [_plain(good, _CHANGE)], bad: [_plain(bad, salt=2)]}, unreadable={bad})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance", mode=mode)
        assert result.exit_code == 2, result.output
        assert _shown(result) == ""
        assert "the balance is incomplete" in result.stderr

    def test_no_address_readable_is_a_network_error_not_zero(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        a, b = w.derive_address(0, 0), w.derive_address(1, 0)
        server = _ElectrumX({a: [_plain(a)], b: [_plain(b, salt=2)]}, unreadable={a, b})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "balance", mode="human")
        assert result.exit_code == 2, result.output
        assert "could not reach ElectrumX" in result.output
        assert "2 of 2 used address reads failed" in result.output
        assert _shown(result) == ""


# --------------------------------------------------------------------------- glyph list


class TestGlyphListScansByDefault:
    def test_a_new_wallet_lists_tokens_at_addresses_never_marked_used(self, tmp_path, monkeypatch) -> None:
        """An NFT at the first receive address and an FT on the change chain: neither address is
        recorded in the file. Both are listed, with the address that holds each."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_tx, nft_ref = _nft(w, 0, 0, "ab")
        ft_tx, ft_ref = _ft(w, 1, 4, "cd", 5_000)
        first, change = w.derive_address(0, 0), w.derive_address(1, 4)
        server = _ElectrumX({first: [nft_tx], change: [ft_tx]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        assert sorted((r["type"], r["ref"], r["address"], r["amount"]) for r in _json(result)) == [
            ("FT", ft_ref, change, "5000"),
            ("NFT", nft_ref, first, "1"),
        ]

    def test_a_wallet_holding_nothing_lists_nothing(self, tmp_path, monkeypatch) -> None:
        """An empty list after a scan that read every address is a real empty list."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        result = _run(tmp_path, monkeypatch, _ElectrumX({first: [_plain(first)]}), mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _json(result) == []

    @pytest.mark.parametrize("mode", ["json", "human"])
    def test_a_read_failure_mid_scan_is_not_an_empty_list(self, tmp_path, monkeypatch, mode) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_tx, _ref = _nft(w, 0, 9, "ab")
        server = _ElectrumX({w.derive_address(0, 9): [nft_tx]}, history_fails_after=5)
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list", mode=mode)
        assert result.exit_code == 2, result.output
        assert "could not reach ElectrumX" in result.output
        assert _shown(result) == "", "no '[]' and no '(none)'"

    def test_a_token_whose_transaction_cannot_be_fetched_is_not_left_out(self, tmp_path, monkeypatch) -> None:
        """The address's UTXO read answers, then fetching the token's transaction fails. The
        scanner used to log that and return an inventory without it."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_tx, _ref = _nft(w, 0, 0, "ab")
        server = _ElectrumX({w.derive_address(0, 0): [nft_tx]}, tx_unreadable={nft_tx.txid()})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 2, result.output
        assert _shown(result) == "", "no '[]'"
        assert "could not reach ElectrumX" in result.output

    def test_one_unreadable_address_marks_the_list_incomplete(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_a, ref_a = _nft(w, 0, 0, "ab")
        nft_b, _ref_b = _nft(w, 0, 1, "cd")
        good, bad = w.derive_address(0, 0), w.derive_address(0, 1)
        server = _ElectrumX({good: [nft_a], bad: [nft_b]}, unreadable={bad})
        human = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list", mode="human")
        assert human.exit_code == 2, human.output
        shown = _shown(human)
        assert ref_a in shown
        assert (
            f"INCOMPLETE: 1 of 2 used addresses could not be read, so this list leaves out whatever they hold: {bad}"
            in shown
        )
        machine = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert machine.exit_code == 2, machine.output
        assert _shown(machine) == ""


# --------------------------------------------------------------------------- utxos, same rule


class TestUtxosFollowsTheSameRule:
    """``utxos`` already scanned (#768) and listed a partial view with exit 0; its strictness was
    left to go with ``balance``'s. It now follows the same rule."""

    def test_one_unreadable_address_marks_the_list_incomplete(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        good, bad = w.derive_address(0, 0), w.derive_address(0, 1)
        server = _ElectrumX({good: [_plain(good, _CHANGE)], bad: [_plain(bad, salt=2)]}, unreadable={bad})
        human = _run(tmp_path, monkeypatch, server, mnemonic, "utxos", mode="human")
        assert human.exit_code == 2, human.output
        assert "7000000" in _shown(human)
        assert "INCOMPLETE: 1 of 2 used addresses could not be read" in _shown(human)
        machine = _run(tmp_path, monkeypatch, server, mnemonic, "utxos")
        assert machine.exit_code == 2, machine.output
        assert _shown(machine) == ""

    def test_addr_on_a_readable_address_is_answered(self, tmp_path, monkeypatch) -> None:
        """The honest half: ``--addr`` asks about one address, and another address's failed read
        does not make that answer incomplete."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        good, bad = w.derive_address(0, 0), w.derive_address(0, 1)
        server = _ElectrumX({good: [_plain(good, _CHANGE)], bad: [_plain(bad, salt=2)]}, unreadable={bad})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "utxos", "--addr", good)
        assert result.exit_code == 0, (result.output, result.exception)
        assert [(r["address"], r["value"]) for r in _json(result)] == [(good, _CHANGE)]
        refused = _run(tmp_path, monkeypatch, server, mnemonic, "utxos", "--addr", bad)
        assert refused.exit_code == 2, refused.output

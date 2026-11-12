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
from pyrxd.glyph.scanner import owned_token_script_hashes
from pyrxd.glyph.script import build_ft_locking_script, build_nft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.hd.wallet import HdWallet
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address, script_hash_for_output
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.utils import address_to_public_key_hash

_FUND = 100 * 100_000_000
_CHANGE = 7_000_000


class _ElectrumX:
    """Stands in for the ElectrumX client and nothing else: the reads these commands make.

    *holdings* maps an address to the transactions paying it at vout 0. Every output is listed
    where a Radiant ElectrumX lists it, under ``script_hash_for_output`` of its script: a plain
    output under the address's P2PKH hash, a token output under its script with the refs zeroed.
    That was measured against both public mainnet servers on 2026-09-29 (#782). It means an
    address holding only a token has no P2PKH history; the gap-limit scan then reads its token
    hashes to mark it used (#787).

    Failures, each the failure of one read: ``history_fails_after=n`` answers *n* history reads
    and fails every later one (a connection lost mid-scan); ``unreadable`` fails the balance and
    UTXO reads for those addresses; ``tx_unreadable`` fails the raw-transaction read for those
    txids.

    Lies, each a server answer its own transaction contradicts: ``misfiled`` maps a script hash
    to transactions it lists (at vout 0) there whatever their script, and ``values`` maps a txid
    to the value the server reports for its vout 0.
    """

    def __init__(
        self,
        holdings: dict[str, list[Transaction]] | None = None,
        *,
        history_fails_after: int | None = None,
        unreadable: set[str] = frozenset(),
        tx_unreadable: set[str] = frozenset(),
        misfiled: dict[bytes, list[Transaction]] | None = None,
        values: dict[str, int] | None = None,
    ) -> None:
        self.held: dict[bytes, list[tuple[Transaction, int]]] = {}
        for txs in (holdings or {}).values():
            for tx in txs:
                for vout, out in enumerate(tx.outputs):
                    listed_under = bytes(script_hash_for_output(out.locking_script.serialize()))
                    self.held.setdefault(listed_under, []).append((tx, vout))
        for script_hash, txs in (misfiled or {}).items():
            self.held.setdefault(bytes(script_hash), []).extend((tx, 0) for tx in txs)
        every_tx = [tx for txs in (holdings or {}).values() for tx in txs]
        every_tx += [tx for txs in (misfiled or {}).values() for tx in txs]
        self.txs = {tx.txid(): tx for tx in every_tx}
        self.values = dict(values or {})
        self.history_fails_after = history_fails_after
        self.history_reads = 0
        self.unreadable = {bytes(h) for a in unreadable for h in _hashes_of(a)}
        self.tx_unreadable = set(tx_unreadable)

    async def __aenter__(self) -> _ElectrumX:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_history(self, script_hash):
        self.history_reads += 1
        if self.history_fails_after is not None and self.history_reads > self.history_fails_after:
            raise NetworkError("simulated: the server dropped the connection mid-scan")
        txids = dict.fromkeys(tx.txid() for tx, _vout in self.held.get(bytes(script_hash), []))
        return [{"tx_hash": txid, "height": 1} for txid in txids]

    def _read(self, script_hash) -> list[tuple[Transaction, int]]:
        if bytes(script_hash) in self.unreadable:
            raise NetworkError("simulated: this address's read failed")
        return self.held.get(bytes(script_hash), [])

    async def get_balance(self, script_hash):
        return sum(tx.outputs[vout].satoshis for tx, vout in self._read(script_hash)), 0

    async def get_utxos(self, script_hash):
        return [
            UtxoRecord(
                tx_hash=tx.txid(), tx_pos=vout, value=self.values.get(tx.txid(), tx.outputs[vout].satoshis), height=1
            )
            for tx, vout in self._read(script_hash)
        ]

    async def get_transaction(self, txid):
        if str(txid) in self.tx_unreadable or str(txid) not in self.txs:
            # Not in this chain covers the token's commit tx, which the metadata lookup asks for:
            # a failed metadata lookup must leave the token listed with no name.
            raise NetworkError(f"simulated: no transaction {str(txid)[:16]}")
        return self.txs[str(txid)].serialize()


def _hashes_of(address: str) -> tuple:
    """Every script hash an address's outputs are listed under: its P2PKH hash and its token hashes."""
    return (script_hash_for_address(address), *owned_token_script_hashes(Hex20(address_to_public_key_hash(address))))


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


def _run(
    tmp_path,
    monkeypatch,
    server: _ElectrumX,
    mnemonic: str,
    *args: str,
    mode: str = "json",
    pair: tuple[_ElectrumX, _ElectrumX] | None = None,
):
    """A command against the real wallet file. Only the transport is swapped.

    *pair* is the two operators ``glyph list`` asks whether its outputs are unspent (#788);
    ``None`` is a single-operator configuration.
    """
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    labelled = (
        None if pair is None else (("wss://first.example:50022", pair[0]), ("wss://second.example:50022", pair[1]))
    )
    monkeypatch.setattr(CliContext, "make_operator_pair", lambda self: labelled)
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
        server = _ElectrumX({first: [_plain(first), nft_tx], change: [_plain(change, salt=2), ft_tx]})
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
        first = w.derive_address(0, 0)
        server = _ElectrumX({first: [_plain(first), nft_tx]}, tx_unreadable={nft_tx.txid()})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 2, result.output
        assert _shown(result) == "", "no '[]'"
        assert "could not reach ElectrumX" in result.output

    def test_one_unreadable_address_marks_the_list_incomplete(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_a, ref_a = _nft(w, 0, 0, "ab")
        nft_b, _ref_b = _nft(w, 0, 1, "cd")
        good, bad = w.derive_address(0, 0), w.derive_address(0, 1)
        server = _ElectrumX({good: [_plain(good), nft_a], bad: [_plain(bad, salt=2), nft_b]}, unreadable={bad})
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


# --------------------------------------------------------------------------- glyph list, unspent is the server's word (#788)

_SPENT_NOTE = (
    "Note: the ElectrumX server says these outputs are unspent; pyrxd did not check that, "
    "and a server can list an output this wallet has already spent."
)


_ONE_OPERATOR = "only one ElectrumX operator is configured, so no second one was asked"


class TestGlyphListSaysUnspentIsTheServersWord:
    """With one operator configured, nothing checks that a listed token output is still unspent:
    a server can re-list one the wallet has spent and it passes every check the scanner makes.
    The output says whose word "unspent" is. The JSON gains a field; no existing field changes."""

    def _held(self, tmp_path, monkeypatch):
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_tx, nft_ref = _nft(w, 0, 0, "ab")
        ft_tx, ft_ref = _ft(w, 0, 0, "cd", 5_000)
        first = w.derive_address(0, 0)
        return mnemonic, _ElectrumX({first: [_plain(first), nft_tx, ft_tx]}), first, nft_ref, ft_ref

    def test_the_human_list_says_so_under_the_table(self, tmp_path, monkeypatch) -> None:
        mnemonic, server, _first, nft_ref, ft_ref = self._held(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list", mode="human")
        assert result.exit_code == 0, (result.output, result.exception)
        lines = _shown(result).splitlines()
        assert lines[-2:] == [_SPENT_NOTE, f"({_ONE_OPERATOR}.)"]
        assert any(nft_ref in line for line in lines[:-2])
        assert any(ft_ref in line for line in lines[:-2])

    def test_an_empty_human_list_has_no_note(self, tmp_path, monkeypatch) -> None:
        """No output is listed, so there is no "unspent" to qualify."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        server = _ElectrumX({first: [_plain(first)]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list", mode="human")
        assert result.exit_code == 0, (result.output, result.exception)
        assert _shown(result) == "(none)"

    def test_each_json_row_names_the_server_and_keeps_every_old_field(self, tmp_path, monkeypatch) -> None:
        mnemonic, server, first, nft_ref, ft_ref = self._held(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        rows = _json(result)
        assert len(rows) == 2
        for row in rows:
            assert set(row) == {"type", "ref", "address", "amount", "name", "spent_status_source"}, row
            assert row["spent_status_source"] == "server"
        assert sorted((r["type"], r["ref"], r["address"], r["amount"], r["name"]) for r in rows) == [
            ("FT", ft_ref, first, "5000", ""),
            ("NFT", nft_ref, first, "1", ""),
        ]

    def test_quiet_prints_only_the_refs(self, tmp_path, monkeypatch) -> None:
        mnemonic, server, _first, nft_ref, ft_ref = self._held(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list", mode="quiet")
        assert result.exit_code == 0, (result.output, result.exception)
        assert sorted(_shown(result).splitlines()) == sorted([nft_ref, ft_ref])


_A = "wss://first.example:50022"
_B = "wss://second.example:50022"
_INV = "the server this list was read from"


def _disputed(result) -> list[str]:
    return [line for line in _shown(result).splitlines() if line.startswith("DISPUTED")]


class _PinFails(_ElectrumX):
    """An operator whose TLS certificate does not match its pin: every read raises the pin error."""

    async def get_utxos(self, script_hash):
        from pyrxd.security.errors import TlsPinMismatchError

        raise TlsPinMismatchError("simulated: certificate does not match the pin")


class _WrongChain(_ElectrumX):
    """An operator on another chain: the failover client's chain check raises ValidationError."""

    async def get_utxos(self, script_hash):
        from pyrxd.security.errors import ValidationError

        raise ValidationError("simulated: ElectrumX endpoint is on the wrong chain")


class _Broken(_ElectrumX):
    """A bug, not a fault: anything that is not a NetworkError must not be read as "unreachable"."""

    async def get_utxos(self, script_hash):
        raise RuntimeError("simulated: a bug in the read")


class _UpperCase(_ElectrumX):
    """An honest server whose listing spells txids in upper case. (A plain record: ``Txid``
    itself would refuse the spelling, but nothing makes every client's records use it.)"""

    async def get_utxos(self, script_hash):
        from types import SimpleNamespace

        return [
            SimpleNamespace(tx_hash=str(u.tx_hash).upper(), tx_pos=u.tx_pos, value=u.value, height=u.height)
            for u in await super().get_utxos(script_hash)
        ]


class TestGlyphListAsksASecondOperator:
    """With two operators configured, each lists the wallet's token outputs itself, under hashes
    derived from the wallet's keys, and each listing is compared with the one the inventory was
    read from, in both directions (#788). So a liar shows up whichever server it is (either
    operator, or a third that served the inventory), whether it re-lists a spent output (a
    decoy) or leaves out one it holds (a withholding), and whether or not the other operator
    can be read.

    The inventory server and the two operators are three separate fakes unless a test says
    otherwise: the fix for the review's 5.1 is exactly that the inventory is a party of its own.
    A re-listed output is a real token transaction of this wallet that only the liar still
    lists, so everything the scanner checks (owner, script hash, amount) passes for it."""

    def _wallet_and_txs(self, tmp_path, monkeypatch):
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        nft_tx, nft_ref = _nft(w, 0, 0, "ab")
        ft_tx, ft_ref = _ft(w, 0, 0, "cd", 5_000)
        spent_tx, spent_ref = _ft(w, 0, 0, "ef", 9_000)  # a different ref, so a different tx
        return mnemonic, first, (nft_tx, nft_ref), (ft_tx, ft_ref), (spent_tx, spent_ref)

    # -- honest paths

    def test_two_operators_that_agree_confirm_every_row(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, nft_ref), (ft_tx, ft_ref), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        inv, a, b = _ElectrumX(held), _ElectrumX(held), _ElectrumX(held)
        machine = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", pair=(a, b))
        assert machine.exit_code == 0, (machine.output, machine.exception)
        rows = _json(machine)
        assert sorted(r["ref"] for r in rows) == sorted([nft_ref, ft_ref])
        assert {r["spent_status_source"] for r in rows} == {"two-operators"}
        human = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", mode="human", pair=(a, b))
        assert human.exit_code == 0, (human.output, human.exception)
        assert _shown(human).splitlines()[-1] == (
            f"Note: two ElectrumX operators ({_A} and {_B}) each list "
            "these outputs as unspent. That is their word, not a proof: two operators can agree and both be wrong."
        )
        assert "DISPUTED" not in human.output

    def test_servers_that_spell_txids_in_different_cases_agree(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        result = _run(
            tmp_path,
            monkeypatch,
            _ElectrumX(held),
            mnemonic,
            "glyph",
            "list",
            pair=(_UpperCase(held), _ElectrumX(held)),
        )
        assert result.exit_code == 0, (result.output, result.exception)
        assert {r["spent_status_source"] for r in _json(result)} == {"two-operators"}

    def test_a_delegate_token_both_list_is_no_dispute(self, tmp_path, monkeypatch) -> None:
        """An output the inventory listed but did not return as a token (a delegate token) is
        still in its listing: the comparison is of listings, so it is not a withholding."""
        from pyrxd.glyph.script import build_delegate_token_script

        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        nft_tx, _nr = _nft(w, 0, 0, "ab")
        ref = GlyphRef(txid=Txid("12" * 32), vout=0)
        delegate = _paying(build_delegate_token_script(_pkh(w, 0, 0), ref), 1, 400)
        held = {first: [_plain(first), nft_tx, delegate]}
        result = _run(
            tmp_path,
            monkeypatch,
            _ElectrumX(held),
            mnemonic,
            "glyph",
            "list",
            pair=(_ElectrumX(held), _ElectrumX(held)),
        )
        assert result.exit_code == 0, (result.output, result.exception)
        assert len(_json(result)) == 1

    def test_one_operator_unreadable_and_the_other_agreeing_is_one_servers_word(self, tmp_path, monkeypatch) -> None:
        """Not a dispute and not a confirmation: shown, as "server", naming who could not be read."""
        mnemonic, first, (nft_tx, nft_ref), (ft_tx, ft_ref), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        inv, b = _ElectrumX(held), _ElectrumX(held)
        down = _ElectrumX(held, unreadable={first})
        machine = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", pair=(down, b))
        assert machine.exit_code == 0, (machine.output, machine.exception)
        rows = _json(machine)
        assert sorted(r["ref"] for r in rows) == sorted([nft_ref, ft_ref])
        assert {r["spent_status_source"] for r in rows} == {"server"}
        human = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", mode="human", pair=(down, b))
        assert human.exit_code == 0, (human.output, human.exception)
        assert _shown(human).splitlines()[-2:] == [
            _SPENT_NOTE,
            f"({_A} could not be read; {_B} lists the same outputs, but one other operator is not a second opinion.)",
        ]

    def test_neither_operator_readable_is_one_servers_word(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        down = (_ElectrumX(held, unreadable={first}), _ElectrumX(held, unreadable={first}))
        human = _run(tmp_path, monkeypatch, _ElectrumX(held), mnemonic, "glyph", "list", mode="human", pair=down)
        assert human.exit_code == 0, (human.output, human.exception)
        assert (
            _shown(human).splitlines()[-1] == f"(neither {_A} nor {_B} could be read, so no second operator was asked.)"
        )

    # -- decoys (re-listed spent outputs)

    def test_an_inventory_decoy_neither_operator_lists_is_caught(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), (spent_tx, _sr) = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        inv = _ElectrumX({first: [_plain(first), nft_tx, ft_tx, spent_tx]})
        machine = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", pair=(_ElectrumX(held), _ElectrumX(held)))
        assert machine.exit_code == 2, machine.output
        assert _shown(machine) == "", "no rows, not even '[]'"
        assert "the ElectrumX servers disagree" in machine.output
        assert f"{spent_tx.txid()}:0" in machine.output, "the error names the disputed outpoint"
        human = _run(
            tmp_path,
            monkeypatch,
            inv,
            mnemonic,
            "glyph",
            "list",
            mode="human",
            pair=(_ElectrumX(held), _ElectrumX(held)),
        )
        assert human.exit_code == 2, human.output
        assert _disputed(human) == [
            f"DISPUTED: {spent_tx.txid()}:0 is listed as unspent by {_INV} but not by {_A} or {_B}"
        ]

    def test_a_decoy_only_the_second_operator_lists_is_caught(self, tmp_path, monkeypatch) -> None:
        """The second operator alone re-lists a spent output. Nothing else differs."""
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), (spent_tx, _sr) = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        liar = _ElectrumX({first: [_plain(first), nft_tx, ft_tx, spent_tx]})
        result = _run(
            tmp_path,
            monkeypatch,
            _ElectrumX(held),
            mnemonic,
            "glyph",
            "list",
            mode="human",
            pair=(_ElectrumX(held), liar),
        )
        assert result.exit_code == 2, result.output
        assert _disputed(result) == [
            f"DISPUTED: {spent_tx.txid()}:0 is listed as unspent by {_B} but not by {_INV} or {_A}"
        ]

    def test_a_decoy_only_the_first_operator_lists_is_caught(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), (spent_tx, _sr) = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        liar = _ElectrumX({first: [_plain(first), nft_tx, ft_tx, spent_tx]})
        result = _run(
            tmp_path,
            monkeypatch,
            _ElectrumX(held),
            mnemonic,
            "glyph",
            "list",
            mode="human",
            pair=(liar, _ElectrumX(held)),
        )
        assert result.exit_code == 2, result.output
        assert _disputed(result) == [
            f"DISPUTED: {spent_tx.txid()}:0 is listed as unspent by {_A} but not by {_INV} or {_B}"
        ]

    # -- withholdings (5.1)

    def test_a_token_the_inventory_leaves_out_but_both_operators_list_is_caught(self, tmp_path, monkeypatch) -> None:
        """Review 5.1: the inventory withholds the NFT; both operators list it. Before the fix the
        FT row was stamped "two-operators" and the NFT was silently missing."""
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        inv = _ElectrumX({first: [_plain(first), ft_tx]})
        machine = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", pair=(_ElectrumX(held), _ElectrumX(held)))
        assert machine.exit_code == 2, machine.output
        assert _shown(machine) == ""
        human = _run(
            tmp_path,
            monkeypatch,
            inv,
            mnemonic,
            "glyph",
            "list",
            mode="human",
            pair=(_ElectrumX(held), _ElectrumX(held)),
        )
        assert human.exit_code == 2, human.output
        assert _disputed(human) == [
            f"DISPUTED: {nft_tx.txid()}:0 is listed as unspent by {_A} and {_B} but not by {_INV}"
        ]

    def test_the_first_operator_serving_the_inventory_and_withholding_is_caught(self, tmp_path, monkeypatch) -> None:
        """One fake is both the inventory and the first operator, and it withholds the NFT from
        both; the second operator lists it."""
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        liar = _ElectrumX({first: [_plain(first), ft_tx]})
        honest = _ElectrumX({first: [_plain(first), nft_tx, ft_tx]})
        result = _run(tmp_path, monkeypatch, liar, mnemonic, "glyph", "list", mode="human", pair=(liar, honest))
        assert result.exit_code == 2, result.output
        assert _disputed(result) == [
            f"DISPUTED: {nft_tx.txid()}:0 is listed as unspent by {_B} but not by {_INV} or {_A}"
        ]

    # -- one operator unreadable (5.2)

    def test_a_liar_that_fails_its_own_check_is_held_to_the_other_operator(self, tmp_path, monkeypatch) -> None:
        """Review 5.2: the first operator serves a decoy in the inventory, then fails every read on
        its pinned connection. The second operator's answer contradicts the list, and is not
        thrown away: exit 2, naming who could not be read."""
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), (spent_tx, _sr) = self._wallet_and_txs(tmp_path, monkeypatch)
        inv = _ElectrumX({first: [_plain(first), nft_tx, ft_tx, spent_tx]})
        silent = _ElectrumX({first: [_plain(first)]}, unreadable={first})
        honest = _ElectrumX({first: [_plain(first), nft_tx, ft_tx]})
        machine = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", pair=(silent, honest))
        assert machine.exit_code == 2, machine.output
        assert f"{_A} could not be read" in machine.output
        human = _run(tmp_path, monkeypatch, inv, mnemonic, "glyph", "list", mode="human", pair=(silent, honest))
        assert human.exit_code == 2, human.output
        assert _disputed(human) == [f"DISPUTED: {spent_tx.txid()}:0 is listed as unspent by {_INV} but not by {_B}"]

    # -- operators that are not merely unreachable (5.4, 5.5) and bugs (P07)

    @pytest.mark.parametrize("fake", [_PinFails, _WrongChain], ids=["tls-pin", "wrong-chain"])
    def test_an_operator_that_is_not_the_configured_server_refuses_the_list(self, tmp_path, monkeypatch, fake) -> None:
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        for mode in ("json", "human"):
            result = _run(
                tmp_path,
                monkeypatch,
                _ElectrumX(held),
                mnemonic,
                "glyph",
                "list",
                mode=mode,
                pair=(_ElectrumX(held), fake(held)),
            )
            assert result.exit_code == 2, result.output
            assert _shown(result) == ""
            assert f"the ElectrumX operator {_B} is not the server configured for it" in result.output

    def test_a_bug_in_the_second_read_is_not_taken_as_unreachable(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, _nr), (ft_tx, _fr), _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        held = {first: [_plain(first), nft_tx, ft_tx]}
        result = _run(
            tmp_path, monkeypatch, _ElectrumX(held), mnemonic, "glyph", "list", pair=(_ElectrumX(held), _Broken(held))
        )
        # The bug path: the exception escapes the command (``main.run`` turns it into exit 4).
        assert isinstance(result.exception, RuntimeError), (result.output, result.exception)
        assert "Note:" not in result.output

    # -- scope

    def test_every_scanned_address_is_asked_about(self, tmp_path, monkeypatch) -> None:
        """The only disagreement is at the SECOND used address, between the operators; the
        inventory is honest. Asking about the first address alone would see none."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        a0, a1 = w.derive_address(0, 0), w.derive_address(0, 1)
        nft_tx, _ref = _nft(w, 0, 0, "ab")
        spent_tx, _sref = _ft(w, 0, 1, "cd", 7_000)
        honest = {a0: [_plain(a0), nft_tx], a1: [_plain(a1, salt=2)]}
        liar = _ElectrumX({a0: [_plain(a0), nft_tx], a1: [_plain(a1, salt=2), spent_tx]})
        result = _run(
            tmp_path,
            monkeypatch,
            _ElectrumX(honest),
            mnemonic,
            "glyph",
            "list",
            mode="human",
            pair=(liar, _ElectrumX(honest)),
        )
        assert result.exit_code == 2, result.output
        assert _disputed(result) == [
            f"DISPUTED: {spent_tx.txid()}:0 is listed as unspent by {_A} but not by {_INV} or {_B}"
        ]

    def test_the_disputed_lines_are_capped(self, tmp_path, monkeypatch) -> None:
        mnemonic, first, (nft_tx, _nr), _ft_pair, _spent = self._wallet_and_txs(tmp_path, monkeypatch)
        w = HdWallet.from_mnemonic(mnemonic)
        decoys = [
            _paying(build_ft_locking_script(_pkh(w, 0, 0), GlyphRef(txid=Txid(f"{i:064x}"), vout=0)), 10, 500 + i)
            for i in range(25)
        ]
        held = {first: [_plain(first), nft_tx]}
        liar = _ElectrumX({first: [_plain(first), nft_tx, *decoys]})
        result = _run(
            tmp_path,
            monkeypatch,
            _ElectrumX(held),
            mnemonic,
            "glyph",
            "list",
            mode="human",
            pair=(_ElectrumX(held), liar),
        )
        assert result.exit_code == 2, result.output
        lines = _disputed(result)
        assert len(lines) == 21 and lines[-1] == "DISPUTED: ... and 5 more"


class TestTheOperatorPair:
    """``CliContext.make_operator_pair`` gives two operators or none, counted by source."""

    def _ctx(self, tmp_path, monkeypatch, body: str, network: str = "mainnet", override: str | None = None):
        from pyrxd.cli import config as cfg_mod

        for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX"):
            monkeypatch.delenv(var, raising=False)
        path = tmp_path / "config.toml"
        path.write_text(body)
        return CliContext(config=cfg_mod.load(path).for_network(network, electrumx_override=override))

    def test_the_shipped_mainnet_default_is_two_operators(self, tmp_path, monkeypatch) -> None:
        from pyrxd.network.registry import default_endpoints
        from pyrxd.network.source_identity import source_key

        pair = self._ctx(tmp_path, monkeypatch, "").make_operator_pair()
        assert pair is not None
        (_la, a), (_lb, b) = pair
        sources_a = {e.source for e in a.profile.endpoints}
        sources_b = {e.source for e in b.profile.endpoints}
        assert len(sources_a) == 1 and len(sources_b) == 1 and sources_a != sources_b
        # Every shipped endpoint of each of the two operators, and nothing of the other's.
        shipped = default_endpoints("mainnet")
        assert {e.url for e in a.profile.endpoints} == {u for u in shipped if source_key(u) in sources_a}
        assert {e.url for e in b.profile.endpoints} == {u for u in shipped if source_key(u) in sources_b}

    def test_one_url_on_the_command_line_is_no_pair(self, tmp_path, monkeypatch) -> None:
        ctx = self._ctx(tmp_path, monkeypatch, "", override="wss://one.example:50022")
        assert ctx.make_operator_pair() is None

    def test_two_urls_of_one_operator_are_no_pair(self, tmp_path, monkeypatch) -> None:
        body = 'electrumx_servers = ["wss://a.example.com:50022", "wss://b.example.com:50022"]\n'
        assert self._ctx(tmp_path, monkeypatch, body).make_operator_pair() is None

    def test_two_declared_operators_are_a_pair(self, tmp_path, monkeypatch) -> None:
        body = (
            'electrumx_servers = [{ url = "wss://a.example.com:50022", operator = "alice" }, '
            '{ url = "wss://b.example.com:50022", operator = "bob" }]\n'
        )
        pair = self._ctx(tmp_path, monkeypatch, body).make_operator_pair()
        assert pair is not None
        assert [label for label, _c in pair] == ["wss://a.example.com:50022", "wss://b.example.com:50022"]

    def test_labels_are_redacted(self, tmp_path, monkeypatch) -> None:
        """A label is printed: an endpoint's credentials and path never reach it."""
        body = (
            'electrumx_servers = [{ url = "wss://user:hunter2@a.example.com:50022/k3y", operator = "alice" }, '
            '{ url = "wss://b.example.com:50022/?token=s3cret", operator = "bob" }]\n'
        )
        pair = self._ctx(tmp_path, monkeypatch, body).make_operator_pair()
        assert pair is not None
        assert [label for label, _c in pair] == ["wss://a.example.com:50022", "wss://b.example.com:50022"]

    def test_an_injected_client_factory_is_no_pair(self, tmp_path, monkeypatch) -> None:
        ctx = self._ctx(tmp_path, monkeypatch, "")
        ctx.client_factory = lambda: None  # type: ignore[assignment,return-value]
        assert ctx.make_operator_pair() is None


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


# --------------------------------------------------------------------------- glyph list, the server checked (#782)


def _nft_hash(address: str) -> bytes:
    return bytes(owned_token_script_hashes(Hex20(address_to_public_key_hash(address)))[0])


class TestGlyphListChecksTheServer:
    """``glyph list`` used to print another key's token, and an FT amount the server made up, with
    exit 0. Each refusal has its honest twin: the wallet's own tokens, listed with the amounts
    their transactions pay."""

    @pytest.mark.parametrize("kind", ["nft", "ft"])
    def test_another_keys_token_is_not_listed_as_the_wallets(self, tmp_path, monkeypatch, kind) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        stranger = Hex20(PrivateKey().public_key().hash160())
        ref = GlyphRef(txid=Txid("ab" * 32), vout=0)
        builder = build_nft_locking_script if kind == "nft" else build_ft_locking_script
        theirs = _paying(builder(stranger, ref), 5_000, 300)
        ours_hash = bytes(
            owned_token_script_hashes(Hex20(address_to_public_key_hash(first)))[0 if kind == "nft" else 1]
        )
        server = _ElectrumX({first: [_plain(first)]}, misfiled={ours_hash: [theirs]})
        for mode in ("json", "human"):
            result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list", mode=mode)
            assert result.exit_code == 2, result.output
            assert _shown(result) == "", "nothing listed, not even '[]'"
            assert "server inconsistency" in result.output
            assert f"that {kind} output is owned by another key ({stranger.hex()}" in result.output

    @pytest.mark.parametrize("kind", ["nft", "ft"])
    def test_the_wallets_own_token_is_listed(self, tmp_path, monkeypatch, kind) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        tx, ref = _nft(w, 0, 0, "ab") if kind == "nft" else _ft(w, 0, 0, "ab", 5_000)
        server = _ElectrumX({first: [_plain(first), tx]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        amount = "1" if kind == "nft" else "5000"
        assert [(r["type"], r["ref"], r["address"], r["amount"]) for r in _json(result)] == [
            (kind.upper(), ref, first, amount)
        ]

    @pytest.mark.parametrize("reported", [999_999_999, None], ids=["inflated", "honest"])
    def test_an_ft_amount_is_what_its_transaction_pays(self, tmp_path, monkeypatch, reported) -> None:
        """The transaction pays 5,000 units. A server reporting 999,999,999 used to be believed."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        ft_tx, ref = _ft(w, 0, 0, "cd", 5_000)
        values = {} if reported is None else {ft_tx.txid(): reported}
        server = _ElectrumX({first: [_plain(first), ft_tx]}, values=values)
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        assert [(r["ref"], r["amount"]) for r in _json(result)] == [(ref, "5000")]

    def test_an_outpoint_not_at_the_address_is_refused(self, tmp_path, monkeypatch) -> None:
        """The server lists, under the address's NFT hash, an output that is not there: here a
        plain payment to the same address, so there is no token owner to compare."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        first = w.derive_address(0, 0)
        elsewhere = _plain(first, 1_234, salt=9)
        server = _ElectrumX({first: [_plain(first)]}, misfiled={_nft_hash(first): [elsewhere]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 2, result.output
        assert _shown(result) == ""
        assert "server inconsistency" in result.output
        assert "but its output is not there" in result.output

    def test_an_address_holding_only_a_token_is_listed(self, tmp_path, monkeypatch) -> None:
        """#787: the address holds the NFT and no plain output, so its P2PKH hash has no history.
        The scan reads its token hashes, marks it used, and ``glyph list`` reads it."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_tx, ref = _nft(w, 0, 0, "ab")
        first = w.derive_address(0, 0)
        server = _ElectrumX({first: [nft_tx]})
        assert bytes(script_hash_for_address(first)) not in server.held, "the P2PKH hash must be empty"
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        assert [(r["ref"], r["address"]) for r in _json(result)] == [(ref, first)]

    def test_a_token_only_address_past_index_zero_is_listed(self, tmp_path, monkeypatch) -> None:
        """The same at index 3, with indexes 0 to 2 empty: within the gap, so the scan reaches it."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        nft_tx, ref = _nft(w, 0, 3, "ab")
        server = _ElectrumX({w.derive_address(0, 3): [nft_tx]})
        result = _run(tmp_path, monkeypatch, server, mnemonic, "glyph", "list")
        assert result.exit_code == 0, (result.output, result.exception)
        assert [(r["ref"], r["address"]) for r in _json(result)] == [(ref, w.derive_address(0, 3))]

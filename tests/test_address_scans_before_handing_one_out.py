"""``pyrxd address`` scans the chain before it hands out an address (#781).

``address`` with no ``--index`` picked the first address the wallet FILE did not mark used. Only
the gap-limit scan (``HdWallet.refresh``) marks an address used, and no command saves a scan (#768
and #779 made the spend and read paths scan, without saving). So on a ``pyrxd wallet new`` file,
``address`` printed index 0 every time, including after index 0 was paid: address reuse. The same
held for ``--change``. It now runs the scan first and prints the first address on the chain with
no history; a scan that cannot finish exits 2 and prints no address.

Every test drives the real command on the real ``pyrxd wallet new`` file, with the mnemonic typed
at the real prompt. The one fake is the ElectrumX client, swapped in at ``CliContext.make_client``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.security.errors import NetworkError


class _ElectrumX:
    """Stands in for the ElectrumX client: history, and UTXOs.

    *history* maps an address to the txids in its history; *utxos* maps an address to the
    txids of the outputs it still holds. An address paid and then spent from appears in
    *history* and not in *utxos*: that is the case a check on UTXOs, rather than on history,
    would take for unused. ``history_fails_after=n`` answers *n* history reads and fails every
    later one (a connection lost mid-scan).
    """

    def __init__(
        self,
        history: dict[str, list[str]] | None = None,
        utxos: dict[str, list[str]] | None = None,
        *,
        history_fails_after: int | None = None,
    ) -> None:
        self.history = {bytes(script_hash_for_address(a)): txids for a, txids in (history or {}).items()}
        self.utxos = {bytes(script_hash_for_address(a)): txids for a, txids in (utxos or {}).items()}
        self.history_fails_after = history_fails_after
        self.history_reads = 0

    async def __aenter__(self) -> _ElectrumX:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get_history(self, script_hash):
        self.history_reads += 1
        if self.history_fails_after is not None and self.history_reads > self.history_fails_after:
            raise NetworkError("simulated: the server dropped the connection mid-scan")
        return [{"tx_hash": txid, "height": 1} for txid in self.history.get(bytes(script_hash), [])]

    async def get_utxos(self, script_hash):
        return [
            UtxoRecord(tx_hash=txid, tx_pos=0, value=100_000, height=1)
            for txid in self.utxos.get(bytes(script_hash), [])
        ]

    async def get_balance(self, script_hash):
        return 100_000 * len(self.utxos.get(bytes(script_hash), [])), 0


def _txid(n: int) -> str:
    return f"{n:064x}"


def _funded(*addresses: str) -> _ElectrumX:
    """Each address paid once and still holding it."""
    return _ElectrumX(
        history={a: [_txid(i + 1)] for i, a in enumerate(addresses)},
        utxos={a: [_txid(i + 1)] for i, a in enumerate(addresses)},
    )


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
    """``pyrxd address`` against the real wallet file. Only the transport is swapped."""
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    return CliRunner().invoke(cli, [*_base(tmp_path, mode), "address", *args], input=mnemonic + "\n")


def _shown(result) -> str:
    """What the command printed on stdout, less the hidden mnemonic prompt."""
    return result.stdout.split("Mnemonic (input hidden): ", 1)[-1].strip()


def _answer(result) -> dict:
    assert result.exit_code == 0, (result.output, result.exception)
    return json.loads(_shown(result))


def _at(w: HdWallet, change: int, index: int) -> dict:
    return {"address": w.derive_address(change, index), "path": f"m/44'/512'/0'/{change}/{index}", "network": "mainnet"}


# --------------------------------------------------------------------------- the receive chain


class TestAddressSkipsWhatTheChainHasSeen:
    def test_a_funded_first_address_is_not_handed_out_again(self, tmp_path, monkeypatch) -> None:
        """#781's case: index 0 paid, the file never marked it used, so the old answer was 0."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, _funded(w.derive_address(0, 0)), mnemonic)
        assert _answer(result) == _at(w, 0, 1)

    def test_an_address_spent_from_is_used_though_it_holds_nothing(self, tmp_path, monkeypatch) -> None:
        """Paid, then spent from: history, and no UTXO. It is still used; judging by UTXOs or
        by balance would hand it out again."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        spent = w.derive_address(0, 0)
        server = _ElectrumX(history={spent: [_txid(1), _txid(2)]}, utxos={})
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic)) == _at(w, 0, 1)

    def test_nothing_on_chain_gives_index_zero(self, tmp_path, monkeypatch) -> None:
        """The honest path: a scan that read every address and found no history."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _ElectrumX()
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic)) == _at(w, 0, 0)
        assert server.history_reads == 40, "the scan reads 20 addresses on each chain before it stops"

    def test_funds_past_the_first_gap_window_are_found(self, tmp_path, monkeypatch) -> None:
        """Indices 0..20 all paid: 21 addresses, one more than the first window of 20. The scan
        extends past it, and the answer is 21."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _funded(*(w.derive_address(0, i) for i in range(21)))
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic)) == _at(w, 0, 21)

    def test_an_unused_address_below_a_used_one_is_the_answer(self, tmp_path, monkeypatch) -> None:
        """Indices 0 and 2 paid, 1 never: 1 has no history, so it is the first unused address,
        and handing it out reuses nothing."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _funded(w.derive_address(0, 0), w.derive_address(0, 2))
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic)) == _at(w, 0, 1)

    def test_history_past_the_gap_limit_is_not_seen(self, tmp_path, monkeypatch) -> None:
        """The window's edge: nothing at 0..19, history at 20. BIP44 stops after 20 unused in a
        row, so 20 is never read and 0, which has no history, is the answer."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _funded(w.derive_address(0, 20))
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic)) == _at(w, 0, 0)

    @pytest.mark.parametrize("mode", ["human", "quiet"])
    def test_every_output_mode_gets_the_scanned_answer(self, tmp_path, monkeypatch, mode) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        result = _run(tmp_path, monkeypatch, _funded(w.derive_address(0, 0)), mnemonic, mode=mode)
        assert result.exit_code == 0, (result.output, result.exception)
        assert w.derive_address(0, 1) in _shown(result)
        assert w.derive_address(0, 0) not in _shown(result)


# --------------------------------------------------------------------------- the change chain


class TestChangeSkipsWhatTheChainHasSeen:
    def test_a_funded_change_address_is_not_handed_out_again(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _funded(w.derive_address(1, 0))
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic, "--change")) == _at(w, 1, 1)

    def test_a_change_address_spent_from_is_used(self, tmp_path, monkeypatch) -> None:
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _ElectrumX(history={w.derive_address(1, 0): [_txid(1), _txid(2)]})
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic, "--change")) == _at(w, 1, 1)

    def test_each_chain_answers_from_its_own_history(self, tmp_path, monkeypatch) -> None:
        """Receive index 0 and 1 paid, change untouched: the receive answer moves, change stays at 0."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _funded(w.derive_address(0, 0), w.derive_address(0, 1))
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic)) == _at(w, 0, 2)
        assert _answer(_run(tmp_path, monkeypatch, server, mnemonic, "--change")) == _at(w, 1, 0)


# --------------------------------------------------------------------------- refusals, and what is not touched


class TestAnAddressNotProvenUnusedIsNotHandedOut:
    @pytest.mark.parametrize("mode", ["json", "human", "quiet"])
    @pytest.mark.parametrize("change", [False, True])
    def test_a_read_failure_mid_scan_prints_no_address(self, tmp_path, monkeypatch, mode, change) -> None:
        """Five history reads, then the connection drops. Whatever the scan read so far, no
        address is printed, in any mode, and the command exits 2."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        server = _ElectrumX(history={w.derive_address(0, 0): [_txid(1)]}, history_fails_after=5)
        args = ("--change",) if change else ()
        result = _run(tmp_path, monkeypatch, server, mnemonic, *args, mode=mode)
        assert result.exit_code == 2, result.output
        assert "could not reach ElectrumX" in result.stderr
        assert _shown(result) == "", "a failed scan must print no address at all"

    def test_a_failure_on_the_last_read_still_refuses(self, tmp_path, monkeypatch) -> None:
        """Every read answered but the last one of the change chain: the receive chain was fully
        read, but the scan did not finish, so nothing is printed."""
        mnemonic, _w = _new_wallet(tmp_path, monkeypatch)
        server = _ElectrumX(history_fails_after=39)
        result = _run(tmp_path, monkeypatch, server, mnemonic)
        assert result.exit_code == 2, result.output
        assert _shown(result) == ""

    @pytest.mark.parametrize("change", [False, True])
    def test_index_reads_nothing_from_the_network(self, tmp_path, monkeypatch, change) -> None:
        """``--index N`` is an explicit request: it derives that address with no scan."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)

        def _no_network(self):
            raise AssertionError("--index must not open a client")

        monkeypatch.setattr(CliContext, "make_client", _no_network)
        args = ["address", "--index", "3", *(["--change"] if change else [])]
        result = CliRunner().invoke(cli, [*_base(tmp_path, "json"), *args], input=mnemonic + "\n")
        assert _answer(result) == _at(w, 1 if change else 0, 3)

    def test_the_scan_is_not_saved(self, tmp_path, monkeypatch) -> None:
        """As in #768 and #779: the wallet file is byte-for-byte unchanged."""
        mnemonic, w = _new_wallet(tmp_path, monkeypatch)
        before = (tmp_path / "wallet.dat").read_bytes()
        server = _funded(w.derive_address(0, 0), w.derive_address(1, 0))
        for args in ((), ("--change",)):
            assert _run(tmp_path, monkeypatch, server, mnemonic, *args).exit_code == 0, args
        assert (tmp_path / "wallet.dat").read_bytes() == before

    def test_help_says_it_scans(self) -> None:
        text = " ".join(CliRunner().invoke(cli, ["address", "--help"]).output.split())
        assert "no chain history, after a gap-limit scan" in text
        assert "Reads nothing from the network" in text

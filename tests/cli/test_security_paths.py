"""CLI security-path coverage (docs/cli-security-backlog.md priorities).

Targets the paths the backlog names as security-relevant but which had no
behavioral tests:

* ``wallet send`` **in-process fallback** (#8) — the mnemonic re-entry path
  taken when no agent is unlocked: happy path, empty/wrong mnemonic, user
  decline, no-funds. Wrong-mnemonic output must never echo the input back.
* ``agent unlock`` **lifecycle** (#8) — mnemonic → decrypt → daemon serve →
  lock-on-exit (both the clean return and the Ctrl-C path must zeroize).
* **query commands' shared ``_load_wallet``** — passphrase branch, internal
  (change) chain walk, balance/utxos query bodies, and the ElectrumX
  boundary error (no stack trace, no input echo, without ``--debug``).
* ``errors.py`` debug-flag plumbing and the three-line error block.

The mnemonic below is the canonical BIP39 test vector already used across
tests/cli/ — a published, fundless vector, never a hand-written key.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.cli.agent_cmds import agent_group
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.errors import CliError, is_debug, render_error, set_debug
from pyrxd.cli.query_cmds import address_cmd, balance_cmd, utxos_cmd
from pyrxd.cli.wallet_cmds import wallet_group
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import NetworkError, UtxoRecord, script_hash_for_address
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DEST = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
WRONG_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _ctx(
    wallet_path: Path,
    client: MagicMock | None = None,
    *,
    output_mode: str = "human",
    yes: bool = False,
) -> CliContext:
    return CliContext(
        config=Config(network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=wallet_path),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=wallet_path,
        output_mode=output_mode,
        yes=yes,
        client_factory=(lambda: client) if client is not None else None,
    )


def _saved_wallet(path: Path) -> HdWallet:
    wallet = HdWallet.from_mnemonic(MNEMONIC)
    wallet.save(path)
    return wallet


def _funded_client_for(addr: str, *, value: int = 100_000_000) -> MagicMock:
    """Mock ElectrumX where *addr* has history + one UTXO paying it."""
    src = Transaction()
    src.add_output(TransactionOutput(P2PKH().lock(addr), value))
    src_txid = src.txid()
    target_sh = script_hash_for_address(addr)

    async def _history(sh):
        return [{"tx_hash": src_txid}] if sh == target_sh else []

    async def _utxos(sh):
        return [UtxoRecord(tx_hash=src_txid, tx_pos=0, value=value, height=800_000)] if sh == target_sh else []

    async def _get_tx(_txid):
        return src.serialize()

    client = MagicMock()
    client.get_history = _history
    client.get_utxos = _utxos
    client.get_transaction = _get_tx
    client.get_balance = AsyncMock(return_value=(value, 0))
    client.broadcast = AsyncMock(return_value="cd" * 32)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


# ═══════════════════════════════════════════════════════════════════════════════
# wallet send — in-process mnemonic-re-entry fallback (#8)
# ═══════════════════════════════════════════════════════════════════════════════


class TestSendInProcessFallback:
    def test_happy_path_signs_and_broadcasts(self, runner: CliRunner, tmp_path: Path) -> None:
        wallet = _saved_wallet(tmp_path / "wallet.dat")
        client = _funded_client_for(wallet._derive_address(0, 0))
        ctx = _ctx(tmp_path / "wallet.dat", client, yes=True)
        result = runner.invoke(
            wallet_group,
            ["send", "--to", DEST, "--amount", "10000000"],
            obj=ctx,
            input=f"{MNEMONIC}\n",
        )
        assert result.exit_code == 0, result.output
        assert "in-process" in result.output
        client.broadcast.assert_awaited_once()

    def test_empty_mnemonic_is_rejected(self, runner: CliRunner, tmp_path: Path) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        client = _funded_client_for(DEST)
        ctx = _ctx(tmp_path / "wallet.dat", client, yes=True)
        result = runner.invoke(
            wallet_group, ["send", "--to", DEST, "--amount", "10000000"], obj=ctx, input="\n"
        )
        assert result.exit_code != 0
        assert "mnemonic is required" in result.output
        client.broadcast.assert_not_awaited()

    def test_wrong_mnemonic_fails_without_echoing_input(self, runner: CliRunner, tmp_path: Path) -> None:
        """Decrypt failure must not leak which words the user typed (#9
        output-snapshot hygiene: result.output is exactly what a pytest
        traceback or CI log would capture)."""
        _saved_wallet(tmp_path / "wallet.dat")
        client = _funded_client_for(DEST)
        ctx = _ctx(tmp_path / "wallet.dat", client, yes=True)
        result = runner.invoke(
            wallet_group,
            ["send", "--to", DEST, "--amount", "10000000"],
            obj=ctx,
            input=f"{WRONG_MNEMONIC}\n",
        )
        assert result.exit_code != 0
        assert "Could not decrypt" in result.output
        for word in ("legal", "winner", "sausage", "yellow"):
            assert word not in result.output, "typed mnemonic words leaked into CLI output"
        client.broadcast.assert_not_awaited()

    def test_user_decline_aborts_before_broadcast(self, runner: CliRunner, tmp_path: Path) -> None:
        wallet = _saved_wallet(tmp_path / "wallet.dat")
        client = _funded_client_for(wallet._derive_address(0, 0))
        ctx = _ctx(tmp_path / "wallet.dat", client, yes=False)
        result = runner.invoke(
            wallet_group,
            ["send", "--to", DEST, "--amount", "10000000"],
            obj=ctx,
            input=f"{MNEMONIC}\nn\n",
        )
        assert result.exit_code != 0
        assert "aborted by user" in result.output
        client.broadcast.assert_not_awaited()

    def test_no_spendable_funds_is_clean_error(self, runner: CliRunner, tmp_path: Path) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        client = _funded_client_for(DEST)  # funds at an address the wallet doesn't own
        ctx = _ctx(tmp_path / "wallet.dat", client, yes=True)
        result = runner.invoke(
            wallet_group,
            ["send", "--to", DEST, "--amount", "10000000"],
            obj=ctx,
            input=f"{MNEMONIC}\n",
        )
        assert result.exit_code != 0
        assert "no spendable funds" in result.output
        client.broadcast.assert_not_awaited()


# ═══════════════════════════════════════════════════════════════════════════════
# agent unlock — mnemonic → daemon → lock-on-exit (#8)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAgentUnlockLifecycle:
    @pytest.fixture
    def daemon_cls(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        """Replace AgentDaemon with a mock and neutralize the process-global
        signal/atexit hooks the command installs."""
        daemon_cls = MagicMock()
        monkeypatch.setattr("pyrxd.cli.agent_cmds.AgentDaemon", daemon_cls)
        monkeypatch.setattr("pyrxd.cli.agent_cmds.signal", MagicMock())
        monkeypatch.setattr("pyrxd.cli.agent_cmds.atexit", MagicMock())
        return daemon_cls

    def test_unlock_serves_then_reports_locked(
        self, runner: CliRunner, tmp_path: Path, daemon_cls: MagicMock
    ) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        ctx = _ctx(tmp_path / "wallet.dat")
        result = runner.invoke(agent_group, ["unlock"], obj=ctx, input=f"{MNEMONIC}\n")
        assert result.exit_code == 0, result.output
        assert "unlocked" in result.output
        assert "agent locked (seed zeroized)" in result.output
        daemon_cls.return_value.serve_forever.assert_called_once()
        # Socket must live next to the wallet file, not in a world-visible tmp.
        assert str(tmp_path) in str(daemon_cls.call_args.kwargs["socket_path"])

    def test_unlock_ctrl_c_still_zeroizes(
        self, runner: CliRunner, tmp_path: Path, daemon_cls: MagicMock
    ) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        daemon_cls.return_value.serve_forever.side_effect = KeyboardInterrupt
        ctx = _ctx(tmp_path / "wallet.dat")
        result = runner.invoke(agent_group, ["unlock"], obj=ctx, input=f"{MNEMONIC}\n")
        assert "agent locked (seed zeroized)" in result.output
        daemon_cls.return_value.lock.assert_called()

    def test_unlock_empty_mnemonic_rejected(
        self, runner: CliRunner, tmp_path: Path, daemon_cls: MagicMock
    ) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        ctx = _ctx(tmp_path / "wallet.dat")
        result = runner.invoke(agent_group, ["unlock"], obj=ctx, input="\n")
        assert result.exit_code != 0
        assert "mnemonic is required" in result.output
        daemon_cls.assert_not_called()

    def test_unlock_wrong_mnemonic_no_echo(
        self, runner: CliRunner, tmp_path: Path, daemon_cls: MagicMock
    ) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        ctx = _ctx(tmp_path / "wallet.dat")
        result = runner.invoke(agent_group, ["unlock"], obj=ctx, input=f"{WRONG_MNEMONIC}\n")
        assert result.exit_code != 0
        assert "Could not decrypt" in result.output
        for word in ("legal", "winner", "sausage", "yellow"):
            assert word not in result.output
        daemon_cls.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════════
# Query commands — the shared mnemonic prompt surface
# ═══════════════════════════════════════════════════════════════════════════════


class TestQueryCommandPaths:
    def test_address_with_passphrase_prompt(self, runner: CliRunner, tmp_path: Path) -> None:
        """--passphrase adds a second hidden prompt; a wallet saved without a
        passphrase must fail to decrypt under a non-empty one (and never echo
        either secret)."""
        _saved_wallet(tmp_path / "wallet.dat")
        ctx = _ctx(tmp_path / "wallet.dat")
        result = runner.invoke(
            address_cmd, ["--index", "0", "--passphrase"], obj=ctx, input=f"{MNEMONIC}\nhunter2\n"
        )
        assert result.exit_code != 0
        assert "Could not decrypt" in result.output
        assert "hunter2" not in result.output

    def test_address_next_on_change_chain(self, runner: CliRunner, tmp_path: Path) -> None:
        _saved_wallet(tmp_path / "wallet.dat")
        ctx = _ctx(tmp_path / "wallet.dat", output_mode="json")
        result = runner.invoke(address_cmd, ["--change"], obj=ctx, input=f"{MNEMONIC}\n")
        assert result.exit_code == 0, result.output
        assert "'/1/" in result.output  # internal (change) chain path

    def test_balance_refresh_reports_confirmed(self, runner: CliRunner, tmp_path: Path) -> None:
        wallet = _saved_wallet(tmp_path / "wallet.dat")
        client = _funded_client_for(wallet._derive_address(0, 0))
        ctx = _ctx(tmp_path / "wallet.dat", client, output_mode="json")
        result = runner.invoke(balance_cmd, ["--refresh"], obj=ctx, input=f"{MNEMONIC}\n")
        assert result.exit_code == 0, result.output
        assert '"confirmed_photons": 100000000' in result.output

    def test_balance_network_error_is_boundary_error(self, runner: CliRunner, tmp_path: Path) -> None:
        """ElectrumX failure surfaces as the three-line boundary error —
        no traceback, no mnemonic echo (without --debug)."""
        _saved_wallet(tmp_path / "wallet.dat")
        client = MagicMock()
        client.__aenter__ = AsyncMock(side_effect=NetworkError("boom"))
        client.__aexit__ = AsyncMock(return_value=None)
        ctx = _ctx(tmp_path / "wallet.dat", client)
        result = runner.invoke(balance_cmd, [], obj=ctx, input=f"{MNEMONIC}\n")
        assert result.exit_code != 0
        assert "could not reach ElectrumX" in result.output
        assert "Traceback" not in result.output
        assert "abandon" not in result.output

    def test_utxos_lists_and_filters(self, runner: CliRunner, tmp_path: Path) -> None:
        # utxos_cmd queries the wallet's KNOWN used addresses (no implicit
        # rescan), so persist the funded address as used before invoking.
        from pyrxd.hd.wallet import AddressRecord

        wallet = HdWallet.from_mnemonic(MNEMONIC)
        funded = wallet._derive_address(0, 0)
        wallet.addresses[wallet._path_key(0, 0)] = AddressRecord(address=funded, change=0, index=0, used=True)
        wallet.save(tmp_path / "wallet.dat")
        client = _funded_client_for(funded)
        ctx = _ctx(tmp_path / "wallet.dat", client, output_mode="json")
        result = runner.invoke(utxos_cmd, [], obj=ctx, input=f"{MNEMONIC}\n")
        assert result.exit_code == 0, result.output
        assert "100000000" in result.output
        # A min-photons filter above the UTXO value must yield an empty list.
        client2 = _funded_client_for(funded)
        ctx2 = _ctx(tmp_path / "wallet.dat", client2, output_mode="json")
        result2 = runner.invoke(
            utxos_cmd, ["--min-photons", "200000000"], obj=ctx2, input=f"{MNEMONIC}\n"
        )
        assert result2.exit_code == 0, result2.output
        assert "100000000" not in result2.output


# ═══════════════════════════════════════════════════════════════════════════════
# errors.py — debug plumbing + error block shape
# ═══════════════════════════════════════════════════════════════════════════════


class TestErrorPlumbing:
    def test_set_debug_roundtrip(self) -> None:
        original = is_debug()
        try:
            set_debug(True)
            assert is_debug() is True
            set_debug(False)
            assert is_debug() is False
        finally:
            set_debug(original)

    def test_exit_code_override(self) -> None:
        err = CliError("msg", exit_code=42)
        assert err.exit_code == 42

    def test_render_error_three_line_block(self) -> None:
        err = CliError("bad thing", cause="the reason", fix="do this instead")
        block = render_error(err)
        assert "error: bad thing" in block
        assert "cause: the reason" in block
        assert "do this instead" in block

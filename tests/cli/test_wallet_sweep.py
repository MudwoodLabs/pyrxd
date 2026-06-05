"""Tests for `pyrxd wallet sweep` — move funds from a derived path (value-bearing)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.wallet_cmds import wallet_group
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# A valid, unrelated P2PKH destination (the canonical abandon-seed coin-0 address).
DEST = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _addr(coin_type: int, account: int, change: int, index: int) -> str:
    w = HdWallet.from_mnemonic(MNEMONIC, account=account, coin_type=coin_type)
    return w._derive_address(change, index)


def _funded_client(funded_addr: str | None, *, value: int = 100_000_000) -> MagicMock:
    """Mock ElectrumX: *funded_addr* has history + one UTXO; everything else empty."""
    from pyrxd.network.electrumx import script_hash_for_address

    async def _get_history(script_hash):
        if funded_addr and script_hash_for_address(funded_addr) == script_hash:
            return [{"tx_hash": "ab" * 32, "height": 800000}]
        return []

    async def _get_utxos(script_hash):
        if funded_addr and script_hash_for_address(funded_addr) == script_hash:
            return [UtxoRecord(tx_hash="ab" * 32, tx_pos=0, value=value, height=800000)]
        return []

    client = MagicMock()
    client.get_history = _get_history
    client.get_utxos = _get_utxos
    client.get_balance = AsyncMock(return_value=(0, 0))
    client.broadcast = AsyncMock(return_value="cd" * 32)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _ctx(client: MagicMock, *, output_mode: str = "human", yes: bool = False) -> CliContext:
    return CliContext(
        config=Config(
            network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=Path("/tmp/_pyrxd_sweep")
        ),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=Path("/tmp/_pyrxd_sweep"),
        output_mode=output_mode,
        yes=yes,
        client_factory=lambda: client,
    )


def _invoke(runner: CliRunner, ctx: CliContext, args: list[str], *, confirm: str = "y"):
    # Mnemonic at the hidden prompt, then the y/N broadcast confirmation.
    return runner.invoke(wallet_group, args, obj=ctx, input=f"{MNEMONIC}\n{confirm}\n")


class TestWalletSweep:
    def test_sweeps_funded_path_and_broadcasts(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST], confirm="y")
        assert result.exit_code == 0, result.output
        assert "Swept" in result.output
        assert "cdcd" in result.output  # txid prefix
        client.broadcast.assert_awaited_once()

    def test_confirmation_decline_does_not_broadcast(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST], confirm="n")
        assert result.exit_code != 0
        assert "abort" in result.output.lower()
        client.broadcast.assert_not_awaited()

    def test_no_funds_errors_without_broadcast(self, runner: CliRunner) -> None:
        client = _funded_client(None)  # nothing funded anywhere
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST])
        assert result.exit_code != 0
        assert "no spendable funds" in result.output
        client.broadcast.assert_not_awaited()

    def test_invalid_destination_rejected(self, runner: CliRunner) -> None:
        client = _funded_client(None)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", "not-an-address"])
        assert result.exit_code != 0
        assert "invalid --to" in result.output
        client.broadcast.assert_not_awaited()

    def test_json_requires_yes(self, runner: CliRunner) -> None:
        client = _funded_client(_addr(0, 0, 0, 0))
        result = _invoke(runner, _ctx(client, output_mode="json"), ["sweep", "--coin-type", "0", "--to", DEST])
        assert result.exit_code != 0
        assert "--yes" in result.output
        client.broadcast.assert_not_awaited()

    def test_json_with_yes_emits_txid(self, runner: CliRunner) -> None:
        funded = _addr(512, 0, 0, 0)
        client = _funded_client(funded)
        ctx = _ctx(client, output_mode="json", yes=True)
        # --yes skips the confirm prompt; only the mnemonic is read from stdin.
        result = runner.invoke(
            wallet_group, ["sweep", "--coin-type", "512", "--to", DEST], obj=ctx, input=f"{MNEMONIC}\n"
        )
        assert result.exit_code == 0, result.output
        start, end = result.output.find("{"), result.output.rfind("}")
        payload = json.loads(result.output[start : end + 1])
        assert payload["txid"] == "cd" * 32
        assert payload["from_path"] == "m/44'/512'/0'"
        assert payload["to"] == DEST
        client.broadcast.assert_awaited_once()

    def test_invalid_mnemonic_rejected_without_broadcast(self, runner: CliRunner) -> None:
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(
            wallet_group,
            ["sweep", "--coin-type", "0", "--to", DEST],
            obj=_ctx(client),
            input="not a real bip39 mnemonic phrase here\ny\n",
        )
        assert result.exit_code != 0
        client.broadcast.assert_not_awaited()

    def test_empty_mnemonic_rejected(self, runner: CliRunner) -> None:
        client = _funded_client(_addr(0, 0, 0, 0))
        result = runner.invoke(wallet_group, ["sweep", "--coin-type", "0", "--to", DEST], obj=_ctx(client), input="\n")
        assert result.exit_code != 0
        assert "mnemonic is required" in result.output
        client.broadcast.assert_not_awaited()

    def test_negative_coin_type_rejected(self, runner: CliRunner) -> None:
        client = _funded_client(None)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "-1", "--to", DEST])
        assert result.exit_code != 0
        client.broadcast.assert_not_awaited()

    def test_summary_shows_amount_fee_and_destination(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _funded_client(funded)
        result = _invoke(runner, _ctx(client), ["sweep", "--coin-type", "0", "--to", DEST], confirm="y")
        assert "from path:   m/44'/0'/0'" in result.output
        assert "to address:" in result.output
        assert DEST in result.output
        assert "you receive" in result.output

"""Tests for `pyrxd wallet recover --scan` — multi-path recovery CLI."""

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

# Canonical BIP39 test vector — same mnemonic whose coin-type-0 address is
# Photonic-verified in tests/test_hd_wallet.py (EXPECTED_0).
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _addr(coin_type: int, account: int, change: int, index: int) -> str:
    w = HdWallet.from_mnemonic(MNEMONIC, account=account, coin_type=coin_type)
    return w._derive_address(change, index)


def _scripthash_client(
    *, history: dict[str, list] | None = None, balance: dict[str, tuple[int, int]] | None = None
) -> MagicMock:
    """A scripthash-aware async-context-manager mock ElectrumX client."""
    from pyrxd.network.electrumx import script_hash_for_address

    history = history or {}
    balance = balance or {}

    async def _get_history(script_hash):
        for addr, hist in history.items():
            if script_hash_for_address(addr) == script_hash:
                return hist
        return []

    async def _get_balance(script_hash):
        for addr, bal in balance.items():
            if script_hash_for_address(addr) == script_hash:
                return bal
        return (0, 0)

    client = MagicMock()
    client.get_history = _get_history
    client.get_balance = _get_balance
    client.get_utxos = AsyncMock(return_value=[])
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _ctx(client: MagicMock, *, output_mode: str = "human") -> CliContext:
    return CliContext(
        config=Config(
            network="mainnet",
            electrumx="wss://test/",
            fee_rate=10_000,
            wallet_path=Path("/tmp/_pyrxd_recover_test"),
        ),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=Path("/tmp/_pyrxd_recover_test"),
        output_mode=output_mode,
        client_factory=lambda: client,
    )


def _invoke(runner: CliRunner, ctx: CliContext, args: list[str]):
    return runner.invoke(wallet_group, args, obj=ctx, input=f"{MNEMONIC}\n")


class TestRecoverScan:
    def test_finds_funds_on_legacy_path_human(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _scripthash_client(
            history={funded: [{"tx_hash": "ab" * 32, "height": 800000}]},
            balance={funded: (1_234_567, 0)},
        )
        result = _invoke(runner, _ctx(client), ["recover", "--scan"])
        assert result.exit_code == 0, result.output
        assert "Found funds" in result.output
        assert "m/44'/0'/0'/0/0" in result.output
        assert funded in result.output
        assert "Chainbow" in result.output  # coin-type label

    def test_json_output_shape(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _scripthash_client(
            history={funded: [{"tx_hash": "ab" * 32, "height": 1}]},
            balance={funded: (500, 0)},
        )
        result = _invoke(runner, _ctx(client, output_mode="json"), ["recover", "--scan"])
        assert result.exit_code == 0, result.output
        start, end = result.output.find("{"), result.output.rfind("}")
        payload = json.loads(result.output[start : end + 1])
        assert payload["found"] is True
        assert payload["total_confirmed_photons"] == 500
        assert payload["hits"][0]["path"] == "m/44'/0'/0'/0/0"
        assert payload["hits"][0]["coin_type"] == 0

    def test_no_hits_message(self, runner: CliRunner) -> None:
        client = _scripthash_client()  # nothing funded
        result = _invoke(runner, _ctx(client), ["recover", "--scan"])
        assert result.exit_code == 0, result.output
        assert "No on-chain history" in result.output
        assert "widen the search" in result.output

    def test_custom_ranges_restrict_scan(self, runner: CliRunner) -> None:
        funded = _addr(236, 0, 0, 0)
        client = _scripthash_client(
            history={funded: [{"tx_hash": "cd" * 32, "height": 1}]},
            balance={funded: (9, 0)},
        )
        result = _invoke(runner, _ctx(client), ["recover", "--scan", "--coin-types", "236", "--accounts", "0"])
        assert result.exit_code == 0, result.output
        assert "m/44'/236'/0'/0/0" in result.output

    def test_requires_scan_flag(self, runner: CliRunner) -> None:
        client = _scripthash_client()
        result = _invoke(runner, _ctx(client), ["recover"])
        assert result.exit_code != 0
        assert "--scan" in result.output

    def test_bad_coin_types_rejected(self, runner: CliRunner) -> None:
        client = _scripthash_client()
        result = _invoke(runner, _ctx(client), ["recover", "--scan", "--coin-types", "abc"])
        assert result.exit_code != 0
        assert "--coin-types" in result.output

    def test_mnemonic_never_echoed(self, runner: CliRunner) -> None:
        funded = _addr(0, 0, 0, 0)
        client = _scripthash_client(
            history={funded: [{"tx_hash": "ab" * 32, "height": 1}]},
            balance={funded: (1, 0)},
        )
        result = _invoke(runner, _ctx(client), ["recover", "--scan"])
        # The hidden prompt label may appear, but the seed words must not be
        # echoed back into the output.
        assert "abandon abandon abandon" not in result.output

    def test_network_error_surfaces_nonzero(self, runner: CliRunner) -> None:
        from pyrxd.security.errors import NetworkError

        client = _scripthash_client()

        async def _boom(_sh):
            raise NetworkError("electrumx down")

        client.get_history = _boom
        result = _invoke(runner, _ctx(client), ["recover", "--scan"])
        assert result.exit_code != 0
        assert "ElectrumX" in result.output

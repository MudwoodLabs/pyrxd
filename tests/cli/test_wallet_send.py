"""Tests for `pyrxd wallet send` — agent-when-live / mnemonic-prompt fallback (#8 A')."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

from pyrxd.agent import AgentDaemon
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.wallet_cmds import wallet_group
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import UtxoRecord, script_hash_for_address
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
DEST = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"  # canonical abandon-seed coin-0 address
_ACCEPT = lambda _s: True  # noqa: E731


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _ctx(wallet_path: Path, client: MagicMock, *, output_mode: str = "human", yes: bool = False) -> CliContext:
    return CliContext(
        config=Config(network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=wallet_path),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=wallet_path,
        output_mode=output_mode,
        yes=yes,
        client_factory=lambda: client,
    )


def _funded_client_for(addr: str, *, value: int = 100_000_000) -> MagicMock:
    """Mock ElectrumX: *addr* has history + one UTXO whose source tx pays it."""
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
    client.broadcast = AsyncMock(return_value="cd" * 32)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client


def _start_daemon(wallet: HdWallet, sock_path: Path) -> tuple[AgentDaemon, threading.Thread]:
    daemon = AgentDaemon(wallet, socket_path=sock_path, confirm=_ACCEPT, harden=False)
    t = threading.Thread(target=daemon.serve_forever, daemon=True)
    t.start()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if sock_path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            probe.settimeout(0.2)
            try:
                probe.connect(str(sock_path))
                probe.close()
                return daemon, t
            except OSError:
                pass
        time.sleep(0.02)
    raise RuntimeError("daemon did not come up")


def test_send_via_agent_when_live(runner: CliRunner, tmp_path: Path) -> None:
    wallet = HdWallet.from_mnemonic(MNEMONIC)
    funded_addr = wallet._derive_address(0, 0)
    client = _funded_client_for(funded_addr)
    ctx = _ctx(tmp_path / "wallet.dat", client)

    daemon, t = _start_daemon(wallet, tmp_path / "agent.sock")
    try:
        result = runner.invoke(wallet_group, ["send", "--to", DEST, "--amount", "10000000"], obj=ctx)
        assert result.exit_code == 0, result.output
        assert "signed by agent" in result.output
        client.broadcast.assert_awaited_once()
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_send_falls_back_to_in_process_when_no_agent(runner: CliRunner, tmp_path: Path) -> None:
    # No daemon running and no wallet file → the in-process branch is taken and
    # reports the missing wallet (proves it did NOT try the agent path).
    client = _funded_client_for(HdWallet.from_mnemonic(MNEMONIC)._derive_address(0, 0))
    ctx = _ctx(tmp_path / "missing.dat", client)
    result = runner.invoke(wallet_group, ["send", "--to", DEST, "--amount", "10000000"], obj=ctx)
    assert result.exit_code != 0
    assert "no wallet" in result.output.lower()
    client.broadcast.assert_not_awaited()


def test_rejects_nonpositive_amount(runner: CliRunner, tmp_path: Path) -> None:
    ctx = _ctx(tmp_path / "wallet.dat", _funded_client_for(DEST))
    result = runner.invoke(wallet_group, ["send", "--to", DEST, "--amount", "0"], obj=ctx)
    assert result.exit_code != 0
    assert "amount" in result.output.lower()


def test_rejects_bad_destination(runner: CliRunner, tmp_path: Path) -> None:
    ctx = _ctx(tmp_path / "wallet.dat", _funded_client_for(DEST))
    result = runner.invoke(wallet_group, ["send", "--to", "not-an-address", "--amount", "10000000"], obj=ctx)
    assert result.exit_code != 0
    assert "address" in result.output.lower()

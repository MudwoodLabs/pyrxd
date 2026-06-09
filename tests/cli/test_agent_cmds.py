"""CLI tests for ``pyrxd agent status|lock|unlock`` (Phase 5, issue #8 A').

status/lock are exercised against a real AgentDaemon started in a thread on the
wallet-co-located socket; unlock's error paths are checked via CliRunner (the
serving path itself is covered by test_agent_daemon).
"""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path

from click.testing import CliRunner

from pyrxd.agent import AgentDaemon
from pyrxd.cli.main import cli
from pyrxd.hd.bip32 import Xpub
from pyrxd.hd.wallet import HdWallet

TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_ACCEPT = lambda _s: True  # noqa: E731


def _start_daemon_on(sock_path: Path) -> tuple[AgentDaemon, threading.Thread]:
    daemon = AgentDaemon(HdWallet.from_mnemonic(TEST_MNEMONIC), socket_path=sock_path, confirm=_ACCEPT, harden=False)
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


def test_status_reports_not_running(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["--wallet", str(tmp_path / "wallet.dat"), "agent", "status"])
    assert result.exit_code == 0, result.output
    assert "not running" in result.output


def test_status_reports_live_with_xpub(runner: CliRunner, tmp_path: Path) -> None:
    daemon, t = _start_daemon_on(tmp_path / "agent.sock")
    try:
        result = runner.invoke(cli, ["--wallet", str(tmp_path / "wallet.dat"), "agent", "status"])
        assert result.exit_code == 0, result.output
        assert "LIVE" in result.output
        expected_xpub = str(Xpub.from_xprv(HdWallet.from_mnemonic(TEST_MNEMONIC)._xprv))
        assert expected_xpub in result.output
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_status_json_shape(runner: CliRunner, tmp_path: Path) -> None:
    daemon, t = _start_daemon_on(tmp_path / "agent.sock")
    try:
        result = runner.invoke(cli, ["--json", "--wallet", str(tmp_path / "wallet.dat"), "agent", "status"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["live"] is True
        assert payload["xpub"] == str(Xpub.from_xprv(HdWallet.from_mnemonic(TEST_MNEMONIC)._xprv))
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_lock_when_not_running(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["--wallet", str(tmp_path / "wallet.dat"), "agent", "lock"])
    assert result.exit_code == 0, result.output
    assert "nothing to lock" in result.output


def test_lock_stops_a_running_agent(runner: CliRunner, tmp_path: Path) -> None:
    daemon, t = _start_daemon_on(tmp_path / "agent.sock")
    try:
        result = runner.invoke(cli, ["--wallet", str(tmp_path / "wallet.dat"), "agent", "lock"])
        assert result.exit_code == 0, result.output
        assert "locked" in result.output
        t.join(timeout=3)
        assert daemon.locked is True
        assert not (tmp_path / "agent.sock").exists()
    finally:
        daemon.lock()
        t.join(timeout=3)


def test_unlock_without_wallet_file_errors(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["--wallet", str(tmp_path / "missing.dat"), "agent", "unlock"])
    assert result.exit_code != 0
    assert "no wallet" in result.output.lower()

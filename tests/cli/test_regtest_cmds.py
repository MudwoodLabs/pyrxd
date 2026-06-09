"""Tests for ``pyrxd regtest`` (the dev regtest tooling CLI surface).

These are fast unit tests: ``pyrxd.devnet.RegtestNode`` is stubbed so no
docker is required. The live docker round-trip (up → mine → fund → claim) is
exercised by the regtest e2e integration tests.
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from pyrxd.cli.main import cli
from pyrxd.devnet import DevKey, DevnetError


def _extract_json(output: str) -> dict:
    start, end = output.find("{"), output.rfind("}")
    assert start != -1 and end != -1, f"no JSON in output:\n{output!r}"
    return json.loads(output[start : end + 1])


_INFO = {
    "container": "pyrxd-devnet",
    "image": "radiant-core:v2.3.0-amd64",
    "rpc_user": "pyrxd",
    "rpc_password": "pyrxd",
    "wallet": "devnet",
    "height": 101,
    "exec_prefix": "docker exec pyrxd-devnet radiant-cli -regtest -rpcuser=pyrxd -rpcpassword=pyrxd",
}


class _FakeNode:
    """A RegtestNode stand-in recording calls, no docker involved."""

    def __init__(self, *, running: bool = False) -> None:
        self._running = running
        self.calls: list[tuple] = []

    def is_running(self) -> bool:
        return self._running

    def start(self, *, fresh: bool = False) -> None:
        self.calls.append(("start", fresh))
        self._running = True

    def stop(self) -> None:
        self.calls.append(("stop",))
        self._running = False

    def info(self) -> dict:
        return dict(_INFO)

    def new_funded_key(self, amount_rxd: float = 100.0) -> DevKey:
        self.calls.append(("new_funded_key", amount_rxd))
        return DevKey(address="n1devaddress", wif="cVdevwif", funded_rxd=amount_rxd)

    def mine(self, count: int = 1, address: str | None = None) -> int:
        self.calls.append(("mine", count, address))
        return 101 + count

    def fund(self, address: str, amount_rxd: float) -> str:
        self.calls.append(("fund", address, amount_rxd))
        return "ab" * 32


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def patch_node(monkeypatch):
    """Install a _FakeNode in place of RegtestNode for the regtest commands."""

    def _install(node: _FakeNode) -> _FakeNode:
        monkeypatch.setattr("pyrxd.cli.regtest_cmds.RegtestNode", lambda: node)
        return node

    return _install


class TestUp:
    def test_up_starts_and_prints_funded_key(self, runner, patch_node):
        patch_node(_FakeNode(running=False))
        result = runner.invoke(cli, ["regtest", "up", "--fund", "50"])
        assert result.exit_code == 0, result.output
        assert "regtest node up" in result.output
        assert "n1devaddress" in result.output
        assert "cVdevwif" in result.output
        assert "50 RXD" in result.output

    def test_up_json(self, runner, patch_node):
        patch_node(_FakeNode(running=False))
        result = runner.invoke(cli, ["regtest", "up", "--json"])
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["dev_address"] == "n1devaddress"
        assert payload["dev_wif"] == "cVdevwif"
        assert payload["container"] == "pyrxd-devnet"

    def test_up_idempotent_when_already_running(self, runner, patch_node):
        node = patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "up"])
        assert result.exit_code == 0, result.output
        assert "already running" in result.output
        # start() called with fresh=False (a no-op inside the node)
        assert ("start", False) in node.calls

    def test_up_fresh_flag_passes_through(self, runner, patch_node):
        node = patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "up", "--fresh"])
        assert result.exit_code == 0, result.output
        assert ("start", True) in node.calls


class TestMineFundDown:
    def test_mine_default_one(self, runner, patch_node):
        patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "mine"])
        assert result.exit_code == 0, result.output
        assert "mined 1 block(s) — height 102" in result.output

    def test_mine_count_json(self, runner, patch_node):
        patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "mine", "3", "--json"])
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload == {"mined": 3, "height": 104}

    def test_fund(self, runner, patch_node):
        node = patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "fund", "n1target", "12.5"])
        assert result.exit_code == 0, result.output
        assert "funded n1target with 12.5 RXD" in result.output
        assert ("fund", "n1target", 12.5) in node.calls

    def test_fund_json(self, runner, patch_node):
        patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "fund", "n1target", "5", "--json"])
        assert result.exit_code == 0, result.output
        payload = _extract_json(result.output)
        assert payload["address"] == "n1target"
        assert payload["amount_rxd"] == 5

    def test_info_human(self, runner, patch_node):
        patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "info"])
        assert result.exit_code == 0, result.output
        assert "container: pyrxd-devnet" in result.output
        assert "height:    101" in result.output

    def test_info_json(self, runner, patch_node):
        patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "info", "--json"])
        assert result.exit_code == 0, result.output
        assert _extract_json(result.output)["container"] == "pyrxd-devnet"

    def test_down(self, runner, patch_node):
        node = patch_node(_FakeNode(running=True))
        result = runner.invoke(cli, ["regtest", "down"])
        assert result.exit_code == 0, result.output
        assert "regtest node down" in result.output
        assert ("stop",) in node.calls


class TestFailClosed:
    def test_up_error_path(self, runner, monkeypatch):
        class _Boom(_FakeNode):
            def start(self, *, fresh: bool = False) -> None:
                raise DevnetError("regtest image not present locally")

        monkeypatch.setattr("pyrxd.cli.regtest_cmds.RegtestNode", lambda: _Boom())
        result = runner.invoke(cli, ["regtest", "up"])
        assert result.exit_code != 0
        assert "not present locally" in result.output

    def test_down_error_path(self, runner, monkeypatch):
        class _Boom(_FakeNode):
            def stop(self) -> None:
                raise DevnetError("docker is not on PATH")

        monkeypatch.setattr("pyrxd.cli.regtest_cmds.RegtestNode", lambda: _Boom())
        result = runner.invoke(cli, ["regtest", "down"])
        assert result.exit_code != 0
        assert "docker is not on PATH" in result.output

    def test_fund_error_path(self, runner, monkeypatch):
        class _Boom(_FakeNode):
            def fund(self, address: str, amount_rxd: float) -> str:
                raise DevnetError("regtest node is not running")

        monkeypatch.setattr("pyrxd.cli.regtest_cmds.RegtestNode", lambda: _Boom())
        result = runner.invoke(cli, ["regtest", "fund", "n1t", "1"])
        assert result.exit_code != 0
        assert "not running" in result.output

    def test_info_when_not_running_errors(self, runner, monkeypatch):
        class _NotRunning(_FakeNode):
            def info(self) -> dict:
                raise DevnetError("regtest node is not running — start it with `pyrxd regtest up`")

        monkeypatch.setattr("pyrxd.cli.regtest_cmds.RegtestNode", lambda: _NotRunning())
        result = runner.invoke(cli, ["regtest", "info"])
        assert result.exit_code != 0
        assert "not running" in result.output

    def test_mine_when_not_running_errors(self, runner, monkeypatch):
        class _NotRunning(_FakeNode):
            def mine(self, count: int = 1, address: str | None = None) -> int:
                raise DevnetError("regtest node is not running — start it with `pyrxd regtest up`")

        monkeypatch.setattr("pyrxd.cli.regtest_cmds.RegtestNode", lambda: _NotRunning())
        result = runner.invoke(cli, ["regtest", "mine"])
        assert result.exit_code != 0
        assert "not running" in result.output

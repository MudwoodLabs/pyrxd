"""Offline tests for ``pyrxd.testing`` (the public regtest helpers and pytest fixtures).

docker is never run here: a scripted node stands in at the ``cli`` boundary, and the
docker/image probe is patched. The real-node path is
``tests/test_starter_kit_regtest_e2e.py``, which runs the starter project's own test,
through these fixtures, against a ``radiantd``.
"""

from __future__ import annotations

import asyncio

import pytest

import pyrxd.testing.regtest as rt
from pyrxd.constants import Network
from pyrxd.devnet import DevnetError, RegtestNode
from pyrxd.fee_sizing import relay_floor_photons_per_byte
from pyrxd.keys import PrivateKey
from pyrxd.testing import RegtestClient, RegtestUnavailable, RegtestWallet, start_test_node

pytest_plugins = ["pytester"]


class _ScriptedNode:
    """A RegtestNode stand-in: answers ``cli`` from a table and records every call."""

    IMAGE = RegtestNode.IMAGE

    def __init__(self, responses: dict[str, object] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, ...]] = []
        self.funded: list[tuple[str, float]] = []
        self.mined = 0

    def cli(self, *args: str, wallet: bool = False) -> object:
        self.calls.append(args)
        if args[0] not in self.responses:
            raise AssertionError(f"unexpected radiant-cli call {args!r}")
        answer = self.responses[args[0]]
        return answer(*args) if callable(answer) else answer

    def mine(self, n: int = 1) -> int:
        self.mined += n
        return 101 + self.mined

    def fund(self, address: str, amount_rxd: float, *, confirm: bool = True) -> str:
        self.funded.append((address, amount_rxd))
        return "ab" * 32


# --------------------------------------------------------------------------- devnet naming


def test_regtest_node_default_container_is_the_cli_one():
    assert RegtestNode().CONTAINER == "pyrxd-devnet"


def test_regtest_node_takes_a_container_name_and_uses_it(monkeypatch):
    seen = []

    class _P:
        returncode, stdout, stderr = 0, "true", ""

    monkeypatch.setattr("pyrxd.devnet.shutil.which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr("pyrxd.devnet.subprocess.run", lambda argv, **k: seen.append(argv) or _P())
    node = RegtestNode(container="pyrxd-test-abc123")
    assert node.is_running()
    assert seen[0][-1] == "pyrxd-test-abc123"
    assert RegtestNode.CONTAINER == "pyrxd-devnet"  # the class default is untouched


@pytest.mark.parametrize("bad", ["", "-rm", "a b", "x", "a;b", "é1", "--name=x"])
def test_regtest_node_refuses_a_container_name_docker_would_misread(bad):
    with pytest.raises(DevnetError, match="invalid container name"):
        RegtestNode(container=bad)


# --------------------------------------------------------------------------- start_test_node


def _patch_start(monkeypatch, *, effective_rxd_per_kb: float, docker: bool = True, image: bool = True):
    """Patch everything start_test_node reaches below RegtestNode's own methods."""
    started, stopped = [], []

    class _Probe:
        returncode = 0 if image else 1
        stdout = stderr = ""

    monkeypatch.setattr(rt.shutil, "which", lambda _: "/usr/bin/docker" if docker else None)
    monkeypatch.setattr(rt.subprocess, "run", lambda argv, **k: _Probe())
    monkeypatch.setattr(RegtestNode, "start", lambda self, **k: started.append((self.CONTAINER, k)))
    monkeypatch.setattr(RegtestNode, "stop", lambda self: stopped.append(self.CONTAINER))
    monkeypatch.setattr(
        RegtestNode,
        "cli",
        lambda self, *a, **k: {"effective_minrelaytxfee": effective_rxd_per_kb, "minrelaytxfee": effective_rxd_per_kb},
    )
    return started, stopped


def test_start_test_node_gives_each_session_its_own_fresh_container(monkeypatch):
    started, stopped = _patch_start(monkeypatch, effective_rxd_per_kb=0.10)
    a, b = start_test_node(), start_test_node()
    assert a.CONTAINER != b.CONTAINER
    for node in (a, b):
        assert node.CONTAINER.startswith(rt.TEST_CONTAINER_PREFIX)
        assert node.CONTAINER != RegtestNode.CONTAINER  # never the `pyrxd regtest up` node
    assert [k for _, k in started] == [{"fresh": True}, {"fresh": True}]
    assert stopped == []


def test_start_test_node_honours_an_explicit_container(monkeypatch):
    _patch_start(monkeypatch, effective_rxd_per_kb=0.10)
    assert start_test_node(container="my-suite-node").CONTAINER == "my-suite-node"


def test_start_test_node_refuses_a_node_below_mainnets_relay_floor_and_removes_it(monkeypatch):
    started, stopped = _patch_start(monkeypatch, effective_rxd_per_kb=0.01)  # radiantd's regtest default
    with pytest.raises(DevnetError, match="relay floor of 1000000 photons/kB, not mainnet's 10000000"):
        start_test_node()
    assert stopped == [started[0][0]]  # the refused node is not left running


def test_start_test_node_accepts_exactly_mainnets_floor(monkeypatch):
    # The honest half of the refusal above: the floor it compares against is the library's.
    assert relay_floor_photons_per_byte() * 1000 == 10_000_000
    _, stopped = _patch_start(monkeypatch, effective_rxd_per_kb=0.10)
    start_test_node()
    assert stopped == []


def test_start_test_node_without_docker_says_how_to_fix_it(monkeypatch):
    started, _ = _patch_start(monkeypatch, effective_rxd_per_kb=0.10, docker=False)
    with pytest.raises(RegtestUnavailable, match="docker is not on PATH"):
        start_test_node()
    assert started == []


def test_start_test_node_without_the_image_names_the_setup_command(monkeypatch):
    started, _ = _patch_start(monkeypatch, effective_rxd_per_kb=0.10, image=False)
    with pytest.raises(RegtestUnavailable, match="pyrxd regtest setup"):
        start_test_node()
    assert started == []


def test_relay_floor_reading_refuses_a_reply_without_the_effective_rate():
    with pytest.raises(DevnetError, match="effective_minrelaytxfee"):
        rt.node_relay_floor_photons_per_kb(_ScriptedNode({"getmempoolinfo": {"minrelaytxfee": 0.1}}))


# --------------------------------------------------------------------------- RegtestClient


def test_client_broadcasts_hex_and_mines_a_block():
    node = _ScriptedNode({"sendrawtransaction": "cd" * 32})
    client = RegtestClient(node)
    assert asyncio.run(client.broadcast(b"\x01\x02")) == "cd" * 32
    assert node.calls == [("sendrawtransaction", "0102")]
    assert node.mined == 1


def test_client_without_auto_mine_leaves_the_tx_in_the_mempool():
    node = _ScriptedNode({"sendrawtransaction": "cd" * 32})
    client = RegtestClient(node, auto_mine=False)
    asyncio.run(client.broadcast("0102"))
    assert node.calls == [("sendrawtransaction", "0102")]
    assert node.mined == 0
    assert client.mine(3) == 104


def test_client_lookup_returns_the_nodes_object_and_refuses_anything_else():
    good = RegtestClient(_ScriptedNode({"getrawtransaction": {"confirmations": 2}}))
    assert asyncio.run(good.get_transaction_verbose("ef" * 32)) == {"confirmations": 2}
    bad = RegtestClient(_ScriptedNode({"getrawtransaction": "not an object"}))
    with pytest.raises(DevnetError, match="did not return an object"):
        asyncio.run(bad.get_transaction_verbose("ef" * 32))


# --------------------------------------------------------------------------- RegtestWallet


def test_funded_wallet_is_a_new_key_the_node_wallet_does_not_hold():
    node = _ScriptedNode()
    w1 = RegtestWallet.funded(node, 2.5)
    w2 = RegtestWallet.funded(node)
    assert w1.address != w2.address
    assert w1.private_key.network == Network.TESTNET
    assert w1.address == w1.private_key.address(network=Network.TESTNET)
    assert node.funded == [(w1.address, 2.5), (w2.address, rt.DEFAULT_WALLET_FUNDING_RXD)]
    # The key never came from the node's wallet: no getnewaddress / dumpprivkey.
    assert node.calls == []


@pytest.mark.parametrize("bad", [0, -1, True, "5", float("nan")])
def test_funded_refuses_a_non_positive_or_non_numeric_amount(bad):
    with pytest.raises(ValueError, match="positive number"):
        RegtestWallet.funded(_ScriptedNode(), bad)


def _wallet_with_unspents(unspents: list[dict], success: bool = True) -> RegtestWallet:
    node = _ScriptedNode({"scantxoutset": {"success": success, "unspents": unspents}})
    return RegtestWallet(node, PrivateKey(network=Network.TESTNET))


def test_utxos_reads_the_scan_with_exact_photon_values_and_block_heights():
    w = _wallet_with_unspents(
        [
            {"txid": "aa" * 32, "vout": 1, "amount": 21.12345678, "height": 102},
            {"txid": "bb" * 32, "vout": 0, "amount": 0.00000001, "height": 7},
        ]
    )
    got = [(u.tx_hash, u.tx_pos, u.value, u.height) for u in w.utxos()]
    assert got == [("aa" * 32, 1, 2_112_345_678, 102), ("bb" * 32, 0, 1, 7)]
    assert w.balance_photons() == 2_112_345_679
    (call,) = {c for c in w.node.calls}
    assert call == ("scantxoutset", "start", f'["addr({w.address})"]')


def test_utxos_refuses_a_failed_scan():
    with pytest.raises(DevnetError, match="scantxoutset failed"):
        _wallet_with_unspents([], success=False).utxos()


@pytest.mark.parametrize("amount", [0.000000001, -1, True, None])
def test_utxos_refuses_an_amount_that_is_not_whole_photons(amount):
    w = _wallet_with_unspents([{"txid": "aa" * 32, "vout": 0, "amount": amount, "height": 1}])
    with pytest.raises(DevnetError):
        w.utxos()


def test_collect_spendable_is_the_minters_triple_shape():
    w = _wallet_with_unspents([{"txid": "aa" * 32, "vout": 0, "amount": 1, "height": 3}])
    ((utxo, address, key),) = asyncio.run(w.collect_spendable(None))
    assert (utxo.value, address, key) == (100_000_000, w.address, w.private_key)


def test_privkey_for_address_answers_only_for_its_own_address():
    w = RegtestWallet(_ScriptedNode(), PrivateKey(network=Network.TESTNET))
    assert w.privkey_for_address(w.address) is w.private_key
    other = PrivateKey(network=Network.TESTNET).address()
    with pytest.raises(KeyError, match="is not this wallet's address"):
        w.privkey_for_address(other)


# --------------------------------------------------------------------------- pytest plugin


_FIXTURE_TEST = """
pytest_plugins = ["pyrxd.testing.pytest_plugin"]

def test_uses_the_chain(regtest_node, regtest_client, regtest_wallet, regtest_wallet_factory):
    assert regtest_client.node is regtest_node
    assert regtest_wallet.node is regtest_node
    other = regtest_wallet_factory(3.0)
    assert other.address != regtest_wallet.address
"""


def test_plugin_fixtures_share_one_node_and_remove_it_at_session_end(pytester, monkeypatch):
    import pyrxd.testing.pytest_plugin as plugin

    node = _ScriptedNode()
    events = []
    node.stop = lambda: events.append("stop")  # type: ignore[attr-defined]
    monkeypatch.setattr(plugin, "start_test_node", lambda: events.append("start") or node)
    pytester.makepyfile(_FIXTURE_TEST)
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-o", "addopts=")
    result.assert_outcomes(passed=1)
    assert events == ["start", "stop"]
    assert [amount for _, amount in node.funded] == [rt.DEFAULT_WALLET_FUNDING_RXD, 3.0]


def test_plugin_fails_rather_than_skips_when_no_node_can_start(pytester, monkeypatch):
    import pyrxd.testing.pytest_plugin as plugin

    def _unavailable():
        raise RegtestUnavailable("docker is not on PATH (scripted)")

    monkeypatch.setattr(plugin, "start_test_node", _unavailable)
    pytester.makepyfile(_FIXTURE_TEST)
    result = pytester.runpytest_inprocess("-p", "no:cacheprovider", "-o", "addopts=")
    result.assert_outcomes(errors=1)  # an error, never a skip: a skipped chain test reads green
    result.stdout.fnmatch_lines(["*could not start a regtest node: docker is not on PATH (scripted)*"])

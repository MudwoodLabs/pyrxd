"""Tests for the read-only ssh-tr RXD reader (``scripts/watchtower_sshtr.py``).

``subprocess.run`` is patched so nothing ever shells out to the real ``tr`` host —
we test the ssh argv construction, JSON parsing, error handling, and that the reader
composes with ``ElectrumRxdChainSource``.
"""

from __future__ import annotations

import json
import pathlib
import sys
import types

import pytest

# scripts/ isn't a package; put it on sys.path so we can import the shim module
# (same pattern as tests/test_dust_swap_shared.py).
_SCRIPTS = str(pathlib.Path(__file__).resolve().parent.parent / "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import watchtower_sshtr
from watchtower_sshtr import SshTrRxdReader

from pyrxd.gravity.watch import ElectrumRxdChainSource


def _patch_run(monkeypatch, *, stdout="", returncode=0, stderr=""):
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    monkeypatch.setattr(watchtower_sshtr.subprocess, "run", fake_run)
    return captured


def test_cli_argv_is_shell_safe():
    argv = SshTrRxdReader()._cli_argv("getblockcount")
    assert argv == ["ssh", "-o", "ConnectTimeout=10", "tr", "docker exec radiant-mainnet radiant-cli getblockcount"]


def test_cli_argv_custom_host_container():
    argv = SshTrRxdReader(ssh_host="myhost", container="rxd")._cli_argv("getblockcount")
    assert argv[3] == "myhost"
    assert argv[4] == "docker exec rxd radiant-cli getblockcount"


async def test_get_tip_height(monkeypatch):
    _patch_run(monkeypatch, stdout="850000\n")
    assert await SshTrRxdReader().get_tip_height() == 850000


async def test_get_transaction_verbose_returns_dict(monkeypatch):
    cap = _patch_run(monkeypatch, stdout=json.dumps({"confirmations": 5, "txid": "ab" * 32}))
    res = await SshTrRxdReader().get_transaction_verbose("ab" * 32)
    assert res["confirmations"] == 5
    # getrawtransaction <txid> true
    assert cap["argv"][4].endswith(f"radiant-cli getrawtransaction {'ab' * 32} true")


async def test_get_transaction_verbose_rejects_non_dict(monkeypatch):
    _patch_run(monkeypatch, stdout=json.dumps("not-a-dict"))
    with pytest.raises(RuntimeError):
        await SshTrRxdReader().get_transaction_verbose("ab" * 32)


async def test_nonzero_exit_raises(monkeypatch):
    _patch_run(monkeypatch, returncode=1, stderr="error: backend down")
    with pytest.raises(RuntimeError):
        await SshTrRxdReader().get_tip_height()


async def test_composes_with_chain_source(monkeypatch):
    # The reader plugs into ElectrumRxdChainSource (the watchtower's RxdChainSource).
    _patch_run(monkeypatch, stdout=json.dumps({"confirmations": 12}))
    src = ElectrumRxdChainSource(SshTrRxdReader())
    assert await src.covenant_confirmations("cd" * 32 + ":0") == 12


async def test_chain_source_unmined_via_reader(monkeypatch):
    _patch_run(monkeypatch, stdout=json.dumps({"confirmations": 0}))
    src = ElectrumRxdChainSource(SshTrRxdReader())
    assert await src.covenant_confirmations("cd" * 32 + ":0") is None


def test_reader_has_no_broadcast_surface():
    # v1 alert-only: the ssh-tr reader must NOT expose any value-moving method.
    reader = SshTrRxdReader()
    for forbidden in ("broadcast", "sendrawtransaction", "carve_fee_input", "get_utxos"):
        assert not hasattr(reader, forbidden)

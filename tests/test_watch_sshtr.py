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


# ssh_host / container are required (no built-in default — see the constructor's docstring:
# this reader ships in the public wheel and must not bake in any one operator's private ssh
# host / docker container name). These are just arbitrary-but-realistic stand-ins for tests
# that don't care about the exact value.
_HOST = "radiant-node"
_CONTAINER = "radiant-mainnet"


def test_cli_argv_is_shell_safe():
    argv = SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER)._cli_argv("getblockcount")
    assert argv == [
        "ssh",
        "-o",
        "ConnectTimeout=10",
        "--",
        _HOST,
        f"docker exec {_CONTAINER} radiant-cli getblockcount",
    ]


def test_cli_argv_custom_host_container():
    argv = SshTrRxdReader(ssh_host="myhost", container="rxd")._cli_argv("getblockcount")
    assert argv[3] == "--"  # end-of-options terminator (argv-injection hardening)
    assert argv[4] == "myhost"
    assert argv[5] == "docker exec rxd radiant-cli getblockcount"


def test_ssh_host_and_container_are_required():
    # The public-wheel hardening: no default host/container (a caller must be explicit).
    with pytest.raises(TypeError):
        SshTrRxdReader()  # type: ignore[call-arg]


async def test_get_tip_height(monkeypatch):
    _patch_run(monkeypatch, stdout="850000\n")
    assert await SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER).get_tip_height() == 850000


async def test_get_transaction_verbose_returns_dict(monkeypatch):
    cap = _patch_run(monkeypatch, stdout=json.dumps({"confirmations": 5, "txid": "ab" * 32}))
    res = await SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER).get_transaction_verbose("ab" * 32)
    assert res["confirmations"] == 5
    # getrawtransaction <txid> true
    assert cap["argv"][-1].endswith(f"radiant-cli getrawtransaction {'ab' * 32} true")


async def test_get_transaction_verbose_rejects_non_dict(monkeypatch):
    _patch_run(monkeypatch, stdout=json.dumps("not-a-dict"))
    with pytest.raises(RuntimeError):
        await SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER).get_transaction_verbose("ab" * 32)


async def test_nonzero_exit_raises(monkeypatch):
    _patch_run(monkeypatch, returncode=1, stderr="error: backend down")
    with pytest.raises(RuntimeError):
        await SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER).get_tip_height()


async def test_composes_with_chain_source(monkeypatch):
    # The reader plugs into ElectrumRxdChainSource (the watchtower's RxdChainSource).
    _patch_run(monkeypatch, stdout=json.dumps({"confirmations": 12}))
    src = ElectrumRxdChainSource(SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER))
    assert await src.covenant_confirmations("cd" * 32 + ":0") == 12


async def test_chain_source_unmined_via_reader(monkeypatch):
    _patch_run(monkeypatch, stdout=json.dumps({"confirmations": 0}))
    src = ElectrumRxdChainSource(SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER))
    assert await src.covenant_confirmations("cd" * 32 + ":0") is None


def test_reader_has_no_broadcast_surface():
    # v1 alert-only: the ssh-tr reader must NOT expose any value-moving method.
    reader = SshTrRxdReader(ssh_host=_HOST, container=_CONTAINER)
    for forbidden in ("broadcast", "sendrawtransaction", "carve_fee_input", "get_utxos"):
        assert not hasattr(reader, forbidden)


#
# argv-injection hardening
#
# ssh_host / ssh_container are operator-supplied (flag, env, config) and land in an argv.
# OpenSSH's getopt honours an option ANYWHERE in argv, so a host of "-oProxyCommand=<cmd>"
# executes <cmd> LOCALLY as the watchtower user -- the account holding pre-signed refund
# blobs and webhook secrets. shlex.quote does not help: it escapes for the REMOTE shell,
# and "-o" needs no shell metacharacters at all.
#
from pyrxd.security.errors import ValidationError


@pytest.mark.parametrize(
    "hostile",
    [
        "-oProxyCommand=touch /tmp/pwned",  # the actual exploit: local command execution
        "-F/tmp/attacker_ssh_config",  # alternate config file
        "-obatchmode=no",
        "--",
        "-",
        "host;touch /tmp/x",
        "host with space",
        "host$(id)",
        "host`id`",
        "host\nProxyCommand=id",
    ],
)
def test_hostile_ssh_host_is_refused(hostile):
    """A host that could be read as an ssh option or shell metacharacter must not construct."""
    with pytest.raises(ValidationError):
        SshTrRxdReader(ssh_host=hostile, container="radiant-mainnet")


@pytest.mark.parametrize("hostile", ["-u", "-v", "--user=root", "c;id", "c d", ""])
def test_hostile_container_is_refused(hostile):
    """`shlex.quote("-u")` is "-u" -- a live `docker exec` flag on the remote side."""
    with pytest.raises(ValidationError):
        SshTrRxdReader(ssh_host="node.example.com", container=hostile)


@pytest.mark.parametrize(
    "ok",
    ["tr", "node.example.com", "user@host", "host:2222", "10.0.0.5", "my-node_1"],
)
def test_legitimate_hosts_still_accepted(ok):
    """The guard must not break real hostnames, user@host, or ports."""
    assert SshTrRxdReader(ssh_host=ok, container="radiant-mainnet") is not None


def test_argv_uses_end_of_options_terminator():
    """Belt-and-braces: `--` stops getopt reading a later token as an option."""
    argv = SshTrRxdReader(ssh_host="node.example.com", container="radiant-mainnet")._cli_argv("getblockcount")
    assert "--" in argv
    assert argv.index("--") < argv.index("node.example.com")

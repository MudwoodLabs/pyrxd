"""Unit tests for ``pyrxd.devnet.RegtestNode`` with docker fully mocked.

No docker is required: ``subprocess.run`` and ``shutil.which`` are patched so
the argv construction, JSON parsing, lifecycle logic, and fail-closed guards
are all exercised in-process. The live docker round-trip is covered separately
by the regtest integration path.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from pyrxd.devnet import DevKey, DevnetError, RegtestNode


class _FakeProc:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _Docker:
    """Configurable fake docker: routes by argv to canned RPC responses."""

    def __init__(self, *, running: bool = True, chain: str = "regtest", height: int = 101) -> None:
        self.running = running
        self.chain = chain
        self.height = height
        self.run_fails_with = ""  # set to simulate `docker run` failure stderr
        self.build_fails_with = ""  # set to simulate `docker build` failure stderr
        self.calls: list[list[str]] = []

    def _rpc_method(self, argv: list[str]) -> str:
        i = argv.index("radiant-cli")
        for a in argv[i + 1 :]:
            if not a.startswith("-"):
                return a
        return ""

    def __call__(self, argv, capture_output=False, text=False, timeout=None):
        self.calls.append(argv)
        if argv[:2] == ["docker", "inspect"]:
            return _FakeProc(0 if self.running else 1, "true" if self.running else "")
        if argv[:2] == ["docker", "rm"]:
            self.running = False
            return _FakeProc(0)
        if argv[:2] == ["docker", "build"]:
            if self.build_fails_with:
                return _FakeProc(1, stderr=self.build_fails_with)
            return _FakeProc(0, stdout="built\n")
        if argv[:2] == ["docker", "run"]:
            if self.run_fails_with:
                return _FakeProc(1, stderr=self.run_fails_with)
            self.running = True
            return _FakeProc(0, stdout="containerid\n")
        if argv[:2] == ["docker", "exec"]:
            return _FakeProc(0, stdout=self._exec_stdout(argv))
        raise AssertionError(f"unexpected argv: {argv}")

    def _exec_stdout(self, argv: list[str]) -> str:
        method = self._rpc_method(argv)
        if method == "getblockchaininfo":
            return json.dumps({"chain": self.chain, "blocks": self.height})
        if method == "getblockcount":
            return str(self.height)
        if method == "getnewaddress":
            return "n1FakeMineAddr"
        if method == "createwallet":
            return json.dumps({"name": "devnet"})
        if method == "generatetoaddress":
            return json.dumps(["00" * 32])
        if method == "dumpprivkey":
            return "cFakeWifValue"
        if method == "sendtoaddress":
            return "ab" * 32
        return ""


@pytest.fixture
def patch_docker(monkeypatch):
    def _install(docker: _Docker) -> _Docker:
        monkeypatch.setattr("pyrxd.devnet.shutil.which", lambda _name: "/usr/bin/docker")
        monkeypatch.setattr("pyrxd.devnet.subprocess.run", docker)
        return docker

    return _install


class TestCli:
    def test_parses_json(self, patch_docker):
        patch_docker(_Docker())
        out = RegtestNode().cli("getblockchaininfo")
        assert out == {"chain": "regtest", "blocks": 101}

    def test_returns_raw_string_when_not_json(self, patch_docker):
        patch_docker(_Docker())
        assert RegtestNode().cli("getnewaddress", wallet=True) == "n1FakeMineAddr"

    def test_wallet_flag_added(self, patch_docker):
        d = patch_docker(_Docker())
        RegtestNode().cli("getnewaddress", wallet=True)
        assert any("-rpcwallet=devnet" in a for a in d.calls[-1])

    def test_nonzero_returncode_raises(self, patch_docker, monkeypatch):
        monkeypatch.setattr("pyrxd.devnet.shutil.which", lambda _n: "/usr/bin/docker")
        monkeypatch.setattr("pyrxd.devnet.subprocess.run", lambda *a, **k: _FakeProc(1, stderr="boom"))
        with pytest.raises(DevnetError, match="boom"):
            RegtestNode().cli("getblockchaininfo")

    def test_docker_missing_raises(self, monkeypatch):
        monkeypatch.setattr("pyrxd.devnet.shutil.which", lambda _n: None)
        with pytest.raises(DevnetError, match="docker is not on PATH"):
            RegtestNode().is_running()


class TestLifecycle:
    def test_is_running_true_false(self, patch_docker):
        patch_docker(_Docker(running=True))
        assert RegtestNode().is_running() is True
        patch_docker(_Docker(running=False))
        assert RegtestNode().is_running() is False

    def test_start_idempotent_when_running(self, patch_docker):
        d = patch_docker(_Docker(running=True))
        RegtestNode().start()
        # No `docker run` issued — we returned early.
        assert not any(c[:2] == ["docker", "run"] for c in d.calls)

    def test_start_fresh_then_run(self, patch_docker):
        d = patch_docker(_Docker(running=True))
        RegtestNode().start(fresh=True, initial_blocks=0)
        assert any(c[:2] == ["docker", "rm"] for c in d.calls)
        assert any(c[:2] == ["docker", "run"] for c in d.calls)

    def test_start_from_stopped_runs_and_mines(self, patch_docker):
        d = patch_docker(_Docker(running=False))
        RegtestNode().start(initial_blocks=101)
        assert any(c[:2] == ["docker", "run"] for c in d.calls)
        assert any("generatetoaddress" in c for c in d.calls)

    def test_start_image_missing(self, patch_docker):
        d = _Docker(running=False)
        d.run_fails_with = "Unable to find image 'x': No such image"
        patch_docker(d)
        with pytest.raises(DevnetError, match="not present locally"):
            RegtestNode().start()

    def test_start_other_run_failure(self, patch_docker):
        d = _Docker(running=False)
        d.run_fails_with = "some docker daemon error"
        patch_docker(d)
        with pytest.raises(DevnetError, match="failed to start"):
            RegtestNode().start()

    def test_start_refuses_non_regtest(self, patch_docker):
        patch_docker(_Docker(running=False, chain="main"))
        with pytest.raises(DevnetError, match="did not come up as regtest"):
            RegtestNode().start(initial_blocks=0)

    def test_stop_removes(self, patch_docker):
        d = patch_docker(_Docker(running=True))
        RegtestNode().stop()
        assert any(c[:2] == ["docker", "rm"] for c in d.calls)


class TestChainOps:
    def test_mine_returns_height(self, patch_docker):
        patch_docker(_Docker(running=True, height=105))
        assert RegtestNode().mine(3) == 105

    def test_mine_explicit_address(self, patch_docker):
        d = patch_docker(_Docker(running=True))
        RegtestNode().mine(1, address="n1Explicit")
        gen = [c for c in d.calls if "generatetoaddress" in c][-1]
        assert "n1Explicit" in gen

    def test_mine_fails_closed_when_down(self, patch_docker):
        patch_docker(_Docker(running=False))
        with pytest.raises(DevnetError, match="not running"):
            RegtestNode().mine()

    def test_fund_sends_and_confirms(self, patch_docker):
        d = patch_docker(_Docker(running=True))
        txid = RegtestNode().fund("n1Target", 12.5)
        assert txid == "ab" * 32
        send = [c for c in d.calls if "sendtoaddress" in c][-1]
        assert "n1Target" in send and "12.50000000" in send
        # confirm=True mines a block
        assert any("generatetoaddress" in c for c in d.calls)

    def test_fund_no_confirm_skips_mine(self, patch_docker):
        d = patch_docker(_Docker(running=True))
        RegtestNode().fund("n1Target", 1.0, confirm=False)
        assert not any("generatetoaddress" in c for c in d.calls)

    def test_new_funded_key(self, patch_docker):
        patch_docker(_Docker(running=True))
        key = RegtestNode().new_funded_key(50.0)
        assert isinstance(key, DevKey)
        assert key.address == "n1FakeMineAddr"
        assert key.wif == "cFakeWifValue"
        assert key.funded_rxd == 50.0

    def test_info(self, patch_docker):
        patch_docker(_Docker(running=True, height=107))
        info = RegtestNode().info()
        assert info["height"] == 107
        assert info["container"] == "pyrxd-devnet"
        assert "docker exec" in info["exec_prefix"]

    def test_info_fails_closed_when_down(self, patch_docker):
        patch_docker(_Docker(running=False))
        with pytest.raises(DevnetError, match="not running"):
            RegtestNode().info()


def test_await_rpc_times_out(monkeypatch):
    """If RPC never reports regtest, start() raises rather than hanging."""
    monkeypatch.setattr("pyrxd.devnet.shutil.which", lambda _n: "/usr/bin/docker")

    def _never_ready(argv, **k):
        if argv[:2] == ["docker", "run"]:
            return _FakeProc(0)
        if argv[:2] in (["docker", "rm"], ["docker", "inspect"]):
            return _FakeProc(1)
        return _FakeProc(1, stderr="not ready")  # every cli call fails

    monkeypatch.setattr("pyrxd.devnet.subprocess.run", _never_ready)
    # Collapse the wait loop so the test is instant.
    monkeypatch.setattr(RegtestNode, "_RPC_READY_TIMEOUT_S", 0)
    monkeypatch.setattr("pyrxd.devnet.time.sleep", lambda _s: None)
    with pytest.raises(DevnetError, match="did not become ready"):
        RegtestNode().start(initial_blocks=0)


def test_cli_filenotfound_maps_to_devnet_error(monkeypatch):
    monkeypatch.setattr("pyrxd.devnet.shutil.which", lambda _n: "/usr/bin/docker")

    def _raise(*a, **k):
        raise FileNotFoundError("docker")

    monkeypatch.setattr("pyrxd.devnet.subprocess.run", _raise)
    with pytest.raises(DevnetError, match="docker is not on PATH"):
        RegtestNode().cli("getblockchaininfo")


class TestImageBuild:
    def test_build_image_constructs_versioned_tag_and_build_arg(self, patch_docker):
        d = patch_docker(_Docker())
        tag = RegtestNode.build_image("v3.1.1")
        assert tag == "radiant-core:v3.1.1-amd64"
        build = next(c for c in d.calls if c[:2] == ["docker", "build"])
        assert "--build-arg" in build and "RADIANT_VERSION=v3.1.1" in build
        assert "-t" in build and "radiant-core:v3.1.1-amd64" in build

    def test_build_image_defaults_to_pinned_version(self, patch_docker):
        from pyrxd.devnet import DEFAULT_RADIANT_VERSION

        patch_docker(_Docker())
        assert RegtestNode.build_image() == f"radiant-core:{DEFAULT_RADIANT_VERSION}-amd64"

    def test_build_image_failure_raises(self, patch_docker):
        d = patch_docker(_Docker())
        d.build_fails_with = "no space left on device"
        with pytest.raises(DevnetError, match="no space left on device"):
            RegtestNode.build_image("v3.1.1")

    def test_image_attr_derives_from_default_version(self):
        from pyrxd.devnet import DEFAULT_RADIANT_VERSION

        assert f"radiant-core:{DEFAULT_RADIANT_VERSION}-amd64" == RegtestNode.IMAGE


def test_committed_dockerfile_matches_embedded_constant():
    """`pyrxd regtest setup` builds from the embedded _REGTEST_DOCKERFILE; the committed
    docker/regtest.Dockerfile must stay byte-identical so a clone, CI, and a pip-installed
    `regtest setup` all build the same image. Regenerate the committed file from the constant
    if this fails."""
    from pathlib import Path

    from pyrxd.devnet import _REGTEST_DOCKERFILE

    committed = Path(__file__).resolve().parents[1] / "docker" / "regtest.Dockerfile"
    assert committed.read_text(encoding="utf-8") == _REGTEST_DOCKERFILE


_ = subprocess  # keep the import meaningful for readers; patched via string paths

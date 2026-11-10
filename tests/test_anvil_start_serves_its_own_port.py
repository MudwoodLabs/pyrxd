"""``tests._anvil.start_anvil`` hands back the anvil it started, never a stranger on the port (#933).

The suites used to pick a free port, close it, start ``anvil --port <it>`` and poll the URL. A
process that took the port in between answered the poll, and the test ran against someone else's
anvil (same dev accounts, so ``nonce too low``). These tests run with a FAKE ``anvil`` on PATH, so
they need no foundry install and run in the default suite:

* asked for a specific port, the fake models losing that race: it starts a "squatter" server on the
  port, prints an address-in-use error and exits. A helper that probes a port it chose itself is
  answered by the squatter;
* asked for port 0, it binds a port of its own, reports it the way anvil does, and answers as
  ``ours``.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import signal
import stat
import sys
import urllib.request

import pytest

from tests._anvil import start_anvil

_FAKE_ANVIL = r"""
import http.server, json, os, socket, subprocess, sys, threading, time

args = sys.argv[1:]

def serve(sock, marker, lifetime_s):
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["content-length"])))
            result = "0x7a69" if req["method"] == "eth_chainId" else marker
            body = json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": result}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H, bind_and_activate=False)
    srv.socket.close()
    srv.socket = sock
    threading.Timer(lifetime_s, srv.shutdown).start()
    srv.serve_forever()

def bound(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    return s

if args[0] == "--squat":
    port, pid_file = int(args[1]), args[2]
    s = bound(port)
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    serve(s, "squatter", 30)
    sys.exit(0)

if os.environ.get("FAKE_ANVIL_MODE") == "die":
    print("Error: failed to start", flush=True)
    sys.exit(1)

port = int(args[args.index("--port") + 1])
if port != 0:
    # Lose the race: someone else takes the port we were told to use, then our bind fails.
    pid_file = os.environ["FAKE_ANVIL_SQUATTER_PID"]
    subprocess.Popen([sys.executable, __file__, "--squat", str(port), pid_file])
    for _ in range(200):
        if os.path.exists(pid_file) and os.path.getsize(pid_file):
            break
        time.sleep(0.02)
    time.sleep(0.2)
    print(f"Error: Address already in use (os error 98) on 127.0.0.1:{port}", flush=True)
    sys.exit(1)

s = bound(0)
print("Available Accounts", flush=True)
print(f"Listening on 127.0.0.1:{s.getsockname()[1]}", flush=True)
serve(s, "ours", 60)
"""


@pytest.fixture()
def fake_anvil(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "anvil"
    exe.write_text(f"#!{sys.executable}\n{_FAKE_ANVIL}")
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    pid_file = tmp_path / "squatter.pid"
    monkeypatch.setenv("FAKE_ANVIL_SQUATTER_PID", str(pid_file))
    yield
    if pid_file.exists() and pid_file.read_text():
        try:
            os.kill(int(pid_file.read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass


def _client_version(url: str) -> str:
    body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "web3_clientVersion", "params": []}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read())["result"]


@pytest.mark.skipif(sys.platform == "win32", reason="the fake anvil is a shebang script")
def test_the_url_is_served_by_the_anvil_we_started(fake_anvil):
    """Honest path, and the race: the URL handed back must reach OUR process. A helper that picks
    the port itself is answered by the fake's squatter, and this assertion sees ``squatter``."""
    with start_anvil(ready_timeout_s=15) as url:
        assert re.fullmatch(r"http://127\.0\.0\.1:\d{1,5}", url)
        assert _client_version(url) == "ours"


@pytest.mark.skipif(sys.platform == "win32", reason="the fake anvil is a shebang script")
def test_an_anvil_that_exits_without_a_port_fails_the_start(fake_anvil, monkeypatch):
    """Refusal: an anvil that dies before reporting a port fails at once, with its output, instead
    of the start polling a port that something else may be answering."""
    monkeypatch.setenv("FAKE_ANVIL_MODE", "die")
    with pytest.raises(
        pytest.fail.Exception, match=r"exited with code 1 before reporting a port(.|\n)*failed to start"
    ):
        with start_anvil(ready_timeout_s=15):
            pass  # pragma: no cover - the start must not yield


@pytest.mark.parametrize("flag", ["--port", "--port=8545", "-p", "--host", "--silent"])
def test_flags_the_helper_owns_are_refused(flag):
    """``--port`` brings the race back, ``--host`` breaks the port report, ``--silent`` hides it."""
    with pytest.raises(ValueError, match="itself"):
        with start_anvil([flag, "1"]):
            pass  # pragma: no cover


def test_every_anvil_the_tests_start_goes_through_the_helper():
    """Derived from the tree, not a list: an argv list in tests/ that starts with the anvil binary,
    anywhere but the helper, is a suite starting anvil the old way."""
    tests_dir = pathlib.Path(__file__).parent
    starts = sorted(
        str(p.relative_to(tests_dir))
        for p in tests_dir.rglob("*.py")
        if re.search(r'\[\s*"anvil"\s*,', p.read_text(encoding="utf-8"))
    )
    assert starts == ["_anvil.py"], starts

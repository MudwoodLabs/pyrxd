"""Start a local anvil and hand back the URL of THAT anvil, never of whatever else answers there.

Every anvil-backed suite used to pick a port by binding port 0, closing the socket, and then
starting ``anvil --port <that port>``, before polling the URL until something answered. Two
things are wrong with that (#933):

* the port is free only at the moment it is read. Another process (a second suite on the same
  machine, or another xdist worker) can bind it before anvil does;
* the poll accepts any server on the port. If anvil lost the race it exits, and the poll is
  answered by the OTHER process's anvil, which holds the same deterministic dev accounts. The test
  then shares an account with a stranger and sees errors like ``nonce too low``.

So :func:`start_anvil` asks anvil itself to bind port 0 and reads back the port anvil reports
(``Listening on 127.0.0.1:<port>``). The kernel hands each bind its own port, so there is no gap
to race through, and the URL is the one the process we started is serving. If anvil exits or
never reports a port, the start fails with anvil's own output instead of carrying on.
"""

from __future__ import annotations

import contextlib
import json
import pathlib
import re
import subprocess
import tempfile
import time
import urllib.request
from collections.abc import Iterator, Sequence

import pytest

#: anvil prints this once its HTTP server is bound. Anchored: a log line that merely mentions an
#: address must not count as the report.
_LISTENING = re.compile(r"^Listening on 127\.0\.0\.1:(\d{1,5})\s*$", re.MULTILINE)

#: Arguments the helper owns. A caller passing one of them would bring back the race.
_OWNED_FLAGS = frozenset({"--port", "-p", "--host", "--silent"})


def _rpc_ok(url: str, timeout_s: float) -> bool:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}).encode()
    req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return "result" in json.loads(resp.read())
    except Exception:
        return False


def _fail(log_path: pathlib.Path, why: str) -> None:
    try:
        tail = log_path.read_text(errors="replace")[-2000:]
    except OSError:
        tail = "<no output>"
    pytest.fail(f"anvil {why}. Its output:\n{tail}")


@contextlib.contextmanager
def start_anvil(args: Sequence[str] = (), *, ready_timeout_s: float = 30.0) -> Iterator[str]:
    """Run ``anvil --host 127.0.0.1 --port 0 *args``; yield ``http://127.0.0.1:<port>`` for the
    port that process reported binding, once it answers ``eth_chainId``. Stopped on exit."""
    owned = _OWNED_FLAGS.intersection(a.split("=", 1)[0] for a in args)
    if owned:
        raise ValueError(f"start_anvil sets {sorted(owned)} itself; do not pass them")
    with tempfile.TemporaryDirectory(prefix="pyrxd-anvil-") as tmp:
        log_path = pathlib.Path(tmp) / "anvil.log"
        with log_path.open("wb") as log:
            # Output goes to a file, not a pipe: anvil logs every request, and a pipe nobody reads
            # fills up and stalls it.
            proc = subprocess.Popen(
                ["anvil", "--host", "127.0.0.1", "--port", "0", *args],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        try:
            deadline = time.monotonic() + ready_timeout_s
            port = None
            while port is None:
                if proc.poll() is not None:
                    _fail(log_path, f"exited with code {proc.returncode} before reporting a port")
                m = _LISTENING.search(log_path.read_text(errors="replace"))
                if m is not None:
                    port = int(m.group(1))
                elif time.monotonic() > deadline:
                    _fail(log_path, f"reported no port within {ready_timeout_s:g}s")
                else:
                    time.sleep(0.05)
            url = f"http://127.0.0.1:{port}"
            while not _rpc_ok(url, timeout_s=2.0):
                if proc.poll() is not None:
                    _fail(log_path, f"exited with code {proc.returncode} after reporting port {port}")
                if time.monotonic() > deadline:
                    _fail(log_path, f"did not answer on its port {port} within {ready_timeout_s:g}s")
                time.sleep(0.1)
            yield url
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - anvil ignores SIGTERM
                proc.kill()
                proc.wait(timeout=10)

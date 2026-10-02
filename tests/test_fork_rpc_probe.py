"""The nightly fork-endpoint probe treats every RPC reply as hostile data.

``.github/workflows/integration.yml``'s ERC-20 lifecycle step probes public RPC endpoints before it
forks one. Its first version parsed the replies in bash and put an endpoint's ``eth_blockNumber``
into ``$(( tip - PROBE_DEPTH_BLOCKS ))``. Bash evaluates that operand as an expression, array
subscripts included, so a reply of ``"PROBE_DEPTH_BLOCKS[$(touch …)]"`` ran a command on the CI
runner, and the endpoint then passed the probe and was chosen. The probe is now
``scripts/fork_rpc_probe.py``.

These tests run THE STEP'S OWN SCRIPT, extracted from the workflow file, with ``poetry`` and
``python`` shimmed and the endpoint list pointed at a local server that answers with hostile replies.
Each hostile endpoint must be refused as a probe failure, nothing it carries may execute, and the
suite must never be started against it. A test that ran the probe script alone could not see the
bash that calls it, which is where the defect was.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW = _ROOT / ".github" / "workflows" / "integration.yml"
_STEP_NAME = "RXD↔USDC/USDT lifecycle on forked Ethereum and Base"
_GOOD_TIP = "0x4000"
_GOOD_CODE = "0x6080604052"
#: Requests that reached the server's "internal" path (reset per server fixture).
_INTERNAL_HITS: list[str] = []

sys.path.insert(0, str(_ROOT / "scripts"))
import fork_rpc_probe

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash to run the workflow step")


def _hostile(name: str, pwned: Path) -> tuple[object, object]:
    """``(eth_blockNumber reply, eth_getCode reply)`` for one named endpoint, as raw JSON-RPC bodies."""

    def ok(result: object) -> dict:
        return {"jsonrpc": "2.0", "id": 1, "result": result}

    replies = {
        "healthy": (ok(_GOOD_TIP), ok(_GOOD_CODE)),
        # The reviewer's proof: bash arithmetic evaluates the array subscript, which runs the command.
        "injection": (ok(f"PROBE_DEPTH_BLOCKS[$(touch {pwned})]"), ok(_GOOD_CODE)),
        "injection_in_code": (ok(_GOOD_TIP), ok(f"0x60$(touch {pwned})")),
        "non_hex": (ok("latest"), ok(_GOOD_CODE)),
        "huge_hex": (ok("0x" + "f" * 17), ok(_GOOD_CODE)),
        "decimal_number": (ok(16384), ok(_GOOD_CODE)),
        "not_json": (b"<html>502 Bad Gateway</html>", ok(_GOOD_CODE)),
        "no_code": (ok(_GOOD_TIP), ok("0x")),
        # A reply trying to start a workflow command of its own inside our ::warning:: annotation.
        "annotation_injection": (
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "x\n::error::forged by the endpoint"}},
            ok(_GOOD_CODE),
        ),
    }
    return replies[name]


@pytest.fixture
def server(tmp_path):
    """A local JSON-RPC server: ``http://127.0.0.1:PORT/<name>`` answers as the named endpoint."""
    pwned = tmp_path / "PWNED"
    internal_hits = _INTERNAL_HITS
    internal_hits.clear()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            pass

        def _internal(self):
            internal_hits.append(self.command)
            out = b"INTERNAL-SECRET-0123456789"
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = _internal

        def do_POST(self):
            name = self.path.split("?")[0].strip("/")
            if name == "internal":
                return self._internal()
            if name == "redirect":
                # An endpoint pointing the probe at an address only the runner can reach.
                self.send_response(302)
                self.send_header("Location", "/internal")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if name == "bad_status":
                # Not HTTP at all: http.client raises BadStatusLine (an HTTPException, not an OSError).
                self.wfile.write(b"GARBAGE\r\n\r\n")
                self.close_connection = True
                return
            if name == "drip":
                # A VALID reply, one byte at a time: each read is short, the call never ends.
                out = json.dumps({"jsonrpc": "2.0", "id": 1, "result": _GOOD_TIP}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                try:
                    for b in out:
                        self.wfile.write(bytes([b]))
                        self.wfile.flush()
                        time.sleep(0.5)
                except OSError:
                    pass
                return
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            tip, code = _hostile(self.path.split("?")[0].strip("/"), pwned)
            if req["method"] == "eth_getCode":
                # The probe asks at tip - depth, computed in Python from a validated quantity.
                assert req["params"][1] == hex(int(_GOOD_TIP, 16) - 1024), req
            reply = tip if req["method"] == "eth_blockNumber" else code
            out = reply if isinstance(reply, bytes) else json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}", pwned
    finally:
        httpd.shutdown()


def _step_script() -> tuple[str, dict]:
    jobs = yaml.safe_load(_WORKFLOW.read_text())["jobs"]
    for step in jobs["nightly-cross-chain"]["steps"]:
        if step.get("name") == _STEP_NAME:
            return step["run"], dict(step.get("env", {}))
    raise AssertionError(f"no step named {_STEP_NAME!r} in nightly-cross-chain: the test would check nothing")


def _run_step(
    tmp_path: Path, eth: list[str], base: list[str], *, suite: str = "pass", probe_python: str | None = None
) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run the workflow step with its endpoint lists replaced, ``poetry``/``python`` shimmed."""
    script, env_block = _step_script()
    lines = script.splitlines()
    replaced = 0
    for i, line in enumerate(lines):
        if line.startswith("run_fork 1 "):
            lines[i], replaced = f"run_fork 1 {' '.join(eth)} || rc=1", replaced + 1
        elif line.startswith("run_fork 8453 "):
            lines[i], replaced = f"run_fork 8453 {' '.join(base)} || rc=1", replaced + 1
    assert replaced == 2, "the step's endpoint lines moved; this test would run the real public endpoints"
    (tmp_path / "step.sh").write_text("\n".join(lines) + "\n")

    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    (shim / "poetry").write_text(
        "#!/bin/sh\n"
        '[ "$1" = run ] && shift\n'
        'case "$1" in\n'
        "  pytest)\n"
        '    echo "$PYRXD_ETH_FORK_CHAIN_ID $PYRXD_ETH_FORK_RPC" >> "$SHIM_LOG"\n'
        '    for a in "$@"; do case "$a" in --junitxml=*) x="${a#--junitxml=}";; esac; done\n'
        '    case "$SHIM_SUITE" in\n'
        '      skip) echo \'<testsuites><testsuite tests="8" skipped="8" failures="0" errors="0"/></testsuites>\' > "$x"; exit 0;;\n'
        '      fail) echo \'<testsuites><testsuite tests="8" skipped="0" failures="1" errors="0"/></testsuites>\' > "$x"; exit 1;;\n'
        "    esac\n"
        '    echo \'<testsuites><testsuite tests="8" skipped="0" failures="0" errors="0"/></testsuites>\' > "$x"\n'
        "    exit 0;;\n"
        '  python) shift; exec "$SHIM_PYTHON" "$@";;\n'
        "esac\n"
        'exec "$@"\n'
    )
    (shim / "python").write_text('#!/bin/sh\nexec "$SHIM_PYTHON" "$@"\n')
    for f in ("poetry", "python"):
        (shim / f).chmod(0o755)
    log = tmp_path / "pytest-calls.log"
    env = {
        **os.environ,
        **{k: str(v) for k, v in env_block.items()},
        "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}",
        "PYTHONPATH": str(_ROOT / "src"),
        "RUNNER_TEMP": str(tmp_path),
        "SHIM_LOG": str(log),
        "SHIM_PYTHON": probe_python or sys.executable,
        "SHIM_SUITE": suite,
    }
    proc = subprocess.run(
        ["bash", str(tmp_path / "step.sh")], cwd=_ROOT, env=env, capture_output=True, text=True, timeout=120
    )
    calls = log.read_text().splitlines() if log.exists() else []
    return proc, calls


_HOSTILE = (
    "injection",
    "injection_in_code",
    "non_hex",
    "huge_hex",
    "decimal_number",
    "not_json",
    "no_code",
    "annotation_injection",
)


@pytest.mark.parametrize("name", _HOSTILE)
def test_a_hostile_endpoint_is_refused_and_nothing_it_sends_runs(name, server, tmp_path):
    base, pwned = server
    url = f"{base}/{name}"
    proc, calls = _run_step(tmp_path, eth=[url], base=[url])
    out = proc.stdout + proc.stderr
    assert not pwned.exists(), f"the {name!r} reply EXECUTED on the runner:\n{out}"
    assert proc.returncode != 0, f"a step whose only endpoint is {name!r} must fail:\n{out}"
    assert calls == [], f"the suite was started against a refused endpoint: {calls}\n{out}"
    for chain in (1, 8453):
        assert f"::warning::chain {chain}: {url} failed the preflight probe" in out, out
        assert f"::error::chain {chain}: no fork endpoint passed the preflight probe" in out, out
    forged = [ln for ln in out.splitlines() if ln.startswith("::error::forged")]
    assert not forged, f"a reply started its own workflow command: {forged}"


def test_a_hostile_first_endpoint_falls_through_to_a_healthy_one(server, tmp_path):
    """The honest path, and the control for every refusal above: the same harness, the same server,
    and a healthy endpoint IS chosen, the suite runs exactly once per chain against it, and the step
    passes. Without it, the refusals could all come from a harness that cannot pass anything."""
    base, pwned = server
    eth = [f"{base}/injection", f"{base}/healthy"]
    proc, calls = _run_step(tmp_path, eth=eth, base=[f"{base}/huge_hex", f"{base}/healthy"])
    out = proc.stdout + proc.stderr
    assert not pwned.exists(), out
    assert proc.returncode == 0, out
    assert calls == [f"1 {base}/healthy", f"8453 {base}/healthy"], (calls, out)
    assert "junit: tests=8 skipped=0" in out, out


@pytest.mark.parametrize(
    "suite, verdict", [("fail", "the suite failed against"), ("skip", "the suite skipped or ran nothing")]
)
def test_a_red_or_skipped_suite_is_red_and_never_retried(suite, verdict, server, tmp_path):
    """Two healthy endpoints per chain, and a suite that fails (or skips). The step must go red, and the
    suite must have run exactly ONCE per chain, against the first endpoint: an intermittent defect must
    not go green on whichever endpoint happens to pass a second attempt."""
    base, _pwned = server
    healthy = [f"{base}/healthy", f"{base}/healthy?second"]
    proc, calls = _run_step(tmp_path, eth=healthy, base=healthy, suite=suite)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert calls == [f"1 {base}/healthy", f"8453 {base}/healthy"], (calls, out)
    assert f"::error::chain 1: {verdict}" in out and f"::error::chain 8453: {verdict}" in out, out


@pytest.mark.parametrize(
    "name, expected",
    [
        ("injection", "not a hex quantity"),
        ("non_hex", "not a hex quantity"),
        ("huge_hex", "not a hex quantity"),
        ("decimal_number", "result is not a string"),
        ("not_json", "not JSON"),
        ("injection_in_code", "not hex data"),
        ("no_code", "no code"),
        ("annotation_injection", "no result"),
    ],
)
def test_the_probe_names_why_it_refused(name, expected, server):
    base, _pwned = server
    with pytest.raises(fork_rpc_probe.ProbeRefused, match=expected) as exc:
        fork_rpc_probe.probe(f"{base}/{name}", "0x" + "11" * 20, depth=1024, timeout=10)
    assert "\n" not in str(exc.value) and "\r" not in str(exc.value)


def test_the_probe_accepts_a_healthy_endpoint(server):
    base, _pwned = server
    fork_rpc_probe.probe(f"{base}/healthy", "0x" + "11" * 20, depth=1024, timeout=10)


def test_a_tip_below_the_probe_depth_is_refused(server):
    base, _pwned = server
    with pytest.raises(fork_rpc_probe.ProbeRefused, match="below the probe depth"):
        fork_rpc_probe.probe(f"{base}/healthy", "0x" + "11" * 20, depth=int(_GOOD_TIP, 16) + 1, timeout=10)


def test_a_redirect_is_refused_and_never_followed(server):
    """A 3xx would let an endpoint point the probe at an address only the runner can reach, and the
    refused reply's excerpt would print that address's body into a public log. Nothing honest needs one."""
    base, _pwned = server
    with pytest.raises(fork_rpc_probe.ProbeRefused, match="redirects are not followed") as exc:
        fork_rpc_probe.probe(f"{base}/redirect", "0x" + "11" * 20, depth=1024, timeout=10)
    assert _INTERNAL_HITS == [], "the probe followed the redirect"
    assert "INTERNAL-SECRET" not in str(exc.value)


def test_a_dripping_endpoint_is_cut_off_at_the_total_deadline(server):
    """The socket timeout bounds each read; a reply sent a byte at a time keeps every read short. The
    deadline is per CALL, so a dripping endpoint is refused near --timeout and the next one is tried."""
    base, _pwned = server
    started = time.monotonic()
    with pytest.raises(fork_rpc_probe.ProbeRefused, match="no complete reply within 2 s"):
        fork_rpc_probe.probe(f"{base}/drip", "0x" + "11" * 20, depth=1024, timeout=2)
    assert time.monotonic() - started < 6, "the call outlived its deadline"


def test_a_chosen_endpoint_not_on_the_list_is_refused(server, tmp_path):
    """The step trusts only the URLs it passed in: a probe that writes anything else is refused before
    the suite runs. Exercised with a stand-in probe that writes an off-list URL."""
    base, _pwned = server
    rogue = tmp_path / "rogue-python"
    rogue.write_text(
        "#!/bin/sh\n"
        'while [ $# -gt 0 ]; do [ "$1" = --chosen-file ] && { printf %s http://elsewhere.invalid/ > "$2"; exit 0; }; shift; done\n'
        "exit 1\n"
    )
    rogue.chmod(0o755)
    healthy = [f"{base}/healthy"]
    proc, calls = _run_step(tmp_path, eth=healthy, base=healthy, probe_python=str(rogue))
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert calls == [], f"the suite ran against an off-list endpoint: {calls}\n{out}"
    assert "the probe chose an endpoint that is not on the list" in out, out


def test_a_malformed_http_response_falls_through_to_the_next_endpoint(server, tmp_path):
    """A garbage status line raises http.client.HTTPException, which is neither URLError nor OSError.
    It must count as a refused endpoint, so the probe moves on, not a traceback that ends the step."""
    base, _pwned = server
    with pytest.raises(fork_rpc_probe.ProbeRefused, match="BadStatusLine"):
        fork_rpc_probe.probe(f"{base}/bad_status", "0x" + "11" * 20, depth=1024, timeout=10)
    proc, calls = _run_step(tmp_path, eth=[f"{base}/bad_status", f"{base}/healthy"], base=[f"{base}/healthy"])
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "Traceback" not in out, out
    assert calls == [f"1 {base}/healthy", f"8453 {base}/healthy"], (calls, out)

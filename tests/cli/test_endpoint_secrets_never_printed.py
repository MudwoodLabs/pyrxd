"""No CLI command prints a credential from an endpoint URL the operator gave it.

An endpoint URL routinely carries a credential — ``wss://user:password@host/``, an API key in the
path (``/v2/<key>``) or the query (``?apikey=<key>``). A hostile review found three routes by
which one reached the terminal: ``swap orders --node-rpc`` (the node-RPC transport rendered
aiohttp's exception repr, which quotes the full request URL, and a node's error body echoing the
request path went out verbatim); the ElectrumX failover client's ``logger.warning("... failed on
%s", endpoint.url)``, printed to stderr for every failed read; and ``fix: check that <URL> is
reachable`` hints on ~20 commands.

The tests run the REAL CLI in a subprocess (``python -m pyrxd.cli``, the production entry point,
with Python's real logging configuration — pytest's log capture would otherwise swallow the
failover warning), with FAKE secrets in every credential-bearing part of the URL, and assert none
appears in stdout or stderr, in human and ``--json`` mode.

The command set is DERIVED from the click tree (every option whose name mentions url/rpc/
electrumx/node, or whose help mentions a URL); the four options known to take an endpoint are
asserted to be in it, so a derivation that silently found nothing would fail.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import click
import pytest

import pyrxd
from pyrxd.cli.main import cli

USER = "FAKEUSERSECRET89AB"
PW = "FAKEPWSECRET77"
PATH = "FAKEPATHSECRET0123"
QUERY = "FAKEQUERYSECRET4567"
FRAG = "FAKEFRAGSECRET42"
SECRETS = (USER, PW, PATH, QUERY, FRAG)

_ENDPOINT_NAME = re.compile(r"url|rpc|electrumx|node", re.IGNORECASE)


def _walk(cmd: click.Command, path: tuple[str, ...]) -> Iterator[tuple[tuple[str, ...], click.Command]]:
    if isinstance(cmd, click.Group):
        for name, sub in cmd.commands.items():
            yield from _walk(sub, (*path, name))
    else:
        yield path, cmd


def _is_endpoint_option(p: click.Parameter) -> bool:
    if not isinstance(p, click.Option) or p.is_flag:
        return False
    if p.name in ("rpc_user", "rpc_password"):
        return False  # credentials passed separately, not URLs
    return bool(_ENDPOINT_NAME.search(p.name or "") or re.search(r"\bURLs?\b", p.help or ""))


def derived_endpoint_options() -> dict[tuple[str, ...], list[str]]:
    """``{command path: [endpoint option flags]}``; the root group's options under ``()``."""
    out = {(): [p.opts[0] for p in cli.params if _is_endpoint_option(p)]}
    for path, cmd in _walk(cli, ()):
        flags = [p.opts[0] for p in cmd.params if _is_endpoint_option(p)]
        if flags:
            out[path] = flags
    return out


def test_the_endpoint_option_derivation_finds_the_known_options() -> None:
    """Control: a derivation that cannot find the options we KNOW exist is broken, not reassuring."""
    derived = derived_endpoint_options()
    print("derived endpoint options:", derived)
    flags = {f for fs in derived.values() for f in fs}
    assert {"--node-rpc", "--electrumx", "--eth-rpc-url", "--btc-api-url"} <= flags
    # Membership pinned: a NEW endpoint option must be added to the sweep below, not skipped.
    assert set(derived) == {(), ("swap", "status"), ("swap", "orders"), ("swap", "recover-preimage")}, derived


# --------------------------------------------------------------------------- the subprocess harness


def _env(tmp_path: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYRXD_")}
    env["HOME"] = str(tmp_path)  # no operator config file can add endpoints to this run
    env["PYTHONPATH"] = str(Path(pyrxd.__file__).resolve().parents[1])  # this checkout, not an install
    return env


def _pyrxd(tmp_path: Path, *args: str) -> tuple[int, str, str]:
    r = subprocess.run(
        [sys.executable, "-m", "pyrxd.cli", *args],
        capture_output=True,
        text=True,
        env=_env(tmp_path),
        timeout=120,
    )
    return r.returncode, r.stdout, r.stderr


def _assert_clean(rc: int, out: str, err: str, what: str) -> None:
    for s in SECRETS:
        assert s.lower() not in out.lower(), f"{what}: {s} in STDOUT:\n{out}"
        assert s.lower() not in err.lower(), f"{what}: {s} in STDERR:\n{err}"
    assert rc != 0, f"{what}: an unreachable endpoint must not succeed:\n{out}\n{err}"
    assert "unexpected failure" not in err, f"{what}: {err}"


def _keyed(base: str) -> str:
    """*base* (``scheme://host:port``) with a fake secret in every credential-bearing part."""
    scheme, rest = base.split("://", 1)
    return f"{scheme}://{USER}:{PW}@{rest}/v2/{PATH}?apikey={QUERY}#{FRAG}"


# --------------------------------------------------------------------------- hostile HTTP endpoints


class _Hostile(BaseHTTPRequestHandler):
    """``redirect``: a 307 loop (aiohttp's TooManyRedirects repr quotes the URL);
    ``echo``: an RPC error body quoting the request path and query back;
    ``badjson``: a 200 whose body is not JSON."""

    def _answer(self) -> None:
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        mode = self.server.mode  # type: ignore[attr-defined]
        self.server.hits += 1  # type: ignore[attr-defined]
        if mode == "redirect":
            self.send_response(307)
            self.send_header("Location", self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "echo":
            body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": None,
                    "error": {"code": -32000, "message": f"bad key {self.path}"},
                }
            ).encode()
            self.send_response(401)
        else:
            body = b"{not json"
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _answer

    def log_message(self, *a: Any) -> None:
        return None


@pytest.fixture
def hostile() -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Hostile)
    srv.mode = "redirect"  # type: ignore[attr-defined]
    srv.hits = 0  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()


@pytest.fixture
def black_hole() -> Iterator[dict[str, int]]:
    """A TCP port that accepts and immediately closes — an ElectrumX endpoint that fails every read.

    Counts connections, so a test can prove the command REACHED the endpoint (non-vacuity: a run
    that failed on argument validation before any read would be clean for the wrong reason).
    """
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)
    state = {"port": sock.getsockname()[1], "hits": 0}
    stop = threading.Event()

    def serve() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            state["hits"] += 1
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield state
    stop.set()
    t.join()
    sock.close()


# --------------------------------------------------------------------------- swap orders --node-rpc


@pytest.mark.parametrize("mode", ["redirect", "echo", "badjson"])
@pytest.mark.parametrize("json_flag", [(), ("--json",)])
def test_swap_orders_never_prints_the_node_rpc_secrets(tmp_path, hostile, mode, json_flag) -> None:
    hostile.mode = mode
    url = _keyed(f"http://127.0.0.1:{hostile.server_port}")
    rc, out, err = _pyrxd(tmp_path, *json_flag, "swap", "orders", "rxd", "--node-rpc", url)
    assert hostile.hits >= 1, "the command never reached the endpoint — the check would be vacuous"
    _assert_clean(rc, out, err, f"swap orders [{mode}]")
    assert "orderbook read failed" in err
    assert f"127.0.0.1:{hostile.server_port}" in err or mode == "echo"  # names the endpoint by host:port


def test_node_rpc_source_error_text_carries_neither_url_nor_repr() -> None:
    """Unit, at the source: NodeRpcSource itself must not embed the URL — every caller benefits."""
    import asyncio

    from pyrxd.security.errors import NetworkError
    from pyrxd.swap.rswp.node_rpc import NodeRpcSource

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Hostile)
    srv.hits = 0  # type: ignore[attr-defined]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for mode in ("redirect", "echo", "badjson"):
            srv.mode = mode  # type: ignore[attr-defined]
            url = _keyed(f"http://127.0.0.1:{srv.server_port}")

            async def call(u: str = url) -> None:
                async with NodeRpcSource(u) as source:
                    await source.get_open_orders("00" * 36)

            with pytest.raises(NetworkError) as ei:
                asyncio.run(call())
            text = str(ei.value)
            for s in SECRETS:
                assert s not in text, (mode, text)
            assert "RequestInfo" not in text and "URL(" not in text, text
    finally:
        srv.shutdown()


def test_swap_orders_renderer_scrubs_the_node_rpc_url_itself(runner, monkeypatch) -> None:
    """Defence in depth at the CLI renderer: even a source that DID quote its URL is scrubbed.

    The fake source raises an error carrying the whole keyed URL — what NodeRpcSource did before
    this fix. The renderer must remove it because ``--node-rpc`` is an endpoint the command used.
    """
    from pyrxd.cli import swap_book_cmds
    from pyrxd.security.errors import NetworkError

    url = _keyed("https://node.example:7332")

    class _Leaky:
        def __init__(self, u: str, **_: Any) -> None:
            self.u = u

        async def __aenter__(self) -> _Leaky:
            raise NetworkError(f"node RPC getopenorders transport error: url={self.u}")

        async def __aexit__(self, *a: Any) -> None:
            return None

    monkeypatch.setattr(swap_book_cmds, "NodeRpcSource", _Leaky)
    result = runner.invoke(cli, ["swap", "orders", "rxd", "--node-rpc", url])
    assert result.exit_code != 0
    assert "orderbook read failed" in result.output
    for s in SECRETS:
        assert s not in result.output, result.output

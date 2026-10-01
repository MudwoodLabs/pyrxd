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

from .test_swap_recovery_cmds import swap as swap_fixture  # noqa: F401 - registered as a fixture by that name

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


# --------------------------------------------------------------------------- the sweep, every endpoint option

P_TEST = bytes.fromhex("11" * 32)
H_TEST = hashlib.sha256(P_TEST).digest()
TXID = "ab" * 32


def _swap_file(tmp_path: Path, chain: str) -> Path:
    """A cold-recovery keys file (fresh random keys; nothing is ever broadcast)."""
    from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
    from pyrxd.keys import PrivateKey

    taker, maker = PrivateKey(), PrivateKey()
    cov = build_htlc_covenant_rxd(
        amount=100_000,
        taker_pkh=bytes(taker.public_key().hash160()),
        maker_pkh=bytes(maker.public_key().hash160()),
        hashlock=H_TEST,
        refund_csv=20,
    )
    d: dict[str, Any] = {
        "stage": "dust",
        "rxd_network": "bc",
        "hashlock_H": H_TEST.hex(),
        "taker_rxd_wif": taker.wif(),
        "rxd_covenant_spk": cov.funded_spk.hex(),
        "t_rxd_blocks": 20,
    }
    if chain == "btc":
        d.update(btc_network="bc", t_btc_blocks=30, btc_htlc_address="bc1qexample")
    else:
        d.update(eth_chain="sepolia", eth_timeout_unix_s=1780686598)
    p = tmp_path / f"keys_{chain}.json"
    p.write_text(json.dumps(d))
    p.chmod(0o600)
    return p


def _fee_wif_file(tmp_path: Path) -> Path:
    from pyrxd.keys import PrivateKey

    p = tmp_path / "fee.wif"
    p.write_text(PrivateKey().wif())
    p.chmod(0o600)
    return p


def _wallet(tmp_path: Path) -> tuple[Path, str]:
    from pyrxd.hd.bip39 import mnemonic_from_entropy
    from pyrxd.hd.wallet import HdWallet

    mnemonic = mnemonic_from_entropy(os.urandom(16))
    path = tmp_path / "wallet.dat"
    HdWallet.from_mnemonic(mnemonic).save(path)
    return path, mnemonic


def _pyrxd_in(tmp_path: Path, args: list[str], stdin: str | None) -> tuple[int, str, str]:
    r = subprocess.run(
        [sys.executable, "-m", "pyrxd.cli", *args],
        capture_output=True,
        text=True,
        env=_env(tmp_path),
        input=stdin,
        timeout=180,
    )
    return r.returncode, r.stdout, r.stderr


def _recover_commands(tmp_path: Path, url: str) -> dict[tuple[str, str], list[str]]:
    kb, ke = _swap_file(tmp_path, "btc"), _swap_file(tmp_path, "eth")
    rp = ["swap", "recover-preimage"]
    return {
        ("swap recover-preimage", "--btc-api-url"): [
            *rp, "--swap-file", str(kb), "--btc-funding-outpoint", f"{TXID}:1", "--btc-api-url", url,
        ],
        ("swap recover-preimage", "--eth-rpc-url"): [
            *rp, "--swap-file", str(ke), "--eth-contract", "0x" + "ab" * 20, "--eth-rpc-url", url,
        ],
    }  # fmt: skip


#: ``swap status`` reads the counter leg only after a successful RXD covenant read, so it is driven
#: in-process with the fake ElectrumX client of ``test_swap_recovery_cmds`` (the counter-leg read
#: itself is real: a real aiohttp session to the hostile server). Logged output is checked via caplog.
STATUS_OPTIONS = ("--btc-api-url", "--eth-rpc-url")


def test_every_derived_endpoint_option_is_swept(tmp_path) -> None:
    """Both directions: every derived (command, option) is swept, and nothing swept is stale."""
    swept = {("", "--electrumx"), ("swap orders", "--node-rpc")}
    swept |= set(_recover_commands(tmp_path, "http://x"))
    swept |= {("swap status", f) for f in STATUS_OPTIONS}
    derived = {(" ".join(path), flag) for path, flags in derived_endpoint_options().items() for flag in flags}
    assert derived == swept, (derived, swept)


@pytest.mark.parametrize("mode", ["redirect", "echo"])
def test_recover_preimage_endpoint_options_never_print_their_secrets(tmp_path, hostile, mode) -> None:
    hostile.mode = mode
    url = _keyed(f"http://127.0.0.1:{hostile.server_port}")
    for name, args in _recover_commands(tmp_path, url).items():
        for json_flag in ((), ("--json",)):
            before = hostile.hits
            rc, out, err = _pyrxd(tmp_path, *json_flag, *args)
            assert hostile.hits > before, f"{name}: never reached the endpoint — vacuous"
            _assert_clean(rc, out, err, f"{name} [{mode}] {json_flag}")


@pytest.mark.parametrize("mode", ["redirect", "echo", "badjson"])
@pytest.mark.parametrize("option", STATUS_OPTIONS)
@pytest.mark.parametrize("output_mode", ["human", "json"])
def test_swap_status_endpoint_options_never_print_their_secrets(
    request, hostile, caplog, mode, option, output_mode
) -> None:
    from .test_swap_recovery_cmds import _eth_swap, _status

    case = request.getfixturevalue("swap_fixture")

    hostile.mode = mode
    url = _keyed(f"http://127.0.0.1:{hostile.server_port}")
    if option == "--eth-rpc-url":
        swap = _eth_swap(case)
        extra = ["--eth-contract", "0x" + "ab" * 20, option, url]
    else:
        swap = case
        extra = ["--btc-funding-outpoint", f"{TXID}:1", option, url]
    caplog.set_level("DEBUG")
    res = _status(swap, *extra, output_mode=output_mode)
    assert hostile.hits >= 1, f"swap status {option}: never reached the endpoint — vacuous:\n{res.output}"
    text = res.output + caplog.text
    for s in SECRETS:
        assert s.lower() not in text.lower(), f"swap status {option} [{mode}]: {s} in:\n{text}"
    assert "unexpected failure" not in text


def _electrumx_commands(tmp_path: Path) -> dict[str, tuple[list[str], str | None]]:
    """Commands that read through the root ``--electrumx`` endpoint: ``{name: (args, stdin)}``."""
    wallet, mnemonic = _wallet(tmp_path)
    kb = _swap_file(tmp_path, "btc")
    fee = _fee_wif_file(tmp_path)
    w = ["--wallet", str(wallet)]
    return {
        "balance": ([*w, "balance"], mnemonic + "\n"),
        "utxos": ([*w, "utxos"], mnemonic + "\n"),
        "address --next": ([*w, "address", "--next"], mnemonic + "\n"),
        "glyph list": ([*w, "glyph", "list"], mnemonic + "\n"),
        "glyph inspect --fetch": (["glyph", "inspect", "--fetch", TXID], None),
        "glyph dmint-estimate --contract": (["glyph", "dmint-estimate", "--contract", f"{TXID}:0"], None),
        "verify": (["verify", "--min-confirmations", "1", TXID], None),
        "swap status --check-chain": (["swap", "status", "--swap-file", str(kb), "--check-chain"], None),
        "swap build-refund": (["swap", "build-refund", "--swap-file", str(kb), "--fee-wif-file", str(fee)], None),
        "swap build-claim": (
            ["swap", "build-claim", "--swap-file", str(kb), "--preimage", P_TEST.hex(), "--fee-wif-file", str(fee)],
            None,
        ),
    }


def test_electrumx_endpoint_secrets_never_printed(tmp_path, black_hole) -> None:
    """``--electrumx`` with a keyed URL whose server fails every read: the failover warning, the
    error and its ``fix:`` hint must name the endpoint by scheme://host:port only."""
    keyed = _keyed(f"wss://127.0.0.1:{black_hole['port']}")
    # A WebSocket URI may not carry a fragment, so the client refuses the first spelling before
    # connecting (that refusal's text must not leak either); the second one reaches the server.
    variants = {"with fragment": (keyed, False), "no fragment": (keyed.split("#", 1)[0], True)}
    commands = _electrumx_commands(tmp_path)
    for variant, (url, must_connect) in variants.items():
        for name, (args, stdin) in commands.items():
            for json_flag in ((), ("--json",)):
                before = black_hole["hits"]
                argv = [*json_flag, "--network", "mainnet", "--electrumx", url, *args]
                rc, out, err = _pyrxd_in(tmp_path, argv, stdin)
                if must_connect:
                    assert black_hole["hits"] > before, f"{name}: never reached the endpoint — vacuous:\n{err}"
                _assert_clean(rc, out, err, f"{name} {json_flag} [{variant}]")


def test_the_unexpected_failure_path_scrubs_every_url_on_the_command_line(monkeypatch, capsys) -> None:
    """The bug path (exit 4) prints the exception's own text; a library's can quote the URL."""
    from pyrxd.cli import main

    url = _keyed("https://node.example:7332")

    def boom() -> None:
        raise RuntimeError(f"Cannot connect to host for url {url}")

    monkeypatch.setattr(main, "cli", boom)
    monkeypatch.setattr(sys, "argv", ["pyrxd", "swap", "orders", "rxd", f"--node-rpc={url}"])
    with pytest.raises(SystemExit) as ei:
        main.run()
    assert ei.value.code == 4
    err = capsys.readouterr().err
    assert "unexpected failure (RuntimeError)" in err
    assert "node.example" in err  # the useful part survives
    for s in SECRETS:
        assert s not in err, err

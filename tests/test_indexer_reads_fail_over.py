"""Indexer reads fail over to the configured server that runs the RXinDexer extension.

THE BUG. Of the two shipped mainnet servers (``registry.DEFAULT_ENDPOINTS["mainnet"]``), only the
second, ``electrumx.radiantcore.org``, runs the RXinDexer extension. The first,
``electrumx.radiant4people.com``, answers indexer calls with JSON-RPC ``-32601`` (measured
2026-09-24 for ``wave.resolve``, ``wave.reverse_lookup``, ``glyph.get_token``, ``glyph.get_recent``
and ``swap.get_orders``). ``FailoverElectrumXClient.call_extension`` retries only when the caller
declares the call idempotent, and ``RxinDexerClient._call`` never did, so the first server's
``-32601`` was final: ``pyrxd glyph inspect <txid> --fetch --verify-wave`` failed with the shipped
defaults (measured live 2026-09-24).

WHAT IS FAKED AND WHAT IS NOT. Only ``websockets.connect``. Each fake server speaks JSON-RPC frames
to a REAL ``ElectrumXClient`` reader loop, and the server without the extension answers with the
frame measured from ``electrumx.radiant4people.com`` on 2026-09-24::

    {"jsonrpc":"2.0","error":{"code":-32601,"message":"unknown method \\"wave.reverse_lookup\\""},"id":2}

so the exception the failover layer sees is the one the transport really builds from it. Chain
verification is ON (both fakes serve the real mainnet genesis header), as in production.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import pyrxd
from pyrxd.cli.main import cli
from pyrxd.keys import PrivateKey
from pyrxd.network import electrumx as electrumx_mod
from pyrxd.network import rxindexer as rxindexer_mod
from pyrxd.network.electrumx import ElectrumXClient, _rpc_error, script_hash_for_address
from pyrxd.network.failover import FailoverElectrumXClient
from pyrxd.network.registry import DEFAULT_ENDPOINTS, NetworkProfile
from pyrxd.network.rxindexer import RxinDexerClient, RxinDexerError
from pyrxd.security.errors import NetworkError, PolicyRejection, RpcMethodNotFound
from pyrxd.security.types import Txid
from tests.test_hashmark_verify_cli import _mark_script, _tx_with

# The real Radiant mainnet genesis header — the live-captured vector also used by
# tests/network/test_registry.py and tests/network/test_electrumx.py. `assert_chain` hashes it
# against the registry constant, so a wrong copy here fails every test below, loudly.
_MAINNET_GENESIS_HEADER_HEX = (
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "372cbaf89794aeed5e711b02e78ec4502ad8b315a987c2e2758a85e36a3f7c02"
    "aadeaf62"
    "ffff001d"
    "7980b72a"
)

PLAIN_URL, INDEXER_URL = DEFAULT_ENDPOINTS["mainnet"]  # the shipped order: plain ElectrumX first

# Every method RxinDexerClient calls, each reviewed as a read against upstream
# Radiant-Core/RXinDexer @ ca8a6a4e (2026-09-24). In `electrumx/server/glyph_api.py` each handler
# calls only `bump_cost` (per-session rate accounting, charged on every request), methods of
# `wave_index` / `glyph_index` / `swap_index`, and — for `glyph.get_token` — the daemon's
# `getrawtransaction`. Those index methods, followed one level into their own helpers, only read
# `utxo_db` (`get` / `iterator`) and build local results; the one attribute they write is
# `wave_index.hot_names`, an in-memory cache `resolve` fills on a hit. REVIEWED, NOT DERIVED:
# the test below pins the SET, so a new method forces a new review. Upstream ALSO serves
# `*.subscribe.*` methods, which register per-session state and are not reads in this sense;
# none is wrapped.
_REVIEWED_READS = frozenset(
    {
        "wave.resolve",
        "wave.check_available",
        "wave.reverse_lookup",
        "wave.get_subdomains",
        "wave.stats",
        "glyph.get_token",
        "glyph.get_balance",
        "glyph.get_metadata",
        "glyph.get_recent",
        "glyph.get_tokens_by_type",
        "swap.get_orders",
    }
)


def _entry(label: str) -> dict:
    """One `wave.reverse_lookup` row, in the shape measured from electrumx.radiantcore.org."""
    return {
        "ref": "9044a9f66bc747bff06f5496e1bf4d89eb78b3f1cb291722525832bc655fed11_0",
        "name": label,
        "full_name": f"{label}.rxd",
        "expires": 1851079510,
        "status": "active",
        "zone": {"address": "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"},
        "owner": "e4bf68e0c8eb9018f15fa0",
    }


class _Server:
    """One ElectrumX server as the wire sees it: a JSON-RPC frame in, a frame out."""

    def __init__(self, url: str, *, indexer: bool, txs: dict[str, bytes] | None = None, names=None) -> None:
        self.url = url
        self.indexer = indexer
        self.txs = txs or {}
        self.names: dict[str, list[dict]] = names or {}  # scripthash hex -> reverse_lookup rows
        self.received: list[str] = []  # methods, in arrival order
        self.unexpected: list[str] = []
        self.sockets: list[_Socket] = []
        self.hold: set[str] = set()  # methods whose answer waits for `released`
        self.released = asyncio.Event()

    def answer(self, req: dict) -> dict:
        method, params, rid = req["method"], req.get("params") or [], req["id"]
        if method == "blockchain.block.header" and params == [0]:
            return {"jsonrpc": "2.0", "result": _MAINNET_GENESIS_HEADER_HEX, "id": rid}
        if method == "blockchain.transaction.get" and len(params) == 2 and params[1] is False and params[0] in self.txs:
            return {"jsonrpc": "2.0", "result": self.txs[params[0]].hex(), "id": rid}
        if method.startswith(("wave.", "glyph.", "swap.")):
            if not self.indexer:
                # What a plain ElectrumX says — the exact frame measured, see the module docstring.
                return {"jsonrpc": "2.0", "error": {"code": -32601, "message": f'unknown method "{method}"'}, "id": rid}
            if method == "wave.reverse_lookup":
                return {"jsonrpc": "2.0", "result": self.names.get(params[0], []), "id": rid}
        self.unexpected.append(f"{method} {params!r}")
        return {"jsonrpc": "2.0", "error": {"code": -32603, "message": "not scripted in this test"}, "id": rid}


class _Socket:
    def __init__(self, server: _Server) -> None:
        self.server = server
        self.outbox: asyncio.Queue[str] = asyncio.Queue()
        self.closed = False
        self._held: list[asyncio.Task] = []

    async def send(self, payload: str) -> None:
        req = json.loads(payload)
        self.server.received.append(req["method"])
        frame = json.dumps(self.server.answer(req), separators=(",", ":"))
        if req["method"] in self.server.hold:
            self._held.append(asyncio.get_running_loop().create_task(self._after_release(frame)))
        else:
            self.outbox.put_nowait(frame)

    async def _after_release(self, frame: str) -> None:
        await self.server.released.wait()
        self.outbox.put_nowait(frame)

    async def recv(self) -> str:
        return await self.outbox.get()

    async def close(self) -> None:
        self.closed = True


def _wire(monkeypatch, *servers: _Server) -> None:
    by_url = {s.url: s for s in servers}

    async def connect(url, *args, **kwargs):
        sock = _Socket(by_url[url])
        by_url[url].sockets.append(sock)
        return sock

    monkeypatch.setattr(electrumx_mod.websockets, "connect", connect)


def _default_profile() -> NetworkProfile:
    return NetworkProfile.build("mainnet", DEFAULT_ENDPOINTS["mainnet"])


async def _until(cond, *, spins: int = 1000) -> None:
    for _ in range(spins):
        if cond():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition never became true")


ADDRESS = "14XmXG3dSBWZUukGT3xzS9zxpiZ53vgx1i"
SH = script_hash_for_address(ADDRESS).hex()


# ── the transport: what the failover layer is actually handed ─────────────────


@pytest.mark.asyncio
async def test_the_measured_minus_32601_frame_arrives_as_rpc_method_not_found(monkeypatch) -> None:
    plain = _Server(PLAIN_URL, indexer=False)
    _wire(monkeypatch, plain)
    async with ElectrumXClient([PLAIN_URL]) as ex:
        with pytest.raises(RpcMethodNotFound) as exc:
            await ex.call_extension("wave.reverse_lookup", [SH])
    # Still a NetworkError, so every existing handler catches it; never a node verdict.
    assert isinstance(exc.value, NetworkError)
    assert not isinstance(exc.value, PolicyRejection)
    assert str(exc.value) == "ElectrumX RPC error (code -32601)"


@pytest.mark.parametrize("method", sorted(_REVIEWED_READS))
def test_no_wrapped_method_name_is_mistaken_for_a_node_verdict(method) -> None:
    """`_rpc_error` checks policy markers ("dust", "scriptpubkey", "non-final", ...) BEFORE the
    -32601 code, against a message that echoes the method name. A wrapped method whose name
    contained a marker would come back as a PolicyRejection, which failover never retries."""
    err = _rpc_error(-32601, f'unknown method "{method}"')
    assert type(err) is RpcMethodNotFound


# ── the failover layer, over real reader loops ────────────────────────────────


@pytest.mark.asyncio
async def test_the_first_servers_minus_32601_is_not_final_and_costs_it_nothing(monkeypatch) -> None:
    plain = _Server(PLAIN_URL, indexer=False)
    idx = _Server(INDEXER_URL, indexer=True, names={SH: [_entry("create")]})
    _wire(monkeypatch, plain, idx)

    async with FailoverElectrumXClient(_default_profile()) as client:
        assert await client.call_extension("wave.reverse_lookup", [SH], idempotent=True) == [_entry("create")]
        # The plain server really was asked first, and answered -32601 (not vacuous).
        assert plain.received == ["blockchain.block.header", "wave.reverse_lookup"]
        # It answered, so it is healthy: its socket stays open and it stays the primary.
        assert [s.closed for s in plain.sockets] == [False]
        assert client.active_url == PLAIN_URL
    assert plain.unexpected == idx.unexpected == []


@pytest.mark.asyncio
async def test_a_core_read_in_flight_on_that_server_survives_its_minus_32601(monkeypatch) -> None:
    """Why the server is not discarded. `_discard` closes its client, and closing fails every call
    in flight on that socket — so an indexer miss would abort an unrelated fetch on a healthy
    server (which then re-ran on the other one)."""
    key = PrivateKey()
    txid, raw = _tx_with(_mark_script(b"in flight\n", key))
    plain = _Server(PLAIN_URL, indexer=False, txs={txid: raw})
    plain.hold = {"blockchain.transaction.get"}
    idx = _Server(INDEXER_URL, indexer=True, txs={txid: raw}, names={SH: [_entry("create")]})
    _wire(monkeypatch, plain, idx)

    async with FailoverElectrumXClient(_default_profile()) as client:
        fetch = asyncio.create_task(client.get_transaction(Txid(txid)))
        await _until(lambda: "blockchain.transaction.get" in plain.received)
        assert await client.call_extension("wave.reverse_lookup", [SH], idempotent=True) == [_entry("create")]
        plain.released.set()
        assert bytes(await fetch) == raw
        assert "blockchain.transaction.get" not in idx.received  # answered by the primary, once
        assert [s.closed for s in plain.sockets] == [False]


# ── the funnel every indexer read crosses: RxinDexerClient._call ──────────────


@pytest.mark.asyncio
async def test_rxindexer_over_the_default_profile_reads_from_the_indexer(monkeypatch) -> None:
    plain = _Server(PLAIN_URL, indexer=False)
    idx = _Server(INDEXER_URL, indexer=True, names={SH: [_entry("create"), _entry("explorer")]})
    _wire(monkeypatch, plain, idx)

    async with FailoverElectrumXClient(_default_profile()) as client:
        assert await RxinDexerClient(client).wave_reverse_lookup(ADDRESS) == ["create.rxd", "explorer.rxd"]
    assert "wave.reverse_lookup" in plain.received  # the -32601 happened and was moved past


@pytest.mark.asyncio
async def test_over_a_plain_single_client_the_minus_32601_still_surfaces(monkeypatch) -> None:
    """The other branch: a plain ElectrumXClient has no `idempotent` keyword and nothing to fail
    over to. The answer must still be the server's -32601 — not a TypeError from a keyword the
    plain client does not take."""
    plain = _Server(PLAIN_URL, indexer=False)
    _wire(monkeypatch, plain)
    async with ElectrumXClient([PLAIN_URL]) as ex:
        with pytest.raises(RxinDexerError, match=r"code -32601"):
            await RxinDexerClient(ex).wave_reverse_lookup(ADDRESS)


@pytest.mark.asyncio
async def test_with_no_indexer_configured_the_error_says_no_server_implements_it(monkeypatch) -> None:
    """E.g. `--electrumx wss://electrumx.radiant4people.com:50022/`: one server, no extension."""
    plain = _Server(PLAIN_URL, indexer=False)
    _wire(monkeypatch, plain)
    async with FailoverElectrumXClient(NetworkProfile.build("mainnet", [PLAIN_URL])) as client:
        with pytest.raises(RxinDexerError, match=r"none of the 1 ElectrumX endpoint\(s\) tried implements"):
            await RxinDexerClient(client).wave_reverse_lookup(ADDRESS)


def test_every_indexer_method_the_client_calls_is_a_reviewed_read() -> None:
    """`_call` declares EVERY call idempotent. That is a claim about each method, so the set is
    derived from the source and pinned: a new `self._call("x.y", ...)` fails here until someone
    has checked it is a read too (a `*.subscribe.*` method is not) and added it above."""
    tree = ast.parse(Path(rxindexer_mod.__file__).read_text())
    called: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "_call"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
        ):
            first = node.args[0]
            assert isinstance(first, ast.Constant) and isinstance(first.value, str), ast.unparse(node)
            called.add(first.value)
    assert called == _REVIEWED_READS


def test_every_production_indexer_call_crosses_rxindexer_call() -> None:
    """The fix lives in `RxinDexerClient._call`, so it holds only if nothing in src/ calls
    `call_extension` by another road. Derived by walking every module, not by listing files."""
    src = Path(pyrxd.__file__).parent
    callers: list[tuple[str, str]] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text())
        parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "call_extension"
            ):
                scope = parent.get(node)
                while scope is not None and not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    scope = parent.get(scope)
                callers.append((path.relative_to(src).as_posix(), scope.name if scope else "<module>"))
    # The failover facade's own delegation to its per-endpoint client, and the funnel.
    assert set(callers) == {("network/failover.py", "call_extension"), ("network/rxindexer.py", "_call")}


# ── the production entry point: `pyrxd glyph inspect --fetch --verify-wave` ───


def test_glyph_inspect_verify_wave_names_the_signer_with_the_shipped_defaults(monkeypatch, tmp_path) -> None:
    """No config file, no --electrumx: the shipped mainnet pair, plain server first. Only the
    websocket is fake — the config load, `make_client`, the failover client, both reader loops,
    the chain check, the classifier, the signature check and the WAVE lookup are all real."""
    for var in ("PYRXD_ELECTRUMX", "PYRXD_NETWORK"):
        monkeypatch.delenv(var, raising=False)
    key = PrivateKey()
    txid, raw = _tx_with(_mark_script(b"the advisory, as published\n", key, label="advisory v1"))
    signer_sh = script_hash_for_address(key.public_key().address()).hex()
    plain = _Server(PLAIN_URL, indexer=False, txs={txid: raw})
    idx = _Server(INDEXER_URL, indexer=True, txs={txid: raw}, names={signer_sh: [_entry("mark-signer")]})
    _wire(monkeypatch, plain, idx)

    r = CliRunner().invoke(
        cli,
        [
            "--config",
            str(tmp_path / "absent.toml"),
            "--wallet",
            str(tmp_path / "w.dat"),
            "--json",
            "glyph",
            "inspect",
            txid,
            "--fetch",
            "--verify-wave",
        ],
    )
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    identities = [row["hashmark"]["wave_identity"] for row in out["outputs"] if row.get("hashmark")]
    assert len(identities) == 1
    assert identities[0]["resolved"] is True, identities[0]
    assert identities[0]["names_resolving_now"] == ["mark-signer.rxd"]
    # Non-vacuity: the fetch came from the plain server, and it WAS asked for the names first.
    assert "blockchain.transaction.get" in plain.received
    assert "wave.reverse_lookup" in plain.received
    assert plain.unexpected == idx.unexpected == []

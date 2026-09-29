"""Every broadcast checks the server's txid echo against the bytes it sent (#780).

``HdWallet.send``, ``pyrxd wallet send`` and ``pyrxd swap cancel`` reported whatever txid the
server returned from ``blockchain.transaction.broadcast``. A lying or broken server could have
the CLI print a txid for a transaction that was not the one sent — the value a user then looks
up, or hands to a counterparty. ``GlyphClient`` already refused a mismatched echo (0.19.0).

The check now lives in :meth:`ElectrumXClient.broadcast`, the only code in pyrxd that issues
``blockchain.transaction.broadcast``, as :func:`verified_broadcast_txid`. ``GlyphClient``'s
``_confirmed_txid`` and ``FailoverElectrumXClient.broadcast`` delegate to it, so there is one
check, not several.

The behavioural tests below fake only the SERVER: each uses a real :class:`ElectrumXClient`
whose ``_call`` answers the JSON-RPC methods, so the client's own parsing and the check run
exactly as in production. :class:`TestEveryBroadcastSiteCrossesTheCheck` derives the call
sites from the source.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from pyrxd.cli.context import CliContext
from pyrxd.cli.main import cli
from pyrxd.hash import hash256
from pyrxd.hd.wallet import HdWallet
from pyrxd.network.electrumx import ElectrumXClient, script_hash_for_address
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import BroadcastEchoMismatch
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
_FUND = 100 * 100_000_000
#: A well-formed txid for some OTHER transaction — what a lying server echoes.
_LIE = "ee" * 32

_SRC = Path(__file__).resolve().parents[1] / "src" / "pyrxd"


#: Somebody else's address. A second output keeps a source transaction over the 64 bytes
#: ``RawTx`` requires of anything the real client reads back.
_ELSEWHERE = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"


def _src_tx(address: str, value: int = _FUND) -> Transaction:
    """A funding transaction paying *address* at vout 0 (the only vout the server lists)."""
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(address), value))
    tx.add_output(TransactionOutput(P2PKH().lock(_ELSEWHERE), 1_000))
    return tx


def _txid_of(raw: bytes) -> str:
    return hash256(raw)[::-1].hex()


class _Server(ElectrumXClient):
    """A real ``ElectrumXClient`` with the server faked at the JSON-RPC boundary.

    Only ``_call`` (the wire) and ``_ensure_connected`` (the socket) are replaced. The
    client's own result parsing — including ``broadcast``'s echo check — is the shipped code.
    ``lie`` makes the server echo :data:`_LIE` instead of the txid of what it was sent.
    """

    def __init__(self, funded: dict[str, Transaction], *, lie: bool) -> None:
        super().__init__(["wss://fake.invalid/"])
        self.lie = lie
        self.by_hash = {bytes(script_hash_for_address(a)).hex(): t for a, t in funded.items()}
        self.txs = {t.txid(): t for t in funded.values()}
        self.broadcasts: list[bytes] = []

    async def _ensure_connected(self) -> None:
        return None

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.scripthash.get_history":
            tx = self.by_hash.get(params[0])
            return [{"tx_hash": tx.txid(), "height": 1}] if tx else []
        if method == "blockchain.scripthash.listunspent":
            tx = self.by_hash.get(params[0])
            return [{"tx_hash": tx.txid(), "tx_pos": 0, "value": tx.outputs[0].satoshis, "height": 1}] if tx else []
        if method == "blockchain.transaction.get":
            return self.txs[params[0]].serialize().hex()
        if method == "blockchain.transaction.broadcast":
            raw = bytes.fromhex(params[0])
            self.broadcasts.append(raw)
            return _LIE if self.lie else _txid_of(raw)
        raise AssertionError(f"unexpected RPC {method} {params}")


# --------------------------------------------------------------------------- HdWallet.send


class TestHdWalletSend:
    def _send(self, *, lie: bool) -> tuple[_Server, Any]:
        w = HdWallet.from_mnemonic(MNEMONIC)
        server = _Server({w.derive_address(0, 0): _src_tx(w.derive_address(0, 0))}, lie=lie)
        to = HdWallet.from_mnemonic(MNEMONIC).derive_address(0, 5)
        try:
            return server, asyncio.run(w.send(server, to, 1_000_000))
        except BroadcastEchoMismatch as exc:
            return server, exc

    def test_an_honest_echo_returns_the_txid_of_what_was_sent(self) -> None:
        server, result = self._send(lie=False)
        assert len(server.broadcasts) == 1
        assert result == _txid_of(server.broadcasts[0])

    def test_a_lying_echo_raises_and_never_returns_the_servers_txid(self) -> None:
        server, result = self._send(lie=True)
        assert len(server.broadcasts) == 1, "the broadcast must have been attempted"
        assert isinstance(result, BroadcastEchoMismatch), result
        assert result.local_txid == _txid_of(server.broadcasts[0])
        assert result.echoed == _LIE
        assert "may not have relayed" in str(result)


# --------------------------------------------------------------------------- the CLI


def _new_wallet(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    """The real ``pyrxd wallet new``. Returns ``(mnemonic, first receive address)``."""
    for var in ("PYRXD_NETWORK", "PYRXD_ELECTRUMX", "PYRXD_FEE_RATE", "PYRXD_WALLET_PATH"):
        monkeypatch.delenv(var, raising=False)
    made = CliRunner().invoke(cli, [*_base(tmp_path), "wallet", "new"])
    assert made.exit_code == 0, (made.output, made.exception)
    doc = json.loads(made.stdout)
    return doc["mnemonic"], doc["address"]


def _base(tmp_path: Path) -> list[str]:
    return ["--config", str(tmp_path / "absent.toml"), "--wallet", str(tmp_path / "wallet.dat"), "--json", "--yes"]


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: _Server, mnemonic: str, *args: str):
    """The root ``cli`` against the real wallet file; only ``make_client`` is swapped for the server."""
    monkeypatch.setattr(CliContext, "make_client", lambda self: server)
    return CliRunner().invoke(cli, [*_base(tmp_path), *args], input=mnemonic + "\n")


def _assert_refused(result, server: _Server) -> None:
    assert len(server.broadcasts) == 1, "the broadcast must have been attempted"
    local = _txid_of(server.broadcasts[0])
    assert result.exit_code == 1, (result.output, result.exception)
    assert "different transaction id than the one we signed" in result.output
    assert local in result.output, "the txid of what was sent is the one thing the user can check"
    assert "may not have relayed" in result.output, "must say the broadcast may still have happened"
    assert "could not reach" not in result.output, "a reachability error invites a re-run that pays again"
    # No success document naming the server's txid as the transaction's.
    assert '"txid"' not in result.stdout and '"cancel_txid"' not in result.stdout


class TestWalletSendCli:
    def _send(self, tmp_path, monkeypatch, *, lie: bool):
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        server = _Server({first: _src_tx(first)}, lie=lie)
        to = HdWallet.from_mnemonic(MNEMONIC).derive_address(0, 0)
        return server, _run(
            tmp_path, monkeypatch, server, mnemonic, "wallet", "send", "--to", to, "--amount", "1000000"
        )

    def test_an_honest_echo_reports_success(self, tmp_path, monkeypatch) -> None:
        server, result = self._send(tmp_path, monkeypatch, lie=False)
        assert result.exit_code == 0, (result.output, result.exception)
        doc = json.loads(result.stdout[result.stdout.index("{") :])
        assert doc["txid"] == _txid_of(server.broadcasts[0])

    def test_a_lying_echo_is_refused(self, tmp_path, monkeypatch) -> None:
        server, result = self._send(tmp_path, monkeypatch, lie=True)
        _assert_refused(result, server)


class TestSwapCancelCli:
    def _cancel(self, tmp_path, monkeypatch, *, lie: bool):
        mnemonic, first = _new_wallet(tmp_path, monkeypatch)
        give = _src_tx(first)  # a plain-RXD offer, big enough to pay its own cancel fee
        server = _Server({first: give}, lie=lie)
        return server, _run(tmp_path, monkeypatch, server, mnemonic, "swap", "cancel", "--give", f"{give.txid()}:0")

    def test_an_honest_echo_reports_success(self, tmp_path, monkeypatch) -> None:
        server, result = self._cancel(tmp_path, monkeypatch, lie=False)
        assert result.exit_code == 0, (result.output, result.exception)
        doc = json.loads(result.stdout[result.stdout.index("{") :])
        assert doc["cancel_txid"] == _txid_of(server.broadcasts[0])

    def test_a_lying_echo_is_refused(self, tmp_path, monkeypatch) -> None:
        server, result = self._cancel(tmp_path, monkeypatch, lie=True)
        _assert_refused(result, server)


# --------------------------------------------------------------------------- the guard

#: The one check, and the helpers that provably delegate to it (asserted below).
_CHECK = "verified_broadcast_txid"
_LOCAL_CHECKS = {_CHECK, "_confirmed_txid"}

#: Broadcast sites that neither run the check in their own function nor provably hold a pyrxd
#: ElectrumX client. REVIEWED, not derived: each reason is a judgement, so the MEMBERSHIP is
#: pinned — adding a broadcast site that fits neither rule fails the test until it is either
#: routed through the check or listed here with a reason someone has read.
_EXEMPT = {
    # Bitcoin, not Radiant. A segwit txid is not hash256(raw), so the Radiant check does not
    # apply. MempoolSpaceBroadcaster binds its own echo (network/bitcoin.py);
    # BitcoinCoreRpcBroadcaster (htlc_leg.py) returns the node's reply unchecked.
    ("btc_wallet/htlc_leg.py", "BitcoinTaprootLeg.fund"): "BTC broadcaster",
    ("btc_wallet/htlc_leg.py", "BitcoinTaprootLeg.claim"): "BTC broadcaster",
    ("btc_wallet/htlc_leg.py", "BitcoinTaprootLeg.refund"): "BTC broadcaster",
    ("gravity/watch/executor.py", "RefundExecutor.execute"): "BtcBroadcaster (isinstance-checked in __init__)",
    # An injected, duck-typed Radiant client. When it is a pyrxd ElectrumX client the funnel
    # checks it; any other client is not checked here.
    ("gravity/maker.py", "GravityMakerSession.create_offer"): "injected Radiant client",
    ("gravity/maker.py", "GravityMakerSession.cancel_offer"): "injected Radiant client",
    ("gravity/trade.py", "GravityTrade._broadcast_radiant"): "injected Radiant client",
    ("gravity/radiant_leg.py", "RadiantChainIO.broadcast"): "injected Radiant client",
    ("gravity/radiant_leg.py", "RadiantCovenantLeg._broadcast"): "injected Radiant client (via RadiantChainIO)",
    # GlyphMinter compares the echo inline with its own post-broadcast policy (a commit record is
    # filed under both keys; a reveal waits on the local txid). With a pyrxd client the funnel
    # raises first.
    ("glyph/mint.py", "GlyphMinter._commit"): "inline echo policy",
    ("glyph/mint.py", "GlyphMinter._reveal"): "inline echo policy",
}


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _walk_with_scope(tree: ast.AST):
    """Yield ``(node, scope)`` where scope is the list of enclosing class/function defs."""

    def visit(node: ast.AST, scope: list[ast.AST]):
        yield node, scope
        inner = [*scope, node] if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) else scope
        for child in ast.iter_child_nodes(node):
            yield from visit(child, inner)

    yield from visit(tree, [])


def _qualname(scope: list[ast.AST]) -> str:
    return ".".join(n.name for n in scope) or "<module>"  # type: ignore[attr-defined]


def _functions(scope: list[ast.AST]) -> list[ast.AST]:
    return [n for n in scope if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]


def _calls_a_check(fn: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call) and (getattr(n.func, "id", None) or getattr(n.func, "attr", None)) in _LOCAL_CHECKS
        for n in ast.walk(fn)
    )


#: Client factories whose production return is a pyrxd ElectrumX client — pinned by
#: :meth:`TestEveryBroadcastSiteCrossesTheCheck.test_the_client_factories_return_checked_clients`.
_FACTORIES = {"make_client", "_make_client"}


def _is_pyrxd_client_expr(expr: ast.AST) -> bool:
    """A factory call, ``ElectrumXClient(...)`` or ``FailoverElectrumXClient(...)``."""
    if not isinstance(expr, ast.Call):
        return False
    name = getattr(expr.func, "attr", None) or getattr(expr.func, "id", None)
    return name in {*_FACTORIES, "ElectrumXClient", "FailoverElectrumXClient"}


def _receiver_is_a_pyrxd_client(receiver: ast.AST, fns: list[ast.AST]) -> bool:
    """Is the broadcast receiver provably a pyrxd ElectrumX client, from its binding?"""
    if not isinstance(receiver, ast.Name):
        return False
    name = receiver.id
    for fn in reversed(fns):  # innermost first; nested `_run` closures bind in the outer def
        args = fn.args  # type: ignore[attr-defined]
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
            if arg.arg == name and arg.annotation is not None:
                return "ElectrumXClient" in ast.unparse(arg.annotation)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                return _is_pyrxd_client_expr(n.value)
            if isinstance(n, ast.AsyncWith | ast.With):
                for item in n.items:
                    v = item.optional_vars
                    if isinstance(v, ast.Name) and v.id == name:
                        return _is_pyrxd_client_expr(item.context_expr)
    return False


def _broadcast_sites() -> list[tuple[str, str, str]]:
    """Every ``<x>.broadcast(...)`` call in src/pyrxd as ``(path, qualname, how it is covered)``."""
    sites = []
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC).as_posix()
        for node, scope in _walk_with_scope(_parse(path)):
            if not (isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "broadcast"):
                continue
            fns = _functions(scope)
            if fns and _calls_a_check(fns[-1]):
                how = "checks locally"
            elif _receiver_is_a_pyrxd_client(node.func.value, fns):  # type: ignore[attr-defined]
                how = "pyrxd client"
            else:
                how = "unchecked"
            sites.append((rel, _qualname(scope), how))
    return sites


class TestEveryBroadcastSiteCrossesTheCheck:
    def test_the_broadcast_rpc_is_issued_in_exactly_one_place_and_it_checks(self) -> None:
        """The funnel: ``blockchain.transaction.broadcast`` is sent from one function, which checks."""
        senders = []
        for path in sorted(_SRC.rglob("*.py")):
            for node, scope in _walk_with_scope(_parse(path)):
                if isinstance(node, ast.Constant) and node.value == "blockchain.transaction.broadcast":
                    senders.append((path.relative_to(_SRC).as_posix(), _qualname(scope), _functions(scope)))
        assert [(p, q) for p, q, _ in senders] == [("network/electrumx.py", "ElectrumXClient.broadcast")], senders
        assert _calls_a_check(senders[0][2][-1]), "ElectrumXClient.broadcast must run the echo check"

    def test_the_other_checks_delegate_to_the_one_check(self) -> None:
        """``_confirmed_txid`` and the failover are not second checks: each calls the one."""
        found = {}
        for rel, name in (("glyph/client.py", "_confirmed_txid"), ("network/failover.py", "broadcast")):
            for node, scope in _walk_with_scope(_parse(_SRC / rel)):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
                    found[(rel, _qualname([*scope, node]))] = any(
                        isinstance(n, ast.Call) and getattr(n.func, "id", None) == _CHECK for n in ast.walk(node)
                    )
        assert found == {
            ("glyph/client.py", "_confirmed_txid"): True,
            ("network/failover.py", "FailoverElectrumXClient.broadcast"): True,
        }

    def test_the_client_factories_return_checked_clients(self) -> None:
        """The factory rule leans on this: every function so named returns a pyrxd client.

        ``CliContext.make_client`` also returns ``client_factory()`` — the test seam — which is
        ``None`` in production (``main.cli`` never sets it)."""
        found = {}
        for path in sorted(_SRC.rglob("*.py")):
            for node, scope in _walk_with_scope(_parse(path)):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name in _FACTORIES:
                    returns = sorted(ast.unparse(n.value) for n in ast.walk(node) if isinstance(n, ast.Return))
                    found[(path.relative_to(_SRC).as_posix(), _qualname([*scope, node]))] = returns
        assert found == {
            ("cli/context.py", "CliContext.make_client"): ["FailoverElectrumXClient(profile)", "self.client_factory()"],
            ("wallet.py", "RxdWallet._make_client"): [
                "ElectrumXClient([self._electrumx_url], allow_insecure=self._allow_insecure)"
            ],
        }

    def test_every_broadcast_site_is_checked_or_reviewed(self) -> None:
        sites = _broadcast_sites()
        # Non-vacuity: sites this file's behavioural tests exercise, each through the funnel.
        by_where = {(p, q): how for p, q, how in sites}
        assert by_where[("hd/wallet.py", "HdWallet.send")] == "pyrxd client"
        assert by_where[("cli/wallet_cmds.py", "_send_in_process._run")] == "pyrxd client"
        assert by_where[("cli/swap_book_cmds.py", "swap_cancel_cmd._run")] == "pyrxd client"
        assert by_where[("glyph/client.py", "GlyphClient.transfer_ft")] == "checks locally"

        unchecked = {(p, q) for p, q, how in sites if how == "unchecked"}
        assert unchecked - set(_EXEMPT) == set(), (
            "a broadcast site neither runs verified_broadcast_txid nor provably holds a pyrxd "
            f"ElectrumX client: {sorted(unchecked - set(_EXEMPT))}"
        )
        # The other direction: an exemption whose site is gone, or is now checked, must go.
        assert set(_EXEMPT) - unchecked == set(), f"stale exemptions: {sorted(set(_EXEMPT) - unchecked)}"

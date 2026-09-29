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
_LOCAL_CHECKS = {_CHECK, "_confirmed_txid", "_local_commit_txid", "_confirmed_reveal_txid"}
_DELEGATES = {
    ("glyph/client.py", "_confirmed_txid"),
    ("cli/glyph_cmds.py", "_local_commit_txid"),
    ("cli/glyph_cmds.py", "_confirmed_reveal_txid"),
    ("network/failover.py", "FailoverElectrumXClient.broadcast"),
}

_RPC = "blockchain.transaction.broadcast"
_RPC_FAMILY = "blockchain.transaction"
_FUNNEL = ("network/electrumx.py", "ElectrumXClient.broadcast")
#: The other ``blockchain.transaction.*`` RPCs pyrxd sends. Pinned both ways below: a new one
#: must be added here on purpose, and one that is gone must leave.
_OTHER_TRANSACTION_RPCS = {"blockchain.transaction.get", "blockchain.transaction.get_merkle"}
#: Functions that fetch an attribute by a name given as a value.
_BY_NAME = {"getattr", "attrgetter", "methodcaller"}

#: Broadcast sites that neither feed their reply into the check nor provably hold a pyrxd
#: ElectrumX client. REVIEWED, not derived: each reason is a judgement, so the MEMBERSHIP is
#: pinned — adding a broadcast site that fits neither rule fails the test until it is either
#: routed through the check or listed here with a reason someone has read.
_EXEMPT = {
    # Bitcoin, not Radiant. A segwit txid is not hash256(raw), so the Radiant check does not
    # apply. MempoolSpaceBroadcaster binds its own echo (network/bitcoin.py);
    # BitcoinCoreBroadcaster (htlc_leg.py) returns the node's reply unchecked.
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
    ("gravity/radiant_leg.py", "RadiantCovenantLeg._send_raw"): "injected Radiant client (via RadiantChainIO)",
    # GlyphMinter compares the echo inline with its own post-broadcast policy (a commit record is
    # filed under both keys; a reveal waits on the local txid). With a pyrxd client the funnel
    # raises first.
    ("glyph/mint.py", "GlyphMinter._commit"): "inline echo policy",
    ("glyph/mint.py", "GlyphMinter._reveal"): "inline echo policy",
}


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _walk_with_scope(tree: ast.AST):
    """Yield ``(node, scope, parent)``; scope is the list of enclosing class/function defs."""

    def visit(node: ast.AST, scope: list[ast.AST], parent: ast.AST | None):
        yield node, scope, parent
        inner = [*scope, node] if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) else scope
        for child in ast.iter_child_nodes(node):
            yield from visit(child, inner, node)

    yield from visit(tree, [], None)


def _qualname(scope: list[ast.AST]) -> str:
    return ".".join(n.name for n in scope) or "<module>"  # type: ignore[attr-defined]


def _functions(scope: list[ast.AST]) -> list[ast.AST]:
    return [n for n in scope if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]


def _fold(node: ast.AST) -> str | None:
    """The string a constant expression evaluates to, or None if it is not one."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _fold(node.left), _fold(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        parts = [_fold(v.value if isinstance(v, ast.FormattedValue) else v) for v in node.values]
        return None if any(p is None for p in parts) else "".join(parts)  # type: ignore[arg-type]
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.List | ast.Tuple)
    ):
        sep, parts = _fold(node.func.value), [_fold(e) for e in node.args[0].elts]
        return None if sep is None or any(p is None for p in parts) else sep.join(parts)  # type: ignore[arg-type]
    return None


def _docstrings(tree: ast.AST) -> set[int]:
    """ids of bare string statements (docstrings): text, never a value anything can send."""
    return {
        id(n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)
    }


def _is_check_call(node: ast.AST) -> bool:
    return isinstance(node, ast.Call) and (getattr(node.func, "id", None) or getattr(node.func, "attr", None)) in (
        _LOCAL_CHECKS
    )


def _reply_is_checked(call: ast.Call, parent: ast.AST | None, fn: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """Does this broadcast's REPLY reach the check, in the function that sends it?

    Either the call sits inside a check call's arguments, or it is assigned to a name that is
    then passed to a check call. Calling the check on something else does not count.
    """
    checks = [n for n in ast.walk(fn) if _is_check_call(n)]
    if any(call in ast.walk(c) for c in checks):
        return True
    holder = parent
    if isinstance(holder, ast.Await):
        holder = parents.get(id(holder))
    if isinstance(holder, ast.Assign) and len(holder.targets) == 1 and isinstance(holder.targets[0], ast.Name):
        name = holder.targets[0].id
        return any(isinstance(a, ast.Name) and a.id == name for c in checks for arg in c.args for a in ast.walk(arg))
    return False


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
    """Is the broadcast receiver BOUND to a pyrxd ElectrumX client? An annotation is not a binding."""
    if not isinstance(receiver, ast.Name):
        return False
    name = receiver.id
    for fn in reversed(fns):  # innermost first; nested `_run` closures bind in the outer def
        args = fn.args  # type: ignore[attr-defined]
        if any(arg.arg == name for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]):
            return False  # a parameter: whatever the caller passed, whatever its annotation says
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
                return _is_pyrxd_client_expr(n.value)
            if isinstance(n, ast.AsyncWith | ast.With):
                for item in n.items:
                    v = item.optional_vars
                    if isinstance(v, ast.Name) and v.id == name:
                        return _is_pyrxd_client_expr(item.context_expr)
    return False


def _scan(tree: ast.Module, rel: str) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """``(sites, violations)`` for one module. A site is ``(path, qualname, how it is covered)``;
    a violation is ``(path, qualname, which rule it breaks)``."""
    docstrings = _docstrings(tree)
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    sites, violations = [], []
    for node, scope, parent in _walk_with_scope(tree):
        where = (rel, _qualname(scope))
        # Rule 1: the RPC name.
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            if _RPC_FAMILY in node.value and node.value not in _OTHER_TRANSACTION_RPCS and where != _FUNNEL:
                violations.append((*where, f"RPC name string {node.value!r} outside the funnel"))
        elif isinstance(node, ast.BinOp | ast.JoinedStr | ast.Call) and _fold(node) == _RPC and where != _FUNNEL:
            violations.append((*where, "an expression folding to the broadcast RPC name"))
        # Rule 2: `.broadcast` is only ever called.
        called = isinstance(parent, ast.Call) and parent.func is node
        if isinstance(node, ast.Attribute) and node.attr == "broadcast" and not called:
            violations.append((*where, "`.broadcast` accessed without being called"))
        # Rule 3: never fetched by name.
        fetcher = isinstance(node, ast.Call) and (getattr(node.func, "id", None) or getattr(node.func, "attr", None))
        if fetcher in _BY_NAME and any(_fold(a) == "broadcast" for a in node.args):  # type: ignore[union-attr]
            violations.append((*where, "`broadcast` fetched by name"))
        # Rule 4: every direct call is covered.
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "broadcast":
            fns = _functions(scope)
            if fns and _reply_is_checked(node, parent, fns[-1], parents):
                how = "reply checked"
            elif _receiver_is_a_pyrxd_client(node.func.value, fns):  # type: ignore[attr-defined]
                how = "pyrxd client"
            else:
                how = "unchecked"
            sites.append((*where, how))
    return sites, violations


def _scan_src() -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    sites, violations = [], []
    for path in sorted(_SRC.rglob("*.py")):
        s, v = _scan(_parse(path), path.relative_to(_SRC).as_posix())
        sites += s
        violations += v
    return sites, violations


def _scan_snippet(source: str) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    return _scan(ast.parse(source), "snippet.py")


class TestEveryBroadcastSiteCrossesTheCheck:
    """The guard: every way to send a broadcast crosses the one check.

    What the guard proves, and what it cannot. It is a static scan of src/pyrxd, so it proves
    only what the source says, and its rules are:

    1. ``blockchain.transaction.broadcast`` is spelled in exactly one function, which runs the
       check. Every other string constant mentioning ``blockchain.transaction`` must be one of the
       other transaction RPCs (pinned below), and no constant expression anywhere else — ``+``,
       an f-string of constants, ``"sep".join`` of constants — may fold to the broadcast name.
    2. ``.broadcast`` is only ever CALLED, directly. An alias (``send = c.broadcast``), a
       ``functools.partial``, a callback registration — any other access — fails, because the
       call it leads to is invisible to rule 4.
    3. ``broadcast`` is never fetched by name (``getattr``, ``operator.attrgetter``,
       ``operator.methodcaller``) with a constant name.
    4. Every direct ``.broadcast(...)`` call either feeds its reply into the check (or a helper
       that provably delegates to it) in the same function, or has a receiver BOUND to a pyrxd
       client there (a pinned factory or a constructor), or is in the pinned exempt set. A type
       annotation is not a binding and does not count: nothing enforces it at runtime.

    KNOWN BLIND SPOTS — each is pinned by
    ``TestTheGuardItself.test_the_known_blind_spots_are_still_blind``, so a guard that learns to
    see one fails that test until the entry is removed here:

    - DYNAMIC GETATTR: ``getattr(c, name)`` where ``name`` is not a constant. pyrxd has many
      legitimate dynamic ``getattr`` calls, so refusing all of them is not a rule anyone would
      keep.
    - RUNTIME RPC NAME: an RPC name assembled at runtime from parts none of which is a constant
      mentioning ``blockchain.transaction`` (e.g. read from config, or ``".".join(parts)`` over a
      variable).
    """

    def test_the_broadcast_rpc_is_spelled_in_exactly_one_place_and_it_checks(self) -> None:
        """The funnel: ``blockchain.transaction.broadcast`` is written in one function, which checks."""
        senders = []
        for path in sorted(_SRC.rglob("*.py")):
            tree = _parse(path)
            docstrings = _docstrings(tree)
            for node, scope, _parent in _walk_with_scope(tree):
                if id(node) not in docstrings and _fold(node) == _RPC:
                    senders.append((path.relative_to(_SRC).as_posix(), _qualname(scope), _functions(scope)))
        assert [(p, q) for p, q, _ in senders] == [_FUNNEL], senders
        assert any(
            isinstance(n, ast.Call) and getattr(n.func, "id", None) == _CHECK for n in ast.walk(senders[0][2][-1])
        )

    def test_no_other_path_to_the_rpc_or_the_method(self) -> None:
        """Rules 1-3 over all of src/pyrxd: no stray RPC name, no alias, no fetch by name."""
        _sites, violations = _scan_src()
        assert violations == []

    def test_the_other_transaction_rpcs_are_exactly_the_pinned_set(self) -> None:
        found = set()
        for path in sorted(_SRC.rglob("*.py")):
            tree = _parse(path)
            docstrings = _docstrings(tree)
            found |= {
                n.value
                for n in ast.walk(tree)
                if isinstance(n, ast.Constant)
                and isinstance(n.value, str)
                and n.value.startswith(_RPC_FAMILY + ".")
                and id(n) not in docstrings
            }
        assert found == {*_OTHER_TRANSACTION_RPCS, _RPC}

    def test_the_other_checks_delegate_to_the_one_check(self) -> None:
        """The helpers counted as checks are not second checks: each calls the one."""
        found = {}
        for rel in sorted({r for r, _ in _DELEGATES}):
            for node, scope, _parent in _walk_with_scope(_parse(_SRC / rel)):
                key = (
                    (rel, _qualname([*scope, node]))
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                    else None
                )
                if key in _DELEGATES:
                    found[key] = any(
                        isinstance(n, ast.Call) and getattr(n.func, "id", None) == _CHECK for n in ast.walk(node)
                    )
        assert found == dict.fromkeys(_DELEGATES, True)
        assert {name for _rel, name in _DELEGATES if "." not in name} | {_CHECK} == _LOCAL_CHECKS

    def test_the_client_factories_return_checked_clients(self) -> None:
        """The factory rule leans on this: every function so named returns a pyrxd client.

        ``CliContext.make_client`` also returns ``client_factory()`` — the test seam — which is
        ``None`` in production (``main.cli`` never sets it)."""
        found = {}
        for path in sorted(_SRC.rglob("*.py")):
            for node, scope, _parent in _walk_with_scope(_parse(path)):
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
        sites, _violations = _scan_src()
        # Non-vacuity: sites this file's behavioural tests exercise, each through the funnel.
        by_where = {(p, q): how for p, q, how in sites}
        assert by_where[("hd/wallet.py", "HdWallet.send")] == "reply checked"
        assert by_where[("cli/wallet_cmds.py", "_send_in_process._run")] == "pyrxd client"
        assert by_where[("cli/swap_book_cmds.py", "swap_cancel_cmd._run")] == "pyrxd client"
        assert by_where[("glyph/client.py", "GlyphClient.transfer_ft")] == "reply checked"

        unchecked = {(p, q) for p, q, how in sites if how == "unchecked"}
        assert unchecked - set(_EXEMPT) == set(), (
            "a broadcast site neither feeds its reply into verified_broadcast_txid nor is bound to a "
            f"pyrxd ElectrumX client: {sorted(unchecked - set(_EXEMPT))}"
        )
        # The other direction: an exemption whose site is gone, or is now checked, must go.
        assert set(_EXEMPT) - unchecked == set(), f"stale exemptions: {sorted(set(_EXEMPT) - unchecked)}"


class TestTheGuardItself:
    """The guard against inputs whose answer is known: the bypasses a review planted, and its blind spots."""

    #: The four bypasses review #786 planted in src/pyrxd/wallet.py, which the first guard passed.
    BYPASSES = {
        "method alias": "async def f(c, raw):\n    send = c.broadcast\n    return await send(raw)\n",
        "getattr with a constant": 'async def f(c, raw):\n    return await getattr(c, "broadcast")(raw)\n',
        "RPC name by concatenation": (
            'async def f(c, raw):\n    return await c._call("blockchain.transaction." + "broadcast", [raw.hex()])\n'
        ),
        "annotation naming ElectrumXClient": (
            'async def f(c: "ElectrumXClient | object", raw):\n    return await c.broadcast(raw)\n'
        ),
        # Two more spellings of the same bypasses, so the rules are not fitted to the four above.
        "partial": "import functools\ndef f(c):\n    return functools.partial(c.broadcast)\n",
        "concatenation in another order": 'M = "blockchain." + "transaction.broadcast"\n',
    }

    @pytest.mark.parametrize("name", sorted(BYPASSES))
    def test_each_review_bypass_fails_the_guard(self, name: str) -> None:
        sites, violations = _scan_snippet(self.BYPASSES[name])
        unchecked = [s for s in sites if s[2] == "unchecked"]
        assert violations or unchecked, f"the guard passed the {name!r} bypass"

    def test_the_honest_shapes_pass(self) -> None:
        honest = (
            "async def f(c, raw):\n    echoed = await c.broadcast(raw)\n    return verified_broadcast_txid(raw, echoed)\n"
            "async def g(ctx, raw):\n    client = ctx.make_client()\n    return await client.broadcast(raw)\n"
            "async def h(c, raw):\n    return verified_broadcast_txid(raw, await c.broadcast(raw))\n"
        )
        sites, violations = _scan_snippet(honest)
        assert violations == []
        assert [how for _p, _q, how in sites] == ["reply checked", "pyrxd client", "reply checked"]

    def test_calling_the_check_on_something_else_does_not_count(self) -> None:
        src = (
            "async def f(c, raw, other):\n"
            "    verified_broadcast_txid(other, other)\n"
            "    return await c.broadcast(raw)\n"
        )
        sites, _violations = _scan_snippet(src)
        assert [how for _p, _q, how in sites] == ["unchecked"]

    #: Pinned: see KNOWN BLIND SPOTS in :class:`TestEveryBroadcastSiteCrossesTheCheck`'s docstring.
    BLIND_SPOTS = {
        "DYNAMIC GETATTR": "async def f(c, raw, name):\n    return await getattr(c, name)(raw)\n",
        "RUNTIME RPC NAME": "async def f(c, raw, parts):\n    return await c._call('.'.join(parts), [raw.hex()])\n",
    }

    @pytest.mark.parametrize("name", sorted(BLIND_SPOTS))
    def test_the_known_blind_spots_are_still_blind(self, name: str) -> None:
        """If this fails, the guard has learned to see it: remove it from KNOWN BLIND SPOTS."""
        sites, violations = _scan_snippet(self.BLIND_SPOTS[name])
        assert violations == [] and [s for s in sites if s[2] == "unchecked"] == []
        assert f"- {name}:" in (TestEveryBroadcastSiteCrossesTheCheck.__doc__ or ""), "documented in the guard"

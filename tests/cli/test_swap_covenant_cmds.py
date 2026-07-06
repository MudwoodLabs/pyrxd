"""``pyrxd swap reserve/post/take/cancel/refund`` v3 covenant CLI seams.

The covenant value mechanics are the fully-tested
:mod:`pyrxd.swap.rswp.covenant` builders (see ``test_swap_rswp_covenant.py``
in the library test suite); what these tests cover is the CLI's ROUTING and
fail-closed guard rails:

* ``take`` fetches the chain tip and checks a v3 order's expiry BEFORE the
  wallet is even opened — an unreachable node must fail closed with no
  wallet prompt and no broadcast.
* ``reserve`` funds exclusively from plain-RXD wallet UTXOs
  (:func:`pyrxd.cli.swap_book_cmds._rxd_funding`); a wallet holding only an
  FT UTXO must be refused cleanly, not silently spend the token.
* ``cancel`` and ``refund`` decide v2-vs-v3 routing purely from
  ``is_refund_covenant`` on the fetched give UTXO's script — never from a
  flag the caller passes.

No real wallet file or node is used anywhere here: the wallet is replaced by
a tiny ``_FakeWallet`` (monkeypatching ``swap_book_cmds._load_wallet``, same
spirit as ``test_swap_book_cmds.py``'s ``_FakeNodeSource``), and the network
is a ``MagicMock`` ElectrumXClient injected via ``CliContext.client_factory``
(the same seam ``test_wallet_sweep.py`` uses).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

import pyrxd.cli.swap_book_cmds as swap_book_cmds
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext

# Importing pyrxd.cli.main wires the reserve/post/take/cancel/refund commands
# onto pyrxd.cli.swap_cmds.swap_group (see main.py's add_command calls) —
# required before invoking swap_group directly below.
from pyrxd.cli.main import cli
from pyrxd.cli.swap_cmds import swap_group
from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset
from pyrxd.swap.rswp import build_refund_covenant_script, create_covenant_order, decode_rswp_order
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_REF = GlyphRef(txid=Txid("cd" * 32), vout=0)
_EXPIRY = 900_000


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()
    return k, k.public_key().hash160()


def _covenant_src(owner_pkh: bytes, expiry: int, value: int = 900) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_refund_covenant_script(owner_pkh, expiry)), value))
    return tx


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), _REF)), value))
    return tx


def _unreachable_wallet(ctx, **kw):
    raise AssertionError("wallet must Not be opened for this guard-rail path")


class _FakeWallet:
    """Stands in for HdWallet: only the ``collect_spendable`` surface the CLI needs."""

    def __init__(self, triples: list) -> None:
        self._triples = triples

    async def collect_spendable(self, client) -> list:
        return self._triples


def _fake_client(*, get_transaction=None, get_tip_height=None) -> MagicMock:
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.broadcast = AsyncMock(return_value="cd" * 32)
    client.get_transaction = get_transaction or AsyncMock()
    if get_tip_height is not None:
        client.get_tip_height = get_tip_height
    return client


def _ctx(client, *, yes: bool = True, output_mode: str = "human") -> CliContext:
    wallet_path = Path("/tmp/_pyrxd_covenant_cli_test")
    return CliContext(
        config=Config(network="mainnet", electrumx="wss://test/", fee_rate=10_000, wallet_path=wallet_path),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=10_000,
        wallet_path=wallet_path,
        output_mode=output_mode,
        yes=yes,
        client_factory=lambda: client,
    )


def _invoke(runner: CliRunner, ctx: CliContext, args: list[str], *, confirm: str = "y"):
    return runner.invoke(swap_group, args, obj=ctx, input="" if ctx.yes else f"{confirm}\n")


# --------------------------------------------------------------------------- reserve: pure parsing


class TestReserveParsing:
    def test_non_positive_amount_rejected_before_network(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["swap", "reserve", "--amount", "0", "--expiry", str(_EXPIRY)])
        assert result.exit_code != 0
        assert "--amount must be Positive" in result.output

    def test_non_positive_expiry_rejected_before_network(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["swap", "reserve", "--amount", "1000", "--expiry", "0"])
        assert result.exit_code != 0
        assert "--expiry must be a Positive" in result.output


# --------------------------------------------------------------------------- reserve: FT-only wallet refused


class TestReserveFundingGuard:
    def test_ft_only_wallet_refused_without_broadcast(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        ft_src = _ft_src(mk_pkh, 500)
        client = _fake_client(get_transaction=AsyncMock(return_value=ft_src.serialize()))
        triples = [(UtxoRecord(tx_hash=ft_src.txid(), tx_pos=0, value=500, height=800_000), "addr", mk)]
        monkeypatch.setattr(swap_book_cmds, "_load_wallet", lambda ctx, **kw: _FakeWallet(triples))

        ctx = _ctx(client)
        result = _invoke(runner, ctx, ["reserve", "--amount", "100000", "--expiry", str(_EXPIRY)])

        assert result.exit_code != 0, result.output
        assert "cannot fund" in result.output
        client.broadcast.assert_not_awaited()


# --------------------------------------------------------------------------- take: v3 expiry / tip guard


class TestTakeCovenantTipGuard:
    def test_v3_take_without_reachable_tip_fails_closed(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        cov_src = _covenant_src(mk_pkh, _EXPIRY, value=900)
        post = create_covenant_order(
            covenant_source_tx=cov_src,
            covenant_vout=0,
            maker_key=mk,
            receive=Asset(kind="rxd", amount=500),
            maker_receive_pkh=mk_pkh,
        )
        order = decode_rswp_order(post.advert_script)
        assert order.expiry_height == _EXPIRY  # sanity: this really is a v3 order

        client = _fake_client(
            get_transaction=AsyncMock(return_value=cov_src.serialize()),
            get_tip_height=AsyncMock(side_effect=NetworkError("Node Unreachable")),
        )
        # `_load_wallet` is intentionally left as the REAL implementation — a
        # dead tip must fail before the wallet is ever touched, so no wallet
        # file or mnemonic input is provided at all.
        ctx = _ctx(client)

        result = _invoke(runner, ctx, ["take", "--advert", post.advert_script.hex()])

        assert result.exit_code != 0, result.output
        assert "Node Unreachable" in result.output
        client.get_tip_height.assert_awaited_once()
        client.broadcast.assert_not_awaited()

    def test_v2_take_never_calls_get_tip_height(self, runner: CliRunner, monkeypatch) -> None:
        # Guard against a regression that fetches the tip unconditionally —
        # a v2 (no-expiry) order must not pay that network round trip.
        from pyrxd.swap.rswp import create_rswp_order

        mk, mk_pkh = _key()
        give_src = _rxd_src(mk_pkh, 900)
        post = create_rswp_order(
            give_source_tx=give_src,
            give_vout=0,
            maker_key=mk,
            receive=Asset(kind="rxd", amount=500),
            maker_receive_pkh=mk_pkh,
        )
        order = decode_rswp_order(post.advert_script)
        assert order.expiry_height is None

        taker_key, taker_pkh = _key()
        funding_src = _rxd_src(taker_pkh, 10_000_000)
        triples = [(UtxoRecord(tx_hash=funding_src.txid(), tx_pos=0, value=10_000_000, height=1), "addr", taker_key)]
        monkeypatch.setattr(swap_book_cmds, "_load_wallet", lambda ctx, **kw: _FakeWallet(triples))

        async def _get_transaction(txid):
            wanted = str(txid)
            if wanted == give_src.txid():
                return give_src.serialize()
            return funding_src.serialize()

        client = _fake_client(get_tip_height=AsyncMock(side_effect=AssertionError("must not be called for v2")))
        client.get_transaction = _get_transaction

        ctx = _ctx(client)
        result = _invoke(runner, ctx, ["take", "--advert", post.advert_script.hex()])

        assert result.exit_code == 0, result.output
        client.get_tip_height.assert_not_awaited()
        client.broadcast.assert_awaited_once()


# --------------------------------------------------------------------------- cancel/refund: is_refund_covenant routing


class TestCancelRoutesOnCovenantDetection:
    def test_covenant_give_routes_to_v3_cancel(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        # Comfortably above the estimated fee + dust floor so the covenant
        # builder's post-fee dust check doesn't fire — this test is about
        # ROUTING, not fee-edge behavior.
        cov_src = _covenant_src(mk_pkh, _EXPIRY, value=10_000_000)
        client = _fake_client(get_transaction=AsyncMock(return_value=cov_src.serialize()))
        triples = [(UtxoRecord(tx_hash="00" * 32, tx_pos=0, value=0, height=0), "addr", mk)]
        monkeypatch.setattr(swap_book_cmds, "_load_wallet", lambda ctx, **kw: _FakeWallet(triples))

        # ctx.yes=False so the confirmation summary (where the routing text
        # lives) actually gets echoed — `--yes` skips printing it entirely.
        ctx = _ctx(client, yes=False)
        result = _invoke(runner, ctx, ["cancel", "--give", f"{cov_src.txid()}:0"], confirm="y")

        assert result.exit_code == 0, result.output
        assert "CANCEL v3 covenant reservation" in result.output
        assert "before OR after expiry" in result.output
        client.broadcast.assert_awaited_once()

    def test_plain_give_routes_to_v2_cancel(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        give_src = _rxd_src(mk_pkh, 1_000_000)  # well above the estimated fee — no extra funding needed
        client = _fake_client(get_transaction=AsyncMock(return_value=give_src.serialize()))
        triples = [(UtxoRecord(tx_hash="00" * 32, tx_pos=0, value=0, height=0), "addr", mk)]
        monkeypatch.setattr(swap_book_cmds, "_load_wallet", lambda ctx, **kw: _FakeWallet(triples))

        ctx = _ctx(client, yes=False)
        result = _invoke(runner, ctx, ["cancel", "--give", f"{give_src.txid()}:0"], confirm="y")

        assert result.exit_code == 0, result.output
        assert "CANCEL posted order" in result.output
        assert "v3 covenant" not in result.output.lower()
        client.broadcast.assert_awaited_once()


class TestRefundRoutesOnCovenantDetection:
    def test_covenant_give_refund_succeeds(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        cov_src = _covenant_src(mk_pkh, _EXPIRY, value=10_000_000)
        client = _fake_client(get_transaction=AsyncMock(return_value=cov_src.serialize()))
        triples = [(UtxoRecord(tx_hash="00" * 32, tx_pos=0, value=0, height=0), "addr", mk)]
        monkeypatch.setattr(swap_book_cmds, "_load_wallet", lambda ctx, **kw: _FakeWallet(triples))

        ctx = _ctx(client, yes=False)
        result = _invoke(runner, ctx, ["refund", "--give", f"{cov_src.txid()}:0"], confirm="y")

        assert result.exit_code == 0, result.output
        assert "REFUND v3 covenant reservation" in result.output
        assert "Malleable" in result.output
        assert f"height {_EXPIRY}" in result.output
        client.broadcast.assert_awaited_once()

    def test_plain_give_refund_refused_cleanly(self, runner: CliRunner, monkeypatch) -> None:
        _mk, mk_pkh = _key()
        give_src = _rxd_src(mk_pkh, 1_000_000)
        client = _fake_client(get_transaction=AsyncMock(return_value=give_src.serialize()))
        # Never reached: the covenant check fails before any wallet access.
        monkeypatch.setattr(swap_book_cmds, "_load_wallet", _unreachable_wallet)

        ctx = _ctx(client)
        result = _invoke(runner, ctx, ["refund", "--give", f"{give_src.txid()}:0"])

        assert result.exit_code != 0, result.output
        assert "Not a v3 refund covenant" in result.output
        client.broadcast.assert_not_awaited()

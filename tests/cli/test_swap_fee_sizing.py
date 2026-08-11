"""``pyrxd swap`` fee sizing — every built transaction must clear Radiant's relay floor.

Regression cover for a pre-existing units bug in
:mod:`pyrxd.cli.swap_book_cmds`. ``_estimate_fee`` computed
``(ctx.fee_rate * size + 999) // 1000`` while ``ctx.fee_rate`` is photons per
**BYTE** (:func:`pyrxd.cli.config.validated_fee_rate` floors it in exactly those
units). Every ``swap post`` / ``take`` / ``cancel`` / ``reserve`` / ``refund``
transaction was therefore fee'd at one-thousandth of the floor — measured at
947x-3424x short across the real builders — and would not relay.

Why that is a fund-safety bug and not a stuck transaction:

* Radiant has **neither RBF nor CPFP** (:mod:`pyrxd.gravity.fee_policy` documents
  the source lines), so an under-fee'd transaction cannot be repaired by any
  means. It holds its inputs until the 8-hour mempool expiry.
* ``swap cancel`` is the ONLY hard revocation for a v2 order. A cancel that never
  relays leaves the order **still takeable** while the CLI reports success — the
  operator believes they withdrew an offer a counterparty can still accept.

The tests below deliberately assert on the CLI's OWN surface — the fee it prints
in the confirmation summary, against the size of the bytes it hands to
``broadcast`` — rather than on any internal helper, so they are expressible
against the buggy code as well as the fixed code. The floor they compare to comes
from :mod:`pyrxd.gravity.fee_policy`, the same helper the fix binds to, so there
is one definition of the relay floor in the tree.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from click.testing import CliRunner

import pyrxd.cli.swap_book_cmds as swap_book_cmds
from pyrxd.cli.config import Config
from pyrxd.cli.context import CliContext
from pyrxd.cli.swap_cmds import swap_group
from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset
from pyrxd.swap.rswp import build_refund_covenant_script, create_rswp_order
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

# Importing pyrxd.cli.main wires the swap subcommands onto swap_group.
import pyrxd.cli.main  # noqa: F401  isort: skip

_REF = GlyphRef(txid=Txid("cd" * 32), vout=0)
_EXPIRY = 900_000
_FEE_RATE = 10_000  # photons per BYTE — the validated CLI default, exactly on the floor
_FEE_LINE = re.compile(r"fee\s*(?:\w+)?\s*:\s*([0-9]+) photons")


def relay_floor(size_bytes: int) -> int:
    """Radiant's ``min relay fee not met`` threshold for *size_bytes* serialized bytes."""
    return DEFAULT_RADIANT_DEADLINE_FEE_POLICY.min_relay_fee(size_bytes)


# --------------------------------------------------------------------------- harness


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()  # never hand-write test keys
    return k, k.public_key().hash160()


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), _REF)), value))
    return tx


def _covenant_src(owner_pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_refund_covenant_script(owner_pkh, _EXPIRY)), value))
    return tx


class _FakeWallet:
    def __init__(self, triples: list) -> None:
        self._triples = triples

    async def collect_spendable(self, client) -> list:
        return self._triples


def _client(*txs: Transaction) -> MagicMock:
    """An ElectrumX stand-in that serves each supplied transaction by its real txid."""
    by_txid = {t.txid(): t.serialize() for t in txs}

    async def _get_transaction(txid):
        return by_txid[str(txid)]

    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    client.broadcast = AsyncMock(return_value="cd" * 32)
    client.get_transaction = AsyncMock(side_effect=_get_transaction)
    client.get_tip_height = AsyncMock(return_value=1)
    return client


def _ctx(client) -> CliContext:
    wallet_path = Path("/tmp/_pyrxd_swap_fee_sizing_test")
    return CliContext(
        config=Config(network="mainnet", electrumx="wss://test/", fee_rate=_FEE_RATE, wallet_path=wallet_path),
        network="mainnet",
        electrumx_url="wss://test/",
        fee_rate=_FEE_RATE,
        wallet_path=wallet_path,
        output_mode="human",
        yes=False,  # so the confirmation summary — which carries the fee line — is printed
        client_factory=lambda: client,
    )


def _run(runner: CliRunner, ctx: CliContext, args: list[str]):
    return runner.invoke(swap_group, args, obj=ctx, input="y\n")


def _fee_and_size(result, client) -> tuple[int, int]:
    """The fee the CLI told the operator it was paying, and the size of what it broadcast."""
    assert result.exit_code == 0, result.output
    match = _FEE_LINE.search(result.output)
    assert match is not None, f"no fee line in the confirmation summary:\n{result.output}"
    client.broadcast.assert_awaited_once()
    raw = client.broadcast.await_args[0][0]
    return int(match.group(1)), len(raw)


def _assert_relays(result, client) -> tuple[int, int]:
    fee, size = _fee_and_size(result, client)
    floor = relay_floor(size)
    assert fee >= floor, (
        f"the CLI built a {size}-byte transaction paying {fee} photons, {floor / fee:.1f}x below "
        f"Radiant's relay floor of {floor}. It would be rejected with 'min relay fee not met', "
        "and with no RBF and no CPFP it could not be repaired."
    )
    return fee, size


# --------------------------------------------------------------------------- the commands


def _wallet(monkeypatch, *triples) -> None:
    monkeypatch.setattr(swap_book_cmds, "_load_wallet", lambda ctx, **kw: _FakeWallet(list(triples)))


def _utxo(tx: Transaction, key: PrivateKey, *, vout: int = 0):
    return (UtxoRecord(tx_hash=tx.txid(), tx_pos=vout, value=tx.outputs[vout].satoshis, height=800_000), "addr", key)


class TestEveryCommandClearsTheRelayFloor:
    """The bug: every one of these fee'd at rate x size / 1000 and could not relay.

    Ran against the pre-fix ``swap_book_cmds.py`` these all FAIL with the transaction
    between ~320x and ~1150x under the floor; they pass against the fix.
    """

    @pytest.mark.parametrize("n_funding", [1, 2, 4])
    def test_post(self, runner: CliRunner, monkeypatch, n_funding: int) -> None:
        mk, mk_pkh = _key()
        give = _rxd_src(mk_pkh, 50_000_000)
        funders = [_rxd_src(mk_pkh, 12_000_000) for _ in range(n_funding)]
        client = _client(give, *funders)
        _wallet(monkeypatch, _utxo(give, mk), *(_utxo(f, mk) for f in funders))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["post", "--give", f"{give.txid()}:0", "--receive", "rxd:900000"])
        _assert_relays(result, client)

    def test_post_ft_advert_is_sized_from_its_real_script(self, runner: CliRunner, monkeypatch) -> None:
        """An FT-give/FT-want advert carries TWO token ids — 310 serialized bytes of
        OP_RETURN, well past what any per-output average covers. Sizing from the
        transaction's own bytes is what makes this case correct rather than lucky."""
        mk, mk_pkh = _key()
        give = _ft_src(mk_pkh, 777)
        funder = _rxd_src(mk_pkh, 100_000_000)
        client = _client(give, funder)
        _wallet(monkeypatch, _utxo(give, mk), _utxo(funder, mk))

        ctx = _ctx(client)
        want = f"{_REF.txid}:{_REF.vout}:50"
        result = _run(runner, ctx, ["post", "--give", f"{give.txid()}:0", "--receive", want])
        _assert_relays(result, client)

    @pytest.mark.parametrize("n_funding", [1, 3])
    def test_take(self, runner: CliRunner, monkeypatch, n_funding: int) -> None:
        mk, mk_pkh = _key()
        tk, tk_pkh = _key()
        give = _rxd_src(mk_pkh, 5_000_000)
        post = create_rswp_order(
            give_source_tx=give,
            give_vout=0,
            maker_key=mk,
            receive=Asset(kind="rxd", amount=900_000),
            maker_receive_pkh=mk_pkh,
        )
        funders = [_rxd_src(tk_pkh, 20_000_000) for _ in range(n_funding)]
        client = _client(give, *funders)
        _wallet(monkeypatch, *(_utxo(f, tk) for f in funders))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["take", "--advert", post.advert_script.hex()])
        _assert_relays(result, client)

    def test_reserve(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        funder = _rxd_src(mk_pkh, 100_000_000)
        client = _client(funder)
        _wallet(monkeypatch, _utxo(funder, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["reserve", "--amount", "20000000", "--expiry", str(_EXPIRY)])
        _assert_relays(result, client)

    def test_refund(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        cov = _covenant_src(mk_pkh, 50_000_000)
        client = _client(cov)
        _wallet(monkeypatch, _utxo(cov, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["refund", "--give", f"{cov.txid()}:0"])
        _assert_relays(result, client)

    def test_v3_covenant_advert_clears_the_floor(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        cov = _covenant_src(mk_pkh, 50_000_000)
        funder = _rxd_src(mk_pkh, 100_000_000)
        client = _client(cov, funder)
        _wallet(monkeypatch, _utxo(cov, mk), _utxo(funder, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["post", "--give", f"{cov.txid()}:0", "--receive", "rxd:900000"])
        _assert_relays(result, client)


class TestCancelClearsTheRelayFloor:
    """``cancel`` gets its own class because its failure mode is the worst one.

    It is the ONLY hard revocation for a v2 order. An unrelayable cancel does not
    merely fail — it reports success while the order stays takeable at the original
    price, so the maker stops watching an offer a counterparty can still accept.
    """

    def test_rxd_cancel_self_funded(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        give = _rxd_src(mk_pkh, 100_000_000)
        client = _client(give)
        _wallet(monkeypatch, _utxo(give, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["cancel", "--give", f"{give.txid()}:0"])
        _assert_relays(result, client)

    def test_ft_cancel_with_separate_fee_funding(self, runner: CliRunner, monkeypatch) -> None:
        """An FT cancel conserves the whole token amount, so the fee comes from a
        separate plain-RXD input — a different code path, same floor."""
        mk, mk_pkh = _key()
        give = _ft_src(mk_pkh, 777)
        funder = _rxd_src(mk_pkh, 100_000_000)
        client = _client(give, funder)
        _wallet(monkeypatch, _utxo(give, mk), _utxo(funder, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["cancel", "--give", f"{give.txid()}:0"])
        _assert_relays(result, client)

    def test_v3_covenant_cancel(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        cov = _covenant_src(mk_pkh, 50_000_000)
        client = _client(cov)
        _wallet(monkeypatch, _utxo(cov, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["cancel", "--give", f"{cov.txid()}:0"])
        _assert_relays(result, client)


# --------------------------------------------------------------------------- unit level


class TestFeeSizingUnits:
    """The units themselves, over a grid of transaction shapes.

    ``ctx.fee_rate`` is photons per BYTE, so the fee for an ``n``-byte transaction is
    ``rate * n``. The old expression divided that by 1000.
    """

    @pytest.mark.parametrize("n_inputs", [1, 2, 3, 8])
    @pytest.mark.parametrize("n_outputs", [1, 2, 4])
    def test_seed_fee_is_never_below_the_floor(self, n_inputs: int, n_outputs: int) -> None:
        ctx = _ctx(MagicMock())
        size = (
            swap_book_cmds._TX_BASE_BYTES
            + n_inputs * swap_book_cmds._TX_PER_INPUT_BYTES
            + n_outputs * swap_book_cmds._TX_PER_OUTPUT_BYTES
        )
        fee = swap_book_cmds._seed_fee(ctx, n_inputs, n_outputs, 0)
        assert fee >= relay_floor(size)
        assert fee == _FEE_RATE * size  # per byte, not per kB

    def test_fee_for_size_is_rate_times_bytes(self) -> None:
        ctx = _ctx(MagicMock())
        for size in (1, 192, 450, 1541, 20_000):
            assert swap_book_cmds._fee_for_size(ctx, size) == _FEE_RATE * size

    def test_floor_binds_even_if_the_rate_was_never_validated(self) -> None:
        """``_fee_for_size`` floors against ``gravity.fee_policy`` rather than trusting
        ``fee_rate``: a CliContext built outside ``config.load`` (tests, embedders) can
        carry a rate that never met ``validated_fee_rate``."""
        ctx = _ctx(MagicMock())
        ctx.fee_rate = 1  # would be refused by config.load, but nothing stops this object
        for size in (192, 450, 1541):
            assert swap_book_cmds._fee_for_size(ctx, size) == relay_floor(size)

    def test_measured_fee_adds_per_input_signature_slack(self) -> None:
        """Trial and final passes sign different messages, so DER lengths can grow by up
        to 3 bytes per input between them. At the floor those bytes decide relay."""
        ctx = _ctx(MagicMock())
        _mk, mk_pkh = _key()
        tx = Transaction()
        tx.add_output(TransactionOutput(P2PKH().lock(mk_pkh), 1_000))
        size = len(tx.serialize())
        assert swap_book_cmds._measured_fee(ctx, tx) == _FEE_RATE * (
            size + swap_book_cmds._SIG_SIZE_SLACK_BYTES * len(tx.inputs)
        )


class TestExplicitFeeOverrideFailsClosed:
    """``--fee`` below the floor is refused BEFORE broadcast, not silently sent.

    Nothing is broadcast, so nothing is at risk; the alternative is a transaction
    squatting on its inputs for 8 hours with no way to bump it.
    """

    def test_sub_floor_fee_override_refused(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        give = _rxd_src(mk_pkh, 100_000_000)
        client = _client(give)
        _wallet(monkeypatch, _utxo(give, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["cancel", "--give", f"{give.txid()}:0", "--fee", "1000"])

        assert result.exit_code != 0, result.output
        assert "below Radiant's relay floor" in result.output
        client.broadcast.assert_not_awaited()

    def test_sufficient_fee_override_is_honoured(self, runner: CliRunner, monkeypatch) -> None:
        mk, mk_pkh = _key()
        give = _rxd_src(mk_pkh, 100_000_000)
        client = _client(give)
        _wallet(monkeypatch, _utxo(give, mk))

        ctx = _ctx(client)
        result = _run(runner, ctx, ["cancel", "--give", f"{give.txid()}:0", "--fee", "9000000"])

        fee, _size = _assert_relays(result, client)
        assert fee == 9_000_000  # the operator's number, not a re-estimate

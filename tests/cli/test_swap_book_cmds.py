"""``pyrxd swap orders/post/take/cancel`` — CLI seams.

The value mechanics under these commands are the fully-tested
:mod:`pyrxd.swap.rswp` builders; what the CLI adds — and what these tests
cover — is argument parsing, the read-only ``orders`` pipeline against a fake
node source, and the guard rails that fire BEFORE any wallet or network
access (FT-demand refusal, undecodable adverts).
"""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from pyrxd.cli.errors import UserError
from pyrxd.cli.main import cli
from pyrxd.cli.swap_book_cmds import (
    _decode_advert_arg,
    _parse_asset_spec,
    _parse_outpoint,
    _parse_token,
)
from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset
from pyrxd.swap.rswp import create_rswp_order, decode_rswp_order, swap_token_id
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_REF = GlyphRef(txid=Txid("cd" * 32), vout=0)


# --------------------------------------------------------------------------- parsing


class TestParsing:
    def test_outpoint_round_trip(self) -> None:
        assert _parse_outpoint("ab" * 32 + ":3") == ("ab" * 32, 3)

    @pytest.mark.parametrize("bad", ["nope", "ab" * 32, "xyz:1", "ab" * 31 + ":0"])
    def test_bad_outpoints_rejected(self, bad: str) -> None:
        with pytest.raises(UserError):
            _parse_outpoint(bad)

    def test_token_forms(self) -> None:
        assert _parse_token("rxd") is None
        assert _parse_token("RXD") is None
        assert _parse_token("cd" * 32 + ":7") == GlyphRef(txid=Txid("cd" * 32), vout=7)
        contract = "cd" * 32 + "00000007"  # 72-hex display form
        assert _parse_token(contract) == GlyphRef(txid=Txid("cd" * 32), vout=7)
        with pytest.raises(UserError):
            _parse_token("not-a-token")

    def test_asset_specs(self) -> None:
        assert _parse_asset_spec("rxd:900") == Asset(kind="rxd", amount=900)
        assert _parse_asset_spec("cd" * 32 + ":0:50") == Asset(kind="ft", amount=50, ref=_REF)
        with pytest.raises(UserError):
            _parse_asset_spec("rxd")  # no amount
        with pytest.raises(UserError):
            _parse_asset_spec("rxd:-5")  # Asset rejects non-positive


# --------------------------------------------------------------------------- advert decoding


def _key() -> tuple[PrivateKey, bytes]:
    k = PrivateKey()
    return k, k.public_key().hash160()


def _ft_src(pkh: bytes, ref: GlyphRef, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), value))
    return tx


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _posted_order(receive: Asset):
    mk, mk_pkh = _key()
    src = _ft_src(mk_pkh, _REF, 500) if receive.kind == "rxd" else _rxd_src(mk_pkh, 1200)
    post = create_rswp_order(give_source_tx=src, give_vout=0, maker_key=mk, receive=receive, maker_receive_pkh=mk_pkh)
    return post, src


class TestDecodeAdvertArg:
    def test_accepts_bare_script_hex(self) -> None:
        post, _ = _posted_order(Asset(kind="rxd", amount=900))
        order = _decode_advert_arg(post.advert_script.hex())
        assert order.offered_utxo_index == 0

    def test_accepts_full_advert_tx_hex(self) -> None:
        post, _ = _posted_order(Asset(kind="rxd", amount=900))
        tx = Transaction()
        tx.add_output(TransactionOutput(Script(post.advert_script), 0))
        assert _decode_advert_arg(tx.serialize().hex()).signature == decode_rswp_order(post.advert_script).signature

    def test_accepts_at_file(self, tmp_path) -> None:
        post, _ = _posted_order(Asset(kind="rxd", amount=900))
        f = tmp_path / "advert.hex"
        f.write_text(post.advert_script.hex() + "\n")
        assert _decode_advert_arg(f"@{f}").offered_txid == decode_rswp_order(post.advert_script).offered_txid

    @pytest.mark.parametrize("garbage", ["zz", "00" * 40, ""])
    def test_garbage_rejected(self, garbage: str) -> None:
        with pytest.raises(UserError):
            _decode_advert_arg(garbage)


# --------------------------------------------------------------------------- take guard rails (pre-wallet)


class TestTakeGuards:
    def test_ft_demand_refused_before_any_network(self, runner: CliRunner) -> None:
        post, _ = _posted_order(Asset(kind="ft", amount=50, ref=_REF))
        result = runner.invoke(cli, ["swap", "take", "--advert", post.advert_script.hex()])
        assert result.exit_code != 0
        assert "RXD-demand orders only" in result.output

    def test_undecodable_advert_refused(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["swap", "take", "--advert", "6a04beef"])
        assert result.exit_code != 0
        assert "no decodable RSWP order" in result.output


# --------------------------------------------------------------------------- orders (fake node source)


class _FakeNodeSource:
    """Stands in for NodeRpcSource: same constructor + async-context surface."""

    rows: list[dict] = []
    txs: dict[str, bytes] = {}

    def __init__(self, url: str, *, rpc_user=None, rpc_password=None, timeout_s: float = 0) -> None:
        self.url = url

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def get_open_orders(self, token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        return [r for r in type(self).rows if r["tokenid"] == token_id_hex]

    async def get_open_orders_by_want(self, want_token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        return [r for r in type(self).rows if r.get("want_tokenid") == want_token_id_hex]

    async def get_transaction(self, txid) -> bytes:
        return type(self).txs[str(txid)]

    async def is_unspent(self, txid: str, vout: int) -> bool:
        return True


@pytest.fixture
def fake_book(monkeypatch):
    post, src = _posted_order(Asset(kind="rxd", amount=900))
    order = decode_rswp_order(post.advert_script)
    row = {
        "version": order.version,
        "flags": order.flags,
        "offered_type": order.offered_type,
        "terms_type": order.terms_type,
        "tokenid": order.token_id[::-1].hex(),
        "utxo": {"txid": order.offered_txid, "vout": order.offered_utxo_index},
        "price_terms": order.price_terms.hex(),
        "signature": order.signature.hex(),
        "block_height": 42,
    }
    _FakeNodeSource.rows = [row]
    _FakeNodeSource.txs = {src.txid(): src.serialize()}
    import pyrxd.cli.swap_book_cmds as mod

    monkeypatch.setattr(mod, "NodeRpcSource", _FakeNodeSource)
    return row


class TestOrders:
    def test_offer_side_lists_verified_order(self, runner: CliRunner, fake_book) -> None:
        token = f"{_REF.txid}:{_REF.vout}"
        result = runner.invoke(cli, ["swap", "orders", token, "--node-rpc", "http://x"])
        assert result.exit_code == 0, result.output
        assert "FILLABLE" in result.output
        assert "500 units of FT" in result.output
        assert "900 photons" in result.output

    def test_json_mode_payload(self, runner: CliRunner, fake_book) -> None:
        token = f"{_REF.txid}:{_REF.vout}"
        result = runner.invoke(cli, ["--json", "swap", "orders", token, "--node-rpc", "http://x"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["count"] == 1
        assert payload["orders"][0]["fillable"] is True
        assert payload["orders"][0]["block_height"] == 42

    def test_lying_index_row_shows_problem(self, runner: CliRunner, fake_book) -> None:
        other = GlyphRef(txid=Txid("ef" * 32), vout=9)
        fake_book["tokenid"] = swap_token_id(other).hex()  # index lies about the asset
        result = runner.invoke(cli, ["swap", "orders", f"{other.txid}:{other.vout}", "--node-rpc", "http://x"])
        assert result.exit_code == 0, result.output
        assert "FILLABLE" not in result.output
        assert "token_id does not match" in result.output

    def test_want_side_rxd_is_a_clean_error(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["swap", "orders", "rxd", "--want", "--node-rpc", "http://x"])
        assert result.exit_code != 0
        assert "want-side book cannot be queried for native RXD" in result.output

    def test_empty_book(self, runner: CliRunner, fake_book) -> None:
        _FakeNodeSource.rows = []
        result = runner.invoke(cli, ["swap", "orders", "rxd", "--node-rpc", "http://x"])
        assert result.exit_code == 0, result.output
        assert "no open orders" in result.output

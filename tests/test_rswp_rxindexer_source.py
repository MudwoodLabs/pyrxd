"""``RxindexerOrderbookSource`` over a fake ElectrumX-shaped transport.

No live RXinDexer endpoint was reachable from this environment (see the
module's "EXPERIMENTAL" docstring note), so these tests exercise the adapter
against an in-memory fake implementing exactly the duck-typed surface it
needs from an ``ElectrumXClient``: ``call_extension`` / ``get_transaction`` /
``get_utxos``. Real orders are built with :func:`create_rswp_order` (same
helper ``tests/test_rswp_book.py`` uses) so the field-mapping assertions
compare against a genuinely re-decoded :class:`RswpOrder`, not hand-typed
hex.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.hash import sha256
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.security.types import Hex20, Hex32, Txid
from pyrxd.swap import Asset, FundingInput, accept_offer
from pyrxd.swap.rswp import (
    OrderbookClient,
    OrderbookSource,
    RxindexerOrderbookSource,
    create_rswp_order,
    decode_rswp_order,
    swap_token_id,
)
from pyrxd.swap.rswp.wire import RXD_TOKEN_ID
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_REF = GlyphRef(txid=Txid("cd" * 32), vout=0)


def _key():
    k = PrivateKey()
    return k, k.public_key().hash160()


def _rxd_src(pkh: bytes, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(pkh), value))
    return tx


def _ft_src(pkh: bytes, ref: GlyphRef, value: int) -> Transaction:
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(build_ft_locking_script(Hex20(pkh), ref)), value))
    return tx


def _advert_tx(advert_script: bytes) -> Transaction:
    """Wrap an RSWP advert script in its own (single-output) advertising tx."""
    tx = Transaction()
    tx.add_output(TransactionOutput(Script(advert_script), 0))
    return tx


def _script_hash_of(tx: Transaction, vout: int) -> Hex32:
    return Hex32(sha256(tx.outputs[vout].locking_script.serialize())[::-1])


class FakeTransport:
    """Minimal ``ElectrumXClient``-shaped fake: call_extension / get_transaction / get_utxos."""

    def __init__(self) -> None:
        self.txs: dict[str, bytes] = {}
        self.extension_responses: dict[str, object] = {}
        self.extension_error: Exception | None = None
        self.utxos: dict[bytes, list[UtxoRecord]] = {}
        self.calls: list[tuple[str, list]] = []
        self.closed = False

    def add_tx(self, tx: Transaction) -> None:
        self.txs[tx.txid()] = tx.serialize()

    async def call_extension(self, method: str, params: list) -> object:
        self.calls.append((method, list(params)))
        if self.extension_error is not None:
            raise self.extension_error
        return self.extension_responses.get(method)

    async def get_transaction(self, txid) -> bytes:
        raw = self.txs.get(str(txid))
        if raw is None:
            raise NetworkError(f"fake transport has no tx for txid {str(txid)[:12]} (test double)")
        return raw

    async def get_utxos(self, script_hash) -> list[UtxoRecord]:
        return self.utxos.get(bytes(script_hash), [])

    async def close(self) -> None:
        self.closed = True


def _make_rxd_offer_ft_want_order():
    """Real v2 order: offers RXD, wants 50 units of an FT. Returns (advert_tx, order, give_source_tx)."""
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 100_000)
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("ft", 50, _REF), maker_receive_pkh=mk_pkh
    )
    tx = _advert_tx(post.advert_script)
    order = decode_rswp_order(post.advert_script)
    return tx, order, src


# --------------------------------------------------------------------------- Protocol conformance


def test_source_with_fake_transport_satisfies_protocol() -> None:
    source = RxindexerOrderbookSource(transport=FakeTransport())
    assert isinstance(source, OrderbookSource)


def test_constructor_requires_exactly_one_of_urls_or_transport() -> None:
    with pytest.raises(ValidationError, match="exactly 1"):
        RxindexerOrderbookSource()
    with pytest.raises(ValidationError, match="exactly 1"):
        RxindexerOrderbookSource(["wss://example.org:1"], transport=FakeTransport())


# --------------------------------------------------------------------------- field mapping


async def test_get_open_orders_maps_fields_via_independent_redecode() -> None:
    """The row is built by independently re-decoding the advert, NOT by trusting whatever
    decoded fields (price/status/maker) RXinDexer's own dict happened to carry."""
    tx, order, _src = _make_rxd_offer_ft_want_order()
    transport = FakeTransport()
    transport.add_tx(tx)
    transport.extension_responses["swap.get_orders"] = [
        {
            "tx_hash": tx.txid(),
            "vout": 0,
            "height": 428525,
            # RXinDexer-derived fields present on the real response but never trusted here:
            "price": 999_999_999,
            "status": "filled",
            "maker_address": "1BoGuSAddreSSxxxxxxxxxxxxxxxxxxxxx",
        }
    ]
    source = RxindexerOrderbookSource(transport=transport)

    rows = await source.get_open_orders(RXD_TOKEN_ID.hex())
    assert len(rows) == 1
    row = rows[0]

    assert row["version"] == order.version
    assert row["flags"] == order.flags
    assert row["offered_type"] == order.offered_type
    assert row["terms_type"] == order.terms_type
    assert row["tokenid"] == order.token_id[::-1].hex()
    assert row["want_tokenid"] == order.want_token_id[::-1].hex()
    assert row["utxo"] == {"txid": order.offered_txid, "vout": order.offered_utxo_index}
    assert row["price_terms"] == order.price_terms.hex()
    assert row["signature"] == order.signature.hex()
    assert row["block_height"] == 428525
    # RXinDexer's own decoded/cached fields are discovery-only, never surfaced.
    assert "price" not in row and "status" not in row and "maker_address" not in row


async def test_get_open_orders_queries_the_verified_ref_format() -> None:
    """base_ref is `<display-hex-token-id>_0` — the format ``glyph_api.py::_parse_ref``
    round-trips back to the on-chain-pushed token id bytes (verified from source)."""
    transport = FakeTransport()
    transport.extension_responses["swap.get_orders"] = []
    source = RxindexerOrderbookSource(transport=transport)

    token_hex = swap_token_id(_REF).hex()
    await source.get_open_orders(token_hex, limit=7, offset=3)

    assert transport.calls == [("swap.get_orders", [f"{token_hex}_0", None, 7, 3])]


async def test_want_token_omitted_when_no_want_side() -> None:
    """An order with no `want` side (flags bit 0 clear) has no want_tokenid key at all —
    matching NodeRpcSource rows, where ``entry.get("want_tokenid")`` is the None case."""
    mk, mk_pkh = _key()
    src = _ft_src(mk_pkh, _REF, 500)
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("rxd", 900), maker_receive_pkh=mk_pkh
    )
    tx = _advert_tx(post.advert_script)

    transport = FakeTransport()
    transport.add_tx(tx)
    transport.extension_responses["swap.get_orders"] = [{"tx_hash": tx.txid(), "vout": 0, "height": 1}]
    source = RxindexerOrderbookSource(transport=transport)

    (row,) = await source.get_open_orders(swap_token_id(_REF).hex())
    assert "want_tokenid" not in row


# --------------------------------------------------------------------------- fail-closed: discovery transport


async def test_transport_error_on_swap_get_orders_raises_network_error() -> None:
    transport = FakeTransport()
    transport.extension_error = RuntimeError("connection reset by peer, code 42")
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(NetworkError):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


async def test_error_dict_result_raises_network_error_not_empty_list() -> None:
    """`{'error': ...}` is RXinDexer's own "swap indexing not enabled" shape (a normal,
    non-exceptional RPC result) — must raise, never silently read as zero orders."""
    transport = FakeTransport()
    transport.extension_responses["swap.get_orders"] = {"error": "Swap indexing not enabled"}
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(NetworkError, match="error field"):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


async def test_non_list_result_raises_network_error() -> None:
    transport = FakeTransport()
    transport.extension_responses["swap.get_orders"] = "surprise-string"
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(NetworkError, match="not a list"):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


async def test_row_missing_tx_hash_raises_network_error() -> None:
    transport = FakeTransport()
    transport.extension_responses["swap.get_orders"] = [{"vout": 0}]  # no tx_hash
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(NetworkError, match="tx_hash"):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


async def test_unknown_advert_tx_raises() -> None:
    """RXinDexer points at a tx_hash the transport can't fetch (stale index / reorg) — fails closed."""
    transport = FakeTransport()
    transport.extension_responses["swap.get_orders"] = [{"tx_hash": "ab" * 32, "vout": 0, "height": 1}]
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(NetworkError):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


async def test_malformed_advert_script_raises_validation_error() -> None:
    """The referenced output exists but isn't a valid RSWP frame — decode_rswp_order raises,
    matching book.py's own "malformed rows raise" contract for _order_from_rpc."""
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(b"\x00" * 20), 0))  # not an OP_RETURN at all
    transport = FakeTransport()
    transport.add_tx(tx)
    transport.extension_responses["swap.get_orders"] = [{"tx_hash": tx.txid(), "vout": 0, "height": 1}]
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(ValidationError):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


async def test_vout_out_of_range_raises_validation_error() -> None:
    tx = Transaction()
    tx.add_output(TransactionOutput(P2PKH().lock(b"\x00" * 20), 0))
    transport = FakeTransport()
    transport.add_tx(tx)
    transport.extension_responses["swap.get_orders"] = [{"tx_hash": tx.txid(), "vout": 5, "height": 1}]
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(ValidationError, match="out of range"):
        await source.get_open_orders(RXD_TOKEN_ID.hex())


# --------------------------------------------------------------------------- get_open_orders_by_want gap


async def test_get_open_orders_by_want_always_raises() -> None:
    """Documented, source-verified capability gap: RXinDexer has no want-only order filter."""
    source = RxindexerOrderbookSource(transport=FakeTransport())
    with pytest.raises(NetworkError, match="no want-only order filter"):
        await source.get_open_orders_by_want(RXD_TOKEN_ID.hex())


# --------------------------------------------------------------------------- get_transaction / is_unspent


async def test_get_transaction_passthrough() -> None:
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    transport = FakeTransport()
    transport.add_tx(src)
    source = RxindexerOrderbookSource(transport=transport)
    assert await source.get_transaction(src.txid()) == src.serialize()


async def test_get_transaction_missing_raises_network_error() -> None:
    source = RxindexerOrderbookSource(transport=FakeTransport())
    with pytest.raises(NetworkError):
        await source.get_transaction("ab" * 32)


async def test_is_unspent_true_when_listed() -> None:
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    transport = FakeTransport()
    transport.add_tx(src)
    transport.utxos[bytes(_script_hash_of(src, 0))] = [UtxoRecord(tx_hash=src.txid(), tx_pos=0, value=1000, height=5)]
    source = RxindexerOrderbookSource(transport=transport)
    assert await source.is_unspent(src.txid(), 0) is True


async def test_is_unspent_false_when_not_listed() -> None:
    """Not present in listunspent (spent, or never existed as this script) -> False, not an error."""
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    transport = FakeTransport()
    transport.add_tx(src)
    source = RxindexerOrderbookSource(transport=transport)
    assert await source.is_unspent(src.txid(), 0) is False


async def test_is_unspent_vout_out_of_range_raises() -> None:
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    transport = FakeTransport()
    transport.add_tx(src)
    source = RxindexerOrderbookSource(transport=transport)
    with pytest.raises(NetworkError, match="out of range"):
        await source.is_unspent(src.txid(), 3)


async def test_is_unspent_transport_error_raises() -> None:
    source = RxindexerOrderbookSource(transport=FakeTransport())
    with pytest.raises(NetworkError):
        await source.is_unspent("ab" * 32, 0)


# --------------------------------------------------------------------------- close() ownership


async def test_close_is_noop_for_injected_transport() -> None:
    """The source never closes a transport it didn't create."""
    transport = FakeTransport()
    async with RxindexerOrderbookSource(transport=transport):
        pass
    assert transport.closed is False


# --------------------------------------------------------------------------- end-to-end through OrderbookClient


async def test_end_to_end_through_orderbook_client_is_fillable() -> None:
    """Discovery via the fake RXinDexer transport -> independent redecode -> the exact same
    fillability pipeline tests/test_rswp_book.py exercises against NodeRpcSource-shaped rows."""
    tx, _order, src = _make_rxd_offer_ft_want_order()
    transport = FakeTransport()
    transport.add_tx(tx)
    transport.add_tx(src)
    transport.extension_responses["swap.get_orders"] = [{"tx_hash": tx.txid(), "vout": 0, "height": 10}]
    # The offered UTXO (src:0) is unspent.
    transport.utxos[bytes(_script_hash_of(src, 0))] = [
        UtxoRecord(tx_hash=src.txid(), tx_pos=0, value=100_000, height=9)
    ]
    source = RxindexerOrderbookSource(transport=transport)

    entries = await OrderbookClient(source).orders_offering(None)  # RXD-native offered side
    assert len(entries) == 1
    entry = entries[0]
    assert entry.status == "open" and entry.fillable and entry.problem is None

    tk, tk_pkh = _key()
    tk_ft_src = _ft_src(tk_pkh, _REF, 50)
    tk_fee_src = _rxd_src(tk_pkh, 1000)
    tx_out = accept_offer(
        entry.offer,
        funding=[FundingInput(tk_ft_src, 0, tk), FundingInput(tk_fee_src, 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=200,
    )
    assert tx_out is not None

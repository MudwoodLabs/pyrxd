"""OrderbookClient: hostile-index pipeline over a fake OrderbookSource.

The index is untrusted: rows are re-verified against chain data fetched with the
computed-txid check, and *fillable* means exactly "what accept_offer would
accept". A lying index can at worst censor (hide/mislabel) — it can never make
a bad order look fillable.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, accept_offer
from pyrxd.swap.rswp import (
    OrderbookClient,
    OrderbookSource,
    create_rswp_order,
    decode_rswp_order,
    swap_token_id,
)
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


def _rpc_row(order, block_height: int = 10) -> dict:
    """Shape a decoded order the way getopenorders reports it (display hex ids)."""
    row = {
        "version": order.version,
        "flags": order.flags,
        "offered_type": order.offered_type,
        "terms_type": order.terms_type,
        "tokenid": order.token_id[::-1].hex(),
        "utxo": {"txid": order.offered_txid, "vout": order.offered_utxo_index},
        "price_terms": order.price_terms.hex(),
        "signature": order.signature.hex(),
        "block_height": block_height,
    }
    if order.want_token_id is not None:
        row["want_tokenid"] = order.want_token_id[::-1].hex()
    return row


class FakeSource:
    """In-memory OrderbookSource backed by real transactions."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.txs: dict[str, bytes] = {}
        self.spent: set[tuple[str, int]] = set()

    def add_tx(self, tx: Transaction) -> None:
        self.txs[tx.txid()] = tx.serialize()

    async def get_open_orders(self, token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        return [r for r in self.rows if r["tokenid"] == token_id_hex]

    async def get_open_orders_by_want(self, want_token_id_hex: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
        return [r for r in self.rows if r.get("want_tokenid") == want_token_id_hex]

    async def get_transaction(self, txid) -> bytes:
        return self.txs[str(txid)]

    async def is_unspent(self, txid: str, vout: int) -> bool:
        return (txid, vout) not in self.spent


def _setup_book() -> tuple[FakeSource, Transaction, PrivateKey, bytes]:
    """One real maker order (offering 500 FT for 900 RXD) on the fake book."""
    mk, mk_pkh = _key()
    src = _ft_src(mk_pkh, _REF, 500)
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("rxd", 900), maker_receive_pkh=mk_pkh
    )
    order = decode_rswp_order(post.advert_script)
    source = FakeSource()
    source.rows.append(_rpc_row(order))
    source.add_tx(src)
    return source, src, mk, mk_pkh


def test_fake_source_satisfies_protocol() -> None:
    assert isinstance(FakeSource(), OrderbookSource)


async def test_open_verified_order_is_fillable_end_to_end() -> None:
    source, _src, _, _ = _setup_book()
    entries = await OrderbookClient(source).orders_offering(_REF)
    assert len(entries) == 1
    e = entries[0]
    assert e.status == "open" and e.fillable and e.problem is None and e.block_height == 10

    # The returned offer is directly acceptable — fillable is not a guess.
    tk, tk_pkh = _key()
    tx = accept_offer(
        e.offer,
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=200,
    )
    assert tx.outputs[0].satoshis == 900


async def test_orders_wanting_finds_the_rxd_side() -> None:
    """An order offering RXD and wanting the FT appears in the want-side book."""
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1200)
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=mk, receive=Asset("ft", 50, _REF), maker_receive_pkh=mk_pkh
    )
    source = FakeSource()
    source.rows.append(_rpc_row(decode_rswp_order(post.advert_script)))
    source.add_tx(src)
    entries = await OrderbookClient(source).orders_wanting(_REF)
    assert len(entries) == 1 and entries[0].fillable


async def test_spent_offered_utxo_reports_spent_not_fillable() -> None:
    source, src, _, _ = _setup_book()
    source.spent.add((src.txid(), 0))
    (e,) = await OrderbookClient(source).orders_offering(_REF)
    assert e.status == "spent" and not e.fillable
    assert "already spent" in e.problem


async def test_lying_row_reported_with_problem_not_dropped() -> None:
    """Index row advertises a token id that doesn't match the real UTXO —
    surfaced as a problem entry, never shown fillable, never silently dropped."""
    source, _src, _, _ = _setup_book()
    source.rows[0]["tokenid"] = swap_token_id(GlyphRef(txid=Txid("ef" * 32), vout=9)).hex()
    entries = await OrderbookClient(source).orders_offering(GlyphRef(txid=Txid("ef" * 32), vout=9))
    assert len(entries) == 1
    e = entries[0]
    assert not e.fillable and e.offer is None
    assert "token_id does not match" in e.problem


async def test_hostile_source_tx_substitution_caught_by_txid_check() -> None:
    """get_transaction returning a different tx than requested (hostile indexer)
    is caught by fetch_transaction's computed-txid check → problem entry."""
    source, src, _, mk_pkh = _setup_book()
    source.txs[src.txid()] = _rxd_src(mk_pkh, 999).serialize()  # substitute
    (e,) = await OrderbookClient(source).orders_offering(_REF)
    assert not e.fillable
    assert "hash != requested" in e.problem


async def test_malformed_index_row_raises_fail_closed() -> None:
    """A structurally-broken row is index misbehavior — the listing call raises
    rather than presenting a partial book as healthy."""
    source, _, _, _ = _setup_book()
    del source.rows[0]["signature"]
    with pytest.raises(ValidationError, match="malformed swapindex response row"):
        await OrderbookClient(source).orders_offering(_REF)

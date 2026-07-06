"""Maker offer lifecycle tracker: classify OPEN / FILLED / CANCELLED against a
fake ElectrumX, adversarially, plus net-position math.

The fake server (``FakeElectrumX``) computes ``get_utxos``/``get_history`` by
scanning registered real :class:`Transaction` objects — the same shape a real
indexer reports — rather than hand-fed lookup tables, so ``classify()``'s
actual chain-walk is exercised, not a mocked shortcut.
"""

from __future__ import annotations

import pytest

from pyrxd.glyph.script import build_ft_locking_script
from pyrxd.glyph.types import GlyphRef
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.security.types import Hex20, Txid
from pyrxd.swap import Asset, FundingInput, SwapTerms
from pyrxd.swap.rswp import (
    OfferStatus,
    OfferTracker,
    TrackedOffer,
    build_advert_tx,
    build_cancel_tx,
    create_rswp_order,
    decode_rswp_order,
    load_offers,
    net_position,
    save_offers,
    take_rswp_order,
)
from pyrxd.swap.rswp.tracker import _script_hash, classify
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_output import TransactionOutput

_REF_G = GlyphRef(txid=Txid("aa" * 32), vout=0)  # token the maker gives
_REF_R = GlyphRef(txid=Txid("bb" * 32), vout=1)  # token the maker wants


def _key() -> tuple[PrivateKey, bytes]:
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


class FakeElectrumX:
    """In-memory ElectrumX stand-in. Registered transactions are scanned for
    ``get_utxos``/``get_history`` responses the way a real indexer would derive
    them — ``classify()`` never gets a hand-tailored answer."""

    def __init__(self) -> None:
        self._txs: dict[str, Transaction] = {}
        self._hostile_raw: dict[str, bytes] = {}

    def add(self, tx: Transaction) -> None:
        self._txs[tx.txid()] = tx

    def substitute(self, txid: str, hostile_raw: bytes) -> None:
        """Simulate a hostile/buggy server returning the WRONG bytes for *txid*."""
        self._hostile_raw[txid] = hostile_raw

    def _spent_outpoints(self) -> set[tuple[str, int]]:
        spent = set()
        for tx in self._txs.values():
            for inp in tx.inputs:
                spent.add((inp.source_txid, inp.source_output_index))
        return spent

    async def get_transaction(self, txid) -> bytes:
        txid = str(txid)
        if txid in self._hostile_raw:
            return self._hostile_raw[txid]
        return self._txs[txid].serialize()

    async def get_utxos(self, script_hash: bytes) -> list[UtxoRecord]:
        spent = self._spent_outpoints()
        out = []
        for txid, tx in self._txs.items():
            for vout, o in enumerate(tx.outputs):
                if (txid, vout) in spent:
                    continue
                if _script_hash(o.locking_script.serialize()) == script_hash:
                    out.append(UtxoRecord(tx_hash=txid, tx_pos=vout, value=o.satoshis, height=0))
        return out

    async def get_history(self, script_hash: bytes) -> list[dict]:
        out = []
        for txid, tx in self._txs.items():
            touches = any(_script_hash(o.locking_script.serialize()) == script_hash for o in tx.outputs)
            if not touches:
                for inp in tx.inputs:
                    src = self._txs.get(inp.source_txid)
                    if src and 0 <= inp.source_output_index < len(src.outputs):
                        spent_script = src.outputs[inp.source_output_index].locking_script.serialize()
                        if _script_hash(spent_script) == script_hash:
                            touches = True
                            break
            if touches:
                out.append({"tx_hash": txid, "height": 0})
        return out


def _post_offer(src: Transaction, maker_key, receive: Asset, maker_pkh: bytes):
    """Post an order and wrap it in a funded advert tx (mirrors the real flow)."""
    post = create_rswp_order(
        give_source_tx=src, give_vout=0, maker_key=maker_key, receive=receive, maker_receive_pkh=maker_pkh
    )
    order = decode_rswp_order(post.advert_script)
    advert_tx = build_advert_tx(
        advert_script=post.advert_script,
        funding=[FundingInput(_rxd_src(maker_pkh, 5000), 0, maker_key)],
        change_pkh=maker_pkh,
        fee=400,
    )
    return post, order, advert_tx


# ─────────────────────────────── classify() ──────────────────────────────────


async def test_classify_open_offer_reports_open_with_no_evidence() -> None:
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    fake = FakeElectrumX()
    fake.add(src)

    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()),
        outpoint_vout=0,
        terms=SwapTerms(give=Asset("rxd", 1000), receive=Asset("rxd", 600)),
    )
    result = await classify(fake, offer)
    assert result.status is OfferStatus.OPEN
    assert result.spending_txid is None


async def test_classify_filled_offer_reports_settlement_txid() -> None:
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    post, order, advert_tx = _post_offer(src, mk, Asset("ft", 50, _REF_R), mk_pkh)

    completion = take_rswp_order(
        order,
        give_source_tx=src,
        funding=[FundingInput(_ft_src(tk_pkh, _REF_R, 60), 0, tk), FundingInput(_rxd_src(tk_pkh, 5000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=300,
    )
    fake = FakeElectrumX()
    fake.add(src)
    fake.add(advert_tx)
    fake.add(completion)

    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()),
        outpoint_vout=0,
        terms=post.offer.terms,
        posted_advert_txid=Txid(advert_tx.txid()),
    )
    result = await classify(fake, offer)
    assert result.status is OfferStatus.FILLED
    assert result.spending_txid == completion.txid()


async def test_classify_cancelled_offer_reports_settlement_txid() -> None:
    mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    post, _order, advert_tx = _post_offer(src, mk, Asset("rxd", 600), mk_pkh)

    cancel_tx = build_cancel_tx(offered_source_tx=src, offered_vout=0, maker_key=mk, refund_pkh=mk_pkh, fee=200)
    fake = FakeElectrumX()
    fake.add(src)
    fake.add(advert_tx)
    fake.add(cancel_tx)

    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()),
        outpoint_vout=0,
        terms=post.offer.terms,
        posted_advert_txid=Txid(advert_tx.txid()),
    )
    result = await classify(fake, offer)
    assert result.status is OfferStatus.CANCELLED
    assert result.spending_txid == cancel_tx.txid()


async def test_classify_spent_without_advert_never_claims_filled() -> None:
    """No advert txid recorded → classify() cannot read the settlement-proof
    demand, so it must NOT guess FILLED — it reports CANCELLED (safe default)."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    post, order, _advert_tx = _post_offer(src, mk, Asset("rxd", 600), mk_pkh)

    completion = take_rswp_order(
        order,
        give_source_tx=src,
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=200,
    )
    fake = FakeElectrumX()
    fake.add(src)
    fake.add(completion)  # NOTE: advert_tx deliberately NOT registered / referenced

    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()), outpoint_vout=0, terms=post.offer.terms, posted_advert_txid=None
    )
    result = await classify(fake, offer)
    assert result.status is OfferStatus.CANCELLED
    assert result.spending_txid == completion.txid()


async def test_classify_hostile_spending_tx_substitution_rejected() -> None:
    """A hostile server returns different bytes than requested for the spending
    txid found via history — caught by fetch_transaction's computed-txid check
    before any settlement byte-compare runs."""
    mk, mk_pkh = _key()
    tk, tk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    post, order, advert_tx = _post_offer(src, mk, Asset("rxd", 600), mk_pkh)

    completion = take_rswp_order(
        order,
        give_source_tx=src,
        funding=[FundingInput(_rxd_src(tk_pkh, 2000), 0, tk)],
        taker_receive_pkh=tk_pkh,
        taker_change_pkh=tk_pkh,
        fee=200,
    )
    fake = FakeElectrumX()
    fake.add(src)
    fake.add(advert_tx)
    fake.add(completion)
    # Substitute a wholly different transaction's bytes for the completion txid.
    decoy = _rxd_src(mk_pkh, 999_999)
    fake.substitute(completion.txid(), decoy.serialize())

    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()),
        outpoint_vout=0,
        terms=post.offer.terms,
        posted_advert_txid=Txid(advert_tx.txid()),
    )
    with pytest.raises(ValidationError, match="hash != requested"):
        await classify(fake, offer)


async def test_classify_hostile_source_tx_substitution_rejected() -> None:
    """Same protection on the OFFERED utxo's own source tx (fetched first, by
    outpoint_txid) — a server cannot lie about what the offered UTXO even is."""
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    fake = FakeElectrumX()
    fake.add(src)
    decoy = _rxd_src(mk_pkh, 42)
    fake.substitute(src.txid(), decoy.serialize())

    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()),
        outpoint_vout=0,
        terms=SwapTerms(give=Asset("rxd", 1000), receive=Asset("rxd", 600)),
    )
    with pytest.raises(ValidationError, match="hash != requested"):
        await classify(fake, offer)


async def test_classify_out_of_range_vout_rejected() -> None:
    _mk, mk_pkh = _key()
    src = _rxd_src(mk_pkh, 1000)
    fake = FakeElectrumX()
    fake.add(src)
    offer = TrackedOffer(
        outpoint_txid=Txid(src.txid()),
        outpoint_vout=5,
        terms=SwapTerms(give=Asset("rxd", 1000), receive=Asset("rxd", 600)),
    )
    with pytest.raises(ValidationError, match="out of range"):
        await classify(fake, offer)


# ─────────────────────────────── OfferTracker ─────────────────────────────────


async def test_offer_tracker_classify_all_preserves_order() -> None:
    mk, mk_pkh = _key()
    open_src = _rxd_src(mk_pkh, 700)
    cancel_src = _rxd_src(mk_pkh, 800)
    post_open, _order_open, advert_open = _post_offer(open_src, mk, Asset("rxd", 500), mk_pkh)
    post_cancel, _order_cancel, advert_cancel = _post_offer(cancel_src, mk, Asset("rxd", 500), mk_pkh)
    cancel_tx = build_cancel_tx(offered_source_tx=cancel_src, offered_vout=0, maker_key=mk, refund_pkh=mk_pkh, fee=200)

    fake = FakeElectrumX()
    for tx in (open_src, advert_open, cancel_src, advert_cancel, cancel_tx):
        fake.add(tx)

    tracker = OfferTracker()
    tracker.add(TrackedOffer(Txid(open_src.txid()), 0, post_open.offer.terms, Txid(advert_open.txid())))
    tracker.add(TrackedOffer(Txid(cancel_src.txid()), 0, post_cancel.offer.terms, Txid(advert_cancel.txid())))

    results = await tracker.classify_all(fake)
    assert [r.status for r in results] == [OfferStatus.OPEN, OfferStatus.CANCELLED]


# ─────────────────────────────── net_position ─────────────────────────────────


def test_net_position_sums_filled_and_open_exact_ints() -> None:
    filled_rxd_for_ft = TrackedOffer(
        Txid("11" * 32), 0, SwapTerms(give=Asset("rxd", 1000), receive=Asset("ft", 50, _REF_R))
    )
    filled_ft_for_rxd = TrackedOffer(
        Txid("22" * 32), 0, SwapTerms(give=Asset("ft", 200, _REF_G), receive=Asset("rxd", 900))
    )
    open_rxd_for_ft = TrackedOffer(
        Txid("33" * 32), 0, SwapTerms(give=Asset("rxd", 300), receive=Asset("ft", 10, _REF_R))
    )
    cancelled = TrackedOffer(Txid("44" * 32), 0, SwapTerms(give=Asset("rxd", 5000), receive=Asset("rxd", 1)))

    offers = [filled_rxd_for_ft, filled_ft_for_rxd, open_rxd_for_ft, cancelled]
    statuses = [OfferStatus.FILLED, OfferStatus.FILLED, OfferStatus.OPEN, OfferStatus.CANCELLED]

    totals = net_position(offers, statuses)

    assert totals["rxd"] == {"given": 1000, "received": 900, "exposed": 300}
    # "exposed" only accrues on the GIVE side of an OPEN offer (the asset actually
    # sitting in the offered UTXO) — open_rxd_for_ft gives RXD, so the FT it merely
    # *wants* is not "exposed" (nothing of the maker's is at risk in that asset).
    assert totals[f"ft:{_REF_R.txid}:{_REF_R.vout}"] == {"given": 0, "received": 50, "exposed": 0}
    assert totals[f"ft:{_REF_G.txid}:{_REF_G.vout}"] == {"given": 200, "received": 0, "exposed": 0}
    # The cancelled offer's asset (RXD, again) must not silently double up "exposed"/"given".
    assert totals["rxd"]["given"] == 1000  # not 6000


def test_net_position_rejects_mismatched_lengths() -> None:
    offer = TrackedOffer(Txid("11" * 32), 0, SwapTerms(give=Asset("rxd", 1000), receive=Asset("rxd", 600)))
    with pytest.raises(ValidationError, match="same Length"):
        net_position([offer], [])


def test_net_position_empty_is_empty() -> None:
    assert net_position([], []) == {}


# ─────────────────────────────── TrackedOffer JSON ─────────────────────────────


def test_tracked_offer_round_trips_through_dict() -> None:
    offer = TrackedOffer(
        outpoint_txid=Txid("55" * 32),
        outpoint_vout=2,
        terms=SwapTerms(give=Asset("ft", 30, _REF_G), receive=Asset("rxd", 400)),
        posted_advert_txid=Txid("66" * 32),
        created_height=12345,
    )
    d = offer.to_dict()
    assert TrackedOffer.from_dict(d) == offer
    # JSON-round-trippable (all plain str/int/dict/None — no key material, no custom types).
    import json

    assert TrackedOffer.from_dict(json.loads(json.dumps(d))) == offer


def test_tracked_offer_rejects_negative_vout() -> None:
    with pytest.raises(ValidationError, match="non-negative"):
        TrackedOffer(
            outpoint_txid=Txid("77" * 32),
            outpoint_vout=-1,
            terms=SwapTerms(give=Asset("rxd", 1), receive=Asset("rxd", 1)),
        )


def test_load_offers_missing_file_is_empty_list(tmp_path) -> None:
    assert load_offers(tmp_path / "does-not-exist.json") == []


def test_save_and_load_offers_round_trip(tmp_path) -> None:
    path = tmp_path / "offers.json"
    offers = [
        TrackedOffer(Txid("88" * 32), 0, SwapTerms(give=Asset("rxd", 100), receive=Asset("rxd", 50))),
        TrackedOffer(
            Txid("99" * 32), 1, SwapTerms(give=Asset("ft", 5, _REF_G), receive=Asset("rxd", 20)), Txid("aa" * 32), 100
        ),
    ]
    save_offers(path, offers)
    assert load_offers(path) == offers

"""The BTC fields a swap record gained in #850 PR 9a (schema 10): our recorded refund, and the claim
and disposition evidence in BTC's hash shapes. Every refusal has its honest twin."""

from __future__ import annotations

import dataclasses
import json

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_state import SWAP_RECORD_SCHEMA_VERSION, CounterDispositionRecord, SwapRecord, SwapState
from pyrxd.security.errors import ValidationError
from tests._fake_btc_chain import FakeBtcChain
from tests.test_swap_coordinator import _terms
from tests.test_swap_state import _eth_locator, _eth_terms


def _btc(chain: FakeBtcChain) -> SwapRecord:
    terms = _terms(hashlock=chain.hashlock, t_btc_blocks=chain.t_btc_blocks)
    return (
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms)
        .with_counter_lock(chain.locator)
        .with_state(SwapState.BTC_LOCKED)
    )


def _eth_base_record() -> SwapRecord:
    return SwapRecord(state=SwapState.NEGOTIATED, terms=_eth_terms()).with_counter_lock(_eth_locator())


def _evidence(**kw) -> CounterDispositionRecord:
    fields = {
        "kind": "refunded",
        "block_number": 160,
        "block_hash": "b1" * 32,
        "tx_hash": "d1" * 32,
        "sources": ("a", "b"),
        "single_source": False,
    }
    return CounterDispositionRecord(**{**fields, **kw})


def test_a_recorded_refund_round_trips_and_writes_the_current_schema():
    chain = FakeBtcChain()
    raw = chain.refund_tx()
    record = dataclasses.replace(_btc(chain), counter_refund_raw=raw.hex().upper())
    assert record.counter_refund_raw == raw.hex(), "not normalised to lower-case"
    d = record.to_dict()
    assert d["schema_version"] == SWAP_RECORD_SCHEMA_VERSION == 11
    assert SwapRecord.from_dict(json.loads(json.dumps(d))) == record
    # ...and a BTC record without any new field keeps the v1 form.
    assert "schema_version" not in _btc(chain).to_dict()


def test_a_recorded_refund_must_spend_this_records_outpoint():
    chain, other = FakeBtcChain(), FakeBtcChain()
    with pytest.raises(ValidationError, match="does not spend"):
        dataclasses.replace(_btc(chain), counter_refund_raw=other.refund_tx().hex())
    with pytest.raises(ValidationError, match="hex"):
        dataclasses.replace(_btc(chain), counter_refund_raw="zz")
    with pytest.raises(ValidationError):
        dataclasses.replace(_btc(chain), counter_refund_raw="00" * 10)  # does not parse
    no_locator = SwapRecord(state=SwapState.NEGOTIATED, terms=_btc(chain).terms)
    with pytest.raises(ValidationError, match="locator"):
        dataclasses.replace(no_locator, counter_refund_raw=chain.refund_tx().hex())


def test_a_recorded_refund_is_a_btc_field():
    chain = FakeBtcChain()
    with pytest.raises(ValidationError, match="BTC counter-leg field"):
        dataclasses.replace(_eth_base_record(), counter_refund_raw=chain.refund_tx().hex())


def test_claim_and_evidence_take_the_shape_of_their_chain():
    chain = FakeBtcChain()
    btc, eth = _btc(chain), _eth_base_record()
    # Honest: each chain's own shape.
    dataclasses.replace(btc, counter_claim_tx="c1" * 32, counter_disposition=_evidence())
    dataclasses.replace(
        eth,
        counter_claim_tx="0x" + "c1" * 32,
        counter_disposition=_evidence(block_hash="0x" + "b1" * 32, tx_hash="0x" + "d1" * 32),
    )
    # Crossed.
    with pytest.raises(ValidationError, match="txid"):
        dataclasses.replace(btc, counter_claim_tx="0x" + "c1" * 32)
    with pytest.raises(ValidationError):
        dataclasses.replace(eth, counter_claim_tx="c1" * 32)
    with pytest.raises(ValidationError, match="not BTC-shaped"):
        dataclasses.replace(btc, counter_disposition=_evidence(block_hash="0x" + "b1" * 32, tx_hash="0x" + "d1" * 32))
    with pytest.raises(ValidationError, match="not ETH-shaped"):
        dataclasses.replace(eth, counter_disposition=_evidence())
    with pytest.raises(ValidationError, match="mixes"):
        _evidence(tx_hash="0x" + "d1" * 32)
    with pytest.raises(ValidationError, match="64 lower-case hex"):
        _evidence(block_hash="B1" * 32)


def test_with_counter_lock_keeps_the_recorded_refund():
    chain = FakeBtcChain()
    record = dataclasses.replace(_btc(chain), counter_refund_raw=chain.refund_tx().hex())
    assert record.with_counter_lock(chain.locator).counter_refund_raw == record.counter_refund_raw
    assert t.btc_txid_from_raw(bytes.fromhex(record.counter_refund_raw))

"""The #850 PR 5a record fields: each validator refuses what it should, and each field alone makes
the record write a schema version (review of 5a: none of this was pinned, and a record whose only
new field was one of these serialised as v2, which an older pyrxd reads by silently dropping it)."""

from __future__ import annotations

import dataclasses

import pytest

from pyrxd.gravity.swap_state import (
    SWAP_RECORD_SCHEMA_VERSION,
    AbortReason,
    CounterDispositionRecord,
    SwapRecord,
    SwapState,
)
from pyrxd.security.errors import ValidationError
from tests.test_swap_record_round_trip_guard import _btc_base, _eth_base

_GOOD = {
    "kind": "refunded",
    "block_number": 90,
    "block_hash": "0x" + "b1" * 32,
    "tx_hash": "0x" + "d1" * 32,
    "sources": ("a.test",),
    "single_source": True,
}


def test_HONEST_a_good_disposition_record_builds():
    assert CounterDispositionRecord(**_GOOD).kind == "refunded"
    assert CounterDispositionRecord(**{**_GOOD, "kind": "claimed", "tx_hash": None}).tx_hash is None


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "open"},
        {"block_number": -1},
        {"block_number": True},
        {"block_hash": "0x12"},
        {"tx_hash": "0xzz"},
        {"sources": ["a.test"]},
        {"sources": (1,)},
        {"single_source": 1},
    ],
)
def test_a_bad_disposition_record_is_refused(bad):
    with pytest.raises(ValidationError):
        CounterDispositionRecord(**{**_GOOD, **bad})


def test_from_dict_does_not_coerce_single_source():
    with pytest.raises(ValidationError):
        CounterDispositionRecord.from_dict({**_GOOD, "sources": list(_GOOD["sources"]), "single_source": "yes"})


@pytest.mark.parametrize(
    ("base", "fields"),
    [
        (_btc_base, {"counter_claim_tx": "0x" + "c1" * 32}),  # ETH-only field on a BTC record
        (_btc_base, {"counter_disposition": CounterDispositionRecord(**_GOOD)}),
        (_eth_base, {"counter_claim_tx": "0x12"}),
        (_eth_base, {"counter_disposition": {"kind": "refunded"}}),
        (_eth_base, {"abort_reason": "counter_leg_refunded"}),
        (_eth_base, {"asset_refund_txid": "AB" * 32}),
        (_eth_base, {"asset_refund_txid": "ab" * 31}),
    ],
)
def test_a_bad_record_field_is_refused(base, fields):
    with pytest.raises(ValidationError):
        dataclasses.replace(base(), **fields)


@pytest.mark.parametrize(
    "fields",
    [
        {"counter_claim_tx": "0x" + "c1" * 32},
        {"counter_disposition": CounterDispositionRecord(**_GOOD)},
        {"abort_reason": AbortReason.COUNTER_LEG_REFUNDED, "state": SwapState.ABORTED},
        {"asset_refund_txid": "ab" * 32},
    ],
)
def test_each_new_field_alone_writes_the_current_schema_version(fields):
    record = dataclasses.replace(_eth_base(), **fields)
    d = record.to_dict()
    assert d["schema_version"] == SWAP_RECORD_SCHEMA_VERSION == 4
    assert SwapRecord.from_dict(d) == record


def test_HONEST_a_record_without_them_keeps_its_old_form():
    assert "schema_version" not in _btc_base().to_dict()

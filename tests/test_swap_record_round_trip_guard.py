"""Every ``SwapRecord`` field survives a write and a read of the record (#850 PR 2, design §4.5).

The coordinator persists its record through ``to_dict`` and resumes from ``from_dict``. A field that
``to_dict`` drops reads back as its default after a restart, with no error anywhere. #850 adds a
field in most of its PRs, so the field set here is DERIVED from ``dataclasses.fields(SwapRecord)``
and checked against a per-field sample registry in both directions: a new field with no sample
fails, and so does a sample for a field that no longer exists.

Each sample sets its field to a non-default value on a valid base record, with only the partners
``SwapRecord`` requires (a deploy handle comes as contract and tx; a push hash comes with its
nonce), and the record must come back equal after a JSON round trip, the transport the record
sink uses.

One gap is known and pinned ``xfail(strict=True)``: the push nonce and hash are serialised only
inside the pending-deploy block (``swap_state.py``, ``if self.pending_counter_contract:``), so a
push recorded without a pending deploy is lost. #850 PR 3 records the push for every token fund
and moves them out of that block; that PR turns these into passes, which fails the build until
the markers are deleted.
"""

from __future__ import annotations

import dataclasses
import json
import os
from collections.abc import Callable

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.gravity.swap_state import SwapRecord, SwapState
from tests.test_swap_record_erc20_migration import _erc20_locator, _token_terms
from tests.test_swap_state import _eth_locator, _eth_terms, _locator, _terms

_HASH = "0x" + "ab" * 32


def _btc_base() -> SwapRecord:
    return SwapRecord(state=SwapState.NEGOTIATED, terms=_terms())


def _eth_base() -> SwapRecord:
    return SwapRecord(state=SwapState.NEGOTIATED, terms=_eth_terms())


def _token_base() -> SwapRecord:
    return SwapRecord(state=SwapState.NEGOTIATED, terms=_token_terms())


def _raw_btc_tx() -> str:
    """A structurally valid segwit transaction, which ``pending_btc_funding_tx`` requires."""
    body = (2).to_bytes(4, "little") + b"\x00\x01\x01"
    body += t.BtcOutpoint(os.urandom(32).hex(), 0).prevout_bytes() + b"\x00" + (0xFFFFFFFD).to_bytes(4, "little")
    body += b"\x01" + (90_000).to_bytes(8, "little") + b"\x01\x51"
    body += b"\x01\x40" + os.urandom(64)
    return (body + (0).to_bytes(4, "little")).hex()


def _with(base: Callable[[], SwapRecord], **fields) -> Callable[[], SwapRecord]:
    return lambda: dataclasses.replace(base(), **fields)


_PUSH_GAP = pytest.mark.xfail(
    strict=True,
    reason="#850 PR 3: the push nonce and hash are serialised only inside the pending-deploy block",
)

#: field name -> [(label, builder, marks)]. Builders return a record with that field set.
SAMPLES: dict[str, list[tuple[str, Callable[[], SwapRecord], tuple]]] = {
    "state": [("state", _with(_btc_base, state=SwapState.BOTH_LOCKED), ())],
    "terms": [
        ("btc-terms", _btc_base, ()),
        ("eth-terms", _eth_base, ()),
        ("token-terms", _token_base, ()),
    ],
    "counterchain_locator": [
        ("btc-locator", lambda: _btc_base().with_counter_lock(_locator()), ()),
        ("eth-locator", lambda: _eth_base().with_counter_lock(_eth_locator()), ()),
        ("erc20-locator", lambda: _token_base().with_counter_lock(_erc20_locator()), ()),
    ],
    "radiant_covenant_outpoint": [
        ("covenant-outpoint", _with(_btc_base, radiant_covenant_outpoint="cd" * 32 + ":0"), ())
    ],
    "radiant_covenant_spk_hex": [
        ("covenant-spk", _with(_btc_base, radiant_covenant_spk_hex="a914" + "11" * 20 + "87"), ())
    ],
    "pending_counter_contract": [
        (
            "pending-deploy",
            _with(_token_base, pending_counter_contract="0x" + "77" * 20, pending_counter_deploy_tx=_HASH),
            (),
        )
    ],
    "pending_counter_deploy_tx": [
        (
            "pending-deploy-tx",
            _with(_eth_base, pending_counter_contract="0x" + "78" * 20, pending_counter_deploy_tx="0x" + "de" * 32),
            (),
        )
    ],
    "pending_push_nonce": [
        (
            "push-nonce-with-pending-deploy",
            _with(
                _token_base,
                pending_counter_contract="0x" + "77" * 20,
                pending_counter_deploy_tx=_HASH,
                pending_push_nonce=7,
            ),
            (),
        ),
        ("push-nonce-alone", _with(_token_base, pending_push_nonce=7), (_PUSH_GAP,)),
    ],
    "pending_push_tx_hash": [
        (
            "push-hash-with-pending-deploy",
            _with(
                _token_base,
                pending_counter_contract="0x" + "77" * 20,
                pending_counter_deploy_tx=_HASH,
                pending_push_nonce=7,
                pending_push_tx_hash="0x" + "ef" * 32,
            ),
            (),
        ),
        (
            "push-hash-and-nonce-alone",
            _with(_token_base, pending_push_nonce=7, pending_push_tx_hash="0x" + "ef" * 32),
            (_PUSH_GAP,),
        ),
    ],
    "single_operator_override": [("override", _with(_btc_base, single_operator_override="operator said so"), ())],
    "fund_refusal": [("fund-refusal", _with(_btc_base, fund_refusal="refused: gate"), ())],
    "pending_btc_funding_tx": [
        ("pending-btc-fund", lambda: dataclasses.replace(_btc_base(), pending_btc_funding_tx=_raw_btc_tx()), ())
    ],
}


def test_the_sample_registry_covers_exactly_the_record_fields() -> None:
    """Both directions: a field with no sample is unguarded; a sample for a removed field checks
    nothing."""
    fields = {f.name for f in dataclasses.fields(SwapRecord)}
    assert fields, "SwapRecord has no fields; this check checked nothing"
    assert set(SAMPLES) == fields, {
        "fields without a sample": sorted(fields - set(SAMPLES)),
        "samples for no field": sorted(set(SAMPLES) - fields),
    }
    assert all(SAMPLES.values()), [name for name, samples in SAMPLES.items() if not samples]


_CASES = [
    pytest.param(field, build, id=label, marks=marks)
    for field, samples in SAMPLES.items()
    for label, build, marks in samples
]


@pytest.mark.parametrize(("field", "build"), _CASES)
def test_each_field_survives_a_json_round_trip(field: str, build: Callable[[], SwapRecord]) -> None:
    record = build()
    default = next(f for f in dataclasses.fields(SwapRecord) if f.name == field).default
    if default is not dataclasses.MISSING:
        assert getattr(record, field) != default, f"the {field} sample leaves the field at its default"
    back = SwapRecord.from_dict(json.loads(json.dumps(record.to_dict())))
    assert getattr(back, field) == getattr(record, field), f"{field} did not survive the round trip"
    assert back == record

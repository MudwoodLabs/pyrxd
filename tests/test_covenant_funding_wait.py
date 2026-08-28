"""The covenant-funding wait actually works against the shape `get_utxos` really returns.

Written after it did not. The helper replaced an operator attestation across five runners, shipped
with guards for call ORDER and for imports, and then crashed on a live mainnet run — at the
`print` in its own success path, on `u.txid`/`u.vout`. The real record is
`pyrxd.network.electrumx.UtxoRecord`, whose fields are `tx_hash`/`tx_pos`.

It had detected the funded covenant correctly. The value comparison was right, the polling was
right, and none of that mattered because the success branch had never once been executed. Order
and import checks say nothing about a return type, and a helper that is only ever exercised by
spending real money on a real chain is a helper with no tests.

The fake here returns REAL `UtxoRecord` instances, not a stand-in with convenient attributes —
a hand-shaped double with `.txid` on it would have passed while production crashed.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from pyrxd.network.electrumx import UtxoRecord

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from _dust_swap_shared import wait_for_covenant_funding

_SPK = bytes.fromhex("76a914" + "11" * 20 + "88ac")
_AMOUNT = 1000


class _Client:
    """Minimal stand-in for SshTrRadiantClient: records registrations, replays scripted answers."""

    def __init__(self, *answers):
        self._answers = list(answers)
        self.registered: list[bytes] = []
        self.calls = 0

    def register_spk(self, spk: bytes) -> None:
        self.registered.append(bytes(spk))

    async def get_utxos(self, script_hash: bytes):
        self.calls += 1
        return self._answers.pop(0) if self._answers else []


async def _run(client, **kw):
    return await wait_for_covenant_funding(client, covenant_spk=_SPK, expected_photons=_AMOUNT, poll_s=0, **kw)


def test_returns_the_matching_utxo_and_survives_formatting_it():
    """The regression. A UtxoRecord must be returned AND printable by the helper's own success path."""
    hit = UtxoRecord(tx_hash="ab" * 32, tx_pos=1, value=_AMOUNT, height=910_000)
    client = _Client([hit])
    got = asyncio.run(_run(client))
    assert got is hit
    assert client.registered == [_SPK], "the SPK must be registered or get_utxos cannot resolve it"


def test_waits_through_an_empty_utxo_set():
    """Nothing there yet is the normal case, not an error — the maker has not funded it."""
    hit = UtxoRecord(tx_hash="cd" * 32, tx_pos=0, value=_AMOUNT, height=910_001)
    client = _Client([], [], [hit])
    assert asyncio.run(_run(client)) is hit
    assert client.calls == 3


def test_an_unconfirmed_utxo_is_not_accepted():
    """height 0 is unconfirmed. The attestation this replaced said ">= 1 conf", and the reorg gate
    downstream assumes a mined covenant, so accepting height 0 would race it."""
    unconfirmed = UtxoRecord(tx_hash="ef" * 32, tx_pos=0, value=_AMOUNT, height=0)
    confirmed = UtxoRecord(tx_hash="ef" * 32, tx_pos=0, value=_AMOUNT, height=910_002)
    client = _Client([unconfirmed], [confirmed])
    assert asyncio.run(_run(client)) is confirmed


def test_a_mis_funded_covenant_is_never_accepted():
    """The covenant PINS its amount, so a UTXO of the wrong value is one the swap can never spend.
    Keeping the wrong value and the right value DIFFERENT here is the point — a fixture where they
    coincide cannot tell an amount check from no check at all."""
    wrong = UtxoRecord(tx_hash="12" * 32, tx_pos=0, value=_AMOUNT + 1, height=910_003)
    right = UtxoRecord(tx_hash="34" * 32, tx_pos=0, value=_AMOUNT, height=910_004)
    client = _Client([wrong], [wrong], [right])
    got = asyncio.run(_run(client))
    assert got is right, "a covenant funded with the wrong amount must not satisfy the wait"


def test_the_right_utxo_is_picked_out_of_a_crowded_spk():
    wrong = UtxoRecord(tx_hash="56" * 32, tx_pos=0, value=_AMOUNT * 7, height=910_005)
    right = UtxoRecord(tx_hash="78" * 32, tx_pos=3, value=_AMOUNT, height=910_006)
    assert asyncio.run(_run(_Client([wrong, right]))) is right


def test_a_none_answer_is_tolerated():
    """Some transports return None rather than [] for an empty set; `for u in None` would raise."""
    hit = UtxoRecord(tx_hash="9a" * 32, tx_pos=0, value=_AMOUNT, height=910_007)
    assert asyncio.run(_run(_Client(None, [hit]))) is hit


@pytest.mark.parametrize("field", ["tx_hash", "tx_pos", "value", "height"])
def test_the_helper_only_uses_fields_UtxoRecord_actually_has(field):
    """Pins the contract that broke. If ElectrumX's record is renamed, this fails here rather than
    on a mainnet run with a funded covenant and an unfunded counter leg."""
    assert field in UtxoRecord.__annotations__, (
        f"UtxoRecord no longer has {field!r}; wait_for_covenant_funding reads it"
    )

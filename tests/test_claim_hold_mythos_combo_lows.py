"""Three LOW findings of the combined Mythos pass of 2026-11-12 on the #789 echo-mismatch fix.

* 3.2: a held claim (one the broadcast client answered with another txid, or only a second opinion
  took) was re-sent for the whole hold whatever the deadline, and a re-send skips the deadline-aware
  fee gate. Now the hold ends once the executor's own finality re-assess, run the fee policy's
  urgency horizon ahead, no longer reads SAFE: from then on each tick rebuilds.
* 3.3: after a mismatch no second opinion was asked. Now ``RadiantChainIO.broadcast`` offers the
  same bytes to the second-opinion clients, so an honest operator relays a claim the broadcast
  client dropped.
* 3.4: a mismatch on a taker's coordinator claim, or on a maker-stall covenant refund, left the
  record behind: a retry rebuilt into a covenant the first send had already spent and failed "no
  UTXO found" every time. Now the claim's txid is kept and checked on retry, and the stall refund's
  txid is recorded as ``asset_refund_txid``.

The executor tests run the real executor, ``RadiantCovenantLeg``, ``RadiantChainIO`` and
``ElectrumXClient`` over the ``_Node`` wire model of ``test_claim_executor_echo_mismatch``.
"""

from __future__ import annotations

import dataclasses
import logging
import os
from typing import Any

import pytest

from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantEchoMismatch, SecondOpinionTxid
from pyrxd.gravity.watch import ExecOutcome
from pyrxd.security.errors import BroadcastEchoMismatch, NetworkError, TlsPinMismatchError

from test_claim_executor_echo_mismatch import (  # isort: skip
    _COVENANT,
    _COVENANT_TXID,
    _LIE,
    _Node,
    _armed,
    _assert_paid_once,
    _txid,
)
from test_claim_second_opinion import _OpNode, _one_chain, _second, _with_second_opinion  # isort: skip

#: ``_armed`` builds the covenant with ``t_rxd`` = 144 blocks.
_T_RXD = 144


class _DeepNode(_Node):
    """A ``_Node`` whose covenant reads ``depth`` confirmations deep."""

    def __init__(self, depth: int = 1) -> None:
        super().__init__()
        self.depth = depth

    async def _call(self, method: str, params: list[Any]) -> Any:
        if method == "blockchain.transaction.get" and params[0] == _COVENANT_TXID:
            return {"txid": params[0], "confirmations": self.depth}
        return await super()._call(method, params)


def _left(blocks: int) -> int:
    """The covenant depth that leaves *blocks* blocks before the maker's refund opens."""
    return _T_RXD - blocks


@pytest.fixture
def tick(caplog):
    async def _tick(ex, rec):
        from test_watch_claim_executor import _claim_decision

        caplog.clear()
        with caplog.at_level(logging.INFO):
            outcome = await ex.execute("swap-1", rec, _claim_decision())
        return outcome, " | ".join(r.getMessage() for r in caplog.records)

    return _tick


# --------------------------------------------------------------------------- 3.2: the hold near the deadline


async def _held_by_a_liar(tick, blocks_left: int):
    """An armed executor whose first claim the broadcast client dropped and lied about, so the
    claim is held; the covenant then reads *blocks_left* blocks from the deadline."""
    node = _DeepNode(depth=1)
    ex, rec, fees = await _armed(node)
    node.lie, node.relay = True, False
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED and "re-sending the same bytes" in said, said
    assert ex._held, "the mismatch holds the claim"
    node.depth = _left(blocks_left)
    return node, ex, rec, fees


async def test_far_from_the_deadline_the_held_bytes_are_re_sent(tick) -> None:
    """Honest path: the hold still saves fee inputs while the window has room. 13 blocks left is the
    nearest a held claim is still re-sent under ``MarginPolicy.estimated`` (6-block burial) and the
    default fee policy (6-block urgency horizon): 13 - 6 = 7 still reads SAFE."""
    node, ex, rec, fees = await _held_by_a_liar(tick, 13)
    first = node.broadcasts[0]
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.FAILED and "re-send echo mismatch" in said, said
    assert node.broadcasts == [first, first] and len(fees.outpoints) == 1


@pytest.mark.parametrize("blocks_left", [12, 7])
async def test_near_the_deadline_the_held_claim_is_rebuilt_not_re_sent(tick, blocks_left) -> None:
    """Inside the last urgency horizon the executor still claims in, a liar that drops the held bytes
    must not keep the claim off the network for the whole hold: every tick rebuilds."""
    node, ex, rec, fees = await _held_by_a_liar(tick, blocks_left)
    first = node.broadcasts[0]

    outcome, said = await tick(ex, rec)
    assert "no longer re-sent, the claim is rebuilt" in said, said
    assert len(fees.outpoints) == 2, "rebuilt on a new fee input"
    assert node.broadcasts[-1] != first

    node.lie, node.relay = False, True
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert len(fees.outpoints) == 3
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(node.broadcasts[-1])


async def test_inside_the_squeeze_the_executor_still_declines(tick) -> None:
    """The early end of the hold does not widen the window: 6 blocks left reads SQUEEZED and
    nothing is sent, held or not."""
    node, ex, rec, fees = await _held_by_a_liar(tick, 6)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "not safe to claim now" in said, said
    assert len(node.broadcasts) == 1 and len(fees.outpoints) == 1


async def test_the_horizon_comes_from_the_legs_fee_policy(tick) -> None:
    """A wider urgency horizon ends the hold earlier: with 20 blocks of horizon, 13 blocks left
    already rebuilds."""
    from pyrxd.gravity.fee_policy import DeadlineFeePolicy

    node, ex, rec, fees = await _held_by_a_liar(tick, 13)
    leg = await ex._resolve_leg("swap-1", rec)
    leg.fee_policy = dataclasses.replace(DeadlineFeePolicy(), urgency_horizon_blocks=20)
    outcome, said = await tick(ex, rec)
    assert "no longer re-sent" in said, said
    assert len(fees.outpoints) == 2


# --------------------------------------------------------------------------- 3.3: a second opinion after a mismatch


async def test_a_mismatch_is_offered_to_the_second_opinion_which_takes_it() -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    primary.lie, primary.relay = True, False
    raw = os.urandom(80)
    txid = await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(raw)
    assert txid == _txid(raw) and isinstance(txid, SecondOpinionTxid)
    assert txid.raw == raw
    assert second.broadcasts == [raw] and set(second.mempool) == {_txid(raw)}


async def test_a_mismatch_no_second_opinion_takes_is_raised_as_the_mismatch() -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    primary.lie = True
    second.reject = (-26, "the second endpoint's reason")
    raw = os.urandom(80)
    with pytest.raises(RadiantEchoMismatch) as info:
        await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(raw)
    assert info.value.raw == raw and info.value.echoed == _LIE
    assert isinstance(info.value.__cause__, BroadcastEchoMismatch)
    assert second.broadcasts == [raw], "the second operator was asked"


async def test_a_pin_mismatch_in_the_round_still_raises_the_mismatch() -> None:
    """The bytes went out to the broadcast client, so a pin failure on the second opinion must not
    turn the answer into a transport failure, which the executor would rebuild on."""
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    primary.lie = True
    second.fail = TlsPinMismatchError("pin mismatch")
    with pytest.raises(RadiantEchoMismatch):
        await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(os.urandom(80))


async def test_without_a_second_opinion_the_mismatch_is_raised_as_before() -> None:
    primary = _OpNode("wss://electrum.alpha.example/")
    primary.lie = True
    with pytest.raises(RadiantEchoMismatch):
        await RadiantChainIO(primary).broadcast(os.urandom(80))


async def test_a_claim_the_broadcast_client_drops_and_lies_about_lands_through_a_second_operator(tick) -> None:
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    ex, rec, fees = await _with_second_opinion(primary, second)
    primary.lie, primary.relay = True, False

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert "first endpoint mis-echoed" in said and "beta.example took it" in said, said
    claim = primary.broadcasts[0]
    assert set(second.mempool) == {_txid(claim)}
    assert ex._held, "held, not marked seen: the one client that took it may be lying"

    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "re-sent the same bytes" in said, said
    assert len(fees.outpoints) == 1
    _one_chain(primary, second)
    assert _assert_paid_once(second, fees) == _txid(claim)


# --------------------------------------------------------------------------- 3.4: the coordinator's claim and stall refund


class _Leg:
    """A Radiant leg for the coordinator whose broadcasts answer as told, over a covenant reader."""

    def __init__(self) -> None:
        self.chain_io = self
        self.claims: list[bytes] = []
        self.refunds = 0
        self.lie = True
        self.confs: dict[str, int] = {}
        self.unspent = True

    async def claim_asset(self, record, preimage: bytes) -> str:
        raw = os.urandom(60)
        self.claims.append(raw)
        if self.lie:
            raise RadiantEchoMismatch(raw, _LIE)
        return _txid(raw)

    async def refund_asset(self, record) -> str:
        self.refunds += 1
        raw = os.urandom(60) + bytes([self.refunds])
        self.last_refund = _txid(raw)
        if self.lie:
            raise RadiantEchoMismatch(raw, _LIE)
        return self.last_refund

    async def confirmations(self, txid: str) -> int:
        if txid not in self.confs:
            raise NetworkError("No such mempool or blockchain transaction")
        return self.confs[txid]

    async def covenant_outpoint_unspent(self, spk: bytes, outpoint: str) -> bool:
        return self.unspent


def _coordinator(leg: _Leg):
    from pyrxd.gravity.swap_coordinator import SwapCoordinator

    coord = SwapCoordinator.__new__(SwapCoordinator)
    coord.radiant_leg = leg
    coord.record = _Rec()
    coord.persisted = []

    async def _persist(record, *, shield: bool = False) -> None:
        coord.persisted.append(record)

    coord._persist_record = _persist
    return coord


@dataclasses.dataclass(frozen=True)
class _Rec:
    radiant_covenant_outpoint: str = _COVENANT
    radiant_covenant_spk_hex: str = "51"
    asset_refund_txid: str | None = None


_P = b"\x01" * 32


async def test_a_mismatched_claim_that_confirms_is_not_sent_again() -> None:
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    sent = _txid(leg.claims[0])
    leg.unspent = False  # the claim spent the covenant
    leg.confs[sent] = 1
    await coord._claim_asset_once(_P)  # returns: the caller advances the record
    assert len(leg.claims) == 1, "nothing sent again"


async def test_a_mismatched_claim_in_the_mempool_waits_and_sends_nothing() -> None:
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.unspent = False
    with pytest.raises(NetworkError, match="not confirmed"):
        await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


async def test_a_mismatched_claim_that_did_not_land_is_sent_again() -> None:
    """Honest path: the covenant still reads unspent, so the claim did not land and is sent again."""
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.lie = False
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 2


async def test_an_honest_claim_is_sent_once() -> None:
    leg = _Leg()
    leg.lie = False
    coord = _coordinator(leg)
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1 and getattr(coord, "_mismatched_claim_txid", None) is None


async def test_a_mismatched_stall_refund_is_recorded_and_not_sent_again_once_it_lands() -> None:
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._refund_asset_on_stall_once()
    assert coord.record.asset_refund_txid == leg.last_refund
    assert coord.persisted and coord.persisted[-1].asset_refund_txid == leg.last_refund, "persisted"
    leg.confs[leg.last_refund] = 1
    await coord._refund_asset_on_stall_once()
    assert leg.refunds == 1, "the recorded refund landed: nothing sent again"


async def test_a_mismatched_stall_refund_that_did_not_land_is_sent_again() -> None:
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._refund_asset_on_stall_once()
    leg.lie = False
    await coord._refund_asset_on_stall_once()
    assert leg.refunds == 2
    assert coord.record.asset_refund_txid is None, "a dropped refund's record is cleared before the re-send"

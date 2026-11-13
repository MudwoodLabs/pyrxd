"""Three LOW findings of the combined Mythos pass of 2026-11-12 on the #789 echo-mismatch fix.

* 3.2: a held claim (one the broadcast client answered with another txid, or only a second opinion
  took) was re-sent for the whole hold whatever the deadline. Now, once the executor's own finality
  re-assess, run the fee policy's urgency horizon ahead, no longer reads SAFE, a held claim is
  rebuilt once per new block and re-sent in between; the held bytes are kept until a rebuild is
  sent, and re-sent when the pool cannot fund one (the Mythos pass on #986, F2.1/F2.2).
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
async def test_near_the_deadline_the_held_claim_is_rebuilt_once_per_block(tick, blocks_left) -> None:
    """Inside the last urgency horizon the executor still claims in, a liar that drops the held bytes
    must not keep the claim off the network for the whole hold: a new block rebuilds it. In the same
    block the rebuilt bytes are re-sent, not rebuilt again."""
    node, ex, rec, fees = await _held_by_a_liar(tick, blocks_left)
    first = node.broadcasts[0]

    outcome, said = await tick(ex, rec)
    assert "rebuilt once per new block" in said, said
    assert "until the next block, then rebuilding" in said, said
    assert len(fees.outpoints) == 2, "rebuilt on a new fee input"
    rebuilt = node.broadcasts[-1]
    assert rebuilt != first

    node.lie, node.relay = False, True
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "now taken by the broadcast client" in said, said
    assert node.broadcasts[-1] == rebuilt and len(fees.outpoints) == 2, "re-sent, not rebuilt"
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(rebuilt)


async def test_a_liar_near_the_deadline_spends_one_input_per_block_not_per_tick(tick) -> None:
    """F2.1: a broadcast client that lies for eight ticks in the last horizon used to take a fee
    input every tick. In one block it now takes one, and the rebuilt claim lands once the client
    stops lying."""
    node, ex, rec, fees = await _held_by_a_liar(tick, 10)
    for _ in range(8):
        await tick(ex, rec)
    assert len(fees.outpoints) == 2, fees.outpoints
    assert len(set(node.broadcasts[1:])) == 1, "the one rebuild is re-sent, not rebuilt"
    node.lie, node.relay = False, True
    await tick(ex, rec)
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(node.broadcasts[-1])


async def test_the_next_block_allows_one_more_rebuild(tick) -> None:
    """Honest path of the per-block bound: a new block lets a held claim be rebuilt again."""
    node, ex, rec, fees = await _held_by_a_liar(tick, 10)
    await tick(ex, rec)
    assert len(fees.outpoints) == 2
    node.depth += 1
    await tick(ex, rec)
    assert len(fees.outpoints) == 3


async def test_an_exhausted_pool_near_the_deadline_re_sends_the_held_bytes(tick) -> None:
    """F2.1: when the pool cannot fund the rebuild, the held claim is re-sent instead of dropped, and
    the page still says the pool is exhausted."""
    from pyrxd.security.errors import FeePoolExhaustedError

    node, ex, rec, fees = await _held_by_a_liar(tick, 10)
    first = node.broadcasts[0]

    def _empty():
        raise FeePoolExhaustedError("the pool is at its cap")

    fees.next_fee_input = _empty
    node.lie, node.relay = False, True
    outcome, _said = await tick(ex, rec)
    why = ex.take_reason("swap-1")
    assert outcome is ExecOutcome.FAILED and why.kind == "fee_pool_exhausted", why
    assert "the held claim was re-sent instead" in why.text, why
    assert node.broadcasts[-1] == first, "the held bytes went out again"
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(first)


async def test_one_over_reporting_depth_source_cannot_force_a_rebuild_per_tick(tick) -> None:
    """F2.2: a quorum source that over-reports depth (and keeps raising it) puts every tick in the
    last horizon. Rebuilds follow the SHALLOWER depth, which does not move, so there is one."""
    _node, ex, rec, fees = await _held_by_a_liar(tick, 30)  # the single node: far from the deadline

    class _Liar:
        depth = _left(10)

        async def covenant_confirmations(self, outpoint: str) -> int:
            self.depth += 1
            return self.depth

    ex._rxd_depth_corroborator = _Liar()
    for _ in range(4):
        await tick(ex, rec)
    assert len(fees.outpoints) == 2, fees.outpoints


async def test_inside_the_squeeze_the_executor_still_declines(tick) -> None:
    """The early end of the hold does not widen the window: 6 blocks left reads SQUEEZED and
    nothing is sent, held or not."""
    node, ex, rec, fees = await _held_by_a_liar(tick, 6)
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.DECLINED and "not safe to claim now" in said, said
    assert len(node.broadcasts) == 1 and len(fees.outpoints) == 1


async def test_the_horizon_comes_from_the_legs_fee_policy(tick) -> None:
    """A wider urgency horizon reaches the last horizon earlier: with 20 blocks of horizon, 13 blocks
    left already rebuilds."""
    from pyrxd.gravity.fee_policy import DeadlineFeePolicy

    _node, ex, rec, fees = await _held_by_a_liar(tick, 13)
    leg = await ex._resolve_leg("swap-1", rec)
    leg.fee_policy = dataclasses.replace(DeadlineFeePolicy(), urgency_horizon_blocks=20)
    _outcome, said = await tick(ex, rec)
    assert "rebuilt once per new block" in said, said
    assert len(fees.outpoints) == 2


async def test_a_primary_that_under_reports_then_climbs_cannot_force_a_rebuild_per_tick(tick) -> None:
    """Re-review of the fix: the primary (the client that mis-echoes) under-reports the covenant's
    depth and then raises it one block per tick, while an honest quorum puts the window in the last
    horizon. A rebuild needs the deeper height to move too, so there is one per real block."""
    node, ex, rec, fees = await _held_by_a_liar(tick, 30)
    node.depth = 2

    class _Honest:
        async def covenant_confirmations(self, outpoint: str) -> int:
            return _left(10)

    ex._rxd_depth_corroborator = _Honest()
    for _ in range(8):
        node.depth += 1
        await tick(ex, rec)
    assert len(fees.outpoints) == 2, fees.outpoints


async def test_an_exhausted_pool_keeps_the_held_bytes_after_the_re_sends_run_out(tick) -> None:
    """Re-review of the fix: with the pool exhausted, a liar that answers more re-sends than the hold
    allows must not cost the signed claim. Once the client stops lying, the held bytes land."""
    from pyrxd.security.errors import FeePoolExhaustedError

    node, ex, rec, fees = await _held_by_a_liar(tick, 12)
    first = node.broadcasts[0]

    def _empty():
        raise FeePoolExhaustedError("the pool is at its cap")

    fees.next_fee_input = _empty
    for _ in range(ex._resend_ticks + 1):
        node.depth += 1 if node.depth < _left(7) else 0
        await tick(ex, rec)
    assert ex._held, "the bytes are kept"
    node.lie, node.relay = False, True
    await tick(ex, rec)
    assert node.broadcasts[-1] == first
    node.mine()
    assert _assert_paid_once(node, fees) == _txid(first)


async def test_a_rebuild_the_broadcast_client_takes_ends_the_hold(tick) -> None:
    """Re-review LOW 2: with no seen store, a rebuilt claim the broadcast client takes must drop the
    older held bytes, or the next tick would re-send them and conflict with the rebuild."""
    node, ex, rec, _fees = await _held_by_a_liar(tick, 10)
    assert ex._seen is None
    node.lie, node.relay = False, True
    outcome, said = await tick(ex, rec)
    assert outcome is ExecOutcome.BROADCAST, said
    assert ex._held == {}


async def test_a_huge_horizon_is_logged_and_still_bounded_per_block(tick) -> None:
    """F1.1: a hand-built fee policy with a horizon wider than the window puts the whole window in
    the last horizon. That is logged, once, and rebuilds stay at one per block."""
    from pyrxd.gravity.fee_policy import DeadlineFeePolicy

    _node, ex, rec, fees = await _held_by_a_liar(tick, 60)
    leg = await ex._resolve_leg("swap-1", rec)
    leg.fee_policy = dataclasses.replace(DeadlineFeePolicy(), urgency_horizon_blocks=1000)
    _outcome, said = await tick(ex, rec)
    assert "1000 block(s) from now" in said, said
    for _ in range(3):
        _outcome, said = await tick(ex, rec)
        assert "1000 block(s)" not in said, "logged once"
    assert len(fees.outpoints) == 2


async def test_an_un_assessable_look_ahead_counts_as_near_the_deadline(tick, monkeypatch) -> None:
    """P04: a look-ahead that cannot be assessed reads as near the deadline (fail closed toward the
    rebuild), not as SAFE. The first assess of each tick is the real gate; the second is the look-ahead."""
    from pyrxd.gravity.watch import claim_executor
    from pyrxd.security.errors import ValidationError

    _node, ex, rec, fees = await _held_by_a_liar(tick, 30)
    real, calls = claim_executor.assess_claim_finality, []

    def _second_raises(**kw):
        calls.append(kw)
        if len(calls) % 2 == 0:
            raise ValidationError("cannot assess")
        return real(**kw)

    monkeypatch.setattr(claim_executor, "assess_claim_finality", _second_raises)
    _outcome, said = await tick(ex, rec)
    assert "un-assessable" in said, said
    assert len(fees.outpoints) == 2, "rebuilt, as near the deadline"


def test_the_default_fee_policy_adds_no_premium_where_the_executor_rebuilds() -> None:
    """F1.3: the docs say a near-deadline rebuild takes a new fee input and, at the default policy, no
    urgency premium: the rebuild zone under ``MarginPolicy.estimated`` is 12 down to 7 blocks left,
    and the premium starts inside the 6-block horizon."""
    from pyrxd.gravity.fee_policy import DEFAULT_RADIANT_DEADLINE_FEE_POLICY as policy

    assert all(policy.urgency_multiplier(b) == 1.0 for b in range(7, 13))
    assert policy.urgency_multiplier(1) > 1.0


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


async def test_a_pin_mismatch_in_the_round_still_raises_the_mismatch(caplog) -> None:
    """The bytes went out to the broadcast client, so a pin failure on the second opinion must not
    turn the answer into a transport failure, which the executor would rebuild on. It is still logged."""
    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    primary.lie = True
    second.fail = TlsPinMismatchError("pin mismatch")
    with caplog.at_level(logging.ERROR), pytest.raises(RadiantEchoMismatch):
        await RadiantChainIO(primary).with_second_opinion((second,)).broadcast(os.urandom(80))
    assert any(r.levelno == logging.ERROR and "TLS pin" in r.getMessage() for r in caplog.records)


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


async def test_a_tick_cancelled_in_the_second_opinion_round_keeps_the_hold(tick, monkeypatch) -> None:
    """F3.1: the broadcast client answered with another txid, then the tick was cancelled while the
    second opinions were asked. The bytes went out, so they are held, not lost to a rebuild."""
    import asyncio

    primary, second = _OpNode("wss://electrum.alpha.example/"), _second()
    ex, rec, fees = await _with_second_opinion(primary, second)
    primary.lie, primary.relay = True, False

    async def _cancelled(self, raw, **kw):
        raise asyncio.CancelledError

    monkeypatch.setattr(RadiantChainIO, "_ask_second_opinion", _cancelled)
    with pytest.raises(asyncio.CancelledError) as info:
        await tick(ex, rec)
    assert isinstance(info.value.__cause__, RadiantEchoMismatch)
    held = next(iter(ex._held.values()))
    assert held[0] == primary.broadcasts[0]
    monkeypatch.undo()
    await tick(ex, rec)
    assert len(fees.outpoints) == 1, "re-sent, not rebuilt"


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


async def test_a_depth_from_the_mis_echoing_client_alone_does_not_end_the_retries() -> None:
    """The client that answered the claim with another txid also reports it one deep, but the
    covenant still reads unspent: the claim did not land, so it is sent again."""
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.confs[_txid(leg.claims[0])] = 1  # the covenant still reads unspent
    leg.lie = False
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 2


async def test_a_mismatched_claim_with_no_chain_reader_is_sent_again() -> None:
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.chain_io = None
    leg.lie = False
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 2


async def test_a_failed_depth_read_with_no_covenant_reader_raises_and_sends_nothing() -> None:
    class _NoCovenantReader(_Leg):
        covenant_outpoint_unspent = None  # type: ignore[assignment]

    leg = _NoCovenantReader()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    with pytest.raises(NetworkError, match="No such mempool"):
        await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


async def test_a_mismatched_stall_refund_with_no_chain_reader_is_sent_again() -> None:
    leg = _Leg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._refund_asset_on_stall_once()
    leg.chain_io = None
    leg.lie = False
    await coord._refund_asset_on_stall_once()
    assert leg.refunds == 2


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


class _SpendLeg(_Leg):
    """A ``_Leg`` that also reads what spent the covenant from every source, as
    ``RadiantCovenantLeg.covenant_spend`` does; ``spend`` is what that read answers."""

    def __init__(self, network: str = "bcrt") -> None:
        super().__init__()
        self.network = network
        self.spend: Any = None
        self.reads: list[int] = []

    async def covenant_spend(self, record, *, burial_blocks: int):
        self.reads.append(burial_blocks)
        return self.spend


def _spend(kind: str, *, buried: bool = True, operators: int = 2):
    from pyrxd.gravity.radiant_leg import CovenantSpend, CovenantSpendKind

    return CovenantSpend(
        CovenantSpendKind(kind),
        "test",
        txid="ee" * 32,
        depth=1 if buried else 0,
        buried=buried,
        sources=("wss://electrum.alpha.example/", "wss://electrum.beta.example/"),
        operators=operators,
    )


async def test_the_mis_echoing_client_alone_cannot_mark_the_claim_landed() -> None:
    """F4.1: the client that answered with another txid says the claim is one deep and the covenant
    spent, but every source together reads the covenant unspent: the claim is sent again."""
    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.confs[_txid(leg.claims[0])], leg.unspent = 1, False  # the one client's word
    leg.spend, leg.lie = _spend("unspent"), False
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 2 and leg.reads == [1]


async def test_a_claim_every_source_reads_buried_is_not_sent_again() -> None:
    """Honest path of F4.1."""
    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.spend = _spend("claimed")
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


@pytest.mark.parametrize(
    "spend",
    [
        _spend("claimed", buried=False),
        _spend("claimed", operators=1),
        _spend("unknown"),
    ],
    ids=["in-the-mempool", "one-operator-on-value", "unknown"],
)
async def test_a_claim_not_shown_landed_by_every_source_sends_nothing(spend) -> None:
    leg = _SpendLeg(network="mainnet")
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.spend = spend
    with pytest.raises(NetworkError, match="Nothing was sent again"):
        await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


async def test_a_stall_refund_the_taker_claimed_says_so() -> None:
    """Re-review LOW 1: a recorded refund, then the covenant reads CLAIMED: the refund can never land,
    and the error says the claim leaf spent it, not "not confirmed"."""
    from pyrxd.security.errors import ValidationError

    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._refund_asset_on_stall_once()
    leg.spend = _spend("claimed")
    with pytest.raises(ValidationError, match="p is public"):
        await coord._refund_asset_on_stall_once()
    assert leg.refunds == 1


async def test_a_claim_the_maker_refunded_says_so() -> None:
    from pyrxd.security.errors import ValidationError

    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.spend = _spend("refunded")
    with pytest.raises(ValidationError, match="CSV refund leaf"):
        await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


async def test_sources_that_cannot_read_history_fall_back_to_the_chain_io() -> None:
    """Re-review LOW 3: no source can read a script's history (none answers, none failed), so the one
    chain IO's reads decide, as before, rather than waiting forever."""
    from pyrxd.gravity.radiant_leg import CovenantSpend, CovenantSpendKind

    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.spend = CovenantSpend(CovenantSpendKind.UNKNOWN, "no source answered")
    leg.unspent, leg.confs[_txid(leg.claims[0])] = False, 1
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


async def test_sources_that_all_failed_send_nothing() -> None:
    """Honest-path pair of the fallback: sources that failed are an outage, not a missing reader."""
    from pyrxd.gravity.radiant_leg import CovenantSpend, CovenantSpendKind

    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    leg.spend = CovenantSpend(CovenantSpendKind.UNKNOWN, "no source answered", failed=("alpha",))
    with pytest.raises(NetworkError, match="Nothing was sent again"):
        await coord._claim_asset_once(_P)
    assert len(leg.claims) == 1


async def test_a_failed_re_send_keeps_the_first_claims_txid() -> None:
    """F4.2: the covenant reads unspent (the first claim is in a mempool the reader cannot see), so
    the claim is sent again and the node refuses the conflict. The first claim's txid is kept, so
    once it confirms a retry sees it and sends nothing."""
    from pyrxd.security.errors import PolicyRejection

    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._claim_asset_once(_P)
    first = coord._mismatched_claim_txid
    leg.spend = _spend("unspent")

    async def _conflict(record, preimage):
        leg.claims.append(b"conflict")
        raise PolicyRejection("txn-mempool-conflict")

    leg.claim_asset = _conflict
    with pytest.raises(PolicyRejection):
        await coord._claim_asset_once(_P)
    assert coord._mismatched_claim_txid == first
    leg.spend = _spend("claimed")
    await coord._claim_asset_once(_P)
    assert len(leg.claims) == 2 and coord._mismatched_claim_txid is None


async def test_a_stall_refund_every_source_reads_buried_is_not_sent_again() -> None:
    """N7.C: the recorded refund counts as landed only on every source's read, not on one depth."""
    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._refund_asset_on_stall_once()
    leg.confs[leg.last_refund] = 1  # the mis-echoing client's depth alone
    leg.spend = _spend("unspent")
    leg.lie = False
    await coord._refund_asset_on_stall_once()
    assert leg.refunds == 2
    assert coord.record.asset_refund_txid is None


async def test_a_stall_refund_in_the_mempool_sends_nothing() -> None:
    leg = _SpendLeg()
    coord = _coordinator(leg)
    with pytest.raises(RadiantEchoMismatch):
        await coord._refund_asset_on_stall_once()
    recorded = coord.record.asset_refund_txid
    leg.spend = _spend("refunded", buried=False)
    with pytest.raises(NetworkError, match="Nothing was sent again"):
        await coord._refund_asset_on_stall_once()
    assert leg.refunds == 1 and coord.record.asset_refund_txid == recorded
    leg.spend = _spend("refunded")
    await coord._refund_asset_on_stall_once()
    assert leg.refunds == 1


def _callers_in(tree: Any, attr: str) -> set[str]:
    """The functions in *tree* whose bodies call ``<anything>.<attr>(...)`` or name *attr* in a string
    (a ``getattr``): any receiver, so an alias of ``self.radiant_leg`` counts (Mythos pass on #986, F4.3)."""
    import ast

    found: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.Attribute) and node.attr == attr) or (
                isinstance(node, ast.Constant) and node.value == attr
            ):
                found.add(fn.name)
    return found


def _callers_of(attr: str) -> set[str]:
    """The functions in ``swap_coordinator`` (methods and module-level helpers alike) that call
    *attr*, read from the module's source, so a new call site that skips the helper is found without
    a hand-kept list of receivers."""
    import ast
    import inspect

    from pyrxd.gravity import swap_coordinator

    return _callers_in(ast.parse(inspect.getsource(swap_coordinator)), attr)


def _calls(fn_name: str) -> set[str]:
    """The attribute names *fn_name* (a SwapCoordinator method) calls."""
    import ast
    import inspect
    import textwrap

    from pyrxd.gravity import swap_coordinator

    tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(swap_coordinator.SwapCoordinator, fn_name))))
    return {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}


def test_every_coordinator_claim_goes_through_the_mismatch_aware_helper() -> None:
    assert _callers_of("claim_asset") == {"_claim_asset_once"}


def test_the_stall_refund_goes_through_the_mismatch_aware_helper() -> None:
    """Pinned as a set: a refund moved to a new method is a new caller (F4.3). The other two are the
    mutual refund and the maker's covenant refund, which record their own txid."""
    assert _callers_of("refund_asset") == {
        "_refund_asset_on_stall_once",
        "_refund_the_covenant_once",
        "maker_refund_covenant",
    }
    assert "_refund_asset_on_stall_once" in _calls("maybe_refund_asset_on_maker_stall")


def test_the_guard_sees_an_alias_of_the_leg() -> None:
    """The F4.3 plants: ``leg = self.radiant_leg; await leg.claim_asset(...)`` and a ``getattr`` by
    name are still callers."""
    import ast

    src = (
        "class C:\n"
        "    async def f(self):\n        leg = self.radiant_leg\n        await leg.claim_asset(1, 2)\n"
        "    async def g(self):\n        await getattr(self.radiant_leg, 'claim_asset')(1, 2)\n"
    )
    assert _callers_in(ast.parse(src), "claim_asset") == {"f", "g"}

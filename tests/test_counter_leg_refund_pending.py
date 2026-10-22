"""Our own ETH counter-leg refund is pending until the chain shows it refunded (#850 PR 5b).

Design §3.3-§3.4 and §7.2 scenarios 1, 2, 3, 10 and 18: the refund is recorded (hash and nonce)
between signing and broadcasting; the record stays put until the reader shows the contract REFUNDED
at the finalized block; a retry reads what happened to the recorded refund and re-sends only on the
bounded rules. Driven through the real ``SwapCoordinator`` and the real reader over the fake chain;
only the leg's broadcast and its read of its own refund are faked (``_ChainLeg``).
"""

from __future__ import annotations

import dataclasses

import pytest

import pyrxd.gravity.swap_coordinator as sc
from pyrxd.gravity.swap_coordinator import REFUND_REPLACE_AFTER_S, SwapCoordinator
from pyrxd.gravity.swap_state import AbortReason, SwapRecord, SwapState
from pyrxd.security.errors import CounterLegPayoutReverts, CounterLegRefundNeedsOperator, ValidationError
from tests._fake_evm_chain import FakeEvmEndpoint
from tests.test_counter_leg_disposition_coordinator import _setup, refund_label


def _logless(chain):
    """Endpoints that answer the log scan with nothing: only a recorded hash or the anchor can
    then prove a refund."""
    return [FakeEvmEndpoint(chain, hide_all_logs=True) for _ in range(3)]


# --------------------------------------------------------------------------- scenario 1


async def test_our_refund_is_recorded_and_the_record_waits_then_aborts_on_the_chain():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    rec = await coord.taker_refund_btc()
    # Plant "advance on broadcast" and this is ABORTED here, before anything mined.
    assert rec.state is SwapState.BTC_LOCKED
    tx, nonce, _ = leg.signed[0]
    assert (rec.counter_refund_tx_hash, rec.counter_refund_nonce) == (tx, nonce)
    chain.refund(85, label=refund_label(1))
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.abort_reason is AbortReason.COUNTER_LEG_REFUNDED
    assert rec.counter_disposition.tx_hash == tx and leg.refunds == 1


async def test_a_dropped_refund_is_sent_again_and_the_new_one_is_followed():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.dropped.add(leg.signed[0][0])
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 2 and rec.counter_refund_tx_hash == leg.signed[1][0]
    assert rec.state is SwapState.BTC_LOCKED
    chain.refund(85, label=refund_label(2))
    assert (await coord.taker_refund_btc()).state is SwapState.ABORTED


async def test_a_refund_whose_nonce_another_transaction_took_is_sent_again():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.nonce_taken.add(leg.signed[0][0])
    await coord.taker_refund_btc()
    assert leg.refunds == 2 and leg.signed[1][2] is None  # a new refund, not a replacement


async def test_the_recorded_hash_alone_proves_the_refund_when_no_log_is_returned():
    """§2.3 (d) with our own hash as the nomination. Plant "do not pass the recorded hash" and the
    answer is UNKNOWN (settled, nothing verified), so the record never leaves BTC_LOCKED."""
    coord, chain, _leg = _setup(endpoints=_logless, chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    coord.record = dataclasses.replace(coord.record, counter_expiry_anchor=None)  # the hash alone
    chain.refund(85, label=refund_label(1))
    assert (await coord.taker_refund_btc()).state is SwapState.ABORTED


# --------------------------------------------------------------------------- pending and replacement


async def test_a_pending_refund_is_not_sent_again_and_is_replaced_only_after_the_wait(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    first, nonce, _ = leg.signed[0]
    await coord.taker_refund_btc()  # first seen pending: starts the clock
    clock[0] += REFUND_REPLACE_AFTER_S - 1
    await coord.taker_refund_btc()
    assert leg.refunds == 1  # still waiting
    clock[0] += 1
    rec = await coord.taker_refund_btc()
    assert leg.refunds == 2
    replaced_tx, replaced_nonce, replace = leg.signed[1]
    assert replace is not None and replace.nonce == nonce == replaced_nonce
    assert replace.previous_fees == {"maxFeePerGas": 100, "maxPriorityFeePerGas": 2}
    assert rec.counter_refund_tx_hash == replaced_tx != first and rec.counter_refund_nonce == nonce


async def test_a_pending_transaction_that_is_none_of_our_refunds_is_never_replaced(monkeypatch):
    """Review round 2 of 5b: replacing what holds the nonce when it is not one of our refunds could
    cancel another transaction from the same key. It asks the operator; even the flag sends nothing."""
    from pyrxd.eth_wallet.htlc_leg import RefundProgress

    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()

    async def foreign(_h, _n, **_k):
        return RefundProgress("pending", fee_fields=None)

    leg.refund_progress = foreign
    await coord.taker_refund_btc()  # starts the clock: waits
    clock[0] += REFUND_REPLACE_AFTER_S
    with pytest.raises(CounterLegRefundNeedsOperator, match="none of the refunds this record signed") as info:
        await coord.taker_refund_btc()
    assert info.value.cause == "other_tx"  # the runner then does not point at the resend flag
    with pytest.raises(CounterLegRefundNeedsOperator):
        await coord.taker_refund_btc(resend_reverted_refund=True)
    assert leg.refunds == 1


async def test_a_replacement_that_never_reached_the_node_is_replaced_over_the_one_it_holds(monkeypatch):
    """Review rounds 1 and 2 of 5b: the replacement's hash is recorded before a broadcast that failed.
    The earlier refund still holds the nonce, so the next replacement is priced over IT, read through
    the earlier hashes the record keeps. Plant "do not pass earlier hashes" and the pending refund
    can never be priced again."""
    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    first, nonce, _ = leg.signed[0]
    await coord.taker_refund_btc()
    clock[0] += REFUND_REPLACE_AFTER_S
    leg.fail_broadcast = True
    from pyrxd.security.errors import NetworkError

    with pytest.raises(NetworkError, match="underpriced"):
        await coord.taker_refund_btc()
    second = leg.signed[1][0]
    assert coord.record.counter_refund_tx_hash == second  # recorded before the broadcast, as designed
    assert coord.record.counter_refund_replaced_tx_hashes == (first,)
    assert coord.persisted[-1].counter_refund_replaced_tx_hashes == (first,)  # durable
    leg.fail_broadcast = False
    await coord.taker_refund_btc()  # first seen pending under the new hash: starts its clock
    clock[0] += REFUND_REPLACE_AFTER_S
    rec = await coord.taker_refund_btc()
    third, third_nonce, replace = leg.signed[2]
    assert third_nonce == nonce and replace.previous_fees == leg.fees[first]  # priced over what the node holds
    assert rec.counter_refund_tx_hash == third and rec.counter_refund_replaced_tx_hashes == (second, first)


async def test_an_earlier_refund_that_mined_is_followed_not_replaced():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    first = leg.signed[0][0]
    leg.dropped.add(first)
    leg.next_nonce = leg.signed[0][1]  # a dropped nonce is free again: the re-send takes it
    await coord.taker_refund_btc()  # re-sent at the same nonce: the first is kept as earlier
    assert coord.record.counter_refund_replaced_tx_hashes == (first,)
    leg.dropped.discard(first)
    chain.refund(85, label=refund_label(1))  # ...and it was the first one that mined
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and leg.refunds == 2


async def test_a_refund_at_a_new_nonce_clears_the_earlier_hashes():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.nonce_taken.add(leg.signed[0][0])
    rec = await coord.taker_refund_btc()  # the fake signs the next one at a new nonce
    assert rec.counter_refund_nonce != leg.signed[0][1] and rec.counter_refund_replaced_tx_hashes == ()


async def test_a_mined_refund_is_followed_not_resent():
    coord, chain, leg = _setup(chain_kw={"finalized": 90, "head": 100})
    await coord.taker_refund_btc()
    chain.refund(95, label=refund_label(1))  # above F: settled at the tip only
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and leg.refunds == 1


# --------------------------------------------------------------------------- scenario 18: persist first


async def test_the_refund_is_persisted_before_it_is_broadcast():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})

    async def down_for_the_refund(record):
        # Only the write that carries the refund fails: the anchor's earlier write must succeed, or
        # this would pass on THAT failure, before the refund was ever signed.
        if record.counter_refund_tx_hash is not None:
            raise OSError("disk full")

    coord._persist = down_for_the_refund
    with pytest.raises(OSError, match="disk full"):
        await coord.taker_refund_btc()
    assert leg.refunds == 1  # it was signed...
    assert leg.signed == []  # ...and the hook raised before the "broadcast"
    assert coord.record.counter_refund_tx_hash is None  # not adopted in memory either


async def test_a_restart_after_the_send_reads_the_recorded_refund_and_sends_nothing():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    reloaded = SwapRecord.from_dict(coord.persisted[-1].to_dict())
    assert reloaded.counter_refund_tx_hash == leg.signed[0][0]
    again = SwapCoordinator(
        record=reloaded,
        counter_leg=leg,
        radiant_leg=coord.radiant_leg,
        indexer=coord.indexer,
        seen_store=coord.seen_store,
        config=coord.config,
    )

    async def _persist(_r):
        return None

    again._persist = _persist
    await again.taker_refund_btc()
    assert leg.refunds == 1


# --------------------------------------------------------------------------- scenario 2: out of gas


async def test_an_out_of_gas_refund_is_resent_once_when_the_estimate_is_higher():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.out_of_gas.add(leg.signed[0][0])
    leg.gas_limit, leg.estimate = 50_000, 60_000
    await coord.taker_refund_btc()
    assert leg.refunds == 2


async def test_an_out_of_gas_refund_at_or_above_the_estimate_is_not_resent():
    """The bound on "one re-send": a refund that ran out of gas at a limit the estimate does not
    exceed would fail again. Plant "drop the estimate check" and this loops a refund per call."""
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.out_of_gas.add(leg.signed[0][0])
    leg.gas_limit, leg.estimate = 150_000, 60_000
    with pytest.raises(CounterLegRefundNeedsOperator, match="ran out of gas") as info:
        await coord.taker_refund_btc()
    assert leg.refunds == 1 and info.value.tx_hash == leg.signed[0][0]
    await coord.taker_refund_btc(resend_reverted_refund=True)  # the operator's explicit retry
    assert leg.refunds == 2


# --------------------------------------------------------------------------- scenario 3: payout reverts


@pytest.mark.parametrize("reason", ["TransferFailed", "SendFailed"])
async def test_a_reverted_refund_whose_payout_fails_is_not_resent(reason):
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.reverted.add(leg.signed[0][0])
    leg.revert_reason = reason
    with pytest.raises(CounterLegPayoutReverts, match=reason) as info:
        await coord.taker_refund_btc()
    assert info.value.reason == reason and leg.refunds == 1
    assert coord.record.state is SwapState.BTC_LOCKED
    with pytest.raises(CounterLegPayoutReverts):  # even when the operator asks: it would revert
        await coord.taker_refund_btc(resend_reverted_refund=True)
    assert leg.refunds == 1


async def test_HONEST_once_the_payout_works_again_the_operator_resends_and_it_aborts():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.reverted.add(leg.signed[0][0])
    leg.revert_reason = None  # unfrozen: a refund now would not revert
    with pytest.raises(CounterLegRefundNeedsOperator, match="would not revert"):
        await coord.taker_refund_btc()
    await coord.taker_refund_btc(resend_reverted_refund=True)
    assert leg.refunds == 2
    chain.refund(85, label=refund_label(2))
    assert (await coord.taker_refund_btc()).state is SwapState.ABORTED


async def test_a_reverted_refund_for_an_unrecognised_reason_waits_for_the_operator():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.reverted.add(leg.signed[0][0])
    leg.revert_reason = "unrecognised: 0xdeadbeef"
    with pytest.raises(CounterLegRefundNeedsOperator, match="0xdeadbeef"):
        await coord.taker_refund_btc()
    assert leg.refunds == 1


async def test_a_reverted_refund_beside_a_contract_that_has_since_settled_waits():
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    leg.reverted.add(leg.signed[0][0])
    leg.revert_reason = "AlreadySettled"
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and leg.refunds == 1


def test_the_operator_refusals_are_validation_errors_so_a_driver_stops():
    assert issubclass(CounterLegPayoutReverts, ValidationError)
    assert issubclass(CounterLegRefundNeedsOperator, ValidationError)


# --------------------------------------------------------------------------- the expiry anchor


async def test_the_expiry_anchor_is_persisted_from_a_quorum_f_expired_read():
    coord, chain, _leg = _setup(chain_kw={"finalized": 90})
    rec = await coord.taker_refund_btc()
    assert rec.counter_expiry_anchor == f"90:0x{chain_block_hash(chain, 90)}"
    assert coord.persisted[0].counter_expiry_anchor == rec.counter_expiry_anchor  # durable


async def test_a_third_party_refund_with_no_log_and_no_hash_is_proven_by_the_anchor():
    """§2.3 (a). Plant "do not pass the anchor" and this is UNKNOWN, so the record stays."""
    coord, chain, leg = _setup(endpoints=_logless, chain_kw={"finalized": 90})
    await coord.taker_refund_btc()  # records the anchor (and our refund)
    chain.refund(85, label="someone-else")
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.tx_hash is None
    assert leg.refunds == 1


async def test_an_anchor_no_longer_canonical_is_not_used():
    """Scenario 10: the anchored block was reorged out; the anchor proves nothing."""
    coord, chain, _leg = _setup(endpoints=_logless, chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    coord.record = dataclasses.replace(coord.record, counter_expiry_anchor="90:0x" + "00" * 32)
    chain.refund(85, label="someone-else")
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED


async def test_one_endpoint_on_a_value_bearing_chain_writes_no_anchor(monkeypatch):
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    leg._rpc = FakeEvmEndpoint(chain)
    monkeypatch.setattr(SwapCoordinator, "_single_source_may_decide", staticmethod(lambda _cid: False))
    rec = await coord.taker_refund_btc()
    assert rec.counter_expiry_anchor is None and rec.counter_refund_tx_hash is not None


async def test_HONEST_one_endpoint_on_a_testnet_writes_the_anchor():
    coord, chain, leg = _setup(chain_kw={"finalized": 90})
    leg._rpc = FakeEvmEndpoint(chain)
    assert (await coord.taker_refund_btc()).counter_expiry_anchor is not None


def chain_block_hash(chain, number):
    from tests._fake_evm_chain import _block_hash

    return _block_hash(number).hex()


async def test_the_earlier_hashes_keep_the_oldest_when_they_are_trimmed(monkeypatch):
    """Review round 3 of 5b: trimming to the newest 16 dropped the original refund, the one the node
    still held when no replacement reached it, and it then read as "none of ours"."""
    from pyrxd.gravity.swap_state import MAX_REPLACED_REFUNDS
    from pyrxd.security.errors import NetworkError

    clock = [0.0]
    monkeypatch.setattr(sc, "_monotonic", lambda: clock[0])
    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    first = leg.signed[0][0]
    leg.fail_broadcast = True
    for _ in range(MAX_REPLACED_REFUNDS + 2):
        await coord.taker_refund_btc()  # starts this hash's clock
        clock[0] += REFUND_REPLACE_AFTER_S
        with pytest.raises(NetworkError):
            await coord.taker_refund_btc()  # a replacement priced over `first`, never delivered
    replaced = coord.record.counter_refund_replaced_tx_hashes
    assert len(replaced) == MAX_REPLACED_REFUNDS and replaced[-1] == first
    assert all(r[2].previous_fees == leg.fees[first] for r in leg.signed[1:])  # always over the held one


async def test_an_error_about_an_earlier_refund_names_that_refund():
    from pyrxd.eth_wallet.htlc_leg import RefundProgress

    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    earlier = "0x" + "e0" * 32

    async def earlier_reverted(_h, _n, **_k):
        return RefundProgress("reverted", gas_limit=150_000, tx_hash=earlier)

    leg.refund_progress = earlier_reverted
    leg.revert_reason = "unrecognised: 0xdeadbeef"
    with pytest.raises(CounterLegRefundNeedsOperator) as info:
        await coord.taker_refund_btc()
    assert info.value.tx_hash == earlier and earlier in str(info.value)


# --------------------------------------------------------------------------- Mythos review of #894


async def test_an_earlier_refund_that_mined_is_proven_by_its_hash_when_no_log_is_returned():
    """Mythos review of #894 (F1, MEDIUM): the reader was given only the NEWEST recorded hash, so a
    refund that mined under an EARLIER hash at the same nonce, with no log returned and no anchor,
    read UNKNOWN for ever while the follow path read it "mined" and waited: the record wedged."""
    coord, chain, leg = _setup(endpoints=_logless, chain_kw={"finalized": 90})
    await coord.taker_refund_btc()
    first = leg.signed[0][0]
    leg.dropped.add(first)
    leg.next_nonce = leg.signed[0][1]
    await coord.taker_refund_btc()  # re-sent at the same nonce; `first` is kept as earlier
    assert coord.record.counter_refund_replaced_tx_hashes == (first,)
    leg.dropped.discard(first)
    coord.record = dataclasses.replace(coord.record, counter_expiry_anchor=None)  # the hashes alone
    chain.refund(85, label=refund_label(1))  # the EARLIER one mined
    rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.ABORTED and rec.counter_disposition.tx_hash == first


async def test_a_mined_refund_on_an_unknown_answer_is_followed_not_resent():
    """Mythos review of #894 (F3): the "mined" branch had no test that reaches it (the earlier one is
    stopped by SETTLED_UNFINAL first). On an UNKNOWN answer it is what stops a re-send."""
    from pyrxd.eth_wallet.htlc_leg import RefundProgress

    def throttled(chain):
        return [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]

    coord, _chain, leg = _setup(endpoints=throttled, chain_kw={"finalized": 90})
    await coord.taker_refund_btc()

    async def mined(_h, _n, **_k):
        return RefundProgress("mined", tx_hash=_h)

    leg.refund_progress = mined
    for _ in range(3):
        rec = await coord.taker_refund_btc()
    assert rec.state is SwapState.BTC_LOCKED and leg.refunds == 1


async def test_a_nonce_gap_below_our_refund_asks_the_operator_and_sends_nothing():
    """Mythos review of #894 (F2): `latest < nonce` read as "dropped", so a re-send was signed at the
    GAP nonce and the record forgot the refund still queued at its own."""
    from pyrxd.eth_wallet.htlc_leg import RefundProgress

    coord, _chain, leg = _setup(chain_kw={"finalized": 90})
    await coord.taker_refund_btc()

    async def gap(_h, _n, **_k):
        return RefundProgress("nonce_gap")

    leg.refund_progress = gap
    with pytest.raises(CounterLegRefundNeedsOperator, match="below") as info:
        await coord.taker_refund_btc(resend_reverted_refund=True)
    assert info.value.cause == "other_tx"
    assert leg.refunds == 1

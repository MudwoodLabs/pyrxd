"""The #850 PR 4 disposition reader, against a fake chain read through honest and lying endpoints.

Each disposition and each precedence rule of design §2.3–§2.4 has a case here, and each lying
endpoint the design names (§2.6, §7) has one. Multi-source cases go through the production
``MultiSourceEthRpc``, so the reader is reached the way PR 5a will reach it.

The timeline used throughout: block ``n`` has timestamp ``GENESIS + 12 n``; the timeout is block
80's timestamp, so block 79 is the last block a claim can land in and block 80 the first a refund
can. By default the head is 100 and the finalized block 64 (before the timeout).
"""

from __future__ import annotations

import os

import pytest

from pyrxd.eth_wallet.disposition import DispositionKind, read_counter_disposition, union_logs
from pyrxd.eth_wallet.events import CLAIMED_TOPIC0, REFUNDED_TOPIC0
from pyrxd.eth_wallet.multi_rpc import MultiSourceEthRpc
from pyrxd.security.errors import ValidationError
from tests._fake_evm_chain import OTHER_CONTRACT, FakeEvmChain, FakeEvmEndpoint

TIMEOUT_BLOCK = 80


def _chain(**kw) -> FakeEvmChain:
    c = FakeEvmChain(preimage=os.urandom(32), timeout=0, **kw)
    c.timeout = c.ts(TIMEOUT_BLOCK)
    return c


def _quorum(chain: FakeEvmChain, *endpoints: FakeEvmEndpoint, n: int = 3) -> MultiSourceEthRpc:
    eps = list(endpoints) + [FakeEvmEndpoint(chain) for _ in range(n - len(endpoints))]
    return MultiSourceEthRpc(eps)


async def _read(rpc, chain: FakeEvmChain, **kw):
    return await read_counter_disposition(rpc, chain.locator(), **kw)


# --------------------------------------------------------------------------- not settled


async def test_open_before_the_timeout():
    chain = _chain(head=70, finalized=60)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.OPEN
    assert d.evidence is None and d.finalized_block == 60


async def test_tip_expired_when_only_the_tip_has_passed_the_timeout():
    chain = _chain()
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.TIP_EXPIRED


async def test_tip_expired_uses_the_lowest_tip_a_lagging_endpoint_reports():
    # One endpoint is behind the timeout. MIN tip time: not yet expired.
    chain = _chain(head=TIMEOUT_BLOCK, finalized=60)
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, lag=1)), chain)
    assert d.kind is DispositionKind.OPEN


async def test_f_expired_when_the_finalized_block_has_passed_the_timeout():
    chain = _chain(finalized=90)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.F_EXPIRED


async def test_settled_unfinal_when_settled_above_f():
    chain = _chain()
    chain.refund(95)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.SETTLED_UNFINAL
    assert d.evidence is None


async def test_one_endpoint_seeing_settled_at_its_tip_means_wait():
    chain = _chain()
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, claim_settled_at_tip=True)), chain)
    assert d.kind is DispositionKind.SETTLED_UNFINAL


# --------------------------------------------------------------------------- terminal answers


async def test_refunded_when_a_refund_verifies_at_or_below_f():
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.REFUNDED
    assert d.evidence is not None
    assert d.evidence.tx_hash == tx and d.evidence.block_number == 90
    assert d.evidence.single_source is False and len(d.evidence.sources) == 3


async def test_refunded_at_exactly_f():
    chain = _chain(finalized=90)
    tx = chain.refund(90)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx


async def test_claimed_when_a_claim_verifies_and_f_is_past_the_timeout():
    chain = _chain(finalized=90)
    tx = chain.claim(70)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.CLAIMED and d.evidence.tx_hash == tx
    assert [c.tx_hash for c in d.claims_seen] == [tx] and d.claims_seen[0].verified


async def test_gap_b_claimed_from_invariants_when_every_endpoint_hides_the_claim_log():
    """Settled at F while ``timestamp(F) < timeout``: the contract refuses refund() before the
    timeout, so the settlement was a claim even though no log was ever returned."""
    chain = _chain()
    chain.claim(50)
    eps = [FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.CLAIMED
    assert d.evidence.tx_hash is None
    assert d.claims_seen == ()


async def test_settled_past_the_timeout_with_no_verified_transaction_is_unknown():
    """Settled at F, F past the timeout, and every endpoint hides the claim: either side could have
    settled it, and the refund proofs (a), (b) are not in this PR."""
    chain = _chain(finalized=90)
    chain.claim(70)
    eps = [FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.UNKNOWN


async def test_a_hidden_claim_is_found_through_the_other_endpoints():
    chain = _chain(finalized=90)
    tx = chain.claim(70)
    hider = FakeEvmEndpoint(chain, hide_claimed=True)
    d = await _read(_quorum(chain, hider), chain)
    assert d.kind is DispositionKind.CLAIMED and d.evidence.tx_hash == tx
    assert str(hider.source_key) not in d.claims_seen[0].nominated_by
    assert len(d.claims_seen[0].nominated_by) == 2


async def test_a_recorded_refund_hash_is_verified_beside_a_failed_log_read():
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    eps = [FakeEvmEndpoint(chain, logs_429=True), FakeEvmEndpoint(chain, logs_429=True), FakeEvmEndpoint(chain)]
    # The answering endpoint also returns the log; hide nothing, and the recorded hash agrees.
    d = await _read(MultiSourceEthRpc(eps), chain, recorded_refund_hashes=[tx])
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx
    assert len(d.logs_answered) == 1 and len(d.logs_failed) == 2


async def test_a_union_with_zero_answers_is_unknown_even_with_a_recorded_refund():
    """§2.6: "A union with zero answers is UNKNOWN." Nothing could be nominated, so a public ``p``
    in a claim would go unseen, whatever the recorded hash and the invariants say."""
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    eps = [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain, recorded_refund_hashes=[tx])
    assert d.kind is DispositionKind.UNKNOWN and "no endpoint answered the log scan" in d.reason
    assert d.logs_answered == frozenset() and len(d.logs_failed) == 3


async def test_a_union_with_zero_answers_is_unknown_on_an_unsettled_contract():
    chain = _chain(finalized=90)
    eps = [FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.UNKNOWN


async def test_a_claim_seen_above_f_is_liveness_only():
    chain = _chain(head=79, finalized=60)
    tx = chain.claim(75)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.SETTLED_UNFINAL
    assert [(c.tx_hash, c.verified) for c in d.claims_seen] == [(tx, False)]


# --------------------------------------------------------------------------- what does not verify


async def test_a_forged_refunded_log_with_no_receipt_does_not_refund():
    chain = _chain(finalized=90)
    liar = FakeEvmEndpoint(chain, forge_refunded_tx="0x" + "ee" * 32)
    d = await _read(_quorum(chain, liar), chain)
    assert d.kind is DispositionKind.F_EXPIRED


async def test_a_forged_refunded_log_and_receipt_on_an_unsettled_contract_changes_nothing():
    """Every endpoint agrees the contract is not settled at F, so no refund can have happened at or
    below F: the forged receipt's disagreement does not matter to a non-terminal answer."""
    chain = _chain(finalized=90)
    liar = FakeEvmEndpoint(chain, forge_refunded_tx="0x" + "ee" * 32, forge_receipt=True)
    d = await _read(_quorum(chain, liar), chain)
    assert d.kind is DispositionKind.F_EXPIRED


async def test_a_forged_refund_beside_a_real_claim_is_unknown_not_claimed():
    """The liveness limit in the reader's docstring: one endpoint forging a refund log and its
    receipt disagrees with the others about that receipt, so a settled answer is UNKNOWN."""
    chain = _chain(finalized=90)
    chain.claim(70)
    liar = FakeEvmEndpoint(chain, forge_refunded_tx="0x" + "ee" * 32, forge_receipt=True)
    d = await _read(_quorum(chain, liar), chain)
    assert d.kind is DispositionKind.UNKNOWN and "could not be checked" in d.reason


async def test_a_single_lying_source_cannot_refund_an_unsettled_contract():
    chain = _chain(finalized=90)
    liar = FakeEvmEndpoint(chain, forge_refunded_tx="0x" + "ee" * 32, forge_receipt=True)
    d = await read_counter_disposition(liar, chain.locator())
    assert d.kind is DispositionKind.UNKNOWN  # rule 5: verified at <= F, not settled at F
    assert d.single_source is True


async def test_a_reverted_refund_does_not_verify():
    chain = _chain(finalized=90)
    tx = chain.reverted(85)
    d = await _read(_quorum(chain), chain, recorded_refund_hashes=[tx])
    assert d.kind is DispositionKind.F_EXPIRED


async def test_a_refunded_log_from_another_contract_is_ignored():
    chain = _chain(finalized=90)
    chain.force_receipt(85, topic0=REFUNDED_TOPIC0, address=OTHER_CONTRACT, label="other")
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.F_EXPIRED


async def test_a_claimed_log_that_does_not_open_the_hashlock_is_ignored():
    chain = _chain(finalized=90)
    chain.force_receipt(70, topic0=CLAIMED_TOPIC0, data="0x" + os.urandom(32).hex(), label="wrong-p")
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.F_EXPIRED and d.claims_seen == ()


async def test_a_receipt_in_a_non_canonical_block_does_not_verify():
    chain = _chain(finalized=90)
    tx = chain.force_receipt(85, topic0=REFUNDED_TOPIC0, label="orphan", block_hash=b"\x01" * 32)
    d = await _read(_quorum(chain), chain, recorded_refund_hashes=[tx])
    assert d.kind is DispositionKind.F_EXPIRED


# --------------------------------------------------------------------------- precedence rules


async def test_rule_2_a_verified_refund_and_a_verified_claim_is_unknown():
    chain = _chain(finalized=90)
    chain.claim(70)
    chain.force_receipt(85, topic0=REFUNDED_TOPIC0, label="impossible-refund")
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.UNKNOWN and "rule 2" in d.reason


async def test_rule_3_a_verified_refund_beside_gap_b_is_unknown():
    chain = _chain()
    chain.force_receipt(50, topic0=REFUNDED_TOPIC0, label="early-refund", settles=True)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.UNKNOWN and "rule 3" in d.reason


async def test_rule_4_a_verified_refund_beside_an_unverified_claim_seen_is_refunded():
    """``p`` is public (a dropped claim carried it), and one lying endpoint nominates a
    ``Claimed(p)`` log for a transaction no endpoint has a receipt for. No honest node returns a log
    for an unmined transaction, so this IS a liar, a polite one: its receipt agrees with the others.
    The refund verifies, so REFUNDED, with the claim kept as liveness."""
    chain = _chain(finalized=90)
    refund_tx = chain.refund(85)
    dropped = {
        "address": "0x" + "c0" * 20,
        "topics": [CLAIMED_TOPIC0],
        "data": "0x" + chain.preimage.hex(),
        "transactionHash": "0x" + "dd" * 32,
        "blockNumber": 78,
    }
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, extra_logs=(dropped,))), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == refund_tx
    assert [(c.tx_hash, c.verified, len(c.nominated_by)) for c in d.claims_seen] == [("0x" + "dd" * 32, False, 1)]


async def test_rule_5_a_verified_receipt_while_not_settled_at_f_is_unknown():
    chain = _chain(finalized=90)
    chain.force_receipt(85, topic0=REFUNDED_TOPIC0, label="no-settle")
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.UNKNOWN and "rule 5" in d.reason


# --------------------------------------------------------------------------- failed reads


async def test_endpoints_disagreeing_on_the_finalized_block_hash_is_unknown():
    chain = _chain(finalized=90)
    chain.refund(85)
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, fork="b")), chain)
    assert d.kind is DispositionKind.UNKNOWN


async def test_a_non_archive_single_source_is_unknown_not_unsettled():
    chain = _chain(head=400, finalized=200)
    chain.refund(85)
    d = await read_counter_disposition(FakeEvmEndpoint(chain, archive=False), chain.locator())
    assert d.kind is DispositionKind.UNKNOWN


async def test_a_non_archive_endpoint_inside_a_quorum_is_outvoted_by_absence():
    chain = _chain(head=400, finalized=200)
    tx = chain.refund(85)
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, archive=False)), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx


async def test_a_429_on_logs_is_recorded_as_a_failure_not_as_empty():
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    throttled = FakeEvmEndpoint(chain, logs_429=True)
    d = await _read(_quorum(chain, throttled), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx
    assert str(throttled.source_key) in d.logs_failed
    assert len(d.logs_answered) == 2


async def test_a_range_capped_endpoint_halves_until_it_answers():
    chain = _chain(head=25_000, finalized=24_000)
    chain.timeout = chain.ts(20_000)
    tx = chain.refund(23_000)
    capped = FakeEvmEndpoint(chain, range_cap=3_000)
    u = await union_logs(capped, address=chain.locator().contract_address, topics=[], from_block=0, to_block=25_000)
    assert u.failed == {} and [log["transactionHash"] for log in u.logs] == [tx]
    # It halved (10,000 -> 5,000 -> 2,500) rather than giving up on the first refusal.
    assert (0, 9_999) in capped.log_requests and (0, 2_499) in capped.log_requests


async def test_logs_newer_than_the_agreed_head_are_still_nominated():
    """The agreed head is the MIN; a log in a block only the fresher endpoints have reached is
    still nominated, through the final request to ``latest``."""
    chain = _chain(head=79, finalized=60)
    tx = chain.claim(79)
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, lag=2)), chain)
    assert [c.tx_hash for c in d.claims_seen] == [tx]


async def test_single_source_answers_are_marked_single_source():
    chain = _chain(finalized=90)
    chain.refund(85)
    d = await read_counter_disposition(FakeEvmEndpoint(chain), chain.locator())
    assert d.kind is DispositionKind.REFUNDED
    assert d.single_source is True and d.evidence.single_source is True


# --------------------------------------------------------------------------- the scan's start


async def test_the_scan_starts_at_the_deploy_block_from_its_receipt():
    chain = _chain(finalized=90)
    chain.refund(85)
    ep = FakeEvmEndpoint(chain)
    await read_counter_disposition(ep, chain.locator())
    assert ep.log_requests[0][0] == chain.deploy_block


async def test_an_unknown_deploy_hash_without_from_block_is_unknown():
    from pyrxd.eth_wallet.locator import UNKNOWN_DEPLOY_TX_HASH

    chain = _chain(finalized=90)
    chain.refund(85)
    loc = chain.locator(deploy_tx_hash=UNKNOWN_DEPLOY_TX_HASH)
    d = await read_counter_disposition(FakeEvmEndpoint(chain), loc)
    assert d.kind is DispositionKind.UNKNOWN
    d = await read_counter_disposition(FakeEvmEndpoint(chain), loc, from_block=0)
    assert d.kind is DispositionKind.REFUNDED


@pytest.mark.parametrize(
    "kw",
    [
        {"from_block": -1},
        {"from_block": True},
        {"recorded_refund_hashes": ["0x12"]},
        {"recorded_refund_hashes": [b"\x00" * 32]},
        {"recorded_refund_hashes": ["0x" + "zz" * 32]},
    ],
)
async def test_bad_inputs_are_refused(kw):
    chain = _chain()
    with pytest.raises(ValidationError):
        await read_counter_disposition(FakeEvmEndpoint(chain), chain.locator(), **kw)


async def test_a_locator_is_required():
    chain = _chain()
    with pytest.raises(ValidationError):
        await read_counter_disposition(FakeEvmEndpoint(chain), object())  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the RPC methods


async def test_multi_source_get_logs_union_asks_every_source():
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    throttled = FakeEvmEndpoint(chain, logs_429=True)
    rpc = _quorum(chain, throttled)
    u = await rpc.get_logs_union(address=chain.locator().contract_address, topics=[], from_block=0, to_block=100)
    assert [log["transactionHash"] for log in u.logs] == [tx]
    assert len(u.answered) == 2 and set(u.failed) == {str(throttled.source_key)}
    assert all(ep.log_requests for ep in rpc.sources)


async def test_f_is_the_lowest_finalized_block_any_endpoint_vouches_for():
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    d = await _read(_quorum(chain, FakeEvmEndpoint(chain, lag=12)), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx
    assert d.finalized_block == 88 and d.evidence.block_number == 88


async def test_a_recorded_hash_whose_refunded_event_comes_from_another_contract_does_not_verify():
    chain = _chain(finalized=90)
    tx = chain.force_receipt(85, topic0=REFUNDED_TOPIC0, address=OTHER_CONTRACT, label="other-recorded")
    d = await _read(_quorum(chain), chain, recorded_refund_hashes=[tx])
    assert d.kind is DispositionKind.F_EXPIRED


async def test_a_failed_receipt_does_not_verify_even_if_it_carries_the_event():
    # A real chain drops a reverted transaction's logs; an endpoint is not obliged to.
    chain = _chain(finalized=90)
    tx = chain.force_receipt(85, topic0=REFUNDED_TOPIC0, label="status-0", status=0)
    d = await _read(_quorum(chain), chain, recorded_refund_hashes=[tx])
    assert d.kind is DispositionKind.F_EXPIRED


async def test_rule_4_with_a_liar_that_also_forges_the_claim_receipt_is_unknown():
    """The impolite liar of rule 4: it also forges a receipt for the claim, so the claim cannot be
    checked, and the settled answer is UNKNOWN (the reader's documented liveness limit)."""
    chain = _chain(finalized=90)
    chain.refund(85)
    claim_tx = "0x" + "dd" * 32
    liar = FakeEvmEndpoint(
        chain,
        extra_logs=(
            {
                "address": "0x" + "c0" * 20,
                "topics": [CLAIMED_TOPIC0],
                "data": "0x" + chain.preimage.hex(),
                "transactionHash": claim_tx,
                "blockNumber": 78,
            },
        ),
        forge_refunded_tx=None,
    )

    async def forged_receipt(tx_hash, _orig=liar.get_transaction_receipt):
        if tx_hash == claim_tx:
            return {"status": 1, "blockNumber": 78, "blockHash": liar._hash(78), "logs": []}
        return await _orig(tx_hash)

    liar.get_transaction_receipt = forged_receipt
    d = await _read(_quorum(chain, liar), chain)
    assert d.kind is DispositionKind.UNKNOWN and "could not be checked" in d.reason


async def test_a_failed_tip_read_does_not_block_a_verified_refund():
    """The tip reads are inputs only to the non-terminal answers (rule 7's scope)."""
    chain = _chain(finalized=90)
    tx = chain.refund(85)
    eps = [FakeEvmEndpoint(chain, tip_reads_fail=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx


async def test_a_failed_tip_read_makes_an_unsettled_answer_unknown():
    chain = _chain(finalized=60)
    eps = [FakeEvmEndpoint(chain, tip_reads_fail=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.UNKNOWN


async def test_a_429_is_not_retried_as_a_smaller_range():
    chain = _chain(finalized=90)
    throttled = FakeEvmEndpoint(chain, logs_429=True)
    u = await union_logs(throttled, address=chain.locator().contract_address, topics=[], from_block=0, to_block=100)
    assert set(u.failed) == {str(throttled.source_key)}
    assert len(throttled.log_requests) == 1


async def test_a_source_missing_a_method_fails_as_that_source_only():
    chain = _chain(finalized=90)
    tx = chain.refund(85)

    class _Old(FakeEvmEndpoint):
        block_hash_and_timestamp = None  # an older client without the new read

    d = await _read(_quorum(chain, _Old(chain)), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx


async def test_the_scan_never_asks_past_an_endpoints_own_head():
    chain = _chain(finalized=90)
    eps = [FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lag=3), FakeEvmEndpoint(chain, lag=7)]
    await _read(MultiSourceEthRpc(eps), chain)
    for ep in eps:
        assert ep.log_requests and all(isinstance(t, int) and t <= ep.head for _f, t in ep.log_requests)

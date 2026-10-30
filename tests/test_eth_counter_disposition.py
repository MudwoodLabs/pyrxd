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
from tests._fake_evm_chain import CONTRACT, OTHER_CONTRACT, FakeEvmChain, FakeEvmEndpoint

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


class _LowHead(FakeEvmEndpoint):
    """Reports a head at the deploy block and answers every other read honestly."""

    async def block_number(self) -> int:
        return self.chain.deploy_block


async def test_an_endpoint_reporting_a_low_head_cannot_cut_the_scan_short_of_a_claim():
    """Re-review of #850 PR 7b, MEDIUM: with two endpoints the agreed head is the lower one. One that
    reports the deploy block and hides the Claimed log cut the honest scan to the deploy block plus
    the tail, short of a claim at block 20000, and the read was a settlement nobody could explain.
    The scan now runs through F, so the low endpoint fails its own scan and the honest one sees the
    claim."""
    chain = FakeEvmChain(preimage=os.urandom(32), timeout=0, head=30_100, finalized=30_000)
    chain.timeout = chain.ts(25_000)
    chain.claim(20_000)
    d = await _read(MultiSourceEthRpc([_LowHead(chain, hide_claimed=True), FakeEvmEndpoint(chain)]), chain)
    assert not d.settled_unexplained and d.kind is DispositionKind.CLAIMED
    assert d.logs_failed and len(d.logs_answered) == 1
    honest = await _read(MultiSourceEthRpc([FakeEvmEndpoint(chain), FakeEvmEndpoint(chain)]), chain)
    assert honest.kind is DispositionKind.CLAIMED and not honest.logs_failed


async def test_rule_2_a_verified_refund_and_a_verified_claim_is_unknown():
    chain = _chain(finalized=90)
    chain.claim(70)
    chain.force_receipt(85, topic0=REFUNDED_TOPIC0, label="impossible-refund")
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.UNKNOWN and "rule 2" in d.reason and not d.settled_unexplained


async def test_rule_3_a_verified_refund_beside_gap_b_is_unknown():
    chain = _chain()
    chain.force_receipt(50, topic0=REFUNDED_TOPIC0, label="early-refund", settles=True)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.UNKNOWN and "rule 3" in d.reason and not d.settled_unexplained


async def test_rule_4_a_verified_refund_beside_an_unverified_claim_seen_is_refunded():
    """``p`` is public (a dropped claim carried it), and one lying endpoint nominates a
    ``Claimed(p)`` log for a transaction no endpoint has a receipt for. No honest node returns a log
    for an unmined transaction, so this IS a liar, a polite one: its receipt agrees with the others.
    The refund verifies, so REFUNDED, with the claim kept as liveness."""
    chain = _chain(finalized=90)
    refund_tx = chain.refund(85)
    dropped = {
        "address": CONTRACT,
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


def _with_liar(chain, liar, *, first: bool):
    honest = [FakeEvmEndpoint(chain), FakeEvmEndpoint(chain)]
    return MultiSourceEthRpc([liar, *honest] if first else [*honest, liar])


@pytest.mark.parametrize("first", [True, False], ids=["liar-first", "liar-last"])
async def test_endpoints_disagreeing_on_the_finalized_block_hash_is_unknown(first):
    """Security review: with the liar FIRST only, this passed with the agreement check removed
    (another check happened to refuse); the reason now pins which check refused."""
    chain = _chain(finalized=90)
    chain.refund(85)
    d = await _read(_with_liar(chain, FakeEvmEndpoint(chain, fork="b"), first=first), chain)
    assert d.kind is DispositionKind.UNKNOWN and "block(90): endpoints disagree" in d.reason


@pytest.mark.parametrize("first", [True, False], ids=["liar-first", "liar-last"])
async def test_one_endpoint_lying_that_the_contract_is_settled_at_f_cannot_make_it_claimed(first):
    """Security review MEDIUM: nothing pinned that the endpoints must AGREE on ``settled`` at F.
    Taking one answer let one liar turn an OPEN contract into a terminal CLAIMED via Gap B."""
    chain = _chain()
    d = await _read(_with_liar(chain, FakeEvmEndpoint(chain, lie_settled_at_blocks=True), first=first), chain)
    assert d.kind is DispositionKind.UNKNOWN and "endpoints disagree" in d.reason


@pytest.mark.parametrize("first", [True, False], ids=["liar-first", "liar-last"])
async def test_one_endpoint_lying_about_the_canonical_hash_stops_the_refund_verifying(first):
    chain = _chain(finalized=90)
    chain.refund(85)
    d = await _read(_with_liar(chain, FakeEvmEndpoint(chain, lie_canonical=True), first=first), chain)
    assert d.kind is DispositionKind.UNKNOWN and "canonical_block_hash" in d.reason


# --------------------------------------------------------------------------- exact boundaries


async def test_a_refund_mined_at_the_timeout_block_with_f_there_is_refunded():
    chain = _chain(finalized=TIMEOUT_BLOCK)
    tx = chain.refund(TIMEOUT_BLOCK)
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash == tx


async def test_settled_at_f_exactly_at_the_timeout_with_no_logs_is_unknown_not_gap_b():
    """``timestamp(F) == timeout``: a refund was already possible, so Gap B must not call it a
    claim. With ``<=`` in place of ``<`` this became a terminal CLAIMED."""
    chain = _chain(finalized=TIMEOUT_BLOCK)
    chain.refund(TIMEOUT_BLOCK)
    eps = [FakeEvmEndpoint(chain, hide_all_logs=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.UNKNOWN


async def test_settled_at_f_one_block_before_the_timeout_with_no_logs_is_gap_b():
    chain = _chain(finalized=TIMEOUT_BLOCK - 1)
    chain.claim(TIMEOUT_BLOCK - 1)
    eps = [FakeEvmEndpoint(chain, hide_all_logs=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert d.kind is DispositionKind.CLAIMED and d.evidence.tx_hash is None


async def test_unsettled_with_f_exactly_at_the_timeout_is_f_expired():
    chain = _chain(finalized=TIMEOUT_BLOCK)
    assert (await _read(_quorum(chain), chain)).kind is DispositionKind.F_EXPIRED


async def test_unsettled_with_the_tip_exactly_at_the_timeout_is_tip_expired():
    chain = _chain(head=TIMEOUT_BLOCK, finalized=60)
    assert (await _read(_quorum(chain), chain)).kind is DispositionKind.TIP_EXPIRED


async def test_unsettled_with_the_tip_one_block_before_the_timeout_is_open():
    chain = _chain(head=TIMEOUT_BLOCK - 1, finalized=60)
    assert (await _read(_quorum(chain), chain)).kind is DispositionKind.OPEN


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


async def test_an_endpoint_capped_below_the_floor_fails_after_a_bounded_number_of_requests():
    """Pair of the test above. A 10-block cap (both Blast endpoints, recorded 2026-10-30) halves to
    the floor and then fails that endpoint, instead of scanning 25,000 blocks ten at a time."""
    from pyrxd.eth_wallet.disposition import LOG_CHUNK_BLOCKS, LOG_MIN_CHUNK_BLOCKS

    chain = _chain(head=25_000, finalized=24_000)
    capped = FakeEvmEndpoint(chain, range_cap=10)
    u = await union_logs(capped, address=chain.locator().contract_address, topics=[], from_block=0, to_block=25_000)
    assert str(capped.source_key) in u.failed
    halvings = (LOG_CHUNK_BLOCKS // LOG_MIN_CHUNK_BLOCKS).bit_length()  # 10,000 -> ... -> 1,250
    assert 1 <= len(capped.log_requests) <= halvings
    assert min(hi - lo + 1 for lo, hi in capped.log_requests) >= LOG_MIN_CHUNK_BLOCKS


async def test_logs_newer_than_the_agreed_head_are_still_nominated():
    """The agreed head is the quorum-th highest (here 2 of 3, both 2 blocks behind); a log in a
    block only the freshest endpoint has reached is still nominated, by its scan past the agreed
    head to its own."""
    chain = _chain(head=79, finalized=60)
    tx = chain.claim(79)
    eps = [FakeEvmEndpoint(chain), FakeEvmEndpoint(chain, lag=2), FakeEvmEndpoint(chain, lag=2)]
    d = await _read(MultiSourceEthRpc(eps), chain)
    assert [c.tx_hash for c in d.claims_seen] == [tx]
    assert d.claims_seen[0].nominated_by == (str(eps[0].source_key),)


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


async def test_a_later_transaction_named_as_the_deploy_is_unknown():
    """The scan starts at the deploy transaction's block, so a later transaction named as the deploy
    would start it past a claim. The reader derives the CREATE address from the named transaction's
    sender and nonce, never from a receipt, and a transaction that created nothing is refused."""
    chain = _chain(finalized=90)
    chain.claim(20)
    later = chain.force_receipt(60, topic0=REFUNDED_TOPIC0, address=OTHER_CONTRACT, label="later-call")
    d = await read_counter_disposition(_quorum(chain), chain.locator(deploy_tx_hash=later))
    assert d.kind is DispositionKind.UNKNOWN and "did not create this contract" in d.reason
    d = await _read(_quorum(chain), chain)  # the honest pair: the real deploy reads the claim
    assert d.kind is DispositionKind.CLAIMED


async def test_a_creation_of_another_contract_named_as_the_deploy_is_unknown():
    """A contract creation is not enough: it must be the creation of THIS contract."""
    chain = _chain(finalized=90)
    chain.claim(20)
    chain.deploy_nonce = 1  # the named deploy now creates another address
    d = await _read(_quorum(chain), chain)
    assert d.kind is DispositionKind.UNKNOWN and "did not create this contract" in d.reason


@pytest.mark.parametrize(
    "kw",
    [
        {"from_block": -1},
        {"from_block": True},
        {"recorded_refund_hashes": ["0x12"]},
        {"recorded_refund_hashes": [b"\x00" * 32]},
        {"recorded_refund_hashes": ["0x" + "zz" * 32]},
        {"recorded_refund_hashes": ["0x" + "ab " * 16 + "0" * 16]},
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
                "address": CONTRACT,
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
    d = await _read(MultiSourceEthRpc(eps), chain)
    for ep in eps:
        assert all(isinstance(t, int) and t <= ep.head for _f, t in ep.log_requests)
    # The agreed head is the 2nd highest (quorum 2 of 3): the endpoint 7 blocks behind cannot
    # cover it, so it is recorded as failed rather than as answering a shorter range.
    assert eps[2].log_requests == [] and str(eps[2].source_key) in d.logs_failed
    assert len(d.logs_answered) == 2


class _TinyHead(FakeEvmEndpoint):
    """Honest except that it reports the deploy block as its head."""

    async def block_number(self) -> int:
        return self.chain.deploy_block


async def test_one_endpoint_reporting_a_tiny_head_does_not_blind_the_others():
    """Review round 2: with the MIN head, this one endpoint capped every scan near the deploy
    block, so a later claim was never nominated."""
    chain = _chain(head=30_000, finalized=29_000)
    chain.timeout = chain.ts(20_000)
    tx = chain.claim(15_000)
    liar = _TinyHead(chain)
    d = await _read(_quorum(chain, liar), chain)
    assert d.kind is DispositionKind.CLAIMED and d.evidence.tx_hash == tx
    assert [c.tx_hash for c in d.claims_seen] == [tx]
    assert str(liar.source_key) in d.logs_failed


async def test_a_single_endpoint_whose_head_drops_below_the_range_has_not_answered():
    chain = _chain(finalized=90)
    chain.refund(85)
    ep = FakeEvmEndpoint(chain)
    u = await union_logs(ep, address=chain.locator().contract_address, topics=[], from_block=0, to_block=150)
    assert u.answered == frozenset() and set(u.failed) == {str(ep.source_key)}


@pytest.mark.parametrize(
    ("text", "halves"),
    [
        ("query returned more than 10000 results. Try with this block range [0x1429ab, 0x1450c0].", True),
        ("query exceeds max block range 3000, requested 14290000-14299999", True),
        ("eth_getLogs is limited to a 10,000 range", True),
        ("range is too large, max is 1k blocks", True),
        ("429 Too Many Requests", False),
        ("rate limit reached for this key", False),
        ("connection reset by peer", False),
    ],
)
def test_which_refusals_halve_the_range(text, halves):
    from pyrxd.eth_wallet.disposition import _is_range_limit

    assert _is_range_limit(Exception(text)) is halves


# --------------------------------------------------------------------------- the expiry anchor (#850 PR 5b)


def _anchor(number: int) -> tuple[int, str]:
    from tests._fake_evm_chain import _block_hash

    return number, "0x" + _block_hash(number).hex()


async def test_an_anchor_beside_a_verified_claim_is_unknown_not_refunded():
    """Mythos review of #894 (F3): unpinned. A claim cannot succeed after a canonical unsettled block at
    or past the timeout, so both together mean a lie somewhere; the anchor must not win."""
    chain = _chain(finalized=90)
    chain.force_receipt(
        85, topic0=CLAIMED_TOPIC0, data="0x" + chain.preimage.hex(), label="impossible-claim", settles=True
    )
    d = await _read(_quorum(chain), chain, expiry_anchor=_anchor(82))
    assert d.kind is DispositionKind.UNKNOWN and "claim" in d.reason


async def test_an_anchor_beside_a_finalized_block_before_the_timeout_is_unknown_not_refunded():
    chain = _chain(finalized=70)
    chain.claim(50)
    hidden = [FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(hidden), chain, expiry_anchor=_anchor(65))
    assert d.kind is DispositionKind.UNKNOWN and "before the timeout" in d.reason


async def test_HONEST_without_the_anchor_that_settlement_is_gap_b_claimed():
    chain = _chain(finalized=70)
    chain.claim(50)
    hidden = [FakeEvmEndpoint(chain, hide_claimed=True) for _ in range(3)]
    assert (await _read(MultiSourceEthRpc(hidden), chain)).kind is DispositionKind.CLAIMED


async def test_HONEST_an_anchor_proves_a_refund_with_no_log_and_no_hash():
    chain = _chain(finalized=90)
    chain.refund(85, label="someone")
    logless = [FakeEvmEndpoint(chain, hide_all_logs=True) for _ in range(3)]
    d = await _read(MultiSourceEthRpc(logless), chain, expiry_anchor=_anchor(82))
    assert d.kind is DispositionKind.REFUNDED and d.evidence.tx_hash is None
    assert (await _read(MultiSourceEthRpc(logless), chain)).kind is DispositionKind.UNKNOWN  # without it


@pytest.mark.parametrize("claim", ["verifies", "withheld", "unverifiable"])
async def test_an_uncheckable_settlement_is_tagged_settled_at_f_unless_a_claim_verifies(claim):
    """#850 PR 6: ``settled_at_finalized`` stops the coordinator following a refund of ours that lost
    the race. When a nominated transaction cannot be checked but a claim verifies, the claim is
    surfaced (``claims_seen``) and the tag is clear. When every endpoint withholds the claim, or the
    claim is nominated but its receipt cannot be agreed, only the tag is left."""
    chain = _chain(finalized=90)
    claim_tx = chain.claim(70)
    hide = claim == "withheld"
    liar = FakeEvmEndpoint(chain, forge_refunded_tx="0x" + "ee" * 32, forge_receipt=True, hide_claimed=hide)
    if claim == "unverifiable":

        async def disputed(tx_hash, _orig=liar.get_transaction_receipt):
            r = await _orig(tx_hash)
            return dict(r, blockHash="0x" + "ab" * 32) if tx_hash == claim_tx else r

        liar.get_transaction_receipt = disputed
    rpc = MultiSourceEthRpc(
        [liar, FakeEvmEndpoint(chain, hide_claimed=hide), FakeEvmEndpoint(chain, hide_claimed=hide)]
    )
    d = await _read(rpc, chain)
    assert d.kind is DispositionKind.UNKNOWN and "could not be checked" in d.reason
    assert bool(d.claims_seen) is (claim != "withheld")
    assert any(c.verified for c in d.claims_seen) is (claim == "verifies")
    assert d.settled_at_finalized is (claim != "verifies")


async def test_a_forged_claim_nomination_does_not_clear_the_settled_at_f_tag():
    """Re-review of PR 6: every endpoint withholds the real claim, and one liar nominates a Claimed log
    for a transaction that does not exist. An unverified nomination must not clear the tag, or the
    liar alone turns the coordinator back to following a refund of ours that lost the race."""
    chain = _chain(finalized=90)
    chain.claim(70)
    decoy = {
        "address": CONTRACT,
        "topics": [CLAIMED_TOPIC0],
        "data": "0x" + chain.preimage.hex(),
        "transactionHash": "0x" + "dc" * 32,
        "blockNumber": 72,
    }
    liar = FakeEvmEndpoint(
        chain, forge_refunded_tx="0x" + "ee" * 32, forge_receipt=True, hide_claimed=True, extra_logs=(decoy,)
    )
    rpc = MultiSourceEthRpc(
        [liar, FakeEvmEndpoint(chain, hide_claimed=True), FakeEvmEndpoint(chain, hide_claimed=True)]
    )
    d = await _read(rpc, chain)
    assert d.kind is DispositionKind.UNKNOWN and "could not be checked" in d.reason
    assert d.claims_seen and not any(c.verified for c in d.claims_seen)
    assert d.settled_at_finalized is True


async def test_no_endpoint_answering_the_log_scan_is_never_tagged_settled_at_f():
    chain = _chain(finalized=90)
    chain.claim(70)
    d = await _read(MultiSourceEthRpc([FakeEvmEndpoint(chain, logs_429=True) for _ in range(3)]), chain)
    assert d.kind is DispositionKind.UNKNOWN and d.settled_at_finalized is False

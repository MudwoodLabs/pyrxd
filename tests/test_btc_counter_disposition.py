"""The BTC counter leg's disposition, read from the chain (#850 PR 9a, design §6, §7.1, §7.2 scenario 21).

Through ``tests._fake_btc_chain``: a real Taproot HTLC, real signed claims and refunds, a mempool with
BIP125 replacement, and sources that lag, lie or fail. Each guard here is paired with the honest case
it must still pass.
"""

from __future__ import annotations

import pytest

from pyrxd.btc_wallet import taproot as t
from pyrxd.btc_wallet.disposition import (
    BtcDispositionKind,
    SpendPath,
    read_btc_counter_disposition,
    spend_path_of,
)
from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg
from pyrxd.btc_wallet.payment import BtcUtxo
from pyrxd.network.bitcoin import MultiSourceBtcFundingReader
from pyrxd.security.errors import NetworkError, ValidationError
from tests._fake_btc_chain import CLAIM_SPK, REFUND_SPK, FakeBtcChain, FakeBtcSource, _xonly

BURIAL = 6
K = BtcDispositionKind


async def _read(chain: FakeBtcChain, sources, *, quorum: int = 2, burial: int = BURIAL):
    return await read_btc_counter_disposition(
        sources, chain.locator, hashlock=chain.hashlock, burial_blocks=burial, quorum=quorum
    )


def _panel(chain: FakeBtcChain, n: int = 3, **kw) -> list[FakeBtcSource]:
    return [FakeBtcSource(chain, **kw) for _ in range(n)]


def _witness_swap(raw: bytes, index: int, item: bytes) -> bytes:
    """*raw* with witness item *index* of its only input replaced (same length), signature and all
    left as they are: a transaction no node would accept, which is what a lying source can serve."""
    stack = t._iter_witness_stack(raw)[0]
    old = stack[index]
    assert len(old) == len(item)
    at = raw.rindex(old)
    return raw[:at] + item + raw[at + len(old) :]


# --------------------------------------------------------------------------- classification (M1)


def test_a_real_refund_and_a_real_claim_classify_by_their_leaf():
    chain = FakeBtcChain()
    assert spend_path_of(chain.refund_tx(), chain.locator, chain.hashlock) is SpendPath.REFUND
    assert spend_path_of(chain.claim_tx(), chain.locator, chain.hashlock) is SpendPath.CLAIM


def test_classification_is_by_leaf_not_txid_so_any_refund_of_ours_is_a_refund():
    """The tower's pre-signed refund has another fee, so another txid: still our refund (M1)."""
    chain = FakeBtcChain()
    a, b = chain.refund_tx(fee_sats=500), chain.refund_tx(fee_sats=900)
    assert t.btc_txid_from_raw(a) != t.btc_txid_from_raw(b)
    assert {spend_path_of(x, chain.locator, chain.hashlock) for x in (a, b)} == {SpendPath.REFUND}


def test_a_claim_leaf_spend_without_a_preimage_of_h_is_not_a_claim():
    chain = FakeBtcChain()
    claim = chain.claim_tx()
    assert spend_path_of(claim, chain.locator, chain.hashlock) is SpendPath.CLAIM
    forged = _witness_swap(claim, 1, b"\x00" * 32)  # item 1 is p
    assert spend_path_of(forged, chain.locator, chain.hashlock) is SpendPath.UNRECOGNISED


def test_a_leaf_this_htlc_does_not_have_is_unrecognised():
    chain = FakeBtcChain()
    refund = chain.refund_tx()
    script = t._iter_witness_stack(refund)[0][1]
    forged = _witness_swap(refund, 1, bytes([script[0] ^ 1]) + script[1:])
    assert spend_path_of(forged, chain.locator, chain.hashlock) is SpendPath.UNRECOGNISED


def test_a_transaction_that_does_not_spend_the_outpoint_is_refused():
    chain, other = FakeBtcChain(), FakeBtcChain()
    with pytest.raises(ValidationError, match="does not spend"):
        spend_path_of(other.refund_tx(), chain.locator, chain.hashlock)


# --------------------------------------------------------------------------- unspent


async def test_unspent_at_every_source_reads_unspent():
    chain = FakeBtcChain()
    d = await _read(chain, _panel(chain))
    assert d.kind is K.UNSPENT and d.spenders == () and not d.single_source


async def test_one_source_down_still_reads_unspent_at_quorum():
    chain = FakeBtcChain()
    d = await _read(chain, [*_panel(chain, 2), FakeBtcSource(chain, down=True)])
    assert d.kind is K.UNSPENT and len(d.failed) == 1


async def test_a_source_that_cannot_answer_is_never_a_vote_for_unspent():
    chain = FakeBtcChain()
    d = await _read(chain, [FakeBtcSource(chain), FakeBtcSource(chain, down=True), FakeBtcSource(chain, down=True)])
    assert d.kind is K.UNKNOWN and "below the quorum" in d.reason


async def test_a_reader_without_the_spender_read_answers_unknown_not_unspent():
    chain = FakeBtcChain()
    d = await _read(chain, [FakeBtcSource(chain, no_spender_read=True)], quorum=1)
    assert d.kind is K.UNKNOWN and d.single_source


async def test_a_served_spender_of_another_outpoint_counts_as_a_failure():
    chain, other = FakeBtcChain(), FakeBtcChain()
    liar = FakeBtcSource(chain, forge_spender=other.refund_tx())
    d = await _read(chain, [*_panel(chain, 2), liar])
    assert d.kind is K.UNSPENT
    assert any("does not spend" in why for _src, why in d.failed)
    d = await _read(chain, [FakeBtcSource(chain), liar])
    assert d.kind is K.UNKNOWN


# --------------------------------------------------------------------------- refund: pending until buried


async def test_a_refund_is_pending_in_the_mempool_and_when_shallow_and_refunded_only_at_burial():
    chain = FakeBtcChain()
    refund = chain.refund_tx()
    txid = chain.submit(refund)
    sources = _panel(chain)
    d = await _read(chain, sources)
    assert d.kind is K.REFUND_PENDING and d.refunds_seen[0].txid == txid and d.evidence is None
    chain.mine(BURIAL - 1)
    d = await _read(chain, sources)
    assert d.kind is K.REFUND_PENDING and d.refunds_seen[0].confirmations == BURIAL - 1
    chain.mine()
    d = await _read(chain, sources)
    assert d.kind is K.REFUNDED
    assert d.evidence is not None
    assert (d.evidence.txid, d.evidence.confirmations) == (txid, BURIAL)
    assert d.evidence.block_hash == chain.block_hash(d.evidence.block_number)
    assert d.evidence.sources == tuple(str(s.source_key) for s in sources)


async def test_one_source_seeing_the_spender_is_enough_to_nominate_it():
    """Discovery is broad (§6): two sources with no mempool view must not outvote the one that sees
    our refund in its mempool into "unspent" (which would have us build a second refund)."""
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    d = await _read(chain, [FakeBtcSource(chain), *_panel(chain, 2, sees_mempool=False)])
    assert d.kind is K.REFUND_PENDING and len(d.refunds_seen[0].nominated_by) == 1


async def test_a_source_hiding_a_buried_claim_does_not_hide_it():
    chain = FakeBtcChain()
    chain.submit(chain.claim_tx())
    chain.mine(BURIAL)
    d = await _read(chain, [FakeBtcSource(chain, hide_spender=True), *_panel(chain, 2)])
    assert d.kind is K.CLAIMED


async def test_depth_is_the_quorum_minimum_so_one_over_reporting_source_cannot_bury_a_spend():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(2)
    d = await _read(chain, [FakeBtcSource(chain, lie_depth=100), *_panel(chain, 2)])
    assert d.kind is K.REFUND_PENDING and d.refunds_seen[0].confirmations == 2
    # ...and the honest twin: every source agreeing on the depth buries it.
    chain.mine(BURIAL)
    assert (await _read(chain, _panel(chain))).kind is K.REFUNDED


async def test_a_lagging_source_holds_the_depth_down():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    d = await _read(chain, [FakeBtcSource(chain, lag=3), *_panel(chain, 2)])
    assert d.kind is K.REFUND_PENDING and d.refunds_seen[0].confirmations == BURIAL - 3


async def test_depth_below_the_quorum_of_answers_is_not_a_depth():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    sources = [FakeBtcSource(chain), FakeBtcSource(chain), FakeBtcSource(chain)]
    sources[1].down = True
    sources[2].down = True
    d = await _read(chain, sources)
    assert d.kind is K.REFUND_PENDING and d.refunds_seen[0].confirmations is None


async def test_sources_that_place_the_spender_in_different_blocks_are_not_evidence():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    d = await _read(chain, [FakeBtcSource(chain, lie_block=(chain.head, "ee" * 32)), *_panel(chain, 2)])
    assert d.kind is K.REFUND_PENDING and d.refunds_seen[0].block is None


async def test_single_source_is_reported_as_such():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    d = await _read(chain, [FakeBtcSource(chain)], quorum=1)
    assert d.kind is K.REFUNDED and d.single_source and d.evidence is not None and d.evidence.single_source


async def test_a_reorg_returns_a_buried_refund_to_pending_or_to_unspent():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    sources = _panel(chain)
    assert (await _read(chain, sources)).kind is K.REFUNDED
    chain.reorg(BURIAL)
    assert (await _read(chain, sources)).kind is K.REFUND_PENDING  # back in the mempool
    chain.drop()
    assert (await _read(chain, sources)).kind is K.UNSPENT  # dropped: nothing spends it now


# --------------------------------------------------------------------------- claims (scenario 21)


async def test_a_refund_replaced_by_a_claim_is_claim_seen_then_claimed_at_burial():
    """Design §7.2 scenario 21: our refund in the mempool, the maker's claim replaces it (BIP125:
    the refund signals by its CSV nSequence). CLAIM_SEEN changes nothing; buried, it is CLAIMED, and
    the claim's bytes give p."""
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx(fee_sats=500))
    claim_txid = chain.submit(chain.claim_tx(fee_sats=2_000))
    sources = _panel(chain)
    d = await _read(chain, sources)
    assert d.kind is K.CLAIM_SEEN and d.evidence is None
    assert [s.txid for s in d.claims_seen] == [claim_txid]
    assert t.scrape_secret(d.claims_seen[0].raw, chain.hashlock) == chain.preimage
    chain.mine(BURIAL)
    d = await _read(chain, sources)
    assert d.kind is K.CLAIMED and d.evidence is not None and d.evidence.txid == claim_txid


async def test_a_claim_seen_at_one_source_beside_a_refund_at_another_is_claim_seen():
    """Mid-replacement the sources' mempools differ. ``p`` is public wherever the claim is."""
    chain = FakeBtcChain()
    refund, claim = chain.refund_tx(), chain.claim_tx(fee_sats=2_000)
    chain.submit(refund)
    d = await _read(chain, [*_panel(chain, 2), FakeBtcSource(chain, forge_spender=claim)])
    assert d.kind is K.CLAIM_SEEN
    assert {s.path for s in d.spenders} == {SpendPath.CLAIM, SpendPath.REFUND}


async def test_a_buried_refund_beside_a_claim_seen_elsewhere_is_refunded_and_keeps_the_claim():
    """§2.4 rule 4 on BTC: the state follows the buried refund; the claim stays visible (D14)."""
    chain = FakeBtcChain()
    claim = chain.claim_tx(fee_sats=2_000)
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    d = await _read(chain, [*_panel(chain, 2), FakeBtcSource(chain, forge_spender=claim)])
    assert d.kind is K.REFUNDED and len(d.claims_seen) == 1


async def test_two_spenders_both_reported_buried_is_unknown():
    chain = FakeBtcChain()
    chain.submit(chain.claim_tx(fee_sats=2_000))
    chain.mine(BURIAL)
    block = (chain.head - BURIAL + 1, chain.block_hash(chain.head - BURIAL + 1))
    forged = chain.refund_tx()
    liars = [FakeBtcSource(chain, forge_spender=forged, lie_depth=50, lie_block=block) for _ in range(2)]
    d = await _read(chain, liars)
    assert d.kind is K.REFUNDED  # the liars agree with each other on the refund only...
    d = await _read(chain, [*liars, FakeBtcSource(chain, lie_depth=50, lie_block=block)])
    assert d.kind is K.UNKNOWN and "contradict" in d.reason  # ...until a source names the claim too
    d = await _read(chain, [*liars, FakeBtcSource(chain)])
    assert d.kind is K.CLAIMED  # an honest third source: its depth of 0 for the forged refund wins (MIN)


async def test_an_unrecognised_spender_is_unknown():
    chain = FakeBtcChain()
    forged = _witness_swap(chain.claim_tx(), 1, b"\x00" * 32)
    d = await _read(chain, [*_panel(chain, 2), FakeBtcSource(chain, forge_spender=forged)])
    assert d.kind is K.UNKNOWN and "neither the claim leaf" in d.reason


async def test_the_reader_refuses_a_bad_quorum_or_burial():
    chain = FakeBtcChain()
    with pytest.raises(ValidationError, match="quorum"):
        await _read(chain, _panel(chain, 2), quorum=3)
    with pytest.raises(ValidationError, match="burial"):
        await _read(chain, _panel(chain), burial=0)
    one = FakeBtcSource(chain)
    with pytest.raises(ValidationError):
        await _read(chain, [one, one])  # one source counted twice


# --------------------------------------------------------------------------- the fake's own rules


def test_the_fake_applies_bip125_and_csv_maturity():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx(fee_sats=500))
    with pytest.raises(NetworkError, match="insufficient fee"):
        chain.submit(chain.refund_tx(fee_sats=520))  # not 1 sat/vB of its own size above
    chain.submit(chain.refund_tx(fee_sats=900))  # the RBF bump
    chain.mine()
    with pytest.raises(NetworkError, match="spent"):
        chain.submit(chain.claim_tx(fee_sats=5_000))  # a mined spend is not replaceable
    young = FakeBtcChain(head=150, funding_height=150)
    with pytest.raises(NetworkError, match="non-BIP68-final"):
        young.submit(young.refund_tx())
    young.submit(young.claim_tx())  # the claim leaf has no timelock


# --------------------------------------------------------------------------- through the leg


def _leg(chain: FakeBtcChain, reader) -> BitcoinTaprootLeg:
    return BitcoinTaprootLeg(
        network="bcrt",
        taker_keypair=chain.taker,
        funding_utxo=BtcUtxo(txid="ab" * 32, vout=0, value=200_000),
        maker_claim_pubkey_xonly=_xonly(chain.maker),
        broadcaster=FakeBtcSource(chain),
        funding_reader=reader,
        refund_to_scriptpubkey=REFUND_SPK,
        claim_to_scriptpubkey=CLAIM_SPK,
        fee_sats=500,
        min_confirmations=1,
    )


async def test_the_leg_reads_each_source_of_a_quorum_reader_at_its_quorum():
    chain = FakeBtcChain()
    chain.submit(chain.refund_tx())
    chain.mine(BURIAL)
    sources = [FakeBtcSource(chain), FakeBtcSource(chain), FakeBtcSource(chain, lag=4)]
    leg = _leg(chain, MultiSourceBtcFundingReader(sources, quorum=2))
    d = await leg.counter_disposition(chain.locator, hashlock=chain.hashlock, burial_blocks=BURIAL)
    assert d.kind is K.REFUND_PENDING and not d.single_source  # the lagging source holds it down
    assert d.sources == tuple(str(s.source_key) for s in sources)


async def test_the_leg_on_one_reader_is_single_source():
    chain = FakeBtcChain()
    leg = _leg(chain, FakeBtcSource(chain))
    d = await leg.counter_disposition(chain.locator, hashlock=chain.hashlock, burial_blocks=BURIAL)
    assert d.kind is K.UNSPENT and d.single_source

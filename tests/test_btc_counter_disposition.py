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
    spend_signature_verifies,
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
    assert any("as the spender, but it does not spend" in why for _src, why in d.failed)
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
    # An honest third source has never seen the liars' refund (its depth read fails, as an Esplora 404
    # does), so the liars still make a quorum on it; but it names the buried claim, and two buried
    # spenders are never a terminal answer.
    d = await _read(chain, [*liars, FakeBtcSource(chain)])
    assert d.kind is K.UNKNOWN and len(d.claims_seen) == 1


async def test_an_unrecognised_spender_counts_as_a_failed_source():
    """A spend through no leaf of this HTLC cannot be on chain: the source serving it failed, and it
    neither blocks "unspent" nor hides a real claim (review of PR 9a, H2 and M1)."""
    chain = FakeBtcChain()
    forged = _witness_swap(chain.claim_tx(), 1, b"\x00" * 32)
    junk = FakeBtcSource(chain, forge_spender=forged)
    d = await _read(chain, [*_panel(chain, 2), junk])
    assert d.kind is K.UNSPENT and any("neither the claim leaf" in why for _s, why in d.failed)
    chain.submit(chain.claim_tx())
    d = await _read(chain, [junk, *_panel(chain, 2)])
    assert d.kind is K.CLAIM_SEEN and len(d.claims_seen) == 1


# --------------------------------------------------------------------------- forged witnesses (review H1, H2)


def _with_witness_of(base: bytes, donor: bytes) -> bytes:
    """*base*'s stripped bytes (so its txid) with *donor*'s witness: what a lying source can serve."""
    bw = t._serialize_witness(t._iter_witness_stack(base)[0])
    dw = t._serialize_witness(t._iter_witness_stack(donor)[0])
    assert base[-4 - len(bw) : -4] == bw
    out = base[: -4 - len(bw)] + dw + base[-4:]
    assert t.btc_txid_from_raw(out) == t.btc_txid_from_raw(base)
    return out


def test_signatures_verify_for_real_spends_and_not_for_a_swapped_witness():
    chain = FakeBtcChain()
    claim, refund = chain.claim_tx(), chain.refund_tx()
    assert spend_signature_verifies(claim, chain.locator) is True
    assert spend_signature_verifies(refund, chain.locator) is True
    assert spend_signature_verifies(_with_witness_of(claim, refund), chain.locator) is False
    assert spend_signature_verifies(_witness_swap(refund, 0, b"\x01" * 64), chain.locator) is False


@pytest.mark.parametrize("hostile_first", [True, False])
async def test_a_buried_claim_served_with_a_refund_witness_stays_claimed(hostile_first):
    """Review H1: the txid binds only the stripped bytes. A source serving the real claim's txid with
    a refund-leaf witness (public script and control block, a made-up signature) turned a buried
    CLAIM into REFUNDED and hid p, whenever it came first. Its signature does not verify, so it fails."""
    chain = FakeBtcChain()
    claim = chain.claim_tx(fee_sats=2_000)
    chain.submit(claim)
    chain.mine(BURIAL)
    liar = FakeBtcSource(chain, forge_spender=_with_witness_of(claim, chain.refund_tx()))
    sources = [liar, *_panel(chain, 2)] if hostile_first else [*_panel(chain, 2), liar]
    d = await _read(chain, sources)
    assert d.kind is K.CLAIMED and len(d.claims_seen) == 1
    assert any("does not verify" in why for _s, why in d.failed)


async def test_a_made_up_refund_cannot_hold_off_unspent():
    """Review H2: a refund-leaf spend no source but one has, with a made-up signature, read
    REFUND_PENDING ("wait") beside two sources saying unspent, so no refund would ever be sent."""
    chain = FakeBtcChain()
    made_up = _witness_swap(chain.refund_tx(fee_sats=777), 0, b"\x02" * 64)
    d = await _read(chain, [FakeBtcSource(chain, forge_spender=made_up), *_panel(chain, 2)])
    assert d.kind is K.UNSPENT and len(d.unspent_by) == 2
    # ...while a real refund of ours that only one source holds still nominates (it is ours, and real).
    d = await _read(chain, [FakeBtcSource(chain, forge_spender=chain.refund_tx()), *_panel(chain, 2)])
    assert d.kind is K.REFUND_PENDING and len(d.unspent_by) == 2


async def test_a_claim_whose_signature_does_not_verify_is_liveness_never_terminal():
    """Only a holder of p can write a claim witness, so it is kept (p is public), but a made-up
    signature never makes it CLAIMED."""
    chain = FakeBtcChain()
    claim_witness = _with_witness_of(chain.refund_tx(), chain.claim_tx())  # a refund's txid, a claim's witness
    assert spend_signature_verifies(claim_witness, chain.locator) is False
    chain.submit(claim_witness)  # the fake does not check signatures: a forged spend, buried
    chain.mine(BURIAL)
    d = await _read(chain, _panel(chain))
    assert d.kind is K.CLAIM_SEEN and not d.claims_seen[0].verified
    assert t.scrape_secret(d.claims_seen[0].raw, chain.hashlock) == chain.preimage


async def test_an_unverified_claim_witness_over_our_buried_refund_cannot_hold_it_off():
    """Re-review N1: once p is public, anyone can write a claim witness over our buried refund's
    txid. Read as "two leaves for one txid", one such source held the refund at UNKNOWN for ever,
    with no key. A verified refund beats claims that do not verify; each is kept as liveness."""
    chain = FakeBtcChain()
    refund = chain.refund_tx()
    chain.submit(refund)
    chain.mine(BURIAL)
    claim_witness = _with_witness_of(refund, chain.claim_tx())
    for sources in (
        [FakeBtcSource(chain, forge_spender=claim_witness), *_panel(chain, 2)],
        [*_panel(chain, 2), FakeBtcSource(chain, forge_spender=claim_witness)],
    ):
        d = await _read(chain, sources)
        assert d.kind is K.REFUNDED and d.evidence is not None
        assert d.evidence.txid == t.btc_txid_from_raw(refund)
        assert len(d.claims_seen) == 1 and not d.claims_seen[0].verified
        assert t.scrape_secret(d.claims_seen[0].raw, chain.hashlock) == chain.preimage
    # ...while an honest panel alone carries no claim.
    d = await _read(chain, _panel(chain))
    assert d.kind is K.REFUNDED and d.claims_seen == ()


def _claim_signed_over(chain: FakeBtcChain, refund: bytes) -> bytes:
    """A claim the maker really signs over *refund*'s stripped bytes (its nSequence and output), so
    the same txid with a claim witness that verifies: both leaves signed for one transaction."""
    fields = t.btc_spend_fields_from_raw(refund)
    ((amount, spk),) = fields.outputs
    out = t._build_spend_tx(
        locator=chain.locator,
        witness_items_after_sig=[chain.preimage],
        sign_privkey=chain.maker._privkey.unsafe_raw_bytes(),
        leaf="claim",
        to_scriptpubkey=spk,
        out_amount_sats=amount,
        nsequence=fields.input_sequences[0],
        locktime=0,
        aux_rand=t.fresh_aux_rand(),
    )
    assert t.btc_txid_from_raw(out) == t.btc_txid_from_raw(refund)
    return out


async def test_both_leaves_signed_for_one_buried_txid_is_unknown():
    """With both signatures valid, which witness is on chain is not known from the txid: UNKNOWN,
    and the claim is kept. The honest twin above: a refund alone reads REFUNDED."""
    chain = FakeBtcChain()
    refund = chain.refund_tx()
    chain.submit(refund)
    chain.mine(BURIAL)
    claim = _claim_signed_over(chain, refund)
    assert spend_signature_verifies(claim, chain.locator) is True
    d = await _read(chain, [FakeBtcSource(chain, forge_spender=claim), *_panel(chain, 2)])
    assert d.kind is K.UNKNOWN and "different leaves" in d.reason
    assert len(d.claims_seen) == 1 and d.claims_seen[0].contested and d.claims_seen[0].verified


@pytest.mark.parametrize("hash_type", [0x00, 0x04, 0x41, 0x80, 0x84])
def test_a_65_byte_signature_with_a_hash_type_bip341_does_not_define_fails(hash_type):
    """Re-review N2: BIP341 defines 0x01-0x03 and 0x81-0x83 for a 65-byte signature, and 0x00 only
    as the 64-byte form. Any other byte is an invalid signature."""
    chain = FakeBtcChain()
    refund = chain.refund_tx()
    sig = t._iter_witness_stack(refund)[0][0]
    assert len(sig) == 64
    bw = t._serialize_witness(t._iter_witness_stack(refund)[0])
    stack = list(t._iter_witness_stack(refund)[0])
    stack[0] = sig + bytes([hash_type])
    forged = refund[: -4 - len(bw)] + t._serialize_witness(stack) + refund[-4:]
    assert spend_signature_verifies(forged, chain.locator) is False


def test_an_anyonecanpay_spend_with_other_inputs_is_checked_and_a_plain_one_is_not():
    """Re-review N3: a SIGHASH_ALL|ANYONECANPAY signature commits to our input alone, so a spender
    with more inputs is still checked; under SIGHASH_DEFAULT it commits to every spent output, and
    only ours is known here, so it is ``None`` (unchecked), never ``True``."""
    chain = FakeBtcChain()
    signed = {}
    for hash_type in (t.SIGHASH_DEFAULT, 0x81):
        one = t._build_spend_tx(
            locator=chain.locator,
            witness_items_after_sig=[],
            sign_privkey=chain.taker._privkey.unsafe_raw_bytes(),
            leaf="refund",
            to_scriptpubkey=REFUND_SPK,
            out_amount_sats=99_000,
            nsequence=chain.timeout.to_nsequence(),
            locktime=0,
            aux_rand=t.fresh_aux_rand(),
            hash_type=hash_type,
        )
        signed[hash_type] = one
    assert spend_signature_verifies(signed[0x81], chain.locator) is True
    assert spend_signature_verifies(signed[t.SIGHASH_DEFAULT], chain.locator) is True
    other = bytes(36)  # a second input before ours, empty witness
    for hash_type, one in signed.items():
        two = _with_extra_input_first(one, other)
        expected = True if hash_type == 0x81 else None
        assert spend_signature_verifies(two, chain.locator) is expected


def _with_extra_input_first(raw: bytes, prevout: bytes) -> bytes:
    """*raw* (one input, segwit) with a second input *prevout* put first, given an empty witness.
    The first signature was made over one input, so only ANYONECANPAY still verifies."""
    assert raw[4:6] == b"\x00\x01" and raw[6] == 1
    body = raw[7:]
    in0 = body[:41]  # 36-byte prevout, empty scriptSig, 4-byte sequence
    assert in0[36] == 0
    rest = body[41:]
    stack = t._iter_witness_stack(raw)[0]
    w = t._serialize_witness(stack)
    outs = rest[: len(rest) - len(w) - 4]
    extra = prevout + b"\x00" + b"\xff\xff\xff\xff"
    return raw[:6] + b"\x02" + extra + in0 + outs + b"\x00" + w + raw[-4:]


async def test_a_malformed_hashlock_is_refused_before_anything_is_read():
    chain = FakeBtcChain()
    with pytest.raises(ValidationError, match="hashlock"):
        await read_btc_counter_disposition(_panel(chain), chain.locator, hashlock=b"x", burial_blocks=6, quorum=2)


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

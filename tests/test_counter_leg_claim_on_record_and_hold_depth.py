"""Two coordinator inputs one source must not choose (0.27 release review, B-1 and B-2).

* B-2: the ``Claimed(p)`` the record keeps as ``counter_claim_tx``. The reader lists claims by hash and
  the first was recorded, so once p was public one endpoint's log on a transaction nobody holds could
  be the claim on record when its hash sorted first.
* B-1: the covenant age that lifts the D14 hold. It was one Radiant server's depth, so one server
  over-reporting it ended a record while p was public and the covenant was still claimable.

Each refusal has its honest twin.
"""

from __future__ import annotations

import asyncio

import pytest

from pyrxd.eth_wallet.events import CLAIMED_TOPIC0
from pyrxd.gravity.radiant_leg import RadiantChainIO
from pyrxd.gravity.swap_state import SwapState
from tests._fake_evm_chain import CONTRACT, FakeEvmEndpoint
from tests._source_hosts import distinct_host
from tests.test_counter_leg_disposition_coordinator import _setup, _with_a_dropped_claim

GHOST = "0x" + "00" * 32  # sorts before any real hash


def _ghost_log(chain):
    return {
        "address": CONTRACT,
        "topics": [CLAIMED_TOPIC0],
        "data": "0x" + chain.preimage.hex(),
        "transactionHash": GHOST,
        "blockNumber": 71,
    }


def _one_ghost(chain):
    return [FakeEvmEndpoint(chain, extra_logs=(_ghost_log(chain),)), FakeEvmEndpoint(chain), FakeEvmEndpoint(chain)]


# --------------------------------------------------------------------------- B-2


@pytest.mark.parametrize("finalized", [90, 60])
async def test_a_ghost_claim_that_sorts_first_is_not_the_claim_on_record(finalized):
    """The maker's claim is mined at block 70 and every endpoint serves it; one endpoint also serves a
    ``Claimed(p)`` on a transaction no endpoint holds, whose hash sorts first. Final (the claim
    verifies) or not yet (neither verifies, the real one has three nominations), the record names the
    real claim."""
    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, endpoints=_one_ghost, chain_kw={"finalized": finalized})
    tx = chain.claim(70)
    assert tx > GHOST
    rec = await coord.reconcile_counter_leg()
    assert rec.state is (SwapState.SECRET_REVEALED if finalized >= 70 else SwapState.BOTH_LOCKED)
    assert coord.record.counter_claim_tx == tx, coord.record.counter_claim_tx


async def test_HONEST_a_lone_seen_claim_is_still_recorded():
    """The D14 path unchanged: a ``Claimed(p)`` only one endpoint serves, with nothing else seen, is the
    claim on record (p is public wherever it is)."""
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90}, confs=1)
    chain.refund(85)
    rec = await coord.reconcile_counter_leg()
    assert rec.counter_claim_tx == "0x" + "dd" * 32


# --------------------------------------------------------------------------- B-1


class _HoldIO:
    """The Radiant reader the hold asks: the primary's depth, and each operator's."""

    def __init__(self, primary, operators):
        self.primary = primary
        self.operators = operators

    async def confirmations(self, txid):
        return self.primary

    async def funding_tx_depths(self, txid):
        return tuple((f"op{i}", d) for i, d in enumerate(self.operators))


def _held_setup(primary, operators):
    coord, chain, _leg = _setup(endpoints=_with_a_dropped_claim, chain_kw={"finalized": 90})
    coord.radiant_leg.chain_io = _HoldIO(primary, operators)
    chain.refund(85)
    return coord, int(coord.record.terms.t_rxd.value)


@pytest.mark.parametrize("liar_at", [0, 1])
async def test_one_over_reporting_server_does_not_lift_the_d14_hold(liar_at):
    coord, t_rxd = _held_setup(0, ())
    honest = t_rxd - 5
    depths = [honest, honest]
    depths[liar_at] = t_rxd + 1000
    coord.radiant_leg.chain_io = _HoldIO(depths[0], (depths[0], depths[1]))
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.BTC_LOCKED and rec.counter_claim_tx is not None


async def test_HONEST_every_operator_past_t_rxd_lifts_the_hold():
    coord, t_rxd = _held_setup(0, ())
    coord.radiant_leg.chain_io = _HoldIO(t_rxd, (t_rxd, t_rxd + 2))
    assert (await coord.reconcile_counter_leg()).state is SwapState.ABORTED


async def test_HONEST_with_no_other_operator_answering_the_primary_decides():
    """A source that does not answer is left out: the hold is no less live than before."""
    coord, t_rxd = _held_setup(0, ())
    coord.radiant_leg.chain_io = _HoldIO(t_rxd, ())
    assert (await coord.reconcile_counter_leg()).state is SwapState.ABORTED


class _Server:
    def __init__(self, confs, *, txid_named=True, fails=False):
        self.confs = confs
        self.txid_named = txid_named
        self.fails = fails
        self.source_key = distinct_host()
        self.tip_reads = 0

    async def get_transaction_verbose(self, txid):
        if self.fails:
            raise ConnectionError("down")
        return {"txid": txid if self.txid_named else "ef" * 32, "confirmations": self.confs}

    async def get_tip_height(self):
        self.tip_reads += 1
        return 10**6

    async def broadcast(self, raw):
        raise AssertionError("no broadcast here")

    async def get_utxos(self, spk):
        return []


def test_funding_tx_depths_reports_each_operator_and_leaves_out_the_rest():
    primary, other, wrong, down, unmined = (
        _Server(40),
        _Server(3),
        _Server(900, txid_named=False),
        _Server(900, fails=True),
        _Server(0),
    )
    io = RadiantChainIO(primary, depth_sources=(other, wrong, down, unmined))
    got = asyncio.run(io.funding_tx_depths("ab" * 32))
    # A 0 that names the transaction is an answer (the deepest under-report an honest operator gives,
    # re-review F-4); a failure and a reply about another transaction are not.
    assert sorted(d for _op, d in got) == [0, 3, 40]
    assert len({op for op, _d in got}) == 3
    assert all(s.tip_reads == 0 for s in (primary, other, wrong, down, unmined))  # no tip or header reads


async def test_an_operator_reporting_the_funding_unconfirmed_keeps_the_d14_hold():
    """Re-review of the B-1 fix, F-4: the primary over-reports the covenant funding's depth past t_rxd
    and the one other operator, honest, reports it unconfirmed (0). Through the real reader that 0 is an
    answer, so the lowest depth keeps the hold."""
    coord, t_rxd = _held_setup(0, ())
    coord.radiant_leg.chain_io = RadiantChainIO(_Server(t_rxd + 1000), depth_sources=(_Server(0),))
    rec = await coord.reconcile_counter_leg()
    assert rec.state is SwapState.BTC_LOCKED and rec.counter_claim_tx is not None


async def test_HONEST_through_the_real_reader_every_operator_past_t_rxd_lifts_the_hold():
    coord, t_rxd = _held_setup(0, ())
    coord.radiant_leg.chain_io = RadiantChainIO(_Server(t_rxd + 5), depth_sources=(_Server(t_rxd + 1),))
    assert (await coord.reconcile_counter_leg()).state is SwapState.ABORTED


async def test_a_variant_of_the_real_claims_log_does_not_cut_its_nominations():
    """Re-review of the B-2 fix: one endpoint serves the ghost and the real claim's log at another block
    number. The reader counts every endpoint that served any variant of a transaction's log, so the
    real claim keeps its three nominations and is still the claim on record."""
    made: list[FakeEvmEndpoint] = []

    def endpoints(chain):
        made.extend(FakeEvmEndpoint(chain) for _ in range(3))
        return made

    coord, chain, _leg = _setup(state=SwapState.BOTH_LOCKED, endpoints=endpoints, chain_kw={"finalized": 60})
    tx = chain.claim(70)
    variant = {**_ghost_log(chain), "transactionHash": tx, "blockNumber": 69}
    made[0].extra_logs = (_ghost_log(chain), variant)
    await coord.reconcile_counter_leg()
    assert coord.record.counter_claim_tx == tx, coord.record.counter_claim_tx


def test_the_btc_claim_on_record_is_chosen_the_same_way():
    """The BTC twin of B-2: a claim-leaf spend one source serves whose signature does not verify, with a
    low txid, beside the real claim the others serve."""
    from pyrxd.btc_wallet.disposition import BtcSpender, SpendPath
    from pyrxd.gravity.swap_coordinator import _claim_to_record

    def spender(txid, by, verified):
        return BtcSpender(
            txid=txid, path=SpendPath.CLAIM, raw=b"", nominated_by=by, confirmations=None, block=None, verified=verified
        )

    real, ghost = "ab" * 32, "00" * 32
    assert _claim_to_record([spender(ghost, ("a",), False), spender(real, ("a", "b", "c"), True)]).txid == real
    assert _claim_to_record([spender(ghost, ("a",), False), spender(real, ("b", "c"), False)]).txid == real
    # A verified claim outranks any number of nominations of one that does not verify.
    assert _claim_to_record([spender(ghost, ("a", "b", "c"), False), spender(real, ("a",), True)]).txid == real
    # Honest twin: a lone claim is recorded whatever its hash.
    assert _claim_to_record([spender(ghost, ("a",), False)]).txid == ghost


def test_two_sources_tied_on_unverified_claims_are_logged(caplog):
    """Re-review of the B-2 fix, F-3: with two sources, a real claim and a ghost each nominated once and
    neither verified cannot be told apart; the record takes the hash order and says so in the log."""
    from pyrxd.btc_wallet.disposition import BtcSpender, SpendPath
    from pyrxd.gravity.swap_coordinator import _claim_to_record

    def spender(txid, by, verified):
        return BtcSpender(
            txid=txid, path=SpendPath.CLAIM, raw=b"", nominated_by=by, confirmations=None, block=None, verified=verified
        )

    real, ghost = "ab" * 32, "00" * 32
    with caplog.at_level("WARNING", logger="pyrxd.gravity.swap_coordinator"):
        assert _claim_to_record([spender(ghost, ("a",), False), spender(real, ("b",), False)]).txid == ghost
    assert any("equal evidence" in r.getMessage() and ghost in r.getMessage() for r in caplog.records)
    caplog.clear()
    # Honest twins: a nomination lead, or a verified claim, is no tie and logs nothing.
    with caplog.at_level("WARNING", logger="pyrxd.gravity.swap_coordinator"):
        assert _claim_to_record([spender(ghost, ("a",), False), spender(real, ("b", "c"), False)]).txid == real
        assert _claim_to_record([spender(ghost, ("a",), True), spender(real, ("b",), True)]).txid == ghost
    assert not any("equal evidence" in r.getMessage() for r in caplog.records)


async def test_a_btc_claim_one_source_forges_is_not_the_claim_on_record(tmp_path):
    """The BTC twin through the coordinator: the maker's real claim is in the mempool and every source
    serves it, except one, which serves a claim-leaf spend carrying p whose signature does not verify
    (signed by a key that is not the maker's), with a lower txid. The record names the real claim."""
    from pyrxd.btc_wallet import taproot as t
    from pyrxd.btc_wallet.keys import generate_keypair
    from tests._fake_btc_chain import CLAIM_SPK
    from tests.test_btc_counter_refund_coordinator import _Swap

    s = _Swap(tmp_path)
    real = s.chain.claim_tx(fee_sats=2_000)
    real_txid = t.btc_txid_from_raw(real)
    stranger = generate_keypair("bcrt")
    for fee in range(600, 900):
        forged = t.build_claim_tx(
            locator=s.chain.locator,
            preimage=s.chain.preimage,
            claim_privkey=stranger._privkey.unsafe_raw_bytes(),
            to_scriptpubkey=CLAIM_SPK,
            fee_sats=fee,
            aux_rand=t.fresh_aux_rand(),
        )
        if t.btc_txid_from_raw(forged) < real_txid:
            break
    else:
        pytest.fail("no forged claim with a lower txid in 300 tries")
    s.chain.submit(real)
    s.sources[0].forge_spender = forged
    rec = await s.coord().taker_refund_btc()
    assert rec.counter_claim_tx == real_txid, rec.counter_claim_tx

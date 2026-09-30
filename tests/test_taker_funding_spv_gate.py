"""The swap TAKER GATE: the maker's Radiant funding is PROVED before the taker locks anything.

Before this gate the taker read the maker's covenant — script, value, depth — from ONE ElectrumX
server's ``listunspent`` and verbose ``confirmations``. A fake server that invented the covenant
drove the real ``SwapCoordinator`` and the real ``RadiantCovenantLeg`` to lock a counter leg against
an output on no chain. That proof is ported here (section a) and now REFUSES.

What each section pins:

(a) the lying server, through the real websocket client, leg and coordinator — refused; and a
    server that fabricates a COMPLETE, self-consistent proof on the value-bearing network is refused
    too, because its headers cannot link to the checkpoints pyrxd ships;
(b) the honest path locks: a synthetic regtest chain through the real leg, a value-bearing chain
    through the real leg, and REAL mainnet headers and transaction (recorded fixture) at the gate;
(c) the settled rule ``k = max(6, burial, ceil(2 × value ÷ C))``, each term at its boundary, the
    subsidy schedule, and the freshness-cap refusal;
(d) every path that calls a counter leg's ``fund`` crosses the gate — the set of call sites is
    DERIVED from the source, with a non-vacuity assertion, and each coordinator entry point that
    reaches one is driven with a refused funding;
(e) a refusal names ``k``, the value, ``C`` and what was proved;
(f) steps 6 and 7 judge the timelocks on the elapsed-depth UPPER bound, not the proved lower bound.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

import pytest
import websockets

from pyrxd.btc_wallet.htlc_leg import BitcoinTaprootLeg, BtcUtxo, FundingPolicy
from pyrxd.btc_wallet.keys import generate_keypair
from pyrxd.gravity import funding_spv
from pyrxd.gravity.funding_spv import (
    FORGERY_COST_FACTOR,
    MAX_HEADERS_FROM_CHECKPOINT_SDK,
    MIN_FUNDING_CONFIRMATIONS,
    MakerFundingNotVerified,
    RadiantChain,
    block_subsidy_photons,
    funding_header_ranges,
    radiant_chain_for_leg,
    required_funding_confirmations,
    verify_maker_funding,
)
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.gravity.radiant_leg import RadiantChainIO, RadiantCovenantLeg
from pyrxd.gravity.reorg_cost import PHOTONS_PER_RXD
from pyrxd.gravity.swap_coordinator import CoordinatorConfig, MarginPolicy, SwapCoordinator
from pyrxd.gravity.swap_state import NegotiatedTerms, SwapRecord, SwapState
from pyrxd.hash import radiant_block_hash
from pyrxd.network.electrumx import ElectrumXClient, UtxoRecord
from pyrxd.security.errors import NetworkError, ValidationError
from pyrxd.spv.radiant import radiant_header_work
from pyrxd.transaction.transaction import Transaction
from tests import test_taker_asset_funding_gate_adversarial as A
from tests._funding_chain import build_funding_chain, mine, regtest_genesis_header
from tests.test_swap_coordinator import (
    _NOW,
    FakeBtcLeg,
    FakeEthLeg,
    FakeIndexer,
    FakeRadiantLeg,
    FakeSeenStore,
    _coordinator,
    _eth_coord_full,
    _eth_terms,
    _final,
    _MemLock,
    _terms,
)

ROOT = Path(__file__).resolve().parent.parent

#: A difficulty for value-bearing synthetic chains: about 2^9 hash attempts per header, so a floor
#: (checkpoint work ÷ 16) above zero and a nonzero C, while a few hundred headers mine in a second.
_HARD_BITS = 0x1F7FFFFF


# --------------------------------------------------------------------------- shared helpers


def _covenant(terms: NegotiatedTerms) -> bytes:
    return build_htlc_covenant_rxd(
        amount=terms.radiant_amount,
        taker_pkh=A._TAKER_PKH,
        maker_pkh=A._MAKER_PKH,
        hashlock=terms.hashlock,
        refund_csv=terms.t_rxd.value,
    ).funded_spk


def _value_bearing_chain(monkeypatch) -> tuple[dict[int, bytes], RadiantChain]:
    """A value-bearing chain the tests can mine: regtest genesis, then headers 1..4 at _HARD_BITS,
    with checkpoints at 0, 2 and 4 — installed as the chain every value-bearing leg resolves to.
    Mainnet's own subsidy schedule; the proof-of-work limit is regtest's so the genesis decodes."""
    base = build_funding_chain(spk=b"\x51", value=1, confs=4, bits=_HARD_BITS).headers
    chain = RadiantChain(
        name="mainnet",
        checkpoints=(
            (0, radiant_block_hash(base[0])),
            (2, radiant_block_hash(base[2])),
            (4, radiant_block_hash(base[4])),
        ),
        pow_limit=(1 << 255) - 1,
        subsidy_halving_interval=210_000,
        value_bearing=True,
    )
    monkeypatch.setattr(funding_spv, "MAINNET_CHAIN", chain)
    return base, chain


#: The measured Radiant fast tail (p10) the value-bearing tests use; the nominal stays 300 s.
_FAST_S = 36.0


def _vb_policy(**over) -> MarginPolicy:
    """An estimated dust-grade policy carrying the measured fast tail a value-bearing gate requires."""
    base = MarginPolicy.estimated(accept_flat_burial=True)
    return type(base)(**{**base.__dict__, "rxd_block_interval_fast_s": _FAST_S, **over})


class _ChainView:
    """An ElectrumX-shaped Radiant server over a synthetic chain it serves honestly — unless told
    to lie: ``listed_spk`` makes ``listunspent`` claim an output for a script the raw transaction
    does not pay (``pays`` is what it really pays)."""

    def __init__(
        self,
        *,
        pays: bytes,
        value: int,
        confs: int,
        base=None,
        bits=0x207FFFFF,
        tip_time=None,
        listed_spk=None,
        listed_value=None,
    ):
        kw = {} if tip_time is None else {"tip_time": tip_time}
        self.chain = build_funding_chain(spk=pays, value=value, confs=confs, base=base, bits=bits, **kw)
        self.listed_spk = listed_spk if listed_spk is not None else pays
        self.value = value if listed_value is None else listed_value
        self.confs = confs
        self.reads: list[str] = []

    async def get_utxos(self, script_hash):
        self.reads.append("listunspent")
        if bytes(script_hash) != hashlib.sha256(self.listed_spk).digest()[::-1]:
            return []
        return [UtxoRecord(tx_hash=self.chain.txid, tx_pos=0, value=self.value, height=self.chain.height)]

    async def get_transaction_verbose(self, txid):
        return {"txid": txid, "confirmations": self.confs}

    async def get_transaction(self, txid):
        self.reads.append("raw")
        return self.chain.raw_tx

    async def get_transaction_merkle_branch(self, txid, height):
        return dict(self.chain.merkle)

    async def get_transaction_id_from_pos(self, height, pos):
        return dict(self.chain.coinbase_merkle)

    async def get_block_headers(self, start, count):
        self.reads.append("headers")
        return [self.chain.headers[h] for h in range(start, start + count) if h in self.chain.headers]

    async def broadcast(self, raw_tx):  # pragma: no cover - the taker never spends here
        raise AssertionError("no Radiant broadcast in this phase")


def _real_leg(view, *, network: str, min_confirmations: int = 1) -> RadiantCovenantLeg:
    return RadiantCovenantLeg(
        network=network,
        taker_pkh=A._TAKER_PKH,
        maker_pkh=A._MAKER_PKH,
        chain_io=RadiantChainIO(view),
        fee_source=A._FeeSource(),
        min_confirmations=min_confirmations,
    )


def _btc_coord(terms, radiant_leg, *, policy=None, btc_view=None, **config):
    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    del maker_kp
    btc_view = btc_view or A._BtcChainView()
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=A._taker_btc_leg(terms=terms, taker_kp=taker_kp, btc_view=btc_view),
        radiant_leg=radiant_leg,
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=policy or MarginPolicy.estimated(), **config),
    )
    return coord, btc_view


def _ab_terms(t_rxd_blocks: int = 400) -> NegotiatedTerms:
    maker_kp, taker_kp = generate_keypair("bcrt"), generate_keypair("bcrt")
    return A._terms(maker_kp=maker_kp, taker_kp=taker_kp, t_rxd_blocks=t_rxd_blocks)


# --------------------------------------------------------------------------- (a) the lying server


async def test_a_lying_electrumx_that_invents_the_covenant_can_no_longer_make_the_taker_lock():
    """PORTED from the proof of the defect. A real websocket JSON-RPC server answers exactly what
    the old gate read — ``listunspent`` inventing the covenant UTXO, and a verbose ``confirmations``
    of 6 — and nothing else. The REAL client, leg and coordinator used to lock the taker's BTC; the
    gate now asks for the proof, the server cannot give one, and NOTHING is broadcast."""
    fake_txid = os.urandom(32).hex()  # a covenant funding tx that exists nowhere
    log: list[str] = []

    async def fake_electrumx(ws):
        async for msg in ws:
            req = json.loads(msg)
            method, params = req["method"], req["params"]
            log.append(method)
            if method == "blockchain.scripthash.listunspent":
                res = [{"tx_hash": fake_txid, "tx_pos": 0, "value": A._RXD_AMOUNT, "height": 100}]
            elif method == "blockchain.transaction.get":
                res = {"txid": params[0], "confirmations": 6}
            else:
                await ws.send(json.dumps({"id": req["id"], "error": {"code": -32601, "message": "nope"}}))
                continue
            await ws.send(json.dumps({"id": req["id"], "result": res}))

    server = await websockets.serve(fake_electrumx, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        terms = _ab_terms(90)
        client = ElectrumXClient(urls=[f"ws://127.0.0.1:{port}"], allow_insecure=True)
        leg = _real_leg(RadiantChainIO(client)._client, network="bcrt")
        coord, btc_view = _btc_coord(terms, leg)

        gate = await coord.pre_btc_lock_check(terms)
        assert gate.ok is False, "the gate passed on a covenant that exists on no chain"
        assert "not verified" in gate.reason
        with pytest.raises((ValidationError, NetworkError)):
            await coord.taker_funds_btc(terms)
        assert btc_view.broadcasts == [], "BTC was locked against an invented covenant"
        assert coord.record.state is SwapState.NEGOTIATED
        # The gate asked for the PROOF, not only the two reads the old gate trusted.
        assert "blockchain.scripthash.listunspent" in log and "blockchain.transaction.get" in log
        await client.close()
    finally:
        server.close()
        await server.wait_closed()


async def test_a_complete_self_consistent_forged_proof_is_refused_on_the_value_bearing_network():
    """The stronger liar: it serves a raw transaction that REALLY pays the covenant for the right
    value, a merkle branch that really leads to its header, and a whole chain of headers for every
    range asked. It cannot serve headers that hash to pyrxd's shipped mainnet checkpoints, so the
    proof is CONTRADICTED and the lock refused."""
    terms = _ab_terms(400)
    spk = _covenant(terms)
    # A whole chain from the height of the second-newest shipped checkpoint to 16 blocks past the
    # newest, every header meeting its own target, the funding 5 blocks past the newest checkpoint.
    table = funding_spv.MAINNET_CHAIN.checkpoints
    offset = table[-2][0]
    span = table[-1][0] - offset
    forged = build_funding_chain(spk=spk, value=terms.radiant_amount, confs=12, funding_height=span + 5)
    headers = {h + offset: b for h, b in forged.headers.items()}

    class _Liar(_ChainView):
        def __init__(self):
            self.chain = forged
            self.listed_spk = spk
            self.value = terms.radiant_amount
            self.confs = 12
            self.reads = []

        async def get_utxos(self, script_hash):
            return [UtxoRecord(tx_hash=forged.txid, tx_pos=0, value=self.value, height=forged.height + offset)]

        async def get_transaction_merkle_branch(self, txid, height):
            return {**forged.merkle, "block_height": height}

        async def get_block_headers(self, start, count):
            return [headers[h] for h in range(start, start + count) if h in headers]

    leg = _real_leg(_Liar(), network="bc")
    coord, btc_view = _btc_coord(terms, leg, policy=_vb_policy(), accept_nondurable_seen=True)
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "did not verify (CONTRADICTED" in gate.reason, gate.reason
    assert "not pyrxd's checkpoint" in gate.reason
    assert btc_view.broadcasts == []


async def test_listunspent_naming_the_covenant_for_a_tx_that_pays_another_script_is_refused():
    """The script and value come from the transaction's own bytes, never from ``listunspent``. The
    server lists the covenant; the (real, mined, provable) transaction pays something else."""
    terms = _ab_terms(90)
    other = b"\x76\xa9\x14" + os.urandom(20) + b"\x88\xac"
    view = _ChainView(pays=other, value=terms.radiant_amount, confs=6, listed_spk=_covenant(terms))
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bcrt"))
    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok is False
    assert "does not pay the covenant scriptPubKey" in gate.reason
    with pytest.raises(ValidationError):
        await coord.taker_funds_btc(terms)
    assert btc_view.broadcasts == []


async def test_listunspent_quoting_the_negotiated_value_for_a_tx_that_pays_less_is_refused():
    """The value too: ``listunspent`` says the negotiated amount, the transaction's own output
    carries one photon less. The raw bytes decide."""
    terms = _ab_terms(90)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount - 1, confs=6, listed_value=terms.radiant_amount)
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bcrt"))
    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok is False
    assert f"carries {terms.radiant_amount - 1} photons, not the negotiated {terms.radiant_amount}" in gate.reason
    assert btc_view.broadcasts == []


async def test_regtest_runs_the_real_verifier_a_header_failing_its_own_pow_refuses():
    """No regtest bypass: the same linkage and proof-of-work code runs against regtest's genesis. A
    header whose hash is above its own target (nonce bumped until it is) is CONTRADICTED."""
    terms = _ab_terms(90)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6)
    h = view.chain.height + 2
    hdr = bytearray(view.chain.headers[h])
    target = 0x7FFFFF << (8 * (0x20 - 3))
    for nonce in range(1, 10_000):
        hdr[76:80] = nonce.to_bytes(4, "little")
        if int(radiant_block_hash(bytes(hdr)), 16) > target:
            break
    view.chain.headers[h] = bytes(hdr)
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bcrt"))
    gate = await coord.pre_btc_lock_check(terms)
    assert gate.ok is False
    assert "CONTRADICTED" in gate.reason
    assert btc_view.broadcasts == []


# --------------------------------------------------------------------------- (b) the honest path


async def test_honest_regtest_funding_verifies_and_the_lock_proceeds():
    terms = _ab_terms(90)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6)
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bcrt"))
    rec = await coord.taker_funds_btc(terms)
    assert rec.state is SwapState.BTC_LOCKED
    assert len(btc_view.broadcasts) == 1
    proof = coord.last_maker_funding
    assert proof is not None and proof.proved_depth == 6 and proof.required_confirmations == 1
    assert "headers" in view.reads and "raw" in view.reads, "the proof was fetched, not assumed"


async def test_honest_value_bearing_funding_verifies_and_the_lock_proceeds(monkeypatch):
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _ab_terms(400)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
    coord, _btc_view = _btc_coord(
        terms,
        _real_leg(view, network="bc"),
        policy=_vb_policy(),
        accept_nondurable_seen=True,
    )
    rec = await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert rec.state is SwapState.BTC_LOCKED
    proof = coord.last_maker_funding
    assert proof.required_confirmations == MIN_FUNDING_CONFIRMATIONS
    assert proof.forged_confirmation_cost_photons > 0
    assert proof.value_at_stake_photons == terms.radiant_amount


async def test_a_value_bearing_gate_without_a_measured_fast_tail_refuses_before_fetching(monkeypatch):
    """The allowance for blocks mined since the reference header divides elapsed time by an interval;
    on a value-bearing network that must be the MEASURED fast tail, never the nominal fallback. With
    none set the gate refuses, and nothing is fetched."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _ab_terms(400)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
    coord, btc_view = _btc_coord(
        terms,
        _real_leg(view, network="bc"),
        policy=MarginPolicy.estimated(accept_flat_burial=True),
        accept_nondurable_seen=True,
    )
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "needs MarginPolicy.rxd_block_interval_fast_s" in gate.reason, gate.reason
    assert view.reads == [], "the gate fetched evidence it could not judge"
    assert btc_view.broadcasts == []


async def test_the_allowance_divides_by_the_measured_fast_tail_not_the_nominal_interval(monkeypatch):
    """One hour since the reference header, a 36 s fast tail and a 300 s nominal: the allowance is
    100 blocks, not 12. Swapping the nominal interval in at the gate fails here."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _ab_terms(400)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW - 3600
    )
    coord, _btc_view = _btc_coord(
        terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True
    )
    assert coord.config.margin_policy.rxd_block_interval_s == 300.0
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    proof = coord.last_maker_funding
    assert proof.withheld_allowance_blocks == 100
    assert proof.elapsed_blocks_upper >= proof.proved_depth + 100 - 1


def test_real_mainnet_headers_and_transaction_verify_at_the_gate():
    """REAL data: the recorded mainnet block 460,572 transaction, its merkle and coinbase branches
    and headers 460,564..460,580 (``tests/fixtures/mark_block_fixtures_2026-09-30.json``), judged
    by the gate's own code at mainnet's proof-of-work limit and subsidy schedule. The checkpoint
    table is built from two of those real headers (the fixture does not span the shipped table's
    last interval); C is then recomputed here independently from the same headers."""
    from tests.test_mark_block_verification import MARKS

    m = MARKS["reference_460572"]
    tx = Transaction.from_hex(m.raw_tx)
    out = tx.outputs[0]
    chain = RadiantChain(
        name="mainnet",
        checkpoints=(
            (460_564, radiant_block_hash(m.headers[460_564])),
            (460_566, radiant_block_hash(m.headers[460_566])),
        ),
        pow_limit=funding_spv.MAINNET_CHAIN.pow_limit,
        subsidy_halving_interval=210_000,
        value_bearing=True,
    )
    from pyrxd.gravity.funding_spv import MakerFundingEvidence

    ev = MakerFundingEvidence(
        txid=m.txid,
        vout=0,
        height=m.height,
        raw_tx=m.raw_tx,
        merkle=m.merkle,
        coinbase_merkle=m.coinbase,
        headers=m.headers,
    )
    subsidy = block_subsidy_photons(460_572, chain)
    assert subsidy == 12_500 * PHOTONS_PER_RXD
    floor = radiant_header_work(m.headers[460_566], pow_limit=chain.pow_limit) // 16
    max_work = max(radiant_header_work(m.headers[h], pow_limit=chain.pow_limit) for h in range(460_564, 460_581))
    cost = subsidy * floor // max_work
    value = 2 * cost  # value term ceil(2 × 2C ÷ C) = 4 → k = 6
    common = dict(
        chain=chain,
        expected_spk=out.locking_script.serialize(),
        expected_value=out.satoshis,
        burial_blocks=6,
        now_unix_s=int.from_bytes(m.headers[460_580][68:72], "little"),
        withheld_block_interval_s=36.0,
    )
    r = verify_maker_funding(ev, value_at_stake_photons=value, **common)
    assert r.proved_depth == 9 and r.required_confirmations == 6
    assert r.forged_confirmation_cost_photons == cost and r.max_header_work == max_work
    # Nine proved blocks cover a value up to 4.5 C; one photon over that needs ten.
    with pytest.raises(MakerFundingNotVerified, match=r"proved only 9 block\(s\) deep; wait for 1 more"):
        verify_maker_funding(ev, value_at_stake_photons=9 * cost // 2 + 1, **common)


# --------------------------------------------------------------------------- (c) the rule


def test_the_subsidy_schedule_matches_radiant_core():
    m = funding_spv.MAINNET_CHAIN
    assert block_subsidy_photons(0, m) == 50_000 * PHOTONS_PER_RXD
    assert block_subsidy_photons(209_999, m) == 50_000 * PHOTONS_PER_RXD
    assert block_subsidy_photons(210_000, m) == 25_000 * PHOTONS_PER_RXD
    assert block_subsidy_photons(420_000, m) == 12_500 * PHOTONS_PER_RXD
    assert block_subsidy_photons(468_000, m) == 12_500 * PHOTONS_PER_RXD
    assert block_subsidy_photons(64 * 210_000, m) == 0
    assert block_subsidy_photons(151, funding_spv.REGTEST_CHAIN) == 25_000 * PHOTONS_PER_RXD


def test_chain_constants_are_derived_from_the_vendored_radiant_core_sources():
    """The subsidy schedule, proof-of-work limits and regtest genesis are READ from the vendored
    ``chainparams.cpp`` / ``validation.cpp`` here, not restated — so a re-pin that moves one fails."""
    import re

    vendor = ROOT / "tests" / "vendor" / "radiant_core"
    params = (vendor / "chainparams.cpp").read_text()
    validation = (vendor / "validation.cpp").read_text()

    def block(cls: str) -> str:
        start = params.index(f"class {cls} ")
        return params[start : params.index("\nclass ", start + 1) if "\nclass " in params[start + 1 :] else None]

    for cls, chain in (("CMainParams", funding_spv.MAINNET_CHAIN), ("CRegTestParams", funding_spv.REGTEST_CHAIN)):
        body = block(cls)
        halving = int(re.search(r"nSubsidyHalvingInterval = (\d+);", body).group(1))
        pow_limit = int(re.search(r'powLimit = uint256S\(\s*"([0-9a-f]{64})"\)', body).group(1), 16)
        genesis = re.search(r'hashGenesisBlock ==\s*uint256S\("([0-9a-f]{64})"\)', body).group(1)
        assert (halving, pow_limit) == (chain.subsidy_halving_interval, chain.pow_limit), cls
        assert chain.checkpoints[0] == (0, genesis), cls
    subsidy = re.search(r"GetBlockSubsidy\(int nHeight.*?nSubsidy = (\d+) \* COIN;", validation, re.S)
    assert int(subsidy.group(1)) * PHOTONS_PER_RXD == funding_spv.INITIAL_SUBSIDY_PHOTONS
    assert radiant_block_hash(regtest_genesis_header()) == funding_spv.REGTEST_CHAIN.checkpoints[0][1]


@pytest.mark.parametrize(
    ("burial", "value", "cost", "k", "term"),
    [
        (1, 1, 100, 6, 1),  # the floor of 6
        (5, 250, 100, 6, 5),  # value term 5 < 6
        (6, 300, 100, 6, 6),  # value term exactly 6
        (6, 301, 100, 7, 7),  # one photon over the boundary rounds UP
        (7, 300, 100, 7, 6),  # burial dominates
        (6, 350, 100, 7, 7),
        (2, 10_000 * PHOTONS_PER_RXD, 764 * PHOTONS_PER_RXD, 27, 27),  # the maintainer's example
        (2, 100_000 * PHOTONS_PER_RXD, 764 * PHOTONS_PER_RXD, 262, 262),  # the maintainer's example
    ],
)
def test_k_is_the_max_of_its_three_terms(burial, value, cost, k, term):
    assert required_funding_confirmations(
        value_bearing=True, burial_blocks=burial, value_at_stake_photons=value, forged_confirmation_cost_photons=cost
    ) == (k, term)
    assert FORGERY_COST_FACTOR == 2 and MIN_FUNDING_CONFIRMATIONS == 6


def test_a_value_bearing_swap_with_nothing_to_size_k_from_refuses():
    with pytest.raises(MakerFundingNotVerified, match="no value at stake"):
        required_funding_confirmations(
            value_bearing=True, burial_blocks=6, value_at_stake_photons=None, forged_confirmation_cost_photons=100
        )
    with pytest.raises(MakerFundingNotVerified, match="prices at 0 photons"):
        required_funding_confirmations(
            value_bearing=True, burial_blocks=6, value_at_stake_photons=10, forged_confirmation_cost_photons=0
        )
    # A test network has no value term and no floor of 6: its configured depth stands.
    assert required_funding_confirmations(
        value_bearing=False, burial_blocks=2, value_at_stake_photons=None, forged_confirmation_cost_photons=0
    ) == (2, 0)


class _Leg:
    def __init__(self, network=None, chain_id=None):
        if network is not None:
            self.network = network
        if chain_id is not None:
            self.chain_id = chain_id


def test_the_value_bearing_network_is_mainnet_and_has_no_opt_out():
    for tag in ("bc", "rxd", "mainnet", "anything-not-cleared"):
        for counter in (_Leg("bcrt"), _Leg("bc"), object()):
            assert radiant_chain_for_leg(_Leg(tag), counter_leg=counter).value_bearing is True
            assert (
                radiant_chain_for_leg(_Leg(tag), counter_leg=counter).checkpoints == funding_spv.CHECKPOINTS["mainnet"]
            )
    assert radiant_chain_for_leg(_Leg("bcrt"), counter_leg=_Leg("bcrt")) is funding_spv.REGTEST_CHAIN
    assert radiant_chain_for_leg(object(), counter_leg=object()) is funding_spv.REGTEST_CHAIN
    with pytest.raises(MakerFundingNotVerified, match="no Radiant chain parameters"):
        radiant_chain_for_leg(_Leg("tb"), counter_leg=_Leg("tb"))


@pytest.mark.parametrize("rxd_leg", [_Leg("bcrt"), _Leg("regtest"), _Leg(""), object()])
@pytest.mark.parametrize(
    "counter",
    [
        _Leg("bc"),
        _Leg("anything-not-cleared"),
        _Leg("mainnet", chain_id=1),
        _Leg("anvil", chain_id=8453),  # Base: the chain id decides, not the tag
        _Leg("sepolia", chain_id=137),  # a chain id pyrxd does not know counts as value-bearing
    ],
)
def test_a_value_bearing_counter_leg_never_selects_the_test_chain(rxd_leg, counter):
    """A swap that locks real value on the counter leg is never proved against a test chain, whatever
    the Radiant leg is tagged: the configuration is refused, with the reason."""
    with pytest.raises(MakerFundingNotVerified, match="the counter leg moves real value .* test network"):
        radiant_chain_for_leg(rxd_leg, counter_leg=counter)


@pytest.mark.parametrize(
    "counter",
    [
        _Leg("bcrt"),
        _Leg("tb"),
        _Leg("signet"),
        object(),
        _Leg("anvil", chain_id=31337),
        _Leg("mainnet", chain_id=11155111),
    ],
)
def test_test_counter_legs_with_a_regtest_radiant_leg_still_select_regtest(counter):
    """The honest test configuration — both legs on test networks — keeps working."""
    assert radiant_chain_for_leg(_Leg("bcrt"), counter_leg=counter) is funding_spv.REGTEST_CHAIN


def test_the_eth_leg_exposes_the_chain_id_it_signs_for():
    """The chain-id half of the rule reads ``EthLeg.chain_id``; without it an EVM leg would fall back
    to its tag, which cannot say whether the chain carries value."""
    from pyrxd.gravity.eth_leg import EthLeg

    class _Inner:
        chain_id = 1

    leg = EthLeg.__new__(EthLeg)
    leg._leg = _Inner()
    assert leg.chain_id == 1


@pytest.mark.parametrize("rxd_tag", ["bcrt", ""])
async def test_a_mainnet_btc_counter_leg_with_a_regtest_radiant_leg_is_refused(rxd_tag):
    """A real ``BitcoinTaprootLeg`` on mainnet (``"bc"``) beside a Radiant leg tagged regtest (or
    untagged), over a server serving a complete regtest chain for the funding. The gate refuses the
    configuration; nothing is broadcast."""
    terms = _ab_terms(400)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6)
    btc_view = A._BtcChainView()
    btc_leg = BitcoinTaprootLeg(
        network="bc",
        taker_keypair=generate_keypair("bc"),
        funding_utxo=BtcUtxo(txid=A._BTC_FUNDING_TXID, vout=0, value=terms.btc_sats * 3),
        maker_claim_pubkey_xonly=terms.btc_claim_pubkey_xonly,
        broadcaster=btc_view,
        funding_reader=btc_view,
        refund_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        claim_to_scriptpubkey=b"\x00\x14" + os.urandom(20),
        policy=FundingPolicy(fee_sats=500, min_confirmations=1),
        maker_claim_privkey=None,
    )
    coord = SwapCoordinator(
        record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        counter_leg=btc_leg,
        radiant_leg=_real_leg(view, network=rxd_tag),
        indexer=FakeIndexer(),
        seen_store=FakeSeenStore(),
        config=CoordinatorConfig(margin_policy=MarginPolicy.estimated(), accept_nondurable_seen=True),
    )
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "the counter leg moves real value (network 'bc')" in gate.reason, gate.reason
    with pytest.raises(ValidationError, match="counter leg moves real value"):
        await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert btc_view.broadcasts == []
    assert coord.last_maker_funding is None


def test_the_freshness_cap_is_a_parameter_defaulting_to_the_pages_value():
    from pyrxd.glyph.mark_block import MAX_HEADERS_FROM_CHECKPOINT, plan_block_verification

    newest = funding_spv.MAINNET_CHAIN.checkpoints[-1][0]
    assert MAX_HEADERS_FROM_CHECKPOINT == 4032 and MAX_HEADERS_FROM_CHECKPOINT_SDK == 20_160
    far = newest + 10_000
    assert plan_block_verification(height=far, min_confirmations=1).reason is not None
    assert plan_block_verification(height=far, min_confirmations=1, max_headers_from_checkpoint=20_160).reason is None
    ranges = funding_header_ranges(funding_spv.MAINNET_CHAIN, far)
    assert ranges[0][0] == funding_spv.MAINNET_CHAIN.checkpoints[-2][0]
    assert sum(n for _s, n in ranges) == 2016 + 20_160 + 1
    with pytest.raises(MakerFundingNotVerified, match="upgrade pyrxd"):
        funding_header_ranges(funding_spv.MAINNET_CHAIN, newest + 20_161)


def test_C_takes_the_hardest_header_of_the_last_checkpoint_interval():
    """``max_header_work`` spans the last checkpoint interval as well as the headers served above the
    newest checkpoint. Here the interval (checkpoints 2 and 4) holds header 3 at eight times the work
    of every other header, and the served window above checkpoint 4 is all easy headers: ``C`` must be
    priced on header 3, the smaller cost, not on the easy window alone."""
    easy, hard = _HARD_BITS, 0x1F0FFFFF  # target 0x0fffff… is 1/8 of 0x7fffff…
    headers = {0: regtest_genesis_header()}
    for h, bits in ((1, easy), (2, easy), (3, hard), (4, easy)):
        root = hashlib.sha256(b"interval" + bytes([h])).digest()
        headers[h] = mine(radiant_block_hash(headers[h - 1]), root, _NOW - 86400 + 300 * h, bits)
    pow_limit = (1 << 255) - 1
    work = {h: radiant_header_work(headers[h], pow_limit=pow_limit) for h in headers}
    assert work[3] >= 8 * work[4] - 8 and work[4] == work[2]
    chain = RadiantChain(
        name="mainnet",
        checkpoints=tuple((h, radiant_block_hash(headers[h])) for h in (0, 2, 4)),
        pow_limit=pow_limit,
        subsidy_halving_interval=210_000,
        value_bearing=True,
    )
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    c = build_funding_chain(spk=spk, value=1000, confs=6, base=headers, bits=easy, tip_time=_NOW)
    assert all(radiant_header_work(c.headers[h], pow_limit=pow_limit) == work[4] for h in range(5, c.top + 1))
    r = verify_maker_funding(
        c.evidence(),
        chain=chain,
        expected_spk=spk,
        expected_value=1000,
        value_at_stake_photons=1000,
        burial_blocks=6,
        now_unix_s=_NOW,
        withheld_block_interval_s=_FAST_S,
    )
    assert r.max_header_work == work[3]
    assert r.forged_confirmation_cost_photons == r.subsidy_photons * (work[4] // 16) // work[3]


def test_k_past_the_cap_refuses_with_upgrade_or_use_your_own_node(monkeypatch):
    base, chain = _value_bearing_chain(monkeypatch)
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=8, base=base, bits=_HARD_BITS)
    kw = dict(
        chain=chain,
        expected_spk=spk,
        expected_value=1000,
        value_at_stake_photons=1,
        burial_blocks=10,
        now_unix_s=_NOW,
        withheld_block_interval_s=36.0,
    )
    # cap 6: block 5 + k(10) - 1 = 14 is 10 past checkpoint 4.
    with pytest.raises(
        MakerFundingNotVerified, match="upgrade pyrxd .newer checkpoints. or verify against your own node"
    ):
        verify_maker_funding(c.evidence(), cap=6, **kw)


# --------------------------------------------------------------------------- (d) every lock path


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _enclosing_fn(node, parents):
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node
    return None


def _fund_call_sites() -> list[tuple[str, ast.AST, ast.Call]]:
    """Every ``<something>leg.fund(...)`` call in shipped code (src/ and scripts/), by AST."""
    out = []
    for path in sorted((ROOT / "src" / "pyrxd").rglob("*.py")) + sorted((ROOT / "scripts").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = _parents(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "fund":
                receiver = ast.unparse(node.func.value).split(".")[-1]
                if receiver.endswith("leg"):
                    out.append((str(path.relative_to(ROOT)), _enclosing_fn(node, parents), node))
    return out


def _calls_in(fn: ast.AST, name: str) -> list[int]:
    return [
        n.lineno
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == name
    ]


#: Reviewed, not derived: a counter-leg ``fund`` outside the coordinator. Pinned as a set so any
#: change forces the reason to be re-read. ``run_dry`` deploys an ETH HTLC on a throwaway local
#: anvil (``network="anvil"``) to prove the wiring; there is no maker, no covenant, no value.
_REVIEWED_OUTSIDE_THE_COORDINATOR = {("scripts/eth_swap_run.py", "run_dry")}


def test_every_counter_leg_fund_call_crosses_the_gate():
    sites = _fund_call_sites()
    coordinator = [(p, fn, c) for p, fn, c in sites if p == "src/pyrxd/gravity/swap_coordinator.py"]
    assert len(coordinator) >= 2, f"non-vacuity: expected the BTC and ETH fund sites, found {len(coordinator)}"
    for _p, fn, call in coordinator:
        verify_lines = _calls_in(fn, "taker_verify_asset_funding")
        gate_lines = _calls_in(fn, "pre_btc_lock_check")
        assert any(line < call.lineno for line in verify_lines), (
            f"{fn.name} calls counter_leg.fund at line {call.lineno} without re-running "
            "taker_verify_asset_funding before it (the verify->lock TOCTOU)"
        )
        assert any(line < call.lineno for line in gate_lines), f"{fn.name} funds without pre_btc_lock_check"
    # A leg's own `fund` delegating to an inner leg (the ERC-20 wrapper) is the same lock, reached
    # through the coordinator; anything else outside the coordinator is the reviewed set.
    outside = {
        (p, fn.name) for p, fn, _c in sites if p != "src/pyrxd/gravity/swap_coordinator.py" and fn.name != "fund"
    }
    assert outside == _REVIEWED_OUTSIDE_THE_COORDINATOR


def _coordinator_entry_points_that_fund() -> set[str]:
    """Public SwapCoordinator methods from which a ``counter_leg.fund`` call is reachable."""
    src = (ROOT / "src/pyrxd/gravity/swap_coordinator.py").read_text(encoding="utf-8")
    cls = next(n for n in ast.parse(src).body if isinstance(n, ast.ClassDef) and n.name == "SwapCoordinator")
    methods = {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    calls = {
        name: {
            c.func.attr
            for c in ast.walk(fn)
            if isinstance(c, ast.Call)
            and isinstance(c.func, ast.Attribute)
            and isinstance(c.func.value, ast.Name)
            and c.func.value.id == "self"
        }
        for name, fn in methods.items()
    }
    funders = {name for name, fn in methods.items() if _calls_in(fn, "fund")}

    def reaches(name, seen=frozenset()):
        return name in funders or any(reaches(c, seen | {name}) for c in calls.get(name, ()) if c not in seen)

    return {name for name in methods if not name.startswith("_") and reaches(name)}


async def _drive_taker_funds_btc_btc():
    terms = _terms(variant="rxd")
    btc = FakeBtcLeg()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=FakeRadiantLeg(asset_funded=False))
    with pytest.raises((ValidationError, NetworkError)) as exc:
        await coord.taker_funds_btc(terms)
    return btc.calls, str(exc.value)


async def _drive_taker_funds_btc_eth():
    _p = os.urandom(32)
    terms = _eth_terms(hashlock=hashlib.sha256(_p).digest())
    eth = FakeEthLeg(preimage=_p, verdict=_final())
    coord = _eth_coord_full(terms=terms, eth_leg=eth, radiant_leg=FakeRadiantLeg(asset_funded=False))
    with pytest.raises((ValidationError, NetworkError)) as exc:
        await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    return eth.calls, str(exc.value)


async def _drive_resume_interrupted_fund_eth(tmp_path):
    import dataclasses

    from pyrxd.gravity.record_sink import JsonFileRecordSink

    _p = os.urandom(32)
    terms = _eth_terms(hashlock=hashlib.sha256(_p).digest())
    sink = JsonFileRecordSink(tmp_path / "swap.json")
    pending = dataclasses.replace(
        SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
        pending_counter_contract="0x" + "ab" * 20,
        pending_counter_deploy_tx="0x" + "cd" * 32,
    )
    await sink(pending)
    seen = FakeSeenStore()
    seen.reserve(terms.hashlock)
    eth = FakeEthLeg(preimage=_p, verdict=_final())
    coord = _eth_coord_full(
        terms=terms, eth_leg=eth, radiant_leg=FakeRadiantLeg(asset_funded=False), seen_store=seen, fund_lock=_MemLock()
    )
    with pytest.raises((ValidationError, NetworkError)) as exc:
        await coord.resume_interrupted_fund(terms, sink=sink, now_unix_s=_NOW)
    return eth.calls, str(exc.value)


async def test_each_coordinator_entry_point_that_funds_refuses_an_unproved_funding(tmp_path):
    """Behavioural half of (d): every public entry point the AST says reaches a ``fund`` call is
    driven with a maker funding the gate refuses, on each counter chain it serves, and the counter
    leg's ``fund`` is never called. A new entry point fails here until it gets a driver."""
    drivers = {
        "taker_funds_btc": [_drive_taker_funds_btc_btc, _drive_taker_funds_btc_eth],
        "resume_interrupted_fund": [lambda: _drive_resume_interrupted_fund_eth(tmp_path)],
    }
    derived = _coordinator_entry_points_that_fund()
    assert derived, "non-vacuity: no coordinator entry point reaches a fund call"
    assert derived == set(drivers), f"entry points that fund: {sorted(derived)}; drivers for: {sorted(drivers)}"
    for name, fns in drivers.items():
        for drive in fns:
            calls, reason = await drive()
            assert "fund" not in calls, f"{name} reached counter_leg.fund with an unproved maker funding"
            # ...and it was the GATE that refused, not some unrelated precondition of the driver.
            assert "maker's Radiant covenant not verified" in reason, (name, reason)


# --------------------------------------------------------------------------- (e) the refusal message


async def test_a_refusal_names_k_the_value_C_and_what_was_proved(monkeypatch):
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _ab_terms(400)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
    value = 1_000_000 * PHOTONS_PER_RXD
    policy = _vb_policy(value_at_risk_photons=value)
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bc"), policy=policy, accept_nondurable_seen=True)
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    reason = gate.reason
    for needle in ("k = ", f"value {value} photons", "C = ", "photons (subsidy", "Required:", "Proved:", "6 deep"):
        assert needle in reason, (needle, reason)
    k = int(reason.split("k = ")[1].split(" ")[0])
    assert k > 6, "the value term, not the floor, set k"
    assert btc_view.broadcasts == []


# --------------------------------------------------------------------------- (f) the upper bound


class _StaleTipLeg(FakeRadiantLeg):
    """The honest fake, but its newest header is stamped ``tip_time`` — as a server that stopped
    serving some blocks ago would present it."""

    def __init__(self, *, tip_time: int, confs: int = 1) -> None:
        super().__init__(report_confs=confs)
        self.tip_time = tip_time

    async def maker_funding_evidence(self, terms, *, header_ranges, min_confirmations=None):
        spk = await self.expected_covenant_scriptpubkey(terms)
        c = build_funding_chain(
            spk=spk, value=int(terms.radiant_amount), confs=self.report_confs, tip_time=self.tip_time
        )
        header_ranges(c.height)
        return c.evidence(reported_confirmations=self.report_confs)


async def test_step_7_judges_the_timelocks_on_the_elapsed_UPPER_bound():
    """One block proved, but the newest header served is 30 blocks' worth of time old. The CSV
    window must be judged as if those blocks were mined — here that leaves too little margin, so
    the gate refuses; the SAME funding with a fresh tip passes."""
    terms = _terms(variant="rxd")  # t_rxd 144, t_btc 24: ~24 Radiant blocks of elapsed slack
    stale = _coordinator(terms=terms, radiant_leg=_StaleTipLeg(tip_time=_NOW - 300 * 30))
    gate = await stale.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "REMAINING window" in gate.reason
    assert stale.last_maker_funding.proved_depth == 1
    assert stale.last_maker_funding.elapsed_blocks_upper == 31

    fresh = _coordinator(terms=terms, radiant_leg=_StaleTipLeg(tip_time=_NOW))
    assert (await fresh.pre_btc_lock_check(terms, now_unix_s=_NOW)).ok is True


def test_the_upper_bound_is_raised_by_the_server_report_and_never_lowered():
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=3, tip_time=_NOW)
    kw = dict(
        chain=funding_spv.REGTEST_CHAIN,
        expected_spk=spk,
        expected_value=1000,
        value_at_stake_photons=None,
        burial_blocks=1,
        withheld_block_interval_s=300.0,
    )
    assert verify_maker_funding(c.evidence(reported_confirmations=50), now_unix_s=_NOW, **kw).elapsed_blocks_upper == 50
    assert verify_maker_funding(c.evidence(reported_confirmations=1), now_unix_s=_NOW, **kw).elapsed_blocks_upper == 3
    r = verify_maker_funding(c.evidence(), now_unix_s=_NOW + 3000, **kw)
    assert (r.proved_depth, r.withheld_allowance_blocks, r.elapsed_blocks_upper) == (3, 10, 13)


def _reference_depth_case():
    """Checkpoints at 0, 2 and 4 (mainnet schedule, floor-bearing bits), then a funding at block 5
    buried 10 deep whose newest header is six hours old."""
    base = build_funding_chain(spk=b"\x51", value=1, confs=4, bits=_HARD_BITS, tip_time=_NOW - 10 * 86400).headers
    chain = RadiantChain(
        name="mainnet",
        checkpoints=tuple((h, radiant_block_hash(base[h])) for h in (0, 2, 4)),
        pow_limit=(1 << 255) - 1,
        subsidy_halving_interval=210_000,
        value_bearing=True,
    )
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    real = build_funding_chain(spk=spk, value=1000, confs=10, base=base, bits=_HARD_BITS, tip_time=_NOW - 6 * 3600)
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6, withheld_block_interval_s=_FAST_S)
    return real, kw


def _time(header: bytes) -> int:
    return int.from_bytes(header[68:72], "little")


def test_the_reference_time_comes_from_a_header_at_depth_value_term():
    """The elapsed-time allowance is measured from the header ``max(1, value term)`` deep below the
    newest one served — the depth at which changing that header costs ``value term × C``, at least
    twice the value at stake — not from the newest header. Serving one more header on top moves the
    reference up by exactly one, so the allowance is still measured from a header that deep."""
    real, kw = _reference_depth_case()
    first = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=1, **kw)
    cost = first.forged_confirmation_cost_photons
    value = 2 * cost  # value term ceil(2 × 2C ÷ C) = 4
    r = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert r.value_term == 4 and r.value_term * cost >= FORGERY_COST_FACTOR * value
    assert r.reference_height == r.served_tip - r.value_term + 1 == 11
    expected = -(-(_NOW - _time(real.headers[11])) // int(_FAST_S))
    assert r.withheld_allowance_blocks == expected > 600
    assert r.elapsed_blocks_upper == (11 - real.height + 1) + expected

    hdrs = dict(real.headers)
    top = max(hdrs)
    hdrs[top + 1] = mine(radiant_block_hash(hdrs[top]), hashlib.sha256(b"one more").digest(), _NOW, _HARD_BITS)
    s = verify_maker_funding(real.evidence(headers=hdrs), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert s.served_tip == top + 1 and s.proved_depth == r.proved_depth + 1
    assert s.reference_height == 12, "the reference moved by more than the one header added"
    assert s.withheld_allowance_blocks == -(-(_NOW - _time(real.headers[12])) // int(_FAST_S)) > 600
    assert s.elapsed_blocks_upper >= s.proved_depth + 600


def test_a_value_term_of_one_references_the_newest_header():
    """When one forged confirmation already costs twice the value (value term 1) the reference is the
    newest header served, exactly as on a test network — no honest swap is charged more time."""
    real, kw = _reference_depth_case()
    r = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=1000, **kw)
    assert r.value_term == 1 and r.forged_confirmation_cost_photons >= FORGERY_COST_FACTOR * 1000
    assert r.reference_height == r.served_tip
    assert r.withheld_allowance_blocks == -(-(_NOW - _time(real.headers[r.served_tip])) // int(_FAST_S))


def test_a_value_bearing_gate_without_a_clock_refuses(monkeypatch):
    base, chain = _value_bearing_chain(monkeypatch)
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=6, base=base, bits=_HARD_BITS)
    with pytest.raises(MakerFundingNotVerified, match="no wall clock"):
        verify_maker_funding(
            c.evidence(),
            chain=chain,
            expected_spk=spk,
            expected_value=1000,
            value_at_stake_photons=1000,
            burial_blocks=6,
            now_unix_s=None,
            withheld_block_interval_s=36.0,
        )


class _VanishesAfterFirstProof(FakeRadiantLeg):
    """Proves the funding once — the pre-lock gate inside ``taker_funds_btc`` — then the covenant is
    gone (double-spent away) when the lock-time re-run asks again."""

    def __init__(self) -> None:
        super().__init__()
        self.proofs = 0

    async def maker_funding_evidence(self, terms, *, header_ranges, min_confirmations=None):
        self.proofs += 1
        if self.proofs > 1:
            raise NetworkError("no UTXO found for the covenant scriptPubKey (spent)")
        return await super().maker_funding_evidence(
            terms, header_ranges=header_ranges, min_confirmations=min_confirmations
        )


async def test_the_lock_time_rerun_alone_catches_a_covenant_that_vanishes_inside_the_fund_call():
    """Isolates the re-run: the gate inside ``taker_funds_btc`` passes, and only the SECOND proof
    — immediately before ``fund`` — can see the covenant is gone. BTC and ETH branches alike."""
    terms = _terms(variant="rxd")
    btc = FakeBtcLeg()
    leg = _VanishesAfterFirstProof()
    coord = _coordinator(terms=terms, btc_leg=btc, radiant_leg=leg)
    with pytest.raises(NetworkError, match="spent"):
        await coord.taker_funds_btc(terms)
    assert leg.proofs == 2 and "fund" not in btc.calls

    _p = os.urandom(32)
    eth_terms = _eth_terms(hashlock=hashlib.sha256(_p).digest())
    eth = FakeEthLeg(preimage=_p, verdict=_final())
    leg = _VanishesAfterFirstProof()
    coord = _eth_coord_full(terms=eth_terms, eth_leg=eth, radiant_leg=leg)
    with pytest.raises(NetworkError, match="spent"):
        await coord.taker_funds_btc(eth_terms, now_unix_s=_NOW)
    assert leg.proofs == 2 and "fund" not in eth.calls

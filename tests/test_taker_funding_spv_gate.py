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
(f) steps 6 and 7 judge the timelocks on the elapsed-depth UPPER bound, not the proved lower bound;
    the bound's time term (median time past, Poisson quantile), its operator-grouped report term,
    and the negotiation-time check's model of it.
"""

from __future__ import annotations

import ast
import dataclasses
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
    MEDIAN_TIME_SPAN,
    MIN_FUNDING_CONFIRMATIONS,
    ElapsedBoundPolicy,
    MakerFundingNotVerified,
    RadiantChain,
    block_subsidy_photons,
    early_elapsed_blocks_upper,
    funding_header_ranges,
    median_time_past,
    poisson_upper_quantile,
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
from pyrxd.network.registry import DEFAULT_ENDPOINTS
from pyrxd.network.source_identity import source_key
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


def _vb_chain(headers: dict[int, bytes], heights: tuple[int, ...]) -> RadiantChain:
    """A value-bearing chain (mainnet's subsidy schedule; regtest's proof-of-work limit so the genesis
    decodes) with checkpoints at *heights* of *headers*, shipping the last interval's work exactly as
    ``scripts/refresh_radiant_checkpoints.py`` computes it for the real table."""
    pow_limit = (1 << 255) - 1
    lo, hi = heights[-2], heights[-1]
    works = [radiant_header_work(headers[h], pow_limit=pow_limit) for h in range(lo, hi + 1)]
    return RadiantChain(
        name="mainnet",
        checkpoints=tuple((h, radiant_block_hash(headers[h])) for h in heights),
        pow_limit=pow_limit,
        subsidy_halving_interval=210_000,
        value_bearing=True,
        last_interval_max_work=max(works),
        newest_checkpoint_work=works[-1],
    )


def _value_bearing_chain(monkeypatch) -> tuple[dict[int, bytes], RadiantChain]:
    """A value-bearing chain the tests can mine: regtest genesis, then headers 1..4 at _HARD_BITS,
    with checkpoints at 0, 2 and 4 — installed as the chain every value-bearing leg resolves to."""
    base = build_funding_chain(spk=b"\x51", value=1, confs=4, bits=_HARD_BITS).headers
    chain = _vb_chain(base, (0, 2, 4))
    monkeypatch.setattr(funding_spv, "MAINNET_CHAIN", chain)
    return base, chain


#: The measured Radiant fast tail (p10) the value-bearing tests use; the nominal stays 300 s.
_FAST_S = 36.0


def _vb_policy(**over) -> MarginPolicy:
    """An estimated dust-grade policy carrying the measured fast tail, which a value-bearing
    coordinator requires for its timelock reserves."""
    base = MarginPolicy.estimated(accept_flat_burial=True)
    return type(base)(**{**base.__dict__, "rxd_block_interval_fast_s": _FAST_S, **over})


#: The distinct operator groups of pyrxd's shipped mainnet endpoints, by ``source_key`` — derived,
#: not typed, so the fixtures count operators the way the gate does.
_SHIPPED_OPERATORS = tuple(dict.fromkeys(source_key(u) for u in DEFAULT_ENDPOINTS["mainnet"]))
assert len(_SHIPPED_OPERATORS) >= 2, _SHIPPED_OPERATORS


def _two_operators(ev):
    """*ev* with the funding's depth reported honestly (the served tip) by two distinct operators —
    what the gate requires above dust on a value-bearing network."""
    depth = max(ev.headers) - ev.height + 1
    reports = tuple((str(k), depth) for k in _SHIPPED_OPERATORS[:2])
    return dataclasses.replace(ev, reported_depths=reports, funding_tx_depths=reports)


class _ChainView:
    """An ElectrumX-shaped Radiant server over a synthetic chain it serves honestly — unless told
    to lie: ``listed_spk`` makes ``listunspent`` claim an output for a script the raw transaction
    does not pay (``pays`` is what it really pays). It is run by the first shipped operator."""

    source_key = _SHIPPED_OPERATORS[0]

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
        chain=None,
    ):
        kw = {} if tip_time is None else {"tip_time": tip_time}
        self.chain = chain or build_funding_chain(spk=pays, value=value, confs=confs, base=base, bits=bits, **kw)
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


class _DepthReader:
    """A second operator's Radiant reader: it reports the depth *view*'s chain really has."""

    def __init__(self, view, key=_SHIPPED_OPERATORS[1]):
        self.source_key = key
        self._view = view

    async def get_transaction_verbose(self, txid):
        return {"txid": txid, "confirmations": self._view.confs}


def _real_leg(view, *, network: str, min_confirmations: int = 1, depth_sources=None) -> RadiantCovenantLeg:
    """The real leg over *view*, asking a second operator (:class:`_DepthReader`) for the depth too
    unless *depth_sources* says otherwise."""
    return RadiantCovenantLeg(
        network=network,
        taker_pkh=A._TAKER_PKH,
        maker_pkh=A._MAKER_PKH,
        chain_io=RadiantChainIO(view, depth_sources=(_DepthReader(view),) if depth_sources is None else depth_sources),
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


def _vb_terms(t_rxd_blocks: int = 400) -> NegotiatedTerms:
    """:func:`_ab_terms` with room for a value-bearing gate's elapsed-depth bound. Those terms leave
    ``t_btc`` 4 BTC blocks (8 Radiant blocks of wall clock) inside the margin — a window no
    value-bearing funding fits, since the negotiation-time check models the bound with the newest
    header up to an hour old. ``t_btc`` is the taker's own leg, so shortening it changes nothing the
    covenant commits to."""
    import dataclasses

    terms = _ab_terms(t_rxd_blocks)
    return dataclasses.replace(terms, t_btc=type(terms.t_btc)(max(1, t_rxd_blocks // 2 - 36 - 40), terms.t_btc.unit))


def _wide_terms(t_rxd_blocks: int, t_btc_blocks: int = 100) -> NegotiatedTerms:
    """:func:`_ab_terms` at a chosen ``t_rxd`` with a short ``t_btc`` — room for large bounds."""
    import dataclasses

    from pyrxd.btc_wallet import taproot as t

    return dataclasses.replace(
        _ab_terms(t_rxd_blocks),
        t_btc=t.Timelock(t_btc_blocks, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
    )


def _time(header: bytes) -> int:
    return int.from_bytes(header[68:72], "little")


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
    terms = _vb_terms(400)
    spk = _covenant(terms)
    # A whole chain from 10 below the second-newest shipped checkpoint (where the planned ranges
    # start) to 16 blocks past the newest, every header meeting its own target, the funding 5 blocks
    # past the newest checkpoint.
    table = funding_spv.MAINNET_CHAIN.checkpoints
    offset = table[-2][0] - (MEDIAN_TIME_SPAN - 1)
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
    terms = _vb_terms(400)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
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


async def test_a_value_bearing_policy_without_the_fast_tail_is_refused_at_construction(monkeypatch):
    """The timelock reserves divide time spans by ``MarginPolicy.rxd_block_interval_fast_s`` and fall
    back to the nominal interval without it. On a value-bearing network the coordinator refuses to
    CONSTRUCT for a negotiated swap without it — for every role, since the reserves are not the taker
    gate's — and ``pre_btc_lock_check`` step 3b refuses a policy that lost it after construction,
    before the chain is read."""
    import dataclasses

    from pyrxd.gravity.swap_state import SwapRole

    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _vb_terms(400)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    no_tail = MarginPolicy.estimated(accept_flat_burial=True)
    for role in (None, SwapRole.TAKER, SwapRole.MAKER):
        with pytest.raises(
            ValidationError,
            match=r"refused before anyone locks.*needs MarginPolicy\.rxd_block_interval_fast_s.*reserves",
        ):
            _btc_coord(terms, _real_leg(view, network="bc"), policy=no_tail, accept_nondurable_seen=True, role=role)
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True)
    coord.config = dataclasses.replace(coord.config, margin_policy=no_tail)
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "needs MarginPolicy.rxd_block_interval_fast_s" in gate.reason, gate.reason
    assert view.reads == [], "the chain was read before the policy was refused"
    assert btc_view.broadcasts == []


async def test_the_gates_bound_does_not_read_the_fast_tail(monkeypatch):
    """The elapsed-depth bound is the statistical one — it reads no inter-block measurement. The same
    funding judged under a 36 s and a 300 s fast tail gives the same bound."""
    import dataclasses

    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _vb_terms(400)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW - 600
    )
    got = []
    for fast in (_FAST_S, 300.0):
        coord, _b = _btc_coord(terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True)
        coord.config = dataclasses.replace(coord.config, margin_policy=_vb_policy(rxd_block_interval_fast_s=fast))
        await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
        got.append(coord.last_maker_funding.elapsed_blocks_upper)
    assert got[0] == got[1] > 6


async def test_the_time_term_is_the_poisson_quantile_from_the_median_time_past(monkeypatch):
    """One hour after the newest header: ``E`` is measured from the median of the 11 timestamps ending
    at the reference header, and the time term is ``poisson_upper_quantile(2 × E ÷ 300, ε)`` with
    ``ε = clamp(1 RXD ÷ value, 1e-12, 1e-3)``. Dropping the surge factor, the value from ``ε``, or
    the median fails here. The coordinator's read clock is held still, so ``now`` is exactly
    ``_NOW`` (the clock's own effect is pinned by the test after the concurrent-reads section)."""
    from pyrxd.gravity import swap_coordinator

    monkeypatch.setattr(swap_coordinator, "_monotonic", lambda: 0.0)
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=70, base=base, bits=_HARD_BITS, tip_time=_NOW - 3600
    )
    value = 10_000 * PHOTONS_PER_RXD
    coord, _btc_view = _btc_coord(
        terms,
        _real_leg(view, network="bc"),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    r = coord.last_maker_funding
    hdrs = view.chain.headers
    window = [_time(hdrs[h]) for h in range(r.reference_height - 10, r.reference_height + 1)]
    assert r.reference_time == sorted(window)[5] == median_time_past(window)
    assert r.reference_time == _time(hdrs[r.reference_height - 5])  # the chain is 300 s apart
    assert r.elapsed_s == _NOW - r.reference_time
    assert r.value_term > 1 and r.reference_height < r.served_tip, "the reference is value_term deep"
    assert r.epsilon == pytest.approx(1 / 10_000)
    assert r.time_blocks == poisson_upper_quantile(3.0 * r.elapsed_s / 300, r.epsilon)
    assert r.elapsed_blocks_upper == (r.reference_height - r.height + 1) + r.time_blocks
    assert r.bound_term == "time" and "the time term set the bound" in r.bound_note


def _gap_case(**over):
    """Checkpoints 0/4/22/24; the funding at block 1, 30 deep (served tip 30). A value term of 23 puts
    the reference header at block 8 — between the funding's own checkpoint (4) and the last checkpoint
    interval (22..24, fetched from 12 for its median-time window), the range the planned spans used
    to leave out. The headers are 300 s apart, the newest stamped the test clock."""
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    real = build_funding_chain(spk=spk, value=1000, confs=30, bits=_HARD_BITS, tip_time=_NOW)
    chain = _vb_chain(real.headers, (0, 4, 22, 24))
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6)
    kw.update(over)
    cap = kw.get("cap", MAX_HEADERS_FROM_CHECKPOINT_SDK)
    fetched = {h for s, n in funding_header_ranges(chain, real.height, cap=cap) for h in range(s, s + n)}
    ev = real.evidence(headers={h: b for h, b in real.headers.items() if h in fetched})
    cost = verify_maker_funding(ev, now_unix_s=_NOW, value_at_stake_photons=1, **kw).forged_confirmation_cost_photons
    return ev, kw, 23 * cost // 2, fetched


def test_a_reference_header_below_the_last_checkpoint_interval_is_fetched_and_linked():
    """The reviewer's probe (``KeyError(5)``, then): the value term puts the reference header in the
    stretch between the funding's checkpoint and the last interval. The planned ranges cover the
    whole span from the funding block up to the newest checkpoint, and the gate links the reference
    header to the checkpoint above it before reading its window."""
    ev, kw, value, fetched = _gap_case()
    assert set(range(0, 25)) <= fetched
    r = verify_maker_funding(_two_operators(ev), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert (r.value_term, r.served_tip, r.reference_height) == (23, 30, 8)


def test_a_reference_header_the_plan_cannot_reach_refuses_by_name_never_a_bare_key_error():
    """With a walk cap smaller than the funding's distance below the newest checkpoint the gap is not
    fetched; the refusal is a MakerFundingNotVerified that names the reference header."""
    ev, kw, value, fetched = _gap_case(cap=4)
    assert not set(range(5, 12)) & fetched
    with pytest.raises(MakerFundingNotVerified, match=r"reference header .*block \d+, 23 deep.*checkpoint 22"):
        verify_maker_funding(_two_operators(ev), now_unix_s=_NOW, value_at_stake_photons=value, **kw)


def test_a_reference_header_that_does_not_link_to_its_checkpoint_is_refused():
    """Served, but not the chain's: a header at the reference height that does not link to the
    checkpoint above it is refused, so its window is never read."""
    ev, kw, value, _fetched = _gap_case()
    forged = dict(ev.headers)
    forged[8] = mine("00" * 32, b"\x00" * 32, _NOW, _HARD_BITS)
    ev = type(ev)(**{**ev.__dict__, "headers": forged})
    with pytest.raises(MakerFundingNotVerified, match=r"reference header .*block 8"):
        verify_maker_funding(_two_operators(ev), now_unix_s=_NOW, value_at_stake_photons=value, **kw)


def test_a_forged_span_between_the_reference_header_and_its_checkpoint_is_refused_by_name():
    """The reviewer's probe (``probe_ref_forge.py``). Checkpoints at 0, 2, 4, 6 and 8; a value term
    that puts the reference header at block 3, inside the interval 2..4 that nothing else links. The
    server serves its own blocks 3 and 4 — block 3 linking to the real block 2, block 4 to its own
    block 3 — so every header in the span links to the one below it, and only the check that the
    span ENDS at checkpoint 4's hash refuses it. The refusal names the reference header."""
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    real = build_funding_chain(spk=spk, value=1000, confs=10, bits=_HARD_BITS, tip_time=_NOW - 6 * 3600)
    chain = _vb_chain(real.headers, (0, 2, 4, 6, 8))
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6)
    cost = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=1, **kw)
    value = 4 * cost.forged_confirmation_cost_photons
    honest = verify_maker_funding(_two_operators(real.evidence()), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert honest.reference_height == 3, honest.reference_height
    h3 = mine(radiant_block_hash(real.headers[2]), b"\x33" * 32, _NOW, _HARD_BITS)
    h4 = mine(radiant_block_hash(h3), b"\x44" * 32, _NOW, _HARD_BITS)
    forged = {**real.headers, 3: h3, 4: h4}
    with pytest.raises(MakerFundingNotVerified, match=r"reference header .*block 3.*checkpoint 4"):
        verify_maker_funding(
            _two_operators(real.evidence(headers=forged)), now_unix_s=_NOW, value_at_stake_photons=value, **kw
        )


def test_a_header_in_the_median_time_window_that_does_not_link_is_refused_by_name():
    """The 10 headers below the reference header are read for the median time past only once each is
    linked to the one above it. Checkpoints 0, 2, 14 and 16 and a funding at block 1, 20 deep: a value
    term of 9 puts the reference at block 12, whose window (2..12) lies mostly in the stretch no other
    check links. A header served there that does not link is refused, named; the honest chain passes."""
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    real = build_funding_chain(spk=spk, value=1000, confs=20, bits=_HARD_BITS, tip_time=_NOW - 3600)
    chain = _vb_chain(real.headers, (0, 2, 14, 16))
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6)
    cost = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=1, **kw)
    value = 9 * cost.forged_confirmation_cost_photons // 2
    honest = verify_maker_funding(_two_operators(real.evidence()), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert (honest.value_term, honest.reference_height) == (9, 12)
    forged = {**real.headers, 7: mine("00" * 32, b"\x07" * 32, _NOW, _HARD_BITS)}
    with pytest.raises(MakerFundingNotVerified, match=r"header 7, in the 11-header window .*blocks 2 to 12"):
        verify_maker_funding(
            _two_operators(real.evidence(headers=forged)), now_unix_s=_NOW, value_at_stake_photons=value, **kw
        )
    missing = {h: b for h, b in real.headers.items() if h != 4}
    with pytest.raises(MakerFundingNotVerified, match=r"header 4, in the 11-header window"):
        verify_maker_funding(
            _two_operators(real.evidence(headers=missing)), now_unix_s=_NOW, value_at_stake_photons=value, **kw
        )


def test_real_mainnet_headers_and_transaction_verify_at_the_gate():
    """REAL data: the recorded mainnet block 460,572 transaction, its merkle and coinbase branches
    and headers 460,564..460,580 (``tests/fixtures/mark_block_fixtures_2026-09-30.json``), judged
    by the gate's own code at mainnet's proof-of-work limit and subsidy schedule. The checkpoint
    table is built from two of those real headers (the fixture does not span the shipped table's
    last interval); C is then recomputed here independently from the same headers."""
    import dataclasses

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
    )
    r = verify_maker_funding(_two_operators(ev), value_at_stake_photons=value, **common)
    assert r.proved_depth == 9 and r.required_confirmations == 6
    assert r.forged_confirmation_cost_photons == cost and r.max_header_work == max_work
    # The negotiation-time floor on C, from the shipped interval work alone, bounds the real C from
    # below on these real headers (the served ones are within the default 2× margin of the interval).
    shipped = dataclasses.replace(
        chain,
        last_interval_max_work=max(
            radiant_header_work(m.headers[h], pow_limit=chain.pow_limit) for h in (460_564, 460_565, 460_566)
        ),
        newest_checkpoint_work=radiant_header_work(m.headers[460_566], pow_limit=chain.pow_limit),
    )
    assert max_work <= 2 * shipped.last_interval_max_work
    assert funding_spv.forged_confirmation_cost_floor_photons(shipped) <= cost
    # Nine proved blocks cover a value up to 4.5 C; one photon over that needs ten.
    with pytest.raises(MakerFundingNotVerified, match=r"proved only 9 block\(s\) deep; wait for 1 more"):
        verify_maker_funding(_two_operators(ev), value_at_stake_photons=9 * cost // 2 + 1, **common)


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


def test_the_median_time_rule_and_spacing_are_derived_from_the_vendored_radiant_core_sources():
    """``nMedianTimeSpan`` and ``GetMedianTimePast``'s choice of element are READ from the vendored
    ``chain.h``, ``nPowTargetSpacing`` from every network in ``chainparams.cpp``, and the consensus
    check that orders a block after the median time past is found in ``validation.cpp`` — all at the
    pinned tag, so a re-pin that moves one fails here."""
    import re

    vendor = ROOT / "tests" / "vendor" / "radiant_core"
    chain_h = (vendor / "chain.h").read_text()
    params = (vendor / "chainparams.cpp").read_text()
    validation = (vendor / "validation.cpp").read_text()
    span = int(re.search(r"static constexpr int nMedianTimeSpan = (\d+);", chain_h).group(1))
    assert span == MEDIAN_TIME_SPAN == 11
    assert "std::sort(pbegin, pend);\n        return pbegin[(pend - pbegin) / 2];" in chain_h
    assert "block.GetBlockTime() <= pindexPrev->GetMedianTimePast()" in validation
    spacings = {int(a) * int(b) for a, b in re.findall(r"nPowTargetSpacing = (\d+) \* (\d+);", params)}
    assert spacings == {funding_spv.TARGET_BLOCK_SPACING_S} == {300}
    assert funding_spv.MAINNET_CHAIN.target_spacing_s == funding_spv.REGTEST_CHAIN.target_spacing_s == 300
    # Core's rule, on a few windows: the element at index len // 2 of the sorted timestamps.
    assert median_time_past([5]) == 5 and median_time_past([9, 1]) == 9
    assert median_time_past(list(range(11, 0, -1))) == 6
    with pytest.raises(ValidationError):
        median_time_past(list(range(12)))


def test_the_local_clock_tolerance_is_one_nominal_block_spacing():
    """``LOCAL_CLOCK_BEHIND_MEDIAN_TOLERANCE_S`` is policy, stated: one nominal spacing (300 s)."""
    assert funding_spv.LOCAL_CLOCK_BEHIND_MEDIAN_TOLERANCE_S == funding_spv.TARGET_BLOCK_SPACING_S == 300


def test_a_local_clock_behind_the_chain_is_refused_not_clamped(monkeypatch):
    """``E = now - MTP(R)`` was clamped at zero, so a clock hours slow made a stale tip read as fresh:
    the bound fell to the proved depth and steps 6 and 7 passed on a window that is gone. On a
    value-bearing network a local clock behind the chain's median time is now REFUSED, saying so: more
    than the 300 s tolerance before the median time past of the newest verified headers. A correct clock
    and any skew within the tolerance pass, and a skew that puts ``now`` before the reference time is
    stated in the note. Headers 300 s apart, the newest stamped ``_NOW``: that median is ``_NOW - 1500``,
    so the boundary is a clock 1,800 s slow."""
    c, kw = _dust_case(monkeypatch)  # value-bearing, newest header stamped _NOW
    ev = _two_operators(c.evidence())
    assert _time(c.headers[c.top]) == _NOW
    tip_mtp = median_time_past([_time(c.headers[h]) for h in range(c.top - 10, c.top + 1)])
    assert tip_mtp == _NOW - 1500

    def run(now, value=10_000 * PHOTONS_PER_RXD):
        return verify_maker_funding(ev, **{**kw, "now_unix_s": now}, value_at_stake_photons=value)

    honest = run(_NOW)
    assert "E was taken as 0" not in honest.bound_note
    stated = 0
    # At a small value the reference header is the newest, so MTP(R) is that same median and a clock
    # within the tolerance below it is clamped — and said so.
    for skew, value in ((60, None), (300, None), (1500, None), (1800, None), (1600, 1000), (1800, 1000)):
        r = run(_NOW - skew) if value is None else run(_NOW - skew, value)
        assert r.elapsed_blocks_upper >= r.proved_depth
        if _NOW - skew < r.reference_time:
            assert "before the reference time (within the 300 s tolerance of the chain's median time)" in r.bound_note
            stated += 1
    assert stated, "non-vacuity: no skew inside the tolerance put now before the reference time"
    for skew in (1801, 7200, 9000, 86_400):
        with pytest.raises(MakerFundingNotVerified, match="local clock appears to be behind the chain") as exc:
            run(_NOW - skew)
        assert f"{skew - 1500} s before the median time past of the newest verified headers" in str(exc.value)
        assert f"(blocks {c.top - 10} to {c.top})" in str(exc.value)


def test_an_honest_clock_behind_the_newest_headers_own_timestamp_but_not_the_median_passes(monkeypatch):
    """The refusal compared ``now`` with the NEWEST header's own timestamp, which can sit ahead of the
    local clock, so an honest clock a minute behind a newest header stamped two hours ahead was refused
    for about a block. The median of the newest headers is the reference now: that clock passes, and a
    clock behind the median is still refused."""
    base, _chain = _value_bearing_chain(monkeypatch)
    spk = b"\x76\xa9" + bytes(32)
    probe = build_funding_chain(spk=spk, value=1000, confs=40, base=base, bits=_HARD_BITS, tip_time=_NOW)
    c = build_funding_chain(
        spk=spk, value=1000, confs=40, base=base, bits=_HARD_BITS, tip_time=_NOW, time_at={probe.top: _NOW + 7200}
    )
    assert _time(c.headers[c.top]) == _NOW + 7200
    kw = dict(chain=_chain, expected_spk=spk, expected_value=1000, burial_blocks=6)
    ev = _two_operators(c.evidence())
    value = 10_000 * PHOTONS_PER_RXD
    r = verify_maker_funding(ev, now_unix_s=_NOW - 60, value_at_stake_photons=value, **kw)
    assert r.proved_depth == 40
    tip_mtp = median_time_past([_time(c.headers[h]) for h in range(c.top - 10, c.top + 1)])
    assert tip_mtp - funding_spv.LOCAL_CLOCK_BEHIND_MEDIAN_TOLERANCE_S < _NOW - 60
    with pytest.raises(MakerFundingNotVerified, match="local clock appears to be behind the chain"):
        verify_maker_funding(
            ev,
            now_unix_s=tip_mtp - funding_spv.LOCAL_CLOCK_BEHIND_MEDIAN_TOLERANCE_S - 1,
            value_at_stake_photons=value,
            **kw,
        )


async def test_a_slow_clock_cannot_make_the_coordinator_fund(monkeypatch):
    """Through the coordinator: the same funding, the clock 9,000 s slow — ``pre_btc_lock_check``
    refuses naming the clock and ``taker_funds_btc`` never reaches ``fund``; with the right clock it
    locks."""
    from pyrxd.gravity import swap_coordinator

    monkeypatch.setattr(swap_coordinator, "_monotonic", lambda: 0.0)
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)

    def coord():
        view = _ChainView(
            pays=_covenant(terms), value=terms.radiant_amount, confs=70, base=base, bits=_HARD_BITS, tip_time=_NOW
        )
        return _btc_coord(
            terms,
            _real_leg(view, network="bc"),
            policy=_vb_policy(value_at_risk_photons=10_000 * PHOTONS_PER_RXD),
            accept_nondurable_seen=True,
        )

    slow, btc_view = coord()
    gate = await slow.pre_btc_lock_check(terms, now_unix_s=_NOW - 9000)
    assert gate.ok is False and "local clock appears to be behind the chain" in gate.reason, gate.reason
    with pytest.raises(ValidationError, match="local clock appears to be behind the chain"):
        await slow.taker_funds_btc(terms, now_unix_s=_NOW - 9000)
    assert btc_view.broadcasts == []

    right, _ = coord()
    assert (await right.pre_btc_lock_check(terms, now_unix_s=_NOW)).ok is True


def _exact_poisson_quantiles(mean: float, epsilons: list[float]) -> dict[float, int]:
    """The smallest ``n`` with ``P(Poisson(mean) > n) <= ε``, for each ε, by a 60-digit summation of
    the pmf from 0 — independent of the implementation's log-space tail and its bisection."""
    from decimal import Decimal, localcontext

    out: dict[float, int] = {}
    with localcontext() as ctx:
        ctx.prec = 60
        m = Decimal(repr(mean))
        term = (-m).exp()
        cdf, j = term, 0
        todo = sorted(epsilons, reverse=True)
        while todo:
            while todo and 1 - cdf <= Decimal(repr(todo[0])):
                out[todo.pop(0)] = j
            j += 1
            term = term * m / j
            cdf += term
    return out


_EPSILONS = [1e-3, 1e-4, 1e-6, 1e-9, 1e-12]


@pytest.mark.parametrize(
    "mean",
    [
        1e-6,
        1e-3,
        0.02,
        0.5,
        1.0,
        2.0,
        3.3,
        7.0,
        16.0,
        24.0,
        50.5,
        100.0,
        333.3,
        1000.0,
        4567.8,
        10_000.0,
        31_622.7,
        100_000.0,
    ],
)
def test_the_poisson_quantile_is_exact_or_one_more_never_less(mean):
    """Against an independent exact computation: the implementation is never below the exact
    quantile (the conservative direction for an upper bound), and at most one above it. The
    closed-form bound used past 1e7 is checked never below the exact quantile on the same grid."""
    import math

    exact = _exact_poisson_quantiles(mean, _EPSILONS)
    for eps in _EPSILONS:
        got = poisson_upper_quantile(mean, eps)
        assert exact[eps] <= got <= exact[eps] + 1, (mean, eps, got, exact[eps])
        big_l = -math.log(eps)
        bernstein = math.ceil(mean + big_l / 3 + math.sqrt(big_l * big_l / 9 + 2 * big_l * mean))
        assert bernstein >= exact[eps], (mean, eps)


def test_the_poisson_quantile_is_monotone_and_zero_at_zero():
    assert poisson_upper_quantile(0.0, 1e-12) == 0
    prev = 0
    for i in range(0, 4000):
        q = poisson_upper_quantile(i * 0.25, 1e-6)
        assert q >= prev
        prev = q
    assert poisson_upper_quantile(2e7, 1e-9) > 2e7 + 5 * (2e7**0.5)
    with pytest.raises(ValidationError):
        poisson_upper_quantile(-1.0, 1e-3)
    with pytest.raises(ValidationError):
        poisson_upper_quantile(1.0, 0.0)


def test_the_confidence_scales_with_the_value_and_the_policy_refuses_what_is_not_an_upper_bound():
    p = ElapsedBoundPolicy()
    assert (p.surge_factor, p.loss_budget_photons, p.early_slack_s, p.early_work_margin) == (
        3.0,
        PHOTONS_PER_RXD,
        3600,
        2.0,
    )
    assert p.epsilon(None) == p.epsilon(0) == 1e-3
    assert p.epsilon(1_000 * PHOTONS_PER_RXD) == pytest.approx(1e-3)
    assert p.epsilon(100_000 * PHOTONS_PER_RXD) == pytest.approx(1e-5)
    assert p.epsilon(10**30) == 1e-12
    assert p.blocks_upper(3600, spacing_s=300, value_at_stake_photons=None) == poisson_upper_quantile(36.0, 1e-3)
    for bad in (
        dict(surge_factor=0.5),
        dict(surge_factor=float("nan")),
        dict(epsilon_min=0.0),
        dict(epsilon_max=0.6),
        dict(epsilon_min=1e-3, epsilon_max=1e-4),
        dict(loss_budget_photons=0),
        dict(early_slack_s=-1),
        dict(early_work_margin=0.9),
    ):
        with pytest.raises(ValidationError):
            ElapsedBoundPolicy(**bad)


def test_a_test_network_bound_uses_the_loosest_confidence_and_no_value_term():
    """Regtest: the reference is the newest header, ``ε`` is ``epsilon_max`` (no value), and the
    bound is the proved depth up to it plus the quantile of the time since its median time past."""
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=12, tip_time=_NOW - 1200)
    r = verify_maker_funding(
        c.evidence(),
        chain=funding_spv.REGTEST_CHAIN,
        expected_spk=spk,
        expected_value=1000,
        value_at_stake_photons=None,
        burial_blocks=6,
        now_unix_s=_NOW,
    )
    assert r.reference_height == r.served_tip and r.epsilon == 1e-3
    assert r.elapsed_s == 1200 + 5 * 300
    assert r.time_blocks == poisson_upper_quantile(3.0 * r.elapsed_s / 300, 1e-3)
    assert r.elapsed_blocks_upper == max(r.proved_depth, r.proved_depth + r.time_blocks)
    no_clock = verify_maker_funding(
        c.evidence(),
        chain=funding_spv.REGTEST_CHAIN,
        expected_spk=spk,
        expected_value=1000,
        value_at_stake_photons=None,
        burial_blocks=6,
        now_unix_s=None,
    )
    assert no_clock.time_blocks is None and no_clock.elapsed_blocks_upper == no_clock.proved_depth
    assert "no clock was supplied" in no_clock.bound_note


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
    # From 10 below the second-newest checkpoint (its median-time window) to the cap.
    assert ranges[0][0] == funding_spv.MAINNET_CHAIN.checkpoints[-2][0] - (MEDIAN_TIME_SPAN - 1)
    assert sum(n for _s, n in ranges) == 10 + 2016 + 20_160 + 1
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
    )
    assert r.max_header_work == work[3] == r.last_interval_max_work
    assert r.forged_confirmation_cost_photons == r.subsidy_photons * (work[4] // 16) // work[3]


#: Twice ``_HARD_BITS``' work: target ``0x3fffff…`` against ``0x7fffff…``.
_HARDER_BITS = 0x1F3FFFFF


def _recent_hashrate_case(monkeypatch):
    """A value-bearing chain whose NEWEST three headers are mined at twice the work of all the others,
    and a proof server that serves the chain only up to just below them — the real recent headers
    left out, so every header it serves is easy. The value is sized so ``k``'s value term is ten at the
    served headers' work and twenty at the withheld ones'."""
    base, chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    spk = _covenant(terms)
    probe = build_funding_chain(spk=spk, value=terms.radiant_amount, confs=40, base=base, bits=_HARD_BITS)
    top = probe.top
    real = build_funding_chain(
        spk=spk,
        value=terms.radiant_amount,
        confs=40,
        base=base,
        bits=_HARD_BITS,
        tip_time=_NOW,
        bits_at={h: _HARDER_BITS for h in range(top - 2, top + 1)},
    )
    pl = chain.pow_limit
    easy_work = radiant_header_work(real.headers[top - 3], pow_limit=pl)
    hard_work = radiant_header_work(real.headers[top], pow_limit=pl)
    assert hard_work >= 2 * easy_work - 2
    served = dataclasses.replace(real, headers={h: b for h, b in real.headers.items() if h <= top - 3})
    subsidy = block_subsidy_photons(real.height, chain)
    c_easy = subsidy * (chain.newest_checkpoint_work // 16) // easy_work
    value = 5 * c_easy  # value term ceil(2 × value ÷ C) = 10 at the easy work
    return chain, terms, spk, real, served, value, easy_work, hard_work


class _TipServer(_DepthReader):
    """A second operator that serves the REAL chain: the funding's confirmations, its tip, and the
    headers ending at its tip (or ``tip_headers`` instead, when given)."""

    def __init__(self, view, real, *, tip_headers=None, fail_headers=False):
        super().__init__(view)
        self.real, self._tip_headers, self.fail_headers, self.header_reads = real, tip_headers, fail_headers, []

    async def get_transaction_verbose(self, txid):
        return {"txid": txid, "confirmations": self.real.top - self.real.height + 1}

    async def get_tip_height(self):
        return self.real.top

    async def get_block_headers(self, start, count):
        self.header_reads.append((start, count))
        if self.fail_headers:
            raise NetworkError("headers unavailable")
        if self._tip_headers is not None:
            return list(self._tip_headers)
        return [self.real.headers[h] for h in range(start, start + count) if h in self.real.headers]


async def test_recent_harder_headers_a_server_leaves_out_still_raise_max_work_and_k(monkeypatch):
    """``max_header_work`` was the maximum over the headers the PROOF's server chose to serve and the
    shipped last checkpoint interval, so a server that left the chain's newest, harder headers out
    priced ``C`` on easier ones: a larger ``C``, a smaller ``k``.

    Through the real leg and ``RadiantChainIO``: a second operator serving its own newest headers —
    the real, harder ones — raises ``max_header_work`` to theirs and doubles the value term, and the
    result says whose headers raised it. One header-range read per operator. Without those headers
    (a source that serves none) the gate is exactly what it was, and says so."""
    from pyrxd.gravity.radiant_leg import TIP_HEADERS_FOR_WORK

    _chain, terms, _spk, real, served, value, easy_work, hard_work = _recent_hashrate_case(monkeypatch)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=40, chain=served)

    async def proof_with(second):
        coord, _ = _btc_coord(
            terms,
            _real_leg(view, network="bc", depth_sources=(second,)),
            policy=_vb_policy(value_at_risk_photons=value),
            accept_nondurable_seen=True,
        )
        await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
        return coord.last_maker_funding

    plain = await proof_with(_DepthReader(view))  # no tip headers served
    assert plain.max_header_work == easy_work and plain.value_term == 10
    assert plain.operator_tip_work == ()
    assert "no source served its tip headers" in plain.bound_note, plain.bound_note

    honest = _TipServer(view, real)
    raised = await proof_with(honest)
    b = str(_SHIPPED_OPERATORS[1])
    start = max(0, real.top - TIP_HEADERS_FOR_WORK + 1)
    assert honest.header_reads == [(start, real.top - start + 1)]  # one header-range read, ending at its tip
    assert raised.max_header_work == hard_work and dict(raised.operator_tip_work)[b] == hard_work
    assert raised.value_term == 20 and raised.required_confirmations == 20 > plain.required_confirmations
    assert raised.forged_confirmation_cost_photons < plain.forged_confirmation_cost_photons
    assert f"raised by the tip headers of {b}" in raised.bound_note, raised.bound_note


def test_tip_headers_can_only_raise_max_work_never_lower_it(monkeypatch):
    """At the gate: a source's tip headers that are EASIER than what the proof served change nothing
    (the maximum cannot fall); a run that does not count is ignored and named, for each reason — headers
    that fail their own proof-of-work or do not link to one another, a run that does not end at the tip
    height its source reported, and a run that does not link to any header the gate verified; and an
    absent read leaves the gate on the proof's headers, said in ``bound_note``. Only a run on the
    verified chain, ending at its reported tip, raises ``max_header_work``."""
    from pyrxd.gravity.funding_spv import TIP_RUN_NOT_AT_TIP, TIP_RUN_UNANCHORED, TIP_RUN_UNVERIFIED
    from tests._funding_chain import REGTEST_BITS

    chain, terms, spk, real, served, value, easy_work, hard_work = _recent_hashrate_case(monkeypatch)
    kw = dict(chain=chain, expected_spk=spk, expected_value=terms.radiant_amount, burial_blocks=6, now_unix_s=_NOW)
    b = str(_SHIPPED_OPERATORS[1])

    def run(tip_headers):
        ev = _two_operators(served.evidence())
        ev = dataclasses.replace(ev, operator_tip_headers=tip_headers)
        return verify_maker_funding(ev, value_at_stake_photons=value, **kw)

    plain = run(())
    assert plain.max_header_work == easy_work and "no source served its tip headers" in plain.bound_note

    # Easier: a valid run at regtest difficulty, forking off a header the gate verified and ending at the
    # tip its source reported — it counts, and cannot lower anything.
    fork_at = max(served.headers) - 5
    prev, t0, easy_run = radiant_block_hash(served.headers[fork_at]), _time(served.headers[fork_at]), []
    for i in range(4):
        easy_run.append(mine(prev, os.urandom(32), t0 + 300 * (i + 1), REGTEST_BITS))
        prev = radiant_block_hash(easy_run[-1])
    easier = run(((b, fork_at + 1, tuple(easy_run), fork_at + 4),))
    assert dict(easier.operator_tip_work)[b] < easy_work
    assert (
        easier.max_header_work == plain.max_header_work
        and easier.required_confirmations == plain.required_confirmations
    )
    assert "did not raise it" in easier.bound_note, easier.bound_note

    tip = [real.headers[h] for h in range(real.top - 9, real.top + 1)]
    # A hard header whose proof-of-work fails: one byte of its nonce changed.
    bad_pow = list(tip)
    bad_pow[-1] = bad_pow[-1][:76] + bytes([bad_pow[-1][76] ^ 1]) + bad_pow[-1][77:]
    # Real hard headers that do not link: one header dropped from the middle (still ending at the tip).
    unlinked = tip[:4] + tip[5:]
    # Hard headers mined SOMEWHERE ELSE — a separate chain on the same checkpoints, every header meeting
    # its own (harder) target and linked to the next — labelled as this source's tip: the shape of a replay
    # of real historical headers. Before, it counted.
    elsewhere = build_funding_chain(spk=b"\x52", value=1, confs=12, base=_base_of(served), bits=_HARDER_BITS)
    replay = tuple(elsewhere.headers[h] for h in range(elsewhere.top - 9, elsewhere.top + 1))
    assert max(radiant_header_work(h, pow_limit=chain.pow_limit) for h in replay) > easy_work
    for entry, why in (
        ((b, real.top - 9, tuple(bad_pow), real.top), TIP_RUN_UNVERIFIED),
        ((b, real.top - 8, tuple(unlinked), real.top), TIP_RUN_UNVERIFIED),
        ((b, real.top - 9, tuple(tip), real.top + 1), TIP_RUN_NOT_AT_TIP),  # not the tip it reported
        ((b, real.top - 9, tuple(tip[1:]), real.top - 1), TIP_RUN_UNANCHORED),  # labelled one height low
        ((b, real.top - 9, replay, real.top), TIP_RUN_UNANCHORED),
    ):
        r = run((entry,))
        assert dict(r.operator_tip_work)[b] is None, why
        assert r.max_header_work == plain.max_header_work, f"an ignored run must change nothing ({why})"
        assert r.required_confirmations == plain.required_confirmations
        assert f"the tip headers of {b} {why}, and were ignored" in r.bound_note, r.bound_note

    good = run(((b, real.top - 9, tuple(tip), real.top),))
    assert good.max_header_work == hard_work and good.required_confirmations > plain.required_confirmations
    assert dict(good.operator_tip_work)[b] == hard_work


def _base_of(served):
    """The checkpoint headers *served* was built on (heights up to the newest checkpoint, 4)."""
    return {h: served.headers[h] for h in range(0, 5)}


def test_a_replay_of_real_historical_mainnet_headers_as_a_tip_run_is_ignored():
    """The reviewer's replay, on REAL mainnet data: 12 real headers from blocks 290,132..290,143
    (``tests/fixtures/mainnet_headers_290132_290143.json``; each meets its own proof-of-work at mainnet's
    limit and links to the next), served as a source's "tip headers" ending at the recorded proof's tip
    (block 460,580 of ``mark_block_fixtures_2026-09-30.json``). They are about 8.6 times harder than the
    hardest header the proof checked, and free to replay. Counted, they raised ``max_header_work`` that
    far and ``k`` with it; they link to no header the gate verified, so they are ignored, named, and
    change nothing. The same source's REAL tip headers (460,569..460,580) count."""
    import dataclasses
    import json as _json

    from pyrxd.gravity.funding_spv import TIP_RUN_UNANCHORED, MakerFundingEvidence
    from tests.test_mark_block_verification import MARKS

    m = MARKS["reference_460572"]
    hist = _json.loads((ROOT / "tests" / "fixtures" / "mainnet_headers_290132_290143.json").read_text())
    replay = tuple(bytes.fromhex(h) for h in hist["headers_hex"])
    assert radiant_block_hash(replay[-1]) == hist["last_block_hash"]
    tx = Transaction.from_hex(m.raw_tx)
    pl = funding_spv.MAINNET_CHAIN.pow_limit
    chain = RadiantChain(
        name="mainnet",
        checkpoints=(
            (460_564, radiant_block_hash(m.headers[460_564])),
            (460_566, radiant_block_hash(m.headers[460_566])),
        ),
        pow_limit=pl,
        subsidy_halving_interval=210_000,
        value_bearing=True,
    )
    ev = _two_operators(
        MakerFundingEvidence(
            txid=m.txid,
            vout=0,
            height=m.height,
            raw_tx=m.raw_tx,
            merkle=m.merkle,
            coinbase_merkle=m.coinbase,
            headers=m.headers,
        )
    )
    top = max(m.headers)
    served_max = max(radiant_header_work(m.headers[h], pow_limit=pl) for h in m.headers)
    replay_max = max(radiant_header_work(h, pow_limit=pl) for h in replay)
    assert replay_max > 8 * served_max  # what counting it would have done to C (and k)
    floor = radiant_header_work(m.headers[460_566], pow_limit=pl) // 16
    cost = block_subsidy_photons(460_572, chain) * floor // served_max
    common = dict(
        chain=chain,
        expected_spk=tx.outputs[0].locking_script.serialize(),
        expected_value=tx.outputs[0].satoshis,
        burial_blocks=6,
        now_unix_s=_time(m.headers[top]),
        value_at_stake_photons=2 * cost,
    )
    b = str(_SHIPPED_OPERATORS[1])
    plain = verify_maker_funding(ev, **common)
    replayed = verify_maker_funding(
        dataclasses.replace(ev, operator_tip_headers=((b, top - len(replay) + 1, replay, top),)), **common
    )
    assert replayed.max_header_work == plain.max_header_work == served_max
    assert replayed.required_confirmations == plain.required_confirmations == 6
    assert dict(replayed.operator_tip_work)[b] is None
    assert f"the tip headers of {b} {TIP_RUN_UNANCHORED}, and were ignored" in replayed.bound_note
    honest_run = tuple(m.headers[h] for h in range(top - 11, top + 1))
    honest = verify_maker_funding(
        dataclasses.replace(ev, operator_tip_headers=((b, top - 11, honest_run, top),)), **common
    )
    assert dict(honest.operator_tip_work)[b] == max(radiant_header_work(h, pow_limit=pl) for h in honest_run)
    assert honest.max_header_work == served_max and "did not raise it" in honest.bound_note


async def test_a_tip_header_read_that_fails_leaves_the_gate_as_it_was(monkeypatch):
    """Fetch failure: the operator answers its depth but its header read raises. The gate falls back to
    the proof's headers — same ``max_header_work``, same ``k`` — the operator still counts for the
    two-operator rule, and ``bound_note`` says no source served its tip headers."""
    _chain, terms, _spk, real, served, value, easy_work, _hard = _recent_hashrate_case(monkeypatch)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=40, chain=served)
    failing = _TipServer(view, real, fail_headers=True)
    coord, _ = _btc_coord(
        terms,
        _real_leg(view, network="bc", depth_sources=(failing,)),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    proof = coord.last_maker_funding
    assert failing.header_reads, "the header read was attempted"
    assert proof.max_header_work == easy_work and proof.value_term == 10
    assert str(_SHIPPED_OPERATORS[1]) in proof.reporting_operators
    assert "no source served its tip headers" in proof.bound_note, proof.bound_note


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
        # ...and the LAST verification before the lock is judged on its own bound (steps 6 and 7):
        # a re-run whose elapsed-depth bound is discarded proves the funding exists and nothing more.
        last_verify = max(line for line in verify_lines if line < call.lineno)
        judged = _calls_in(fn, "_judge_remaining_window")
        assert any(last_verify <= line < call.lineno for line in judged), (
            f"{fn.name} re-runs taker_verify_asset_funding at line {last_verify} but does not judge "
            f"steps 6 and 7 on its bound before counter_leg.fund at line {call.lineno}"
        )
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
    terms = _wide_terms(450)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    # 3.5 × this chain's C: a value term of 7 or more, which proved depth 6 cannot meet, while the
    # negotiation-time check (which models k up to 14) still finds room in t_rxd 450.
    value = 10_937_50 * PHOTONS_PER_RXD // 100
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


# --------------------------------------------------------------------------- (e2) before anyone locks

_BIG = 1_000_000 * PHOTONS_PER_RXD


def test_a_swap_whose_t_rxd_cannot_hold_the_bound_is_refused_when_the_coordinator_is_built(monkeypatch):
    """A value this large can make the gate require the maker's funding hundreds of blocks deep, and
    t_rxd is 400. That is refused at negotiation — constructing the coordinator — before the maker
    locks anything and before any chain read, with C bounded from below by the shipped interval work."""
    base, chain = _value_bearing_chain(monkeypatch)
    terms = _ab_terms(400)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    with pytest.raises(ValidationError, match="refused before anyone locks") as exc:
        _btc_coord(
            terms,
            _real_leg(view, network="bc"),
            policy=_vb_policy(value_at_risk_photons=_BIG),
            accept_nondurable_seen=True,
        )
    floor = funding_spv.forged_confirmation_cost_floor_photons(chain)
    newest = chain.checkpoints[-1][0]
    assert floor == (
        block_subsidy_photons(newest + MAX_HEADERS_FROM_CHECKPOINT_SDK, chain)
        * (chain.newest_checkpoint_work // 16)
        // (2 * chain.last_interval_max_work)
    )
    early = early_elapsed_blocks_upper(chain=chain, value_at_stake_photons=_BIG, burial_blocks=1)
    assert early.required_confirmations == early.value_term == -(-2 * _BIG // floor)
    msg = str(exc.value)
    assert f"up to {early.required_confirmations} blocks deep" in msg and f"C at least {floor} photons" in msg
    assert f"can then be {early.elapsed_blocks_upper} on an honest chain" in msg
    assert view.reads == []


def _eth_early_case(monkeypatch, *, t_rxd: int | None = None, deadline_s: int = 86_400):
    """An ETH counter leg against a value-bearing Radiant leg, as ``eth_swap_run.py --stage sepolia-dust``
    builds it: the deadline ``deadline_s`` after ``_NOW``, the measured fast tail, the dust margins. Returns
    ``(build, terms_at, reserve)``: ``build(terms, value, now=_NOW)`` constructs a NEGOTIATED coordinator;
    ``terms_at(t_rxd)`` the terms; ``reserve(value)`` the taker gate's modelled elapsed bound."""
    import dataclasses

    from pyrxd.btc_wallet import taproot as t
    from pyrxd.gravity.eth_rxd_timelock import CrossClockMargin
    from pyrxd.gravity.swap_coordinator import taker_gate_early_bound

    base, chain = _value_bearing_chain(monkeypatch)
    p = os.urandom(32)
    margin = CrossClockMargin(
        eth_reorg_finality_s=768, rxd_claim_burial_s=1800, rxd_confirm_slack_s=600, rounding_slack_s=300
    )

    def policy(value):
        return _vb_policy(
            value_at_risk_photons=value,
            eth_finalization_window_s=768,
            cross_clock_margin=margin,
            max_covenant_confirm_wait_s=3600,
        )

    def terms_at(t_rxd_blocks):
        terms = dataclasses.replace(
            _eth_terms(hashlock=hashlib.sha256(p).digest(), eth_timeout_unix_s=_NOW + deadline_s),
            t_btc=t.Timelock(1, t.TimeUnit.BLOCKS),
            t_rxd=t.Timelock(t_rxd_blocks, t.TimeUnit.BLOCKS),
            radiant_amount=1000,
        )
        cov = build_htlc_covenant_rxd(
            amount=terms.radiant_amount,
            taker_pkh=A._TAKER_PKH,
            maker_pkh=A._MAKER_PKH,
            hashlock=terms.hashlock,
            refund_csv=t_rxd_blocks,
        )
        # The destinations the real leg's covenant commits to, so an honest funding of it verifies.
        return dataclasses.replace(
            terms, taker_dest_hash=cov.expected_taker_hash, maker_dest_hash=cov.expected_maker_hash
        )

    def build(terms, value=1000, now=_NOW):
        view = _ChainView(
            pays=_covenant(terms), value=terms.radiant_amount, confs=100, base=base, bits=_HARD_BITS, tip_time=_NOW
        )
        eth = FakeEthLeg(preimage=p, verdict=_final())
        eth.network, eth.chain_id = "sepolia", 11155111
        return SwapCoordinator(
            record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
            counter_leg=eth,
            radiant_leg=_real_leg(view, network="bc"),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(
                margin_policy=policy(value),
                maker_stall_safety_window_blocks=6,
                accept_estimated_eth_margins=True,
                accept_nondurable_seen=True,
            ),
            now_unix_s=now,
        )

    def reserve(value=1000):
        return taker_gate_early_bound(
            chain=chain, policy=policy(value), value_at_stake_photons=value
        ).elapsed_blocks_upper

    floor = -(-(deadline_s + margin.total_s()) // int(_FAST_S))  # the deadline alone, nothing elapsed
    return build, terms_at, reserve, floor, chain


def test_an_eth_swap_that_steps_3_and_7_would_refuse_is_refused_when_the_coordinator_is_built(monkeypatch):
    """The reviewer's probe (``eth_swap_run.py --stage sepolia-dust`` at its defaults, t_rxd 160 against a
    24 h deadline): the coordinator CONSTRUCTED, the maker locked, and only then did ``pre_btc_lock_check``
    step 3 refuse — the projected refund 5,760 s out against a deadline a day away. The negotiation-time
    check ran the timelock ordering for a BTC counter leg only. It now runs step 3 and step 7 for every
    counter leg, from the clock the coordinator is built with:

    * t_rxd 160 is refused at construction, naming step 3 (it fails with nothing elapsed);
    * t_rxd that meets the deadline only with nothing elapsed is refused too — step 7 on the bound;
    * that plus the modelled bound constructs, and the coordinator's own step 3 and steps 6/7 then pass at
      ``now`` with the modelled maximum elapsed;
    * without a clock it is refused, naming ``now_unix_s``."""
    build, terms_at, reserve, floor, _chain = _eth_early_case(monkeypatch)
    e = reserve()
    assert e >= 1
    with pytest.raises(ValidationError, match=r"refused before anyone locks.*step 3.*refund could open too EARLY"):
        build(terms_at(160))
    with pytest.raises(ValidationError, match=r"refused before anyone locks.*step 7") as exc:
        build(terms_at(floor + e - 1))
    assert f"with {e} elapsed the timelock ordering fails" in str(exc.value), str(exc.value)
    terms = terms_at(floor + e)
    coord = build(terms)
    coord._assert_eth_timelock_ordering(terms, now_unix_s=_NOW)  # step 3
    assert coord._judge_remaining_window(terms, cov_confs=e, now_unix_s=_NOW) is None  # steps 6 and 7
    assert coord._judge_remaining_window(terms, cov_confs=e + 1, now_unix_s=_NOW) is not None  # tight
    with pytest.raises(ValidationError, match="refused before anyone locks.*pass now_unix_s"):
        build(terms, now=None)


def test_the_early_eth_check_also_refuses_step_3_alone(monkeypatch):
    """A deadline already past: the step-3 liveness floor refuses at construction (nothing below has a
    more specific reason, since the ordering trivially holds), naming step 3."""
    build, terms_at, reserve, floor, _chain = _eth_early_case(monkeypatch, deadline_s=-60)
    with pytest.raises(ValidationError, match=r"refused before anyone locks.*step 3"):
        build(terms_at(floor + reserve() + 100))


def test_an_eth_deadline_too_near_for_the_takers_gate_is_refused_when_the_coordinator_is_built(monkeypatch):
    """The deadline's liveness floor runs the other way from the ordering: a LATER clock is nearer the
    deadline. The taker's gate first accepts the funding once it is ``k`` deep — on the modelled honest
    chain ``k`` nominal spacings plus the bound's slack after the coordinator is built — so a deadline that
    clears the floor now but not then (``eth_swap_grief_run.py``'s old 1,800 s default) is refused at
    construction, naming that wait; a deadline that clears it then constructs. At ``pre_btc_lock_check``
    step 3b nothing is added: the funding already exists there, and step 3 judges the real clock."""
    from pyrxd.gravity.eth_rxd_timelock import assert_eth_deadline_is_claimable

    for deadline in (1800, 3600):
        build, terms_at, reserve, floor, _chain = _eth_early_case(monkeypatch, deadline_s=deadline)
        terms = terms_at(floor + reserve())
        with pytest.raises(ValidationError, match=r"first accept the funding about 5400 s from now.*too near") as exc:
            build(terms)
        assert "Negotiate a later counter-leg deadline" in str(exc.value)
        assert "Negotiate a longer t_rxd" not in str(exc.value)
    build, terms_at, reserve, floor, _chain = _eth_early_case(monkeypatch, deadline_s=7200)
    terms = terms_at(floor + reserve())
    coord = build(terms)
    # The same terms judged at step 3b (no wait added) pass, and the floor itself holds at the taker's time.
    assert coord._funding_proof_room_failure(terms, now_unix_s=_NOW) is None
    assert_eth_deadline_is_claimable(
        now_unix_s=_NOW + 5400,
        eth_timeout_unix_s=terms.eth_timeout_unix_s,
        margin=coord.config.margin_policy.cross_clock_margin,
    )


async def test_an_honest_eth_swap_passes_pre_btc_lock_check_with_its_clock(monkeypatch):
    """The other branch: an ETH swap on value-bearing Radiant, built with room for the bound, a real
    funding 100 blocks deep and the right clock passes ``pre_btc_lock_check`` end to end — step 3b
    judges the ETH ordering from the clock the call was handed, and never refuses it for want of one."""
    from pyrxd.gravity import swap_coordinator

    monkeypatch.setattr(swap_coordinator, "_monotonic", lambda: 0.0)
    build, terms_at, reserve, floor, _chain = _eth_early_case(monkeypatch)
    terms = terms_at(floor + reserve() + 200)
    coord = build(terms)
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is True, gate.reason
    assert coord.last_maker_funding is not None and coord.last_maker_funding.proved_depth >= 100


def test_the_early_check_runs_the_step_6_floor_on_the_bound_for_an_eth_swap(monkeypatch):
    """The step-6 floor on the bound, for an ETH counter leg: a small value constructs; a value whose
    modelled bound leaves t_rxd no room for a safe claim is refused at construction, naming step 6."""
    build, terms_at, reserve, floor, chain = _eth_early_case(monkeypatch, deadline_s=7200)
    terms = terms_at(floor + reserve() + 10)
    assert build(terms) is not None
    big = 150 * funding_spv.forged_confirmation_cost_floor_photons(chain)
    assert early_elapsed_blocks_upper(chain=chain, value_at_stake_photons=big, burial_blocks=1).elapsed_blocks_upper > (
        terms.t_rxd.value
    )
    with pytest.raises(ValidationError, match=r"refused before anyone locks.*step 6"):
        build(terms, value=big)


#: About three times the work of ``_HARD_BITS`` (its target is a third as large): the hardest header
#: of mainnet's shipped last interval carries 3.02× the checkpoint's work (at 465,703).
_HARDER_3X = 0x1F2AAAAA


def _honest(monkeypatch, *, value_rxd: int, interval_bits: int = _HARDER_3X, served_bits: dict | None = None):
    """An honest value-bearing chain for the early-vs-step-6 tests: checkpoints 0, 2 and 4 with a
    3×-work header at 3 in the last interval; the funding at block 15; blocks 300 s apart. Returns a
    builder ``(terms, confs, tip_time) -> view`` plus the policy and the ``k`` step 6 will require."""
    spk = b"\x51"

    def base_at(tip_time):
        return build_funding_chain(
            spk=spk, value=1, confs=4, bits=_HARD_BITS, bits_at={3: interval_bits}, tip_time=tip_time
        ).headers

    chain = _vb_chain(base_at(_NOW), (0, 2, 4))
    pow_limit = chain.pow_limit
    works = [radiant_header_work(h, pow_limit=pow_limit) for h in base_at(_NOW).values()]
    served = dict(served_bits or {})
    max_work = max(
        [
            *works,
            *(radiant_header_work(mine("00" * 32, b"\0" * 32, 0, b), pow_limit=pow_limit) for b in served.values()),
        ]
    )
    cost = block_subsidy_photons(15, chain) * (chain.newest_checkpoint_work // 16) // max_work
    value = value_rxd * PHOTONS_PER_RXD
    k, vt = required_funding_confirmations(
        value_bearing=True, burial_blocks=1, value_at_stake_photons=value, forged_confirmation_cost_photons=cost
    )
    policy = _vb_policy(value_at_risk_photons=value)

    def view_for(terms, *, confs, tip_time):
        top = 15 + confs - 1
        base = base_at(tip_time - 300 * (top - 4))
        installed = _vb_chain(base, (0, 2, 4))
        monkeypatch.setattr(funding_spv, "MAINNET_CHAIN", installed)
        c = build_funding_chain(
            spk=_covenant(terms),
            value=terms.radiant_amount,
            confs=confs,
            base=base,
            funding_height=15,
            bits=_HARD_BITS,
            bits_at={15 + i: b for i, b in served.items()},
            tip_time=tip_time,
        )
        return _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=confs, chain=c)

    monkeypatch.setattr(funding_spv, "MAINNET_CHAIN", chain)
    return view_for, policy, k, vt


def _boundary(view_for, policy, terms_at, lo=20, hi=6000) -> int:
    """The smallest t_rxd the early check accepts among those that pass step 3's own ordering."""
    probe_terms = terms_at(hi)
    probe, _b = _btc_coord(
        probe_terms,
        _real_leg(view_for(probe_terms, confs=10, tip_time=_NOW), network="bc"),
        policy=policy,
        accept_nondurable_seen=True,
    )
    return next(
        n
        for n in range(lo, hi)
        if _step3_passes(terms_at(n), policy) and probe._funding_proof_room_failure(terms_at(n)) is None
    )


@pytest.mark.parametrize("tip_age_s", [0, 1800, 3600])
async def test_the_early_check_is_at_least_as_strict_as_step_6_on_an_honest_chain(monkeypatch, tip_age_s):
    """The reviewer's probe (``test_probe_ceiling_gap.py``), turned into the property. On an honest
    chain — blocks 300 s apart, the last checkpoint interval holding a header with three times the
    checkpoint's work (as mainnet's does), the funding exactly the ``k`` step 6 requires deep, and the
    newest header up to ``early_slack_s`` (an hour) old — the smallest t_rxd the early check accepts
    PASSES step 6 and 7, and the early check's modelled bound is at least the gate's. One block
    shorter is refused at construction, before anyone locks."""
    view_for, policy, k, vt = _honest(monkeypatch, value_rxd=15_000)
    assert vt > MIN_FUNDING_CONFIRMATIONS, "the value term, not the floor, sets k here"

    def terms_at(n):
        return _wide_terms(n, t_btc_blocks=10)

    boundary = _boundary(view_for, policy, terms_at)
    short = terms_at(boundary - 1)
    assert _step3_passes(short, policy)
    with pytest.raises(ValidationError, match="refused before anyone locks"):
        _btc_coord(
            short,
            _real_leg(view_for(short, confs=k, tip_time=_NOW), network="bc"),
            policy=policy,
            accept_nondurable_seen=True,
        )

    at = terms_at(boundary)
    coord, btc_view = _btc_coord(
        at,
        _real_leg(view_for(at, confs=k, tip_time=_NOW - tip_age_s), network="bc"),
        policy=policy,
        accept_nondurable_seen=True,
    )
    gate = await coord.pre_btc_lock_check(at, now_unix_s=_NOW)
    assert gate.ok is True, gate.reason
    proof = coord.last_maker_funding
    assert (proof.required_confirmations, proof.proved_depth) == (k, k)
    early = early_elapsed_blocks_upper(
        chain=funding_spv.MAINNET_CHAIN, value_at_stake_photons=policy.value_at_risk_photons, burial_blocks=1
    )
    assert early.elapsed_blocks_upper >= proof.elapsed_blocks_upper
    assert btc_view.broadcasts == []


async def test_a_served_header_harder_than_the_work_margin_is_the_stated_gap(monkeypatch):
    """What the early check does NOT cover, pinned so the statement cannot go stale: it assumes no
    header served above the newest checkpoint carries more than ``early_work_margin`` (2×) the shipped
    interval's hardest. At the smallest t_rxd it accepts, a served header at 1.9× that still passes
    step 6; one at 8× lowers the gate's C to an eighth of the interval's, raises k in proportion, and
    step 6 refuses — the case the PR states as the remaining gap."""
    within = 0x1F166666  # about 1.9 × the 3×-header's work
    beyond = 0x1F055555  # about 8 ×
    for bits, ok in ((within, True), (beyond, False)):
        view_for, policy, k, _vt = _honest(monkeypatch, value_rxd=15_000, served_bits={2: bits})

        def terms_at(n):
            return _wide_terms(n, t_btc_blocks=10)

        at = terms_at(_boundary(view_for, policy, terms_at))
        coord, _btc_view = _btc_coord(
            at,
            _real_leg(view_for(at, confs=k, tip_time=_NOW), network="bc"),
            policy=policy,
            accept_nondurable_seen=True,
        )
        gate = await coord.pre_btc_lock_check(at, now_unix_s=_NOW)
        assert gate.ok is ok, (bits, gate.reason)


def _step3_passes(terms, policy) -> bool:
    from pyrxd.gravity.swap_coordinator import assert_timelock_margin

    try:
        assert_timelock_margin(terms.t_btc, terms.t_rxd, policy)
    except ValidationError:
        return False
    return True


async def test_pre_btc_lock_check_runs_the_same_check_on_the_terms_it_is_handed(monkeypatch):
    """The record's terms leave room; the terms handed to ``pre_btc_lock_check`` clear the negotiated
    ordering at step 3 and step 6's floor, but not the ordering once the modelled elapsed-depth bound
    is spent. Refused at step 3b, before the chain is read."""
    import dataclasses

    from pyrxd.btc_wallet import taproot as t

    base, chain = _value_bearing_chain(monkeypatch)
    early = early_elapsed_blocks_upper(chain=chain, value_at_stake_photons=_BIG, burial_blocks=1).elapsed_blocks_upper
    roomy = _wide_terms(early + 1000)
    view = _ChainView(
        pays=_covenant(roomy), value=roomy.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    coord, btc_view = _btc_coord(
        roomy, _real_leg(view, network="bc"), policy=_vb_policy(value_at_risk_photons=_BIG), accept_nondurable_seen=True
    )
    tight = dataclasses.replace(roomy, t_rxd=t.Timelock(early + 150, t.TimeUnit.BLOCKS))
    assert _step3_passes(tight, coord.config.margin_policy)
    gate = await coord.pre_btc_lock_check(tight, now_unix_s=_NOW)
    assert gate.ok is False
    assert "refused before anyone locks" in gate.reason and "step 7" in gate.reason, gate.reason
    assert view.reads == [] and btc_view.broadcasts == []


async def test_the_proved_bound_at_step_6_stays_authoritative(monkeypatch):
    """The negotiation-time check passes (a small value: k is the floor of 6), but the funding's
    newest header is twenty hours old, so the elapsed-depth upper bound is hundreds of blocks and
    step 6 refuses on the proof. Passing the early check decides nothing."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _vb_terms(400)
    view = _ChainView(
        pays=_covenant(terms),
        value=terms.radiant_amount,
        confs=6,
        base=base,
        bits=_HARD_BITS,
        tip_time=_NOW - 20 * 3600,
    )
    coord, btc_view = _btc_coord(terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True)
    assert coord._funding_proof_room_failure(terms) is None
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "can NEVER reach a safe claim" in gate.reason, gate.reason
    assert coord.last_maker_funding.elapsed_blocks_upper > 400
    assert "headers" in view.reads and btc_view.broadcasts == []


def test_a_maker_role_coordinator_is_not_refused_for_the_taker_gates_value_input(monkeypatch):
    """An ``ft`` swap has no in-protocol value. The taker gate needs one (it refuses at step 5 without
    it), so a coordinator that runs the gate — the legacy one-coordinator flow or a taker — is refused
    at construction; a MAKER-role coordinator never runs the taker gate and constructs."""
    import dataclasses

    from pyrxd.gravity.swap_state import SwapRole

    base, _chain = _value_bearing_chain(monkeypatch)
    terms = dataclasses.replace(_vb_terms(400), asset_variant="ft", genesis_ref=b"\x01" * 36)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    for role in (None, SwapRole.TAKER):
        with pytest.raises(ValidationError, match=r"refused before anyone locks.*taker gate this coordinator runs"):
            _btc_coord(
                terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True, role=role
            )
    coord, _b = _btc_coord(
        terms, _real_leg(view, network="bc"), policy=_vb_policy(), accept_nondurable_seen=True, role=SwapRole.MAKER
    )
    assert coord.record.state is SwapState.NEGOTIATED


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


async def test_step_7_judges_the_timelocks_on_the_elapsed_UPPER_bound(monkeypatch):
    """One block proved, but the newest header served is 30 blocks' worth of time old. The CSV
    window must be judged as if the blocks that time allows were mined — here that leaves too little
    margin, so the gate refuses; the SAME funding with a fresh tip passes. (The coordinator's read
    clock is held still, so ``now`` is exactly ``_NOW``.)"""
    from pyrxd.gravity import swap_coordinator

    monkeypatch.setattr(swap_coordinator, "_monotonic", lambda: 0.0)
    terms = _terms(variant="rxd")  # t_rxd 144, t_btc 24: ~24 Radiant blocks of elapsed slack
    stale = _coordinator(terms=terms, radiant_leg=_StaleTipLeg(tip_time=_NOW - 300 * 30))
    gate = await stale.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "REMAINING window" in gate.reason
    proof = stale.last_maker_funding
    assert proof.proved_depth == 1 and proof.elapsed_s == 9000
    assert proof.elapsed_blocks_upper == 1 + poisson_upper_quantile(90.0, proof.epsilon)

    fresh = _coordinator(terms=terms, radiant_leg=_StaleTipLeg(tip_time=_NOW))
    assert (await fresh.pre_btc_lock_check(terms, now_unix_s=_NOW)).ok is True


def _regtest_kw(spk):
    return dict(
        chain=funding_spv.REGTEST_CHAIN,
        expected_spk=spk,
        expected_value=1000,
        value_at_stake_photons=None,
        burial_blocks=1,
    )


def test_the_upper_bound_is_raised_by_a_report_and_never_lowered():
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=3, tip_time=_NOW)
    kw = _regtest_kw(spk)
    honest = verify_maker_funding(c.evidence(), now_unix_s=_NOW, **kw)
    assert honest.bound_term == "time"
    high = verify_maker_funding(c.evidence(reported_confirmations=50), now_unix_s=_NOW, **kw)
    assert (high.elapsed_blocks_upper, high.bound_term) == (50, "reported")
    low = verify_maker_funding(c.evidence(reported_confirmations=1), now_unix_s=_NOW, **kw)
    assert low.elapsed_blocks_upper == honest.elapsed_blocks_upper
    later = verify_maker_funding(c.evidence(), now_unix_s=_NOW + 3000, **kw)
    assert later.elapsed_s == honest.elapsed_s + 3000
    assert later.elapsed_blocks_upper == 3 + poisson_upper_quantile(3.0 * later.elapsed_s / 300, 1e-3)


def test_the_report_term_is_the_max_over_operators_and_a_lower_one_never_lowers_it():
    """Reports are grouped by operator: each operator's largest report counts, and the bound takes
    the largest over them. A second operator reporting LESS changes nothing; one reporting more
    raises the bound, and the result names the report term. With one operator configured the time
    term governs and the result says so."""
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=3, tip_time=_NOW)
    kw = _regtest_kw(spk)

    def run(*reports):
        return verify_maker_funding(c.evidence(reported_depths=tuple(reports)), now_unix_s=_NOW, **kw)

    one = run(("operator:radiantcore", 3))
    assert one.bound_term == "time" and one.reported_by_operator == (("operator:radiantcore", 3),)
    assert "with one operator configured, the time term is what stands" in one.bound_note
    lower = run(("operator:radiantcore", 3), ("operator:radiant4people", 1))
    assert lower.elapsed_blocks_upper == one.elapsed_blocks_upper and lower.bound_term == "time"
    assert "reports from 2 operators" in lower.bound_note and "one operator configured" not in lower.bound_note
    higher = run(("operator:radiantcore", 3), ("operator:radiant4people", 1), ("operator:radiant4people", 90))
    assert higher.reported_by_operator == (("operator:radiant4people", 90), ("operator:radiantcore", 3))
    assert (higher.elapsed_blocks_upper, higher.bound_term) == (90, "reported")


async def test_the_leg_reports_each_configured_source_by_its_operator():
    """``RadiantChainIO`` asks the client, the proof client and every extra depth source once each,
    takes each one's larger of ``confirmations`` and ``tip - H + 1``, and labels it by ``source_key``."""
    from pyrxd.network.source_identity import source_key

    class _Src:
        def __init__(self, url, confs, tip):
            self.source_key = source_key(url)
            self._confs, self._tip = confs, tip

        async def get_transaction_verbose(self, txid):
            return {"txid": txid, "confirmations": self._confs}

        async def get_tip_height(self):
            return self._tip

        async def broadcast(self, raw):  # pragma: no cover
            raise AssertionError

        async def get_utxos(self, sh):  # pragma: no cover
            return []

    a = _Src("wss://electrumx.radiantcore.org/", 5, 104)  # tip-derived 5 at H=100
    b = _Src("wss://electrumx.radiant4people.com:50022/", 2, 120)  # tip-derived 21
    io = RadiantChainIO(a, proof_client=a, depth_sources=(b,))
    got = await io.reported_depths("ab" * 32, 100)
    assert got == (("operator:radiantcore", 5), ("operator:radiant4people", 21))


async def test_a_server_that_stops_serving_early_is_still_bounded(monkeypatch):
    """Withholding: the chain really has 30 blocks on the funding, all fresh; a server serves only
    the first 12. The median time past it hands over is older by the withheld blocks' time, so the
    time term still covers the real depth."""
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    real = build_funding_chain(spk=spk, value=1000, confs=30, bits=_HARD_BITS, tip_time=_NOW)
    chain = _vb_chain(real.headers, (0, 2, 4))
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6, value_at_stake_photons=10**11)
    full = verify_maker_funding(real.evidence(), now_unix_s=_NOW, **kw)
    cut = verify_maker_funding(real.evidence(drop_above=real.height + 11), now_unix_s=_NOW, **kw)
    assert cut.proved_depth == 12 and full.proved_depth == 30
    assert cut.elapsed_s >= full.elapsed_s + 18 * 300
    assert cut.elapsed_blocks_upper >= full.proved_depth, "the withheld blocks are not covered"
    assert cut.bound_term == "time"


def test_one_header_stamped_later_than_its_neighbours_moves_the_bound_by_at_most_one_interval():
    """For each header of the reference header's 11-header window in turn — the reference itself
    included — stamp it two hours later than the honest chain has it. The median moves by at most one
    position of the sorted window, i.e. one 300 s interval here, so the bound is never below the
    honest chain's by more than ``blocks_upper(E) - blocks_upper(E - 300)``."""
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    honest_chain = build_funding_chain(spk=spk, value=1000, confs=40, bits=_HARD_BITS, tip_time=_NOW - 600)
    chain = _vb_chain(honest_chain.headers, (0, 2, 4))
    value = 10_000 * PHOTONS_PER_RXD
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6, value_at_stake_photons=value)
    honest = verify_maker_funding(_two_operators(honest_chain.evidence()), now_unix_s=_NOW, **kw)
    ref = honest.reference_height
    policy = ElapsedBoundPolicy()
    tol = honest.time_blocks - policy.blocks_upper(honest.elapsed_s - 300, spacing_s=300, value_at_stake_photons=value)
    assert 0 < tol <= 4
    for h in range(ref - 10, ref + 1):
        c = build_funding_chain(
            spk=spk,
            value=1000,
            confs=40,
            bits=_HARD_BITS,
            tip_time=_NOW - 600,
            time_at={h: _time(honest_chain.headers[h]) + 7200},
        )
        r = verify_maker_funding(
            _two_operators(c.evidence()), now_unix_s=_NOW, **{**kw, "chain": _vb_chain(c.headers, (0, 2, 4))}
        )
        assert r.reference_height == ref
        assert r.elapsed_blocks_upper >= honest.elapsed_blocks_upper - tol, h


def _reference_depth_case():
    """Checkpoints at 0, 2 and 4 (mainnet schedule, floor-bearing bits), then a funding at block 5
    buried 10 deep whose newest header is six hours old; the checkpoint headers ten days older."""
    base = build_funding_chain(spk=b"\x51", value=1, confs=4, bits=_HARD_BITS, tip_time=_NOW - 10 * 86400).headers
    chain = _vb_chain(base, (0, 2, 4))
    spk = b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    real = build_funding_chain(spk=spk, value=1000, confs=10, base=base, bits=_HARD_BITS, tip_time=_NOW - 6 * 3600)
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6)
    return real, kw


def _mtp_at(headers, ref):
    return median_time_past([_time(headers[h]) for h in range(max(0, ref - 10), ref + 1)])


def test_the_reference_time_comes_from_a_header_at_depth_value_term():
    """The time term is measured from the median time past at the header ``max(1, value term)`` deep
    below the newest one served — the depth at which changing any header of its window costs
    ``value term × C``, at least twice the value at stake — not from the newest header. Serving one
    more header on top moves the reference up by exactly one."""
    real, kw = _reference_depth_case()
    first = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=1, **kw)
    cost = first.forged_confirmation_cost_photons
    value = 2 * cost  # value term ceil(2 × 2C ÷ C) = 4
    r = verify_maker_funding(_two_operators(real.evidence()), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert r.value_term == 4 and r.value_term * cost >= FORGERY_COST_FACTOR * value
    assert r.reference_height == r.served_tip - r.value_term + 1 == 11
    assert r.reference_time == _mtp_at(real.headers, 11)
    expected = poisson_upper_quantile(3.0 * (_NOW - r.reference_time) / 300, r.epsilon)
    assert r.time_blocks == expected
    assert r.elapsed_blocks_upper == (11 - real.height + 1) + expected

    hdrs = dict(real.headers)
    top = max(hdrs)
    hdrs[top + 1] = mine(radiant_block_hash(hdrs[top]), hashlib.sha256(b"one more").digest(), _NOW, _HARD_BITS)
    s = verify_maker_funding(
        _two_operators(real.evidence(headers=hdrs)), now_unix_s=_NOW, value_at_stake_photons=value, **kw
    )
    assert s.served_tip == top + 1 and s.proved_depth == r.proved_depth + 1
    assert s.reference_height == 12, "the reference moved by more than the one header added"
    assert s.reference_time == _mtp_at(real.headers, 12)


def test_a_value_term_of_one_references_the_newest_header():
    """When one forged confirmation already costs twice the value (value term 1) the reference is the
    newest header served, exactly as on a test network — no honest swap is charged more time."""
    real, kw = _reference_depth_case()
    r = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=1000, **kw)
    assert r.value_term == 1 and r.forged_confirmation_cost_photons >= FORGERY_COST_FACTOR * 1000
    assert r.reference_height == r.served_tip
    assert r.reference_time == _mtp_at(real.headers, r.served_tip)


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


class _Clock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class _SlowSecondProof(_StaleTipLeg):
    """An honest leg whose SECOND evidence fetch — the lock-time re-run inside ``taker_funds_btc`` —
    takes ``delay`` seconds of the coordinator's monotonic clock."""

    def __init__(self, *, clock: _Clock, delay: int, tip_time: int) -> None:
        super().__init__(tip_time=tip_time)
        self.clock, self.delay, self.proofs = clock, delay, 0

    async def maker_funding_evidence(self, terms, **kw):
        self.proofs += 1
        if self.proofs == 2:
            self.clock.t += self.delay
        return await super().maker_funding_evidence(terms, **kw)


async def _fresh_gate_refusal_delay(build, terms, *, hi: int = 20_000) -> int:
    """The smallest delay (s) after ``_NOW`` at which a FRESH ``pre_btc_lock_check`` refuses this swap
    at step 6 or 7 — found by bisection against the real gate, never typed."""

    async def ok(delay):
        coord = build(_StaleTipLeg(tip_time=_NOW))
        return (await coord.pre_btc_lock_check(terms, now_unix_s=_NOW + delay)).ok

    lo = 0
    assert await ok(lo) and not await ok(hi), "the swap must pass now and be refused later"
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if await ok(mid):
            lo = mid
        else:
            hi = mid
    coord = build(_StaleTipLeg(tip_time=_NOW))
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW + hi)
    assert "REMAINING window" in gate.reason or "safe claim" in gate.reason, gate.reason
    return hi


async def test_the_lock_time_rerun_judges_steps_6_and_7_on_its_own_bound(monkeypatch, tmp_path):
    """The lock-time re-run's elapsed-depth bound used to be DISCARDED: the gate inside
    ``taker_funds_btc`` judged steps 6 and 7 on the first read's bound, and the re-run — which reads
    later, so its bound can be larger — only had to prove the funding exists. Measured on the code
    that shipped: a re-run read that took as long as it takes a fresh gate to refuse this swap
    (1,165 s for the BTC case) still FUNDED.

    Driven through every public entry point that reaches ``fund`` (BTC and ETH ``taker_funds_btc``,
    ETH ``resume_interrupted_fund``): the first proof is instant and passes, the re-run's read takes
    exactly the delay at which a fresh gate refuses, and the counter leg is never funded. The same
    swap with the re-run one second faster than that locks, so the refusal is the window and not the
    fixture."""
    import dataclasses

    from pyrxd.gravity import swap_coordinator
    from pyrxd.gravity.record_sink import JsonFileRecordSink

    clock = _Clock()
    monkeypatch.setattr(swap_coordinator, "_monotonic", clock)

    btc_terms = _terms(variant="rxd")
    _p = os.urandom(32)
    eth_terms = _eth_terms(hashlock=hashlib.sha256(_p).digest())

    def btc_build(leg, btc=None):
        return _coordinator(terms=btc_terms, btc_leg=btc or FakeBtcLeg(), radiant_leg=leg)

    def eth_build(leg, eth=None, **kw):
        return _eth_coord_full(
            terms=eth_terms, eth_leg=eth or FakeEthLeg(preimage=_p, verdict=_final()), radiant_leg=leg, **kw
        )

    async def btc_fund(delay):
        btc = FakeBtcLeg()
        leg = _SlowSecondProof(clock=clock, delay=delay, tip_time=_NOW)
        coord = btc_build(leg, btc)
        return leg, btc, coord, coord.taker_funds_btc(btc_terms, now_unix_s=_NOW)

    async def eth_fund(delay):
        eth = FakeEthLeg(preimage=_p, verdict=_final())
        leg = _SlowSecondProof(clock=clock, delay=delay, tip_time=_NOW)
        coord = eth_build(leg, eth)
        return leg, eth, coord, coord.taker_funds_btc(eth_terms, now_unix_s=_NOW)

    async def eth_resume(delay):
        sink = JsonFileRecordSink(tmp_path / f"swap-{delay}-{os.urandom(4).hex()}.json")
        await sink(
            dataclasses.replace(
                SwapRecord(state=SwapState.NEGOTIATED, terms=eth_terms),
                pending_counter_contract="0x" + "ab" * 20,
                pending_counter_deploy_tx="0x" + "cd" * 32,
            )
        )
        seen = FakeSeenStore()
        seen.reserve(eth_terms.hashlock)
        eth = FakeEthLeg(preimage=_p, verdict=_final())
        leg = _SlowSecondProof(clock=clock, delay=delay, tip_time=_NOW)
        coord = eth_build(leg, eth, seen_store=seen, fund_lock=_MemLock())
        return leg, eth, coord, coord.resume_interrupted_fund(eth_terms, sink=sink, now_unix_s=_NOW)

    cases = {
        "taker_funds_btc (btc)": (btc_build, btc_terms, btc_fund),
        "taker_funds_btc (eth)": (eth_build, eth_terms, eth_fund),
        "resume_interrupted_fund (eth)": (eth_build, eth_terms, eth_resume),
    }
    assert {name.split(" ")[0] for name in cases} == _coordinator_entry_points_that_fund()
    for name, (build, terms, drive) in cases.items():
        refuse_at = await _fresh_gate_refusal_delay(build, terms)

        leg, counter, coord, run = await drive(refuse_at)
        with pytest.raises(ValidationError, match="lock-time re-run refused funding") as exc:
            await run
        assert leg.proofs == 2, (name, leg.proofs)
        assert "fund" not in counter.calls, f"{name}: funded on a window a fresh gate refuses"
        assert "REMAINING window" in str(exc.value) or "safe claim" in str(exc.value), (name, str(exc.value))
        assert coord.last_maker_funding.elapsed_s >= refuse_at, name

        # Honest path: one second faster and the same swap locks.
        leg, counter, coord, run = await drive(refuse_at - 1)
        await run
        assert leg.proofs == 2 and "fund" in counter.calls, name


# --------------------------------------------------------------------------- (g) two operators above dust

#: The shipped mainnet endpoints, grouped by operator (``source_key``) — derived, never typed.
_SHIPPED_BY_OPERATOR: dict[str, list[str]] = {}
for _url in DEFAULT_ENDPOINTS["mainnet"]:
    _SHIPPED_BY_OPERATOR.setdefault(str(source_key(_url)), []).append(_url)

_ABOVE_DUST = ElapsedBoundPolicy().dust_threshold_photons + 1


def _dust_case(monkeypatch):
    base, chain = _value_bearing_chain(monkeypatch)
    spk = b"\x76\xa9" + bytes(32)
    c = build_funding_chain(spk=spk, value=1000, confs=40, base=base, bits=_HARD_BITS, tip_time=_NOW)
    kw = dict(chain=chain, expected_spk=spk, expected_value=1000, burial_blocks=6, now_unix_s=_NOW)
    return c, kw


def test_above_dust_the_gate_refuses_unless_two_distinct_operators_report_the_depth(monkeypatch):
    """The rule, at the gate: above ``dust_threshold_photons`` on a value-bearing network, reports
    from fewer than two distinct operators refuse, naming how many answered and which (and which
    configured ones did not); two pass. An unidentified source, a zero report and a second server of
    the same operator are not a second operator. At the threshold one operator suffices, and the
    result says the time term may govern."""
    c, kw = _dust_case(monkeypatch)
    a, b = (str(k) for k in _SHIPPED_OPERATORS[:2])
    depth = max(c.headers) - c.height + 1

    def run(reports, value=_ABOVE_DUST, configured=(a, b), **extra):
        ev = c.evidence(
            reported_depths=tuple(reports), funding_tx_depths=tuple(reports), configured_operators=configured
        )
        return verify_maker_funding(ev, value_at_stake_photons=value, **kw, **extra)

    for reports in (
        [],
        [(a, depth)],
        [(a, depth), (a, depth - 1)],
        [(a, depth), ("unidentified source #1 (_Src)", depth)],
        [(a, depth), (b, 0)],
    ):
        with pytest.raises(MakerFundingNotVerified) as exc:
            run(reports)
        msg = str(exc.value)
        answered = 1 if reports else 0
        assert f"at least 2 distinct operators; {answered} answered" in msg, msg
        if answered:
            assert f"({a})" in msg and f"{b} did not" in msg, msg
        assert "above the dust threshold" in msg and f"{_ABOVE_DUST} photons" in msg, msg

    ok = run([(a, depth), (b, depth)])
    assert ok.reporting_operators == (a, b) and ok.reporting_operators_required == 2
    assert "2 distinct operators reported the funding transaction, 2 required above the dust threshold" in ok.bound_note

    # At the threshold: one operator suffices, and the result says the time term may govern.
    at = run([(a, depth)], value=_ABOVE_DUST - 1)
    assert at.reporting_operators_required == 0
    assert "at or below the dust threshold" in at.bound_note and "time term may govern" in at.bound_note
    # The threshold is policy: raised, the same value proceeds on one operator.
    raised = run([(a, depth)], bound_policy=ElapsedBoundPolicy(dust_threshold_photons=_ABOVE_DUST))
    assert raised.reporting_operators_required == 0
    # A test network has no value to protect: no operator count.
    reg = verify_maker_funding(
        build_funding_chain(spk=kw["expected_spk"], value=1000, confs=3, tip_time=_NOW).evidence(),
        now_unix_s=_NOW,
        **{**_regtest_kw(kw["expected_spk"]), "value_at_stake_photons": 10**15},
    )
    assert reg.reporting_operators_required == 0


def _operator_leg(chain_io) -> RadiantCovenantLeg:
    return RadiantCovenantLeg(
        network="bc",
        taker_pkh=A._TAKER_PKH,
        maker_pkh=A._MAKER_PKH,
        chain_io=chain_io,
        fee_source=A._FeeSource(),
        min_confirmations=1,
    )


def _build_with(chain_io, value):
    terms = _wide_terms(3000)
    return _btc_coord(
        terms,
        _operator_leg(chain_io),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )


def test_the_coordinator_refuses_before_anyone_locks_a_config_with_fewer_than_two_operators_above_dust():
    """Construction, on the real shipped mainnet chain data, with real clients (nothing connects):

    * pyrxd's shipped mainnet endpoints, as one client — two operators — construct above dust;
    * the user's own loopback node plus one public operator construct above dust;
    * two servers of ONE operator (as two clients) are refused above dust, naming it;
    * the same one-operator config constructs at dust."""
    shipped = RadiantChainIO(ElectrumXClient(urls=list(DEFAULT_ENDPOINTS["mainnet"])))
    assert len(funding_spv.counted_operators(shipped.configured_depth_operators())) >= 2
    assert _build_with(shipped, 10_000 * PHOTONS_PER_RXD)[0] is not None

    public = next(iter(_SHIPPED_BY_OPERATOR.values()))[0]
    own = RadiantChainIO(
        ElectrumXClient(["ws://127.0.0.1:50001"], allow_insecure=True), depth_sources=(ElectrumXClient([public]),)
    )
    assert own.configured_depth_operators() == ("localhost", str(source_key(public)))
    assert _build_with(own, 10_000 * PHOTONS_PER_RXD)[0] is not None

    op, urls = next((k, v) for k, v in _SHIPPED_BY_OPERATOR.items() if len(v) >= 2)
    one = RadiantChainIO(ElectrumXClient([urls[0]]), depth_sources=(ElectrumXClient([urls[1]]),))
    assert one.configured_depth_operators() == (op,)
    with pytest.raises(ValidationError) as exc:
        _build_with(one, 10_000 * PHOTONS_PER_RXD)
    msg = str(exc.value)
    assert "refused before anyone locks" in msg and "at least 2 distinct operators" in msg, msg
    assert f"configured to ask 1: {op}" in msg, msg
    assert _build_with(one, ElapsedBoundPolicy().dust_threshold_photons)[0] is not None


async def test_step_5_refuses_when_only_one_of_two_configured_operators_answers(monkeypatch):
    """Through the production path (``pre_btc_lock_check`` → the real leg → ``RadiantChainIO``): two
    operators configured, so the swap constructs; at the lock one of them does not answer, and the
    gate refuses naming who answered and who did not. When both answer, it locks."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=70, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    value = 10_000 * PHOTONS_PER_RXD

    class _Silent(_DepthReader):
        async def get_transaction_verbose(self, txid):
            raise NetworkError("unreachable")

    silent = _Silent(view)
    coord, btc_view = _btc_coord(
        terms,
        _real_leg(view, network="bc", depth_sources=(silent,)),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert f"1 answered ({view.source_key}), and {silent.source_key} did not" in gate.reason, gate.reason
    assert btc_view.broadcasts == []

    coord, _ = _btc_coord(
        terms,
        _real_leg(view, network="bc"),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )
    assert (await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)).ok is True
    assert coord.last_maker_funding.reporting_operators == (str(view.source_key), str(_SHIPPED_OPERATORS[1]))


class _TipOnly(_DepthReader):
    """A second operator that does not know the funding transaction — its verbose read fails, as
    ElectrumX answers a txid it has never seen — but answers its tip height, which can be anything."""

    def __init__(self, view, *, tip, key=_SHIPPED_OPERATORS[1]):
        super().__init__(view, key=key)
        self.tip = tip

    async def get_transaction_verbose(self, txid):
        raise NetworkError("No such mempool or blockchain transaction")

    async def get_tip_height(self):
        return self.tip


async def test_a_tip_height_alone_is_not_an_operator_reporting_the_funding(monkeypatch):
    """The two-operator rule counted an operator whose verbose read of the funding FAILED, through
    its tip height: ``tip - H + 1`` is a number for any txid, real or not, so "two operators report
    the depth" held with one operator knowing nothing about the funding.

    Now: through the real leg and ``RadiantChainIO``, an operator that answers only its tip is in
    the bound's reports and not among the operators counted, so above dust the gate refuses and
    names it; the same operator answering the verbose read is counted and the swap locks; and a
    tip-only report still RAISES the bound, at dust, where one operator suffices."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=70, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    tip = view.chain.top

    def coord_for(depth_source, value):
        return _btc_coord(
            terms,
            _real_leg(view, network="bc", depth_sources=(depth_source,)),
            policy=_vb_policy(value_at_risk_photons=value),
            accept_nondurable_seen=True,
        )

    # The leg keeps the two kinds of report apart.
    io = RadiantChainIO(view, depth_sources=(_TipOnly(view, tip=tip),))
    got = await io.depth_reports(view.chain.txid, view.chain.height)
    b = str(_SHIPPED_OPERATORS[1])
    assert dict(got.reported)[b] == tip - view.chain.height + 1
    assert b not in dict(got.funding_tx) and dict(got.funding_tx) == {str(view.source_key): view.confs}

    above = 10_000 * PHOTONS_PER_RXD
    coord, btc_view = coord_for(_TipOnly(view, tip=tip), above)
    gate = await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert f"1 answered ({view.source_key}), and {b} did not" in gate.reason, gate.reason
    assert f"{b} gave only a tip height" in gate.reason, gate.reason
    assert btc_view.broadcasts == []

    # Honest path: the same operator answering the funding transaction's verbose read counts.
    coord, _ = coord_for(_DepthReader(view), above)
    assert (await coord.pre_btc_lock_check(terms, now_unix_s=_NOW)).ok is True
    assert coord.last_maker_funding.reporting_operators == (str(view.source_key), b)

    # A tip-only report still raises the bound (it can only raise it): at dust, one operator suffices.
    dust = ElapsedBoundPolicy().dust_threshold_photons
    coord, _ = coord_for(_TipOnly(view, tip=tip + 500), dust)
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    proof = coord.last_maker_funding
    assert proof.reporting_operators == (str(view.source_key),)
    assert (proof.elapsed_blocks_upper, proof.bound_term) == (tip + 500 - view.chain.height + 1, "reported")
    assert f"of which {b} gave only a tip height" in proof.bound_note, proof.bound_note


class _NamesTx(_DepthReader):
    """A second operator whose verbose reply carries *names* as its own ``txid`` field (``None``: absent)."""

    def __init__(self, view, *, names):
        super().__init__(view)
        self.names = names

    async def get_transaction_verbose(self, txid):
        reply = {"confirmations": self._view.confs}
        if self.names is not None:
            reply["txid"] = self.names(txid) if callable(self.names) else self.names
        return reply


async def test_a_verbose_reply_that_names_another_transaction_is_not_a_report_of_this_one(monkeypatch):
    """The verbose reply's own ``txid`` field was never compared with the txid asked about, so a source
    could answer with ANOTHER transaction's confirmations and be counted as an operator reporting this
    funding. Through the real leg: a reply naming a different txid, one with no ``txid`` field, and ones
    whose field is not 64 hex characters are not counted (above dust the gate refuses, naming the
    operator as having given only a tip height when it gave one); the same reply naming this txid — in
    either case — is counted and the swap locks."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=70, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    b = str(_SHIPPED_OPERATORS[1])
    above = 10_000 * PHOTONS_PER_RXD

    async def gate_with(names):
        coord, btc_view = _btc_coord(
            terms,
            _real_leg(view, network="bc", depth_sources=(_NamesTx(view, names=names),)),
            policy=_vb_policy(value_at_risk_photons=above),
            accept_nondurable_seen=True,
        )
        return await coord.pre_btc_lock_check(terms, now_unix_s=_NOW), coord, btc_view

    other = os.urandom(32).hex()
    for names in (other, None, lambda t: t[:-1], lambda t: t + "00", lambda t: t[:-1] + "g", 7):
        gate, _coord, btc_view = await gate_with(names)
        assert gate.ok is False, names
        assert f"1 answered ({view.source_key}), and {b} did not" in gate.reason, gate.reason
        assert btc_view.broadcasts == []
    for names in (lambda t: t, lambda t: t.upper()):
        gate, coord, _ = await gate_with(names)
        assert gate.ok is True, gate.reason
        assert coord.last_maker_funding.reporting_operators == (str(view.source_key), b)


async def test_a_client_over_several_operators_is_asked_once_per_operator(monkeypatch):
    """An ``ElectrumXClient`` over pyrxd's shipped mainnet endpoints races them, so one reply cannot
    say which operator sent it: ``RadiantChainIO`` asks one client per operator group instead, labels
    each by its ``source_key``, and closes them."""
    closed: list[tuple[str, ...]] = []
    depth_of = {op: 10 + i for i, op in enumerate(_SHIPPED_BY_OPERATOR)}

    async def verbose(self, txid):
        (op,) = {str(source_key(u)) for u in self._urls}  # a split client is ONE operator
        return {"confirmations": depth_of[op]}

    async def tip(self):
        (op,) = {str(source_key(u)) for u in self._urls}
        return 100 + depth_of[op] - 1

    async def close(self):
        closed.append(tuple(self._urls))

    async def no_network(self, *a, **k):  # pragma: no cover - reached only if a read is not faked
        raise AssertionError("the test reached the network")

    monkeypatch.setattr(ElectrumXClient, "_call", no_network)
    monkeypatch.setattr(ElectrumXClient, "get_tip_height", tip)
    monkeypatch.setattr(ElectrumXClient, "get_transaction_verbose", verbose)
    monkeypatch.setattr(ElectrumXClient, "close", close)
    client = ElectrumXClient(urls=list(DEFAULT_ENDPOINTS["mainnet"]))
    assert client.source_key is None and tuple(map(str, client.source_keys)) == tuple(_SHIPPED_BY_OPERATOR)
    got = await RadiantChainIO(client).reported_depths("ab" * 32, 100)
    assert got == tuple(depth_of.items())
    assert sorted(closed) == sorted(tuple(v) for v in _SHIPPED_BY_OPERATOR.values())


def _exact_log_tail(mean: float, n: int):
    """``log P(Poisson(mean) > n)`` by a 60-digit summation of the pmf from 0, as a ``Decimal``."""
    from decimal import MAX_EMAX, MIN_EMIN, Decimal, localcontext

    with localcontext() as ctx:
        ctx.prec, ctx.Emax, ctx.Emin = 60, MAX_EMAX, MIN_EMIN
        m = Decimal(repr(mean))
        term = (-m).exp()
        cdf = term
        for j in range(1, n + 1):
            term = term * m / j
            cdf += term
        # The upper part directly, so a tail far below 1 keeps all 60 digits.
        tail, j = Decimal(0), n + 1
        term = term * m / j if n >= 0 else term
        while True:
            tail += term
            j += 1
            term = term * m / j
            if j > m and term < tail * Decimal(10) ** -40:
                return (tail + term).ln()


@pytest.mark.parametrize("mean", [0.5, 30.0, 3_000.0, 100_000.0])
def test_the_log_tail_error_stays_far_inside_the_quantile_margin(mean):
    """``_log_poisson_tail`` against an exact 60-digit log-tail, below, at and far above the mean:
    its floating-point error is under a hundredth of ``_QUANTILE_LOG_MARGIN``, the margin that makes
    :func:`poisson_upper_quantile` conservative.

    NOT PINNED, by measurement: the geometric remainder the function adds once the terms fall below
    1e-17 of the sum. Against a 60-digit tail it moves the result by at most 4e-15 (at a mean of
    1e7), seven orders below the function's own rounding error there (3.3e-8), so no comparison with
    an exact tail can see it; dropping it was a plant that survived, and still does."""
    import math

    sd = math.sqrt(mean)
    for n in sorted({max(-1, int(mean - 3 * sd)), int(mean), int(mean + 3 * sd), int(mean + 20 * sd + 10)}):
        exact = float(_exact_log_tail(mean, n))
        got = funding_spv._log_poisson_tail(mean, n)
        assert abs(got - exact) <= funding_spv._QUANTILE_LOG_MARGIN / 100, (mean, n, got, exact)


# --------------------------------------------------------------------------- (g) the user override

_RXD = PHOTONS_PER_RXD
_DEFAULT_THRESHOLD = ElapsedBoundPolicy().dust_threshold_photons


def _statement(up_to_rxd: str, default_rxd: str = "1000") -> str:
    return f"single-operator depth accepted up to {up_to_rxd} RXD by user override (default {default_rxd} RXD)"


@pytest.mark.parametrize("bad", [-1, -(10**9), True, False, 1.5, 1000.0, "1000", b"1"])
def test_the_single_operator_override_refuses_nonsense_at_construction(bad):
    with pytest.raises(
        ValidationError, match="accept_single_operator_up_to_photons must be None or a non-negative int"
    ):
        ElapsedBoundPolicy(accept_single_operator_up_to_photons=bad)


def test_the_override_defaults_to_none_and_changes_nothing_unset():
    p = ElapsedBoundPolicy()
    assert _DEFAULT_THRESHOLD == 1_000 * _RXD  # the shipped default, unchanged
    assert p.accept_single_operator_up_to_photons is None
    assert p.single_operator_threshold_photons == _DEFAULT_THRESHOLD
    assert p.single_operator_override_statement() is None and not p.single_operator_threshold_raised
    zero = ElapsedBoundPolicy(accept_single_operator_up_to_photons=0)
    assert zero.single_operator_threshold_photons == 0
    assert zero.single_operator_override_statement() == _statement("0")


def _one_operator_run(monkeypatch, *, value, policy):
    c, kw = _dust_case(monkeypatch)
    a, b = (str(k) for k in _SHIPPED_OPERATORS[:2])
    depth = max(c.headers) - c.height + 1
    ev = c.evidence(reported_depths=((a, depth),), funding_tx_depths=((a, depth),), configured_operators=(a, b))
    return lambda: verify_maker_funding(ev, value_at_stake_photons=value, bound_policy=policy, **kw)


def test_without_the_override_the_gate_is_unchanged_and_says_nothing_of_one(monkeypatch, caplog):
    ok = _one_operator_run(monkeypatch, value=_DEFAULT_THRESHOLD, policy=ElapsedBoundPolicy())()
    assert ok.single_operator_override is None and ok.single_operator_threshold_photons == _DEFAULT_THRESHOLD
    assert "user override" not in ok.bound_note
    with pytest.raises(MakerFundingNotVerified) as exc:
        _one_operator_run(monkeypatch, value=_DEFAULT_THRESHOLD + 1, policy=ElapsedBoundPolicy())()
    # The refusal names the override and what it gives up — and, unset, no "currently".
    msg = str(exc.value)
    assert "accept_single_operator_up_to_photons" in msg and "--accept-single-operator-up-to" in msg, msg
    assert "you then rely on that one operator for the funding's depth" in msg, msg
    assert "currently" not in msg, msg
    assert not [r for r in caplog.records if "user override" in r.getMessage()]


def test_an_override_above_the_value_accepts_one_operator_warns_and_states_it(monkeypatch, caplog):
    value = 10_000 * _RXD
    policy = ElapsedBoundPolicy(accept_single_operator_up_to_photons=20_000 * _RXD)
    with caplog.at_level("WARNING", logger="pyrxd.gravity.funding_spv"):
        ok = _one_operator_run(monkeypatch, value=value, policy=policy)()
    assert ok.reporting_operators_required == 0 and len(ok.reporting_operators) == 1
    assert ok.single_operator_threshold_photons == 20_000 * _RXD
    assert ok.single_operator_override == _statement("20000")
    assert _statement("20000") in ok.bound_note, ok.bound_note
    warned = [r for r in caplog.records if r.levelname == "WARNING" and _statement("20000") in r.getMessage()]
    assert len(warned) == 1, [r.getMessage() for r in caplog.records]
    assert "10000 RXD" in warned[0].getMessage()  # the value at stake, stated


def test_an_override_below_the_value_still_refuses_and_names_the_override(monkeypatch):
    policy = ElapsedBoundPolicy(accept_single_operator_up_to_photons=5_000 * _RXD)
    with pytest.raises(MakerFundingNotVerified) as exc:
        _one_operator_run(monkeypatch, value=10_000 * _RXD, policy=policy)()
    msg = str(exc.value)
    assert "at least 2 distinct operators; 1 answered" in msg, msg
    assert f"dust threshold ({5_000 * _RXD} photons)" in msg, msg
    assert f"currently {_statement('5000')}" in msg, msg


def test_lowering_the_threshold_refuses_a_previously_dust_swap_on_one_operator(monkeypatch, caplog):
    value = 500 * _RXD
    assert _one_operator_run(monkeypatch, value=value, policy=ElapsedBoundPolicy())().reporting_operators_required == 0
    lowered = ElapsedBoundPolicy(accept_single_operator_up_to_photons=100 * _RXD)
    with caplog.at_level("WARNING", logger="pyrxd.gravity.funding_spv"):
        with pytest.raises(MakerFundingNotVerified) as exc:
            _one_operator_run(monkeypatch, value=value, policy=lowered)()
        assert f"currently {_statement('100')}" in str(exc.value)
        # Recorded, but not warned: lowering asks MORE of the funding.
        ok = _one_operator_run(monkeypatch, value=100 * _RXD, policy=lowered)()
    assert ok.single_operator_override == _statement("100") and _statement("100") in ok.bound_note
    assert not [r for r in caplog.records if r.levelname == "WARNING"], [r.getMessage() for r in caplog.records]


def test_the_early_check_honours_and_names_the_override():
    """At construction, before anyone locks: a one-operator configuration above the default is
    refused naming the override; with the override above the value it constructs; with the override
    below the value it is refused, and the refusal says what the override currently is."""
    _op, urls = next((k, v) for k, v in _SHIPPED_BY_OPERATOR.items() if len(v) >= 2)
    one = RadiantChainIO(ElectrumXClient([urls[0]]), depth_sources=(ElectrumXClient([urls[1]]),))
    value = 10_000 * PHOTONS_PER_RXD

    def build(policy):
        return _btc_coord(
            _wide_terms(3000),
            _operator_leg(one),
            policy=_vb_policy(value_at_risk_photons=value),
            accept_nondurable_seen=True,
            funding_bound=policy,
        )

    with pytest.raises(ValidationError) as exc:
        build(ElapsedBoundPolicy())
    msg = str(exc.value)
    assert "refused before anyone locks" in msg and "--accept-single-operator-up-to" in msg, msg
    assert "you then rely on that one operator for the funding's depth" in msg, msg
    assert build(ElapsedBoundPolicy(accept_single_operator_up_to_photons=value))[0] is not None
    with pytest.raises(ValidationError) as exc:
        build(ElapsedBoundPolicy(accept_single_operator_up_to_photons=value - 1))
    assert "currently single-operator depth accepted up to 9999.99999999 RXD by user override" in str(exc.value)


async def test_the_durable_record_carries_the_override_statement(monkeypatch):
    """Through the production path (``taker_funds_btc`` → the real leg → the gate): one operator
    configured, a value above the default, the override above it. The swap locks, and EVERY record
    written to durable storage — the intent written before the lock and the funded one after —
    carries the statement, and it survives the JSON round trip."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    view = _ChainView(
        pays=_covenant(terms), value=terms.radiant_amount, confs=70, base=base, bits=_HARD_BITS, tip_time=_NOW
    )
    value = 10_000 * PHOTONS_PER_RXD
    written: list[dict] = []

    async def persist(record):
        written.append(json.loads(json.dumps(record.to_dict())))

    coord, _btc_view = _btc_coord(
        terms,
        _real_leg(view, network="bc", depth_sources=()),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
        funding_bound=ElapsedBoundPolicy(accept_single_operator_up_to_photons=20_000 * PHOTONS_PER_RXD),
    )
    coord._persist = persist
    rec = await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert rec.state is SwapState.BTC_LOCKED
    assert len(written) >= 2 and all(w.get("single_operator_override") == _statement("20000") for w in written)
    assert SwapRecord.from_dict(written[-1]).single_operator_override == _statement("20000")

    # A later gate run WITHOUT the override (a resume, say) keeps the statement: it is history.
    resumed, _ = _btc_coord(
        terms,
        _real_leg(view, network="bc"),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )
    resumed.record = SwapRecord.from_dict(written[0])
    await resumed.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    assert resumed.last_maker_funding.single_operator_override is None
    assert resumed.record.single_operator_override == _statement("20000")

    # Without the override the record does not grow the field (its wire form is unchanged).
    coord, _ = _btc_coord(
        terms,
        _real_leg(view, network="bc"),
        policy=_vb_policy(value_at_risk_photons=value),
        accept_nondurable_seen=True,
    )
    written.clear()
    coord._persist = persist
    assert (await coord.taker_funds_btc(terms, now_unix_s=_NOW)).state is SwapState.BTC_LOCKED
    assert written and all("single_operator_override" not in w for w in written)


# --------------------------------------------------------------------------- concurrent depth reads


class _Blackholed:
    """A depth source that never answers (a dropped route: the read just hangs)."""

    def __init__(self, key):
        self.source_key = key
        self.cancelled = 0

    async def _hang(self, *_a):
        import asyncio

        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise

    async def get_transaction_verbose(self, txid):
        return await self._hang()

    async def get_tip_height(self):
        return await self._hang()


async def test_blackholed_depth_sources_cost_one_timeout_not_one_each():
    """The reviewer's case: each unresponsive operator added a full timeout to the call, one after
    another. Now the sources are asked concurrently, each under ``depth_timeout_s``: two blackholed
    sources beside one that answers finish in about ONE timeout, the silent ones are dropped exactly
    as a failing source is, and their pending reads are cancelled."""
    import asyncio
    import time

    view = _ChainView(pays=b"\x51", value=1, confs=9)
    holes = (_Blackholed("operator:hole-a"), _Blackholed("operator:hole-b"))
    timeout = 0.4
    io = RadiantChainIO(view, depth_sources=(*holes, _DepthReader(view)), depth_timeout_s=timeout)
    t0 = time.monotonic()
    try:  # bounded here too, so a regression that drops the per-source timeout fails, not hangs
        got = await asyncio.wait_for(io.reported_depths(view.chain.txid, view.chain.height), 10 * timeout)
    except asyncio.TimeoutError:
        pytest.fail(f"reported_depths did not return within {10 * timeout}s: a blackholed source was awaited unbounded")
    took = time.monotonic() - t0
    assert got == ((str(view.source_key), 9), (str(_SHIPPED_OPERATORS[1]), 9)), got
    assert timeout <= took < 1.5 * timeout, f"{took:.2f}s for two blackholed sources at {timeout}s each"
    # Each source's reads run one after the other, so only the first (the hung one) was pending.
    assert all(h.cancelled == 1 for h in holes), [h.cancelled for h in holes]


async def test_one_fresh_client_is_asked_its_two_reads_on_one_connection():
    """Re-attack of the concurrent reads: only SOURCES run concurrently. A fresh
    ``ElectrumXClient`` asked its verbose and tip reads at once opens two sockets, and the reply on
    the one its reader does not follow is never read — the source then times out and is dropped.
    Through a real websocket server: both reads are answered, on ONE connection."""
    import asyncio

    txid = os.urandom(32).hex()
    connections: list[int] = []

    async def server_side(ws):
        connections.append(1)
        async for msg in ws:
            req = json.loads(msg)
            if req["method"] == "blockchain.transaction.get":
                res = {"txid": txid, "confirmations": 9}
            elif req["method"] == "blockchain.headers.subscribe":
                res = {"height": 100 + 11, "hex": "00" * 80}
            else:
                await ws.send(json.dumps({"id": req["id"], "error": {"code": -32601, "message": "nope"}}))
                continue
            await asyncio.sleep(0.05)  # both requests are in flight together
            await ws.send(json.dumps({"id": req["id"], "result": res}))

    server = await websockets.serve(server_side, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        client = ElectrumXClient([f"ws://127.0.0.1:{port}"], allow_insecure=True)
        io = RadiantChainIO(_ChainView(pays=b"\x51", value=1, confs=9), depth_sources=(client,), depth_timeout_s=2.0)
        got = await asyncio.wait_for(io.reported_depths(txid, 100), 10)
        assert (str(client.source_key), 12) in got, got  # max(9 confirmations, 111 - 100 + 1)
        assert len(connections) == 1, f"{len(connections)} connections for one client's reads"
        await client.close()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True, "5"])
def test_the_depth_timeout_must_be_a_positive_finite_number(bad):
    view = _ChainView(pays=b"\x51", value=1, confs=9)
    with pytest.raises(ValidationError, match="depth_timeout_s"):
        RadiantChainIO(view, depth_timeout_s=bad)


# --------------------------------------------------------------------------- the reference time is taken after the reads


class _FakeMonotonic:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def _slow_reads(monkeypatch, view, seconds: float):
    """The coordinator's read clock, and a view whose header fetch takes *seconds* on it."""
    from pyrxd.gravity import swap_coordinator

    clock = _FakeMonotonic()
    monkeypatch.setattr(swap_coordinator, "_monotonic", clock)
    real = view.get_block_headers

    async def slow(start, count):
        clock.t += seconds  # one header range is fetched per proof here (asserted below)
        return await real(start, count)

    view.get_block_headers = slow
    return clock


async def test_the_reference_time_is_taken_after_the_reads(monkeypatch):
    """The gate's ``now`` was the caller's ``now_unix_s``, read before the fetch: a read that took ten
    minutes left the time term ten minutes short. Now ``now`` is ``now_unix_s`` advanced by the
    monotonic time the reads took — so ``E`` grows by exactly that — and through ``taker_funds_btc``
    the lock-time re-run is advanced by everything since the call began (both fetches)."""
    base, _chain = _value_bearing_chain(monkeypatch)
    terms = _wide_terms(3000)
    value = 10_000 * PHOTONS_PER_RXD

    def coord_over(view):
        return _btc_coord(
            terms,
            _real_leg(view, network="bc"),
            policy=_vb_policy(value_at_risk_photons=value),
            accept_nondurable_seen=True,
        )[0]

    def view_():
        return _ChainView(
            pays=_covenant(terms),
            value=terms.radiant_amount,
            confs=70,
            base=base,
            bits=_HARD_BITS,
            tip_time=_NOW - 3600,
        )

    fast = view_()
    _slow_reads(monkeypatch, fast, 0)
    coord = coord_over(fast)
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    base_elapsed = coord.last_maker_funding.elapsed_s
    assert base_elapsed == _NOW - coord.last_maker_funding.reference_time

    slow = view_()
    _slow_reads(monkeypatch, slow, 600)
    coord = coord_over(slow)
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    assert slow.reads.count("headers") == 1, slow.reads
    assert coord.last_maker_funding.elapsed_s == base_elapsed + 600
    assert coord.last_maker_funding.time_blocks > 0

    # A fractional second is rounded UP (never less conservative).
    slow = view_()
    _slow_reads(monkeypatch, slow, 0.2)
    coord = coord_over(slow)
    await coord.taker_verify_asset_funding(terms, now_unix_s=_NOW)
    assert coord.last_maker_funding.elapsed_s == base_elapsed + 1

    # Through the production entry point: the lock-time re-run counts both fetches.
    slow = view_()
    _slow_reads(monkeypatch, slow, 600)
    coord = coord_over(slow)
    rec = await coord.taker_funds_btc(terms, now_unix_s=_NOW)
    assert rec.state is SwapState.BTC_LOCKED
    assert coord.last_maker_funding.elapsed_s == base_elapsed + 1200


def test_a_reply_names_a_txid_only_as_exactly_64_hex_characters_ignoring_case():
    """``_names_txid`` directly: both sides must be 64 hex characters — a shorter or longer string that
    merely equals the other is not a txid, on either side — compared ignoring case."""
    from pyrxd.gravity.radiant_leg import _names_txid

    t = os.urandom(32).hex()
    assert _names_txid(t, t) and _names_txid(t.upper(), t) and _names_txid(t, t.upper())
    for reported, requested in (
        (t[:-1], t[:-1]),
        (t + "00", t + "00"),
        ("g" * 64, "g" * 64),
        (os.urandom(32).hex(), t),
        (None, t),
        (t, None),
        (int(t, 16), t),
    ):
        assert not _names_txid(reported, requested), (reported, requested)

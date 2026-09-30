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
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
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
    the median fails here."""
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
    assert r.time_blocks == poisson_upper_quantile(2.0 * r.elapsed_s / 300, r.epsilon)
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
    r = verify_maker_funding(ev, now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert (r.value_term, r.served_tip, r.reference_height) == (23, 30, 8)


def test_a_reference_header_the_plan_cannot_reach_refuses_by_name_never_a_bare_key_error():
    """With a walk cap smaller than the funding's distance below the newest checkpoint the gap is not
    fetched; the refusal is a MakerFundingNotVerified that names the reference header."""
    ev, kw, value, fetched = _gap_case(cap=4)
    assert not set(range(5, 12)) & fetched
    with pytest.raises(MakerFundingNotVerified, match=r"reference header .*block \d+, 23 deep.*checkpoint 22"):
        verify_maker_funding(ev, now_unix_s=_NOW, value_at_stake_photons=value, **kw)


def test_a_reference_header_that_does_not_link_to_its_checkpoint_is_refused():
    """Served, but not the chain's: a header at the reference height that does not link to the
    checkpoint above it is refused, so its window is never read."""
    ev, kw, value, _fetched = _gap_case()
    forged = dict(ev.headers)
    forged[8] = mine("00" * 32, b"\x00" * 32, _NOW, _HARD_BITS)
    ev = type(ev)(**{**ev.__dict__, "headers": forged})
    with pytest.raises(MakerFundingNotVerified, match=r"reference header .*block 8"):
        verify_maker_funding(ev, now_unix_s=_NOW, value_at_stake_photons=value, **kw)


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
    honest = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert honest.reference_height == 3, honest.reference_height
    h3 = mine(radiant_block_hash(real.headers[2]), b"\x33" * 32, _NOW, _HARD_BITS)
    h4 = mine(radiant_block_hash(h3), b"\x44" * 32, _NOW, _HARD_BITS)
    forged = {**real.headers, 3: h3, 4: h4}
    with pytest.raises(MakerFundingNotVerified, match=r"reference header .*block 3.*checkpoint 4"):
        verify_maker_funding(real.evidence(headers=forged), now_unix_s=_NOW, value_at_stake_photons=value, **kw)


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
    honest = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert (honest.value_term, honest.reference_height) == (9, 12)
    forged = {**real.headers, 7: mine("00" * 32, b"\x07" * 32, _NOW, _HARD_BITS)}
    with pytest.raises(MakerFundingNotVerified, match=r"header 7, in the 11-header window .*blocks 2 to 12"):
        verify_maker_funding(real.evidence(headers=forged), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    missing = {h: b for h, b in real.headers.items() if h != 4}
    with pytest.raises(MakerFundingNotVerified, match=r"header 4, in the 11-header window"):
        verify_maker_funding(real.evidence(headers=missing), now_unix_s=_NOW, value_at_stake_photons=value, **kw)


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
    r = verify_maker_funding(ev, value_at_stake_photons=value, **common)
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
        2.0,
        PHOTONS_PER_RXD,
        3600,
        2.0,
    )
    assert p.epsilon(None) == p.epsilon(0) == 1e-3
    assert p.epsilon(1_000 * PHOTONS_PER_RXD) == pytest.approx(1e-3)
    assert p.epsilon(100_000 * PHOTONS_PER_RXD) == pytest.approx(1e-5)
    assert p.epsilon(10**30) == 1e-12
    assert p.blocks_upper(3600, spacing_s=300, value_at_stake_photons=None) == poisson_upper_quantile(24.0, 1e-3)
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
    assert r.time_blocks == poisson_upper_quantile(2.0 * r.elapsed_s / 300, 1e-3)
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
    terms = _wide_terms(400)
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
    # 3.5 × this chain's C: a value term of 7 or more, which proved depth 6 cannot meet, while the
    # negotiation-time check (which models k up to 14) still finds room in t_rxd 400.
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
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
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


def test_the_early_check_runs_the_step_6_floor_on_the_bound_for_an_eth_swap(monkeypatch):
    """For an ETH counter leg only the step-6 floor runs early (the ordering needs a clock), so the
    floor alone must see the bound. A small value constructs; a value whose modelled bound leaves
    t_rxd 600 no room for a safe claim is refused at construction."""
    import dataclasses

    from pyrxd.btc_wallet import taproot as t

    base, chain = _value_bearing_chain(monkeypatch)
    p = os.urandom(32)
    terms = dataclasses.replace(
        _eth_terms(hashlock=hashlib.sha256(p).digest()),
        t_btc=t.Timelock(1, t.TimeUnit.BLOCKS),
        t_rxd=t.Timelock(600, t.TimeUnit.BLOCKS),
        radiant_amount=1000,
    )
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=100, base=base, bits=_HARD_BITS)
    eth = FakeEthLeg(preimage=p, verdict=_final())
    eth.network, eth.chain_id = "sepolia", 11155111

    def build(value):
        return SwapCoordinator(
            record=SwapRecord(state=SwapState.NEGOTIATED, terms=terms),
            counter_leg=eth,
            radiant_leg=_real_leg(view, network="bc"),
            indexer=FakeIndexer(),
            seen_store=FakeSeenStore(),
            config=CoordinatorConfig(
                margin_policy=_vb_policy(value_at_risk_photons=value, eth_finalization_window_s=768),
                maker_stall_safety_window_blocks=6,
                accept_estimated_eth_margins=True,
                accept_nondurable_seen=True,
            ),
        )

    assert build(1000) is not None
    big = 150 * funding_spv.forged_confirmation_cost_floor_photons(chain)
    assert (
        early_elapsed_blocks_upper(chain=chain, value_at_stake_photons=big, burial_blocks=1).elapsed_blocks_upper > 600
    )
    with pytest.raises(ValidationError, match=r"refused before anyone locks.*step 6"):
        build(big)


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
    view = _ChainView(pays=_covenant(roomy), value=roomy.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
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
    view = _ChainView(pays=_covenant(terms), value=terms.radiant_amount, confs=6, base=base, bits=_HARD_BITS)
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


async def test_step_7_judges_the_timelocks_on_the_elapsed_UPPER_bound():
    """One block proved, but the newest header served is 30 blocks' worth of time old. The CSV
    window must be judged as if the blocks that time allows were mined — here that leaves too little
    margin, so the gate refuses; the SAME funding with a fresh tip passes."""
    terms = _terms(variant="rxd")  # t_rxd 144, t_btc 24: ~24 Radiant blocks of elapsed slack
    stale = _coordinator(terms=terms, radiant_leg=_StaleTipLeg(tip_time=_NOW - 300 * 30))
    gate = await stale.pre_btc_lock_check(terms, now_unix_s=_NOW)
    assert gate.ok is False
    assert "REMAINING window" in gate.reason
    proof = stale.last_maker_funding
    assert proof.proved_depth == 1 and proof.elapsed_s == 9000
    assert proof.elapsed_blocks_upper == 1 + poisson_upper_quantile(60.0, proof.epsilon)

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
    assert later.elapsed_blocks_upper == 3 + poisson_upper_quantile(2.0 * later.elapsed_s / 300, 1e-3)


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
            return {"confirmations": self._confs}

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
    honest = verify_maker_funding(honest_chain.evidence(), now_unix_s=_NOW, **kw)
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
        r = verify_maker_funding(c.evidence(), now_unix_s=_NOW, **{**kw, "chain": _vb_chain(c.headers, (0, 2, 4))})
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
    r = verify_maker_funding(real.evidence(), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
    assert r.value_term == 4 and r.value_term * cost >= FORGERY_COST_FACTOR * value
    assert r.reference_height == r.served_tip - r.value_term + 1 == 11
    assert r.reference_time == _mtp_at(real.headers, 11)
    expected = poisson_upper_quantile(2.0 * (_NOW - r.reference_time) / 300, r.epsilon)
    assert r.time_blocks == expected
    assert r.elapsed_blocks_upper == (11 - real.height + 1) + expected

    hdrs = dict(real.headers)
    top = max(hdrs)
    hdrs[top + 1] = mine(radiant_block_hash(hdrs[top]), hashlib.sha256(b"one more").digest(), _NOW, _HARD_BITS)
    s = verify_maker_funding(real.evidence(headers=hdrs), now_unix_s=_NOW, value_at_stake_photons=value, **kw)
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

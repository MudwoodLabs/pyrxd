"""Live-regtest CONSENSUS proof for the **cold swap-recovery builders**.

:func:`~pyrxd.cli.swap_recovery.build_cold_claim` and
:func:`~pyrxd.cli.swap_recovery.build_cold_refund` are what an operator reaches for at
the worst moment in a swap's life: the counterparty is gone, a timelock is running, and
the spend is being reconstructed from a recovery file. Every other test for them is
offline — they assert on the dataclass the builder returns, which is a statement about
Python, not about whether a node would take the bytes.

That distinction has teeth here. Radiant has **neither RBF nor CPFP**
(:mod:`pyrxd.gravity.fee_policy`), so a recovery spend that is rejected — or accepted
but under-fee'd — cannot be repaired: it squats on its own inputs until the 8-hour
mempool expiry, quite possibly past the deadline it was racing. The pre-release audit
of this toolkit found two defects of exactly that shape (an unbounded fee UTXO that
burned 18,727x the requirement; a build against a 0-conf covenant), and neither offline
test noticed.

What each case proves, against a real ``radiant-core:v3.1.1`` node:

1. **A cold claim spends the covenant and pays the taker.** Not "assembles" — mined,
   the covenant outpoint gone, ``output[0]`` byte-equal to the covenant's pinned taker
   holder script.
2. **The claim cannot be redirected or forged.** Two negative controls on the same
   accepted bytes: repoint ``output[0]`` at an attacker (the covenant's ``hash256``
   output pin), and substitute a wrong preimage (the hashlock ``OP_EQUALVERIFY``).
3. **The CSV refund is rejected before maturity and accepted at it.** The SAME bytes,
   across the boundary — the timelock is the entire point of the refund path, so both
   sides of it are proven, at the exact block.
4. **A 0-conf covenant is refused.** Audit B5, against genuine mempool-only chain state
   read back from the node, not a fabricated ``confirmations=0``.
5. **The builder's fee floor IS the node's fee floor.** Measured at the boundary: a fee
   input of exactly ``ceil(size x rate / 1000)`` photons is accepted, and one photon
   less is rejected. This is the property the whole "no RBF, no CPFP" argument rests on,
   and it is the one thing an offline test structurally cannot check.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Manages its own throwaway
container; never touches a mainnet node and moves no real value. Every key is freshly
generated.

Run: ``RADIANT_REGTEST=1 pytest tests/test_cold_recovery_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import hashlib
import os

import pytest

# Reuse the isolated-regtest harness wholesale (the house pattern — see
# tests/test_ft_airdrop_regtest_e2e.py): the ``node`` fixture spins up + tears down a
# throwaway container. Bare module names, NOT ``tests.X``: pytest's prepend import mode
# puts ``tests/`` on sys.path and there is no ``tests/__init__.py``.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _pay_to_spk,
    _RegtestNode,
    node,
)

from pyrxd.cli import swap_recovery as sr
from pyrxd.gravity.fee_policy import (
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    DeadlineFeePolicy,
    photons_per_kb_from_rxd_per_kb,
)
from pyrxd.gravity.htlc_covenant import build_htlc_covenant_rxd
from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.security.errors import InsufficientFundsError, ValidationError
from pyrxd.security.types import Hex20

pytestmark = pytest.mark.integration

#: The covenant carrier. Small on purpose: the covenant permits ONE output, so the
#: carrier is not the fee — the separate fee input is.
_CARRIER = 100_000
#: Relative timelock on the refund branch, in blocks. 3 keeps the maturity walk short
#: while still being a real BIP68 lock the node evaluates.
_REFUND_CSV = 3
#: A comfortable fee input for the cases that are not about fee sizing. Above the node's
#: floor for a ~270-byte spend, below :func:`~pyrxd.cli.swap_recovery.fee_overpay_ceiling`.
_FEE_VALUE = 20_000_000


def _p2pkh(pkh: bytes) -> bytes:
    return b"\x76\xa9\x14" + bytes(pkh) + b"\x88\xac"


def _carve_fee_utxo(rt: _RegtestNode, value: int) -> tuple[str, UtxoRecord]:
    """Fund a plain P2PKH output under a FRESH key and return ``(wif, utxo)``.

    A fresh key per call, never a literal: this module's builders sign with the returned
    WIF, and the cold toolkit handles the most sensitive material in the system — nothing
    it touches in a test may be a guessable key.
    """
    key = PrivateKey(os.urandom(32))
    txid = _pay_to_spk(rt, _p2pkh(key.public_key().hash160()), value)
    return key.wif(), UtxoRecord(tx_hash=txid, tx_pos=0, value=value, height=0)


def _covenant(*, refund_csv: int = _REFUND_CSV):
    """A fresh RXD HTLC covenant plus its preimage. Every key and secret is random."""
    p = os.urandom(32)
    taker = PrivateKey(os.urandom(32))
    maker = PrivateKey(os.urandom(32))
    cov = build_htlc_covenant_rxd(
        amount=_CARRIER,
        taker_pkh=bytes(Hex20(taker.public_key().hash160())),
        maker_pkh=bytes(Hex20(maker.public_key().hash160())),
        hashlock=hashlib.sha256(p).digest(),
        refund_csv=refund_csv,
    )
    return cov, p


def _chain_state(rt: _RegtestNode, txid: str, vout: int = 0) -> sr.CovenantChainState:
    """Read the covenant's REAL depth off the node.

    Deliberately not fabricated: ``confirmations`` drives the CSV maturity verdict, the
    deadline-urgency premium, and the 0-conf refusal, so a hand-written value would let
    all three pass against a state the chain is not in.
    """
    out = rt.cli("gettxout", txid, str(vout))
    assert out, f"covenant outpoint {txid}:{vout} is not unspent on the node"
    tip = int(rt.cli("getblockcount"))
    confs = int(out["confirmations"])
    return sr.CovenantChainState(
        outpoint=f"{txid}:{vout}",
        carrier_value=round(out["value"] * 1e8),
        funding_height=(tip - confs + 1) if confs else None,
        tip_height=tip,
        confirmations=confs,
    )


def _node_policy(rt: _RegtestNode) -> DeadlineFeePolicy:
    """A fee policy at the rate THIS node advertises, not a hardcoded default.

    ``effective_minrelaytxfee`` is node policy and it moves — the reference mainnet node
    reports 0.10 RXD/kB, this regtest build reports 0.01. Reading it is the only way the
    boundary case below can claim to be measuring the node's real floor.
    """
    rate = photons_per_kb_from_rxd_per_kb(float(rt.cli("getmempoolinfo")["effective_minrelaytxfee"]))
    # `allow_below_protocol_floor` because that reading IS below the protocol floor:
    # `protocol_floor_per_kb` now defaults to the EFFECTIVE mainnet rate (it used to
    # default to the legacy one, which was 10x too low to bound anything), and a
    # default regtest node advertises a tenth of it. Pointing at a node that really
    # relays this low is exactly what the escape hatch is for.
    return DeadlineFeePolicy(relay_fee_per_kb=rate, allow_below_protocol_floor=True)


def _funded_covenant(rt: _RegtestNode, *, refund_csv: int = _REFUND_CSV):
    cov, p = _covenant(refund_csv=refund_csv)
    txid = _pay_to_spk(rt, cov.funded_spk, _CARRIER)
    return cov, p, txid


class TestColdClaimOnConsensus:
    def test_cold_claim_spends_the_covenant_and_pays_the_taker(self, node):  # noqa: F811
        """Case 1: the claim is MINED and the covenant outpoint is gone."""
        cov, p, cov_txid = _funded_covenant(node)
        wif, fee_utxo = _carve_fee_utxo(node, _FEE_VALUE)
        chain = _chain_state(node, cov_txid)

        cold = sr.build_cold_claim(covenant=cov, chain=chain, preimage=p, fee_wif=wif, fee_utxo=fee_utxo)

        # The reported size must be the size of the bytes it printed: the operator reads
        # `size_bytes` to judge the fee, and the fee floor is derived from it.
        assert cold.size_bytes == len(bytes.fromhex(cold.raw_hex))
        assert cold.clears_floor is True

        res = node.accepts(cold.raw_hex)
        assert res.get("allowed") is True, f"cold claim REJECTED by consensus: {res}"
        txid = node.cli("sendrawtransaction", cold.raw_hex)
        assert txid == cold.txid, f"builder txid {cold.txid} != broadcast txid {txid}"
        node.mine(1)

        assert node.cli("gettxout", cov_txid, "0") in (None, ""), "covenant UTXO should be spent after a cold claim"
        confirmed = node.cli("getrawtransaction", txid, "true")
        assert confirmed["confirmations"] >= 1
        # Pays the destination the covenant pins — the operator's real check.
        assert len(confirmed["vout"]) == 1, "the covenant permits exactly one output"
        assert confirmed["vout"][0]["scriptPubKey"]["hex"] == cov.taker_holder_script.hex()
        assert round(confirmed["vout"][0]["value"] * 1e8) == _CARRIER

    def test_redirecting_a_cold_claim_to_an_attacker_is_rejected(self, node):  # noqa: F811
        """Negative control: the covenant pins ``output[0]`` by ``hash256``.

        The bytes differ from an ACCEPTED claim only in the destination script. If
        consensus took this, the positive case above would prove nothing about where the
        asset goes — which is the only thing an operator recovering funds cares about.
        """
        cov, p, cov_txid = _funded_covenant(node)
        wif, fee_utxo = _carve_fee_utxo(node, _FEE_VALUE)
        cold = sr.build_cold_claim(
            covenant=cov, chain=_chain_state(node, cov_txid), preimage=p, fee_wif=wif, fee_utxo=fee_utxo
        )
        assert node.accepts(cold.raw_hex).get("allowed") is True, "control precondition: the unmutated claim is valid"

        attacker_spk = _p2pkh(PrivateKey(os.urandom(32)).public_key().hash160())
        redirected = cold.raw_hex.replace(cov.taker_holder_script.hex(), attacker_spk.hex(), 1)
        assert redirected != cold.raw_hex

        res = node.accepts(redirected)
        assert res.get("allowed") is False, f"consensus ACCEPTED a redirected cold claim: {res}"
        reason = str(res.get("reject-reason", ""))
        assert "false/empty top stack element" in reason, f"rejected, but not by the covenant's output pin: {res}"
        print(f"redirect control reject-reason: {reason}")

    def test_a_cold_claim_with_a_wrong_preimage_is_rejected(self, node):  # noqa: F811
        """Negative control: the hashlock ``OP_EQUALVERIFY``.

        The builder refuses a wrong preimage up front, so the mutation happens after the
        build — this measures consensus, not the guard.
        """
        cov, p, cov_txid = _funded_covenant(node)
        wif, fee_utxo = _carve_fee_utxo(node, _FEE_VALUE)
        cold = sr.build_cold_claim(
            covenant=cov, chain=_chain_state(node, cov_txid), preimage=p, fee_wif=wif, fee_utxo=fee_utxo
        )
        wrong = cold.raw_hex.replace(p.hex(), os.urandom(32).hex(), 1)
        assert wrong != cold.raw_hex

        res = node.accepts(wrong)
        assert res.get("allowed") is False, f"consensus ACCEPTED a wrong-preimage cold claim: {res}"
        reason = str(res.get("reject-reason", ""))
        assert "OP_EQUALVERIFY" in reason, f"rejected, but not by the hashlock this control is testing: {res}"
        print(f"wrong-preimage control reject-reason: {reason}")


class TestColdRefundOnConsensus:
    def test_cold_refund_is_rejected_before_csv_maturity_and_accepted_at_it(self, node):  # noqa: F811
        """Case 3: ONE transaction, both sides of the timelock boundary.

        The refund's raw bytes do not depend on the covenant's depth (there is no
        urgency premium on this path — see :func:`build_cold_refund`), so the same hex is
        offered at every height. A pass therefore cannot come from having rebuilt into
        something different: it is the chain's verdict on identical bytes changing at
        exactly the block BIP68 opens.
        """
        # Carve the fee input FIRST: each funding mines a block, and building the refund
        # at the covenant's very first confirmation is what makes the walk below start
        # one full block before the lock could possibly open.
        wif, fee_utxo = _carve_fee_utxo(node, _FEE_VALUE)
        cov, _p, cov_txid = _funded_covenant(node)
        chain = _chain_state(node, cov_txid)
        assert chain.confirmations == 1, "precondition: the walk must start at the first confirmation"

        cold = sr.build_cold_refund(covenant=cov, chain=chain, fee_wif=wif, fee_utxo=fee_utxo, allow_immature=True)
        raw = cold.raw_hex
        assert cold.csv_mature is False
        # No urgency premium on the refund path: the CSV window opens and stays open.
        assert cold.urgency_multiplier == 1.0
        assert cold.target_photons == cold.relay_floor_photons

        # Walk the boundary one block at a time and record the verdict at each depth.
        verdicts: dict[int, tuple[bool, str]] = {}
        while True:
            confs = _chain_state(node, cov_txid).confirmations
            res = node.accepts(raw)
            verdicts[confs] = (bool(res.get("allowed")), str(res.get("reject-reason", "")))
            if res.get("allowed"):
                break
            assert confs <= _REFUND_CSV, f"refund never matured by {confs} confirmations: {res}"
            node.mine(1)

        print(f"CSV boundary verdicts by confirmations: {verdicts}")
        # Every depth below the CSV must have been refused, and refused BY THE TIMELOCK.
        for confs, (allowed, reason) in verdicts.items():
            if confs < _REFUND_CSV:
                assert allowed is False, f"a refund at {confs} confs was accepted before the CSV opened"
                assert "BIP68" in reason or "non-final" in reason, (
                    f"rejected at {confs} confs, but not by the relative timelock: {reason}"
                )
        assert verdicts[_REFUND_CSV][0] is True, "the refund must be accepted at exactly refund_csv confirmations"

        rtxid = node.cli("sendrawtransaction", raw)
        assert rtxid == cold.txid
        node.mine(1)
        assert node.cli("gettxout", cov_txid, "0") in (None, ""), "covenant UTXO should be spent after a cold refund"

        confirmed = node.cli("getrawtransaction", rtxid, "true")
        assert confirmed["confirmations"] >= 1
        # Spent via the CSV branch: v2 + the covenant input's nSequence carrying the lock.
        assert confirmed["version"] == 2, "BIP68 only engages on a v2 transaction"
        assert confirmed["vin"][0]["sequence"] == _REFUND_CSV
        # And it pays the MAKER holder script the covenant pins — not the taker's.
        assert len(confirmed["vout"]) == 1
        assert confirmed["vout"][0]["scriptPubKey"]["hex"] == cov.maker_holder_script.hex()
        assert confirmed["vout"][0]["scriptPubKey"]["hex"] != cov.taker_holder_script.hex()
        assert round(confirmed["vout"][0]["value"] * 1e8) == _CARRIER


class TestColdBuilderGuardsAgainstRealChainState:
    def test_a_mempool_only_covenant_is_refused(self, node):  # noqa: F811
        """Case 4 (audit B5), against genuine 0-conf state read back from the node.

        A spend of an unconfirmed parent dies with that parent, and with no RBF and no
        CPFP its fee input is then squatted on until the 8h mempool expiry — inside the
        very window the recovery exists to beat.
        """
        cov, p = _covenant()
        wif, fee_utxo = _carve_fee_utxo(node, _FEE_VALUE)

        # Fund the covenant, then invalidate the block that confirmed it. The funding
        # returns to the mempool, so the covenant outpoint is REAL and genuinely 0-conf —
        # the state the audit finding was about, not a hand-written `confirmations=0`.
        cov_txid = _pay_to_spk(node, cov.funded_spk, _CARRIER)
        tip_hash = str(node.cli("getbestblockhash"))
        node.cli("invalidateblock", tip_hash)
        entry = node.cli("getmempoolentry", cov_txid)
        assert entry, "precondition: the covenant funding must be back in the mempool"
        assert node.cli("gettxout", cov_txid, "0", "true")["confirmations"] == 0

        chain = sr.CovenantChainState(
            outpoint=f"{cov_txid}:0",
            carrier_value=_CARRIER,
            funding_height=None,
            tip_height=int(node.cli("getblockcount")),
            confirmations=0,
        )
        with pytest.raises(ValidationError, match="UNCONFIRMED"):
            sr.build_cold_claim(covenant=cov, chain=chain, preimage=p, fee_wif=wif, fee_utxo=fee_utxo)
        with pytest.raises(ValidationError, match="UNCONFIRMED"):
            sr.build_cold_refund(covenant=cov, chain=chain, fee_wif=wif, fee_utxo=fee_utxo, allow_immature=True)

        node.cli("reconsiderblock", tip_hash)
        node.mine(1)

    def test_the_builders_relay_floor_is_the_nodes_relay_floor(self, node):  # noqa: F811
        """Case 5: the fee boundary, measured — at the floor accepted, one photon under rejected.

        Radiant's ``AcceptToMemoryPool`` checks the fee against ``tx.GetTotalSize()`` —
        the full serialized length, explicitly NOT a vsize — and
        :meth:`DeadlineFeePolicy.min_relay_fee` claims to reproduce that arithmetic. The
        claim is only worth as much as a node agreeing with it, and it can only be
        checked at the boundary: a floor that is too LOW ships an unrelayable recovery
        spend that cannot be bumped.

        The fee input's value is part of the BIP143 preimage, so changing it changes the
        signature and can change its DER length by a byte — which changes the serialized
        size, which changes the floor derived from it. That coupling is exactly the
        trial-versus-final hazard this case exists to probe, so the boundary value is
        SEARCHED for rather than computed once: a naive fixed-point iteration can enter a
        two-cycle between adjacent sizes and never land on the boundary at all.

        Everything is built with a deliberately loose policy so the builder's own guard
        never short-circuits the search; the at-floor transaction is then rebuilt under
        the node's real policy, byte-for-byte, to show the guard admits it.
        """
        policy = _node_policy(node)
        loose = DeadlineFeePolicy(relay_fee_per_kb=1_000, protocol_floor_per_kb=1_000, allow_below_protocol_floor=True)
        print(f"node effective_minrelaytxfee -> {policy.relay_fee_per_kb} photons/kB")
        cov, p, cov_txid = _funded_covenant(node)

        def _build_at(value: int, *, pol: DeadlineFeePolicy = loose):
            wif, utxo = _carve_fee_utxo(node, value)
            cold = sr.build_cold_claim(
                covenant=cov, chain=_chain_state(node, cov_txid), preimage=p, fee_wif=wif, fee_utxo=utxo, policy=pol
            )
            return cold, wif, utxo

        def _search(offset: int):
            """A fee input worth exactly ``min_relay_fee(own size) + offset``.

            Iterating ``value <- min_relay_fee(size(value))`` can two-cycle: if the value
            that a 266-byte spend demands happens to sign into 267 bytes and vice versa,
            no value is its own fixed point and the loop never terminates. So instead
            every observed size contributes a candidate value, and each candidate is
            retried — with a FRESH fee key, which re-rolls the DER length independently of
            the value — until one lands on its own boundary.
            """
            probe, _w, _u = _build_at(400_000)
            sizes = {probe.size_bytes}
            for _ in range(12):
                for size in sorted(sizes):
                    cold, wif, utxo = _build_at(policy.min_relay_fee(size) + offset)
                    sizes.add(cold.size_bytes)
                    if cold.fee_photons == policy.min_relay_fee(cold.size_bytes) + offset:
                        return cold, wif, utxo
            raise AssertionError(f"no fee input reached min_relay_fee(size){offset:+d} for its own size")

        at_floor, floor_wif, floor_utxo = _search(0)
        assert at_floor.fee_photons == policy.min_relay_fee(at_floor.size_bytes)
        # The shipped guard admits it: same inputs, the node's real rate, no refusal, and
        # the identical bytes. (`_assert_fee_clears_relay_floor` raises rather than
        # returning an under-fee'd transaction, so reaching this line is the assertion.)
        under_node_policy = sr.build_cold_claim(
            covenant=cov,
            chain=_chain_state(node, cov_txid),
            preimage=p,
            fee_wif=floor_wif,
            fee_utxo=floor_utxo,
            policy=policy,
        )
        assert under_node_policy.raw_hex == at_floor.raw_hex

        res = node.accepts(at_floor.raw_hex)
        assert res.get("allowed") is True, (
            f"a fee of exactly the derived floor was REJECTED — the derivation UNDER-states the node's "
            f"requirement, which is how an unrepairable recovery spend ships: {res}"
        )
        print(f"at-floor: size={at_floor.size_bytes}B fee={at_floor.fee_photons}ph -> accepted")

        # One photon under. Only reachable through the loose policy: at the node's own
        # rate the builder raises rather than returning these bytes, which is the guard
        # working — so what is measured here is the node's verdict, not the builder's.
        under, under_wif, under_utxo = _search(-1)
        assert under.fee_photons == policy.min_relay_fee(under.size_bytes) - 1
        with pytest.raises(InsufficientFundsError, match="below the required"):
            sr.build_cold_claim(
                covenant=cov,
                chain=_chain_state(node, cov_txid),
                preimage=p,
                fee_wif=under_wif,
                fee_utxo=under_utxo,
                policy=policy,
            )
        res = node.accepts(under.raw_hex)
        assert res.get("allowed") is False, (
            f"one photon below the derived floor was ACCEPTED — the derivation OVER-states the node's "
            f"requirement, so the at-floor pass above is not a boundary: {res}"
        )
        reason = str(res.get("reject-reason", ""))
        assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
        print(f"one-photon-under: size={under.size_bytes}B fee={under.fee_photons}ph -> {reason}")

        # And the SHIPPED default is not weaker than what this node demands. The default
        # is the reference mainnet node's post-2.0 effective rate; a node advertising less
        # is a node this policy over-pays, never one it under-pays.
        assert policy.relay_fee_per_kb <= RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB

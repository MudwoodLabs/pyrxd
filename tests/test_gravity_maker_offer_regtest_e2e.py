"""Live-regtest CONSENSUS proof for :func:`pyrxd.gravity.transactions.build_maker_offer_tx`.

``build_maker_offer_tx`` is the Maker's deployment step: it spends a plain P2PKH UTXO
and creates the MakerOffer P2SH output a Taker later takes with ``build_claim_tx``. Every
existing test for it is offline — they check that the returned ``tx_hex`` re-hashes to the
returned ``txid`` and that the accounting fields add up, which is a statement about the
serializer, not about whether the chain would accept the bytes or let anyone spend the
output afterwards.

Two things make that gap worth closing on a node rather than on paper:

* The transaction is signed with **Radiant's** BIP143 variant — the one with
  ``hashOutputHashes`` spliced between ``hashSequence`` and ``hashOutputs``
  (:func:`~pyrxd.gravity.transactions._sign_radiant_p2sh_input`). A sighash that is
  merely self-consistent produces a signature every offline check accepts and no node
  does.
* An offer that funds but cannot be **taken** is worse than one that never deployed: the
  Maker's photons sit in a P2SH whose only other exit is the ``forfeit`` deadline. So the
  proof runs the full deploy → take path, on chain, not just the deploy.

What each case proves against a real ``radiant-core:v3.1.1`` node:

1. **The offer transaction confirms**, and the mined output is byte-equal to
   ``P2SH(offer_redeem)`` at the photon value the builder reported.
2. **The offer can be taken.** ``build_claim_tx`` spends it, the MakerOffer outpoint is
   gone, and the MakerClaimed P2SH exists at the expected script.
3. **The signature binds the outputs.** Negative control: raise the offer output by one
   photon after signing and the node refuses it.
4. **A stranger cannot take the offer.** Negative control for the audit-04-S3 taker-key
   requirement, measured at consensus rather than in the builder.
5. **The builder's relay-floor guard is the node's floor.** Boundary proved in both
   directions against the rate this node advertises: one photon under is refused by the
   builder AND by the node, exactly at the floor is accepted by both. This case used to
   pin the opposite — that the builder enforced no floor at all.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Manages its own throwaway
container; never touches a mainnet node and moves no real value. Every key is generated
from ``os.urandom(32)``.

Run: ``RADIANT_REGTEST=1 pytest tests/test_gravity_maker_offer_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import os

import pytest

# Reuse the isolated-regtest harness wholesale (the house pattern). Bare module names,
# NOT ``tests.X`` — pytest's prepend import mode puts ``tests/`` on sys.path and there is
# no ``tests/__init__.py``.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _pay_to_spk,
    _RegtestNode,
    node,
)

from pyrxd.gravity.codehash import compute_p2sh_script_pubkey
from pyrxd.gravity.covenant import build_gravity_offer
from pyrxd.gravity.fee_policy import (
    RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB,
    DeadlineFeePolicy,
    photons_per_kb_from_rxd_per_kb,
)
from pyrxd.gravity.transactions import build_claim_tx, build_maker_offer_tx
from pyrxd.keys import PrivateKey
from pyrxd.security.errors import InsufficientFundsError
from pyrxd.security.secrets import PrivateKeyMaterial

pytestmark = pytest.mark.integration

#: Year-2030 deadline: past ``GravityOffer``'s 24h floor and past the MakerClaimed
#: covenant's own baked ``claimDeadline`` floor (1774427796).
_CLAIM_DEADLINE = 1_900_000_000
#: Difficulty-1 wire nBits. Legal for a regtest offer; ``reject_low_difficulty=False``
#: opts out of the audit F-02 floor that exists to stop this on mainnet.
_NBITS = b"\xff\xff\x7f\x1d"
_PHOTONS_OFFERED = 10_000_000  # 0.1 RXD locked in the MakerOffer P2SH
_FUNDING = 60_000_000  # 0.6 RXD of plain P2PKH the Maker spends
#: Comfortably above this node's relay floor for a ~190-byte offer tx and a ~283-byte
#: claim. The node runs at MAINNET's floor (10 000 photons/byte), so a 500-byte
#: transaction needs 5 000 000 and this covers every transaction the suite builds. The
#: floor itself is the subject of its own case below, which derives its numbers from
#: ``_node_relay_rate`` rather than from this constant.
_FEE = 5_000_000


class _Party:
    """A freshly generated party. No literal keys — the swap stack's standing rule."""

    def __init__(self) -> None:
        raw = os.urandom(32)
        self.material = PrivateKeyMaterial(raw)
        self.key = PrivateKey(raw)

    @property
    def pkh(self) -> bytes:
        return self.key.public_key().hash160()

    @property
    def pub(self) -> bytes:
        return self.key.public_key().serialize()

    @property
    def p2pkh_spk(self) -> bytes:
        return b"\x76\xa9\x14" + self.pkh + b"\x88\xac"


def _offer(maker: _Party, taker: _Party):
    """A real MakerOffer/MakerClaimed pair built from the bundled covenant artifacts."""
    return build_gravity_offer(
        maker_pkh=maker.pkh,
        maker_pk=maker.pub,
        taker_pk=taker.pub,
        taker_radiant_pkh=taker.pkh,
        # A fresh receive hash per offer — the structural defence against the
        # cross-offer replay documented on build_gravity_offer (C-ECON-1).
        btc_receive_hash=os.urandom(20),
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=os.urandom(32),
        expected_nbits=_NBITS,
        anchor_height=800_000,
        merkle_depth=1,
        claim_deadline=_CLAIM_DEADLINE,
        photons_offered=_PHOTONS_OFFERED,
        reject_low_difficulty=False,
    )


def _deploy(rt: _RegtestNode, maker: _Party, taker: _Party, *, fee: int = _FEE, policy=None):
    """Fund the Maker, build the offer tx, and return ``(offer, result)`` unbroadcast.

    ``policy`` defaults to THIS node's advertised rate. That is not a convenience: the
    builder's relay-floor guard defaults to the reference *mainnet* rate, and a regtest
    node advertises a lower one, so a fee that is perfectly viable here would otherwise be
    refused before it ever reached the node. Reading ``getmempoolinfo`` and passing the
    result is exactly what the ``fee_policy`` parameter exists for.
    """
    offer = _offer(maker, taker)
    funding_txid = _pay_to_spk(rt, maker.p2pkh_spk, _FUNDING)
    result = build_maker_offer_tx(
        offer=offer,
        funding_txid=funding_txid,
        funding_vout=0,
        funding_photons=_FUNDING,
        fee_sats=fee,
        maker_privkey=maker.material,
        fee_policy=policy if policy is not None else _node_policy(rt),
    )
    return offer, result


def _node_relay_rate(rt: _RegtestNode) -> int:
    """The photons/kB rate THIS node advertises (node policy, not a protocol constant)."""
    return photons_per_kb_from_rxd_per_kb(float(rt.cli("getmempoolinfo")["effective_minrelaytxfee"]))


def _node_policy(rt: _RegtestNode) -> DeadlineFeePolicy:
    """A fee policy pinned to this node's own advertised floor."""
    return DeadlineFeePolicy(relay_fee_per_kb=_node_relay_rate(rt), allow_below_protocol_floor=True)


class TestMakerOfferOnConsensus:
    def test_the_offer_confirms_and_the_taker_can_take_it(self, node):  # noqa: F811
        """Cases 1 + 2: deploy → take, both mined."""
        maker, taker = _Party(), _Party()
        offer, result = _deploy(node, maker, taker)
        offer_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.offer_redeem_hex))

        assert result.tx_size == len(bytes.fromhex(result.tx_hex))
        res = node.accepts(result.tx_hex)
        assert res.get("allowed") is True, f"maker offer tx REJECTED by consensus: {res}"

        offer_txid = node.cli("sendrawtransaction", result.tx_hex)
        assert offer_txid == result.txid, f"builder txid {result.txid} != broadcast txid {offer_txid}"
        node.mine(1)

        deployed = node.cli("gettxout", offer_txid, "0")
        assert deployed, "the MakerOffer P2SH output should be unspent on chain"
        assert deployed["scriptPubKey"]["hex"] == offer_spk.hex(), "the mined output is not P2SH(offer_redeem)"
        assert round(deployed["value"] * 1e8) == result.output_photons
        # Single-output mode: everything but the miner fee is locked in the covenant.
        assert result.output_photons == _FUNDING - _FEE

        # ---- and it can be TAKEN ------------------------------------------
        claim = build_claim_tx(
            offer=offer,
            funding_txid=offer_txid,
            funding_vout=0,
            funding_photons=result.output_photons,
            fee_sats=_FEE,
            taker_privkey=taker.material,
            # Judge the fee against THIS node's advertised floor rather than the
            # builder's compiled-in default. They agree today (the harness starts the
            # node at the mainnet floor), and that is the point: the node is the
            # oracle for its own policy, so the case still holds if either moves.
            fee_policy=_node_policy(node),
        )
        res = node.accepts(claim.tx_hex)
        assert res.get("allowed") is True, f"the deployed offer could not be TAKEN: {res}"
        claim_txid = node.cli("sendrawtransaction", claim.tx_hex)
        node.mine(1)

        assert node.cli("gettxout", offer_txid, "0") in (None, ""), "the MakerOffer UTXO should be spent after claim"
        claimed = node.cli("getrawtransaction", claim_txid, "true")
        assert claimed["confirmations"] >= 1
        claimed_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.claimed_redeem_hex))
        assert claimed["vout"][0]["scriptPubKey"]["hex"] == claimed_spk.hex()
        assert round(claimed["vout"][0]["value"] * 1e8) == claim.output_photons

    def test_raising_the_offer_output_by_one_photon_is_rejected(self, node):  # noqa: F811
        """Negative control: the Radiant sighash must actually bind the outputs.

        ``_sign_radiant_p2sh_input`` commits to the outputs twice — once through
        ``hashOutputs`` and once through Radiant's ``hashOutputHashes`` extension. If
        either were computed over something other than the bytes that ship, a mutated
        output would still verify, and the accepted case above would be proving only
        that *some* transaction is valid.
        """
        maker, taker = _Party(), _Party()
        offer, result = _deploy(node, maker, taker)
        offer_spk = compute_p2sh_script_pubkey(bytes.fromhex(offer.offer_redeem_hex))
        assert node.accepts(result.tx_hex).get("allowed") is True, "control precondition: the offer tx is valid"

        raw = bytearray(bytes.fromhex(result.tx_hex))
        idx = raw.find(offer_spk)
        assert idx > 0, "could not locate the offer output in the serialized tx"
        value_off = idx - 1 - 8  # <value 8 LE><varint len><spk>
        value = int.from_bytes(raw[value_off : value_off + 8], "little")
        assert value == result.output_photons
        raw[value_off : value_off + 8] = (value + 1).to_bytes(8, "little")

        res = node.accepts(bytes(raw).hex())
        assert res.get("allowed") is False, (
            f"consensus ACCEPTED an offer tx whose output was altered after signing: {res}"
        )
        reason = str(res.get("reject-reason", ""))
        assert "script-verify" in reason, f"rejected, but not by signature verification: {res}"
        print(f"mutated-output control reject-reason: {reason}")

    def test_a_stranger_cannot_take_the_offer(self, node):  # noqa: F811
        """Negative control: ``claim()`` requires the TAKER's signature (audit 04-S3).

        Third-party state-advance grief is only prevented if the covenant actually
        checks the key. The builder will happily sign with any key handed to it, so this
        is a consensus question.
        """
        maker, taker = _Party(), _Party()
        offer, result = _deploy(node, maker, taker)
        offer_txid = node.cli("sendrawtransaction", result.tx_hex)
        node.mine(1)

        stranger = _Party()
        forged = build_claim_tx(
            offer=offer,
            funding_txid=offer_txid,
            funding_vout=0,
            funding_photons=result.output_photons,
            fee_sats=_FEE,
            taker_privkey=stranger.material,
            fee_policy=_node_policy(node),
        )
        res = node.accepts(forged.tx_hex)
        assert res.get("allowed") is False, f"consensus let a STRANGER take the offer: {res}"
        reason = str(res.get("reject-reason", ""))
        assert "script-verify" in reason, f"rejected, but not by the covenant's taker check: {res}"
        print(f"stranger-claim control reject-reason: {reason}")

        # And the real taker still can — so the refusal above is about the key, not about
        # something structurally wrong with every claim of this offer.
        good = build_claim_tx(
            offer=offer,
            funding_txid=offer_txid,
            funding_vout=0,
            funding_photons=result.output_photons,
            fee_sats=_FEE,
            taker_privkey=taker.material,
            # Judge the fee against THIS node's advertised floor rather than the
            # builder's compiled-in default. They agree today (the harness starts the
            # node at the mainnet floor), and that is the point: the node is the
            # oracle for its own policy, so the case still holds if either moves.
            fee_policy=_node_policy(node),
        )
        assert node.accepts(good.tx_hex).get("allowed") is True

    def test_build_maker_offer_tx_refuses_a_fee_below_the_relay_floor(self, node):  # noqa: F811
        """The builder's floor guard, proved to be the NODE's floor and not merely a number.

        This case previously pinned the opposite — that ``fee_sats`` was taken entirely on
        trust and ``build_maker_offer_tx`` returned a fully-populated ``MakerOfferResult``
        for a transaction no node would relay. That was a finding, deliberately recorded as
        a passing test so it could not be lost. It is now a fund-safety guard, and this
        case asserts the guard instead. Radiant has neither RBF nor CPFP, so the
        transaction it used to hand back could not be replaced or bumped and squatted on
        the Maker's funding UTXO until the 8h mempool expiry.

        10,000 photons was not an arbitrary underpayment: it was the fee the whole offline
        suite used, which is precisely why nothing offline could have noticed.

        The boundary is proved in BOTH directions against this node's own advertised floor
        (read from ``getmempoolinfo``, not assumed — regtest advertises less than mainnet):

        * one photon UNDER the floor: the builder refuses, and a transaction forced past the
          guard with an explicitly permissive policy is refused by the node too, with the
          reason quoted verbatim;
        * exactly AT the floor: the builder returns it and the node accepts it.
        """
        rate = _node_relay_rate(node)
        policy = DeadlineFeePolicy(relay_fee_per_kb=rate, allow_below_protocol_floor=True)
        maker, taker = _Party(), _Party()
        print(f"node advertises effective_minrelaytxfee = {rate} photons/kB")

        # ---- the old fixture fee is now refused outright -------------------
        with pytest.raises(InsufficientFundsError) as exc:
            _deploy(node, maker, taker, fee=10_000, policy=policy)
        print(f"builder refusal at the old fixture fee: {exc.value}")
        # ...and a fortiori under the mainnet reference rate.
        with pytest.raises(InsufficientFundsError):
            _deploy(
                node,
                maker,
                taker,
                fee=10_000,
                policy=DeadlineFeePolicy(relay_fee_per_kb=RADIANT_EFFECTIVE_MIN_RELAY_PHOTONS_PER_KB),
            )

        # ---- the boundary, both sides --------------------------------------
        # Searched, not solved: the fee is subtracted from the signed output value, so
        # changing it re-signs the input and can move the DER length — and with it the size
        # the floor is derived from. Each attempt spends a fresh funding UTXO, which
        # re-rolls that length independently of the fee.
        #
        # `permissive` exists only to FORCE the under-floor transaction into existence so
        # the node can be asked about it. Without it the guard refuses and there would be
        # nothing to submit — which is the point of the guard, but proves nothing about
        # where the node's line actually is.
        permissive = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)

        at_floor = under = None
        for _ in range(20):
            _o, probe = _deploy(node, maker, taker, fee=policy.min_relay_fee(200), policy=policy)
            floor = policy.min_relay_fee(probe.tx_size)
            try:
                _o, candidate = _deploy(node, maker, taker, fee=floor, policy=policy)
            except InsufficientFundsError:
                continue  # re-signing GREW the tx past the bid; the guard refusing is correct
            if candidate.fee_sats != policy.min_relay_fee(candidate.tx_size):
                continue  # re-signing shrank it; this build is not on the boundary
            at_floor = candidate
            # One photon under, at the same size, forced past the guard.
            _o, u = _deploy(node, maker, taker, fee=floor - 1, policy=permissive)
            if u.tx_size == candidate.tx_size:
                under = u
                break
        assert at_floor is not None, "no offer tx reached a fee equal to its own relay floor"
        assert under is not None, "could not build a same-size transaction one photon under the floor"

        # The guard itself refuses that fee. Stated in two parts, because a single
        # `pytest.raises(_deploy(fee=under.fee_sats))` is NOT a deterministic
        # assertion and was failing roughly one run in four: `_deploy` spends a fresh
        # funding UTXO, so the rebuild re-rolls its own DER length, and a rebuild that
        # comes out SMALLER legitimately clears its own floor at this fee — the guard
        # allowing it is correct, not a miss. (Same failure mode as the covenant
        # boundary search in tests/test_fee_floor_boundary_regtest_e2e.py, which
        # avoids it by holding the state fixed across the pair.)
        #
        # (a) Deterministic, on the bytes actually in hand: the guard's own condition
        #     holds for this transaction at this size.
        assert under.fee_sats < policy.min_relay_fee(under.tx_size)
        # (b) Reached through the public builder: over several rebuilds at that fee,
        #     at least one must be refused, and anything RETURNED must clear its own
        #     floor — so no build slips through underpaying.
        refused = 0
        for _ in range(12):
            try:
                _o, rebuilt = _deploy(node, maker, taker, fee=under.fee_sats, policy=policy)
            except InsufficientFundsError:
                refused += 1
                continue
            assert rebuilt.fee_sats >= policy.min_relay_fee(rebuilt.tx_size), (
                f"the guard returned an underpaying offer: {rebuilt.fee_sats} for {rebuilt.tx_size} bytes"
            )
        assert refused > 0, "12 rebuilds at a sub-floor fee and the guard refused none of them"

        res = node.accepts(under.tx_hex)
        assert res.get("allowed") is False, f"the node ACCEPTED one photon under its own floor: {res}"
        reason = str(res.get("reject-reason", ""))
        assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
        print(
            f"one-photon-under: size={under.tx_size}B fee={under.fee_sats}ph "
            f"(floor {policy.min_relay_fee(under.tx_size)}ph at {rate}ph/kB) -> {reason}"
        )

        accepted = node.accepts(at_floor.tx_hex)
        assert accepted.get("allowed") is True, f"a fee at exactly the node's floor was rejected: {accepted}"
        print(f"at-floor: size={at_floor.tx_size}B fee={at_floor.fee_sats}ph -> accepted")

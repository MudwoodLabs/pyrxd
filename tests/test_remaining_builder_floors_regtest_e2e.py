"""Live-node proof that the new relay-floor guards ARE each node's own floor.

The offline suite (``test_remaining_builder_relay_fee_floors.py``) proves the guards are
self-consistent: they refuse what they compute. That is a statement about arithmetic. This
file asks the chain instead, in both directions and against the floor **the node itself
advertises** rather than one assumed from mainnet:

* one unit UNDER the floor — the builder refuses, AND a transaction forced past the guard
  is rejected by the node, with the reason quoted verbatim;
* exactly AT the floor — the builder returns it and the node accepts it.

Reading the rate matters, and it is what makes this file portable across node policies.
The shared Radiant harness now starts its node at MAINNET's floor, so the Radiant cases
below are measured at exactly the rate the builders ship with — but the BTC node in the
same file advertises its own, unrelated rate, and a default ``radiantd -regtest`` would
advertise a tenth of mainnet's. Every case therefore passes a ``fee_policy`` built from
``getmempoolinfo``/``getnetworkinfo`` rather than assuming any of them.

The under-floor transaction has to be FORCED into existence to ask the node about it — the
guard would otherwise refuse and there would be nothing to submit. Every case does that
with ``DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)``, the
deliberate, greppable escape hatch that already existed.

The boundary is SEARCHED FOR, not solved, on the Radiant side: the fee is part of the
signed output value, so changing it re-signs the input and can move the DER length — and
with it the size the floor is derived from. Cases retry with fresh keys until a build lands
exactly on the boundary. The BTC side needs no search: BIP340 signatures are a fixed 64
bytes, so the size does not move with the fee.

Coverage and its limits, stated rather than implied:

* PROVEN AT A NODE — ``rswp.build_cancel_tx``, ``gravity.build_claim_tx``,
  ``gravity.build_cancel_tx``, ``gravity.build_forfeit_tx``,
  ``taproot.build_claim_tx``, ``taproot.build_refund_tx``.
* NOT PROVEN AT A NODE — ``gravity.build_finalize_tx``. Its spend requires a real SPV
  proof whose headers and Merkle branch satisfy the MakerClaimed covenant's committed
  anchor; standing that up on regtest is a separate exercise from a fee boundary, and
  faking it would produce a script-level rejection that says nothing about the fee. Its
  guard is the SAME shared call as the four Radiant builders proved here, on the same
  measured ``radiant_relay_size`` input, and is covered offline.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1`` / ``BTC_REGTEST=1``. Each
suite manages its own throwaway container and tears it down. REGTEST ONLY — no mainnet
node is contacted on either chain and no real value moves. Every key comes from
``os.urandom(32)`` / ``PrivateKey()``.

Run::

    RADIANT_REGTEST=1 BTC_REGTEST=1 pytest tests/test_remaining_builder_floors_regtest_e2e.py \\
        -m integration -s
"""

from __future__ import annotations

import hashlib
import os

import coincurve
import pytest

# Reuse the isolated-regtest harnesses wholesale (the house pattern). Bare module names,
# NOT ``tests.X``: pytest's prepend import mode puts ``tests/`` on sys.path and there is no
# ``tests/__init__.py``. Both Radiant imports resolve to the SAME module-scoped container.
from test_btc_htlc_regtest_e2e import (  # noqa: F401  (btc = fixture)
    _BtcRegtest,
    btc,
)
from test_gravity_maker_offer_regtest_e2e import (
    _NBITS,
    _node_policy,
    _node_relay_rate,
    _Party,
)
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _pay_to_spk,
    _RegtestNode,
    node,
)

from pyrxd.base58 import base58check_encode
from pyrxd.btc_wallet import taproot as tr
from pyrxd.constants import Network
from pyrxd.gravity.covenant import build_gravity_offer
from pyrxd.gravity.fee_policy import DeadlineFeePolicy
from pyrxd.gravity.transactions import build_cancel_tx, build_claim_tx, build_forfeit_tx
from pyrxd.keys import PrivateKey
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import InsufficientFundsError
from pyrxd.swap.rswp import build_cancel_tx as rswp_build_cancel_tx
from pyrxd.transaction.transaction import Transaction

pytestmark = pytest.mark.integration

#: Forces an under-floor build into existence so the NODE can be asked about it. Never a
#: way to make a guard stop complaining — only a way to manufacture the negative control.
_PERMISSIVE = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)

_FUNDING = 200_000_000  # 2 RXD of plain P2PKH to work with
_CLAIM_DEADLINE = 1_900_000_000  # year 2030 — past the covenant's own baked floor
#: A deadline that is in the PAST (so ``forfeit`` is legal) but still above the MakerClaimed
#: covenant's baked ``claimDeadline`` floor of 1774427796.
_PAST_DEADLINE = 1_780_000_000


def _mainnet_p2pkh_address(pkh: bytes) -> str:
    """A version-0x00 P2PKH address for a fresh key hash.

    ``build_cancel_tx`` / ``build_forfeit_tx`` decode the payout address themselves and
    accept only Radiant's mainnet version byte (0x00) — the regtest wallet hands out
    testnet-prefixed addresses (0x6f), which they reject before any fee logic runs. The
    node only ever sees the resulting **scriptPubKey**, and a P2PKH script is a P2PKH
    script regardless of how the address was displayed, so encoding the payout this way
    changes nothing the chain checks. The key is CSPRNG and its coins are never swept.
    """
    return base58check_encode(b"\x00" + pkh)


def _btc_relay_sats_per_kvb(b: _BtcRegtest) -> int:
    """The floor THIS bitcoind advertises, in sats/kvB — read, not assumed."""
    relay_btc_per_kvb = float(b.cli("getnetworkinfo")["relayfee"])
    return round(relay_btc_per_kvb * 1e8)


def _btc_policy(b: _BtcRegtest) -> DeadlineFeePolicy:
    rate = _btc_relay_sats_per_kvb(b)
    return DeadlineFeePolicy(relay_fee_per_kb=rate, protocol_floor_per_kb=rate)


def _reason(res: dict) -> str:
    return str(res.get("reject-reason") or res.get("reject_reason") or res)


# ===========================================================================
# Radiant: the RSWP cancel — the fund-safety one.
# ===========================================================================


def _fund_p2pkh(rt: _RegtestNode, key: PrivateKey, photons: int) -> tuple[Transaction, int]:
    """Wallet-pay ``photons`` to the key's P2PKH address; return the REAL (tx, vout).

    A real parsed funding transaction, not a stub: the cancel self-spends it, so the node
    has to agree the input exists and the signature over it is valid. Anything less would
    prove the serializer, not the chain.
    """
    spk = P2PKH().lock(key.public_key().hash160()).serialize()
    addr = key.public_key().address(network=Network.TESTNET)  # regtest shares testnet prefixes
    txid = str(rt.cli("sendtoaddress", addr, f"{photons / 1e8:.8f}", wallet=True))
    rt.mine(1)
    tx = Transaction.from_hex(bytes.fromhex(str(rt.cli("getrawtransaction", txid))))
    assert tx is not None and tx.txid() == txid
    vout = next(i for i, o in enumerate(tx.outputs) if o.locking_script.serialize() == spk)
    return tx, vout


class TestRswpCancelFloorAtTheNode:
    """``build_cancel_tx`` is the ONLY hard revocation on the v2 orderbook.

    Until the cancel CONFIRMS, every copy of the signed ``0xC3`` advertisement is still
    fillable at the original price. An unrelayable cancel cannot be replaced (no RBF) or
    bumped (no CPFP), so the order stays takeable while the caller has been handed a txid
    and told it was revoked. This proves the guard's number is the node's number.
    """

    def test_cancel_boundary_is_the_nodes_own_floor(self, node):  # noqa: F811
        rate = _node_relay_rate(node)
        policy = _node_policy(node)
        print(f"\nRADIANT node advertises effective_minrelaytxfee = {rate} photons/kB")

        # The builder refuses the fee the old fixtures used, before any node is involved.
        key = PrivateKey()
        src, vout = _fund_p2pkh(node, key, _FUNDING)
        with pytest.raises(InsufficientFundsError) as ei:
            rswp_build_cancel_tx(
                offered_source_tx=src,
                offered_vout=vout,
                maker_key=key,
                refund_pkh=key.public_key().hash160(),
                fee=1_000,
                fee_policy=policy,
            )
        print(f"builder refusal at the old fixture fee: {ei.value}")

        def build(fee: int, pol):
            k = PrivateKey()
            s, v = _fund_p2pkh(node, k, _FUNDING)
            return rswp_build_cancel_tx(
                offered_source_tx=s,
                offered_vout=v,
                maker_key=k,
                refund_pkh=k.public_key().hash160(),
                fee=fee,
                fee_policy=pol,
            )

        at_floor = under = None
        for _ in range(12):
            probe = build(policy.min_relay_fee(200), policy)
            floor = policy.min_relay_fee(len(probe.serialize()))
            try:
                cand = build(floor, policy)
            except InsufficientFundsError:
                continue
            if policy.min_relay_fee(len(cand.serialize())) != floor:
                continue
            at_floor = cand
            u = build(floor - 1, _PERMISSIVE)
            if policy.min_relay_fee(len(u.serialize())) == floor:
                under = u
                break
        assert at_floor is not None, "no cancel landed exactly on its own relay floor"
        assert under is not None, "could not build a same-size cancel one photon under the floor"

        res = node.accepts(under.serialize().hex())
        assert res.get("allowed") is False, f"the node ACCEPTED one photon under its own floor: {res}"
        reason = _reason(res)
        assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
        floor = policy.min_relay_fee(len(under.serialize()))
        print(
            f"one-photon-under: size={len(under.serialize())}B fee={floor - 1}ph "
            f"(floor {floor}ph at {rate}ph/kB) -> {reason}"
        )

        ok = node.accepts(at_floor.serialize().hex())
        assert ok.get("allowed") is True, f"the node REJECTED a cancel at exactly its floor: {ok}"
        print(f"at-floor:         size={len(at_floor.serialize())}B fee={floor}ph -> accepted")

        # And it really does revoke: broadcasting it spends the offered UTXO for good.
        txid = str(node.cli("sendrawtransaction", at_floor.serialize().hex()))
        node.mine(1)
        assert node.cli("gettxout", txid, "0") is not None


# ===========================================================================
# Radiant: the gravity covenant spends.
# ===========================================================================


def _offer_for(maker: _Party, taker: _Party, deadline: int):
    return build_gravity_offer(
        maker_pkh=maker.pkh,
        maker_pk=maker.pub,
        taker_pk=taker.pub,
        taker_radiant_pkh=taker.pkh,
        btc_receive_hash=os.urandom(20),
        btc_receive_type="p2wpkh",
        btc_satoshis=100_000,
        btc_chain_anchor=os.urandom(32),
        expected_nbits=_NBITS,
        anchor_height=800_000,
        merkle_depth=12,
        claim_deadline=deadline,
        photons_offered=10_000_000,
        accept_short_deadline=True,
        reject_low_difficulty=False,
    )


def _deploy_offer(rt: _RegtestNode, maker: _Party, taker: _Party, deadline: int, policy):
    """Deploy a MakerOffer P2SH on chain and return (offer, txid, vout, photons)."""
    from pyrxd.gravity.transactions import build_maker_offer_tx

    offer = _offer_for(maker, taker, deadline)
    funding_txid = _pay_to_spk(rt, maker.p2pkh_spk, _FUNDING)
    res = build_maker_offer_tx(
        offer=offer,
        funding_txid=funding_txid,
        funding_vout=0,
        funding_photons=_FUNDING,
        fee_sats=policy.min_relay_fee(300) * 4,
        maker_privkey=maker.material,
        change_address=None,
        fee_policy=policy,
    )
    txid = str(rt.cli("sendrawtransaction", res.tx_hex))
    rt.mine(1)
    return offer, txid, 0, res.output_photons


def _boundary(rt: _RegtestNode, policy, make, label: str):
    """Shared search: return (at_floor_raw, under_raw, floor) for a Radiant builder.

    ``make(fee, policy) -> raw bytes``. Retries with fresh state until one build lands
    exactly on its own floor and a same-size build sits one photon under it.
    """
    at_floor = under = floor = None
    for _ in range(10):
        probe = make(policy.min_relay_fee(400), _PERMISSIVE)
        f = policy.min_relay_fee(len(probe))
        try:
            cand = make(f, policy)
        except InsufficientFundsError:
            continue
        if policy.min_relay_fee(len(cand)) != f:
            continue
        u = make(f - 1, _PERMISSIVE)
        if policy.min_relay_fee(len(u)) != f:
            continue
        at_floor, under, floor = cand, u, f
        break
    assert at_floor is not None, f"{label}: no build landed exactly on its own relay floor"
    return at_floor, under, floor


def _assert_boundary_at_node(rt: _RegtestNode, at_floor: bytes, under: bytes, floor: int, rate: int, label: str):
    res = rt.accepts(under.hex())
    assert res.get("allowed") is False, f"{label}: the node ACCEPTED one photon under its floor: {res}"
    reason = _reason(res)
    assert "min relay fee not met" in reason, f"{label}: rejected, but not for the fee: {res}"
    print(
        f"{label} one-photon-under: size={len(under)}B fee={floor - 1}ph (floor {floor}ph at {rate}ph/kB) -> {reason}"
    )

    ok = rt.accepts(at_floor.hex())
    assert ok.get("allowed") is True, f"{label}: the node REJECTED a tx at exactly its floor: {ok}"
    print(f"{label} at-floor:         size={len(at_floor)}B fee={floor}ph -> accepted")


class TestGravitySpendFloorsAtTheNode:
    def test_claim_boundary_is_the_nodes_own_floor(self, node):  # noqa: F811
        rate, policy = _node_relay_rate(node), _node_policy(node)

        def make(fee: int, pol) -> bytes:
            maker, taker = _Party(), _Party()
            offer, txid, vout, photons = _deploy_offer(node, maker, taker, _CLAIM_DEADLINE, policy)
            r = build_claim_tx(
                offer=offer,
                funding_txid=txid,
                funding_vout=vout,
                funding_photons=photons,
                fee_sats=fee,
                taker_privkey=taker.material,
                accept_short_deadline=True,
                fee_policy=pol,
            )
            return bytes.fromhex(r.tx_hex)

        at_floor, under, floor = _boundary(node, policy, make, "claim")
        _assert_boundary_at_node(node, at_floor, under, floor, rate, "gravity claim")

    def test_cancel_boundary_is_the_nodes_own_floor(self, node):  # noqa: F811
        rate, policy = _node_relay_rate(node), _node_policy(node)
        addr = _mainnet_p2pkh_address(_Party().pkh)

        def make(fee: int, pol) -> bytes:
            maker, taker = _Party(), _Party()
            offer, txid, vout, photons = _deploy_offer(node, maker, taker, _CLAIM_DEADLINE, policy)
            r = build_cancel_tx(
                offer=offer,
                funding_txid=txid,
                funding_vout=vout,
                funding_photons=photons,
                maker_address=addr,
                fee_sats=fee,
                maker_privkey=maker.material,
                fee_policy=pol,
            )
            return bytes.fromhex(r.tx_hex)

        at_floor, under, floor = _boundary(node, policy, make, "cancel")
        _assert_boundary_at_node(node, at_floor, under, floor, rate, "gravity cancel")

    def test_forfeit_boundary_is_the_nodes_own_floor(self, node):  # noqa: F811
        """Forfeit spends a MakerClaimed UTXO after the deadline — the Maker's last exit.

        Needs a claim first, so the offer carries a deadline that is already in the past
        (still above the covenant's own baked floor). ``claim()`` does not check the
        deadline on chain; ``forfeit()`` requires CLTV to have passed, which is why the
        transaction sets nLockTime to it.
        """
        rate, policy = _node_relay_rate(node), _node_policy(node)

        def make(fee: int, pol) -> bytes:
            maker, taker = _Party(), _Party()
            # The payout MUST go to the maker's own committed pkh: the MakerClaimed
            # covenant's forfeit branch checks it (an arbitrary address gets
            # `mandatory-script-verify-flag-failed (OP_EQUALVERIFY)`, which would be a
            # script rejection masquerading as a fee result).
            addr = _mainnet_p2pkh_address(maker.pkh)
            offer, txid, vout, photons = _deploy_offer(node, maker, taker, _PAST_DEADLINE, policy)
            claim = build_claim_tx(
                offer=offer,
                funding_txid=txid,
                funding_vout=vout,
                funding_photons=photons,
                fee_sats=policy.min_relay_fee(400) * 4,
                taker_privkey=taker.material,
                accept_short_deadline=True,
                fee_policy=policy,
            )
            claimed_txid = str(node.cli("sendrawtransaction", claim.tx_hex))
            node.mine(1)
            r = build_forfeit_tx(
                offer,
                claimed_txid,
                0,
                claim.output_photons,
                addr,
                fee,
                fee_policy=pol,
            )
            return bytes.fromhex(r.tx_hex)

        at_floor, under, floor = _boundary(node, policy, make, "forfeit")
        _assert_boundary_at_node(node, at_floor, under, floor, rate, "gravity forfeit")


# ===========================================================================
# Bitcoin: the taproot HTLC spends.
# ===========================================================================


def _xonly(sk: coincurve.PrivateKey) -> bytes:
    return sk.public_key.format(compressed=True)[1:]


class TestBtcHtlcSpendFloorsAtTheNode:
    """Bitcoin's floor is its own: 1 sat per BIP141 **vbyte**, not Radiant's 10,000
    photons per total byte. A taproot script-path spend is where that gap is widest —
    signature, preimage, leaf script and control block are all witness, all discounted 4x.
    """

    def _setup(self, b: _BtcRegtest):
        p = os.urandom(32)
        msk, tsk = coincurve.PrivateKey(os.urandom(32)), coincurve.PrivateKey(os.urandom(32))
        timeout = tr.Timelock(3, tr.TimeUnit.BLOCKS)
        htlc = tr.build_htlc(
            hashlock=hashlib.sha256(p).digest(),
            claim_pubkey_xonly=_xonly(msk),
            refund_pubkey_xonly=_xonly(tsk),
            timeout=timeout,
            network="bcrt",
        )
        loc = b.fund_htlc(htlc)
        return loc, p, msk, tsk, timeout, b.payout_spk()

    def test_claim_boundary_is_the_nodes_own_floor(self, btc):  # noqa: F811
        rate = _btc_relay_sats_per_kvb(btc)
        policy = _btc_policy(btc)
        print(f"\nBITCOIN node advertises relayfee = {rate} sats/kvB")

        loc, p, msk, _tsk, _to, spk = self._setup(btc)

        def make(fee: int, pol) -> bytes:
            return tr.build_claim_tx(
                locator=loc,
                preimage=p,
                claim_privkey=msk.secret,
                to_scriptpubkey=spk,
                fee_sats=fee,
                aux_rand=os.urandom(32),
                fee_policy=pol,
            )

        # BIP340 signatures are a fixed 64 bytes, so the size does not move with the fee
        # and the boundary needs no search: one probe gives the exact vsize.
        probe = make(1, _PERMISSIVE)
        vsize = btc.cli("decoderawtransaction", probe.hex())["vsize"]
        floor = policy.min_relay_fee(vsize)
        print(f"claim vsize (from the NODE's decoderawtransaction) = {vsize} vB -> floor {floor} sats")

        with pytest.raises(InsufficientFundsError) as ei:
            make(floor - 1, policy)
        print(f"builder refusal one sat under: {ei.value}")

        under = make(floor - 1, _PERMISSIVE)
        res = btc.accepts(under.hex())
        assert res.get("allowed") is False, f"the node ACCEPTED one sat under its own floor: {res}"
        reason = _reason(res)
        assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
        print(f"one-sat-under: vsize={vsize}vB fee={floor - 1}sat -> {reason}")

        at_floor = make(floor, policy)
        ok = btc.accepts(at_floor.hex())
        assert ok.get("allowed") is True, f"the node REJECTED a claim at exactly its floor: {ok}"
        print(f"at-floor:      vsize={vsize}vB fee={floor}sat -> accepted")
        print(f"witness discount on the at-floor tx: total={len(at_floor)}B vs vsize={vsize}vB")
        assert vsize < len(at_floor), "a taproot script-path spend must be discounted"

    def test_refund_boundary_is_the_nodes_own_floor(self, btc):  # noqa: F811
        """The refund leg matters more than the claim: it is routinely PRE-SIGNED and
        parked for a watchtower, so nothing re-checks it between signing and broadcast."""
        policy = _btc_policy(btc)
        loc, _p, _msk, tsk, timeout, spk = self._setup(btc)
        btc.mine(timeout.value)  # mature the CSV so the only possible rejection is the fee

        def make(fee: int, pol) -> bytes:
            return tr.build_refund_tx(
                locator=loc,
                refund_privkey=tsk.secret,
                timeout=timeout,
                to_scriptpubkey=spk,
                fee_sats=fee,
                aux_rand=os.urandom(32),
                fee_policy=pol,
            )

        probe = make(1, _PERMISSIVE)
        vsize = btc.cli("decoderawtransaction", probe.hex())["vsize"]
        floor = policy.min_relay_fee(vsize)

        under = make(floor - 1, _PERMISSIVE)
        res = btc.accepts(under.hex())
        assert res.get("allowed") is False, f"the node ACCEPTED one sat under its own floor: {res}"
        reason = _reason(res)
        assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
        print(f"refund one-sat-under: vsize={vsize}vB fee={floor - 1}sat -> {reason}")

        ok = btc.accepts(make(floor, policy).hex())
        assert ok.get("allowed") is True, f"the node REJECTED a refund at exactly its floor: {ok}"
        print(f"refund at-floor:      vsize={vsize}vB fee={floor}sat -> accepted")

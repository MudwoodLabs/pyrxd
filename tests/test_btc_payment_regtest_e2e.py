"""Live-regtest CONSENSUS proof for :func:`pyrxd.btc_wallet.payment.build_payment_tx`.

``build_payment_tx`` is the Gravity Taker's BTC-side leg: the payment whose bytes are
later pushed, whole, into a Radiant covenant's scriptSig as the SPV-proven leaf. It is
hand-serialized — segwit marker/flag, witness stack, BIP143 segwit-v0 sighash, all
assembled byte by byte in Python rather than through a transaction class — and every
existing test for it is offline. Those tests re-hash the builder's own output and agree
with it, which is a closed loop: an incorrect ``hashPrevouts``, a mis-serialized
scriptCode, or a witness in the wrong order produces a transaction that passes all of
them and that no node accepts.

It is also the one builder here on a chain where **size is not one number**. Bitcoin
charges relay fees against ``vsize`` (witness-discounted), while Radiant charges against
``GetTotalSize``; a fee sized against the wrong one is wrong in a direction that depends
on the chain.

What each case proves against a real ``ruimarinho/bitcoin-core:24`` node:

1. **A native-segwit (P2WPKH) input pays and confirms**, the destination receives the
   exact amount, and the change comes back to the sender's own P2WPKH script.
2. **A wrapped-segwit (P2SH-P2WPKH) input works too** — the 23-byte scriptSig branch,
   which the covenant's structural check accepts and which no offline test can
   distinguish from a wrong one — paying a P2TR destination.
3. **All four destination types are accepted**: P2PKH, P2WPKH, P2SH, P2TR.
4. **Sub-dust change is swept into the fee**, and the mined transaction really does have
   one output, with the miner keeping the difference.
5. **The signature binds the amount.** Negative control: raise the payment output by one
   satoshi after signing.
6. **The input type must match the UTXO.** Negative control: spend a P2SH-P2WPKH output
   with ``input_type="p2wpkh"``.
7. **The builder's relay-floor guard is the node's floor**, measured at the exact ``vsize``
   boundary against the rate ``getnetworkinfo`` advertises: one satoshi under is refused by
   the builder AND by the node, exactly at the floor is accepted by both. This case used to
   pin the opposite — that the builder enforced no floor at all.

Opt-in: ``@pytest.mark.integration`` + ``BTC_REGTEST=1``. Manages its own throwaway
bitcoind container; never touches mainnet and moves no real value. Keys come from
``generate_keypair`` (CSPRNG), never a literal.

Run: ``BTC_REGTEST=1 pytest tests/test_btc_payment_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import pytest

# Reuse the isolated bitcoind harness wholesale (the house pattern — the ``btc`` fixture
# starts and tears down a throwaway container and asserts the chain is regtest). Bare
# module name, NOT ``tests.X``.
from test_btc_htlc_regtest_e2e import btc  # noqa: F401  (btc = fixture)

from pyrxd.btc_wallet import BtcUtxo, build_payment_tx, generate_keypair
from pyrxd.btc_wallet.payment import DUST_LIMIT
from pyrxd.gravity.fee_policy import BITCOIN_MIN_RELAY_SATS_PER_KB, DeadlineFeePolicy
from pyrxd.security.errors import InsufficientFundsError
from pyrxd.spv.payment import P2PKH, P2SH, P2TR, P2WPKH

pytestmark = pytest.mark.integration

#: The wallet funds each throwaway keypair with this much, in BTC.
_FUND_BTC = "0.01"
#: Comfortably above the 1 sat/vB relay floor for the ~110-180 vbyte shapes here. The
#: floor itself is the subject of its own case below.
_FEE = 2_000


def _keypair():
    """A fresh regtest keypair (CSPRNG). ``bcrt`` so the addresses the node sees are ours."""
    return generate_keypair(network="bcrt")


def _fund(node, address: str, amount: str = _FUND_BTC) -> BtcUtxo:
    """Send to ``address`` from the node wallet, mine it, and return the funded outpoint."""
    txid = node.cli("sendtoaddress", address, amount, wallet=True)
    assert isinstance(txid, str), f"funding {address} failed: {txid}"
    node.mine(1)
    tx = node.cli("getrawtransaction", txid, "true")
    for out in tx["vout"]:
        spk = out["scriptPubKey"]
        if spk.get("address") == address or address in (spk.get("addresses") or []):
            return BtcUtxo(txid=txid, vout=out["n"], value=round(out["value"] * 1e8))
    raise AssertionError(f"no output of {txid} pays {address}")


def _destination(node, kind: str) -> bytes:
    """A wallet-owned destination scriptPubKey of the requested address type."""
    addr = node.cli("getnewaddress", "", kind, wallet=True)
    return bytes.fromhex(node.cli("getaddressinfo", addr, wallet=True)["scriptPubKey"])


def _confirm(node, tx_hex: str) -> dict:
    """Broadcast, mine, and return the CONFIRMED transaction as the node reports it."""
    txid = node.cli("sendrawtransaction", tx_hex)
    assert isinstance(txid, str), f"broadcast failed: {txid}"
    node.mine(1)
    confirmed = node.cli("getrawtransaction", txid, "true")
    assert confirmed["confirmations"] >= 1
    return confirmed


class TestBtcPaymentOnConsensus:
    def test_p2wpkh_input_pays_and_the_change_comes_home(self, btc):  # noqa: F811
        """Case 1: mined, the destination is paid, and the change returns to the sender."""
        kp = _keypair()
        utxo = _fund(btc, kp.p2wpkh_address)
        dest_spk = _destination(btc, "bech32")
        amount = 500_000

        result = build_payment_tx(kp, utxo, dest_spk[2:], P2WPKH, amount, _FEE, input_type="p2wpkh")
        assert result.change_sats == utxo.value - amount - _FEE

        res = btc.accepts(result.tx_hex)
        assert res.get("allowed") is True, f"BTC payment REJECTED by consensus: {res}"

        confirmed = _confirm(btc, result.tx_hex)
        # The txid the builder computed (hash256 of the NON-witness serialization) must be
        # the txid the chain assigned. A witness accidentally included in that hash would
        # show up here and nowhere in an offline test.
        assert confirmed["txid"] == result.txid
        assert len(confirmed["vout"]) == 2
        assert confirmed["vout"][0]["scriptPubKey"]["hex"] == dest_spk.hex()
        assert round(confirmed["vout"][0]["value"] * 1e8) == amount
        # Change back to the SENDER's own P2WPKH script, not anywhere else.
        assert confirmed["vout"][1]["scriptPubKey"]["hex"] == (b"\x00\x14" + kp.pkh).hex()
        assert round(confirmed["vout"][1]["value"] * 1e8) == result.change_sats
        # The miner got exactly the fee the builder reported.
        assert utxo.value - amount - result.change_sats == _FEE
        # Total size is not vsize on this chain — record both, since the fee floor below
        # is charged against the second.
        print(f"p2wpkh->p2wpkh: size={confirmed['size']}B vsize={confirmed['vsize']}vB")

    def test_p2sh_p2wpkh_input_pays_a_taproot_destination(self, btc):  # noqa: F811
        """Case 2: the wrapped-segwit branch — a 23-byte scriptSig plus a witness."""
        kp = _keypair()
        utxo = _fund(btc, kp.p2sh_p2wpkh_address)
        dest_spk = _destination(btc, "bech32m")
        assert dest_spk[:2] == b"\x51\x20", "precondition: the destination must be a v1 taproot output"
        amount = 600_000

        result = build_payment_tx(kp, utxo, dest_spk[2:], P2TR, amount, _FEE, input_type="p2sh_p2wpkh")
        res = btc.accepts(result.tx_hex)
        assert res.get("allowed") is True, f"P2SH-P2WPKH input REJECTED by consensus: {res}"

        confirmed = _confirm(btc, result.tx_hex)
        assert confirmed["vout"][0]["scriptPubKey"]["hex"] == dest_spk.hex()
        assert round(confirmed["vout"][0]["value"] * 1e8) == amount
        # The redeem-script push really is in the scriptSig, and the node validated it.
        assert confirmed["vin"][0]["scriptSig"]["hex"] == ("16" + "0014" + kp.pkh.hex())

    @pytest.mark.parametrize(
        ("addr_kind", "to_type", "hash_slice"),
        [
            ("legacy", P2PKH, slice(3, 23)),
            ("bech32", P2WPKH, slice(2, 22)),
            ("p2sh-segwit", P2SH, slice(2, 22)),
            ("bech32m", P2TR, slice(2, 34)),
        ],
    )
    def test_every_destination_type_is_accepted(self, btc, addr_kind, to_type, hash_slice):  # noqa: F811
        """Case 3: the four ``_output_script`` branches, each against a real wallet address.

        Each destination script is taken from the node's own ``getaddressinfo`` rather
        than rebuilt here, so a builder that encoded, say, P2SH as ``OP_HASH160 <h>
        OP_EQUALVERIFY`` would be caught by the comparison as well as by the node.
        """
        kp = _keypair()
        utxo = _fund(btc, kp.p2wpkh_address)
        dest_spk = _destination(btc, addr_kind)
        result = build_payment_tx(kp, utxo, dest_spk[hash_slice], to_type, 400_000, _FEE)
        res = btc.accepts(result.tx_hex)
        assert res.get("allowed") is True, f"{to_type} destination REJECTED: {res}"
        confirmed = _confirm(btc, result.tx_hex)
        assert confirmed["vout"][0]["scriptPubKey"]["hex"] == dest_spk.hex()

    def test_sub_dust_change_is_swept_into_the_fee(self, btc):  # noqa: F811
        """Case 4: below 546 sats the change output is dropped, not created.

        A dust output is non-standard and would make the whole transaction unrelayable,
        so this is a correctness requirement, not a nicety — and the sweep must show up
        as a real one-output transaction with the miner keeping the remainder.
        """
        kp = _keypair()
        utxo = _fund(btc, kp.p2wpkh_address)
        dest_spk = _destination(btc, "bech32")
        residue = DUST_LIMIT - 146  # 400 sats: change would exist, but below the limit
        amount = utxo.value - _FEE - residue

        result = build_payment_tx(kp, utxo, dest_spk[2:], P2WPKH, amount, _FEE)
        assert result.change_sats == 0, "sub-dust change must be swept, not emitted"

        res = btc.accepts(result.tx_hex)
        assert res.get("allowed") is True, f"dust-swept payment REJECTED: {res}"
        confirmed = _confirm(btc, result.tx_hex)
        assert len(confirmed["vout"]) == 1, "the swept transaction must have exactly one output"
        assert round(confirmed["vout"][0]["value"] * 1e8) == amount
        # The residue went to the miner on top of the requested fee.
        assert utxo.value - amount == _FEE + residue

    def test_raising_the_payment_amount_by_one_satoshi_is_rejected(self, btc):  # noqa: F811
        """Negative control: the BIP143 ``hashOutputs`` commitment.

        Same bytes as an accepted payment except for one satoshi on the destination
        output. If this were taken, nothing above would say anything about how much the
        recipient is actually paid.
        """
        kp = _keypair()
        utxo = _fund(btc, kp.p2wpkh_address)
        dest_spk = _destination(btc, "bech32")
        good = build_payment_tx(kp, utxo, dest_spk[2:], P2WPKH, 500_000, _FEE)
        assert btc.accepts(good.tx_hex).get("allowed") is True, "control precondition: the payment is valid"

        raw = bytearray(bytes.fromhex(good.tx_hex))
        idx = raw.find(bytes([len(dest_spk)]) + dest_spk)
        assert idx > 0, "could not locate the payment output in the serialized tx"
        value_off = idx - 8
        value = int.from_bytes(raw[value_off : value_off + 8], "little")
        assert value == 500_000
        raw[value_off : value_off + 8] = (value + 1).to_bytes(8, "little")

        res = btc.accepts(bytes(raw).hex())
        assert res.get("allowed") is False, f"consensus ACCEPTED a payment altered after signing: {res}"
        reason = str(res.get("reject-reason", ""))
        assert "script-verify" in reason, f"rejected, but not by signature verification: {res}"
        print(f"mutated-amount control reject-reason: {reason}")

    def test_a_p2sh_wrapped_utxo_spent_as_native_segwit_is_rejected(self, btc):  # noqa: F811
        """Negative control: ``input_type`` is not cosmetic.

        Spending a P2SH-P2WPKH output with an EMPTY scriptSig leaves the P2SH redeem
        script unsupplied. The builder cannot tell — it never sees the UTXO's script —
        so the only thing standing between a caller's mistake and a stuck payment is the
        node, and this records what the node says.
        """
        kp = _keypair()
        utxo = _fund(btc, kp.p2sh_p2wpkh_address)
        dest_spk = _destination(btc, "bech32")
        wrong = build_payment_tx(kp, utxo, dest_spk[2:], P2WPKH, 500_000, _FEE, input_type="p2wpkh")

        res = btc.accepts(wrong.tx_hex)
        assert res.get("allowed") is False, f"consensus ACCEPTED a wrapped-segwit UTXO spent as native: {res}"
        print(f"wrong-input-type control reject-reason: {res.get('reject-reason', '')}")

        # The same UTXO with the right input_type IS accepted — so the refusal is about
        # the scriptSig, not about the funding.
        right = build_payment_tx(kp, utxo, dest_spk[2:], P2WPKH, 500_000, _FEE, input_type="p2sh_p2wpkh")
        assert btc.accepts(right.tx_hex).get("allowed") is True

    def test_build_payment_tx_refuses_a_fee_below_the_relay_floor(self, btc):  # noqa: F811
        """The builder's floor guard, proved against the floor this node advertises.

        This case previously pinned the opposite — that ``fee_sats`` was taken entirely on
        trust, so ``build_payment_tx`` returned a well-formed ``BtcPaymentTx`` (correct
        ``txid``, correct ``change_sats``) for a zero-fee transaction no node will relay.
        That was recorded as a finding; it is now guarded, and this case asserts the guard.

        On Bitcoin an under-fee'd payment is recoverable — RBF, CPFP, or simply rebuilding
        — so this is genuinely a lesser problem than the same gap on Radiant. It is still
        the builder's job to fail closed rather than hand back unbroadcastable bytes.

        The floor is read from the node (``getnetworkinfo.relayfee``), not assumed, and
        the boundary is proved in both directions. Bitcoin Core charges against BIP141
        ``vsize``, so at 1 sat/vB the floor in satoshis is numerically the vsize — which
        is also the demonstration that sizing this builder against **total** size (what
        Radiant requires) would over-charge here by roughly the witness discount.
        """
        kp = _keypair()
        dest_spk = _destination(btc, "bech32")

        node_relay_btc_per_kvb = float(btc.cli("getnetworkinfo")["relayfee"])
        node_rate = round(node_relay_btc_per_kvb * 1e8)  # sats per kvB
        print(f"node advertises relayfee = {node_relay_btc_per_kvb} BTC/kvB = {node_rate} sats/kvB")
        assert node_rate == BITCOIN_MIN_RELAY_SATS_PER_KB, (
            f"this node's floor ({node_rate} sats/kvB) differs from the builder default "
            f"({BITCOIN_MIN_RELAY_SATS_PER_KB}); the boundary below would be proved at the wrong rate"
        )
        policy = DeadlineFeePolicy(
            relay_fee_per_kb=node_rate,
            protocol_floor_per_kb=BITCOIN_MIN_RELAY_SATS_PER_KB,
        )

        # ---- a zero fee is now refused outright ----------------------------
        utxo = _fund(btc, kp.p2wpkh_address)
        with pytest.raises(InsufficientFundsError) as exc:
            build_payment_tx(kp, utxo, dest_spk[2:], P2WPKH, utxo.value, 0)
        print(f"builder refusal at a zero fee: {exc.value}")

        # ---- the boundary, both sides --------------------------------------
        # `permissive` exists only to FORCE the under-floor transaction into existence so
        # the node can be asked about it; the guard would otherwise refuse and there would
        # be nothing to submit.
        permissive = DeadlineFeePolicy(relay_fee_per_kb=1, allow_below_protocol_floor=True)

        def _build(fee: int, u: BtcUtxo, pol) -> tuple[int, str]:
            built = build_payment_tx(kp, u, dest_spk[2:], P2WPKH, u.value - fee - 100_000, fee, fee_policy=pol)
            probe = btc.accepts(built.tx_hex)
            # testmempoolaccept reports vsize on acceptance only; fall back to a decode.
            vsize = probe.get("vsize") or btc.cli("decoderawtransaction", built.tx_hex)["vsize"]
            return int(vsize), built.tx_hex

        # Searched, not solved: the fee is part of the change output value and therefore of
        # the BIP143 preimage, so changing it re-signs the input and can move the DER length
        # by a byte. A fresh funding UTXO each round re-rolls that independently.
        at_floor_hex = under_hex = None
        at_vsize = under_vsize = 0
        for _ in range(10):
            u = _fund(btc, kp.p2wpkh_address)
            probe_vsize, _ = _build(400, u, policy)
            fee = policy.min_relay_fee(probe_vsize)
            u2 = _fund(btc, kp.p2wpkh_address)
            vsize, tx_hex = _build(fee, u2, policy)
            if fee != policy.min_relay_fee(vsize):
                continue  # not on the boundary; the re-sign moved the size
            at_floor_hex, at_vsize = tx_hex, vsize
            u3 = _fund(btc, kp.p2wpkh_address)
            v_u, tx_u = _build(fee - 1, u3, permissive)
            if v_u == vsize:
                under_hex, under_vsize = tx_u, v_u
                break
        assert at_floor_hex is not None, "no payment reached a fee equal to its own vsize floor"
        assert under_hex is not None, "could not build a same-vsize payment one satoshi under the floor"

        # The guard itself refuses that fee.
        with pytest.raises(InsufficientFundsError):
            _build(policy.min_relay_fee(under_vsize) - 1, _fund(btc, kp.p2wpkh_address), policy)

        res = btc.accepts(under_hex)
        assert res.get("allowed") is False, f"one satoshi below the vsize floor was ACCEPTED: {res}"
        reason = str(res.get("reject-reason", ""))
        assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
        print(f"one-sat-under: vsize={under_vsize}vB fee={policy.min_relay_fee(under_vsize) - 1}sat -> {reason}")

        res = btc.accepts(at_floor_hex)
        assert res.get("allowed") is True, f"a fee of exactly vsize satoshis was REJECTED: {res}"
        print(f"at-floor: vsize={at_vsize}vB fee={policy.min_relay_fee(at_vsize)}sat -> accepted")

        # And the total serialization really is larger than the vsize the floor used, so
        # Radiant's total-size rule would have demanded strictly more here.
        total = len(bytes.fromhex(at_floor_hex))
        assert total > at_vsize, f"expected a witness discount: total={total}B vsize={at_vsize}vB"
        print(f"witness discount on the at-floor tx: total={total}B vs vsize={at_vsize}vB")

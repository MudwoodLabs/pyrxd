"""Live-regtest CONSENSUS proof for ``RxdWallet.build_send_tx`` / ``build_send_max_tx``.

Plain RXD sends are the most-used path in the SDK, and until this module every
test covering them was offline: they asserted on the builder's own return value,
which is the one witness that cannot detect a builder that produces plausible
bytes a node will not take. This repo has shipped exactly that failure mode more
than once — the non-minimal height push that made every pre-redesign V2 contract
un-mineable, the multi-ref sighash endianness bug, and the CONTAINER builder that
emitted an unspendable output for four releases.

Every assertion below is read back off a transaction the node CONFIRMED, or off
the node's own UTXO set (``scantxoutset``), never off the ``Transaction`` object
the builder returned.

What each case proves:

1. **An ordinary send with change is accepted, mined, and lands where it says.**
   Recipient value, change value, and the disappearance of the funding outpoint
   are all read from the chain.
2. **The change output is spendable.** A change output that no key can redeem
   still looks perfect from Python — the CONTAINER bug shipped for four releases
   on exactly that blind spot — so the change is re-spent by a second builder
   call and confirmed.
3. **Multi-input selection spends exactly the coins it selected**, and leaves the
   coins it did not select untouched in the UTXO set.
4. **``send_max`` strands nothing.** After confirmation the wallet's own script
   has an EMPTY UTXO set: every photon moved or became fee.
5. **The fee actually paid equals the fee the builder reported**, derived by
   re-fetching each input's source transaction from the node.
6. **Neither builder can emit a transaction below the relay floor.** It used to:
   the fee was sized from a TRIAL signing pass and never re-measured after the
   final pass, so whenever the final DER signature came out longer than the trial
   one the transaction paid for fewer bytes than it contained — 25.4%-38.1% of
   builds, measured. The node refused those with ``66: min relay fee not met``,
   and Radiant has neither RBF nor CPFP, so they could not be repaired. The fee is
   now sized with per-input signature headroom and the FINAL transaction is
   re-measured and refused if it falls short (``pyrxd.fee_sizing``). Every build
   below is put to the node.

Negative controls, because a node that accepted everything would make every
"accepted" above meaningless — each one quotes the node's own reject reason:

* mutating an output after signing → ``mandatory-script-verify-flag-failed``
* re-signed outputs exceeding inputs → ``bad-txns-in-belowout``
* a stranger's key over the wallet's coin → ``OP_EQUALVERIFY`` failure
* a hand-built fee ONE PHOTON under the floor → ``min relay fee not met``, with the
  same transaction accepted at exactly the floor. Without this pair, "the wallet's
  sends are accepted" would be equally true of a node that rejects nothing.

Opt-in: ``@pytest.mark.integration`` + ``RADIANT_REGTEST=1``. Never runs in normal
CI. Manages its own throwaway container; moves no real value; regtest only.

Run: ``RADIANT_REGTEST=1 pytest tests/test_wallet_send_regtest_e2e.py -m integration -s``
"""

from __future__ import annotations

import json

import pytest

# Reuse the isolated-regtest harness wholesale (same pattern as the FT-airdrop and
# dMint e2e tests): the ``node`` fixture spins up + tears down a throwaway container.
from test_htlc_regtest_e2e import (  # noqa: F401  (node = fixture)
    _p2pkh_unlock,
    _pay_to_spk,
    _RegtestNode,
    _src,
    node,
)

from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.script import Script
from pyrxd.script.type import P2PKH
from pyrxd.security.errors import ValidationError
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.wallet import DEFAULT_FEE_RATE, RxdWallet

pytestmark = pytest.mark.integration

# 5 RXD per funded coin. Large enough that a 1-RXD send leaves change well clear
# of any wallet floor, small enough to fund many of them from one regtest coinbase.
_FUND = 500_000_000
_SEND = 100_000_000

_UNUSED_URL = "wss://unused.invalid"  # no network call is made by the builders


# --------------------------------------------------------------------------- helpers


def _wallet(fee_rate: int = DEFAULT_FEE_RATE) -> RxdWallet:
    """A wallet on a freshly generated key. Never a hard-coded key: weak inline
    test keys in this repo were once swept by a live bot."""
    return RxdWallet(PrivateKey(), _UNUSED_URL, fee_rate=fee_rate)


def _spk(address: str) -> bytes:
    return P2PKH().lock(address).serialize()


def _fund(rt: _RegtestNode, wallet: RxdWallet, value: int = _FUND) -> UtxoRecord:
    """Pay ``value`` to the wallet's P2PKH script and mine it. Returns the coin."""
    txid = _pay_to_spk(rt, _spk(wallet.address), value)
    return UtxoRecord(tx_hash=txid, tx_pos=0, value=value, height=1)


def _photons(rxd_value: float) -> int:
    """Convert a node-reported RXD amount to photons."""
    return round(rxd_value * 100_000_000)


def _confirm(rt: _RegtestNode, tx: Transaction) -> dict:
    """Accept-check, broadcast, mine, and return the CONFIRMED verbose tx.

    Every later assertion reads this dict, not the ``tx`` object.
    """
    raw = tx.serialize().hex()
    res = rt.accepts(raw)
    assert res.get("allowed") is True, f"consensus REJECTED a wallet send: {res}"
    txid = str(rt.cli("sendrawtransaction", raw))
    rt.mine(1)
    confirmed = rt.cli("getrawtransaction", txid, "true")
    assert confirmed["confirmations"] >= 1
    return confirmed


def _utxo_set(rt: _RegtestNode, spk: bytes) -> dict:
    """The node's own UTXO-set view of one scriptPubKey.

    ``addr()`` descriptors are unusable here: pyrxd emits mainnet-format
    addresses and the regtest node rejects them, so scan the raw script.
    """
    res = rt.cli("scantxoutset", "start", json.dumps([f"raw({spk.hex()})"]))
    assert res["success"] is True
    return res


def _chain_fee(rt: _RegtestNode, confirmed: dict) -> int:
    """Fee in photons, derived purely from the chain.

    Re-fetches every input's source transaction so the input side is the node's
    number, not the test's bookkeeping.
    """
    total_in = 0
    for vin in confirmed["vin"]:
        src_tx = rt.cli("getrawtransaction", vin["txid"], "true")
        total_in += _photons(src_tx["vout"][vin["vout"]]["value"])
    total_out = sum(_photons(o["value"]) for o in confirmed["vout"])
    return total_in - total_out


def _outputs_by_script(confirmed: dict) -> dict[str, int]:
    """Map scriptPubKey hex → total photons paid to it in this transaction."""
    out: dict[str, int] = {}
    for o in confirmed["vout"]:
        spk_hex = o["scriptPubKey"]["hex"]
        out[spk_hex] = out.get(spk_hex, 0) + _photons(o["value"])
    return out


def _relay_floor(rt: _RegtestNode) -> int:
    """The node's own minimum relay fee, in photons per byte.

    Read from the node rather than assumed: the constant pyrxd builds against
    (``DEFAULT_FEE_RATE`` = 10_000/byte) is the MAINNET floor, and a default
    regtest node runs 10x lower. Reading it makes the node the oracle for its
    own policy at whatever rate it happens to enforce.
    """
    info = rt.cli("getnetworkinfo")
    return round(info["relayfee"] * 100_000_000 / 1000)


def _effective_rate(tx: Transaction) -> float:
    """Photons per byte this transaction actually pays, against its TOTAL size.

    Radiant checks the relay floor against ``GetTotalSize()`` — there is no
    witness discount and no vsize on this chain.
    """
    return tx.get_fee() / len(tx.serialize())


# --------------------------------------------------------------------------- build_send_tx


def test_single_input_send_with_change_confirms_on_chain(node):  # noqa: F811
    """Case 1: the ordinary send. Two outputs, both verified off the chain."""
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coin = _fund(node, wallet)

    tx = wallet.build_send_tx([coin], recipient, _SEND)
    confirmed = _confirm(node, tx)

    assert len(confirmed["vin"]) == 1, "a 5-RXD coin should cover a 1-RXD send by itself"
    assert len(confirmed["vout"]) == 2, "expected recipient + change"

    paid = _outputs_by_script(confirmed)
    assert paid[_spk(recipient).hex()] == _SEND, "recipient did not receive the requested amount"
    change_on_chain = paid[_spk(wallet.address).hex()]

    # The funding coin is gone from the UTXO set and the change replaced it.
    assert node.cli("gettxout", coin.tx_hash, str(coin.tx_pos)) in ("", None), "funding coin was not spent"
    wallet_set = _utxo_set(node, _spk(wallet.address))
    assert _photons(wallet_set["total_amount"]) == change_on_chain
    assert len(wallet_set["unspents"]) == 1

    recipient_set = _utxo_set(node, _spk(recipient))
    assert _photons(recipient_set["total_amount"]) == _SEND

    # Conservation, and the fee is genuinely what the builder said.
    assert _SEND + change_on_chain + _chain_fee(node, confirmed) == _FUND
    assert _chain_fee(node, confirmed) == tx.get_fee()


def test_mutating_a_send_output_after_signing_is_rejected(node):  # noqa: F811
    """Negative control for case 1.

    The signature must commit to the output values, or "accepted" above proves
    nothing about where the money went. Inflate the recipient output by a single
    photon WITHOUT re-signing and the node must refuse it.
    """
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coin = _fund(node, wallet)

    tx = wallet.build_send_tx([coin], recipient, _SEND)
    assert node.accepts(tx.serialize().hex()).get("allowed") is True

    tx.outputs[0].satoshis += 1
    res = node.accepts(tx.serialize().hex())
    assert res.get("allowed") is False, f"consensus ACCEPTED a tampered send — the positive cases prove nothing: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "mandatory-script-verify-flag-failed" in reason, (
        f"rejected, but not by the signature check this control is testing: {res}"
    )
    print(f"tamper-after-sign reject-reason: {reason}")


def test_multi_input_send_spends_exactly_the_coins_it_selected(node):  # noqa: F811
    """Case 3: greedy descending selection, verified against the chain's view.

    Three coins, an amount only the two largest can cover. The chain must show
    those two consumed and the third still unspent.
    """
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    big = _fund(node, wallet, 400_000_000)
    mid = _fund(node, wallet, 300_000_000)
    small = _fund(node, wallet, 100_000_000)

    amount = 650_000_000  # needs big + mid, not small
    tx = wallet.build_send_tx([small, big, mid], recipient, amount)
    confirmed = _confirm(node, tx)

    spent = {(v["txid"], v["vout"]) for v in confirmed["vin"]}
    assert spent == {(big.tx_hash, big.tx_pos), (mid.tx_hash, mid.tx_pos)}, (
        f"selection spent the wrong coins: {sorted(spent)}"
    )
    assert node.cli("gettxout", small.tx_hash, str(small.tx_pos)) not in ("", None), (
        "an unselected coin was consumed anyway"
    )

    paid = _outputs_by_script(confirmed)
    assert paid[_spk(recipient).hex()] == amount
    change = paid[_spk(wallet.address).hex()]
    assert amount + change + _chain_fee(node, confirmed) == big.value + mid.value
    assert _chain_fee(node, confirmed) == tx.get_fee()


def test_a_send_paying_out_more_than_its_inputs_is_rejected(node):  # noqa: F811
    """Negative control for case 3: value cannot be created.

    Re-SIGNED (not merely tampered), so the signature is valid and only the
    conservation rule can stop it. If a node accepted this, every balance
    assertion in this module would be worthless.
    """
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coin = _fund(node, wallet)

    overspend = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(coin.tx_hash, coin.tx_pos, _spk(wallet.address), coin.value),
                source_txid=coin.tx_hash,
                source_output_index=coin.tx_pos,
                unlocking_script_template=_p2pkh_unlock(wallet._private_key),
            )
        ],
        tx_outputs=[TransactionOutput(P2PKH().lock(recipient), coin.value + 1)],
    )
    overspend.sign()

    res = node.accepts(overspend.serialize().hex())
    assert res.get("allowed") is False, f"consensus ACCEPTED a value-creating send: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "bad-txns-in-belowout" in reason, f"rejected, but not by the conservation rule this control tests: {res}"
    print(f"overspend reject-reason: {reason}")


def test_change_output_is_spendable_by_the_wallet(node):  # noqa: F811
    """Case 2: the change is real money, not a plausible-looking dead end.

    A locking script nobody can redeem serialises exactly as cleanly as one that
    works — that is precisely how the CONTAINER builder shipped an unspendable
    output for four releases. The only proof is a second transaction that spends
    the change and is itself confirmed.
    """
    wallet = _wallet()
    coin = _fund(node, wallet)
    first = _confirm(node, wallet.build_send_tx([coin], PrivateKey().public_key().address(), _SEND))

    change_vout = next(i for i, o in enumerate(first["vout"]) if o["scriptPubKey"]["hex"] == _spk(wallet.address).hex())
    change = UtxoRecord(
        tx_hash=first["txid"],
        tx_pos=change_vout,
        value=_photons(first["vout"][change_vout]["value"]),
        height=1,
    )

    second_recipient = PrivateKey().public_key().address()
    second = _confirm(node, wallet.build_send_tx([change], second_recipient, _SEND))

    assert (change.tx_hash, change.tx_pos) in {(v["txid"], v["vout"]) for v in second["vin"]}
    assert _outputs_by_script(second)[_spk(second_recipient).hex()] == _SEND
    assert node.cli("gettxout", change.tx_hash, str(change.tx_pos)) in ("", None), "change output was never consumed"


def test_change_output_cannot_be_spent_by_another_key(node):  # noqa: F811
    """Negative control for case 2.

    Spendable-by-the-wallet is only meaningful if it is not spendable by anyone
    else. A stranger's signature over the same coin must die on the P2PKH
    pubkey-hash check.
    """
    wallet = _wallet()
    coin = _fund(node, wallet)
    stranger = PrivateKey()

    forged = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(coin.tx_hash, coin.tx_pos, _spk(wallet.address), coin.value),
                source_txid=coin.tx_hash,
                source_output_index=coin.tx_pos,
                unlocking_script_template=_p2pkh_unlock(stranger),
            )
        ],
        tx_outputs=[TransactionOutput(P2PKH().lock(stranger.public_key().address()), coin.value - 5_000_000)],
    )
    forged.sign()

    res = node.accepts(forged.serialize().hex())
    assert res.get("allowed") is False, f"consensus let a STRANGER spend the wallet's coin: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "OP_EQUALVERIFY" in reason, f"rejected, but not by the pubkey-hash check this control tests: {res}"
    print(f"stranger-key reject-reason: {reason}")


def test_change_below_the_send_policy_floor_is_burned_to_fee(node):  # noqa: F811
    """The 546-photon floor is a pyrxd SEND POLICY, not a chain rule.

    Radiant has no dust threshold (``GetDustThreshold`` returns 1), so a sub-546
    change output would relay fine; pyrxd drops it into the fee instead. Prove
    the resulting one-output transaction is real, and that the burned remainder
    shows up as fee on the chain rather than vanishing from the ledger.
    """
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coin = _fund(node, wallet)

    # Search offline for a send amount that leaves sub-floor change. The window is
    # only 546 photons wide and it sits just under whatever fee the build lands on,
    # so calibrate from a real build rather than a hard-coded constant — the fee
    # moves whenever the sizing changes, and a stale constant would turn this test
    # into "could not land a sub-floor change amount" rather than a real failure.
    # The probe's own fee can be a byte or two off the next build's (DER lengths
    # vary), hence the small sweep around it.
    probe_fee = wallet.build_send_tx([coin], recipient, _SEND).get_fee()
    tx = None
    for byte_delta in (0, 1, -1, 2, -2, 3):
        base = probe_fee + byte_delta * wallet.fee_rate
        for slack in range(1, 546):
            try:
                candidate = wallet.build_send_tx([coin], recipient, _FUND - base - slack)
            except ValidationError:
                continue  # this slack put the fee above what the coin can pay
            if len(candidate.outputs) == 1:
                tx = candidate
                break
        if tx is not None:
            break
    assert tx is not None, "could not land a sub-floor change amount against this coin"

    confirmed = _confirm(node, tx)
    assert len(confirmed["vout"]) == 1, "the dust change output should have been dropped"
    fee = _chain_fee(node, confirmed)
    assert fee == coin.value - _photons(confirmed["vout"][0]["value"])
    assert fee == tx.get_fee()
    # Nothing is left behind for the wallet.
    assert _photons(_utxo_set(node, _spk(wallet.address))["total_amount"]) == 0


# --------------------------------------------------------------------------- build_send_max_tx


def test_send_max_sweeps_every_coin_and_strands_nothing(node):  # noqa: F811
    """Case 4: the whole balance moves, verified against the node's UTXO set."""
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coins = [_fund(node, wallet, 400_000_000), _fund(node, wallet, 250_000_000), _fund(node, wallet, 90_000_000)]
    total_in = sum(c.value for c in coins)

    before = _utxo_set(node, _spk(wallet.address))
    assert _photons(before["total_amount"]) == total_in

    tx = wallet.build_send_max_tx(coins, recipient)
    confirmed = _confirm(node, tx)

    assert len(confirmed["vin"]) == len(coins), "send_max did not consume every coin"
    assert {(v["txid"], v["vout"]) for v in confirmed["vin"]} == {(c.tx_hash, c.tx_pos) for c in coins}
    assert len(confirmed["vout"]) == 1, "send_max must not emit a change output"

    swept = _photons(confirmed["vout"][0]["value"])
    assert confirmed["vout"][0]["scriptPubKey"]["hex"] == _spk(recipient).hex()

    after = _utxo_set(node, _spk(wallet.address))
    assert after["unspents"] == [], f"send_max stranded coins on the source wallet: {after}"
    assert _photons(after["total_amount"]) == 0

    fee = _chain_fee(node, confirmed)
    assert swept + fee == total_in, "photons went missing across the sweep"
    assert fee == tx.get_fee()
    assert _photons(_utxo_set(node, _spk(recipient))["total_amount"]) == swept


def test_send_max_cannot_pay_out_more_than_it_swept(node):  # noqa: F811
    """Negative control for case 4: the sweep total is enforced, not asserted."""
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coins = [_fund(node, wallet, 300_000_000), _fund(node, wallet, 200_000_000)]
    total_in = sum(c.value for c in coins)

    inflated = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(c.tx_hash, c.tx_pos, _spk(wallet.address), c.value),
                source_txid=c.tx_hash,
                source_output_index=c.tx_pos,
                unlocking_script_template=_p2pkh_unlock(wallet._private_key),
            )
            for c in coins
        ],
        tx_outputs=[TransactionOutput(P2PKH().lock(recipient), total_in + 1)],
    )
    inflated.sign()

    res = node.accepts(inflated.serialize().hex())
    assert res.get("allowed") is False, f"consensus ACCEPTED a sweep paying out more than it swept: {res}"
    reason = str(res.get("reject-reason", ""))
    assert "bad-txns-in-belowout" in reason, f"rejected, but not by the conservation rule this control tests: {res}"
    print(f"send_max overspend reject-reason: {reason}")


# --------------------------------------------------------------------------- fee accounting


@pytest.mark.parametrize("n_coins", [1, 2, 3])
def test_fee_paid_matches_the_fee_the_builder_reported(node, n_coins):  # noqa: F811
    """Case 5: the builder's arithmetic and the chain's agree, at several shapes.

    ``get_fee()`` is the number a caller sees; the chain's number is inputs minus
    outputs with the inputs re-fetched from the node. A builder that silently
    took its fee from somewhere else would diverge here.
    """
    wallet = _wallet()
    recipient = PrivateKey().public_key().address()
    coins = [_fund(node, wallet, 200_000_000) for _ in range(n_coins)]
    amount = 150_000_000 * n_coins

    tx = wallet.build_send_tx(coins, recipient, amount)
    reported = tx.get_fee()
    confirmed = _confirm(node, tx)
    assert _chain_fee(node, confirmed) == reported, "the fee the builder reported is not the fee the chain took"

    # And the size the fee was charged against is the total serialised size the
    # node saw — Radiant has no vsize discount.
    assert confirmed["size"] == len(tx.serialize())


# --------------------------------------------------------------------------- the relay floor


def _fee_at_exactly(wallet: RxdWallet, coin: UtxoRecord, recipient: str, fee_of_size) -> Transaction:
    """A hand-built 1-in/1-out P2PKH send paying exactly ``fee_of_size(its own size)``.

    Built OUTSIDE ``RxdWallet``'s fee sizing on purpose: this is how the negative
    control produces the below-floor transaction that the builders no longer will.
    Signing is re-run until the assumed size matches the signed size, because the
    DER signature length is not fixed — which is the very thing that made the
    builders underpay.
    """
    size = 226  # a plausible 1-in/2-out P2PKH send; only the first guess
    for _ in range(60):
        fee = fee_of_size(size)
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=_src(coin.tx_hash, coin.tx_pos, _spk(wallet.address), coin.value),
                    source_txid=coin.tx_hash,
                    source_output_index=coin.tx_pos,
                    unlocking_script_template=_p2pkh_unlock(wallet._private_key),
                )
            ],
            tx_outputs=[TransactionOutput(P2PKH().lock(recipient), coin.value - fee)],
        )
        tx.sign()
        signed_size = len(tx.serialize())
        if signed_size == size:
            return tx
        size = signed_size
    raise AssertionError("could not settle on a signed size — the DER length never repeated")


def test_a_fee_one_photon_under_the_floor_is_rejected(node):  # noqa: F811
    """Negative control for the whole fee story, and the boundary it turns on.

    Hand-build the same transaction twice: once paying exactly ``size × floor`` and
    once paying one photon less. The node must take the first and refuse the
    second. Without this, "every wallet send is accepted" would be satisfied by a
    node that never rejects anything, and the fix below would prove nothing.

    One photon, not a round number, because that is the real margin: the node's
    check is ``nModifiedFees < GetEffectiveMinRelayFee(height).GetFee(nSize)``.
    """
    floor = _relay_floor(node)
    wallet = _wallet(fee_rate=floor)
    recipient = PrivateKey().public_key().address()

    at_floor = _fee_at_exactly(wallet, _fund(node, wallet), recipient, lambda s: s * floor)
    ok = node.accepts(at_floor.serialize().hex())
    assert ok.get("allowed") is True, (
        f"node refused a fee EXACTLY at its own floor — the control is miscalibrated: {ok}"
    )

    short = _fee_at_exactly(wallet, _fund(node, wallet), recipient, lambda s: s * floor - 1)
    size, fee = len(short.serialize()), short.get_fee()
    assert fee == size * floor - 1, "the control did not land exactly one photon short"

    res = node.accepts(short.serialize().hex())
    assert res.get("allowed") is False, (
        f"node ACCEPTED a fee one photon under its own floor ({fee} on {size} bytes at {floor}/byte): {res}"
    )
    reason = str(res.get("reject-reason", ""))
    assert "min relay fee not met" in reason, f"rejected, but not for the fee: {res}"
    print(f"one photon short: size={size} fee={fee} (floor {size * floor}) -> {reason}")


def test_every_send_pays_at_least_the_rate_it_was_built_for(node):  # noqa: F811
    """REGRESSION: the invariant both builders must hold, judged by the node.

    Builds at the node's OWN advertised floor — so the node is the oracle for its
    own policy — and requires every result to relay. This was a ``strict=True``
    xfail while the fee was sized off the trial signing pass and the final signed
    transaction was never re-measured; roughly a third of builds paid below the
    requested rate. ``pyrxd.fee_sizing`` now adds per-input signature headroom and
    re-measures the final transaction, and the marker is gone.

    40 rounds each, with a different recipient every time. Signing is deterministic
    (RFC 6979), so whether a transaction underpays is a fixed property of that
    transaction rather than a per-run coin flip — one hard-coded send would have
    passed forever while a third of real ones failed.

    ``DEFAULT_FEE_RATE`` is exactly the mainnet relay floor, so what the regtest
    node refuses here is what mainnet refuses — and with neither RBF nor CPFP,
    such a transaction cannot be fee-bumped, only abandoned for 8 hours.
    """
    assert DEFAULT_FEE_RATE == 10_000, "the mainnet-floor assumption in this test's reasoning has moved"
    floor = _relay_floor(node)
    wallet = _wallet(fee_rate=floor)
    coin = _fund(node, wallet)
    sweep_coins = [_fund(node, wallet, 300_000_000), _fund(node, wallet, 200_000_000)]

    for _ in range(40):
        tx = wallet.build_send_tx([coin], PrivateKey().public_key().address(), _SEND)
        assert _effective_rate(tx) >= floor, f"send paid {_effective_rate(tx):.2f}/byte for a {floor}/byte floor"
        assert node.accepts(tx.serialize().hex()).get("allowed") is True

        sweep = wallet.build_send_max_tx(sweep_coins, PrivateKey().public_key().address())
        assert _effective_rate(sweep) >= floor, f"sweep paid {_effective_rate(sweep):.2f}/byte"
        assert node.accepts(sweep.serialize().hex()).get("allowed") is True


@pytest.mark.parametrize("n_inputs", [1, 3])
def test_multi_input_sends_and_sweeps_all_relay_at_the_floor(node, n_inputs):  # noqa: F811
    """The same regression across input counts — the shortfall grew with them.

    Offline measurement before the fix: 25.4% short at one input rising to 36.8%
    at five, because each extra input is another signature that can change length.
    Every build here is put to the node, and one of each is actually confirmed so
    the acceptance is not only ``testmempoolaccept``.
    """
    floor = _relay_floor(node)
    wallet = _wallet(fee_rate=floor)
    coins = [_fund(node, wallet, 300_000_000) for _ in range(n_inputs)]
    sweep_wallet = _wallet(fee_rate=floor)
    sweep_coins = [_fund(node, sweep_wallet, 300_000_000) for _ in range(n_inputs)]

    for _ in range(25):
        tx = wallet.build_send_tx(coins, PrivateKey().public_key().address(), 200_000_000 * n_inputs)
        res = node.accepts(tx.serialize().hex())
        assert res.get("allowed") is True, (
            f"node refused a {n_inputs}-input send built at its own floor: {res} "
            f"(size {len(tx.serialize())}, fee {tx.get_fee()})"
        )
        sweep = sweep_wallet.build_send_max_tx(sweep_coins, PrivateKey().public_key().address())
        res = node.accepts(sweep.serialize().hex())
        assert res.get("allowed") is True, (
            f"node refused a {n_inputs}-input sweep built at its own floor: {res} "
            f"(size {len(sweep.serialize())}, fee {sweep.get_fee()})"
        )

    confirmed = _confirm(node, wallet.build_send_tx(coins, PrivateKey().public_key().address(), 200_000_000 * n_inputs))
    assert _chain_fee(node, confirmed) >= confirmed["size"] * floor, "a CONFIRMED send was under the floor"

    swept = _confirm(node, sweep_wallet.build_send_max_tx(sweep_coins, PrivateKey().public_key().address()))
    assert _chain_fee(node, swept) >= swept["size"] * floor, "a CONFIRMED sweep was under the floor"


def test_a_one_photon_output_relays_so_546_is_policy_not_consensus(node):  # noqa: F811
    """Supporting fact for the burned-change case above.

    ``DUST_THRESHOLD`` is documented in ``wallet.py`` as a send-policy floor
    rather than a chain rule. If the chain did reject sub-546 outputs, burning
    that change to fee would be a requirement instead of a choice — so the claim
    is worth holding a node to.
    """
    wallet = _wallet()
    coin = _fund(node, wallet)
    tiny_recipient = PrivateKey().public_key().address()

    tx = Transaction(
        tx_inputs=[
            TransactionInput(
                source_transaction=_src(coin.tx_hash, coin.tx_pos, _spk(wallet.address), coin.value),
                source_txid=coin.tx_hash,
                source_output_index=coin.tx_pos,
                unlocking_script_template=_p2pkh_unlock(wallet._private_key),
            )
        ],
        tx_outputs=[
            TransactionOutput(P2PKH().lock(tiny_recipient), 1),
            TransactionOutput(Script(_spk(wallet.address)), coin.value - 5_000_000 - 1),
        ],
    )
    tx.sign()

    confirmed = _confirm(node, tx)
    assert _photons(_utxo_set(node, _spk(tiny_recipient))["total_amount"]) == 1
    assert any(_photons(o["value"]) == 1 for o in confirmed["vout"]), "the 1-photon output did not survive"

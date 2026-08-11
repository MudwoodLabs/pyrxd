"""The relay-floor negative control must be constructible OFFLINE and every time.

Why this file exists
--------------------
``tests/test_wallet_send_regtest_e2e.py`` proves the wallet's sends are accepted by a
real node. That claim is only worth something next to a control showing the node
rejects *anything* — otherwise "every send is accepted" is equally true of a node that
accepts everything. That control is
``test_a_fee_one_photon_under_the_floor_is_rejected``, and it is built by
``_fee_at_exactly``: a hand-made transaction paying exactly ``fee_of_size(its own
size)``, once at the floor and once one photon under.

``_fee_at_exactly`` used to iterate a fixed point — assume a size, derive the fee, sign,
adopt the signed size, repeat — and for roughly a quarter of keys that map has NO fixed
point. The fee sets the output value, the output value goes into the sighash, the
sighash sets the signature, and the DER signature length is 71 or 72 bytes, so the map
becomes a two-cycle: assuming 191 signs to 192 and assuming 192 signs to 191. It raised
``AssertionError("could not settle on a signed size")``. Measured here, offline, over
400 fresh keys: 98 non-convergent (24.5%), 97 of them the 191/192 pair. Called twice per
run, that is ~44% — so the only node-rejection control in the suite failed about as
often as it ran.

That whole construction is pure: ``Transaction`` building and RFC 6979 signing need no
node. Only ``_relay_floor`` and the broadcast do. So the determinism of the control is
testable here, in the ordinary offline suite, while the integration module stays
``-m integration``. This file pins only that the transactions can always be built and
that they pay exactly what they claim; the node's verdict on them is
``test_a_fee_one_photon_under_the_floor_is_rejected``, confirmed on a regtest node
started at the mainnet floor.
"""

from __future__ import annotations

import os

import pytest

# The helper under test lives in the integration module, but importing it opens no
# socket and starts no container — the `node` fixture is what does that, and nothing
# here requests it.
from test_wallet_send_regtest_e2e import (
    _fee_at_exactly,
    _p2pkh_unlock,
    _spk,
    _src,
    _wallet,
)

from pyrxd.keys import PrivateKey
from pyrxd.network.electrumx import UtxoRecord
from pyrxd.script.type import P2PKH
from pyrxd.transaction.transaction import Transaction
from pyrxd.transaction.transaction_input import TransactionInput
from pyrxd.transaction.transaction_output import TransactionOutput
from pyrxd.wallet import DEFAULT_FEE_RATE, RxdWallet

pytestmark = pytest.mark.unit

#: The rate the control is actually built at, in photons per byte. It tracks the live
#: control rather than being chosen here: that one reads the floor off its node, and the
#: harness starts the node at MAINNET's floor — which is exactly ``DEFAULT_FEE_RATE``.
#: (This used to be a hard-coded 1_000, the default regtest node's tenth of that; the
#: mirror then exercised a different rate from the thing it mirrors.)
_NODE_FLOOR = DEFAULT_FEE_RATE

#: Enough draws that missing a 24.5%-likely event is a 0.755**60 ≈ 5e-8 accident.
_DRAWS = 60


def _offline_coin(wallet: RxdWallet, value: int = 200_000_000) -> UtxoRecord:
    """A coin the wallet can spend, with a synthetic outpoint. No node involved.

    The txid is never looked up — ``_src`` fabricates the source transaction and pins
    its ``txid()`` — so random bytes are exactly as good as a real funding txid here.
    """
    return UtxoRecord(tx_hash=os.urandom(32).hex(), tx_pos=0, value=value, height=1)


def _naive_size_fixed_point(wallet: RxdWallet, coin: UtxoRecord, recipient: str, fee_of_size) -> bool:
    """The pre-fix construction, verbatim. ``True`` if it settles, ``False`` if it cycles.

    Kept here rather than deleted so the property under test is stated as a
    difference: whatever this cannot do, ``_fee_at_exactly`` must.
    """
    size = 226
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
            return True
        size = signed_size
    return False


def _a_case_the_naive_loop_cannot_settle(fee_of_size):
    """Draw fresh keys until one defeats the naive fixed point. ~1 in 4, so this is quick."""
    for _ in range(_DRAWS):
        wallet = _wallet(fee_rate=_NODE_FLOOR)
        coin = _offline_coin(wallet)
        recipient = PrivateKey().public_key().address()
        if not _naive_size_fixed_point(wallet, coin, recipient, fee_of_size):
            return wallet, coin, recipient
    return None


def test_the_naive_size_fixed_point_really_does_oscillate() -> None:
    """The bug is real and reachable — the premise the fix rests on.

    If this ever stops finding a case, the DER length has stopped varying and
    ``_fee_at_exactly`` no longer needs to grind; that is a fact worth failing over
    rather than silently carrying dead machinery.
    """
    found = _a_case_the_naive_loop_cannot_settle(lambda s: s * _NODE_FLOOR)
    assert found is not None, (
        f"no oscillating (key, coin) in {_DRAWS} draws — at the measured 24.5% rate that is "
        "a 5e-8 accident, so the signing behaviour has changed and this file's premise needs review"
    )


@pytest.mark.parametrize(
    ("label", "fee_of_size"),
    [
        ("at the floor", lambda s: s * _NODE_FLOOR),
        ("one photon under", lambda s: s * _NODE_FLOOR - 1),
    ],
)
def test_fee_at_exactly_settles_where_the_naive_fixed_point_cannot(label: str, fee_of_size) -> None:
    """THE regression: a case selected BECAUSE the old loop cycles on it forever.

    Selecting the input this way makes the test deterministic in outcome rather than
    probabilistic — reverting ``_fee_at_exactly`` to the plain size fixed point fails
    here every time, not one run in four.
    """
    found = _a_case_the_naive_loop_cannot_settle(fee_of_size)
    assert found is not None, f"could not find an oscillating case in {_DRAWS} draws ({label})"
    wallet, coin, recipient = found

    tx = _fee_at_exactly(wallet, coin, recipient, fee_of_size)

    size = len(tx.serialize())
    assert tx.get_fee() == fee_of_size(size), (
        f"the control is miscalibrated: {size} bytes paying {tx.get_fee()}, wanted {fee_of_size(size)}"
    )


@pytest.mark.parametrize(
    ("label", "fee_of_size"),
    [
        ("at the floor", lambda s: s * _NODE_FLOOR),
        ("one photon under", lambda s: s * _NODE_FLOOR - 1),
    ],
)
def test_fee_at_exactly_always_settles_on_freshly_drawn_keys(label: str, fee_of_size) -> None:
    """Breadth: every draw settles, and none of them is off by a photon.

    ``fee == fee_of_size(size)`` is the boundary the one-photon-short assertion turns
    on. A "fix" that settled by rounding the fee up to the next size would pass the
    convergence half of this and still destroy the control, so both are asserted here.
    """
    for _ in range(_DRAWS):
        wallet = _wallet(fee_rate=_NODE_FLOOR)
        coin = _offline_coin(wallet)
        recipient = PrivateKey().public_key().address()

        tx = _fee_at_exactly(wallet, coin, recipient, fee_of_size)

        size = len(tx.serialize())
        assert tx.get_fee() == fee_of_size(size), f"{label}: {size} bytes paid {tx.get_fee()}"
        assert len(tx.inputs) == 1 and len(tx.outputs) == 1, "the control must stay 1-in/1-out"


def test_the_grind_parameter_cannot_change_the_size_or_the_verdict() -> None:
    """nLockTime is the grind knob; it is only safe because of these two properties.

    Four bytes at every value, so it cannot perturb the size the fee is charged
    against; and every input is final (nSequence 0xFFFFFFFF), so a node never enforces
    it and the transaction is valid whichever value the grind lands on.
    """
    wallet = _wallet(fee_rate=_NODE_FLOOR)
    coin = _offline_coin(wallet)
    recipient = PrivateKey().public_key().address()

    sizes = set()
    for locktime in (0, 1, 7, 500_000, 0xFFFFFFFF):
        tx = Transaction(
            tx_inputs=[
                TransactionInput(
                    source_transaction=_src(coin.tx_hash, coin.tx_pos, _spk(wallet.address), coin.value),
                    source_txid=coin.tx_hash,
                    source_output_index=coin.tx_pos,
                    unlocking_script_template=_p2pkh_unlock(wallet._private_key),
                )
            ],
            tx_outputs=[TransactionOutput(P2PKH().lock(recipient), coin.value - 250_000)],
            locktime=locktime,
        )
        assert all(i.sequence == 0xFFFFFFFF for i in tx.inputs), (
            "an input is not final, so nLockTime would become enforceable and the grind unsafe"
        )
        tx.sign()
        sizes.add(len(tx.serialize()) - len(tx.inputs[0].unlocking_script.serialize()))

    assert len(sizes) == 1, f"nLockTime changed the serialised size: {sorted(sizes)}"
